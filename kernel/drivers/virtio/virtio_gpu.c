/*
 * Kiseki OS - VirtIO GPU 2D Framebuffer Driver
 *
 * Provides a simple linear framebuffer via the VirtIO GPU device.
 * Implements the 2D subset of the VirtIO GPU specification:
 *   - GET_DISPLAY_INFO to discover display dimensions
 *   - RESOURCE_CREATE_2D to create a framebuffer resource
 *   - RESOURCE_ATTACH_BACKING to attach guest physical memory
 *   - SET_SCANOUT to connect the resource to a display
 *   - TRANSFER_TO_HOST_2D + RESOURCE_FLUSH to update the display
 *
 * The driver follows the same MMIO transport patterns as virtio_blk.c
 * and virtio_net.c, with its own static DMA pages for the controlq.
 *
 * Reference: VirtIO Specification v1.2, Section 5.7 — GPU Device
 *            XNU IOKit/IOFramebuffer model (conceptual)
 */

#include <kiseki/types.h>
#include <kiseki/platform.h>
#include <kern/kprintf.h>
#include <kern/sync.h>
#include <kern/pmm.h>
#include <drivers/virtio.h>
#include <drivers/virtio_gpu.h>
#include <drivers/gic.h>

/* ============================================================================
 * MMIO Helpers (same as virtio_blk.c and virtio_net.c)
 * ============================================================================ */

static inline void mmio_write32(uint64_t addr, uint32_t val)
{
    *(volatile uint32_t *)addr = val;
}

static inline uint32_t mmio_read32(uint64_t addr)
{
    return *(volatile uint32_t *)addr;
}

static inline void dsb(void)
{
    __asm__ volatile("dsb sy" ::: "memory");
}

/* ============================================================================
 * Driver State
 * ============================================================================ */

static struct virtio_device gpudev;
static bool gpudev_found = false;
static spinlock_t gpu_lock = SPINLOCK_INIT;

/* The GPU's GIC IRQ number (set during init) */
static uint32_t gpu_irq_num = 0;

/* Framebuffer state */
static struct framebuffer_info gpu_fb;

/*
 * Default framebuffer dimensions. GET_DISPLAY_INFO will override these
 * if the display reports a preferred resolution.
 */
#define DEFAULT_FB_WIDTH    1024
#define DEFAULT_FB_HEIGHT   768
#define FB_BPP              32      /* Bits per pixel */
#define FB_BYTES_PER_PIXEL  4       /* 32-bit RGBA */

/* Resource ID for the primary framebuffer (guest-chosen, must be > 0) */
#define FB_RESOURCE_ID      1

/*
 * Framebuffer backing pages.
 * For a 1024x768x32bpp framebuffer: 1024 * 768 * 4 = 3,145,728 bytes
 * = 768 pages. We allocate pages from the PMM at init time.
 *
 * Maximum supported: 1920x1080x32bpp = 8,294,400 bytes = 2025 pages.
 * We cap at 4096 pages (~16MB) for safety.
 */
#define FB_MAX_PAGES        4096

static uint64_t fb_pages[FB_MAX_PAGES];     /* Physical addresses of backing pages */
static uint32_t fb_num_pages = 0;           /* Number of allocated pages */

/* ============================================================================
 * VirtIO GPU Controlq — DMA Pages and Queue Helpers
 *
 * Each VirtIO queue needs its own physically-contiguous DMA region for
 * the descriptor table, available ring, and used ring. Following the
 * pattern from virtio_blk.c and virtio_net.c, we use static buffers.
 *
 * The controlq (queue 0) handles all 2D commands.
 * The cursorq (queue 1) handles cursor updates — not needed for a
 * simple framebuffer, so we leave it uninitialised.
 * ============================================================================ */

/* DMA region for controlq (queue 0): desc + avail + used */
static uint8_t ctlq_pages[3 * PAGE_SIZE] __aligned(PAGE_SIZE);

/*
 * Static buffers for GPU command submission.
 *
 * VirtIO GPU uses a request-response protocol: the driver writes a
 * command struct, the device writes a response struct. Both are placed
 * in the virtqueue as a descriptor chain:
 *   - Descriptor 0: command (device-readable)
 *   - Descriptor 1: response (device-writable, VIRTQ_DESC_F_WRITE)
 *
 * We use static buffers to avoid needing kmalloc. Only one command can
 * be in-flight at a time (protected by gpu_lock).
 */

/* Request buffer — large enough for the biggest command we send.
 * RESOURCE_ATTACH_BACKING is the biggest: header (32 bytes) + up to
 * FB_MAX_PAGES mem_entries (16 bytes each). But we actually send the
 * attach_backing header + mem_entries as a separate descriptor chain,
 * so we only need enough for the header struct here. The mem_entries
 * are in a separate buffer. */
static uint8_t gpu_req_buf[512] __aligned(16);

/* Response buffer — large enough for the biggest response.
 * GET_DISPLAY_INFO returns virtio_gpu_resp_display_info which is
 * 24 (header) + 16 * 24 (pmodes) = 408 bytes. */
static uint8_t gpu_resp_buf[512] __aligned(16);

/* Separate buffer for ATTACH_BACKING mem_entries (scatter-gather list).
 * Each entry is 16 bytes; we need up to FB_MAX_PAGES entries.
 * 4096 * 16 = 65536 bytes = 16 pages. Allocate statically for the
 * maximum we'll ever need based on our max framebuffer size. */
#define FB_ATTACH_MAX_ENTRIES   2048    /* Enough for 1920x1080 */
static struct virtio_gpu_mem_entry
    gpu_mem_entries[FB_ATTACH_MAX_ENTRIES] __aligned(16);

/* ============================================================================
 * Controlq Setup (following virtio_blk.c pattern)
 * ============================================================================ */

/*
 * gpu_setup_controlq - Set up controlq (queue 0) using static DMA pages
 *
 * This mirrors virtio_alloc_queue() but uses our own static buffer
 * rather than the shared one in virtio_blk.c.
 */
static int gpu_setup_controlq(struct virtio_device *dev)
{
    uint64_t base = dev->base;

    /* Select queue 0 (controlq) */
    mmio_write32(base + VIRTIO_MMIO_QUEUE_SEL, 0);
    dsb();

    uint32_t max_size = mmio_read32(base + VIRTIO_MMIO_QUEUE_NUM_MAX);
    if (max_size == 0) {
        kprintf("[virtio-gpu] controlq not available\n");
        return -1;
    }

    uint32_t num = max_size;
    if (num > VIRTQ_MAX_SIZE)
        num = VIRTQ_MAX_SIZE;

    struct virtqueue *vq = &dev->vq[0];
    vq->num = num;

    /* Zero the DMA region */
    uint8_t *mem = ctlq_pages;
    for (uint64_t i = 0; i < sizeof(ctlq_pages); i++)
        mem[i] = 0;

    /* Layout: desc | avail | (padding) | used */
    vq->desc  = (struct virtq_desc *)mem;
    vq->avail = (struct virtq_avail *)(mem + num * sizeof(struct virtq_desc));
    vq->used  = (struct virtq_used *)
                    (mem + ALIGN_UP(num * sizeof(struct virtq_desc)
                                    + sizeof(struct virtq_avail)
                                    + num * sizeof(uint16_t),
                                    PAGE_SIZE));

    /* Initialise free descriptor list */
    for (uint32_t i = 0; i < num; i++) {
        vq->desc[i].next = (uint16_t)(i + 1);
        vq->desc[i].flags = 0;
    }
    vq->desc[num - 1].next = 0;
    vq->free_head = 0;
    vq->num_free = num;
    vq->last_used_idx = 0;

    /* Set queue size */
    mmio_write32(base + VIRTIO_MMIO_QUEUE_NUM, num);
    dsb();

    if (dev->version == 1) {
        /* Legacy interface */
        mmio_write32(base + VIRTIO_MMIO_GUEST_PAGE_SIZE, PAGE_SIZE);
        dsb();
        mmio_write32(base + VIRTIO_MMIO_QUEUE_PFN,
                     (uint32_t)((uint64_t)mem / PAGE_SIZE));
    } else {
        /* Modern interface */
        uint64_t desc_pa  = (uint64_t)vq->desc;
        uint64_t avail_pa = (uint64_t)vq->avail;
        uint64_t used_pa  = (uint64_t)vq->used;

        mmio_write32(base + VIRTIO_MMIO_QUEUE_DESC_LOW,
                     (uint32_t)(desc_pa & 0xFFFFFFFF));
        mmio_write32(base + VIRTIO_MMIO_QUEUE_DESC_HIGH,
                     (uint32_t)(desc_pa >> 32));
        mmio_write32(base + VIRTIO_MMIO_QUEUE_AVAIL_LOW,
                     (uint32_t)(avail_pa & 0xFFFFFFFF));
        mmio_write32(base + VIRTIO_MMIO_QUEUE_AVAIL_HIGH,
                     (uint32_t)(avail_pa >> 32));
        mmio_write32(base + VIRTIO_MMIO_QUEUE_USED_LOW,
                     (uint32_t)(used_pa & 0xFFFFFFFF));
        mmio_write32(base + VIRTIO_MMIO_QUEUE_USED_HIGH,
                     (uint32_t)(used_pa >> 32));
        dsb();
        mmio_write32(base + VIRTIO_MMIO_QUEUE_READY, 1);
    }

    dsb();
    kprintf("[virtio-gpu] controlq: %u descriptors\n", num);
    return 0;
}

/* ============================================================================
 * Virtqueue I/O Helpers (same pattern as virtio_blk.c)
 * ============================================================================ */

static int gpu_alloc_desc(struct virtqueue *vq)
{
    if (vq->num_free == 0)
        return -1;

    uint32_t idx = vq->free_head;
    vq->free_head = vq->desc[idx].next;
    vq->num_free--;
    return (int)idx;
}

static void gpu_free_desc(struct virtqueue *vq, uint32_t idx)
{
    vq->desc[idx].next = (uint16_t)vq->free_head;
    vq->desc[idx].flags = 0;
    vq->free_head = idx;
    vq->num_free++;
}

static void gpu_free_chain(struct virtqueue *vq, uint32_t head)
{
    uint32_t idx = head;
    for (;;) {
        uint16_t flags = vq->desc[idx].flags;
        uint32_t next = vq->desc[idx].next;
        gpu_free_desc(vq, idx);
        if (!(flags & VIRTQ_DESC_F_NEXT))
            break;
        idx = next;
    }
}

/* ============================================================================
 * GPU Command Submission
 *
 * All GPU commands follow the same pattern:
 *   1. Fill request buffer with the command struct
 *   2. Allocate 2 descriptors: req (device-readable) + resp (device-writable)
 *   3. Submit to controlq and poll for completion
 *   4. Check response header type
 *
 * gpu_lock must be held by the caller.
 * ============================================================================ */

/*
 * gpu_submit_cmd - Submit a command to the controlq and wait for response
 *
 * @req_buf:  Physical address of request buffer
 * @req_len:  Length of request in bytes
 * @resp_buf: Physical address of response buffer
 * @resp_len: Length of response buffer in bytes
 *
 * Returns the response type (VIRTIO_GPU_RESP_*) or 0 on queue error.
 */
static uint32_t gpu_submit_cmd(void *req_buf, uint32_t req_len,
                               void *resp_buf, uint32_t resp_len)
{
    struct virtqueue *vq = &gpudev.vq[0];

    int d0 = gpu_alloc_desc(vq);
    int d1 = gpu_alloc_desc(vq);
    if (d0 < 0 || d1 < 0) {
        kprintf("[virtio-gpu] no free descriptors\n");
        if (d0 >= 0) gpu_free_desc(vq, (uint32_t)d0);
        if (d1 >= 0) gpu_free_desc(vq, (uint32_t)d1);
        return 0;
    }

    /* Descriptor 0: request (device-readable) */
    vq->desc[d0].addr  = (uint64_t)req_buf;
    vq->desc[d0].len   = req_len;
    vq->desc[d0].flags = VIRTQ_DESC_F_NEXT;
    vq->desc[d0].next  = (uint16_t)d1;

    /* Descriptor 1: response (device-writable) */
    vq->desc[d1].addr  = (uint64_t)resp_buf;
    vq->desc[d1].len   = resp_len;
    vq->desc[d1].flags = VIRTQ_DESC_F_WRITE;
    vq->desc[d1].next  = 0;

    /* Add to available ring */
    vq->avail->ring[vq->avail->idx % vq->num] = (uint16_t)d0;
    dsb();
    vq->avail->idx++;
    dsb();

    /* Notify device (queue 0) */
    mmio_write32(gpudev.base + VIRTIO_MMIO_QUEUE_NOTIFY, 0);

    /* Poll for completion with timeout */
    {
        uint32_t timeout = 10000000;
        while (vq->used->idx == vq->last_used_idx && timeout > 0) {
            dsb();
            timeout--;
        }
        if (timeout == 0) {
            kprintf("[virtio-gpu] cmd2 TIMEOUT (avail=%u used=%u last=%u)\n",
                    vq->avail->idx, vq->used->idx, vq->last_used_idx);
            gpu_free_chain(vq, (uint32_t)d0);
            return 0;
        }
    }

    vq->last_used_idx++;

    /* ACK interrupt */
    uint32_t isr = mmio_read32(gpudev.base + VIRTIO_MMIO_INTERRUPT_STATUS);
    if (isr)
        mmio_write32(gpudev.base + VIRTIO_MMIO_INTERRUPT_ACK, isr);

    /* Read response type */
    struct virtio_gpu_ctrl_hdr *resp_hdr = (struct virtio_gpu_ctrl_hdr *)resp_buf;
    uint32_t resp_type = resp_hdr->type;

    /* Free descriptor chain */
    gpu_free_chain(vq, (uint32_t)d0);

    return resp_type;
}

/*
 * gpu_submit_cmd_3desc - Submit a command with 3 descriptors
 *
 * Used for RESOURCE_ATTACH_BACKING where we need:
 *   desc 0: command header (device-readable)
 *   desc 1: mem_entries array (device-readable)
 *   desc 2: response (device-writable)
 */
static uint32_t gpu_submit_cmd_3desc(void *req_buf, uint32_t req_len,
                                     void *data_buf, uint32_t data_len,
                                     void *resp_buf, uint32_t resp_len)
{
    struct virtqueue *vq = &gpudev.vq[0];

    int d0 = gpu_alloc_desc(vq);
    int d1 = gpu_alloc_desc(vq);
    int d2 = gpu_alloc_desc(vq);
    if (d0 < 0 || d1 < 0 || d2 < 0) {
        kprintf("[virtio-gpu] no free descriptors (3-chain)\n");
        if (d0 >= 0) gpu_free_desc(vq, (uint32_t)d0);
        if (d1 >= 0) gpu_free_desc(vq, (uint32_t)d1);
        if (d2 >= 0) gpu_free_desc(vq, (uint32_t)d2);
        return 0;
    }

    /* Descriptor 0: command header (device-readable) */
    vq->desc[d0].addr  = (uint64_t)req_buf;
    vq->desc[d0].len   = req_len;
    vq->desc[d0].flags = VIRTQ_DESC_F_NEXT;
    vq->desc[d0].next  = (uint16_t)d1;

    /* Descriptor 1: data (device-readable) */
    vq->desc[d1].addr  = (uint64_t)data_buf;
    vq->desc[d1].len   = data_len;
    vq->desc[d1].flags = VIRTQ_DESC_F_NEXT;
    vq->desc[d1].next  = (uint16_t)d2;

    /* Descriptor 2: response (device-writable) */
    vq->desc[d2].addr  = (uint64_t)resp_buf;
    vq->desc[d2].len   = resp_len;
    vq->desc[d2].flags = VIRTQ_DESC_F_WRITE;
    vq->desc[d2].next  = 0;

    /* Add to available ring */
    vq->avail->ring[vq->avail->idx % vq->num] = (uint16_t)d0;
    dsb();
    vq->avail->idx++;
    dsb();

    /* Notify device (queue 0) */
    mmio_write32(gpudev.base + VIRTIO_MMIO_QUEUE_NOTIFY, 0);

    /* Poll for completion with timeout */
    {
        uint32_t timeout = 10000000;
        while (vq->used->idx == vq->last_used_idx && timeout > 0) {
            dsb();
            timeout--;
        }
        if (timeout == 0) {
            kprintf("[virtio-gpu] cmd3 TIMEOUT (avail=%u used=%u last=%u)\n",
                    vq->avail->idx, vq->used->idx, vq->last_used_idx);
            gpu_free_chain(vq, (uint32_t)d0);
            return 0;
        }
    }

    vq->last_used_idx++;

    /* ACK interrupt */
    uint32_t isr = mmio_read32(gpudev.base + VIRTIO_MMIO_INTERRUPT_STATUS);
    if (isr)
        mmio_write32(gpudev.base + VIRTIO_MMIO_INTERRUPT_ACK, isr);

    /* Read response type */
    struct virtio_gpu_ctrl_hdr *resp_hdr = (struct virtio_gpu_ctrl_hdr *)resp_buf;
    uint32_t resp_type = resp_hdr->type;

    /* Free descriptor chain */
    gpu_free_chain(vq, (uint32_t)d0);

    return resp_type;
}

/* ============================================================================
 * GPU Command Wrappers
 * ============================================================================ */

/*
 * gpu_get_display_info - Query display configuration
 *
 * Returns the preferred width and height of scanout 0.
 * If no display info is available, returns the defaults.
 */
static void gpu_get_display_info(uint32_t *width, uint32_t *height)
{
    /* Build request */
    struct virtio_gpu_ctrl_hdr *req = (struct virtio_gpu_ctrl_hdr *)gpu_req_buf;
    for (uint32_t i = 0; i < sizeof(struct virtio_gpu_ctrl_hdr); i++)
        ((uint8_t *)req)[i] = 0;
    req->type = VIRTIO_GPU_CMD_GET_DISPLAY_INFO;

    /* Clear response */
    for (uint32_t i = 0; i < sizeof(gpu_resp_buf); i++)
        gpu_resp_buf[i] = 0;

    uint32_t resp = gpu_submit_cmd(
        req, sizeof(struct virtio_gpu_ctrl_hdr),
        gpu_resp_buf, sizeof(struct virtio_gpu_resp_display_info));

    if (resp == VIRTIO_GPU_RESP_OK_DISPLAY_INFO) {
        struct virtio_gpu_resp_display_info *info =
            (struct virtio_gpu_resp_display_info *)gpu_resp_buf;

        /* Use the first enabled scanout */
        for (int i = 0; i < VIRTIO_GPU_MAX_SCANOUTS; i++) {
            if (info->pmodes[i].enabled &&
                info->pmodes[i].r.width > 0 &&
                info->pmodes[i].r.height > 0) {
                *width  = info->pmodes[i].r.width;
                *height = info->pmodes[i].r.height;
                kprintf("[virtio-gpu] display %d: %ux%u (enabled)\n",
                        i, *width, *height);
                return;
            }
        }
    }

    /* Fallback to defaults */
    kprintf("[virtio-gpu] no display info, using %ux%u\n",
            DEFAULT_FB_WIDTH, DEFAULT_FB_HEIGHT);
    *width  = DEFAULT_FB_WIDTH;
    *height = DEFAULT_FB_HEIGHT;
}

/*
 * gpu_resource_create_2d - Create a 2D resource
 */
static int gpu_resource_create_2d(uint32_t resource_id, uint32_t format,
                                  uint32_t width, uint32_t height)
{
    struct virtio_gpu_resource_create_2d *req =
        (struct virtio_gpu_resource_create_2d *)gpu_req_buf;
    for (uint32_t i = 0; i < sizeof(*req); i++)
        ((uint8_t *)req)[i] = 0;

    req->hdr.type   = VIRTIO_GPU_CMD_RESOURCE_CREATE_2D;
    req->resource_id = resource_id;
    req->format      = format;
    req->width       = width;
    req->height      = height;

    for (uint32_t i = 0; i < sizeof(gpu_resp_buf); i++)
        gpu_resp_buf[i] = 0;

    uint32_t resp = gpu_submit_cmd(
        req, sizeof(*req),
        gpu_resp_buf, sizeof(struct virtio_gpu_ctrl_hdr));

    if (resp != VIRTIO_GPU_RESP_OK_NODATA) {
        kprintf("[virtio-gpu] RESOURCE_CREATE_2D failed: resp=0x%x\n", resp);
        return -1;
    }

    kprintf("[virtio-gpu] created 2D resource %u: %ux%u format=%u\n",
            resource_id, width, height, format);
    return 0;
}

/*
 * gpu_resource_attach_backing - Attach guest physical pages to a resource
 */
static int gpu_resource_attach_backing(uint32_t resource_id,
                                       uint64_t *pages, uint32_t num_pages)
{
    if (num_pages > FB_ATTACH_MAX_ENTRIES) {
        kprintf("[virtio-gpu] too many backing pages (%u > %u)\n",
                num_pages, FB_ATTACH_MAX_ENTRIES);
        return -1;
    }

    /* Build the attach_backing header */
    struct virtio_gpu_resource_attach_backing *req =
        (struct virtio_gpu_resource_attach_backing *)gpu_req_buf;
    for (uint32_t i = 0; i < sizeof(*req); i++)
        ((uint8_t *)req)[i] = 0;

    req->hdr.type    = VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING;
    req->resource_id = resource_id;
    req->nr_entries  = num_pages;

    /* Build the scatter-gather list of mem_entries */
    for (uint32_t i = 0; i < num_pages; i++) {
        gpu_mem_entries[i].addr    = pages[i];
        gpu_mem_entries[i].length  = PAGE_SIZE;
        gpu_mem_entries[i].padding = 0;
    }

    for (uint32_t i = 0; i < sizeof(struct virtio_gpu_ctrl_hdr); i++)
        gpu_resp_buf[i] = 0;

    /*
     * Use a 3-descriptor chain:
     *   d0: attach_backing header (device-readable)
     *   d1: mem_entries array (device-readable)
     *   d2: response (device-writable)
     */
    uint32_t resp = gpu_submit_cmd_3desc(
        req, sizeof(*req),
        gpu_mem_entries, num_pages * sizeof(struct virtio_gpu_mem_entry),
        gpu_resp_buf, sizeof(struct virtio_gpu_ctrl_hdr));

    if (resp != VIRTIO_GPU_RESP_OK_NODATA) {
        kprintf("[virtio-gpu] RESOURCE_ATTACH_BACKING failed: resp=0x%x\n",
                resp);
        return -1;
    }

    kprintf("[virtio-gpu] attached %u backing pages to resource %u\n",
            num_pages, resource_id);
    return 0;
}

/*
 * gpu_set_scanout - Connect a resource to a display scanout
 */
static int gpu_set_scanout(uint32_t scanout_id, uint32_t resource_id,
                           uint32_t width, uint32_t height)
{
    struct virtio_gpu_set_scanout *req =
        (struct virtio_gpu_set_scanout *)gpu_req_buf;
    for (uint32_t i = 0; i < sizeof(*req); i++)
        ((uint8_t *)req)[i] = 0;

    req->hdr.type    = VIRTIO_GPU_CMD_SET_SCANOUT;
    req->r.x         = 0;
    req->r.y         = 0;
    req->r.width     = width;
    req->r.height    = height;
    req->scanout_id  = scanout_id;
    req->resource_id = resource_id;

    for (uint32_t i = 0; i < sizeof(gpu_resp_buf); i++)
        gpu_resp_buf[i] = 0;

    uint32_t resp = gpu_submit_cmd(
        req, sizeof(*req),
        gpu_resp_buf, sizeof(struct virtio_gpu_ctrl_hdr));

    if (resp != VIRTIO_GPU_RESP_OK_NODATA) {
        kprintf("[virtio-gpu] SET_SCANOUT failed: resp=0x%x\n", resp);
        return -1;
    }

    kprintf("[virtio-gpu] scanout %u: resource %u, %ux%u\n",
            scanout_id, resource_id, width, height);
    return 0;
}

/*
 * gpu_transfer_to_host_2d - Transfer a rectangle from backing to host resource
 */
static int gpu_transfer_to_host_2d(uint32_t resource_id,
                                   uint32_t x, uint32_t y,
                                   uint32_t width, uint32_t height)
{
    struct virtio_gpu_transfer_to_host_2d *req =
        (struct virtio_gpu_transfer_to_host_2d *)gpu_req_buf;
    for (uint32_t i = 0; i < sizeof(*req); i++)
        ((uint8_t *)req)[i] = 0;

    req->hdr.type    = VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D;
    req->r.x         = x;
    req->r.y         = y;
    req->r.width     = width;
    req->r.height    = height;
    /*
     * The offset field specifies the byte offset into the resource's
     * backing pages where the transfer should start reading pixel data.
     * For a sub-rectangle at (x, y), the first pixel is at:
     *   offset = y * pitch + x * bytes_per_pixel
     *
     * Reference: VirtIO Specification v1.2, Section 5.7.6.8
     *            struct virtio_gpu_transfer_to_host_2d
     */
    req->offset      = (uint64_t)y * gpu_fb.pitch + (uint64_t)x * FB_BYTES_PER_PIXEL;
    req->resource_id = resource_id;

    for (uint32_t i = 0; i < sizeof(struct virtio_gpu_ctrl_hdr); i++)
        gpu_resp_buf[i] = 0;

    uint32_t resp = gpu_submit_cmd(
        req, sizeof(*req),
        gpu_resp_buf, sizeof(struct virtio_gpu_ctrl_hdr));

    if (resp != VIRTIO_GPU_RESP_OK_NODATA) {
        kprintf("[virtio-gpu] TRANSFER_TO_HOST_2D failed: resp=0x%x\n", resp);
        return -1;
    }

    return 0;
}

/*
 * gpu_resource_flush - Flush a rectangle from host resource to display
 */
static int gpu_resource_flush(uint32_t resource_id,
                              uint32_t x, uint32_t y,
                              uint32_t width, uint32_t height)
{
    struct virtio_gpu_resource_flush *req =
        (struct virtio_gpu_resource_flush *)gpu_req_buf;
    for (uint32_t i = 0; i < sizeof(*req); i++)
        ((uint8_t *)req)[i] = 0;

    req->hdr.type    = VIRTIO_GPU_CMD_RESOURCE_FLUSH;
    req->r.x         = x;
    req->r.y         = y;
    req->r.width     = width;
    req->r.height    = height;
    req->resource_id = resource_id;

    for (uint32_t i = 0; i < sizeof(struct virtio_gpu_ctrl_hdr); i++)
        gpu_resp_buf[i] = 0;

    uint32_t resp = gpu_submit_cmd(
        req, sizeof(*req),
        gpu_resp_buf, sizeof(struct virtio_gpu_ctrl_hdr));

    if (resp != VIRTIO_GPU_RESP_OK_NODATA) {
        kprintf("[virtio-gpu] RESOURCE_FLUSH failed: resp=0x%x\n", resp);
        return -1;
    }

    return 0;
}

/* ============================================================================
 * Public API
 * ============================================================================ */

int virtio_gpu_init(void)
{
    kprintf("[virtio-gpu] Scanning for VirtIO GPU device...\n");

    /* Scan all 32 MMIO transport slots for a GPU device */
    for (uint32_t i = 0; i < VIRTIO_MMIO_COUNT; i++) {
        uint64_t base = VIRTIO_MMIO_BASE + i * VIRTIO_MMIO_STRIDE;
        uint32_t irq  = VIRTIO_MMIO_IRQ_BASE + i;

        int ret = virtio_init_device(&gpudev, base, irq);
        if (ret < 0)
            continue;

        if (gpudev.device_id != VIRTIO_DEV_GPU) {
            /* Not a GPU — reset and move on. Do not disturb other devices. */
            mmio_write32(base + VIRTIO_MMIO_STATUS, 0);
            dsb();
            continue;
        }

        kprintf("[virtio-gpu] Found GPU at MMIO slot %u (base=0x%lx, IRQ=%u, version=%u)\n",
                i, base, irq, gpudev.version);
        gpu_irq_num = irq;

        /*
         * Feature negotiation.
         * We only need 2D mode — no virgl, no EDID, no blobs.
         * Request VIRTIO_F_VERSION_1 if the device supports it.
         */
        uint64_t features = virtio_negotiate_features(&gpudev,
                                                       VIRTIO_F_VERSION_1);
        kprintf("[virtio-gpu] Negotiated features: 0x%lx\n", features);

        /* Set up controlq (queue 0) */
        if (gpu_setup_controlq(&gpudev) < 0) {
            kprintf("[virtio-gpu] Failed to set up controlq\n");
            mmio_write32(base + VIRTIO_MMIO_STATUS, VIRTIO_STATUS_FAILED);
            return -1;
        }

        /* Set DRIVER_OK — device is now live */
        gpudev.status |= VIRTIO_STATUS_DRIVER_OK;
        mmio_write32(base + VIRTIO_MMIO_STATUS, gpudev.status);
        dsb();

        gpudev_found = true;

        /* Enable GIC interrupt for this device */
        gic_enable_irq(irq);

        /*
         * Step 1: Query display info for preferred resolution
         */
        uint32_t fb_width = DEFAULT_FB_WIDTH;
        uint32_t fb_height = DEFAULT_FB_HEIGHT;
        gpu_get_display_info(&fb_width, &fb_height);

        /*
         * Step 2: Allocate framebuffer backing pages
         */
        uint32_t fb_size = fb_width * fb_height * FB_BYTES_PER_PIXEL;
        uint32_t pages_needed = (fb_size + PAGE_SIZE - 1) / PAGE_SIZE;
        if (pages_needed > FB_MAX_PAGES) {
            kprintf("[virtio-gpu] Framebuffer too large (%u pages > %u max)\n",
                    pages_needed, FB_MAX_PAGES);
            return -1;
        }

        /*
         * Allocate a CONTIGUOUS block of pages for the framebuffer.
         *
         * The VirtIO GPU accepts a scatter-gather list of pages (they
         * don't need to be contiguous from the device's perspective),
         * but the fbconsole pixel renderer needs a contiguous kernel VA
         * range to write pixels directly. Since we use identity mapping
         * (PA == kernel VA), contiguous physical pages give us a
         * contiguous VA range.
         *
         * Use the buddy allocator's pmm_alloc_pages(order) to get a
         * power-of-2 aligned contiguous block. This wastes at most
         * 2x pages (buddy rounding) but guarantees contiguity.
         */
        uint32_t alloc_order = 0;
        while ((1u << alloc_order) < pages_needed)
            alloc_order++;

        if (alloc_order > PMM_MAX_ORDER) {
            kprintf("[virtio-gpu] Framebuffer too large (need order %u > max %u)\n",
                    alloc_order, PMM_MAX_ORDER);
            return -1;
        }

        uint32_t alloc_pages = (1u << alloc_order);

        kprintf("[virtio-gpu] Allocating %u pages (order %u) for %ux%u framebuffer (%u bytes)\n",
                alloc_pages, alloc_order, fb_width, fb_height, fb_size);

        uint64_t fb_contig_base = pmm_alloc_pages(alloc_order);
        if (fb_contig_base == 0) {
            kprintf("[virtio-gpu] OOM allocating contiguous framebuffer block\n");
            return -1;
        }

        /* Zero the entire contiguous block (identity-mapped: PA == kernel VA) */
        uint8_t *fb_mem = (uint8_t *)fb_contig_base;
        for (uint64_t b = 0; b < (uint64_t)alloc_pages * PAGE_SIZE; b++)
            fb_mem[b] = 0;

        /* Fill fb_pages[] with sequential page addresses for the
         * scatter-gather list used by RESOURCE_ATTACH_BACKING.
         * Only populate the pages_needed entries (not the full
         * power-of-2 allocation). */
        for (uint32_t p = 0; p < pages_needed; p++)
            fb_pages[p] = fb_contig_base + (uint64_t)p * PAGE_SIZE;

        fb_num_pages = pages_needed;

        /*
         * Step 3: Create a 2D resource
         *
         * We use B8G8R8X8_UNORM (format 2) which is the most widely
         * supported format in QEMU's virtio-gpu. This gives us BGRX
         * byte order (common on x86/ARM little-endian).
         */
        uint64_t irq_flags;
        spin_lock_irqsave(&gpu_lock, &irq_flags);

        if (gpu_resource_create_2d(FB_RESOURCE_ID,
                                   VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM,
                                   fb_width, fb_height) < 0) {
            spin_unlock_irqrestore(&gpu_lock, irq_flags);
            return -1;
        }

        /*
         * Step 4: Attach backing pages to the resource
         */
        if (gpu_resource_attach_backing(FB_RESOURCE_ID,
                                        fb_pages, fb_num_pages) < 0) {
            spin_unlock_irqrestore(&gpu_lock, irq_flags);
            return -1;
        }

        /*
         * Step 5: Set scanout 0 to display the resource
         */
        if (gpu_set_scanout(0, FB_RESOURCE_ID, fb_width, fb_height) < 0) {
            spin_unlock_irqrestore(&gpu_lock, irq_flags);
            return -1;
        }

        /*
         * Step 6: Initial transfer + flush to show the (blank) framebuffer
         */
        gpu_transfer_to_host_2d(FB_RESOURCE_ID, 0, 0, fb_width, fb_height);
        gpu_resource_flush(FB_RESOURCE_ID, 0, 0, fb_width, fb_height);

        spin_unlock_irqrestore(&gpu_lock, irq_flags);

        /* Fill in framebuffer info */
        gpu_fb.phys_addr = fb_pages[0];
        gpu_fb.width     = fb_width;
        gpu_fb.height    = fb_height;
        gpu_fb.pitch     = fb_width * FB_BYTES_PER_PIXEL;
        gpu_fb.bpp       = FB_BPP;
        gpu_fb.format    = VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM;
        gpu_fb.active    = true;

        kprintf("[virtio-gpu] Framebuffer ready: %ux%u, %u bpp, pitch=%u\n",
                gpu_fb.width, gpu_fb.height, gpu_fb.bpp, gpu_fb.pitch);
        kprintf("[virtio-gpu] Backing memory: PA 0x%lx (%u pages)\n",
                gpu_fb.phys_addr, fb_num_pages);

        return 0;
    }

    kprintf("[virtio-gpu] No VirtIO GPU device found\n");
    return -1;
}

void virtio_gpu_flush(uint32_t x, uint32_t y, uint32_t width, uint32_t height)
{
    if (!gpudev_found || !gpu_fb.active)
        return;

    uint64_t flags;
    spin_lock_irqsave(&gpu_lock, &flags);

    gpu_transfer_to_host_2d(FB_RESOURCE_ID, x, y, width, height);
    gpu_resource_flush(FB_RESOURCE_ID, x, y, width, height);

    spin_unlock_irqrestore(&gpu_lock, flags);
}

void virtio_gpu_flush_all(void)
{
    if (!gpudev_found || !gpu_fb.active)
        return;

    virtio_gpu_flush(0, 0, gpu_fb.width, gpu_fb.height);
}

const struct framebuffer_info *virtio_gpu_get_fb(void)
{
    if (!gpudev_found || !gpu_fb.active)
        return NULL;
    return &gpu_fb;
}

uint32_t virtio_gpu_get_irq(void)
{
    return gpu_irq_num;
}

void virtio_gpu_irq_handler(void)
{
    if (!gpudev_found)
        return;

    /*
     * ACK the interrupt. For our polling-based command submission,
     * we don't actually need to process used buffers here — the
     * polling loop in gpu_submit_cmd already handles that.
     *
     * However, the device may fire interrupts for display configuration
     * changes (EVENT_DISPLAY). We acknowledge them here.
     */
    uint32_t isr = mmio_read32(gpudev.base + VIRTIO_MMIO_INTERRUPT_STATUS);
    if (isr)
        mmio_write32(gpudev.base + VIRTIO_MMIO_INTERRUPT_ACK, isr);
}
