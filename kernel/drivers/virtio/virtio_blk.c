/*
 * Kiseki OS - VirtIO Block Device Driver
 *
 * VirtIO MMIO block device driver for QEMU virt machine.
 * Implements synchronous (polling-based) block I/O via virtqueues.
 *
 * The QEMU virt machine provides 32 VirtIO MMIO transports starting at
 * VIRTIO_MMIO_BASE (0x0a000000) with stride VIRTIO_MMIO_STRIDE (0x200).
 * Block devices are identified by device_id == 2.
 *
 * Reference: Virtual I/O Device (VIRTIO) Specification v1.1
 */

#include <kiseki/types.h>
#include <kiseki/platform.h>
#include <kern/kprintf.h>
#include <kern/sync.h>
#include <kern/pmm.h>
#include <drivers/virtio.h>

#ifdef PLATFORM_QEMU

/* ============================================================================
 * MMIO Helpers
 * ============================================================================ */

static inline void mmio_write32(uint64_t addr, uint32_t val)
{
    *(volatile uint32_t *)addr = val;
}

static inline uint32_t mmio_read32(uint64_t addr)
{
    return *(volatile uint32_t *)addr;
}

/* Data synchronization barrier -- ensure all prior memory ops complete */
static inline void dsb(void)
{
    __asm__ volatile("dsb sy" ::: "memory");
}

/* ============================================================================
 * Module State
 * ============================================================================ */

/* The block device we discovered during probing */
static struct virtio_device blkdev;
static bool blkdev_found = false;

/* Lock protecting concurrent access to the virtqueue */
static spinlock_t blk_lock = SPINLOCK_INIT;

/* Block size in bytes */
#define VIRTIO_BLK_SECTOR_SIZE  512

/*
 * Static buffers for the single request queue.
 * We allocate descriptor table + available ring + used ring from a
 * physically-contiguous page.  For a queue of VIRTQ_MAX_SIZE (256)
 * entries the total is well under 4 KB on the descriptor side and
 * another page for the rings.  We use 2 pages (8 KB) to be safe.
 *
 * Layout (within the allocated pages):
 *   offset 0x0000: struct virtq_desc  [num]      (16 * 256 = 4096)
 *   offset 0x1000: struct virtq_avail + ring[num] (6 + 2*256 = 518)
 *   offset 0x1400: struct virtq_used  + ring[num] (6 + 8*256 = 2054)
 */

/* Statically-allocated DMA region for the virtqueue.
 * 3 pages = 12 KB -- enough for 256-entry queue structures.
 */
static uint8_t vq_pages[3 * PAGE_SIZE] __aligned(PAGE_SIZE);

/* Static request header and status byte (must be physically addressable) */
static struct virtio_blk_req blk_req_hdr __aligned(16);
static uint8_t blk_req_status __aligned(16);

/* ============================================================================
 * VirtIO MMIO Device Initialization
 * ============================================================================ */

int virtio_init_device(struct virtio_device *dev, uint64_t base, uint32_t irq)
{
    /* Check magic value */
    uint32_t magic = mmio_read32(base + VIRTIO_MMIO_MAGIC_VALUE);
    if (magic != VIRTIO_MMIO_MAGIC)
        return -1;

    /* Read version and device ID */
    uint32_t version = mmio_read32(base + VIRTIO_MMIO_VERSION);
    uint32_t device_id = mmio_read32(base + VIRTIO_MMIO_DEVICE_ID);

    /* device_id 0 means no device on this transport */
    if (device_id == 0)
        return -1;

    dev->base = base;
    dev->version = version;
    dev->device_id = device_id;
    dev->irq = irq;
    dev->status = 0;
    dev->features = 0;

    /* Reset the device */
    mmio_write32(base + VIRTIO_MMIO_STATUS, 0);
    dsb();

    /* Set ACKNOWLEDGE status bit */
    dev->status = VIRTIO_STATUS_ACKNOWLEDGE;
    mmio_write32(base + VIRTIO_MMIO_STATUS, dev->status);

    /* Set DRIVER status bit */
    dev->status |= VIRTIO_STATUS_DRIVER;
    mmio_write32(base + VIRTIO_MMIO_STATUS, dev->status);

    return 0;
}

uint64_t virtio_negotiate_features(struct virtio_device *dev,
                                   uint64_t driver_features)
{
    uint64_t base = dev->base;

    /* Read device features (word 0: bits 0-31) */
    mmio_write32(base + VIRTIO_MMIO_DEVICE_FEATURES_SEL, 0);
    dsb();
    uint32_t dev_feat_lo = mmio_read32(base + VIRTIO_MMIO_DEVICE_FEATURES);

    /* Read device features (word 1: bits 32-63) */
    mmio_write32(base + VIRTIO_MMIO_DEVICE_FEATURES_SEL, 1);
    dsb();
    uint32_t dev_feat_hi = mmio_read32(base + VIRTIO_MMIO_DEVICE_FEATURES);

    uint64_t device_features = ((uint64_t)dev_feat_hi << 32) | dev_feat_lo;

    /* Intersect with what the driver supports */
    dev->features = device_features & driver_features;

    /* Write negotiated features back (word 0) */
    mmio_write32(base + VIRTIO_MMIO_DRIVER_FEATURES_SEL, 0);
    dsb();
    mmio_write32(base + VIRTIO_MMIO_DRIVER_FEATURES,
                 (uint32_t)(dev->features & 0xFFFFFFFF));

    /* Write negotiated features back (word 1) */
    mmio_write32(base + VIRTIO_MMIO_DRIVER_FEATURES_SEL, 1);
    dsb();
    mmio_write32(base + VIRTIO_MMIO_DRIVER_FEATURES,
                 (uint32_t)(dev->features >> 32));

    /* For version 2 (modern), set FEATURES_OK and verify */
    if (dev->version >= 2) {
        dev->status |= VIRTIO_STATUS_FEATURES_OK;
        mmio_write32(base + VIRTIO_MMIO_STATUS, dev->status);
        dsb();

        uint32_t s = mmio_read32(base + VIRTIO_MMIO_STATUS);
        if (!(s & VIRTIO_STATUS_FEATURES_OK)) {
            kprintf("[virtio] device rejected features!\n");
            dev->status = VIRTIO_STATUS_FAILED;
            mmio_write32(base + VIRTIO_MMIO_STATUS, dev->status);
            return 0;
        }
    }

    return dev->features;
}

int virtio_alloc_queue(struct virtio_device *dev, uint32_t queue_idx)
{
    uint64_t base = dev->base;

    /* Select queue */
    mmio_write32(base + VIRTIO_MMIO_QUEUE_SEL, queue_idx);
    dsb();

    /* Read max queue size */
    uint32_t max_size = mmio_read32(base + VIRTIO_MMIO_QUEUE_NUM_MAX);
    if (max_size == 0) {
        kprintf("[virtio] queue %u not available\n", queue_idx);
        return -1;
    }

    uint32_t num = max_size;
    if (num > VIRTQ_MAX_SIZE)
        num = VIRTQ_MAX_SIZE;

    struct virtqueue *vq = &dev->vq[queue_idx];
    vq->num = num;

    /*
     * Lay out virtqueue structures in the static DMA region.
     * Descriptor table: num * 16 bytes, page-aligned
     * Available ring:   6 + num * 2 bytes, 2-byte aligned
     * Used ring:        6 + num * 8 bytes, page-aligned (for device DMA)
     */
    uint8_t *mem = vq_pages;

    /* Zero the entire region */
    for (uint64_t i = 0; i < sizeof(vq_pages); i++)
        mem[i] = 0;

    vq->desc  = (struct virtq_desc *)mem;
    vq->avail = (struct virtq_avail *)(mem + num * sizeof(struct virtq_desc));
    vq->used  = (struct virtq_used *)
                    (mem + ALIGN_UP(num * sizeof(struct virtq_desc)
                                    + sizeof(struct virtq_avail)
                                    + num * sizeof(uint16_t),
                                    PAGE_SIZE));

    /* Initialize free descriptor list (singly-linked via next field) */
    for (uint32_t i = 0; i < num; i++) {
        vq->desc[i].next = (uint16_t)(i + 1);
        vq->desc[i].flags = 0;
    }
    vq->desc[num - 1].next = 0;  /* sentinel -- won't be followed */
    vq->free_head = 0;
    vq->num_free = num;
    vq->last_used_idx = 0;

    /* Set queue size */
    mmio_write32(base + VIRTIO_MMIO_QUEUE_NUM, num);
    dsb();

    if (dev->version == 1) {
        /* Legacy interface: set page size and queue PFN */
        mmio_write32(base + VIRTIO_MMIO_GUEST_PAGE_SIZE, PAGE_SIZE);
        dsb();
        mmio_write32(base + VIRTIO_MMIO_QUEUE_PFN,
                     (uint32_t)((uint64_t)mem / PAGE_SIZE));
    } else {
        /* Modern interface: set individual addresses */
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
    kprintf("[virtio] queue %u: %u descriptors\n", queue_idx, num);
    return 0;
}

/* ============================================================================
 * Virtqueue I/O Helpers
 * ============================================================================ */

/*
 * alloc_desc - Allocate a descriptor from the free list
 *
 * Returns descriptor index, or -1 if none available.
 * Caller must hold blk_lock.
 */
static int alloc_desc(struct virtqueue *vq)
{
    if (vq->num_free == 0)
        return -1;

    uint32_t idx = vq->free_head;
    vq->free_head = vq->desc[idx].next;
    vq->num_free--;
    return (int)idx;
}

/*
 * free_desc - Return a descriptor to the free list
 *
 * Caller must hold blk_lock.
 */
static void free_desc(struct virtqueue *vq, uint32_t idx)
{
    vq->desc[idx].addr = 0;
    vq->desc[idx].len = 0;
    vq->desc[idx].flags = 0;
    vq->desc[idx].next = (uint16_t)vq->free_head;
    vq->free_head = idx;
    vq->num_free++;
}

/*
 * free_chain - Free a chain of descriptors starting from head
 *
 * Caller must hold blk_lock.
 */
static void free_chain(struct virtqueue *vq, uint32_t head)
{
    uint32_t idx = head;
    for (;;) {
        uint16_t flags = vq->desc[idx].flags;
        uint32_t next = vq->desc[idx].next;
        free_desc(vq, idx);
        if (!(flags & VIRTQ_DESC_F_NEXT))
            break;
        idx = next;
    }
}

/* ============================================================================
 * Block I/O (Polling)
 * ============================================================================ */

/*
 * virtio_blk_rw - Perform a read or write operation
 *
 * @type:      VIRTIO_BLK_T_IN (read) or VIRTIO_BLK_T_OUT (write)
 * @sector:    Starting sector (512-byte units)
 * @buf:       Data buffer
 * @nsectors:  Number of sectors to transfer
 *
 * Returns 0 on success, -1 on failure.
 *
 * VirtIO block requests use a 3-descriptor chain:
 *   [0] device-readable:  struct virtio_blk_req header
 *   [1] device-readable (write) or device-writable (read): data
 *   [2] device-writable:  1-byte status
 */
static int virtio_blk_rw(uint32_t type, uint64_t sector,
                          void *buf, uint32_t nsectors)
{
    if (!blkdev_found)
        return -1;

    struct virtqueue *vq = &blkdev.vq[0];
    uint64_t flags;

    spin_lock_irqsave(&blk_lock, &flags);

    /* Allocate 3 descriptors */
    int d0 = alloc_desc(vq);
    int d1 = alloc_desc(vq);
    int d2 = alloc_desc(vq);

    if (d0 < 0 || d1 < 0 || d2 < 0) {
        kprintf("[virtio-blk] out of descriptors\n");
        if (d0 >= 0) free_desc(vq, (uint32_t)d0);
        if (d1 >= 0) free_desc(vq, (uint32_t)d1);
        if (d2 >= 0) free_desc(vq, (uint32_t)d2);
        spin_unlock_irqrestore(&blk_lock, flags);
        return -1;
    }

    /* Fill in the request header */
    blk_req_hdr.type = type;
    blk_req_hdr.reserved = 0;
    blk_req_hdr.sector = sector;

    blk_req_status = 0xFF;  /* sentinel */

    uint32_t data_len = nsectors * VIRTIO_BLK_SECTOR_SIZE;

    /* Descriptor 0: request header (device-readable) */
    vq->desc[d0].addr  = (uint64_t)&blk_req_hdr;
    vq->desc[d0].len   = sizeof(struct virtio_blk_req);
    vq->desc[d0].flags = VIRTQ_DESC_F_NEXT;
    vq->desc[d0].next  = (uint16_t)d1;

    /* Descriptor 1: data buffer */
    vq->desc[d1].addr  = (uint64_t)buf;
    vq->desc[d1].len   = data_len;
    vq->desc[d1].flags = VIRTQ_DESC_F_NEXT;
    if (type == VIRTIO_BLK_T_IN) {
        /* Read: device writes to buf */
        vq->desc[d1].flags |= VIRTQ_DESC_F_WRITE;
    }
    vq->desc[d1].next  = (uint16_t)d2;

    /* Descriptor 2: status byte (device-writable) */
    vq->desc[d2].addr  = (uint64_t)&blk_req_status;
    vq->desc[d2].len   = 1;
    vq->desc[d2].flags = VIRTQ_DESC_F_WRITE;
    vq->desc[d2].next  = 0;

    /* Add head of chain to available ring */
    uint16_t avail_idx = vq->avail->idx;
    vq->avail->ring[avail_idx % vq->num] = (uint16_t)d0;
    dsb();
    vq->avail->idx = avail_idx + 1;
    dsb();

    /* Notify the device */
    mmio_write32(blkdev.base + VIRTIO_MMIO_QUEUE_NOTIFY, 0);

    /* Poll for completion: wait until the used ring advances */
    while (vq->used->idx == vq->last_used_idx) {
        /* Spin -- in production this would be interrupt-driven */
        dsb();
    }

    /* Process used ring entry */
    vq->last_used_idx++;

    /* Acknowledge interrupt (clear bit 0: used buffer notification) */
    uint32_t isr = mmio_read32(blkdev.base + VIRTIO_MMIO_INTERRUPT_STATUS);
    mmio_write32(blkdev.base + VIRTIO_MMIO_INTERRUPT_ACK, isr);

    /* Free the descriptor chain */
    free_chain(vq, (uint32_t)d0);

    spin_unlock_irqrestore(&blk_lock, flags);

    if (blk_req_status != VIRTIO_BLK_S_OK) {
        kprintf("[virtio-blk] I/O error: status=%u sector=%lu\n",
                blk_req_status, sector);
        return -1;
    }

    return 0;
}

/* ============================================================================
 * Public API
 * ============================================================================ */

/*
 * virtio_blk_init - Probe VirtIO MMIO transports for a block device
 *
 * Scans all 32 VirtIO MMIO transport slots on the QEMU virt machine.
 * Initializes the first block device (device_id == 2) found.
 *
 * Returns 0 on success, -1 if no block device found.
 */
int virtio_blk_init(void)
{
    kprintf("[virtio-blk] probing %u MMIO transports at 0x%lx\n",
            VIRTIO_MMIO_COUNT, (uint64_t)VIRTIO_MMIO_BASE);

    for (uint32_t i = 0; i < VIRTIO_MMIO_COUNT; i++) {
        uint64_t base = VIRTIO_MMIO_BASE + (uint64_t)i * VIRTIO_MMIO_STRIDE;
        uint32_t irq  = VIRTIO_MMIO_IRQ_BASE + i;

        /* Debug: read raw MMIO values */
        uint32_t magic = mmio_read32(base + VIRTIO_MMIO_MAGIC_VALUE);
        uint32_t version = mmio_read32(base + VIRTIO_MMIO_VERSION);
        uint32_t devid = mmio_read32(base + VIRTIO_MMIO_DEVICE_ID);

        if (magic == VIRTIO_MMIO_MAGIC && devid != 0) {
            kprintf("[virtio-blk] slot %u @ 0x%lx: magic=0x%x ver=%u devid=%u\n",
                    i, base, magic, version, devid);
        }

        struct virtio_device dev;
        if (virtio_init_device(&dev, base, irq) != 0)
            continue;

        if (dev.device_id != VIRTIO_DEV_BLK)
            continue;

        kprintf("[virtio-blk] found block device at 0x%lx (version %u)\n",
                base, dev.version);

        /*
         * Negotiate features.
         * Modern devices (version 2) require VIRTIO_F_VERSION_1.
         */
        uint64_t driver_features = VIRTIO_F_VERSION_1;
        virtio_negotiate_features(&dev, driver_features);

        /* Allocate the request queue (queue 0) */
        if (virtio_alloc_queue(&dev, 0) != 0) {
            kprintf("[virtio-blk] failed to allocate queue\n");
            mmio_write32(base + VIRTIO_MMIO_STATUS, VIRTIO_STATUS_FAILED);
            continue;
        }

        /* Tell the device we're ready */
        dev.status |= VIRTIO_STATUS_DRIVER_OK;
        mmio_write32(base + VIRTIO_MMIO_STATUS, dev.status);
        dsb();

        blkdev = dev;
        blkdev_found = true;

        kprintf("[virtio-blk] device initialized successfully\n");
        return 0;
    }

    kprintf("[virtio-blk] no block device found\n");
    return -1;
}

/*
 * virtio_blk_read - Read sectors from the block device
 *
 * @sector:   Starting sector number (512-byte sectors)
 * @buf:      Destination buffer (must be at least count * 512 bytes)
 * @count:    Number of sectors to read
 *
 * Returns 0 on success, -1 on failure.
 */
int virtio_blk_read(uint64_t sector, void *buf, uint32_t count)
{
    return virtio_blk_rw(VIRTIO_BLK_T_IN, sector, buf, count);
}

/*
 * virtio_blk_write - Write sectors to the block device
 *
 * @sector:   Starting sector number (512-byte sectors)
 * @buf:      Source buffer (must be at least count * 512 bytes)
 * @count:    Number of sectors to write
 *
 * Returns 0 on success, -1 on failure.
 */
int virtio_blk_write(uint64_t sector, void *buf, uint32_t count)
{
    return virtio_blk_rw(VIRTIO_BLK_T_OUT, sector, buf, count);
}

#endif /* PLATFORM_QEMU */
