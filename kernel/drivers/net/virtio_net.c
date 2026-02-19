/*
 * Kiseki OS - VirtIO Network Device Driver
 *
 * VirtIO MMIO network device driver for QEMU virt machine.
 * Implements basic packet send/receive via virtqueues.
 *
 * The QEMU virt machine provides 32 VirtIO MMIO transports.
 * Network devices are identified by device_id == 1 (VIRTIO_DEV_NET).
 *
 * VirtIO-net uses two queues:
 *   Queue 0 (receiveq): device writes received packets
 *   Queue 1 (transmitq): driver writes packets to send
 *
 * Each packet is preceded by a virtio_net_hdr (10 or 12 bytes).
 *
 * Reference: Virtual I/O Device (VIRTIO) Specification v1.1, Section 5.1
 */

#include <kiseki/types.h>
#include <kiseki/platform.h>
#include <kern/kprintf.h>
#include <kern/sync.h>
#include <kern/pmm.h>
#include <drivers/virtio.h>
#include <net/net.h>

#ifdef PLATFORM_QEMU

/* ============================================================================
 * MMIO Helpers (duplicated from virtio_blk.c for independence)
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
 * VirtIO-Net Header
 *
 * Prepended to every packet on both RX and TX queues.
 * ============================================================================ */

#define VIRTIO_NET_HDR_SIZE     10      /* Without mergeable buffers */

struct virtio_net_hdr {
    uint8_t     flags;
    uint8_t     gso_type;
    uint16_t    hdr_len;
    uint16_t    gso_size;
    uint16_t    csum_start;
    uint16_t    csum_offset;
} __packed;

#define VIRTIO_NET_HDR_F_NEEDS_CSUM  1
#define VIRTIO_NET_GSO_NONE          0

/* VirtIO-net feature bits */
#define VIRTIO_NET_F_MAC            (1UL << 5)
#define VIRTIO_NET_F_STATUS         (1UL << 16)
#define VIRTIO_NET_F_MRG_RXBUF     (1UL << 15)

/* MAC address config offset (from device-specific config area) */
#define VIRTIO_NET_MAC_OFFSET       0x100

/* ============================================================================
 * Module State
 * ============================================================================ */

static struct virtio_device netdev;
static bool netdev_found = false;
static spinlock_t net_tx_lock = SPINLOCK_INIT;

/* DMA regions for the two virtqueues (RX and TX) */
static uint8_t rxq_pages[3 * PAGE_SIZE] __aligned(PAGE_SIZE);
static uint8_t txq_pages[3 * PAGE_SIZE] __aligned(PAGE_SIZE);

/* Receive buffer pool */
#define NET_RX_BUFSZ    2048
#define NET_RX_NBUFS    16
static uint8_t rx_buffers[NET_RX_NBUFS][NET_RX_BUFSZ] __aligned(16);

/* Transmit buffer (single, protected by net_tx_lock) */
#define NET_TX_BUFSZ    2048
static uint8_t tx_buffer[NET_TX_BUFSZ] __aligned(16);

/* Our MAC address (read from device config) */
static uint8_t net_mac[6];

/* External ethernet layer functions */
void eth_input(const void *frame, uint32_t len);
void eth_set_mac(const uint8_t *mac);

/* ============================================================================
 * Virtqueue Helpers (simplified, per-queue)
 * ============================================================================ */

/*
 * Setup a virtqueue from a static page region.
 * This is similar to virtio_alloc_queue but uses per-device page buffers
 * and doesn't conflict with the block device's queue setup.
 */
static int virtio_net_setup_queue(struct virtio_device *dev,
                                   uint32_t queue_idx,
                                   uint8_t *pages, uint64_t pages_size)
{
    uint64_t base = dev->base;

    mmio_write32(base + VIRTIO_MMIO_QUEUE_SEL, queue_idx);
    dsb();

    uint32_t max_size = mmio_read32(base + VIRTIO_MMIO_QUEUE_NUM_MAX);
    if (max_size == 0) {
        kprintf("[virtio-net] queue %u not available\n", queue_idx);
        return -1;
    }

    uint32_t num = max_size;
    if (num > VIRTQ_MAX_SIZE)
        num = VIRTQ_MAX_SIZE;

    struct virtqueue *vq = &dev->vq[queue_idx];
    vq->num = num;

    /* Zero the DMA region */
    for (uint64_t i = 0; i < pages_size; i++)
        pages[i] = 0;

    vq->desc  = (struct virtq_desc *)pages;
    vq->avail = (struct virtq_avail *)(pages + num * sizeof(struct virtq_desc));
    vq->used  = (struct virtq_used *)
                    (pages + ALIGN_UP(num * sizeof(struct virtq_desc)
                                      + sizeof(struct virtq_avail)
                                      + num * sizeof(uint16_t),
                                      PAGE_SIZE));

    /* Initialize free descriptor list */
    for (uint32_t i = 0; i < num; i++) {
        vq->desc[i].next = (uint16_t)(i + 1);
        vq->desc[i].flags = 0;
    }
    vq->desc[num - 1].next = 0;
    vq->free_head = 0;
    vq->num_free = num;
    vq->last_used_idx = 0;

    mmio_write32(base + VIRTIO_MMIO_QUEUE_NUM, num);
    dsb();

    if (dev->version == 1) {
        mmio_write32(base + VIRTIO_MMIO_GUEST_PAGE_SIZE, PAGE_SIZE);
        dsb();
        mmio_write32(base + VIRTIO_MMIO_QUEUE_PFN,
                     (uint32_t)((uint64_t)pages / PAGE_SIZE));
    } else {
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
    kprintf("[virtio-net] queue %u: %u descriptors\n", queue_idx, num);
    return 0;
}

/* Allocate a descriptor from a virtqueue */
static int vq_alloc_desc(struct virtqueue *vq)
{
    if (vq->num_free == 0)
        return -1;

    uint32_t idx = vq->free_head;
    vq->free_head = vq->desc[idx].next;
    vq->num_free--;
    return (int)idx;
}

/* Free a descriptor back to the virtqueue */
static void vq_free_desc(struct virtqueue *vq, uint32_t idx)
{
    vq->desc[idx].addr = 0;
    vq->desc[idx].len = 0;
    vq->desc[idx].flags = 0;
    vq->desc[idx].next = (uint16_t)vq->free_head;
    vq->free_head = idx;
    vq->num_free++;
}

/* ============================================================================
 * Receive Path
 * ============================================================================ */

/*
 * virtio_net_fill_rx - Post receive buffers to the RX queue.
 *
 * Each receive buffer is preceded by a virtio_net_hdr that the device
 * will fill in.
 */
static void virtio_net_fill_rx(void)
{
    struct virtqueue *vq = &netdev.vq[0];

    for (int i = 0; i < NET_RX_NBUFS; i++) {
        int d = vq_alloc_desc(vq);
        if (d < 0)
            break;

        vq->desc[d].addr  = (uint64_t)rx_buffers[i];
        vq->desc[d].len   = NET_RX_BUFSZ;
        vq->desc[d].flags = VIRTQ_DESC_F_WRITE;    /* Device writes here */
        vq->desc[d].next  = 0;

        uint16_t avail_idx = vq->avail->idx;
        vq->avail->ring[avail_idx % vq->num] = (uint16_t)d;
        dsb();
        vq->avail->idx = avail_idx + 1;
        dsb();
    }

    /* Notify device about new RX buffers */
    mmio_write32(netdev.base + VIRTIO_MMIO_QUEUE_NOTIFY, 0);
}

/*
 * virtio_net_recv - Poll for received packets.
 *
 * Checks the RX used ring for completed receive buffers,
 * passes them up to the ethernet layer, then re-posts the buffers.
 */
void virtio_net_recv(void)
{
    if (!netdev_found)
        return;

    struct virtqueue *vq = &netdev.vq[0];

    dsb();  /* Ensure we see device's latest writes to used ring */
    while (vq->last_used_idx != vq->used->idx) {
        dsb();

        uint32_t used_idx = vq->last_used_idx % vq->num;
        uint32_t desc_idx = vq->used->ring[used_idx].id;
        uint32_t total_len = vq->used->ring[used_idx].len;

        vq->last_used_idx++;

        /* Skip virtio_net_hdr to get the actual frame */
        if (total_len > VIRTIO_NET_HDR_SIZE) {
            uint8_t *frame = (uint8_t *)((uint64_t)vq->desc[desc_idx].addr)
                             + VIRTIO_NET_HDR_SIZE;
            uint32_t frame_len = total_len - VIRTIO_NET_HDR_SIZE;

            eth_input(frame, frame_len);
        }

        /* Re-post the buffer */
        vq->desc[desc_idx].len   = NET_RX_BUFSZ;
        vq->desc[desc_idx].flags = VIRTQ_DESC_F_WRITE;

        uint16_t avail_idx = vq->avail->idx;
        vq->avail->ring[avail_idx % vq->num] = (uint16_t)desc_idx;
        dsb();
        vq->avail->idx = avail_idx + 1;
        dsb();

        /* Notify device */
        mmio_write32(netdev.base + VIRTIO_MMIO_QUEUE_NOTIFY, 0);
    }

    /* Acknowledge interrupts */
    uint32_t isr = mmio_read32(netdev.base + VIRTIO_MMIO_INTERRUPT_STATUS);
    if (isr)
        mmio_write32(netdev.base + VIRTIO_MMIO_INTERRUPT_ACK, isr);
}

/* ============================================================================
 * Transmit Path
 * ============================================================================ */

/*
 * virtio_net_send - Send a raw Ethernet frame.
 *
 * Prepends a virtio_net_hdr and submits to the TX queue.
 *
 * @frame: Ethernet frame (starting with dst MAC)
 * @len:   Frame length in bytes
 *
 * Returns 0 on success, -1 on failure.
 */
int virtio_net_send(const void *frame, uint32_t len)
{
    if (!netdev_found)
        return -1;

    if (len + VIRTIO_NET_HDR_SIZE > NET_TX_BUFSZ) {
        kprintf("[virtio-net] TX frame too large (%u bytes)\n", len);
        return -1;
    }

    uint64_t flags;
    spin_lock_irqsave(&net_tx_lock, &flags);

    /* Prepend virtio_net_hdr (all zeros = no offload) */
    struct virtio_net_hdr *hdr = (struct virtio_net_hdr *)tx_buffer;
    hdr->flags       = 0;
    hdr->gso_type    = VIRTIO_NET_GSO_NONE;
    hdr->hdr_len     = 0;
    hdr->gso_size    = 0;
    hdr->csum_start  = 0;
    hdr->csum_offset = 0;

    /* Copy frame data after header */
    const uint8_t *src = (const uint8_t *)frame;
    uint8_t *dst = tx_buffer + VIRTIO_NET_HDR_SIZE;
    for (uint32_t i = 0; i < len; i++)
        dst[i] = src[i];

    uint32_t total = VIRTIO_NET_HDR_SIZE + len;

    /* Submit to TX queue (queue 1) */
    struct virtqueue *vq = &netdev.vq[1];

    int d = vq_alloc_desc(vq);
    if (d < 0) {
        spin_unlock_irqrestore(&net_tx_lock, flags);
        kprintf("[virtio-net] TX queue full\n");
        return -1;
    }

    vq->desc[d].addr  = (uint64_t)tx_buffer;
    vq->desc[d].len   = total;
    vq->desc[d].flags = 0;     /* Device reads this buffer */
    vq->desc[d].next  = 0;

    uint16_t avail_idx = vq->avail->idx;
    vq->avail->ring[avail_idx % vq->num] = (uint16_t)d;
    dsb();
    vq->avail->idx = avail_idx + 1;
    dsb();

    /* Notify device (TX queue = 1) */
    mmio_write32(netdev.base + VIRTIO_MMIO_QUEUE_NOTIFY, 1);

    /* Poll for TX completion */
    dsb();
    while (vq->used->idx == vq->last_used_idx) {
        dsb();
    }

    vq->last_used_idx++;
    vq_free_desc(vq, (uint32_t)d);

    /* Only acknowledge TX-specific interrupt bit (bit 0 = used buffer).
     * Don't blindly ACK all bits — that would clear pending RX interrupts. */
    uint32_t isr = mmio_read32(netdev.base + VIRTIO_MMIO_INTERRUPT_STATUS);
    if (isr & 1)
        mmio_write32(netdev.base + VIRTIO_MMIO_INTERRUPT_ACK, 1);

    spin_unlock_irqrestore(&net_tx_lock, flags);

    return 0;
}

/*
 * nic_send - Hook into the ethernet layer.
 *
 * This overrides the __weak nic_send() in eth.c.
 */
int nic_send(const void *frame, uint32_t len)
{
    return virtio_net_send(frame, len);
}

/* ============================================================================
 * Initialization
 * ============================================================================ */

/*
 * virtio_net_init - Probe VirtIO MMIO transports for a network device.
 *
 * Scans all 32 VirtIO MMIO transport slots on the QEMU virt machine.
 * Initializes the first network device (device_id == 1) found.
 *
 * Returns 0 on success, -1 if no network device found.
 */
int virtio_net_init(void)
{
    kprintf("[virtio-net] probing %u MMIO transports at 0x%lx\n",
            VIRTIO_MMIO_COUNT, VIRTIO_MMIO_BASE);

    for (uint32_t i = 0; i < VIRTIO_MMIO_COUNT; i++) {
        uint64_t base = VIRTIO_MMIO_BASE + i * VIRTIO_MMIO_STRIDE;
        uint32_t irq  = VIRTIO_MMIO_IRQ_BASE + i;

        /* Check magic */
        uint32_t magic = mmio_read32(base + VIRTIO_MMIO_MAGIC_VALUE);
        if (magic != VIRTIO_MMIO_MAGIC)
            continue;

        uint32_t device_id = mmio_read32(base + VIRTIO_MMIO_DEVICE_ID);
        if (device_id != VIRTIO_DEV_NET)
            continue;

        uint32_t version = mmio_read32(base + VIRTIO_MMIO_VERSION);

        kprintf("[virtio-net] found network device at 0x%lx (version %u)\n",
                base, version);

        /* Initialize device state */
        netdev.base      = base;
        netdev.version   = version;
        netdev.device_id = device_id;
        netdev.irq       = irq;
        netdev.status    = 0;

        /* Reset */
        mmio_write32(base + VIRTIO_MMIO_STATUS, 0);
        dsb();

        /* ACKNOWLEDGE */
        netdev.status = VIRTIO_STATUS_ACKNOWLEDGE;
        mmio_write32(base + VIRTIO_MMIO_STATUS, netdev.status);

        /* DRIVER */
        netdev.status |= VIRTIO_STATUS_DRIVER;
        mmio_write32(base + VIRTIO_MMIO_STATUS, netdev.status);

        /* Negotiate features - we just want basic MAC and no fancy offloads */
        uint64_t driver_features = VIRTIO_NET_F_MAC;
        mmio_write32(base + VIRTIO_MMIO_DEVICE_FEATURES_SEL, 0);
        dsb();
        uint32_t dev_feat = mmio_read32(base + VIRTIO_MMIO_DEVICE_FEATURES);
        uint64_t negotiated = dev_feat & (uint32_t)driver_features;

        mmio_write32(base + VIRTIO_MMIO_DRIVER_FEATURES_SEL, 0);
        dsb();
        mmio_write32(base + VIRTIO_MMIO_DRIVER_FEATURES, (uint32_t)negotiated);

        netdev.features = negotiated;

        if (version >= 2) {
            netdev.status |= VIRTIO_STATUS_FEATURES_OK;
            mmio_write32(base + VIRTIO_MMIO_STATUS, netdev.status);
            dsb();

            uint32_t s = mmio_read32(base + VIRTIO_MMIO_STATUS);
            if (!(s & VIRTIO_STATUS_FEATURES_OK)) {
                kprintf("[virtio-net] device rejected features\n");
                mmio_write32(base + VIRTIO_MMIO_STATUS, VIRTIO_STATUS_FAILED);
                continue;
            }
        }

        /* Read MAC address from device config space.
         * The MAC occupies bytes 0-5 of the device-specific config area.
         * VirtIO MMIO legacy (v1) exposes config as 32-bit registers,
         * but the MAC bytes are packed at consecutive byte offsets.
         * Read two 32-bit words and extract the 6 bytes. */
        if (negotiated & VIRTIO_NET_F_MAC) {
            uint32_t mac_lo = mmio_read32(base + VIRTIO_NET_MAC_OFFSET);
            uint32_t mac_hi = mmio_read32(base + VIRTIO_NET_MAC_OFFSET + 4);
            net_mac[0] = (uint8_t)(mac_lo);
            net_mac[1] = (uint8_t)(mac_lo >> 8);
            net_mac[2] = (uint8_t)(mac_lo >> 16);
            net_mac[3] = (uint8_t)(mac_lo >> 24);
            net_mac[4] = (uint8_t)(mac_hi);
            net_mac[5] = (uint8_t)(mac_hi >> 8);
            kprintf("[virtio-net] MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                    net_mac[0], net_mac[1], net_mac[2],
                    net_mac[3], net_mac[4], net_mac[5]);
            eth_set_mac(net_mac);
        }

        /* Setup RX queue (queue 0) */
        if (virtio_net_setup_queue(&netdev, 0, rxq_pages, sizeof(rxq_pages)) != 0) {
            kprintf("[virtio-net] failed to setup RX queue\n");
            mmio_write32(base + VIRTIO_MMIO_STATUS, VIRTIO_STATUS_FAILED);
            continue;
        }

        /* Setup TX queue (queue 1) */
        if (virtio_net_setup_queue(&netdev, 1, txq_pages, sizeof(txq_pages)) != 0) {
            kprintf("[virtio-net] failed to setup TX queue\n");
            mmio_write32(base + VIRTIO_MMIO_STATUS, VIRTIO_STATUS_FAILED);
            continue;
        }

        /* Mark device as ready */
        netdev.status |= VIRTIO_STATUS_DRIVER_OK;
        mmio_write32(base + VIRTIO_MMIO_STATUS, netdev.status);
        dsb();

        netdev_found = true;

        /* Post initial receive buffers */
        virtio_net_fill_rx();

        kprintf("[virtio-net] device initialized successfully\n");
        return 0;
    }

    kprintf("[virtio-net] no network device found\n");
    return -1;
}

#endif /* PLATFORM_QEMU */
