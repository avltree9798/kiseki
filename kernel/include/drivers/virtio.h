/*
 * Kiseki OS - VirtIO MMIO Device Interface
 *
 * VirtIO over MMIO transport for QEMU virt machine.
 * Implements VirtIO 1.0 (legacy MMIO interface, version 2).
 *
 * Reference: Virtual I/O Device (VIRTIO) Specification v1.1
 *            Section 4.2 - Virtio Over MMIO
 */

#ifndef _DRIVERS_VIRTIO_H
#define _DRIVERS_VIRTIO_H

#include <kiseki/types.h>

/* ============================================================================
 * VirtIO MMIO Register Offsets
 * ============================================================================ */
#define VIRTIO_MMIO_MAGIC_VALUE         0x000   /* 0x74726976 ("virt") */
#define VIRTIO_MMIO_VERSION             0x004   /* Device version (1 = legacy, 2 = 1.0) */
#define VIRTIO_MMIO_DEVICE_ID           0x008   /* Virtio Subsystem Device ID */
#define VIRTIO_MMIO_VENDOR_ID           0x00C   /* Virtio Subsystem Vendor ID */
#define VIRTIO_MMIO_DEVICE_FEATURES     0x010   /* Flags representing features the device supports */
#define VIRTIO_MMIO_DEVICE_FEATURES_SEL 0x014   /* Device feature word selection */
#define VIRTIO_MMIO_DRIVER_FEATURES     0x020   /* Flags representing features understood/activated by driver */
#define VIRTIO_MMIO_DRIVER_FEATURES_SEL 0x024   /* Driver feature word selection */
#define VIRTIO_MMIO_QUEUE_SEL           0x030   /* Virtual queue index */
#define VIRTIO_MMIO_QUEUE_NUM_MAX       0x034   /* Maximum virtual queue size */
#define VIRTIO_MMIO_QUEUE_NUM           0x038   /* Virtual queue size */
#define VIRTIO_MMIO_QUEUE_READY         0x044   /* Virtual queue ready bit */
#define VIRTIO_MMIO_QUEUE_NOTIFY        0x050   /* Queue notifier */
#define VIRTIO_MMIO_INTERRUPT_STATUS    0x060   /* Interrupt status */
#define VIRTIO_MMIO_INTERRUPT_ACK       0x064   /* Interrupt acknowledge */
#define VIRTIO_MMIO_STATUS              0x070   /* Device status */
#define VIRTIO_MMIO_QUEUE_DESC_LOW      0x080   /* Descriptor table address (low 32 bits) */
#define VIRTIO_MMIO_QUEUE_DESC_HIGH     0x084   /* Descriptor table address (high 32 bits) */
#define VIRTIO_MMIO_QUEUE_AVAIL_LOW     0x090   /* Available ring address (low 32 bits) */
#define VIRTIO_MMIO_QUEUE_AVAIL_HIGH    0x094   /* Available ring address (high 32 bits) */
#define VIRTIO_MMIO_QUEUE_USED_LOW      0x0A0   /* Used ring address (low 32 bits) */
#define VIRTIO_MMIO_QUEUE_USED_HIGH     0x0A4   /* Used ring address (high 32 bits) */

/* Legacy (v1) MMIO registers -- QEMU virt uses legacy for -device virtio-blk-device */
#define VIRTIO_MMIO_GUEST_PAGE_SIZE     0x028   /* Guest page size (legacy) */
#define VIRTIO_MMIO_QUEUE_PFN           0x040   /* Queue PFN (legacy) */
#define VIRTIO_MMIO_QUEUE_ALIGN         0x03C   /* Queue alignment (legacy) -- undocumented alias */

/* Expected magic value */
#define VIRTIO_MMIO_MAGIC               0x74726976

/* ============================================================================
 * VirtIO Device Status Bits
 * ============================================================================ */
#define VIRTIO_STATUS_ACKNOWLEDGE        1      /* Guest OS has found the device */
#define VIRTIO_STATUS_DRIVER             2      /* Guest OS knows how to drive the device */
#define VIRTIO_STATUS_DRIVER_OK          4      /* Driver is ready */
#define VIRTIO_STATUS_FEATURES_OK        8      /* Feature negotiation complete */
#define VIRTIO_STATUS_DEVICE_NEEDS_RESET 64     /* Device has experienced an error */
#define VIRTIO_STATUS_FAILED             128    /* Something went wrong, give up */

/* ============================================================================
 * VirtIO Device IDs
 * ============================================================================ */
#define VIRTIO_DEV_NET                  1       /* Network card */
#define VIRTIO_DEV_BLK                  2       /* Block device */
#define VIRTIO_DEV_CONSOLE              3       /* Console */
#define VIRTIO_DEV_ENTROPY              4       /* Entropy source */
#define VIRTIO_DEV_BALLOON              5       /* Memory balloon */
#define VIRTIO_DEV_GPU                  16      /* GPU device */
#define VIRTIO_DEV_INPUT                18      /* Input device */

/* ============================================================================
 * VirtIO Block Device Feature Bits
 * ============================================================================ */
#define VIRTIO_BLK_F_SIZE_MAX           (1UL << 1)
#define VIRTIO_BLK_F_SEG_MAX            (1UL << 2)
#define VIRTIO_BLK_F_GEOMETRY           (1UL << 4)
#define VIRTIO_BLK_F_RO                 (1UL << 5)
#define VIRTIO_BLK_F_BLK_SIZE           (1UL << 6)
#define VIRTIO_BLK_F_FLUSH              (1UL << 9)
#define VIRTIO_BLK_F_TOPOLOGY           (1UL << 10)

/* Common feature bits (high 24-31) */
#define VIRTIO_F_RING_INDIRECT_DESC     (1UL << 28)
#define VIRTIO_F_RING_EVENT_IDX         (1UL << 29)
#define VIRTIO_F_VERSION_1              (1UL << 32)

/* ============================================================================
 * VirtIO Block Request Types
 * ============================================================================ */
#define VIRTIO_BLK_T_IN                 0       /* Read */
#define VIRTIO_BLK_T_OUT               1       /* Write */
#define VIRTIO_BLK_T_FLUSH             4       /* Flush */

/* VirtIO Block Status */
#define VIRTIO_BLK_S_OK                 0
#define VIRTIO_BLK_S_IOERR             1
#define VIRTIO_BLK_S_UNSUPP            2

/* ============================================================================
 * Virtqueue Descriptor Flags
 * ============================================================================ */
#define VIRTQ_DESC_F_NEXT               1       /* Buffer continues via the next field */
#define VIRTQ_DESC_F_WRITE              2       /* Buffer is device write-only (vs read-only) */
#define VIRTQ_DESC_F_INDIRECT           4       /* Buffer contains a list of descriptors */

/* ============================================================================
 * Virtqueue Structures (Section 2.6)
 * ============================================================================ */

/* Virtqueue descriptor (16 bytes) */
struct virtq_desc {
    uint64_t addr;      /* Physical address of buffer */
    uint32_t len;       /* Length of buffer */
    uint16_t flags;     /* VIRTQ_DESC_F_* */
    uint16_t next;      /* Next descriptor index if VIRTQ_DESC_F_NEXT */
} __packed;

/* Virtqueue available ring */
struct virtq_avail {
    uint16_t flags;     /* 1 = no interrupt */
    uint16_t idx;       /* Next index driver will write to */
    uint16_t ring[];    /* Descriptor chain heads */
} __packed;

/* Virtqueue used ring element */
struct virtq_used_elem {
    uint32_t id;        /* Index of start of used descriptor chain */
    uint32_t len;       /* Total bytes written to descriptor buffers */
} __packed;

/* Virtqueue used ring */
struct virtq_used {
    uint16_t flags;     /* 1 = no notification */
    uint16_t idx;       /* Next index device will write to */
    struct virtq_used_elem ring[];
} __packed;

/* Maximum queue size */
#define VIRTQ_MAX_SIZE  256

/* ============================================================================
 * Virtqueue (driver-side state)
 * ============================================================================ */
struct virtqueue {
    uint32_t num;                       /* Number of descriptors */
    uint32_t free_head;                 /* Head of free descriptor list */
    uint32_t num_free;                  /* Number of free descriptors */
    uint16_t last_used_idx;             /* Last used index we processed */
    uint16_t _pad;

    struct virtq_desc  *desc;           /* Descriptor table */
    struct virtq_avail *avail;          /* Available ring */
    struct virtq_used  *used;           /* Used ring */
};

/* ============================================================================
 * VirtIO Device (MMIO transport)
 * ============================================================================ */
struct virtio_device {
    uint64_t base;                      /* MMIO base address */
    uint32_t device_id;                 /* Device type (VIRTIO_DEV_*) */
    uint32_t version;                   /* MMIO version */
    uint32_t irq;                       /* Interrupt number */
    uint32_t status;                    /* Current device status */
    uint64_t features;                  /* Negotiated feature bits */
    struct virtqueue vq[2];             /* Virtqueues (most devices use 1-2) */
};

/* VirtIO block device request header (prepended to every I/O request) */
struct virtio_blk_req {
    uint32_t type;                      /* VIRTIO_BLK_T_IN or _OUT */
    uint32_t reserved;
    uint64_t sector;                    /* Starting sector */
} __packed;

/* ============================================================================
 * VirtIO Functions
 * ============================================================================ */

/*
 * virtio_init_device - Probe and initialize a VirtIO MMIO device
 *
 * @dev:  Device structure to fill in
 * @base: MMIO base address of the transport
 * @irq:  Interrupt number for this transport
 *
 * Returns 0 on success (device found), -1 if no device present.
 */
int virtio_init_device(struct virtio_device *dev, uint64_t base, uint32_t irq);

/*
 * virtio_negotiate_features - Negotiate feature bits with device
 *
 * @dev:              Device to negotiate with
 * @driver_features:  Feature bits the driver supports
 *
 * Reads device features, ANDs with driver features, writes result.
 * Returns the negotiated feature set.
 */
uint64_t virtio_negotiate_features(struct virtio_device *dev,
                                   uint64_t driver_features);

/*
 * virtio_alloc_queue - Allocate and configure a virtqueue
 *
 * @dev:       Device owning the queue
 * @queue_idx: Queue index (0 for requestq, etc.)
 *
 * Allocates descriptor table, available ring, and used ring.
 * Returns 0 on success, -1 on failure.
 */
int virtio_alloc_queue(struct virtio_device *dev, uint32_t queue_idx);

#endif /* _DRIVERS_VIRTIO_H */
