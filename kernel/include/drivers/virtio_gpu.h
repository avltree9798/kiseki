/*
 * Kiseki OS - VirtIO GPU Device Interface
 *
 * VirtIO GPU 2D framebuffer driver definitions.
 * Implements the subset of VirtIO GPU needed for a simple linear
 * framebuffer: resource creation, backing attachment, scanout
 * configuration, transfer, and flush.
 *
 * Reference: Virtual I/O Device (VIRTIO) Specification v1.2
 *            Section 5.7 — GPU Device
 */

#ifndef _DRIVERS_VIRTIO_GPU_H
#define _DRIVERS_VIRTIO_GPU_H

#include <kiseki/types.h>

/* ============================================================================
 * VirtIO GPU Feature Bits
 * ============================================================================ */
#define VIRTIO_GPU_F_VIRGL          (1UL << 0)  /* virgl 3D mode */
#define VIRTIO_GPU_F_EDID           (1UL << 1)  /* EDID support */
#define VIRTIO_GPU_F_RESOURCE_UUID  (1UL << 2)  /* Resource UUID export */
#define VIRTIO_GPU_F_RESOURCE_BLOB  (1UL << 3)  /* Blob resources */
#define VIRTIO_GPU_F_CONTEXT_INIT   (1UL << 4)  /* Multiple context types */

/* ============================================================================
 * VirtIO GPU Device Configuration
 * ============================================================================ */
#define VIRTIO_GPU_EVENT_DISPLAY    (1 << 0)

struct virtio_gpu_config {
    uint32_t events_read;       /* Pending events (read-only by driver) */
    uint32_t events_clear;      /* Write-1-to-clear bits in events_read */
    uint32_t num_scanouts;      /* Max scanouts supported (1..16) */
    uint32_t num_capsets;       /* Max capability sets (0 if no 3D) */
} __packed;

/* ============================================================================
 * VirtIO GPU Command / Response Types
 * ============================================================================ */

/* 2D commands */
#define VIRTIO_GPU_CMD_GET_DISPLAY_INFO         0x0100
#define VIRTIO_GPU_CMD_RESOURCE_CREATE_2D       0x0101
#define VIRTIO_GPU_CMD_RESOURCE_UNREF           0x0102
#define VIRTIO_GPU_CMD_SET_SCANOUT              0x0103
#define VIRTIO_GPU_CMD_RESOURCE_FLUSH           0x0104
#define VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D      0x0105
#define VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING  0x0106
#define VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING  0x0107
#define VIRTIO_GPU_CMD_GET_CAPSET_INFO          0x0108
#define VIRTIO_GPU_CMD_GET_CAPSET               0x0109
#define VIRTIO_GPU_CMD_GET_EDID                 0x010a
#define VIRTIO_GPU_CMD_RESOURCE_ASSIGN_UUID     0x010b
#define VIRTIO_GPU_CMD_RESOURCE_CREATE_BLOB     0x010c
#define VIRTIO_GPU_CMD_SET_SCANOUT_BLOB         0x010d

/* Cursor commands */
#define VIRTIO_GPU_CMD_UPDATE_CURSOR            0x0300
#define VIRTIO_GPU_CMD_MOVE_CURSOR              0x0301

/* Success responses */
#define VIRTIO_GPU_RESP_OK_NODATA               0x1100
#define VIRTIO_GPU_RESP_OK_DISPLAY_INFO         0x1101
#define VIRTIO_GPU_RESP_OK_CAPSET_INFO          0x1102
#define VIRTIO_GPU_RESP_OK_CAPSET               0x1103
#define VIRTIO_GPU_RESP_OK_EDID                 0x1104
#define VIRTIO_GPU_RESP_OK_RESOURCE_UUID        0x1105
#define VIRTIO_GPU_RESP_OK_MAP_INFO             0x1106

/* Error responses */
#define VIRTIO_GPU_RESP_ERR_UNSPEC              0x1200
#define VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY       0x1201
#define VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID  0x1202
#define VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID 0x1203
#define VIRTIO_GPU_RESP_ERR_INVALID_CONTEXT_ID  0x1204
#define VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER   0x1205

/* ============================================================================
 * VirtIO GPU Control Header (base for all commands/responses)
 * ============================================================================ */
#define VIRTIO_GPU_FLAG_FENCE           (1 << 0)
#define VIRTIO_GPU_FLAG_INFO_RING_IDX   (1 << 1)

struct virtio_gpu_ctrl_hdr {
    uint32_t type;          /* VIRTIO_GPU_CMD_* or VIRTIO_GPU_RESP_* */
    uint32_t flags;         /* Request/response flags */
    uint64_t fence_id;      /* Fence ID for synchronisation */
    uint32_t ctx_id;        /* Rendering context (3D mode only) */
    uint8_t  ring_idx;      /* Context-specific ring index */
    uint8_t  padding[3];
} __packed;

/* ============================================================================
 * VirtIO GPU Pixel Formats
 *
 * Naming: byte order from low address to high address.
 * E.g., B8G8R8A8 = byte 0=B, byte 1=G, byte 2=R, byte 3=A.
 * All formats are 32 bits per pixel, unsigned normalised.
 * ============================================================================ */
#define VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM    1
#define VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM    2
#define VIRTIO_GPU_FORMAT_A8R8G8B8_UNORM    3
#define VIRTIO_GPU_FORMAT_X8R8G8B8_UNORM    4
#define VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM    67
#define VIRTIO_GPU_FORMAT_X8B8G8R8_UNORM    68
#define VIRTIO_GPU_FORMAT_A8B8G8R8_UNORM    121
#define VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM    134

/* ============================================================================
 * VirtIO GPU Geometry Types
 * ============================================================================ */

struct virtio_gpu_rect {
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
} __packed;

/* ============================================================================
 * VirtIO GPU Display Info
 * ============================================================================ */
#define VIRTIO_GPU_MAX_SCANOUTS 16

struct virtio_gpu_display_one {
    struct virtio_gpu_rect r;   /* Preferred position and size */
    uint32_t enabled;           /* 1 if display is enabled/connected */
    uint32_t flags;             /* Reserved */
} __packed;

struct virtio_gpu_resp_display_info {
    struct virtio_gpu_ctrl_hdr hdr;
    struct virtio_gpu_display_one pmodes[VIRTIO_GPU_MAX_SCANOUTS];
} __packed;

/* ============================================================================
 * VirtIO GPU 2D Commands
 * ============================================================================ */

/* RESOURCE_CREATE_2D */
struct virtio_gpu_resource_create_2d {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t resource_id;       /* Guest-chosen unique resource ID */
    uint32_t format;            /* VIRTIO_GPU_FORMAT_* */
    uint32_t width;
    uint32_t height;
} __packed;

/* RESOURCE_UNREF */
struct virtio_gpu_resource_unref {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t resource_id;
    uint32_t padding;
} __packed;

/* SET_SCANOUT */
struct virtio_gpu_set_scanout {
    struct virtio_gpu_ctrl_hdr hdr;
    struct virtio_gpu_rect r;   /* Region within the resource to display */
    uint32_t scanout_id;        /* Which display/scanout */
    uint32_t resource_id;       /* Resource to scan out (0 = disable) */
} __packed;

/* RESOURCE_FLUSH */
struct virtio_gpu_resource_flush {
    struct virtio_gpu_ctrl_hdr hdr;
    struct virtio_gpu_rect r;   /* Rectangle to flush */
    uint32_t resource_id;
    uint32_t padding;
} __packed;

/* TRANSFER_TO_HOST_2D */
struct virtio_gpu_transfer_to_host_2d {
    struct virtio_gpu_ctrl_hdr hdr;
    struct virtio_gpu_rect r;   /* Rectangle to transfer */
    uint64_t offset;            /* Byte offset into backing store */
    uint32_t resource_id;
    uint32_t padding;
} __packed;

/* RESOURCE_ATTACH_BACKING */
struct virtio_gpu_resource_attach_backing {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t resource_id;
    uint32_t nr_entries;        /* Number of virtio_gpu_mem_entry following */
} __packed;

/* Scatter-gather entry for backing pages */
struct virtio_gpu_mem_entry {
    uint64_t addr;              /* Guest physical address */
    uint32_t length;            /* Length in bytes */
    uint32_t padding;
} __packed;

/* RESOURCE_DETACH_BACKING */
struct virtio_gpu_resource_detach_backing {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t resource_id;
    uint32_t padding;
} __packed;

/* ============================================================================
 * VirtIO GPU Cursor Commands
 * ============================================================================ */

struct virtio_gpu_cursor_pos {
    uint32_t scanout_id;
    uint32_t x;
    uint32_t y;
    uint32_t padding;
} __packed;

struct virtio_gpu_update_cursor {
    struct virtio_gpu_ctrl_hdr hdr;
    struct virtio_gpu_cursor_pos pos;
    uint32_t resource_id;       /* Cursor resource (0 = no cursor) */
    uint32_t hot_x;             /* Hotspot X */
    uint32_t hot_y;             /* Hotspot Y */
    uint32_t padding;
} __packed;

/* ============================================================================
 * Framebuffer Configuration (exported by driver)
 * ============================================================================ */

struct framebuffer_info {
    uint64_t phys_addr;         /* Physical address of framebuffer memory */
    uint32_t width;             /* Width in pixels */
    uint32_t height;            /* Height in pixels */
    uint32_t pitch;             /* Bytes per row (stride) */
    uint32_t bpp;               /* Bits per pixel (32) */
    uint32_t format;            /* VIRTIO_GPU_FORMAT_* */
    bool     active;            /* true if GPU is initialised and scanout set */
};

/* ============================================================================
 * VirtIO GPU Driver API
 * ============================================================================ */

/*
 * virtio_gpu_init - Probe VirtIO MMIO transports for a GPU device
 *
 * Scans all 32 MMIO slots, initialises the first GPU found, creates
 * a 2D resource, attaches backing pages, and sets up scanout 0.
 *
 * Returns 0 on success, -1 if no GPU found or initialisation failed.
 */
int virtio_gpu_init(void);

/*
 * virtio_gpu_flush - Transfer dirty rectangle to host and flush to display
 *
 * @x, @y:     Top-left corner of dirty rectangle
 * @width, @height: Size of dirty rectangle
 *
 * Sends TRANSFER_TO_HOST_2D followed by RESOURCE_FLUSH.
 * Call this after rendering into the framebuffer to update the display.
 */
void virtio_gpu_flush(uint32_t x, uint32_t y, uint32_t width, uint32_t height);

/*
 * virtio_gpu_flush_all - Flush the entire framebuffer to display
 *
 * Convenience wrapper for virtio_gpu_flush(0, 0, fb_width, fb_height).
 */
void virtio_gpu_flush_all(void);

/*
 * virtio_gpu_get_fb - Get framebuffer information
 *
 * Returns a pointer to the framebuffer info struct, or NULL if
 * no GPU is initialised.
 */
const struct framebuffer_info *virtio_gpu_get_fb(void);

/*
 * virtio_gpu_irq_handler - Handle VirtIO GPU interrupt
 *
 * Called from irq_dispatch() when the GPU's MMIO slot interrupt fires.
 * Acknowledges the interrupt and processes any used buffers.
 */
void virtio_gpu_irq_handler(void);

/*
 * virtio_gpu_get_irq - Get the GIC IRQ number for the GPU device
 *
 * Returns the IRQ number, or 0 if no GPU device is initialised.
 * Used by irq_dispatch() to route the correct VirtIO MMIO interrupt.
 */
uint32_t virtio_gpu_get_irq(void);

#endif /* _DRIVERS_VIRTIO_GPU_H */
