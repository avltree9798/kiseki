/*
 * Kiseki OS - Block Device Abstraction Layer
 *
 * Platform-agnostic block device interface. Routes block I/O requests
 * to the appropriate backend driver:
 *   - QEMU:     VirtIO block device (virtio_blk)
 *   - Raspi 4:  eMMC/SD controller (emmc)
 *
 * Additional block devices (NVMe, USB mass storage, etc.) can be
 * registered at runtime via blkdev_register().
 */

#ifndef _DRIVERS_BLKDEV_H
#define _DRIVERS_BLKDEV_H

#include <kiseki/types.h>

/* ============================================================================
 * Block Device Operations
 * ============================================================================ */

/* IOCTL command codes */
#define BLKDEV_IOCTL_GET_SIZE       1   /* Get device size in sectors */
#define BLKDEV_IOCTL_GET_BLKSIZE    2   /* Get sector size in bytes */
#define BLKDEV_IOCTL_FLUSH          3   /* Flush write cache */

struct blkdev_ops {
    /*
     * read - Read sectors from the device
     *
     * @sector:  Starting sector number (512-byte sectors)
     * @buf:     Destination buffer
     * @count:   Number of sectors to read
     *
     * Returns 0 on success, -1 on error.
     */
    int (*read)(uint64_t sector, void *buf, uint32_t count);

    /*
     * write - Write sectors to the device
     *
     * @sector:  Starting sector number (512-byte sectors)
     * @buf:     Source buffer
     * @count:   Number of sectors to write
     *
     * Returns 0 on success, -1 on error.
     */
    int (*write)(uint64_t sector, void *buf, uint32_t count);

    /*
     * ioctl - Device-specific control operations
     *
     * @cmd:   BLKDEV_IOCTL_* command
     * @arg:   Command-specific argument
     *
     * Returns 0 on success, -1 on error or unsupported command.
     */
    int (*ioctl)(uint32_t cmd, uint64_t arg);
};

/* ============================================================================
 * Block Device Descriptor
 * ============================================================================ */

/* Maximum number of registered block devices */
#define BLKDEV_MAX  8

struct blkdev {
    const char          *name;      /* Human-readable name (e.g. "virtio0") */
    uint32_t            dev_id;     /* Device number */
    uint32_t            sector_size;/* Sector size in bytes (typically 512) */
    uint64_t            capacity;   /* Total sectors */
    struct blkdev_ops   *ops;       /* I/O operations */
    bool                active;     /* Device is initialized and usable */
};

/* ============================================================================
 * Block Device API
 * ============================================================================ */

/*
 * blkdev_init - Initialize the block device subsystem
 *
 * Probes the platform-appropriate block device driver:
 *   - PLATFORM_QEMU:   calls virtio_blk_init()
 *   - PLATFORM_RASPI4: calls emmc_init()
 *
 * Returns 0 on success, -1 if no block device could be initialized.
 */
int blkdev_init(void);

/*
 * blkdev_register - Register a block device
 *
 * @name:        Human-readable name
 * @ops:         I/O operations table
 * @sector_size: Sector size in bytes
 * @capacity:    Total number of sectors
 *
 * Returns the assigned device number (>= 0), or -1 on failure.
 */
int blkdev_register(const char *name, struct blkdev_ops *ops,
                    uint32_t sector_size, uint64_t capacity);

/*
 * blkdev_read - Read sectors from a block device
 *
 * @dev:     Device number (from blkdev_register)
 * @sector:  Starting sector
 * @buf:     Destination buffer
 * @count:   Number of sectors
 *
 * Returns 0 on success, -1 on error.
 */
int blkdev_read(uint32_t dev, uint64_t sector, void *buf, uint32_t count);

/*
 * blkdev_write - Write sectors to a block device
 *
 * @dev:     Device number (from blkdev_register)
 * @sector:  Starting sector
 * @buf:     Source buffer
 * @count:   Number of sectors
 *
 * Returns 0 on success, -1 on error.
 */
int blkdev_write(uint32_t dev, uint64_t sector, void *buf, uint32_t count);

/*
 * blkdev_ioctl - Perform a control operation on a block device
 *
 * @dev:  Device number
 * @cmd:  BLKDEV_IOCTL_* command
 * @arg:  Command argument
 *
 * Returns 0 on success, -1 on error.
 */
int blkdev_ioctl(uint32_t dev, uint32_t cmd, uint64_t arg);

/*
 * blkdev_get - Get the blkdev descriptor for a device number
 *
 * Returns pointer to the blkdev struct, or NULL if invalid/inactive.
 */
struct blkdev *blkdev_get(uint32_t dev);

/* ============================================================================
 * Platform Backend Declarations
 *
 * These are implemented in the platform-specific driver files:
 *   kernel/drivers/virtio/virtio_blk.c  (PLATFORM_QEMU)
 *   kernel/drivers/emmc/emmc.c          (PLATFORM_RASPI4)
 * ============================================================================ */

#if defined(PLATFORM_QEMU)

int virtio_blk_init(void);
int virtio_blk_read(uint64_t sector, void *buf, uint32_t count);
int virtio_blk_write(uint64_t sector, void *buf, uint32_t count);

#elif defined(PLATFORM_RASPI4)

int emmc_init(void);
int emmc_read(uint64_t sector, void *buf, uint32_t count);
int emmc_write(uint64_t sector, void *buf, uint32_t count);

#endif

#endif /* _DRIVERS_BLKDEV_H */
