/*
 * Kiseki OS - Block Device Abstraction Layer
 *
 * Platform-agnostic block device registration and dispatch.
 * Routes I/O requests to the correct backend driver based on
 * the device number assigned during registration.
 *
 * On QEMU:   initializes virtio_blk and registers it as device 0.
 * On Raspi4: initializes eMMC and registers it as device 0.
 */

#include <kiseki/types.h>
#include <kiseki/platform.h>
#include <kern/kprintf.h>
#include <kern/sync.h>
#include <drivers/blkdev.h>

/* ============================================================================
 * Device Table
 * ============================================================================ */

static struct blkdev devices[BLKDEV_MAX];
static uint32_t num_devices = 0;
static spinlock_t blkdev_lock = SPINLOCK_INIT;

/* ============================================================================
 * Platform Backend Wrappers
 * ============================================================================ */

#if defined(PLATFORM_QEMU)

static int platform_blk_read(uint64_t sector, void *buf, uint32_t count)
{
    return virtio_blk_read(sector, buf, count);
}

static int platform_blk_write(uint64_t sector, void *buf, uint32_t count)
{
    return virtio_blk_write(sector, buf, count);
}

static int platform_blk_ioctl(uint32_t cmd, uint64_t arg)
{
    (void)cmd;
    (void)arg;
    return -1;  /* Not yet implemented */
}

static struct blkdev_ops platform_blk_ops = {
    .read  = platform_blk_read,
    .write = platform_blk_write,
    .ioctl = platform_blk_ioctl,
};

#elif defined(PLATFORM_RASPI4)

static int platform_blk_read(uint64_t sector, void *buf, uint32_t count)
{
    return emmc_read(sector, buf, count);
}

static int platform_blk_write(uint64_t sector, void *buf, uint32_t count)
{
    return emmc_write(sector, buf, count);
}

static int platform_blk_ioctl(uint32_t cmd, uint64_t arg)
{
    (void)cmd;
    (void)arg;
    return -1;
}

static struct blkdev_ops platform_blk_ops = {
    .read  = platform_blk_read,
    .write = platform_blk_write,
    .ioctl = platform_blk_ioctl,
};

#endif

/* ============================================================================
 * Public API
 * ============================================================================ */

int blkdev_init(void)
{
    /* Zero out device table */
    for (uint32_t i = 0; i < BLKDEV_MAX; i++) {
        devices[i].active = false;
        devices[i].ops = NULL;
    }
    num_devices = 0;

    kprintf("[blkdev] initializing block device subsystem\n");

    int ret;

#if defined(PLATFORM_QEMU)
    ret = virtio_blk_init();
    if (ret != 0) {
        kprintf("[blkdev] virtio_blk_init failed\n");
        return -1;
    }
    ret = blkdev_register("virtio0", &platform_blk_ops, 512, 0);
#elif defined(PLATFORM_RASPI4)
    ret = emmc_init();
    if (ret != 0) {
        kprintf("[blkdev] emmc_init failed\n");
        return -1;
    }
    ret = blkdev_register("emmc0", &platform_blk_ops, 512, 0);
#else
    ret = -1;
#endif

    if (ret < 0) {
        kprintf("[blkdev] failed to register platform block device\n");
        return -1;
    }

    kprintf("[blkdev] platform block device registered as dev %d\n", ret);
    return 0;
}

int blkdev_register(const char *name, struct blkdev_ops *ops,
                    uint32_t sector_size, uint64_t capacity)
{
    uint64_t flags;
    spin_lock_irqsave(&blkdev_lock, &flags);

    if (num_devices >= BLKDEV_MAX) {
        spin_unlock_irqrestore(&blkdev_lock, flags);
        kprintf("[blkdev] device table full\n");
        return -1;
    }

    uint32_t id = num_devices;
    struct blkdev *dev = &devices[id];

    dev->name = name;
    dev->dev_id = id;
    dev->sector_size = sector_size;
    dev->capacity = capacity;
    dev->ops = ops;
    dev->active = true;
    num_devices++;

    spin_unlock_irqrestore(&blkdev_lock, flags);

    kprintf("[blkdev] registered '%s' as dev %u (sector_size=%u)\n",
            name, id, sector_size);
    return (int)id;
}

int blkdev_read(uint32_t dev, uint64_t sector, void *buf, uint32_t count)
{
    if (dev >= BLKDEV_MAX || !devices[dev].active || !devices[dev].ops)
        return -1;
    if (!devices[dev].ops->read)
        return -1;
    return devices[dev].ops->read(sector, buf, count);
}

int blkdev_write(uint32_t dev, uint64_t sector, void *buf, uint32_t count)
{
    if (dev >= BLKDEV_MAX || !devices[dev].active || !devices[dev].ops)
        return -1;
    if (!devices[dev].ops->write)
        return -1;
    return devices[dev].ops->write(sector, buf, count);
}

int blkdev_ioctl(uint32_t dev, uint32_t cmd, uint64_t arg)
{
    if (dev >= BLKDEV_MAX || !devices[dev].active || !devices[dev].ops)
        return -1;
    if (!devices[dev].ops->ioctl)
        return -1;
    return devices[dev].ops->ioctl(cmd, arg);
}

struct blkdev *blkdev_get(uint32_t dev)
{
    if (dev >= BLKDEV_MAX || !devices[dev].active)
        return NULL;
    return &devices[dev];
}
