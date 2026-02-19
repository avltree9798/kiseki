/*
 * Kiseki OS - Raspberry Pi eMMC/SD Driver (Stub)
 *
 * Stub implementation for the BCM2711 eMMC controller on the
 * Raspberry Pi 4.  Provides the same block I/O interface as the
 * VirtIO block driver so the buffer cache and filesystem layers
 * work identically on both platforms.
 *
 * TODO: Implement actual eMMC initialization (clock setup, CMD0/CMD8/
 *       ACMD41/CMD2/CMD3 sequence), data transfer via ADMA2, and
 *       interrupt handling.
 *
 * Reference: BCM2711 ARM Peripherals Manual, Section 5 - EMMC
 *            SD Host Controller Simplified Specification v3.00
 */

#include <kiseki/types.h>
#include <kiseki/platform.h>
#include <kern/kprintf.h>

#ifdef PLATFORM_RASPI4

/*
 * emmc_init - Initialize the eMMC controller
 *
 * Returns 0 on success, -1 on failure.
 */
int emmc_init(void)
{
    kprintf("[emmc] stub: eMMC driver not yet implemented\n");
    kprintf("[emmc] EMMC_BASE = 0x%lx\n", (uint64_t)EMMC_BASE);
    return -1;
}

/*
 * emmc_read - Read sectors from the eMMC device
 *
 * @sector:  Starting sector number (512-byte sectors)
 * @buf:     Destination buffer
 * @count:   Number of sectors to read
 *
 * Returns 0 on success, -1 on failure.
 */
int emmc_read(uint64_t sector, void *buf, uint32_t count)
{
    (void)sector;
    (void)buf;
    (void)count;
    return -1;
}

/*
 * emmc_write - Write sectors to the eMMC device
 *
 * @sector:  Starting sector number (512-byte sectors)
 * @buf:     Source buffer
 * @count:   Number of sectors to write
 *
 * Returns 0 on success, -1 on failure.
 */
int emmc_write(uint64_t sector, void *buf, uint32_t count)
{
    (void)sector;
    (void)buf;
    (void)count;
    return -1;
}

#endif /* PLATFORM_RASPI4 */
