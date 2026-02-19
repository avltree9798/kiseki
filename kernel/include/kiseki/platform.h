/*
 * Kiseki OS - Platform Abstraction
 *
 * Hardware-specific base addresses and constants for supported platforms.
 * Selected at compile time via PLATFORM_QEMU or PLATFORM_RASPI4.
 */

#ifndef _KISEKI_PLATFORM_H
#define _KISEKI_PLATFORM_H

#include <kiseki/types.h>

/* ============================================================================
 * QEMU virt Machine
 * Reference: QEMU hw/arm/virt.c memory map
 * ============================================================================ */
#if defined(PLATFORM_QEMU)

#define PLATFORM_NAME           "QEMU virt"

/* UART (PL011) */
#define UART0_BASE              0x09000000UL
#define UART0_IRQ               33

/* GICv2 */
#define GICD_BASE               0x08000000UL   /* Distributor */
#define GICC_BASE               0x08010000UL   /* CPU Interface */

/* RAM */
#define RAM_BASE                0x40000000UL
#define RAM_SIZE                0x40000000UL   /* 1GB default */
#define KERNEL_PHYS_BASE        0x40080000UL

/* virtio MMIO (32 transports starting at 0x0a000000, 0x200 apart) */
#define VIRTIO_MMIO_BASE        0x0a000000UL
#define VIRTIO_MMIO_STRIDE      0x200UL
#define VIRTIO_MMIO_COUNT       32
#define VIRTIO_MMIO_IRQ_BASE    48

/* RTC (PL031) */
#define RTC_BASE                0x09010000UL

/* ============================================================================
 * Raspberry Pi 4 (BCM2711)
 * Reference: BCM2711 ARM Peripherals Manual
 * ============================================================================ */
#elif defined(PLATFORM_RASPI4)

#define PLATFORM_NAME           "Raspberry Pi 4"

/* UART (Mini UART / PL011) */
#define UART0_BASE              0xFE201000UL   /* PL011 UART0 */
#define MINI_UART_BASE          0xFE215040UL   /* Mini UART (UART1) */
#define UART0_IRQ               153             /* SPI 121 -> ID 153 */

/* GIC-400 (GICv2) */
#define GICD_BASE               0xFF841000UL
#define GICC_BASE               0xFF842000UL

/* RAM */
#define RAM_BASE                0x00000000UL
#define RAM_SIZE                0x40000000UL   /* 1GB (low memory) */
#define KERNEL_PHYS_BASE        0x00080000UL

/* eMMC / SD */
#define EMMC_BASE               0xFE340000UL

/* Ethernet (GENET) */
#define GENET_BASE              0xFD580000UL

/* GPIO */
#define GPIO_BASE               0xFE200000UL

/* Mailbox */
#define MBOX_BASE               0xFE00B880UL

#else
#error "No platform defined. Pass -DPLATFORM_QEMU or -DPLATFORM_RASPI4"
#endif

/* ============================================================================
 * Common Constants
 * ============================================================================ */

/* Maximum number of CPU cores */
#define MAX_CPUS                4

/* Kernel stack size per CPU (must match linker script) */
#define KERNEL_STACK_SIZE       0x8000  /* 32KB */

#endif /* _KISEKI_PLATFORM_H */
