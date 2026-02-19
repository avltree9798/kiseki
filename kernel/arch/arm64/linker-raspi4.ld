/*
 * Kiseki OS - Linker Script for Raspberry Pi 4
 *
 * RPi4 loads kernel8.img at 0x80000 by default.
 * RAM starts at 0x00000000, first 512KB for GPU/firmware.
 *
 * Memory layout:
 *   0x00000000 - 0x0007FFFF  : GPU / firmware reserved (512KB)
 *   0x00080000 - ...         : Kernel image
 *   ...        - 0xFC000000  : Remaining RAM (up to ~4GB, minus MMIO)
 *   0xFC000000 - 0xFFFFFFFF  : Peripheral MMIO (BCM2711)
 *
 * For early boot (MMU off), we link at physical addresses.
 */

ENTRY(_start)

KERNEL_PHYS_BASE = 0x80000;

/* Stack size per CPU core */
KERNEL_STACK_SIZE = 0x8000;  /* 32KB per core */
NUM_CPUS = 4;

MEMORY
{
    RAM (rwx) : ORIGIN = 0x80000, LENGTH = 512M
}

SECTIONS
{
    . = KERNEL_PHYS_BASE;

    /* --- Code Section --- */
    .text : AT(KERNEL_PHYS_BASE)
    {
        __text_start = .;
        *boot.o(.text)
        *vectors.o(.text)
        *(.text .text.*)
        __text_end = .;
    } > RAM

    /* --- Read-only Data --- */
    .rodata : ALIGN(4096)
    {
        __rodata_start = .;
        *(.rodata .rodata.*)
        __rodata_end = .;
    } > RAM

    /* --- Read-write Data --- */
    .data : ALIGN(4096)
    {
        __data_start = .;
        *(.data .data.*)
        __data_end = .;
    } > RAM

    /* --- BSS (Zero-initialized) --- */
    .bss : ALIGN(4096)
    {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    } > RAM

    . = ALIGN(4096);
    __kernel_end = .;

    /* --- Per-CPU Kernel Stacks --- */
    .stack (NOLOAD) : ALIGN(4096)
    {
        __stack_bottom = .;
        . += KERNEL_STACK_SIZE * NUM_CPUS;
        __stack_top = .;
    } > RAM

    . = ALIGN(4096);
    __heap_start = .;

    /DISCARD/ :
    {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}
