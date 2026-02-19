/*
 * Kiseki OS - ARM64 Boot Code
 *
 * Entry point for the kernel. Runs at EL2 (QEMU) or EL1 (RPi4 default).
 *
 * Boot sequence:
 *   1. Identify CPU core (only core 0 proceeds, others spin)
 *   2. Drop from EL2 to EL1 if necessary
 *   3. Configure system registers
 *   4. Set up kernel stack
 *   5. Clear BSS
 *   6. Jump to kmain()
 */

.section .text
.global _start
.global _secondary_entry

/* ============================================================================
 * Primary Entry Point
 * ============================================================================ */
_start:
    /* Read core ID from MPIDR_EL1 */
    mrs     x0, mpidr_el1
    and     x0, x0, #0xFF          /* Extract Aff0 (core number) */
    cbnz    x0, _secondary_spin    /* If not core 0, go to spin loop */

    /* --- Core 0 boot path --- */

    /* Check current exception level */
    mrs     x0, CurrentEL
    and     x0, x0, #0xC           /* Extract EL bits */
    cmp     x0, #0x8               /* EL2 = 0b1000 */
    b.eq    _from_el2
    cmp     x0, #0x4               /* EL1 = 0b0100 */
    b.eq    _at_el1
    /* EL3 not expected on these platforms */
    b       _halt

/* Drop from EL2 to EL1 */
_from_el2:
    /* Configure HCR_EL2: RW=1 (AArch64 at EL1) */
    mov     x0, #(1 << 31)         /* HCR_EL2.RW */
    msr     hcr_el2, x0

    /* Don't trap FP/SIMD at EL2 (CPTR_EL2.TFP = 0) */
    msr     cptr_el2, xzr

    /* Configure SPSR_EL2: Return to EL1h with interrupts masked */
    mov     x0, #0x3C5             /* D=1,A=1,I=1,F=1, M[4:0]=00101 (EL1h) */
    msr     spsr_el2, x0

    /* Set return address to _at_el1 */
    adr     x0, _at_el1
    msr     elr_el2, x0

    /* Return to EL1 */
    eret

/* Now running at EL1 */
_at_el1:
    /* Disable MMU and caches initially */
    mrs     x0, sctlr_el1
    bic     x0, x0, #(1 << 0)     /* M: MMU off */
    bic     x0, x0, #(1 << 2)     /* C: Data cache off */
    bic     x0, x0, #(1 << 12)    /* I: Instruction cache off */
    msr     sctlr_el1, x0
    isb

    /*
     * Enable FP/SIMD access for EL1 and EL0.
     * CPACR_EL1.FPEN (bits [21:20]) = 0b11: no trapping.
     * Without this, any FP/SIMD instruction from EL0 traps with EC=0x7.
     */
    mov     x0, #(3 << 20)         /* FPEN = 0b11 */
    msr     cpacr_el1, x0
    isb

    /* Set up exception vector table */
    ldr     x0, =_vectors
    msr     vbar_el1, x0
    isb

    /* Set up kernel stack for core 0
     * Stack grows downward: SP = __stack_top - (core_id * STACK_SIZE)
     * Core 0: SP = __stack_top
     */
    ldr     x0, =__stack_top
    mov     sp, x0

    /* Clear BSS */
    ldr     x0, =__bss_start
    ldr     x1, =__bss_end
_bss_clear:
    cmp     x0, x1
    b.ge    _bss_done
    str     xzr, [x0], #8
    b       _bss_clear
_bss_done:

    /* Jump to C entry point
     * x0 = DTB pointer (passed by QEMU in x0 at entry, but we clobbered it)
     * For now, pass 0 - we'll fix DTB passing later
     */
    mov     x0, #0
    bl      kmain

    /* kmain should not return, but if it does: */
    b       _halt

/* ============================================================================
 * Secondary Core Entry (called via PSCI or spin-table)
 * ============================================================================ */
_secondary_entry:
    /* x0 = core ID (set by caller or read from MPIDR) */
    mrs     x0, mpidr_el1
    and     x0, x0, #0xFF

    /* Check exception level and drop to EL1 if needed */
    mrs     x1, CurrentEL
    and     x1, x1, #0xC
    cmp     x1, #0x8
    b.ne    _secondary_at_el1

    /* EL2 -> EL1 drop for secondary */
    mov     x1, #(1 << 31)
    msr     hcr_el2, x1
    mov     x1, #0x3C5
    msr     spsr_el2, x1
    adr     x1, _secondary_at_el1
    msr     elr_el2, x1
    eret

_secondary_at_el1:
    /* Re-read core ID (may have been lost in EL drop) */
    mrs     x0, mpidr_el1
    and     x0, x0, #0xFF

    /* Set up per-core stack
     * SP = __stack_top - (core_id * KERNEL_STACK_SIZE)
     */
    ldr     x1, =__stack_top
    mov     x2, #0x4000            /* KERNEL_STACK_SIZE = 16KB */
    mul     x3, x0, x2
    sub     x1, x1, x3
    mov     sp, x1

    /* Set exception vectors */
    ldr     x1, =_vectors
    msr     vbar_el1, x1
    isb

    /* Jump to C secondary entry: secondary_main(core_id) */
    bl      secondary_main

    b       _halt

/* ============================================================================
 * Secondary Core Spin Loop (wait for wakeup)
 * ============================================================================ */
_secondary_spin:
    wfe                             /* Wait For Event - low power idle */
    b       _secondary_spin

/* ============================================================================
 * Halt
 * ============================================================================ */
.global _halt
_halt:
    wfi
    b       _halt
