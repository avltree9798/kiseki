/*
 * Kiseki OS - ARM64 Exception Vector Table
 *
 * Each vector entry is only 128 bytes (32 instructions), so we use
 * a branch to out-of-line handlers that do the full save/restore.
 */

#include <machine/trap.h>

.section .text

/* ============================================================================
 * Macro: Save all registers to a trap frame on the kernel stack.
 * After: x0 = pointer to trap_frame.
 * ============================================================================ */
.macro SAVE_REGS el
    sub     sp, sp, #TF_SIZE

    stp     x0, x1, [sp, #(0 * 8)]
    stp     x2, x3, [sp, #(2 * 8)]
    stp     x4, x5, [sp, #(4 * 8)]
    stp     x6, x7, [sp, #(6 * 8)]
    stp     x8, x9, [sp, #(8 * 8)]
    stp     x10, x11, [sp, #(10 * 8)]
    stp     x12, x13, [sp, #(12 * 8)]
    stp     x14, x15, [sp, #(14 * 8)]
    stp     x16, x17, [sp, #(16 * 8)]
    stp     x18, x19, [sp, #(18 * 8)]
    stp     x20, x21, [sp, #(20 * 8)]
    stp     x22, x23, [sp, #(22 * 8)]
    stp     x24, x25, [sp, #(24 * 8)]
    stp     x26, x27, [sp, #(26 * 8)]
    stp     x28, x29, [sp, #(28 * 8)]
    str     x30, [sp, #(30 * 8)]

    .if \el == 0
        mrs     x0, sp_el0
    .else
        add     x0, sp, #TF_SIZE
    .endif
    str     x0, [sp, #TF_SP]

    mrs     x0, elr_el1
    str     x0, [sp, #TF_ELR]
    mrs     x0, spsr_el1
    str     x0, [sp, #TF_SPSR]
    mrs     x0, esr_el1
    str     x0, [sp, #TF_ESR]
    mrs     x0, far_el1
    str     x0, [sp, #TF_FAR]

    mov     x0, sp
.endm

/* ============================================================================
 * Macro: Restore all registers and return from exception.
 * ============================================================================ */
.macro RESTORE_REGS el
    ldr     x0, [sp, #TF_ELR]
    msr     elr_el1, x0
    ldr     x0, [sp, #TF_SPSR]
    msr     spsr_el1, x0

    .if \el == 0
        ldr     x0, [sp, #TF_SP]
        msr     sp_el0, x0
    .endif

    ldp     x0, x1, [sp, #(0 * 8)]
    ldp     x2, x3, [sp, #(2 * 8)]
    ldp     x4, x5, [sp, #(4 * 8)]
    ldp     x6, x7, [sp, #(6 * 8)]
    ldp     x8, x9, [sp, #(8 * 8)]
    ldp     x10, x11, [sp, #(10 * 8)]
    ldp     x12, x13, [sp, #(12 * 8)]
    ldp     x14, x15, [sp, #(14 * 8)]
    ldp     x16, x17, [sp, #(16 * 8)]
    ldp     x18, x19, [sp, #(18 * 8)]
    ldp     x20, x21, [sp, #(20 * 8)]
    ldp     x22, x23, [sp, #(22 * 8)]
    ldp     x24, x25, [sp, #(24 * 8)]
    ldp     x26, x27, [sp, #(26 * 8)]
    ldp     x28, x29, [sp, #(28 * 8)]
    ldr     x30, [sp, #(30 * 8)]

    add     sp, sp, #TF_SIZE
    eret
.endm

/* ============================================================================
 * Vector Table
 *
 * Each entry is exactly 128 bytes. We just branch to out-of-line handlers.
 * ============================================================================ */
.balign 2048
.global _vectors

_vectors:

/* Current EL with SP_EL0 (unused) */
.balign 128; b _vec_unhandled
.balign 128; b _vec_unhandled
.balign 128; b _vec_unhandled
.balign 128; b _vec_unhandled

/* Current EL with SP_ELx (kernel mode) */
.balign 128; b _handle_el1h_sync
.balign 128; b _handle_el1h_irq
.balign 128; b _vec_unhandled      /* FIQ */
.balign 128; b _vec_unhandled      /* SError */

/* Lower EL using AArch64 (user mode) */
.balign 128; b _handle_el0_sync
.balign 128; b _handle_el0_irq
.balign 128; b _vec_unhandled      /* FIQ */
.balign 128; b _vec_unhandled      /* SError */

/* Lower EL using AArch32 (not supported) */
.balign 128; b _vec_unhandled
.balign 128; b _vec_unhandled
.balign 128; b _vec_unhandled
.balign 128; b _vec_unhandled

/* ============================================================================
 * Out-of-line exception handlers
 * ============================================================================ */

_handle_el1h_sync:
    SAVE_REGS 1
    bl      trap_sync_el1
    RESTORE_REGS 1

_handle_el1h_irq:
    SAVE_REGS 1
    bl      trap_irq_el1
    RESTORE_REGS 1

_handle_el0_sync:
    SAVE_REGS 0
    bl      trap_sync_el0
    RESTORE_REGS 0

_handle_el0_irq:
    SAVE_REGS 0
    bl      trap_irq_el0
    RESTORE_REGS 0

/* ============================================================================
 * fork_child_return - Entry point for a forked child process
 *
 * Called via the scheduler when a forked child thread gets its first
 * context switch. The child thread was set up by sys_fork_impl with:
 *   - context.x30 = fork_child_return
 *   - context.sp  = top of kernel stack (where trap frame is placed)
 *   - context.x19 = pointer to child's vm_space (for TTBR0 switch)
 *
 * The trap frame was placed at the top of the child's kernel stack
 * (kernel_stack + kernel_stack_size - TF_SIZE). SP was set to point
 * there, so on entry here SP points to the trap frame.
 *
 * We need to:
 *   1. Switch to the child's address space (TTBR0)
 *   2. Enable interrupts
 *   3. Restore the trap frame and eret to user mode
 * ============================================================================ */
.global fork_child_return
fork_child_return:
    /* x19 = pointer to child's vm_space (set by thread_create context)
     * vm_space layout: [pgd (8 bytes)][asid (8 bytes)]
     * We need TTBR0 = pgd | (asid << 48) */
    ldr     x0, [x19, #0]      /* x0 = pgd */
    ldr     x1, [x19, #8]      /* x1 = asid */
    orr     x0, x0, x1, lsl #48
    msr     ttbr0_el1, x0
    tlbi    vmalle1             /* Flush TLB — child has a fresh address space */
    dsb     sy
    isb

    /* Enable interrupts (child starts with IRQs masked from context_switch) */
    msr     daifclr, #0x2

    /* SP already points to the trap frame. Do RESTORE_REGS 0 inline. */
    RESTORE_REGS 0

/* ============================================================================
 * Unhandled exception - minimal save and panic
 * ============================================================================ */
_vec_unhandled:
    mrs     x0, esr_el1
    mrs     x1, elr_el1
    mrs     x2, far_el1
    mrs     x3, spsr_el1
    bl      exception_handler_early
    b       _halt
