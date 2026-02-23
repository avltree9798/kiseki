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
    isb             /* Ensure all prior operations complete before eret */
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
    /*
     * TTBR0 switch with full cache/TLB maintenance (Inner Shareable).
     *
     * x19 = pointer to child's vm_space (set by sys_fork_impl)
     * vm_space layout: [pgd (8 bytes)][asid (8 bytes)]
     * TTBR0 format: pgd | (asid << 48)
     */
    dsb     sy                  /* Ensure ALL page table writes globally visible */
    
    /* Build TTBR0 value: pgd | (asid << 48) */
    ldr     x0, [x19, #0]       /* x0 = pgd (physical address) */
    ldr     x1, [x19, #8]       /* x1 = asid */
    orr     x0, x0, x1, lsl #48
    
    msr     ttbr0_el1, x0       /* Switch to child's address space */
    isb                         /* Context sync - TTBR change takes effect */
    
    tlbi    vmalle1is           /* Invalidate ALL TLB entries (broadcast) */
    dsb     ish                 /* Ensure TLBI completes on all CPUs */
    
    ic      ialluis             /* Invalidate ALL instruction caches (broadcast) */
    dsb     ish                 /* Ensure IC completes on all CPUs */
    isb                         /* Sync instruction stream */

    /*
     * WORKAROUND: Add a delay to allow cache maintenance to fully propagate.
     */
    mov     x0, #0x1000         /* Delay counter */
1:  sub     x0, x0, #1
    cbnz    x0, 1b
    
    /* Second barrier sequence after delay */
    dsb     sy
    isb

    /*
     * DEBUG: Validate trap frame before RESTORE_REGS.
     */
    ldr     x0, [sp, #TF_ELR]       /* x0 = trap frame's ELR (user return PC) */
    
    /* Check if ELR is in kernel RAM range [0x40000000, 0x80000000) */
    mov     x1, #0x4000
    lsl     x1, x1, #16             /* x1 = 0x40000000 (RAM_BASE) */
    cmp     x0, x1
    b.lo    1f                      /* Branch if x0 < 0x40000000 (not in kernel RAM) */
    mov     x1, #0x8000
    lsl     x1, x1, #16             /* x1 = 0x80000000 (RAM_BASE + RAM_SIZE) */
    cmp     x0, x1
    b.hs    1f                      /* Branch if x0 >= 0x80000000 (not in kernel RAM) */
    /* ELR is in kernel RAM range - BUG! */
    mov     x2, x0                  /* Save bad ELR for panic */
    ldr     x3, [sp, #TF_SP]        /* Load user SP for context */
    b       _fork_trapframe_panic
1:

    /* Enable interrupts (child starts with IRQs masked from context_switch) */
    msr     daifclr, #0x2

    /*
     * NUCLEAR OPTION: Complete TLB and I-cache flush right before eret.
     */
    tlbi    vmalle1is
    dsb     sy
    ic      ialluis
    dsb     sy
    isb

    /* SP already points to the trap frame. Do RESTORE_REGS 0 inline. */
    RESTORE_REGS 0

/*
 * _fork_trapframe_panic - Called when fork_child_return detects bad trap frame
 * x2 = ELR value, x3 = SP value
 */
_fork_trapframe_panic:
    /* Call panic with trap frame info */
    /* For now, just halt - proper panic would need stack setup */
    mov     x0, x2      /* Pass ELR as arg */
    mov     x1, x3      /* Pass SP as arg */
    bl      fork_trapframe_panic_c
    b       _halt

/* ============================================================================
 * init_thread_return - Entry point for the init (PID 1) process thread
 *
 * Called via the scheduler when init's thread gets its first context
 * switch. The thread was set up by kernel_init_process() with:
 *   - context.x30 = init_thread_return
 *   - context.sp  = top of kernel stack (where trap frame is placed)
 *   - context.x19 = pointer to init's vm_space (for TTBR0 switch)
 *
 * Identical flow to fork_child_return:
 *   1. Switch to init's address space (TTBR0)
 *   2. Enable interrupts
 *   3. Restore the trap frame and eret to user mode
 * ============================================================================ */
.global init_thread_return
init_thread_return:
    /* x19 = pointer to init's vm_space
     * vm_space layout: [pgd (8 bytes)][asid (8 bytes)]
     * TTBR0 = pgd | (asid << 48) */
    dsb     sy                  /* Ensure ALL page table writes globally visible */

    ldr     x0, [x19, #0]       /* x0 = pgd */
    ldr     x1, [x19, #8]       /* x1 = asid */
    orr     x0, x0, x1, lsl #48
    msr     ttbr0_el1, x0
    isb

    tlbi    vmalle1is
    dsb     ish
    ic      ialluis
    dsb     ish
    isb

    /* Enable interrupts (thread starts with IRQs masked from context_switch) */
    msr     daifclr, #0x2

    /* SP already points to the trap frame. Restore and eret to EL0. */
    RESTORE_REGS 0

/* ============================================================================
 * user_thread_return - Entry point for newly created user threads (pthread)
 *
 * Called via the scheduler when a pthread_create'd thread gets its first
 * context switch. The thread was set up by thread_create_user with:
 *   - context.x30 = user_thread_return
 *   - context.sp  = top of kernel stack (where trap frame is placed)
 *   - context.x19 = pointer to task's vm_space (for TTBR0 switch)
 *   - context.x20 = TLS base address (for TPIDR_EL0)
 *
 * We need to:
 *   1. Switch to the thread's address space (TTBR0) - same as task
 *   2. Set up TLS base in TPIDR_EL0
 *   3. Enable interrupts
 *   4. Restore the trap frame and eret to user mode
 * ============================================================================ */
.global user_thread_return
user_thread_return:
    /* x19 = pointer to task's vm_space (set by thread_create_user context)
     * vm_space layout: [pgd (8 bytes)][asid (8 bytes)]
     * We need TTBR0 = pgd | (asid << 48) */
    dsb     sy                  /* Ensure prior stores visible */
    
    ldr     x0, [x19, #0]       /* x0 = pgd */
    ldr     x1, [x19, #8]       /* x1 = asid */
    orr     x0, x0, x1, lsl #48
    msr     ttbr0_el1, x0
    isb                         /* Ensure TTBR0 change takes effect */
    
    /* Full TLB and I-cache invalidation for SMP correctness */
    tlbi    vmalle1is
    dsb     ish
    ic      ialluis
    dsb     ish
    isb

    /* x20 = TLS base address - set TPIDR_EL0 for user-space pthread TLS */
    msr     tpidr_el0, x20

    /* Enable interrupts (thread starts with IRQs masked from context_switch) */
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

.section .text
