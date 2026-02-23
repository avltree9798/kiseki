/*
 * Kiseki OS - ARM64 Context Switch
 *
 * Saves and restores thread register state for the scheduler.
 * Saves callee-saved registers (x19-x30), SP, and restores them
 * on the new thread's context.
 */

.section .text
.global context_switch

/*
 * context_switch(old_ctx, new_ctx)
 *
 * x0 = pointer to old thread's saved register context (uint64_t[32])
 * x1 = pointer to new thread's saved register context (uint64_t[32])
 *
 * Saves callee-saved registers (x19-x30, SP) to old context,
 * restores them from new context, and returns.
 */
context_switch:
    /* Save callee-saved registers to old context */
    stp     x19, x20, [x0, #0]
    stp     x21, x22, [x0, #16]
    stp     x23, x24, [x0, #32]
    stp     x25, x26, [x0, #48]
    stp     x27, x28, [x0, #64]
    stp     x29, x30, [x0, #80]    /* x29=FP, x30=LR */
    mov     x2, sp
    str     x2, [x0, #96]           /* Save SP */

    /*
     * DEBUG: After saving to old_ctx, verify what we just saved.
     * x30 saved at [x0, #88], SP saved at [x0, #96].
     * They should both be kernel addresses (0x40000000-0x80000000).
     */
    ldr     x3, [x0, #88]           /* x3 = saved x30 */
    ldr     x4, [x0, #96]           /* x4 = saved SP */
    /* Check saved x30 is in kernel RAM [0x40000000, 0x80000000) */
    mov     x5, #0x4000
    lsl     x5, x5, #16             /* x5 = 0x40000000 */
    cmp     x3, x5
    b.lo    .Lsave_x30_bad          /* < 0x40000000 */
    mov     x5, #0x8000
    lsl     x5, x5, #16             /* x5 = 0x80000000 */
    cmp     x3, x5
    b.hs    .Lsave_x30_bad          /* >= 0x80000000 */
    b       .Lsave_ok
.Lsave_x30_bad:
    /* Saved x30 is not in kernel RAM - print warning (non-fatal,
     * because fork_child_return is a valid x30 that should be in kernel RAM,
     * and thread_trampoline too. If we see this, something is very wrong.) */
    stp     x0, x1, [sp, #-32]!     /* Save old_ctx, new_ctx */
    stp     x3, x4, [sp, #16]       /* Save x30_val, sp_val */
    adr     x0, .Lfmt_save_bad
    mov     x1, x3                   /* saved x30 */
    mov     x2, x4                   /* saved SP */
    bl      kprintf
    ldp     x3, x4, [sp, #16]
    ldp     x0, x1, [sp], #32       /* Restore old_ctx, new_ctx */
.Lsave_ok:

    /* Restore callee-saved registers from new context */
    ldp     x19, x20, [x1, #0]
    ldp     x21, x22, [x1, #16]
    ldp     x23, x24, [x1, #32]
    ldp     x25, x26, [x1, #48]
    ldp     x27, x28, [x1, #64]
    ldp     x29, x30, [x1, #80]
    ldr     x2, [x1, #96]
    mov     sp, x2                   /* Restore SP */

    /*
     * DEBUG: After restore, verify x30 (about to ret to) is a kernel address.
     * Kernel RAM: [0x40000000, 0x80000000)
     * If x30 is outside this range, we have a fatal corruption bug.
     */
    mov     x2, #0x4000
    lsl     x2, x2, #16             /* x2 = 0x40000000 */
    cmp     x30, x2
    b.lo    .Lrestore_x30_bad       /* x30 < 0x40000000 */
    mov     x2, #0x8000
    lsl     x2, x2, #16             /* x2 = 0x80000000 */
    cmp     x30, x2
    b.hs    .Lrestore_x30_bad       /* x30 >= 0x80000000 */
    b       .Lrestore_ok

.Lrestore_x30_bad:
    /* FATAL: x30 after restore is not a kernel address.
     * Print and panic. We need a valid stack for kprintf.
     * SP was just restored from new context - use it as-is. */
    stp     x29, x30, [sp, #-16]!
    mov     x1, x30                  /* arg1 = bad x30 */
    mov     x2, sp                   /* arg2 = current SP */
    mov     x3, x19                  /* arg3 = restored x19 */
    mov     x4, x29                  /* arg4 = restored x29 */
    adr     x0, .Lfmt_restore_bad
    bl      kprintf
    ldp     x29, x30, [sp], #16
    adr     x0, .Lfmt_restore_panic
    bl      panic

.Lrestore_ok:
    ret                              /* Return via restored LR (x30) */

/* ============================================================================
 * load_context(new_ctx)
 *
 * One-way context switch: restores callee-saved registers and SP from
 * the given context, then returns (via the restored x30/LR).
 *
 * This is used to abandon the current stack (e.g. the boot stack) and
 * jump into a thread that was set up by thread_create(). The old
 * stack/context is NOT saved — it is discarded forever.
 *
 * Equivalent to XNU's load_context() / machine_load_context().
 *
 * x0 = pointer to new thread's saved register context (struct cpu_context)
 * ============================================================================ */
.global load_context
load_context:
    /* Restore callee-saved registers from new context */
    ldp     x19, x20, [x0, #0]
    ldp     x21, x22, [x0, #16]
    ldp     x23, x24, [x0, #32]
    ldp     x25, x26, [x0, #48]
    ldp     x27, x28, [x0, #64]
    ldp     x29, x30, [x0, #80]
    ldr     x2, [x0, #96]
    mov     sp, x2                   /* Restore SP */

    ret                              /* Jump to restored LR (x30) */

/* Format strings in rodata */
.section .rodata
.Lfmt_save_bad:
    .asciz "[CTX_ASM] WARNING: saved old x30=0x%lx sp=0x%lx NOT in kernel RAM!\n"
.Lfmt_restore_bad:
    .asciz "\n!!! CTX_ASM FATAL: restored x30=0x%lx sp=0x%lx x19=0x%lx x29=0x%lx !!!\n"
.Lfmt_restore_panic:
    .asciz "context_switch: restored x30 is not a kernel address"
.section .text
