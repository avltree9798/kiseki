/*
 * Kiseki OS - ARM64 Context Switch
 *
 * Saves and restores thread register state for the scheduler.
 * Saves callee-saved registers (x19-x30, SP, d8-d15) and restores
 * them on the new thread's context.
 */

.section .text
.global context_switch

/*
 * context_switch(old_ctx, new_ctx)
 *
 * x0 = pointer to old thread's saved register context (struct cpu_context)
 * x1 = pointer to new thread's saved register context (struct cpu_context)
 *
 * Saves callee-saved registers (x19-x30, SP, d8-d15) to old context,
 * restores them from new context, and returns.
 */
context_switch:
    /* Save callee-saved GPRs to old context */
    stp     x19, x20, [x0, #0]
    stp     x21, x22, [x0, #16]
    stp     x23, x24, [x0, #32]
    stp     x25, x26, [x0, #48]
    stp     x27, x28, [x0, #64]
    stp     x29, x30, [x0, #80]    /* x29=FP, x30=LR */
    mov     x2, sp
    str     x2, [x0, #96]           /* Save SP */

    /* Save callee-saved NEON registers d8-d15 (AAPCS64) */
    stp     d8,  d9,  [x0, #104]
    stp     d10, d11, [x0, #120]
    stp     d12, d13, [x0, #136]
    stp     d14, d15, [x0, #152]

    /* Restore callee-saved GPRs from new context */
    ldp     x19, x20, [x1, #0]
    ldp     x21, x22, [x1, #16]
    ldp     x23, x24, [x1, #32]
    ldp     x25, x26, [x1, #48]
    ldp     x27, x28, [x1, #64]
    ldp     x29, x30, [x1, #80]
    ldr     x2, [x1, #96]
    mov     sp, x2                   /* Restore SP */

    /* Restore callee-saved NEON registers d8-d15 */
    ldp     d8,  d9,  [x1, #104]
    ldp     d10, d11, [x1, #120]
    ldp     d12, d13, [x1, #136]
    ldp     d14, d15, [x1, #152]

#ifdef DEBUG
    /*
     * Debug-only: verify x30 (about to ret to) is a kernel address.
     * Kernel RAM: [0x40000000, 0x80000000)
     * If x30 is outside this range, we have a fatal corruption bug.
     * This converts an unpredictable crash into a clean panic with
     * diagnostic output.  Compiled out in release builds.
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
     * Print and panic. SP was just restored from new context. */
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
#endif /* DEBUG */

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

    /* Restore callee-saved NEON registers d8-d15 */
    ldp     d8,  d9,  [x0, #104]
    ldp     d10, d11, [x0, #120]
    ldp     d12, d13, [x0, #136]
    ldp     d14, d15, [x0, #152]

    ret                              /* Jump to restored LR (x30) */

#ifdef DEBUG
/* Format strings in rodata (debug builds only) */
.section .rodata
.Lfmt_restore_bad:
    .asciz "\n!!! CTX_ASM FATAL: restored x30=0x%lx sp=0x%lx x19=0x%lx x29=0x%lx !!!\n"
.Lfmt_restore_panic:
    .asciz "context_switch: restored x30 is not a kernel address"
.section .text
#endif /* DEBUG */
