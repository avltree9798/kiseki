/*
 * Kiseki OS - setjmp/longjmp
 *
 * Non-local jumps for error handling.
 * ARM64 AArch64 implementation.
 */

#ifndef _LIBSYSTEM_SETJMP_H
#define _LIBSYSTEM_SETJMP_H

/*
 * jmp_buf layout for ARM64:
 * - x19-x28 (10 callee-saved registers)
 * - x29 (frame pointer)
 * - x30 (link register / return address)
 * - sp (stack pointer)
 * - d8-d15 (8 callee-saved FP registers)
 * Total: 22 * 8 = 176 bytes, aligned to 16
 */
typedef long jmp_buf[22];

/* POSIX sigjmp_buf (same as jmp_buf for now - no signal mask saving) */
typedef long sigjmp_buf[22];

/* Save calling environment for non-local jump */
int setjmp(jmp_buf env);
int _setjmp(jmp_buf env);
int sigsetjmp(sigjmp_buf env, int savesigs);

/* Restore calling environment saved by setjmp */
void longjmp(jmp_buf env, int val) __attribute__((noreturn));
void _longjmp(jmp_buf env, int val) __attribute__((noreturn));
void siglongjmp(sigjmp_buf env, int val) __attribute__((noreturn));

#endif /* _LIBSYSTEM_SETJMP_H */
