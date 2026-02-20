/*
 * Kiseki OS - Userland Raw Syscall Interface
 *
 * Inline functions to invoke BSD syscalls via svc #0x80.
 * XNU convention:
 *   - x16 = syscall number (positive for BSD, negative for Mach)
 *   - x0-x5 = arguments
 *   - Return value in x0
 *   - On error: carry flag (PSTATE.C / NZCV bit 29) is set, x0 = positive errno
 *   - On success: carry clear, x0 = return value
 *
 * These functions return -errno on error, or the non-negative result on success.
 */

#ifndef _LIBSYSTEM_SYSCALL_H
#define _LIBSYSTEM_SYSCALL_H

#include <types.h>

/* Syscall numbers from shared header (at repo root include/sys/syscall.h) */
#include "../../../include/sys/syscall.h"

/* mmap constants */
#define PROT_NONE       0x00
#define PROT_READ       0x01
#define PROT_WRITE      0x02
#define PROT_EXEC       0x04

#define MAP_SHARED      0x0001
#define MAP_PRIVATE     0x0002
#define MAP_FIXED       0x0010
#define MAP_ANON        0x1000
#define MAP_ANONYMOUS   MAP_ANON

#define MAP_FAILED      ((void *)-1)

/* ============================================================================
 * Inline syscall wrappers
 *
 * ARM64 calling convention for svc #0x80:
 *   Input:  x16 = syscall number, x0-x5 = arguments
 *   Output: x0 = return value (or positive errno if carry set)
 *
 * After svc, we read NZCV via mrs to check the carry flag (bit 29).
 * If carry is set, the syscall failed and x0 holds a positive errno;
 * we negate it to return -errno.
 * ============================================================================ */

static inline long __syscall(long number, long a0, long a1, long a2,
                             long a3, long a4, long a5)
{
    register long x16 __asm__("x16") = number;
    register long x0  __asm__("x0")  = a0;
    register long x1  __asm__("x1")  = a1;
    register long x2  __asm__("x2")  = a2;
    register long x3  __asm__("x3")  = a3;
    register long x4  __asm__("x4")  = a4;
    register long x5  __asm__("x5")  = a5;
    register long nzcv;

    __asm__ volatile(
        "svc    #0x80\n\t"
        "mrs    %[nzcv], nzcv"
        : [nzcv] "=r" (nzcv),
          "+r" (x0)
        : "r" (x16), "r" (x1), "r" (x2), "r" (x3), "r" (x4), "r" (x5)
        : "memory", "cc"
    );

    /* Carry flag is bit 29 of NZCV */
    if (nzcv & (1L << 29))
        return -x0;    /* Error: return -errno */
    return x0;          /* Success */
}

static inline long syscall0(long number)
{
    return __syscall(number, 0, 0, 0, 0, 0, 0);
}

static inline long syscall1(long number, long a0)
{
    return __syscall(number, a0, 0, 0, 0, 0, 0);
}

static inline long syscall2(long number, long a0, long a1)
{
    return __syscall(number, a0, a1, 0, 0, 0, 0);
}

static inline long syscall3(long number, long a0, long a1, long a2)
{
    return __syscall(number, a0, a1, a2, 0, 0, 0);
}

static inline long syscall4(long number, long a0, long a1, long a2, long a3)
{
    return __syscall(number, a0, a1, a2, a3, 0, 0);
}

static inline long syscall5(long number, long a0, long a1, long a2,
                             long a3, long a4)
{
    return __syscall(number, a0, a1, a2, a3, a4, 0);
}

static inline long syscall6(long number, long a0, long a1, long a2,
                             long a3, long a4, long a5)
{
    return __syscall(number, a0, a1, a2, a3, a4, a5);
}

#endif /* _LIBSYSTEM_SYSCALL_H */
