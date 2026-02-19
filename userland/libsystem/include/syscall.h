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

/* ============================================================================
 * BSD Syscall Numbers (must match kernel/include/bsd/syscall.h)
 * ============================================================================ */

#define SYS_exit            1
#define SYS_fork            2
#define SYS_read            3
#define SYS_write           4
#define SYS_open            5
#define SYS_close           6
#define SYS_wait4           7
#define SYS_link            9
#define SYS_unlink          10
#define SYS_chdir           12
#define SYS_fchdir          13
#define SYS_mknod           14
#define SYS_chmod           15
#define SYS_chown           16
#define SYS_getpid          20
#define SYS_setuid          23
#define SYS_getuid          24
#define SYS_geteuid         25
#define SYS_access          33
#define SYS_sync            36
#define SYS_kill            37
#define SYS_getppid         39
#define SYS_dup             41
#define SYS_pipe            42
#define SYS_getegid         43
#define SYS_sigaction       46
#define SYS_getgid          47
#define SYS_ioctl           54
#define SYS_symlink         57
#define SYS_readlink        58
#define SYS_execve          59
#define SYS_umask           60
#define SYS_dup2            90
#define SYS_fcntl           92
#define SYS_select          93
#define SYS_recvfrom        29
#define SYS_accept          30
#define SYS_getpeername     31
#define SYS_getsockname     32
#define SYS_socket          97
#define SYS_connect         98
#define SYS_bind            104
#define SYS_setsockopt      105
#define SYS_listen          106
#define SYS_getsockopt      118
#define SYS_sendto          133
#define SYS_shutdown        134
#define SYS_munmap          73
#define SYS_mprotect        74
#define SYS_mkdir           136
#define SYS_rmdir           137
#define SYS_rename          128
#define SYS_fstat           153
#define SYS_pread           173
#define SYS_pwrite          174
#define SYS_setgid          181
#define SYS_mmap            197
#define SYS_lseek           199
#define SYS_sysctl          202
#define SYS_sigprocmask     48
#define SYS_setpgid         82
#define SYS_getpgrp         81
#define SYS_setsid          147
#define SYS_getpgid         151
#define SYS_tcgetpgrp       256     /* via ioctl in practice */
#define SYS_tcsetpgrp       257     /* via ioctl in practice */
#define SYS_nanosleep       240
#define SYS_stat            338
#define SYS_lstat           340
#define SYS_getdirentries   196
#define SYS_getcwd          304
#define SYS_pthread_kill    286
#define SYS_issetugid       327
#define SYS_read_nocancel   396
#define SYS_write_nocancel  397
#define SYS_open_nocancel   398
#define SYS_close_nocancel  399
#define SYS_gettimeofday    116
#define SYS_settimeofday    122
#define SYS_fchmod          124
#define SYS_statfs          157
#define SYS_fstatfs         158
#define SYS_proc_info       336
#define SYS_getentropy      500
#define SYS_openpty         501

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
