/*
 * Kiseki OS - Assembly Syscall Stubs
 *
 * These provide an alternative to the inline-asm wrappers in syscall.h.
 * Each stub loads x16 with the syscall number (args already in x0-x5),
 * executes svc #0x80, checks carry for error, and returns.
 *
 * Convention:
 *   On success: return non-negative value in x0
 *   On error:   return -errno (negative)
 *
 * These are used by linking against libsystem.a.  The inline versions
 * in syscall.h are preferred for performance-critical paths.
 */

    .text

/*
 * Macro to generate a syscall stub.
 * Name: function name (e.g., __sys_read)
 * Num:  syscall number
 */
.macro SYSCALL_STUB name, num
    .globl \name
    .type \name, %function
    .align 4
\name:
    mov     x16, #\num
    svc     #0x80

    /* Check carry flag (PSTATE.C = NZCV bit 29) */
    mrs     x8, nzcv
    tbnz    x8, #29, 1f        /* Branch if carry set (error) */
    ret                         /* Success: x0 has return value */
1:
    neg     x0, x0              /* Error: negate errno to return -errno */
    ret
    .size \name, . - \name
.endm

/* ============================================================================
 * Syscall stubs
 * ============================================================================ */

/* Process lifecycle */
SYSCALL_STUB __sys_exit,        1
SYSCALL_STUB __sys_fork,        2
SYSCALL_STUB __sys_execve,      59
SYSCALL_STUB __sys_getpid,      20
SYSCALL_STUB __sys_getppid,     39
SYSCALL_STUB __sys_getuid,      24
SYSCALL_STUB __sys_geteuid,     25
SYSCALL_STUB __sys_setuid,      23
SYSCALL_STUB __sys_getgid,      47
SYSCALL_STUB __sys_kill,        37
SYSCALL_STUB __sys_wait4,       7
SYSCALL_STUB __sys_setsid,      147
SYSCALL_STUB __sys_setpgid,     82
SYSCALL_STUB __sys_getpgrp,     81

/* File I/O */
SYSCALL_STUB __sys_read,        3
SYSCALL_STUB __sys_write,       4
SYSCALL_STUB __sys_open,        5
SYSCALL_STUB __sys_close,       6
SYSCALL_STUB __sys_lseek,       199
SYSCALL_STUB __sys_dup,         41
SYSCALL_STUB __sys_dup2,        90
SYSCALL_STUB __sys_pipe,        42
SYSCALL_STUB __sys_fcntl,       92
SYSCALL_STUB __sys_fstat,       153
SYSCALL_STUB __sys_stat,        338
SYSCALL_STUB __sys_lstat,       340
SYSCALL_STUB __sys_ioctl,       54
SYSCALL_STUB __sys_pread,       173
SYSCALL_STUB __sys_pwrite,      174

/* File system */
SYSCALL_STUB __sys_unlink,      10
SYSCALL_STUB __sys_link,        9
SYSCALL_STUB __sys_symlink,     57
SYSCALL_STUB __sys_readlink,    58
SYSCALL_STUB __sys_rename,      128
SYSCALL_STUB __sys_mkdir,       136
SYSCALL_STUB __sys_rmdir,       137
SYSCALL_STUB __sys_chdir,       12
SYSCALL_STUB __sys_getcwd,      304
SYSCALL_STUB __sys_access,      33
SYSCALL_STUB __sys_chmod,       15
SYSCALL_STUB __sys_chown,       16
SYSCALL_STUB __sys_umask,       60
SYSCALL_STUB __sys_getdirentries, 196

/* Memory management */
SYSCALL_STUB __sys_mmap,        197
SYSCALL_STUB __sys_munmap,      73
SYSCALL_STUB __sys_mprotect,    74

/* Signals */
SYSCALL_STUB __sys_sigaction,   46
SYSCALL_STUB __sys_sigprocmask, 48

/* System */
SYSCALL_STUB __sys_sysctl,      202
SYSCALL_STUB __sys_nanosleep,   240
SYSCALL_STUB __sys_sync,        36
SYSCALL_STUB __sys_select,      93

/* Network */
SYSCALL_STUB __sys_socket,      97
SYSCALL_STUB __sys_connect,     98
SYSCALL_STUB __sys_bind,        104
SYSCALL_STUB __sys_listen,      106
SYSCALL_STUB __sys_accept,      30
