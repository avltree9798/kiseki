/*
 * Kiseki OS - BSD Syscall Numbers
 *
 * Shared header for kernel and userland - single source of truth.
 * XNU-compatible syscall numbers.
 *
 * Convention:
 *   - User executes `svc #0x80` with syscall number in x16
 *   - Arguments in x0-x5
 *   - Return value in x0
 *   - On error: carry flag set, positive errno in x0
 *
 * Reference: XNU bsd/kern/syscalls.master
 */

#ifndef _SYS_SYSCALL_H
#define _SYS_SYSCALL_H

/* ============================================================================
 * BSD Syscall Numbers (XNU-compatible)
 * ============================================================================ */

#define SYS_syscall         0
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
#define SYS_ptrace          26
#define SYS_recvfrom        29
#define SYS_accept          30
#define SYS_getpeername     31
#define SYS_getsockname     32
#define SYS_access          33
#define SYS_sync            36
#define SYS_kill            37
#define SYS_getppid         39
#define SYS_dup             41
#define SYS_pipe            42
#define SYS_getegid         43
#define SYS_sigaction       46
#define SYS_getgid          47
#define SYS_sigprocmask     48
#define SYS_ioctl           54
#define SYS_reboot          55
#define SYS_symlink         57
#define SYS_readlink        58
#define SYS_execve          59
#define SYS_umask           60
#define SYS_munmap          73
#define SYS_mprotect        74
#define SYS_getpgrp         81
#define SYS_setpgid         82
#define SYS_dup2            90
#define SYS_fcntl           92
#define SYS_select          93
#define SYS_socket          97
#define SYS_connect         98
#define SYS_bind            104
#define SYS_setsockopt      105
#define SYS_listen          106
#define SYS_gettimeofday    116
#define SYS_getsockopt      118
#define SYS_settimeofday    122
#define SYS_fchmod          124
#define SYS_rename          128
#define SYS_sendto          133
#define SYS_shutdown        134
#define SYS_mkdir           136
#define SYS_rmdir           137
#define SYS_setsid          147
#define SYS_getpgid         151
#define SYS_fstat           153
#define SYS_statfs          157
#define SYS_fstatfs         158
#define SYS_pread           173
#define SYS_pwrite          174
#define SYS_setgid          181
#define SYS_sigreturn       184
#define SYS_fstat64         189
#define SYS_getdirentries   196
#define SYS_mmap            197
#define SYS_lseek           199
#define SYS_sysctl          202
#define SYS_nanosleep       240
#define SYS_pthread_kill    286
#define SYS_getcwd          304
#define SYS_issetugid       327
#define SYS_proc_info       336
#define SYS_stat            338
#define SYS_fstat_extended  339
#define SYS_lstat           340
#define SYS_read_nocancel   396
#define SYS_write_nocancel  397
#define SYS_open_nocancel   398
#define SYS_close_nocancel  399
#define SYS_fcntl_nocancel  406

/* Kiseki extensions (500+) */
#define SYS_getentropy      500
#define SYS_openpty         501

/* Maximum BSD syscall number */
#define SYS_MAXSYSCALL      512

/* ============================================================================
 * Mach Trap Numbers (negative x16 values)
 *
 * In XNU, Mach traps are indexed by negating x16.
 * E.g., x16 = -28 -> task_self_trap
 * ============================================================================ */

#define MACH_TRAP_mach_reply_port           (-26)
#define MACH_TRAP_thread_self_trap          (-27)
#define MACH_TRAP_task_self_trap            (-28)
#define MACH_TRAP_mach_msg_trap             (-31)
#define MACH_TRAP_mach_msg_overwrite_trap   (-32)
#define MACH_TRAP_mach_port_allocate        (-36)
#define MACH_TRAP_mach_port_deallocate      (-37)

/* ============================================================================
 * sysctl CTL_* constants (shared between kernel and userland)
 * ============================================================================ */

#define CTL_KERN            1
#define CTL_NET             4
#define CTL_HW              6

/* CTL_KERN */
#define KERN_OSTYPE         1
#define KERN_OSRELEASE      2
#define KERN_OSREV          3
#define KERN_VERSION        4
#define KERN_HOSTNAME       10
#define KERN_PROC           14
#define KERN_OSVERSION      65

/* CTL_HW */
#define HW_MACHINE          1
#define HW_NCPU             3
#define HW_PAGESIZE         7
#define HW_MEMSIZE          12

/* CTL_NET - Kiseki extensions for network info */
#define NET_KISEKI_IFADDR   100
#define NET_KISEKI_IFMASK   101
#define NET_KISEKI_IFGW     102

#endif /* _SYS_SYSCALL_H */
