/*
 * Kiseki OS - BSD Syscall Kernel Interface
 *
 * Kernel-specific syscall handling declarations.
 * Syscall numbers are in the shared header <sys/syscall.h>.
 */

#ifndef _BSD_SYSCALL_H
#define _BSD_SYSCALL_H

#include <kiseki/types.h>
#include <sys/syscall.h>  /* Shared syscall numbers */

struct trap_frame;

/* ============================================================================
 * BSD Syscall Handler (main dispatch)
 * ============================================================================ */

/*
 * syscall_handler - Main syscall dispatch entry point
 *
 * Called from trap_sync_el0 when EC == EC_SVC_A64.
 * Reads x16 from the trap frame:
 *   - Positive: dispatch to BSD syscall table
 *   - Negative: dispatch to Mach trap table
 * Sets return value in tf->regs[0].
 * On error: sets carry flag (bit 29) in tf->spsr and puts positive errno in x0.
 */
void syscall_handler(struct trap_frame *tf);

/* ============================================================================
 * Individual BSD Syscall Declarations
 *
 * Each takes a trap_frame so it can read args from x0-x5.
 * Returns: 0 on success, or positive errno on error.
 * Actual return value (e.g., bytes read) is placed in tf->regs[0].
 * ============================================================================ */

/* Process lifecycle */
void    sys_exit(struct trap_frame *tf);
int     sys_fork(struct trap_frame *tf);
int     sys_execve(struct trap_frame *tf);
int     sys_getpid(struct trap_frame *tf);
int     sys_getppid(struct trap_frame *tf);
int     sys_getuid(struct trap_frame *tf);
int     sys_geteuid(struct trap_frame *tf);
int     sys_setuid(struct trap_frame *tf);
int     sys_getgid(struct trap_frame *tf);
int     sys_setgid(struct trap_frame *tf);
int     sys_issetugid(struct trap_frame *tf);
int     sys_kill(struct trap_frame *tf);
int     sys_wait4(struct trap_frame *tf);

/* File I/O */
int     sys_open(struct trap_frame *tf);
int     sys_close(struct trap_frame *tf);
int     sys_read(struct trap_frame *tf);
int     sys_write(struct trap_frame *tf);
int     sys_pread(struct trap_frame *tf);
int     sys_pwrite(struct trap_frame *tf);
int     sys_lseek(struct trap_frame *tf);
int     sys_fstat(struct trap_frame *tf);
int     sys_dup(struct trap_frame *tf);
int     sys_dup2(struct trap_frame *tf);
int     sys_pipe(struct trap_frame *tf);
int     sys_fcntl(struct trap_frame *tf);
int     sys_unlink(struct trap_frame *tf);

/* Memory management */
int     sys_mmap(struct trap_frame *tf);
int     sys_munmap(struct trap_frame *tf);
int     sys_mprotect(struct trap_frame *tf);

/* System information */
int     sys_sysctl(struct trap_frame *tf);

/* Signals */
int     sys_pthread_kill(struct trap_frame *tf);

#endif /* _BSD_SYSCALL_H */
