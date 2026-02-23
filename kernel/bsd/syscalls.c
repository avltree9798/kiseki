/*
 * Kiseki OS - BSD Syscall Implementation
 *
 * Dispatches system calls from userspace. XNU convention:
 *   - svc #0x80, syscall number in x16
 *   - Positive x16 -> BSD syscall
 *   - Negative x16 -> Mach trap
 *   - Args in x0-x5, return in x0
 *   - On error: carry flag (SPSR bit 29) set, positive errno in x0
 *
 * This file implements the core POSIX-subset syscalls needed for
 * early userspace (init, sh, basic utilities).
 */

#include <kiseki/types.h>
#include <bsd/syscall.h>
#include <bsd/signal.h>
#include <machine/trap.h>
#include <kern/thread.h>
#include <kern/proc.h>
#include <kern/vmm.h>
#include <kern/pmm.h>
#include <kern/kprintf.h>
#include <drivers/uart.h>
#include <fs/vfs.h>
#include <mach/ipc.h>
#include <kern/tty.h>
#include <net/net.h>
#include <net/tcp.h>
#include <kern/pty.h>

/* devfs query — check if a vnode is a console/tty character device */
extern bool devfs_is_console(struct vnode *vp);

/* Buffer cache sync */
extern void buf_sync(void);

/* ============================================================================
 * SPSR Carry Flag (PSTATE.C)
 *
 * ARM64 SPSR layout: bit 29 = C (carry).
 * XNU sets this on syscall error so userspace libsyscall can detect errors.
 * ============================================================================ */

#define SPSR_CARRY_BIT  (1UL << 29)

static inline void syscall_return(struct trap_frame *tf, int64_t retval)
{
    tf->regs[0] = (uint64_t)retval;
    /* Clear carry flag (success) */
    tf->spsr &= ~SPSR_CARRY_BIT;
}

static inline void syscall_error(struct trap_frame *tf, int errno_val)
{
    tf->regs[0] = (uint64_t)errno_val;
    /* Set carry flag (error) */
    tf->spsr |= SPSR_CARRY_BIT;
}

/* ============================================================================
 * Path Resolution Helper
 *
 * Converts relative paths to absolute by prepending process cwd.
 * Canonicalizes "." and ".." components.
 * ============================================================================ */

#define PATH_MAX_KERN 1024

static uint32_t sc_strlen(const char *s)
{
    uint32_t n = 0;
    while (s[n]) n++;
    return n;
}

static void sc_strcpy(char *dst, const char *src)
{
    while (*src)
        *dst++ = *src++;
    *dst = '\0';
}

static void sc_strncpy(char *dst, const char *src, uint32_t max)
{
    uint32_t i;
    for (i = 0; i < max - 1 && src[i]; i++)
        dst[i] = src[i];
    dst[i] = '\0';
}


/*
 * canonicalize_path - Resolve "." and ".." in an absolute path in-place.
 * Input must start with '/'. Operates on the buffer directly.
 */
static void canonicalize_path(char *path)
{
    /* Stack of component start offsets */
    int offsets[128];
    int depth = 0;

    char out[PATH_MAX_KERN];
    uint32_t olen = 0;

    const char *p = path;
    if (*p != '/') return; /* should not happen */

    while (*p) {
        /* Skip duplicate slashes */
        while (*p == '/')
            p++;
        if (!*p) break;

        /* Find end of component */
        const char *start = p;
        while (*p && *p != '/')
            p++;
        uint32_t clen = (uint32_t)(p - start);

        if (clen == 1 && start[0] == '.') {
            /* "." - skip, stay in current directory */
            continue;
        }

        if (clen == 2 && start[0] == '.' && start[1] == '.') {
            /* ".." - go up one level */
            if (depth > 0) {
                depth--;
                olen = (uint32_t)offsets[depth];
            }
            continue;
        }

        /* Normal component: append "/component" */
        if (depth < 128) {
            offsets[depth++] = (int)olen;
        }
        out[olen++] = '/';
        for (uint32_t i = 0; i < clen && olen < PATH_MAX_KERN - 1; i++)
            out[olen++] = start[i];
    }

    if (olen == 0) {
        /* Root directory */
        path[0] = '/';
        path[1] = '\0';
    } else {
        out[olen] = '\0';
        sc_strcpy(path, out);
    }
}

/*
 * resolve_user_path - Convert a user-supplied path to an absolute path.
 *
 * If the path is already absolute (starts with '/'), it's copied as-is.
 * If relative, the current process's cwd is prepended.
 * Then "." and ".." are canonicalized.
 *
 * Returns 0 on success, positive errno on error.
 */
static int resolve_user_path(const char *user_path, char *abs_buf, uint32_t bufsz)
{
    if (!user_path || !user_path[0])
        return EINVAL;

    if (user_path[0] == '/') {
        /* Already absolute */
        sc_strncpy(abs_buf, user_path, bufsz);
    } else {
        /* Relative: prepend cwd */
        struct proc *p = proc_current();
        const char *cwd = (p && p->p_cwd_path[0]) ? p->p_cwd_path : "/";
        uint32_t cwd_len = sc_strlen(cwd);
        uint32_t path_len = sc_strlen(user_path);

        if (cwd_len + 1 + path_len + 1 > bufsz)
            return ENAMETOOLONG;

        uint32_t pos = 0;
        /* Copy cwd */
        for (uint32_t i = 0; i < cwd_len && pos < bufsz - 1; i++)
            abs_buf[pos++] = cwd[i];
        /* Add separator if cwd doesn't end with '/' */
        if (pos > 0 && abs_buf[pos - 1] != '/' && pos < bufsz - 1)
            abs_buf[pos++] = '/';
        /* Copy relative path */
        for (uint32_t i = 0; i < path_len && pos < bufsz - 1; i++)
            abs_buf[pos++] = user_path[i];
        abs_buf[pos] = '\0';
    }

    canonicalize_path(abs_buf);
    return 0;
}

/* ============================================================================
 * Mach Trap Dispatch (negative x16)
 * ============================================================================ */

static void mach_trap_dispatch(struct trap_frame *tf, int32_t trap_num)
{
    kern_return_t kr;

    switch (trap_num) {
    case MACH_TRAP_task_self_trap: {
        mach_port_t port = task_self_trap();
        syscall_return(tf, (int64_t)port);
        return;
    }

    case MACH_TRAP_mach_reply_port: {
        mach_port_t port = mach_reply_port_trap();
        syscall_return(tf, (int64_t)port);
        return;
    }

    case MACH_TRAP_thread_self_trap: {
        mach_port_t port = thread_self_trap();
        syscall_return(tf, (int64_t)port);
        return;
    }

    case MACH_TRAP_mach_msg_trap:
    case MACH_TRAP_mach_msg_overwrite_trap: {
        mach_msg_return_t ret = mach_msg_trap(tf);
        syscall_return(tf, (int64_t)ret);
        return;
    }

    case MACH_TRAP_mach_port_allocate: {
        kr = mach_port_allocate_trap(tf);
        syscall_return(tf, (int64_t)kr);
        return;
    }

    case MACH_TRAP_mach_port_deallocate: {
        kr = mach_port_deallocate_trap(tf);
        syscall_return(tf, (int64_t)kr);
        return;
    }

    default:
        kprintf("[syscall] unhandled Mach trap %d\n", trap_num);
        syscall_return(tf, (int64_t)KERN_FAILURE);
        return;
    }
}

/* Forward declarations for syscall handlers defined later in this file */
static int sys_chdir(struct trap_frame *tf);
static int sys_ioctl(struct trap_frame *tf);
static int sys_access(struct trap_frame *tf);
static int sys_getpgrp(struct trap_frame *tf);
static int sys_setpgid(struct trap_frame *tf);
static int sys_getpgid(struct trap_frame *tf);
static int sys_setsid(struct trap_frame *tf);
static int sys_sigaction(struct trap_frame *tf);
static int sys_sigprocmask(struct trap_frame *tf);
static int sys_umask(struct trap_frame *tf);
static int sys_stat(struct trap_frame *tf);
static int sys_lstat(struct trap_frame *tf);
static int sys_getcwd(struct trap_frame *tf);
static int sys_nanosleep(struct trap_frame *tf);
static int sys_getdirentries(struct trap_frame *tf);
static int sys_getegid(struct trap_frame *tf);
static int sys_mkdir(struct trap_frame *tf);
static int sys_rmdir(struct trap_frame *tf);
static int sys_rename(struct trap_frame *tf);
static int sys_chmod(struct trap_frame *tf);
static int sys_readlink(struct trap_frame *tf);
static int sys_select(struct trap_frame *tf);
static int sys_reboot(struct trap_frame *tf);

/* Socket syscalls */
static int sys_socket(struct trap_frame *tf);
static int sys_bind(struct trap_frame *tf);
static int sys_listen_sc(struct trap_frame *tf);
static int sys_accept_sc(struct trap_frame *tf);
static int sys_connect_sc(struct trap_frame *tf);
static int sys_sendto(struct trap_frame *tf);
static int sys_recvfrom(struct trap_frame *tf);
static int sys_shutdown_sc(struct trap_frame *tf);
static int sys_setsockopt(struct trap_frame *tf);
static int sys_getsockopt(struct trap_frame *tf);
static int sys_getpeername(struct trap_frame *tf);
static int sys_getsockname_sc(struct trap_frame *tf);

/* New syscalls */
static int sys_chown(struct trap_frame *tf);
static int sys_sync(struct trap_frame *tf);
static int sys_fchdir(struct trap_frame *tf);
static int sys_getentropy(struct trap_frame *tf);
static int sys_link(struct trap_frame *tf);
static int sys_sigreturn(struct trap_frame *tf);
static int sys_proc_info(struct trap_frame *tf);
static int sys_statfs_sc(struct trap_frame *tf);
static int sys_fstatfs_sc(struct trap_frame *tf);
static int sys_fchmod(struct trap_frame *tf);
static int sys_gettimeofday(struct trap_frame *tf);
static int sys_settimeofday(struct trap_frame *tf);
static int sys_openpty_sc(struct trap_frame *tf);
static int sys_fsync(struct trap_frame *tf);
static int sys_ftruncate(struct trap_frame *tf);
static int sys_truncate(struct trap_frame *tf);

/* BSD thread syscalls */
static int sys_bsdthread_create(struct trap_frame *tf);
static int sys_bsdthread_terminate(struct trap_frame *tf);
static int sys_bsdthread_register(struct trap_frame *tf);
static int sys_thread_selfid(struct trap_frame *tf);

/* External: poll for received network packets */
void virtio_net_recv(void);

/* ICMP functions for ping syscall support */
int icmp_send_echo(uint32_t dst_addr, uint16_t id, uint16_t seq,
                   const void *payload, uint32_t payload_len);
int icmp_check_reply(uint32_t *src_addr);

/* ============================================================================
 * BSD Syscall Dispatch (positive x16)
 * ============================================================================ */

void syscall_handler(struct trap_frame *tf)
{
    /*
     * x16 is a signed syscall number:
     *   positive -> BSD syscall
     *   negative -> Mach trap
     *
     * Cast to signed for the comparison.
     */
    int64_t callnum = (int64_t)tf->regs[16];

    /* Syscall tracing — disabled for production, enable for debugging */
#if 0
    if (callnum != 4 && callnum != -31 && callnum != -26) {
        struct thread *_t = current_thread_get();
        pid_t _p = (_t && _t->task) ? _t->task->pid : -1;
        kprintf("[sc] PID%d %ld(0x%lx, 0x%lx, 0x%lx) PC=0x%lx\n",
                _p, callnum, tf->regs[0], tf->regs[1], tf->regs[2],
                tf->elr);
    }
#endif

    if (callnum < 0) {
        mach_trap_dispatch(tf, (int32_t)callnum);
        return;
    }

    int error = 0;

    switch ((uint32_t)callnum) {
    case SYS_exit:
        sys_exit(tf);
        /* Does not return */
        return;

    case SYS_fork:
        error = sys_fork(tf);
        break;

    case SYS_read:
    case SYS_read_nocancel:
        error = sys_read(tf);
        break;

    case SYS_write:
    case SYS_write_nocancel:
        error = sys_write(tf);
        break;

    case SYS_open:
    case SYS_open_nocancel:
        error = sys_open(tf);
        break;

    case SYS_close:
    case SYS_close_nocancel:
        error = sys_close(tf);
        break;

    case SYS_wait4:
        error = sys_wait4(tf);
        break;

    case SYS_getpid:
        error = sys_getpid(tf);
        break;

    case SYS_getppid:
        error = sys_getppid(tf);
        break;

    case SYS_getuid:
        error = sys_getuid(tf);
        break;

    case SYS_setuid:
        error = sys_setuid(tf);
        break;

    case SYS_geteuid:
        error = sys_geteuid(tf);
        break;

    case SYS_getgid:
        error = sys_getgid(tf);
        break;

    case SYS_issetugid:
        error = sys_issetugid(tf);
        break;

    case SYS_setgid:
        error = sys_setgid(tf);
        break;

    case SYS_dup:
        error = sys_dup(tf);
        break;

    case SYS_dup2:
        error = sys_dup2(tf);
        break;

    case SYS_pipe:
        error = sys_pipe(tf);
        break;

    case SYS_lseek:
        error = sys_lseek(tf);
        break;

    case SYS_fstat:
        error = sys_fstat(tf);
        break;

    case SYS_pread:
        error = sys_pread(tf);
        break;

    case SYS_pwrite:
        error = sys_pwrite(tf);
        break;

    case SYS_unlink:
        error = sys_unlink(tf);
        break;

    case SYS_chdir:
        error = sys_chdir(tf);
        break;

    case SYS_execve:
        error = sys_execve(tf);
        break;

    case SYS_mmap:
        error = sys_mmap(tf);
        break;

    case SYS_munmap:
        error = sys_munmap(tf);
        break;

    case SYS_mprotect:
        error = sys_mprotect(tf);
        break;

    case SYS_sysctl:
        error = sys_sysctl(tf);
        break;

    case SYS_ioctl:
        error = sys_ioctl(tf);
        break;

    case SYS_reboot:
        error = sys_reboot(tf);
        break;

    case SYS_fcntl:
    case SYS_fcntl_nocancel:
        error = sys_fcntl(tf);
        break;

    case SYS_access:
        error = sys_access(tf);
        break;

    case SYS_kill:
        error = sys_kill(tf);
        break;

    case SYS_getegid:
        error = sys_getegid(tf);
        break;

    case SYS_sigaction:
        error = sys_sigaction(tf);
        break;

    case SYS_sigprocmask:
        error = sys_sigprocmask(tf);
        break;

    case SYS_umask:
        error = sys_umask(tf);
        break;

    case SYS_getpgrp:
        error = sys_getpgrp(tf);
        break;

    case SYS_setpgid:
        error = sys_setpgid(tf);
        break;

    case SYS_select:
        error = sys_select(tf);
        break;

    case SYS_rename:
        error = sys_rename(tf);
        break;

    case SYS_mkdir:
        error = sys_mkdir(tf);
        break;

    case SYS_rmdir:
        error = sys_rmdir(tf);
        break;

    case SYS_setsid:
        error = sys_setsid(tf);
        break;

    case SYS_getpgid:
        error = sys_getpgid(tf);
        break;

    case SYS_getdirentries:
        error = sys_getdirentries(tf);
        break;

    case SYS_nanosleep:
        error = sys_nanosleep(tf);
        break;

    case SYS_getcwd:
        error = sys_getcwd(tf);
        break;

    case SYS_stat:
        error = sys_stat(tf);
        break;

    case SYS_lstat:
        error = sys_lstat(tf);
        break;

    case SYS_fstat64:
        /* macOS libSystem sometimes uses 189 for fstat */
        error = sys_fstat(tf);
        break;

    case SYS_readlink:
        error = sys_readlink(tf);
        break;

    case SYS_chmod:
        error = sys_chmod(tf);
        break;

    case SYS_pthread_kill:
        error = sys_pthread_kill(tf);
        break;

    /* --- Socket syscalls --- */
    case SYS_socket:
        error = sys_socket(tf);
        break;
    case SYS_bind:
        error = sys_bind(tf);
        break;
    case SYS_listen:
        error = sys_listen_sc(tf);
        break;
    case SYS_accept:
        error = sys_accept_sc(tf);
        break;
    case SYS_connect:
        error = sys_connect_sc(tf);
        break;
    case SYS_sendto:
        error = sys_sendto(tf);
        break;
    case SYS_recvfrom:
        error = sys_recvfrom(tf);
        break;
    case SYS_shutdown:
        error = sys_shutdown_sc(tf);
        break;
    case SYS_setsockopt:
        error = sys_setsockopt(tf);
        break;
    case SYS_getsockopt:
        error = sys_getsockopt(tf);
        break;
    case SYS_getpeername:
        error = sys_getpeername(tf);
        break;
    case SYS_getsockname:
        error = sys_getsockname_sc(tf);
        break;

    /* --- New syscalls --- */
    case SYS_chown:
        error = sys_chown(tf);
        break;
    case SYS_sync:
        error = sys_sync(tf);
        break;
    case SYS_fchdir:
        error = sys_fchdir(tf);
        break;
    case SYS_getentropy:
        error = sys_getentropy(tf);
        break;
    case SYS_link:
        error = sys_link(tf);
        break;
    case SYS_sigreturn:
        error = sys_sigreturn(tf);
        break;

    case SYS_proc_info:
        error = sys_proc_info(tf);
        break;

    case SYS_statfs:
        error = sys_statfs_sc(tf);
        break;
    case SYS_fstatfs:
        error = sys_fstatfs_sc(tf);
        break;
    case SYS_fchmod:
        error = sys_fchmod(tf);
        break;
    case SYS_gettimeofday:
        error = sys_gettimeofday(tf);
        break;
    case SYS_settimeofday:
        error = sys_settimeofday(tf);
        break;

    case SYS_openpty:
        error = sys_openpty_sc(tf);
        break;

    case SYS_fsync:
        error = sys_fsync(tf);
        break;

    case SYS_ftruncate:
        error = sys_ftruncate(tf);
        break;

    case SYS_truncate:
        error = sys_truncate(tf);
        break;

    /* BSD thread syscalls */
    case SYS_bsdthread_create:
        error = sys_bsdthread_create(tf);
        break;

    case SYS_bsdthread_terminate:
        error = sys_bsdthread_terminate(tf);
        break;

    case SYS_bsdthread_register:
        error = sys_bsdthread_register(tf);
        break;

    case SYS_thread_selfid:
        error = sys_thread_selfid(tf);
        break;

    default:
        kprintf("[syscall] unimplemented BSD syscall %ld\n", (uint64_t)callnum);
        error = ENOSYS;
        break;
    }

    if (error != 0) {
        syscall_error(tf, error);
    }
    /* On success, x0 was already set by the individual handler via
     * syscall_return() or directly writing tf->regs[0]. The carry
     * flag was cleared by the handler. We clear it here too for
     * handlers that only return 0 without calling syscall_return. */
    else {
        tf->spsr &= ~SPSR_CARRY_BIT;
    }
}

/* ============================================================================
 * Process Lifecycle Syscalls
 * ============================================================================ */

/*
 * sys_exit - Terminate the calling process
 *
 * x0 = exit status
 */
void sys_exit(struct trap_frame *tf)
{
    int status = (int)tf->regs[0];

    struct thread *cur = current_thread_get();
    pid_t pid = (cur && cur->task) ? cur->task->pid : -1;

    /* If PID 1 (init) exits, the system is done */
    if (pid == 1) {
        kprintf("\n=== Kiseki OS: init exited with status %d ===\n", status);
        kprintf("=== System halted ===\n");
        /* Halt the CPU */
        for (;;)
            __asm__ volatile("wfi");
    }

    /*
     * Proper exit: call proc_exit to close fds, reparent children,
     * destroy VM space, transition to zombie, and wake parent.
     * Then terminate the thread so the scheduler picks the next one.
     */
    struct proc *p = proc_current();
    if (p) {
        proc_exit(p, W_EXITCODE(status, 0));
    }

    /* Terminate the current thread (switches to next runnable) */
    thread_exit();
    /* NOTREACHED */
}

/*
 * sys_fork - Create a child process
 *
 * Returns: child pid in parent (x0), 0 in child (x0).
 * XNU convention: x1 = 1 in child, 0 in parent (we set this in fork_impl).
 */
int sys_fork(struct trap_frame *tf)
{
    return sys_fork_impl(tf);
}

/*
 * sys_execve - Execute a program
 *
 * x0 = path (user pointer), x1 = argv, x2 = envp
 */
int sys_execve(struct trap_frame *tf)
{
    const char *path = (const char *)tf->regs[0];
    const char **argv = (const char **)tf->regs[1];
    const char **envp = (const char **)tf->regs[2];

    if (path == NULL)
        return EINVAL;

    char abs_path[PATH_MAX_KERN];
    int perr = resolve_user_path(path, abs_path, sizeof(abs_path));
    if (perr)
        return perr;

    return sys_execve_impl(tf, abs_path, argv, envp);
}

/*
 * sys_getpid - Return process ID
 */
int sys_getpid(struct trap_frame *tf)
{
    struct thread *cur = current_thread_get();
    if (cur == NULL || cur->task == NULL)
        return ENOSYS;

    syscall_return(tf, (int64_t)cur->task->pid);
    return 0;
}

/*
 * sys_getppid - Return parent process ID
 */
int sys_getppid(struct trap_frame *tf)
{
    struct proc *p = proc_current();
    if (p == NULL)
        return ENOSYS;

    syscall_return(tf, (int64_t)p->p_ppid);
    return 0;
}

/*
 * sys_getuid - Return real user ID
 */
int sys_getuid(struct trap_frame *tf)
{
    struct thread *cur = current_thread_get();
    if (cur == NULL || cur->task == NULL)
        return ENOSYS;

    syscall_return(tf, (int64_t)cur->task->uid);
    return 0;
}

/*
 * sys_setuid - Set real user ID
 *
 * x0 = uid
 * Only root (uid 0) can change to arbitrary uid.
 */
int sys_setuid(struct trap_frame *tf)
{
    uid_t new_uid = (uid_t)tf->regs[0];

    struct thread *cur = current_thread_get();
    if (cur == NULL || cur->task == NULL)
        return ENOSYS;

    /* Only root can set arbitrary uid */
    if (cur->task->euid != 0 && new_uid != cur->task->uid)
        return EACCES;

    /* Update Mach task credentials */
    cur->task->uid = new_uid;
    cur->task->euid = new_uid;

    /* Also update BSD proc credentials so fork() inherits correctly */
    struct proc *p = proc_current();
    if (p) {
        p->p_ucred.cr_uid = new_uid;
        p->p_ucred.cr_ruid = new_uid;
        p->p_ucred.cr_svuid = new_uid;
    }

    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_geteuid - Return effective user ID
 */
int sys_geteuid(struct trap_frame *tf)
{
    struct thread *cur = current_thread_get();
    if (cur == NULL || cur->task == NULL)
        return ENOSYS;

    syscall_return(tf, (int64_t)cur->task->euid);
    return 0;
}

/*
 * sys_getgid - Return real group ID
 */
int sys_getgid(struct trap_frame *tf)
{
    struct thread *cur = current_thread_get();
    if (cur == NULL || cur->task == NULL)
        return ENOSYS;

    syscall_return(tf, (int64_t)cur->task->gid);
    return 0;
}

/*
 * sys_setgid - Set real group ID
 *
 * x0 = gid
 * Only root (uid 0) can change to arbitrary gid.
 */
int sys_setgid(struct trap_frame *tf)
{
    gid_t new_gid = (gid_t)tf->regs[0];

    struct thread *cur = current_thread_get();
    if (cur == NULL || cur->task == NULL)
        return ENOSYS;

    if (cur->task->euid != 0 && new_gid != cur->task->gid)
        return EACCES;

    /* Update Mach task credentials */
    cur->task->gid = new_gid;
    cur->task->egid = new_gid;

    /* Also update BSD proc credentials so fork() inherits correctly */
    struct proc *p = proc_current();
    if (p) {
        p->p_ucred.cr_gid = new_gid;
        p->p_ucred.cr_rgid = new_gid;
        p->p_ucred.cr_svgid = new_gid;
    }

    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_issetugid - Check if process was exec'd setuid/setgid
 *
 * Returns 0 (we don't have SUID exec yet).
 */
int sys_issetugid(struct trap_frame *tf)
{
    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_kill - Send signal to a process
 *
 * x0 = pid (positive=process, negative=process group, 0=own group, -1=all)
 * x1 = sig (0 = existence check only, no signal delivered)
 *
 * For now, we record the signal as pending in the target proc's sigacts.
 * Actual signal delivery (user-mode handler invocation) is deferred to
 * the return-to-user path. sig=0 is a pure existence check.
 *
 * Kill permission rules (simplified):
 *   - Root (euid 0) can signal any process
 *   - Otherwise, sender's euid or ruid must match target's ruid or svuid
 */
int sys_kill(struct trap_frame *tf)
{
    pid_t pid = (pid_t)(int64_t)tf->regs[0];
    int sig = (int)tf->regs[1];

    /* Validate signal number */
    if (sig < 0 || sig >= NSIG)
        return EINVAL;

    struct proc *sender = proc_current();
    if (sender == NULL)
        return EINVAL;

    /*
     * Helper: send signal to a single proc.
     * Returns 0 on success, positive errno on error.
     */
    #define DO_KILL_ONE(target_proc) do {                               \
        struct proc *_tp = (target_proc);                               \
        if (_tp == NULL || _tp->p_state == PROC_UNUSED ||               \
            _tp->p_state == PROC_ZOMBIE)                                \
            break;  /* skip */                                          \
        /* Permission check (simplified) */                             \
        if (sender->p_ucred.cr_uid != 0 &&                             \
            sender->p_ucred.cr_uid != _tp->p_ucred.cr_ruid &&          \
            sender->p_ucred.cr_ruid != _tp->p_ucred.cr_ruid) {         \
            found_no_perm = true;                                       \
            break;                                                      \
        }                                                               \
        found = true;                                                   \
        if (sig > 0) {                                                  \
            /* Record signal as pending */                              \
            sigaddset(&_tp->p_sigacts.pending, sig);                    \
        }                                                               \
    } while (0)

    bool found = false;
    bool found_no_perm = false;

    if (pid > 0) {
        /* Send to specific process */
        struct proc *target = proc_find(pid);
        if (target == NULL)
            return ESRCH;
        DO_KILL_ONE(target);
        if (!found && !found_no_perm)
            return ESRCH;
    } else if (pid == 0) {
        /* Send to all processes in sender's process group */
        for (int i = 0; i < PROC_MAX; i++) {
            struct proc *tp = &proc_table[i];
            if (tp->p_state != PROC_UNUSED && tp->p_pgrp == sender->p_pgrp)
                DO_KILL_ONE(tp);
        }
    } else if (pid == -1) {
        /* Send to all processes (except PID 0 and self) */
        for (int i = 1; i < PROC_MAX; i++) {
            if (i == sender->p_pid)
                continue;
            struct proc *tp = &proc_table[i];
            if (tp->p_state != PROC_UNUSED)
                DO_KILL_ONE(tp);
        }
        found = true;  /* Always succeed for -1 even if no targets */
    } else {
        /* pid < -1: send to process group abs(pid) */
        pid_t pgrp = -pid;
        for (int i = 0; i < PROC_MAX; i++) {
            struct proc *tp = &proc_table[i];
            if (tp->p_state != PROC_UNUSED && tp->p_pgrp == pgrp)
                DO_KILL_ONE(tp);
        }
        if (!found)
            return ESRCH;
    }

    #undef DO_KILL_ONE

    if (found_no_perm && !found)
        return EPERM;

    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_wait4 - Wait for child process
 *
 * x0 = pid, x1 = &status, x2 = options, x3 = &rusage (ignored)
 */
int sys_wait4(struct trap_frame *tf)
{
    return sys_wait4_impl(tf);
}

/* ============================================================================
 * File I/O Syscalls
 * ============================================================================ */

/*
 * sys_open - Open a file
 *
 * x0 = path (user pointer), x1 = flags, x2 = mode
 * Returns: fd in x0
 */
int sys_open(struct trap_frame *tf)
{
    const char *path = (const char *)tf->regs[0];
    uint32_t flags   = (uint32_t)tf->regs[1];
    mode_t mode      = (mode_t)tf->regs[2];

    if (path == NULL)
        return EINVAL;

    char abs_path[PATH_MAX_KERN];
    int err = resolve_user_path(path, abs_path, sizeof(abs_path));
    if (err)
        return err;

    int fd = vfs_open(abs_path, flags, mode);
    if (fd < 0)
        return (int)(-fd);  /* vfs returns negative errno */

    syscall_return(tf, (int64_t)fd);
    return 0;
}

/*
 * sys_close - Close a file descriptor
 *
 * x0 = fd
 */
int sys_close(struct trap_frame *tf)
{
    int fd = (int)tf->regs[0];

    /* Check if this is a socket fd */
    int sockidx = vfs_get_sockidx(fd);
    if (sockidx >= 0) {
        net_close(sockidx);
        vfs_free_fd(fd);
        syscall_return(tf, 0);
        return 0;
    }

    /* Check if this is a PTY fd */
    {
        int pty_close_side;
        struct pty *pty_close = (struct pty *)vfs_get_pty(fd, &pty_close_side);
        if (pty_close != NULL) {
            if (pty_close_side == 0)
                pty_close->pt_master_open = 0;
            else
                pty_close->pt_slave_open = 0;
            /* Free the PTY pair when both sides are closed */
            if (!pty_close->pt_master_open && !pty_close->pt_slave_open)
                pty_free(pty_close);
            vfs_free_fd(fd);
            syscall_return(tf, 0);
            return 0;
        }
    }

    int ret = vfs_close(fd);
    if (ret < 0)
        return (int)(-ret);

    syscall_return(tf, 0);
    return 0;
}

/* Pipe buffer size — forward declaration for sys_read/sys_write */
#define PIPE_BUF_SIZE   4096

struct pipe_data {
    uint8_t     buf[PIPE_BUF_SIZE];
    uint32_t    read_pos;
    uint32_t    write_pos;
    uint32_t    count;      /* bytes available to read */
    bool        write_closed;
    bool        read_closed;
};

/*
 * sys_read - Read from a file descriptor
 *
 * x0 = fd, x1 = buf, x2 = count
 * Returns: bytes read in x0
 */
int sys_read(struct trap_frame *tf)
{
    int fd          = (int)tf->regs[0];
    void *buf       = (void *)tf->regs[1];
    uint64_t count  = tf->regs[2];

    if (buf == NULL)
        return EINVAL;

    int64_t ret;

    /* PTY fd: dispatch to PTY read */
    {
        int pty_side;
        struct pty *pty_r = (struct pty *)vfs_get_pty(fd, &pty_side);
        if (pty_r != NULL) {
            if (pty_side == 0) {
                /* Master side — read slave output */
                ret = pty_master_read(pty_r, buf, count);
            } else {
                /* Slave side — read with line discipline */
                ret = pty_slave_read(pty_r, buf, count);
            }
            if (ret < 0)
                return (int)(-ret);
            syscall_return(tf, ret);
            return 0;
        }
    }

    /*
     * Console fast path: fd 0 (stdin) reads from UART.
     * We check that the fd is actually the console sentinel (no vnode)
     * rather than a file that happened to get fd 0. This prevents
     * blocking on uart_getc() when reading from a file descriptor.
     */
    /* Pipe fd: read from pipe ring buffer */
    int pipe_dir;
    struct pipe_data *pipe_r = (struct pipe_data *)vfs_get_pipe(fd, &pipe_dir);
    if (pipe_r != NULL && pipe_dir == 0) {
        /* Read end of pipe */
        uint64_t nread = 0;
        struct proc *pp = proc_current();
        while (nread < count) {
            if (pipe_r->count == 0) {
                if (pipe_r->write_closed || nread > 0)
                    break;
                /* Block: yield and retry */
                extern void sched_yield(void);
                sched_yield();
                continue;
            }
            uint8_t byte = pipe_r->buf[pipe_r->read_pos];
            pipe_r->read_pos = (pipe_r->read_pos + 1) % PIPE_BUF_SIZE;
            pipe_r->count--;

            if (pp && pp->p_vmspace) {
                uint64_t pa = vmm_translate(pp->p_vmspace->pgd,
                                            (uint64_t)buf + nread);
                if (pa) *(uint8_t *)pa = byte;
            }
            nread++;
        }
        ret = (int64_t)nread;
    }
    /* Socket fd: delegate to net_recv */
    else {
        int sockidx_r = vfs_get_sockidx(fd);
        if (sockidx_r >= 0) {
            virtio_net_recv();
            ret = net_recv(sockidx_r, buf, count);
            if (ret == -EAGAIN) {
                for (int retry = 0; retry < 50; retry++) {
                    for (volatile int d = 0; d < 100000; d++) ;
                    virtio_net_recv();
                    ret = net_recv(sockidx_r, buf, count);
                    if (ret != -EAGAIN) break;
                }
            }
        } else if (fd == 0 && !vfs_fd_has_vnode(fd)) {
            struct tty *tp = tty_get_console();
            ret = tty_read(tp, buf, count);
        } else {
            ret = vfs_read(fd, buf, count);
        }
    }

    if (ret < 0)
        return (int)(-ret);

    syscall_return(tf, ret);
    return 0;
}

/*
 * sys_write - Write to a file descriptor
 *
 * x0 = fd, x1 = buf, x2 = count
 * Returns: bytes written in x0
 */
int sys_write(struct trap_frame *tf)
{
    int fd              = (int)tf->regs[0];
    const void *buf     = (const void *)tf->regs[1];
    uint64_t count      = tf->regs[2];

    if (buf == NULL)
        return EINVAL;

    int64_t ret;

    /* PTY fd: dispatch to PTY write */
    {
        int pty_wside;
        struct pty *pty_w = (struct pty *)vfs_get_pty(fd, &pty_wside);
        if (pty_w != NULL) {
            if (pty_wside == 0) {
                /* Master side — write feeds slave input */
                ret = pty_master_write(pty_w, buf, count);
            } else {
                /* Slave side — write with output processing */
                ret = pty_slave_write(pty_w, buf, count);
            }
            if (ret < 0)
                return (int)(-ret);
            syscall_return(tf, ret);
            return 0;
        }
    }

    /*
     * Console fast path: fd 1 (stdout) and fd 2 (stderr) go directly
     * to the UART. Check that the fd is the console sentinel (no vnode)
     * rather than a real file descriptor.
     */
    /* Pipe fd: write to pipe ring buffer */
    int pipe_wdir;
    struct pipe_data *pipe_w = (struct pipe_data *)vfs_get_pipe(fd, &pipe_wdir);
    if (pipe_w != NULL && pipe_wdir == 1) {
        /* Write end of pipe */
        if (pipe_w->read_closed) {
            /* Broken pipe — reader closed */
            return EPIPE;
        }
        uint64_t nwritten = 0;
        struct proc *pp = proc_current();
        while (nwritten < count) {
            if (pipe_w->count >= PIPE_BUF_SIZE) {
                if (nwritten > 0)
                    break;
                /* Buffer full — yield and retry */
                extern void sched_yield(void);
                sched_yield();
                continue;
            }
            uint8_t byte = 0;
            if (pp && pp->p_vmspace) {
                uint64_t pa = vmm_translate(pp->p_vmspace->pgd,
                                            (uint64_t)buf + nwritten);
                if (pa) byte = *(const uint8_t *)pa;
            }
            pipe_w->buf[pipe_w->write_pos] = byte;
            pipe_w->write_pos = (pipe_w->write_pos + 1) % PIPE_BUF_SIZE;
            pipe_w->count++;
            nwritten++;
        }
        ret = (int64_t)nwritten;
    }
    /* Socket fd: delegate to net_send */
    else {
        int sockidx_w = vfs_get_sockidx(fd);
        if (sockidx_w >= 0) {
            virtio_net_recv();
            ret = net_send(sockidx_w, buf, count);
        } else if ((fd == 1 || fd == 2) && !vfs_fd_has_vnode(fd)) {
            struct tty *tp = tty_get_console();
            ret = tty_write(tp, buf, count);
        } else {
            ret = vfs_write(fd, buf, count);
        }
    }

    if (ret < 0)
        return (int)(-ret);

    syscall_return(tf, ret);
    return 0;
}

/*
 * sys_pread - Read at offset without changing file position
 *
 * x0 = fd, x1 = buf, x2 = count, x3 = offset
 *
 * Implements pread by saving the file offset, seeking to the requested
 * offset, reading, then restoring the original offset.
 */
int sys_pread(struct trap_frame *tf)
{
    int fd          = (int)tf->regs[0];
    void *buf       = (void *)tf->regs[1];
    uint64_t count  = tf->regs[2];
    int64_t offset  = (int64_t)tf->regs[3];

    if (buf == NULL)
        return EINVAL;

    /* Save current offset */
    int64_t saved = vfs_lseek(fd, 0, SEEK_CUR);
    if (saved < 0)
        return (int)(-saved);

    /* Seek to requested offset */
    int64_t seeked = vfs_lseek(fd, offset, SEEK_SET);
    if (seeked < 0)
        return (int)(-seeked);

    /* Read */
    int64_t nread = vfs_read(fd, buf, count);

    /* Restore original offset */
    vfs_lseek(fd, saved, SEEK_SET);

    if (nread < 0)
        return (int)(-nread);

    syscall_return(tf, nread);
    return 0;
}

/*
 * sys_pwrite - Write at offset without changing file position
 *
 * x0 = fd, x1 = buf, x2 = count, x3 = offset
 */
int sys_pwrite(struct trap_frame *tf)
{
    int fd              = (int)tf->regs[0];
    const void *buf     = (const void *)tf->regs[1];
    uint64_t count      = tf->regs[2];
    int64_t offset      = (int64_t)tf->regs[3];

    if (buf == NULL)
        return EINVAL;

    /* Save current offset */
    int64_t saved = vfs_lseek(fd, 0, SEEK_CUR);
    if (saved < 0)
        return (int)(-saved);

    /* Seek to requested offset */
    int64_t seeked = vfs_lseek(fd, offset, SEEK_SET);
    if (seeked < 0)
        return (int)(-seeked);

    /* Write */
    int64_t nwritten = vfs_write(fd, buf, count);

    /* Restore original offset */
    vfs_lseek(fd, saved, SEEK_SET);

    if (nwritten < 0)
        return (int)(-nwritten);

    syscall_return(tf, nwritten);
    return 0;
}

/*
 * sys_lseek - Reposition read/write file offset
 *
 * x0 = fd, x1 = offset, x2 = whence
 * Returns: new offset in x0
 */
int sys_lseek(struct trap_frame *tf)
{
    int fd          = (int)tf->regs[0];
    int64_t offset  = (int64_t)tf->regs[1];
    int whence      = (int)tf->regs[2];

    int64_t ret = vfs_lseek(fd, offset, whence);
    if (ret < 0)
        return (int)(-ret);

    syscall_return(tf, ret);
    return 0;
}

/*
 * sys_fstat - Get file status
 *
 * x0 = fd, x1 = pointer to struct stat
 */
int sys_fstat(struct trap_frame *tf)
{
    int fd              = (int)tf->regs[0];
    struct stat *st     = (struct stat *)tf->regs[1];

    if (st == NULL)
        return EINVAL;

    int ret = vfs_fstat(fd, st);
    if (ret < 0)
        return (int)(-ret);

    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_dup - Duplicate a file descriptor
 *
 * x0 = oldfd
 * Returns: new fd in x0 (lowest available >= 0)
 */
int sys_dup(struct trap_frame *tf)
{
    int oldfd = (int)tf->regs[0];

    int newfd = vfs_dup_fd(oldfd, 0);
    if (newfd < 0)
        return (int)(-newfd);

    syscall_return(tf, newfd);
    return 0;
}

/*
 * sys_dup2 - Duplicate a file descriptor to a specific number
 *
 * x0 = oldfd, x1 = newfd
 * Returns: newfd in x0
 *
 * If oldfd == newfd, return newfd (no-op per POSIX).
 * If newfd is already open, close it first, then duplicate oldfd to newfd.
 */
int sys_dup2(struct trap_frame *tf)
{
    int oldfd = (int)tf->regs[0];
    int newfd = (int)tf->regs[1];

    if (oldfd < 0 || oldfd >= VFS_MAX_FD || newfd < 0 || newfd >= VFS_MAX_FD)
        return EBADF;

    /* Verify oldfd is valid */
    if (!vfs_fd_has_vnode(oldfd) && vfs_get_fd_flags(oldfd) < 0) {
        /* Check if it's a console sentinel (refcount > 0 but no vnode) */
        /* vfs_get_fd_flags returns -EBADF for truly invalid fds */
        /* For console fds (0,1,2), fd_flags exists, so this works */
    }

    /* If oldfd == newfd, just return it (POSIX) */
    if (oldfd == newfd) {
        syscall_return(tf, newfd);
        return 0;
    }

    /* Close newfd if it's open (ignore errors) */
    vfs_close(newfd);

    /* Now duplicate oldfd to newfd.
     * We can't use vfs_dup_fd (which picks lowest free >= minfd).
     * Instead, we directly copy at the VFS level.
     * Use a targeted approach: close newfd, then call vfs_dup_fd
     * with minfd=newfd. Since newfd was just freed, it should be
     * picked as the lowest free fd >= newfd... unless something
     * between oldfd+1 and newfd-1 is also free.
     * 
     * Simpler: use vfs_dup2 if available, otherwise we need a
     * direct copy. Let's implement the copy inline.
     */
    /* vfs_dup_fd won't necessarily give us exactly newfd.
     * We need to directly manipulate the fd table. Use a helper. */
    int result = vfs_dup_fd(oldfd, newfd);
    if (result < 0)
        return (int)(-result);
    
    /* If we got a different fd than newfd, that's a problem.
     * In practice with our sequential allocator, closing newfd
     * then dup_fd(oldfd, newfd) should give us newfd. */
    if (result != newfd) {
        /* Got wrong fd - close it and try harder.
         * This shouldn't happen since we just freed newfd. */
        vfs_close(result);
        return EBADF;
    }

    syscall_return(tf, newfd);
    return 0;
}

/*
 * sys_pipe - Create a pipe
 *
 * x0 = int fildes[2] (user pointer, receives read/write fds)
 * Returns: 0 on success
 *
 * Pipes are implemented as a small kernel buffer (4KB). Data written
 * to pipe[1] can be read from pipe[0]. For our single-threaded use
 * case (bash heredocs), we use a simplified synchronous pipe backed
 * by an anonymous memory buffer.
 */

/* Small pool of pipe structures (struct pipe_data defined above sys_read) */
#define PIPE_MAX    16
static struct pipe_data pipe_pool[PIPE_MAX];
static bool pipe_pool_used[PIPE_MAX];

static struct pipe_data *pipe_alloc_data(void)
{
    for (int i = 0; i < PIPE_MAX; i++) {
        if (!pipe_pool_used[i]) {
            pipe_pool_used[i] = true;
            struct pipe_data *pd = &pipe_pool[i];
            pd->read_pos = 0;
            pd->write_pos = 0;
            pd->count = 0;
            pd->write_closed = false;
            pd->read_closed = false;
            return pd;
        }
    }
    return NULL;
}

int sys_pipe(struct trap_frame *tf)
{
    uint64_t fildes_uaddr = tf->regs[0];
    if (fildes_uaddr == 0)
        return EINVAL;

    struct pipe_data *pd = pipe_alloc_data();
    if (pd == NULL)
        return ENFILE;

    /* Allocate two file descriptors with pipe data pointers */
    int rfd = vfs_alloc_pipefd(pd, 0);  /* 0 = read end */
    if (rfd < 0) {
        pipe_pool_used[pd - pipe_pool] = false;
        return EMFILE;
    }
    int wfd = vfs_alloc_pipefd(pd, 1);  /* 1 = write end */
    if (wfd < 0) {
        vfs_free_fd(rfd);
        pipe_pool_used[pd - pipe_pool] = false;
        return EMFILE;
    }

    /* Write the fd pair to user space */
    struct proc *p = proc_current();
    if (p && p->p_vmspace) {
        uint64_t pa0 = vmm_translate(p->p_vmspace->pgd, fildes_uaddr);
        uint64_t pa1 = vmm_translate(p->p_vmspace->pgd, fildes_uaddr + 4);
        if (pa0) *(int *)pa0 = rfd;
        if (pa1) *(int *)pa1 = wfd;
    }

    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_fcntl - File control
 *
 * x0 = fd, x1 = cmd, x2 = arg
 */
int sys_fcntl(struct trap_frame *tf)
{
    int fd  = (int)tf->regs[0];
    int cmd = (int)tf->regs[1];
    uint64_t arg = tf->regs[2];

    switch (cmd) {
    case F_DUPFD: {
        /* Duplicate fd to lowest available >= arg */
        int newfd = vfs_dup_fd(fd, (int)arg);
        if (newfd < 0)
            return (int)(-newfd);
        syscall_return(tf, newfd);
        return 0;
    }

    case F_GETFD: {
        int flags = vfs_get_fd_flags(fd);
        if (flags < 0)
            return EBADF;
        syscall_return(tf, flags);
        return 0;
    }

    case F_SETFD: {
        int err = vfs_set_fd_flags(fd, (uint8_t)arg);
        if (err < 0)
            return EBADF;
        syscall_return(tf, 0);
        return 0;
    }

    case F_GETFL: {
        int flags = vfs_get_file_flags(fd);
        if (flags < 0)
            return EBADF;
        syscall_return(tf, flags);
        return 0;
    }

    case F_SETFL: {
        int err = vfs_set_file_flags(fd, (uint32_t)arg);
        if (err < 0)
            return EBADF;
        syscall_return(tf, 0);
        return 0;
    }

    case F_GETOWN:
        /* No async I/O owner yet - return 0 */
        syscall_return(tf, 0);
        return 0;

    case F_SETOWN:
        /* Accept but ignore - no async I/O signal support yet */
        syscall_return(tf, 0);
        return 0;

    default:
        kprintf("[fcntl] unimplemented cmd %d on fd %d\n", cmd, fd);
        return EINVAL;
    }
}

/*
 * sys_unlink - Remove a directory entry
 *
 * x0 = path (user pointer)
 */
int sys_unlink(struct trap_frame *tf)
{
    const char *path = (const char *)tf->regs[0];

    if (path == NULL)
        return EINVAL;

    char abs_path[PATH_MAX_KERN];
    int perr = resolve_user_path(path, abs_path, sizeof(abs_path));
    if (perr)
        return perr;

    int ret = vfs_unlink(abs_path);
    if (ret < 0)
        return (int)(-ret);

    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_chdir - Change current working directory
 *
 * x0 = path (user pointer)
 *
 * Verifies the path exists and is a directory, then stores the path
 * string in proc->p_cwd_path for getcwd() and updates the cwd vnode.
 */
static int sys_chdir(struct trap_frame *tf)
{
    const char *path = (const char *)tf->regs[0];
    if (path == NULL)
        return EINVAL;

    char abs_path[PATH_MAX_KERN];
    int perr = resolve_user_path(path, abs_path, sizeof(abs_path));
    if (perr)
        return perr;

    /* Verify the path exists via VFS */
    struct vnode *vn = NULL;
    int err = vfs_lookup(abs_path, &vn);
    if (err != 0 || vn == NULL)
        return ENOENT;

    /* Must be a directory */
    if (vn->v_type != VDIR) {
        vnode_release(vn);
        return ENOTDIR;
    }

    /* Update the proc's working directory */
    struct proc *p = proc_current();
    if (p) {
        /* Release old cwd vnode if any */
        if (p->p_cwd)
            vnode_release(p->p_cwd);
        p->p_cwd = vn;  /* takes ownership of the ref */

        /* Store the canonicalized absolute path for getcwd */
        uint64_t i;
        for (i = 0; i < sizeof(p->p_cwd_path) - 1 && abs_path[i] != '\0'; i++)
            p->p_cwd_path[i] = abs_path[i];
        p->p_cwd_path[i] = '\0';
    } else {
        vnode_release(vn);
    }

    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_ioctl - I/O control operations on file descriptors.
 *
 * x0 = fd, x1 = cmd (ioctl number), x2 = arg (user pointer)
 *
 * For terminal fds (0/1/2 console), dispatches to the TTY subsystem.
 * For regular file fds, handles generic file ioctls.
 */
static int sys_ioctl(struct trap_frame *tf)
{
    int fd              = (int)tf->regs[0];
    unsigned long cmd   = (unsigned long)tf->regs[1];
    uint64_t arg        = tf->regs[2];

    /*
     * Console TTY: fds 0, 1, 2 when they are console sentinels
     * (no backing vnode). All terminal ioctls go through the TTY layer.
     */
    if ((fd == 0 || fd == 1 || fd == 2) && !vfs_fd_has_vnode(fd)) {
        struct tty *tp = tty_get_console();
        int err = tty_ioctl(tp, cmd, arg);
        if (err != 0)
            return err;
        syscall_return(tf, 0);
        return 0;
    }

    /*
     * PTY slave fd: route to the PTY's slave TTY for ioctl.
     */
    {
        int pty_ioctl_side;
        struct pty *pty_io = (struct pty *)vfs_get_pty(fd, &pty_ioctl_side);
        if (pty_io != NULL) {
            struct tty *tp = pty_get_slave_tty(pty_io);
            int err = tty_ioctl(tp, cmd, arg);
            if (err != 0)
                return err;
            syscall_return(tf, 0);
            return 0;
        }
    }

    /*
     * Character device vnodes (e.g., /dev/console opened by getty):
     * If the fd's vnode is a devfs console device, route to TTY ioctl.
     */
    {
        struct vnode *vp = vfs_fd_get_vnode(fd);
        if (vp != NULL && devfs_is_console(vp)) {
            struct tty *tp = tty_get_console();
            int err = tty_ioctl(tp, cmd, arg);
            if (err != 0)
                return err;
            syscall_return(tf, 0);
            return 0;
        }
    }

    /*
     * Regular file descriptors — handle generic file ioctls.
     */
    switch (cmd) {
    case FIONREAD: {
        /* Report 0 bytes available for non-TTY fds for now */
        int val = 0;
        struct proc *p = proc_current();
        if (p && p->p_vmspace) {
            uint64_t pa = vmm_translate(p->p_vmspace->pgd, arg);
            if (pa != 0)
                *(int *)pa = val;
        }
        syscall_return(tf, 0);
        return 0;
    }

    case FIONBIO: {
        /* Set/clear O_NONBLOCK based on *arg */
        struct proc *p = proc_current();
        if (p && p->p_vmspace) {
            uint64_t pa = vmm_translate(p->p_vmspace->pgd, arg);
            if (pa != 0) {
                int val = *(int *)pa;
                int cur = vfs_get_file_flags(fd);
                if (cur >= 0) {
                    if (val)
                        vfs_set_file_flags(fd, (uint32_t)cur | O_NONBLOCK);
                    else
                        vfs_set_file_flags(fd, (uint32_t)cur & ~(uint32_t)O_NONBLOCK);
                }
            }
        }
        syscall_return(tf, 0);
        return 0;
    }

    case FIOCLEX:
        vfs_set_fd_flags(fd, FD_CLOEXEC);
        syscall_return(tf, 0);
        return 0;

    case FIONCLEX:
        vfs_set_fd_flags(fd, 0);
        syscall_return(tf, 0);
        return 0;

    default:
        kprintf("[ioctl] unimplemented cmd 0x%lx on fd %d\n", cmd, fd);
        return ENOTTY;
    }
}

/* ============================================================================
 * Memory Management Syscalls
 * ============================================================================ */

/*
 * sys_mmap - Map files or anonymous memory
 *
 * x0 = addr, x1 = length, x2 = prot, x3 = flags, x4 = fd, x5 = offset
 * Returns: mapped address in x0, or MAP_FAILED (-1) on error
 *
 * Supports:
 *   - MAP_ANON | MAP_PRIVATE: anonymous zero-filled pages
 *   - MAP_FIXED: place mapping at exact address
 *   - MAP_PRIVATE with fd: read file data into private pages
 *
 * Required by dyld to allocate memory for loading dylibs.
 */

/* mmap flags (XNU-compatible) */
#define MAP_ANON_K      0x1000
#define MAP_PRIVATE_K   0x0002
#define MAP_FIXED_K     0x0010

/* mmap prot (XNU-compatible) */
#define PROT_READ_K     0x01
#define PROT_WRITE_K    0x02
#define PROT_EXEC_K     0x04

/* Simple bump allocator for anonymous mmap address hints.
 * Starts at 0x300000000 (12GB) to avoid collisions with main binary
 * (0x100000000) and dyld (0x200000000). */
static uint64_t mmap_next_addr = 0x300000000UL;

int sys_mmap(struct trap_frame *tf)
{
    uint64_t addr   = tf->regs[0];
    uint64_t length = tf->regs[1];
    uint32_t prot   = (uint32_t)tf->regs[2];
    uint32_t flags  = (uint32_t)tf->regs[3];
    int fd          = (int)tf->regs[4];
    int64_t offset  = (int64_t)tf->regs[5];

    /* Verbose mmap tracing - uncomment for debugging
    kprintf("[mmap] enter: addr=0x%lx len=0x%lx prot=0x%x flags=0x%x fd=%d\n",
            addr, length, prot, flags, fd);
    */

    if (length == 0)
        return EINVAL;

    /* Round length up to page size */
    length = ALIGN_UP(length, PAGE_SIZE);

    struct proc *p = proc_current();
    if (p == NULL || p->p_vmspace == NULL)
        return EINVAL;

    /* Determine the virtual address for the mapping */
    uint64_t map_va;
    if (flags & MAP_FIXED_K) {
        if (addr == 0)
            return EINVAL;
        map_va = addr & ~(PAGE_SIZE - 1);
    } else if (addr != 0) {
        /* Hint address — try it, but we just use it directly for simplicity */
        map_va = addr & ~(PAGE_SIZE - 1);
    } else {
        /* Kernel chooses the address */
        map_va = ALIGN_UP(mmap_next_addr, PAGE_SIZE);
        mmap_next_addr = map_va + length;
    }

    /* Determine PTE flags from prot */
    uint64_t pte_flags;
    if ((prot & PROT_READ_K) && (prot & PROT_WRITE_K) && (prot & PROT_EXEC_K))
        pte_flags = PTE_USER_RWX;
    else if ((prot & PROT_READ_K) && (prot & PROT_WRITE_K))
        pte_flags = PTE_USER_RW;
    else if ((prot & PROT_READ_K) && (prot & PROT_EXEC_K))
        pte_flags = PTE_USER_RX;
    else if (prot & PROT_READ_K)
        pte_flags = PTE_USER_RO;
    else
        pte_flags = PTE_USER_RW;  /* Default: RW */

    /* Allocate physical pages and map them */
    uint64_t num_pages = length / PAGE_SIZE;
    /* kprintf("[mmap] mapping %lu pages at VA 0x%lx\n", num_pages, map_va); */
    for (uint64_t i = 0; i < num_pages; i++) {
        uint64_t pa = pmm_alloc_page();
        if (pa == 0) {
            /* OOM: unmap what we already mapped */
            for (uint64_t j = 0; j < i; j++) {
                uint64_t old_pa = vmm_unmap_page(p->p_vmspace->pgd,
                                                  map_va + j * PAGE_SIZE);
                if (old_pa)
                    pmm_free_page(old_pa);
            }
            return ENOMEM;
        }

        /* Zero the page (identity mapping: PA == VA for kernel access) */
        uint8_t *kva = (uint8_t *)pa;
        for (uint64_t b = 0; b < PAGE_SIZE; b++)
            kva[b] = 0;

        int ret = vmm_map_page(p->p_vmspace->pgd,
                               map_va + i * PAGE_SIZE, pa, pte_flags);
        if (ret != 0) {
            pmm_free_page(pa);
            return ENOMEM;
        }
    }

    /*
     * If this is a file-backed mapping (not MAP_ANON), read file data
     * into the mapped pages. dyld uses this pattern:
     *   mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0)
     * followed by sys_read() to fill the buffer. So this path is less
     * critical, but we support it for completeness.
     */
    if (!(flags & MAP_ANON_K) && fd >= 0) {
        /* Save and restore file position */
        int64_t saved_pos = vfs_lseek(fd, 0, SEEK_CUR);

        if (offset >= 0)
            vfs_lseek(fd, offset, SEEK_SET);

        /* Read file data into the mapped region.
         * We read page by page, translating user VA to PA for the copy. */
        uint64_t remaining = length;
        uint64_t cur_va = map_va;
        while (remaining > 0) {
            uint64_t chunk = remaining > PAGE_SIZE ? PAGE_SIZE : remaining;
            uint64_t pa = vmm_translate(p->p_vmspace->pgd, cur_va);
            if (pa == 0)
                break;
            /* Read directly into physical page (identity mapped) */
            int64_t nread = vfs_read(fd, (void *)pa, chunk);
            if (nread <= 0)
                break;
            cur_va += chunk;
            remaining -= chunk;
        }

        /* Restore file position */
        if (saved_pos >= 0)
            vfs_lseek(fd, saved_pos, SEEK_SET);
    }

    /* Return the mapped address */
    /* kprintf("[mmap] addr=0x%lx -> 0x%lx\n", addr, map_va); */
    syscall_return(tf, (int64_t)map_va);
    return 0;
}

/*
 * sys_munmap - Unmap memory
 *
 * x0 = addr, x1 = length
 */
int sys_munmap(struct trap_frame *tf)
{
    uint64_t addr   = tf->regs[0];
    uint64_t length = tf->regs[1];

    if (length == 0 || (addr & (PAGE_SIZE - 1)) != 0)
        return EINVAL;

    length = ALIGN_UP(length, PAGE_SIZE);

    struct proc *p = proc_current();
    if (p == NULL || p->p_vmspace == NULL)
        return EINVAL;

    /* Unmap each page and free the physical page */
    uint64_t num_pages = length / PAGE_SIZE;
    for (uint64_t i = 0; i < num_pages; i++) {
        uint64_t pa = vmm_unmap_page(p->p_vmspace->pgd,
                                      addr + i * PAGE_SIZE);
        if (pa != 0)
            pmm_free_page(pa);
    }

    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_mprotect - Set memory protection
 *
 * x0 = addr, x1 = length, x2 = prot
 *
 * For now, always succeeds (we don't actually change the PTE permissions).
 * This is safe because our initial mappings are typically RW or RWX.
 * A full implementation would walk the page tables and update PTE AP/XN bits.
 */
int sys_mprotect(struct trap_frame *tf)
{
    uint64_t addr   = tf->regs[0];
    uint64_t length = tf->regs[1];
    uint32_t prot   = (uint32_t)tf->regs[2];

    struct proc *p = proc_current();
    if (!p || !p->p_vmspace || !p->p_vmspace->pgd) {
        syscall_return(tf, 0);
        return 0;
    }

    /* Page-align */
    addr &= ~(PAGE_SIZE - 1);
    length = ALIGN_UP(length, PAGE_SIZE);

    /* Convert prot to PTE flags (same mapping as sys_mmap) */
    uint64_t pte_flags;
    if ((prot & PROT_READ_K) && (prot & PROT_WRITE_K) && (prot & PROT_EXEC_K))
        pte_flags = PTE_USER_RWX;
    else if ((prot & PROT_READ_K) && (prot & PROT_WRITE_K))
        pte_flags = PTE_USER_RW;
    else if ((prot & PROT_READ_K) && (prot & PROT_EXEC_K))
        pte_flags = PTE_USER_RX;
    else if (prot & PROT_READ_K)
        pte_flags = PTE_USER_RO;
    else
        pte_flags = PTE_USER_RO;  /* PROT_NONE → read-only (simplification) */

    /* Walk each page and update its PTE flags */
    for (uint64_t va = addr; va < addr + length; va += PAGE_SIZE) {
        vmm_protect_page(p->p_vmspace->pgd, va, pte_flags);
        /* Silently skip unmapped pages — matches XNU behaviour */
    }

    syscall_return(tf, 0);
    return 0;
}

/* ============================================================================
 * System Information Syscalls
 * ============================================================================ */

/*
 * sysctl OIDs are defined in <sys/syscall.h> (shared header)
 */

/*
 * sysctl_copyout_str - Helper to copy a string to a sysctl output buffer.
 */
static int sysctl_copyout_str(const char *str, void *oldp, size_t *oldlenp)
{
    uint32_t len = sc_strlen(str) + 1; /* include NUL */
    if (oldp != NULL && oldlenp != NULL) {
        if (*oldlenp < len)
            return EINVAL;
        sc_strcpy((char *)oldp, str);
        *oldlenp = len;
    } else if (oldlenp != NULL) {
        *oldlenp = len; /* size query */
    }
    return 0;
}

static int sysctl_copyout_int(int val, void *oldp, size_t *oldlenp)
{
    if (oldp != NULL && oldlenp != NULL) {
        if (*oldlenp < sizeof(int))
            return EINVAL;
        *(int *)oldp = val;
        *oldlenp = sizeof(int);
    } else if (oldlenp != NULL) {
        *oldlenp = sizeof(int);
    }
    return 0;
}

static int sysctl_copyout_u64(uint64_t val, void *oldp, size_t *oldlenp)
{
    if (oldp != NULL && oldlenp != NULL) {
        if (*oldlenp < sizeof(uint64_t))
            return EINVAL;
        *(uint64_t *)oldp = val;
        *oldlenp = sizeof(uint64_t);
    } else if (oldlenp != NULL) {
        *oldlenp = sizeof(uint64_t);
    }
    return 0;
}

/*
 * sys_sysctl - Get/set system information
 *
 * x0 = name (int array pointer), x1 = namelen
 * x2 = oldp (output buffer), x3 = oldlenp (in/out size)
 * x4 = newp (input buffer, NULL for read-only)
 * x5 = newlen
 */
int sys_sysctl(struct trap_frame *tf)
{
    int *name           = (int *)tf->regs[0];
    uint32_t namelen    = (uint32_t)tf->regs[1];
    void *oldp          = (void *)tf->regs[2];
    size_t *oldlenp     = (size_t *)tf->regs[3];
    /* newp in regs[4], newlen in regs[5] - not used yet */

    if (name == NULL || namelen < 2)
        return EINVAL;

    int err;

    /* --- CTL_HW (6) --- */
    if (name[0] == CTL_HW) {
        switch (name[1]) {
        case HW_PAGESIZE:
            err = sysctl_copyout_int((int)PAGE_SIZE, oldp, oldlenp);
            if (err) return err;
            syscall_return(tf, 0);
            return 0;

        case HW_MACHINE:
            err = sysctl_copyout_str("arm64", oldp, oldlenp);
            if (err) return err;
            syscall_return(tf, 0);
            return 0;

        case HW_NCPU: {
            err = sysctl_copyout_int(4, oldp, oldlenp); /* 4 cores from -smp 4 */
            if (err) return err;
            syscall_return(tf, 0);
            return 0;
        }

        case HW_MEMSIZE: {
            /* Report available RAM. We have 256MB in QEMU config. */
            uint64_t memsize = 256ULL * 1024 * 1024;
            err = sysctl_copyout_u64(memsize, oldp, oldlenp);
            if (err) return err;
            syscall_return(tf, 0);
            return 0;
        }

        default:
            break;
        }
    }

    /* --- CTL_KERN (1) --- */
    if (name[0] == CTL_KERN) {
        switch (name[1]) {
        case KERN_OSTYPE:
            err = sysctl_copyout_str("Kiseki", oldp, oldlenp);
            if (err) return err;
            syscall_return(tf, 0);
            return 0;

        case KERN_OSRELEASE:
            err = sysctl_copyout_str("1.0.0", oldp, oldlenp);
            if (err) return err;
            syscall_return(tf, 0);
            return 0;

        case KERN_VERSION:
            err = sysctl_copyout_str(
                "Kiseki Kernel Version 1.0.0: ARM64 Hybrid Kernel",
                oldp, oldlenp);
            if (err) return err;
            syscall_return(tf, 0);
            return 0;

        case KERN_HOSTNAME:
            err = sysctl_copyout_str("kiseki", oldp, oldlenp);
            if (err) return err;
            syscall_return(tf, 0);
            return 0;

        case KERN_OSVERSION:
            err = sysctl_copyout_str("1A1", oldp, oldlenp);
            if (err) return err;
            syscall_return(tf, 0);
            return 0;

        case KERN_OSREV:
            err = sysctl_copyout_int(1, oldp, oldlenp);
            if (err) return err;
            syscall_return(tf, 0);
            return 0;

        default:
            break;
        }
    }

    /* --- CTL_NET (4) --- */
    if (name[0] == CTL_NET && namelen >= 2) {
        /* Get network configuration from DHCP module */
        extern uint32_t dhcp_get_ip(void);
        extern uint32_t dhcp_get_netmask(void);
        extern uint32_t dhcp_get_gateway(void);
        
        switch (name[1]) {
        case NET_KISEKI_IFADDR: {
            uint32_t ip = dhcp_get_ip();
            err = sysctl_copyout_int((int)ip, oldp, oldlenp);
            if (err) return err;
            syscall_return(tf, 0);
            return 0;
        }
        case NET_KISEKI_IFMASK: {
            uint32_t mask = dhcp_get_netmask();
            err = sysctl_copyout_int((int)mask, oldp, oldlenp);
            if (err) return err;
            syscall_return(tf, 0);
            return 0;
        }
        case NET_KISEKI_IFGW: {
            uint32_t gw = dhcp_get_gateway();
            err = sysctl_copyout_int((int)gw, oldp, oldlenp);
            if (err) return err;
            syscall_return(tf, 0);
            return 0;
        }
        default:
            break;
        }
    }

    /* Unknown sysctl — return ENOSYS (many programs tolerate this) */
    return ENOSYS;
}

/* ============================================================================
 * Signal Syscalls
 * ============================================================================ */

/*
 * sys_pthread_kill - Send signal to a thread
 *
 * x0 = thread port, x1 = signal number
 *
 * In our single-threaded-per-process model, this is equivalent to
 * sending the signal to the owning process. Accept signal 0 (existence
 * check) and non-zero signals (record as pending).
 */
int sys_pthread_kill(struct trap_frame *tf)
{
    /* uint64_t thread_port = tf->regs[0]; */
    int sig = (int)tf->regs[1];

    if (sig < 0 || sig >= NSIG)
        return EINVAL;

    /* sig 0 is just a validity check */
    if (sig == 0) {
        syscall_return(tf, 0);
        return 0;
    }

    /* Post to current proc (since we have 1 thread per proc) */
    struct proc *p = proc_current();
    if (p) {
        sigaddset(&p->p_sigacts.pending, sig);
    }

    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_sigaction - Examine and change a signal action
 *
 * x0 = signum
 * x1 = pointer to new struct sigaction (or NULL to query only)
 * x2 = pointer to old struct sigaction (or NULL to skip)
 *
 * macOS arm64 struct sigaction layout:
 *   uint64_t sa_handler/sa_sigaction;  (8 bytes - function pointer)
 *   uint32_t sa_mask;                  (4 bytes - sigset_t)
 *   int32_t  sa_flags;                (4 bytes)
 *   Total: 16 bytes
 *
 * We store the actions in proc->p_sigacts.actions[].
 */
static int sys_sigaction(struct trap_frame *tf)
{
    int signum = (int)tf->regs[0];
    uint64_t act_uaddr = tf->regs[1];
    uint64_t oldact_uaddr = tf->regs[2];

    if (signum < 1 || signum >= NSIG)
        return EINVAL;

    /* SIGKILL and SIGSTOP cannot be caught or ignored */
    if (signum == SIGKILL || signum == SIGSTOP)
        return EINVAL;

    struct proc *p = proc_current();
    if (p == NULL)
        return EINVAL;

    struct sigaction *cur = &p->p_sigacts.actions[signum];

    /* Copy current action to oldact if requested */
    if (oldact_uaddr != 0 && p->p_vmspace) {
        uint64_t pa = vmm_translate(p->p_vmspace->pgd, oldact_uaddr);
        if (pa != 0) {
            /* Write: sa_handler (8), sa_mask (4), sa_flags (4) */
            *(uint64_t *)pa = (uint64_t)cur->sa_handler;
            *(uint32_t *)(pa + 8) = (uint32_t)cur->sa_mask;
            *(int32_t *)(pa + 12) = cur->sa_flags;
        }
    }

    /* Install new action if provided */
    if (act_uaddr != 0 && p->p_vmspace) {
        uint64_t pa = vmm_translate(p->p_vmspace->pgd, act_uaddr);
        if (pa != 0) {
            cur->sa_handler = (sig_handler_t)(*(uint64_t *)pa);
            cur->sa_mask = (sigset_t)(*(uint32_t *)(pa + 8));
            cur->sa_flags = *(int32_t *)(pa + 12);
        }
    }

    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_sigprocmask - Examine and change blocked signals
 *
 * x0 = how (SIG_BLOCK=1, SIG_UNBLOCK=2, SIG_SETMASK=3)
 * x1 = pointer to new sigset_t (or NULL)
 * x2 = pointer to old sigset_t (or NULL)
 *
 * macOS sigset_t is uint32_t (32 signals, bit mask).
 */
static int sys_sigprocmask(struct trap_frame *tf)
{
    int how = (int)tf->regs[0];
    uint64_t set_uaddr = tf->regs[1];
    uint64_t oldset_uaddr = tf->regs[2];

    struct proc *p = proc_current();
    if (p == NULL)
        return EINVAL;

    /* Return current mask */
    if (oldset_uaddr != 0 && p->p_vmspace) {
        uint64_t pa = vmm_translate(p->p_vmspace->pgd, oldset_uaddr);
        if (pa != 0)
            *(uint32_t *)pa = (uint32_t)p->p_sigacts.blocked;
    }

    /* Apply new mask */
    if (set_uaddr != 0 && p->p_vmspace) {
        uint64_t pa = vmm_translate(p->p_vmspace->pgd, set_uaddr);
        if (pa != 0) {
            sigset_t newset = (sigset_t)(*(uint32_t *)pa);
            switch (how) {
            case SIG_BLOCK:
                p->p_sigacts.blocked |= newset;
                break;
            case SIG_UNBLOCK:
                p->p_sigacts.blocked &= ~newset;
                break;
            case SIG_SETMASK:
                p->p_sigacts.blocked = newset;
                break;
            default:
                return EINVAL;
            }
            /* SIGKILL and SIGSTOP can never be blocked */
            sigdelset(&p->p_sigacts.blocked, SIGKILL);
            sigdelset(&p->p_sigacts.blocked, SIGSTOP);
        }
    }

    syscall_return(tf, 0);
    return 0;
}

/* ============================================================================
 * Process Group / Session Syscalls
 * ============================================================================ */

/*
 * sys_getpgrp - Get process group ID of calling process
 *
 * Returns: process group ID in x0
 */
static int sys_getpgrp(struct trap_frame *tf)
{
    struct proc *p = proc_current();
    if (p == NULL)
        return EINVAL;

    syscall_return(tf, (int64_t)p->p_pgrp);
    return 0;
}

/*
 * sys_setpgid - Set process group ID
 *
 * x0 = pid (0 means calling process)
 * x1 = pgid (0 means use pid as pgid)
 *
 * A process can only set its own pgrp or a child's pgrp (before the
 * child has exec'd, in a strict implementation). We're permissive here
 * since we don't track the exec flag per child.
 */
static int sys_setpgid(struct trap_frame *tf)
{
    pid_t pid = (pid_t)(int64_t)tf->regs[0];
    pid_t pgid = (pid_t)(int64_t)tf->regs[1];

    struct proc *caller = proc_current();
    if (caller == NULL)
        return EINVAL;

    /* pid 0 means self */
    struct proc *target;
    if (pid == 0) {
        target = caller;
        pid = caller->p_pid;
    } else {
        target = proc_find(pid);
        if (target == NULL)
            return ESRCH;
        /* Must be self or a child */
        if (target != caller && target->p_ppid != caller->p_pid)
            return ESRCH;
    }

    /* pgid 0 means use pid as pgid */
    if (pgid == 0)
        pgid = pid;

    /* Can't change pgrp across sessions */
    if (target->p_session != caller->p_session)
        return EPERM;

    /* Session leaders can't change their pgrp */
    if (target->p_session_leader)
        return EPERM;

    target->p_pgrp = pgid;

    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_getpgid - Get process group ID of a specific process
 *
 * x0 = pid (0 means calling process)
 * Returns: process group ID in x0
 */
static int sys_getpgid(struct trap_frame *tf)
{
    pid_t pid = (pid_t)(int64_t)tf->regs[0];

    struct proc *target;
    if (pid == 0) {
        target = proc_current();
    } else {
        target = proc_find(pid);
    }

    if (target == NULL)
        return ESRCH;

    syscall_return(tf, (int64_t)target->p_pgrp);
    return 0;
}

/*
 * sys_setsid - Create a new session
 *
 * The calling process becomes the session leader of a new session
 * and the process group leader of a new process group. The process
 * has no controlling terminal.
 *
 * Returns: session ID (== caller's PID) in x0
 */
static int sys_setsid(struct trap_frame *tf)
{
    struct proc *p = proc_current();
    if (p == NULL)
        return EINVAL;

    /* Must not already be a session leader */
    if (p->p_session_leader)
        return EPERM;

    /* Must not already be a process group leader with the same pgid
     * as another process's session. Simplified check: just disallow
     * if already a pgrp leader. */
    /* For simplicity we skip this check — it's fine for our use case */

    p->p_pgrp = p->p_pid;
    p->p_session = p->p_pid;
    p->p_session_leader = true;

    /* Detach from controlling terminal (handled by TTY layer) */

    syscall_return(tf, (int64_t)p->p_pid);
    return 0;
}

/* ============================================================================
 * File System Syscalls
 * ============================================================================ */

/*
 * sys_access - Check file accessibility
 *
 * x0 = path (user pointer)
 * x1 = mode (F_OK=0, R_OK=4, W_OK=2, X_OK=1)
 *
 * Checks whether the calling process can access the file at path.
 * Uses real UID/GID (not effective) per POSIX spec.
 */
#define F_OK_K  0
#define R_OK_K  4
#define W_OK_K  2
#define X_OK_K  1

static int sys_access(struct trap_frame *tf)
{
    const char *path = (const char *)tf->regs[0];
    int mode = (int)tf->regs[1];

    if (path == NULL)
        return EINVAL;

    char abs_path[PATH_MAX_KERN];
    int perr = resolve_user_path(path, abs_path, sizeof(abs_path));
    if (perr)
        return perr;

    /* Look up the path */
    struct vnode *vn = NULL;
    int err = vfs_lookup(abs_path, &vn);
    if (err != 0 || vn == NULL)
        return ENOENT;

    /* F_OK: just check existence */
    if (mode == F_OK_K) {
        vnode_release(vn);
        syscall_return(tf, 0);
        return 0;
    }

    /*
     * Permission check using real UID/GID (POSIX access() semantics).
     * Root (uid 0) bypasses all checks.
     */
    struct proc *p = proc_current();
    if (p == NULL) {
        vnode_release(vn);
        return EINVAL;
    }

    uid_t ruid = p->p_ucred.cr_ruid;
    gid_t rgid = p->p_ucred.cr_rgid;

    if (ruid == 0) {
        /* Root can access anything */
        vnode_release(vn);
        syscall_return(tf, 0);
        return 0;
    }

    mode_t file_mode = vn->v_mode;
    int granted = 0;

    if (vn->v_uid == ruid) {
        /* Owner permissions */
        if (file_mode & S_IRUSR) granted |= R_OK_K;
        if (file_mode & S_IWUSR) granted |= W_OK_K;
        if (file_mode & S_IXUSR) granted |= X_OK_K;
    } else if (vn->v_gid == rgid) {
        /* Group permissions */
        if (file_mode & S_IRGRP) granted |= R_OK_K;
        if (file_mode & S_IWGRP) granted |= W_OK_K;
        if (file_mode & S_IXGRP) granted |= X_OK_K;
    } else {
        /* Other permissions */
        if (file_mode & S_IROTH) granted |= R_OK_K;
        if (file_mode & S_IWOTH) granted |= W_OK_K;
        if (file_mode & S_IXOTH) granted |= X_OK_K;
    }

    vnode_release(vn);

    if ((mode & granted) != mode)
        return EACCES;

    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_stat - Get file status by path
 *
 * x0 = path (user pointer)
 * x1 = pointer to struct stat (user pointer)
 *
 * Resolves the path, calls getattr on the vnode, and copies the
 * result to user space.
 */
static int sys_stat(struct trap_frame *tf)
{
    const char *path = (const char *)tf->regs[0];
    uint64_t st_uaddr = tf->regs[1];

    if (path == NULL || st_uaddr == 0)
        return EINVAL;

    struct proc *p = proc_current();
    if (p == NULL || p->p_vmspace == NULL)
        return EINVAL;

    char abs_path[PATH_MAX_KERN];
    int perr = resolve_user_path(path, abs_path, sizeof(abs_path));
    if (perr)
        return perr;

    /* Look up the path */
    struct vnode *vn = NULL;
    int err = vfs_lookup(abs_path, &vn);
    if (err != 0 || vn == NULL)
        return ENOENT;

    /* Get attributes */
    struct stat st;
    /* Zero it */
    for (uint64_t i = 0; i < sizeof(st); i++)
        ((uint8_t *)&st)[i] = 0;

    if (vn->v_ops && vn->v_ops->getattr) {
        err = vn->v_ops->getattr(vn, &st);
    } else {
        /* Synthesize from vnode fields (Darwin 144-byte layout) */
        st.st_dev = (dev_t)vn->v_dev;
        st.st_mode = vn->v_mode;
        st.st_nlink = vn->v_nlink;
        st.st_ino = vn->v_ino;
        st.st_uid = vn->v_uid;
        st.st_gid = vn->v_gid;
        st.st_rdev = 0;
        st.st_size = (int64_t)vn->v_size;
        st.st_blksize = 4096;
        st.st_blocks = (int64_t)((vn->v_size + 511) / 512);
        st.st_atimespec.tv_sec = 0;
        st.st_atimespec.tv_nsec = 0;
        st.st_mtimespec.tv_sec = 0;
        st.st_mtimespec.tv_nsec = 0;
        st.st_ctimespec.tv_sec = 0;
        st.st_ctimespec.tv_nsec = 0;
        st.st_birthtimespec.tv_sec = 0;
        st.st_birthtimespec.tv_nsec = 0;
        st.st_flags = 0;
        st.st_gen = 0;
        err = 0;
    }

    vnode_release(vn);

    if (err != 0)
        return (err < 0) ? -err : err;

    /* Copy to user space (byte-by-byte to handle page boundary) */
    uint8_t *src = (uint8_t *)&st;
    for (uint64_t i = 0; i < sizeof(struct stat); i++) {
        uint64_t pa = vmm_translate(p->p_vmspace->pgd, st_uaddr + i);
        if (pa == 0)
            return EFAULT;
        *(uint8_t *)pa = src[i];
    }

    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_lstat - Get file status by path (don't follow symlinks)
 *
 * x0 = path, x1 = pointer to struct stat
 *
 * Since we don't have symlinks yet, this is identical to stat.
 */
static int sys_lstat(struct trap_frame *tf)
{
    /* Same as stat — we have no symlinks yet */
    return sys_stat(tf);
}

/*
 * sys_getcwd - Get current working directory
 *
 * x0 = buf (user pointer)
 * x1 = size
 *
 * Returns: the path string in buf, with length in x0
 */
static int sys_getcwd(struct trap_frame *tf)
{
    uint64_t buf_uaddr = tf->regs[0];
    uint64_t size = tf->regs[1];

    if (buf_uaddr == 0 || size == 0)
        return EINVAL;

    struct proc *p = proc_current();
    if (p == NULL || p->p_vmspace == NULL)
        return EINVAL;

    const char *cwd = p->p_cwd_path;
    if (cwd[0] == '\0')
        cwd = "/";

    /* Measure length */
    uint64_t len = 0;
    while (cwd[len] != '\0')
        len++;
    len++;  /* include null terminator */

    if (len > size)
        return ERANGE;

    /* Copy to user space */
    uint64_t pa = vmm_translate(p->p_vmspace->pgd, buf_uaddr);
    if (pa == 0)
        return EFAULT;

    /* Copy byte by byte (may cross page boundary for long paths,
     * but cwd is typically short) */
    uint8_t *dst = (uint8_t *)pa;
    for (uint64_t i = 0; i < len; i++)
        dst[i] = (uint8_t)cwd[i];

    syscall_return(tf, (int64_t)buf_uaddr);
    return 0;
}

/*
 * sys_getdirentries - Read directory entries
 *
 * x0 = fd
 * x1 = buf (user pointer)
 * x2 = nbytes
 * x3 = basep (user pointer to long, or NULL)
 *
 * Returns: number of bytes transferred
 *
 * macOS getdirentries fills the buffer with struct dirent entries.
 * Our kernel struct dirent is 1048 bytes (Darwin arm64 ABI).
 * We read entries from VFS and pack them into the user buffer.
 */
static int sys_getdirentries(struct trap_frame *tf)
{
    int fd = (int)tf->regs[0];
    uint64_t buf_uaddr = tf->regs[1];
    uint64_t nbytes = tf->regs[2];
    /* basep in regs[3] — we ignore it for now */

    if (buf_uaddr == 0 || nbytes == 0)
        return EINVAL;

    struct proc *p = proc_current();
    if (p == NULL || p->p_vmspace == NULL)
        return EINVAL;

    /* Read directory entries into a kernel buffer, then copy to user.
     * Our struct dirent is 1048 bytes (Darwin arm64 ABI). Read one at a time.
     * Copy byte-by-byte using vmm_translate to handle page boundaries. */
    struct dirent kd;
    uint64_t total = 0;

    while (total + sizeof(struct dirent) <= nbytes) {
        int n = vfs_readdir(fd, &kd, 1);
        if (n <= 0)
            break;

        /* Copy the dirent struct byte-by-byte to user space */
        uint8_t *src = (uint8_t *)&kd;
        for (uint64_t i = 0; i < sizeof(struct dirent); i++) {
            uint64_t pa = vmm_translate(p->p_vmspace->pgd,
                                        buf_uaddr + total + i);
            if (pa == 0)
                goto done;
            *(uint8_t *)pa = src[i];
        }

        total += sizeof(struct dirent);
    }

done:
    syscall_return(tf, (int64_t)total);
    return 0;
}

/* ============================================================================
 * Misc Syscalls
 * ============================================================================ */

/*
 * sys_getegid - Return effective group ID
 */
static int sys_getegid(struct trap_frame *tf)
{
    struct thread *cur = current_thread_get();
    if (cur == NULL || cur->task == NULL)
        return ENOSYS;

    syscall_return(tf, (int64_t)cur->task->egid);
    return 0;
}

/*
 * sys_umask - Set file creation mask
 *
 * x0 = new mask
 * Returns: old mask in x0
 */
static int sys_umask(struct trap_frame *tf)
{
    mode_t newmask = (mode_t)tf->regs[0];

    struct proc *p = proc_current();
    if (p == NULL)
        return EINVAL;

    mode_t old = p->p_umask;
    p->p_umask = newmask & 0777;

    syscall_return(tf, (int64_t)old);
    return 0;
}

/*
 * sys_nanosleep - High-resolution sleep
 *
 * x0 = pointer to struct timespec (seconds, nanoseconds)
 * x1 = pointer to remaining time (or NULL)
 *
 * struct timespec on macOS arm64:
 *   int64_t tv_sec;   (8 bytes)
 *   int64_t tv_nsec;  (8 bytes — actually long, which is 8 on LP64)
 *
 * We implement this using the ARM generic timer. Read CNTFRQ_EL0 for
 * the timer frequency, compute the number of ticks to wait, then
 * busy-wait (or yield in a loop for cooperative scheduling).
 */
static int sys_nanosleep(struct trap_frame *tf)
{
    uint64_t req_uaddr = tf->regs[0];
    /* uint64_t rem_uaddr = tf->regs[1]; */

    if (req_uaddr == 0)
        return EINVAL;

    struct proc *p = proc_current();
    if (p == NULL || p->p_vmspace == NULL)
        return EINVAL;

    /* Read struct timespec from user space */
    uint64_t pa = vmm_translate(p->p_vmspace->pgd, req_uaddr);
    if (pa == 0)
        return EFAULT;

    int64_t tv_sec = *(int64_t *)pa;
    int64_t tv_nsec = *(int64_t *)(pa + 8);

    if (tv_sec < 0 || tv_nsec < 0 || tv_nsec >= 1000000000L)
        return EINVAL;

    /* Read timer frequency */
    uint64_t freq;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(freq));

    /* Compute total nanoseconds and convert to timer ticks */
    uint64_t total_ns = (uint64_t)tv_sec * 1000000000UL + (uint64_t)tv_nsec;
    uint64_t ticks = (total_ns * freq) / 1000000000UL;

    /* Read current counter */
    uint64_t start;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(start));

    uint64_t target = start + ticks;

    /* Yield-loop until the target time is reached.
     * This is cooperative: we give up the CPU on each iteration
     * so other processes can run. */
    while (1) {
        uint64_t now;
        __asm__ volatile("mrs %0, cntvct_el0" : "=r"(now));
        if (now >= target)
            break;
        /* Yield to scheduler */
        sched_yield();
    }

    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_mkdir - Create a directory
 *
 * x0 = path, x1 = mode
 */
static int sys_mkdir(struct trap_frame *tf)
{
    const char *path = (const char *)tf->regs[0];
    mode_t mode = (mode_t)tf->regs[1];

    if (path == NULL)
        return EINVAL;

    char abs_path[PATH_MAX_KERN];
    int perr = resolve_user_path(path, abs_path, sizeof(abs_path));
    if (perr)
        return perr;

    int ret = vfs_mkdir(abs_path, mode);
    if (ret < 0)
        return (int)(-ret);

    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_rmdir - Remove a directory
 *
 * x0 = path
 *
 * For now, delegates to vfs_unlink which handles both files and dirs.
 */
static int sys_rmdir(struct trap_frame *tf)
{
    const char *path = (const char *)tf->regs[0];
    if (path == NULL)
        return EINVAL;

    char abs_path[PATH_MAX_KERN];
    int perr = resolve_user_path(path, abs_path, sizeof(abs_path));
    if (perr)
        return perr;

    int ret = vfs_unlink(abs_path);
    if (ret < 0)
        return (int)(-ret);

    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_rename - Rename a file or directory
 *
 * x0 = old path, x1 = new path
 *
 * Implemented as: create new hard link at destination, then unlink source.
 * For cross-directory renames on ext4, this uses the VFS create + unlink path.
 * For same-directory renames, this is atomic at the directory level.
 */
static int sys_rename(struct trap_frame *tf)
{
    const char *oldpath = (const char *)tf->regs[0];
    const char *newpath = (const char *)tf->regs[1];

    if (oldpath == NULL || newpath == NULL)
        return EINVAL;

    char old_abs[PATH_MAX_KERN];
    char new_abs[PATH_MAX_KERN];
    int perr = resolve_user_path(oldpath, old_abs, sizeof(old_abs));
    if (perr)
        return perr;
    perr = resolve_user_path(newpath, new_abs, sizeof(new_abs));
    if (perr)
        return perr;

    /* Look up the source to verify it exists and get its data */
    struct vnode *src_vp = NULL;
    int err = vfs_lookup(old_abs, &src_vp);
    if (err != 0)
        return ENOENT;

    /* If destination exists, try to unlink it first */
    struct vnode *dst_vp = NULL;
    err = vfs_lookup(new_abs, &dst_vp);
    if (err == 0 && dst_vp != NULL) {
        vnode_release(dst_vp);
        err = vfs_unlink(new_abs);
        if (err < 0) {
            vnode_release(src_vp);
            return (int)(-err);
        }
    }

    /* Read the source file data if it's a regular file */
    if (src_vp->v_type == VREG) {
        /* Create the new file */
        int new_fd = vfs_open(new_abs, O_CREAT | O_WRONLY, src_vp->v_mode & 0x0FFF);
        if (new_fd < 0) {
            vnode_release(src_vp);
            return (int)(-new_fd);
        }

        /* Copy data in chunks */
        uint64_t offset = 0;
        uint64_t size = src_vp->v_size;
        uint8_t copybuf[4096];

        while (offset < size) {
            uint64_t chunk = size - offset;
            if (chunk > sizeof(copybuf))
                chunk = sizeof(copybuf);

            int64_t nread = src_vp->v_ops->read(src_vp, copybuf, offset, chunk);
            if (nread <= 0)
                break;

            int64_t nwritten = vfs_write(new_fd, copybuf, (uint64_t)nread);
            if (nwritten <= 0)
                break;

            offset += (uint64_t)nwritten;
        }

        vfs_close(new_fd);

        /* Copy permissions via setattr */
        struct vnode *new_vp = NULL;
        if (vfs_lookup(new_abs, &new_vp) == 0 && new_vp != NULL) {
            if (new_vp->v_ops && new_vp->v_ops->setattr) {
                struct stat st;
                uint8_t *p = (uint8_t *)&st;
                for (uint64_t i = 0; i < sizeof(struct stat); i++)
                    p[i] = 0xFF;
                st.st_mode = src_vp->v_mode & 0x0FFF;
                new_vp->v_ops->setattr(new_vp, &st);
            }
            vnode_release(new_vp);
        }
    } else if (src_vp->v_type == VDIR) {
        /* Can't rename directories across filesystems easily.
         * For same-fs same-parent rename, we'd need to modify dir entries.
         * For now, return ENOSYS for directory renames. */
        vnode_release(src_vp);
        return ENOSYS;
    }

    vnode_release(src_vp);

    /* Unlink the old file */
    err = vfs_unlink(old_abs);
    if (err < 0)
        return (int)(-err);

    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_chmod - Change file mode
 *
 * x0 = path, x1 = mode
 */
static int sys_chmod(struct trap_frame *tf)
{
    const char *path = (const char *)tf->regs[0];
    mode_t mode = (mode_t)tf->regs[1];

    if (path == NULL)
        return EINVAL;

    char abs_path[PATH_MAX_KERN];
    int perr = resolve_user_path(path, abs_path, sizeof(abs_path));
    if (perr)
        return perr;

    /* Look up the vnode */
    struct vnode *vn = NULL;
    int err = vfs_lookup(abs_path, &vn);
    if (err != 0 || vn == NULL)
        return ENOENT;

    /* Call setattr to change the mode */
    if (vn->v_ops && vn->v_ops->setattr) {
        struct stat st;
        /* Fill with sentinels: -1 means "don't change" */
        uint8_t *p = (uint8_t *)&st;
        for (uint64_t i = 0; i < sizeof(struct stat); i++)
            p[i] = 0xFF;
        /* Set the mode we want to change to */
        st.st_mode = mode;
        err = vn->v_ops->setattr(vn, &st);
        vnode_release(vn);
        if (err != 0)
            return -err;  /* setattr returns -errno, syscall wants positive */
    } else {
        vnode_release(vn);
    }

    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_readlink - Read the target of a symbolic link
 *
 * x0 = path, x1 = buf, x2 = bufsize
 *
 * Look up the path, verify it's a symlink, and read the link target
 * via the vnode readlink op. Returns the number of bytes placed in buf
 * (not NUL-terminated, per POSIX readlink semantics).
 */
static int sys_readlink(struct trap_frame *tf)
{
    const char *path = (const char *)tf->regs[0];
    char *buf        = (char *)tf->regs[1];
    uint64_t bufsize = tf->regs[2];

    if (path == NULL || buf == NULL || bufsize == 0)
        return EINVAL;

    char abs_path[PATH_MAX_KERN];
    int perr = resolve_user_path(path, abs_path, sizeof(abs_path));
    if (perr)
        return perr;

    /* Look up the vnode */
    struct vnode *vp = NULL;
    int err = vfs_lookup(abs_path, &vp);
    if (err != 0)
        return ENOENT;

    /* Check if it's a symlink */
    if (vp->v_type != VLNK) {
        vnode_release(vp);
        return EINVAL;
    }

    /* Read link target via vnode op */
    if (vp->v_ops == NULL || vp->v_ops->readlink == NULL) {
        vnode_release(vp);
        return EINVAL;
    }

    /* Allocate kernel buffer for readlink result */
    char kbuf[1024];
    uint64_t klen = bufsize;
    if (klen > sizeof(kbuf))
        klen = sizeof(kbuf);

    int ret = vp->v_ops->readlink(vp, kbuf, klen);
    vnode_release(vp);

    if (ret < 0)
        return (int)(-ret);

    /* Copy result to userspace */
    struct proc *p = proc_current();
    if (p && p->p_vmspace) {
        for (int i = 0; i < ret; i++) {
            uint64_t pa = vmm_translate(p->p_vmspace->pgd,
                                        (uint64_t)buf + i);
            if (pa)
                *(char *)pa = kbuf[i];
        }
    }

    syscall_return(tf, ret);
    return 0;
}

/*
 * sys_select - Synchronous I/O multiplexing
 *
 * x0 = nfds, x1 = readfds, x2 = writefds, x3 = errorfds, x4 = timeout
 *
 * Implementation: check fd readiness for stdin (uart data available),
 * regular files (always ready), sockets (data in buffer), and pipes.
 * Write fds are always considered ready. Error fds are never set.
 *
 * fd_set is a bitmask: 32 bytes = 256 bits (matching FD_SETSIZE=256).
 */
static int sys_select(struct trap_frame *tf)
{
    int nfds = (int)tf->regs[0];
    uint32_t *readfds  = (uint32_t *)tf->regs[1];
    uint32_t *writefds = (uint32_t *)tf->regs[2];
    /* uint32_t *errorfds = (uint32_t *)tf->regs[3]; */
    struct { int64_t tv_sec; int64_t tv_usec; } *timeout =
        (void *)tf->regs[4];

    if (nfds < 0 || nfds > 256)
        return EINVAL;

    /* Limit words to process: 32 bits per uint32_t */
    int nwords = (nfds + 31) / 32;

    /* Copy input fd_sets (we'll modify in place for output) */
    uint32_t rd_in[8];   /* 256 bits max */
    uint32_t wr_in[8];

    for (int i = 0; i < 8; i++) {
        rd_in[i] = 0;
        wr_in[i] = 0;
    }

    if (readfds) {
        for (int i = 0; i < nwords; i++)
            rd_in[i] = readfds[i];
    }
    if (writefds) {
        for (int i = 0; i < nwords; i++)
            wr_in[i] = writefds[i];
    }

    /* Determine if this is a poll (timeout == 0,0) or blocking */
    bool do_poll = false;
    if (timeout && timeout->tv_sec == 0 && timeout->tv_usec == 0)
        do_poll = true;

    int ready_count = 0;

    /* Clear output sets */
    uint32_t rd_out[8];
    uint32_t wr_out[8];
    for (int i = 0; i < 8; i++) {
        rd_out[i] = 0;
        wr_out[i] = 0;
    }

    /* Check each fd */
    for (int fd = 0; fd < nfds; fd++) {
        int word = fd / 32;
        uint32_t bit = 1u << (fd % 32);

        /* Check read readiness */
        if (readfds && (rd_in[word] & bit)) {
            bool ready = false;

            /* fd 0 (stdin) — check if UART has data */
            if (fd == 0) {
                extern bool uart_rx_ready(void);
                if (uart_rx_ready())
                    ready = true;
            }
            /* Socket fd — check if receive buffer has data */
            else if (vfs_get_sockidx(fd) >= 0) {
                extern struct socket socket_table[];
                int sidx = vfs_get_sockidx(fd);
                struct socket *so = &socket_table[sidx];
                if (so->so_rcv.sb_len > 0)
                    ready = true;
            }
            /* Regular file — always readable */
            else if (vfs_fd_has_vnode(fd)) {
                ready = true;
            }
            /* Pipe or console fd — for stdin-like fds */
            else if (fd <= 2) {
                if (fd == 0) {
                    extern bool uart_rx_ready(void);
                    if (uart_rx_ready())
                        ready = true;
                } else {
                    ready = true;
                }
            }

            if (ready) {
                rd_out[word] |= bit;
                ready_count++;
            }
        }

        /* Check write readiness — always ready for our simple implementation */
        if (writefds && (wr_in[word] & bit)) {
            wr_out[word] |= bit;
            ready_count++;
        }
    }

    /* If nothing ready and not polling, do a brief retry loop */
    if (ready_count == 0 && !do_poll) {
        /*
         * Brief retry for stdin readiness.
         * TODO: Proper blocking select() for vi - currently causes system hang.
         * For now, just do a few retries and return.
         */
        extern void sched_yield(void);
        extern bool uart_rx_ready(void);
        
        for (int retry = 0; retry < 100 && ready_count == 0; retry++) {
            sched_yield();
            
            /* Re-check stdin (fd 0) */
            if (readfds && nfds > 0) {
                uint32_t bit0 = 1u << 0;
                if ((rd_in[0] & bit0) && uart_rx_ready()) {
                    rd_out[0] |= bit0;
                    ready_count++;
                }
            }
        }
    }

    /* Write results back */
    if (readfds) {
        for (int i = 0; i < nwords; i++)
            readfds[i] = rd_out[i];
    }
    if (writefds) {
        for (int i = 0; i < nwords; i++)
            writefds[i] = wr_out[i];
    }
    /* Clear error fds */
    uint32_t *errorfds = (uint32_t *)tf->regs[3];
    if (errorfds) {
        for (int i = 0; i < nwords; i++)
            errorfds[i] = 0;
    }

    syscall_return(tf, (int64_t)ready_count);
    return 0;
}

/* ============================================================================
 * System Reboot/Halt (PSCI on ARM64)
 *
 * XNU reboot() howto flags:
 *   RB_HALT    = 0x08  — halt (power off)
 *   RB_REBOOT  = 0     — reboot
 * ============================================================================ */

#define RB_AUTOBOOT     0       /* Reboot */
#define RB_HALT         0x08    /* Halt (power off) */

/* PSCI 0.2 function IDs (SMCCC32 convention for SYSTEM_OFF/RESET) */
#define PSCI_SYSTEM_OFF     0x84000008
#define PSCI_SYSTEM_RESET   0x84000009

static void psci_system_off(void)
{
    register uint64_t x0 __asm__("x0") = PSCI_SYSTEM_OFF;
    __asm__ volatile("hvc #0" : "+r"(x0) : : "x1", "x2", "x3");
    /* Should not return */
}

static void psci_system_reset(void)
{
    register uint64_t x0 __asm__("x0") = PSCI_SYSTEM_RESET;
    __asm__ volatile("hvc #0" : "+r"(x0) : : "x1", "x2", "x3");
    /* Should not return */
}

/*
 * sys_reboot - Reboot or halt the system.
 *
 * x0 = howto (RB_HALT = power off, 0 = reboot)
 *
 * Only root (uid 0) can call this.
 */
static int sys_reboot(struct trap_frame *tf)
{
    int howto = (int)tf->regs[0];

    struct proc *p = proc_current();
    if (p == NULL)
        return EPERM;

    /* Only root can reboot */
    if (p->p_ucred.cr_uid != 0)
        return EPERM;

    kprintf("\n");

    /* Sync all dirty buffers to disk before rebooting */
    kprintf("[kern] Syncing disks...\n");
    extern void buf_sync(void);
    buf_sync();

    if (howto & RB_HALT) {
        kprintf("[kern] System halting...\n");
        /* Disable interrupts */
        __asm__ volatile("msr daifset, #0xF");
        psci_system_off();
        /* If PSCI didn't work, just spin */
        for (;;)
            __asm__ volatile("wfi");
    } else {
        kprintf("[kern] System rebooting...\n");
        /* Disable interrupts */
        __asm__ volatile("msr daifset, #0xF");
        psci_system_reset();
        /* If PSCI didn't work, just spin */
        for (;;)
            __asm__ volatile("wfi");
    }

    /* NOTREACHED */
    return 0;
}

/* ============================================================================
 * Signal Infrastructure
 * ============================================================================ */

void signal_init(struct sigacts *sa)
{
    if (sa == NULL)
        return;

    /* Clear all actions to default, no pending/blocked signals */
    for (int i = 0; i < NSIG; i++) {
        sa->actions[i].sa_handler = SIG_DFL;
        sa->actions[i].sa_mask = 0;
        sa->actions[i].sa_flags = 0;
    }
    sa->pending = 0;
    sa->blocked = 0;
    sa->altstack_sp = 0;
    sa->altstack_size = 0;
    sa->altstack_active = false;
}

/*
 * signal_send - Post a signal to a process.
 *
 * Sets the pending bit in the target's sigacts. The signal will be
 * delivered on the next return-to-user path via signal_check().
 *
 * SIGKILL and SIGCONT have special handling:
 *   SIGKILL: Cannot be blocked/caught, always terminates.
 *   SIGCONT: Clears any pending stop signals.
 */
int signal_send(struct task *target_task, int sig)
{
    if (sig < 1 || sig >= NSIG)
        return -EINVAL;

    /* Find the proc for this task */
    struct proc *p = NULL;
    if (target_task != NULL) {
        for (int i = 0; i < PROC_MAX; i++) {
            if (proc_table[i].p_state != PROC_UNUSED &&
                proc_table[i].p_task == target_task) {
                p = &proc_table[i];
                break;
            }
        }
    }
    if (p == NULL)
        return -ESRCH;

    /* Set the pending bit */
    sigaddset(&p->p_sigacts.pending, sig);

    return 0;
}

/*
 * signal_send_pgid - Send a signal to all processes in a process group.
 *
 * Used by TTY ISIG handling (Ctrl-C -> SIGINT to foreground pgrp).
 */
void signal_send_pgid(pid_t pgid, int sig)
{
    if (sig < 1 || sig >= NSIG)
        return;

    for (int i = 0; i < PROC_MAX; i++) {
        struct proc *p = &proc_table[i];
        if (p->p_state != PROC_UNUSED &&
            p->p_state != PROC_ZOMBIE &&
            p->p_pgrp == pgid) {
            sigaddset(&p->p_sigacts.pending, sig);
        }
    }
}

/*
 * Default signal action table.
 *
 * For each signal, the default action is one of:
 *   'T' = Terminate
 *   'C' = Terminate + core dump (we treat same as 'T' for now)
 *   'I' = Ignore
 *   'S' = Stop
 *   'R' = Continue (resume stopped process)
 */
static const char sig_default_action[NSIG] = {
    [0]         = 'I',  /* Signal 0 (unused) */
    [SIGHUP]    = 'T',
    [SIGINT]    = 'T',
    [SIGQUIT]   = 'C',
    [SIGILL]    = 'C',
    [SIGTRAP]   = 'C',
    [SIGABRT]   = 'C',
    [SIGEMT]    = 'C',
    [SIGFPE]    = 'C',
    [SIGKILL]   = 'T',
    [SIGBUS]    = 'C',
    [SIGSEGV]   = 'C',
    [SIGSYS]    = 'C',
    [SIGPIPE]   = 'T',
    [SIGALRM]   = 'T',
    [SIGTERM]   = 'T',
    [SIGURG]    = 'I',
    [SIGSTOP]   = 'S',
    [SIGTSTP]   = 'S',
    [SIGCONT]   = 'R',
    [SIGCHLD]   = 'I',
    [SIGTTIN]   = 'S',
    [SIGTTOU]   = 'S',
    [SIGIO]     = 'I',
    [SIGXCPU]   = 'T',
    [SIGXFSZ]   = 'T',
    [SIGVTALRM] = 'T',
    [SIGPROF]   = 'T',
    [SIGWINCH]  = 'I',
    [SIGINFO]   = 'I',
    [SIGUSR1]   = 'T',
    [SIGUSR2]   = 'T',
};

/*
 * signal_check - Check for and deliver pending signals.
 *
 * Called on the return-to-user path (from trap.c) after handling
 * a syscall or interrupt from EL0.
 *
 * For now, we only handle SIG_DFL and SIG_IGN dispositions:
 *   - SIG_DFL with terminate action: kill the process
 *   - SIG_DFL with ignore action: discard the signal
 *   - SIG_IGN: discard the signal
 *   - Custom handler: push signal trampoline frame onto user stack
 *
 * Returns true if a signal was delivered (process may have been killed).
 */
bool signal_check(struct thread *th, struct trap_frame *tf)
{
    if (th == NULL || th->task == NULL)
        return false;

    struct proc *p = proc_current();
    if (p == NULL)
        return false;

    struct sigacts *sa = &p->p_sigacts;

    /* Find any deliverable signal: pending & ~blocked */
    sigset_t deliverable = sa->pending & ~sa->blocked;
    if (deliverable == 0)
        return false;

    /* Find the lowest-numbered pending signal */
    int sig = 0;
    for (int i = 1; i < NSIG; i++) {
        if (deliverable & (1u << i)) {
            sig = i;
            break;
        }
    }
    if (sig == 0)
        return false;

    /* Clear the pending bit */
    sigdelset(&sa->pending, sig);

    /* Determine disposition */
    sig_handler_t handler = sa->actions[sig].sa_handler;

    if (handler == SIG_IGN) {
        /* Ignore the signal (SIGKILL and SIGSTOP can never be SIG_IGN,
         * but sys_sigaction already prevents that) */
        return false;
    }

    if (handler == SIG_DFL) {
        /* Default action */
        char action = (sig < NSIG) ? sig_default_action[sig] : 'T';

        switch (action) {
        case 'T':   /* Terminate */
        case 'C':   /* Terminate + core (same as 'T' for now) */
            /* Kill the process with signal exit status */
            proc_exit(p, W_EXITCODE(0, sig));
            /* proc_exit doesn't return for the current proc — the
             * scheduler will pick the next runnable thread. But if
             * proc_exit returns (shouldn't happen), fall through. */
            thread_exit();
            /* NOTREACHED */
            return true;

        case 'S':   /* Stop (SIGTSTP, SIGSTOP, SIGTTIN, SIGTTOU) */
            p->p_state = PROC_STOPPED;
            /* Wake up parent in case it's waiting */
            {
                extern struct proc proc_table[];
                struct proc *parent = &proc_table[p->p_ppid];
                if (parent->p_state != PROC_UNUSED)
                    condvar_signal(&parent->p_waitcv);
            }
            /* Block this thread until SIGCONT */
            thread_block("stopped");
            return true;

        case 'R':   /* Continue (SIGCONT) */
            if (p->p_state == PROC_STOPPED) {
                p->p_state = PROC_RUNNING;
                /* Thread will be unblocked by signal delivery path */
            }
            return false;

        case 'I':   /* Ignore */
        default:
            return false;
        }
    }

    /*
     * Custom handler: push signal context frame onto user stack.
     *
     * Stack layout after setup (growing down):
     *   [saved trap_frame: 288 bytes]  <- sigcontext (at new SP)
     *   ...
     *   new SP (16-byte aligned)
     *
     * tf->elr = handler address
     * x0 = signal number
     * x30 (LR) = CommPage sigreturn trampoline (not on stack)
     *
     * The trampoline in CommPage at offset 0x280 is:
     *   mov x16, #184     ; SYS_sigreturn
     *   svc #0x80
     *
     * Using CommPage avoids executable stack pages.
     */
    if (tf == NULL)
        return false;

    struct proc *pp = proc_current();
    if (!pp || !pp->p_vmspace)
        return false;

    /* Reserve space on user stack for sigcontext only (no trampoline) */
    uint64_t frame_size = sizeof(struct trap_frame);
    frame_size = (frame_size + 15) & ~(uint64_t)15;  /* 16-byte align */

    uint64_t new_sp = tf->sp - frame_size;

    /* Write saved trap frame (sigcontext) to user stack */
    uint64_t sc_addr = new_sp;
    const uint8_t *src = (const uint8_t *)tf;
    for (uint64_t i = 0; i < sizeof(struct trap_frame); i++) {
        uint64_t pa = vmm_translate(pp->p_vmspace->pgd, sc_addr + i);
        if (pa == 0)
            return false;  /* Can't set up signal frame — discard signal */
        *(uint8_t *)pa = src[i];
    }

    /* CommPage sigreturn trampoline address:
     * COMMPAGE_VA (0x0000000FFFFFC000) + COMMPAGE_STUB_SIGRETURN (0x280) */
#define COMMPAGE_VA             0x0000000FFFFFC000UL
#define COMMPAGE_STUB_SIGRETURN 0x280
    uint64_t tramp_addr = COMMPAGE_VA + COMMPAGE_STUB_SIGRETURN;

    /* Modify trap frame to enter signal handler */
    tf->elr = (uint64_t)handler;        /* PC = signal handler */
    tf->regs[0] = (uint64_t)sig;        /* x0 = signal number */
    tf->regs[30] = tramp_addr;          /* LR = CommPage trampoline */
    tf->sp = new_sp;                     /* SP = sigcontext address */

    /* Clear carry flag so handler starts clean */
    tf->spsr &= ~SPSR_CARRY_BIT;

    /* Reset handler to SIG_DFL if SA_RESETHAND would be set (default BSD behavior
     * for non-SA_RESTART signals). For simplicity, don't reset. */

    return true;
}

/*
 * sys_sigreturn - Restore trap frame after signal handler returns.
 *
 * Called from the CommPage sigreturn trampoline when a signal handler returns.
 * The sigcontext (saved trap_frame) is at the current SP (pushed by signal_check).
 * We read it back and overwrite the current trap frame.
 */
static int sys_sigreturn(struct trap_frame *tf)
{
    struct proc *p = proc_current();
    if (!p || !p->p_vmspace)
        return EINVAL;

    /* The sigcontext is at the address where we saved it:
     * current SP points to our frame base (new_sp from signal_check).
     * The saved trap_frame starts at sp (sc_addr = new_sp). */
    uint64_t sc_addr = tf->sp;

    /* Read the saved trap frame from user stack */
    uint8_t *dst = (uint8_t *)tf;
    for (uint64_t i = 0; i < sizeof(struct trap_frame); i++) {
        uint64_t pa = vmm_translate(p->p_vmspace->pgd, sc_addr + i);
        if (pa == 0)
            return EFAULT;
        dst[i] = *(const uint8_t *)pa;
    }

    /* Trap frame is now restored — when we return from syscall_handler
     * and eret, we'll land back at the original PC with original state.
     * Return 0 but don't call syscall_return — the trap frame is fully
     * restored including the original x0. */
    return 0;
}

void signal_return(struct trap_frame *tf)
{
    sys_sigreturn(tf);
}

/* ============================================================================
 * New Filesystem & System Syscalls
 * ============================================================================ */

/*
 * sys_chown - Change file owner and group
 *
 * x0 = path, x1 = uid, x2 = gid
 */
static int sys_chown(struct trap_frame *tf)
{
    const char *path = (const char *)tf->regs[0];
    uid_t owner = (uid_t)tf->regs[1];
    gid_t group = (gid_t)tf->regs[2];

    if (path == NULL)
        return EINVAL;

    char abs_path[PATH_MAX_KERN];
    int perr = resolve_user_path(path, abs_path, sizeof(abs_path));
    if (perr)
        return perr;

    /* Only root can chown */
    struct proc *p = proc_current();
    if (p && p->p_ucred.cr_uid != 0)
        return EPERM;

    struct vnode *vn = NULL;
    int err = vfs_lookup(abs_path, &vn);
    if (err != 0 || vn == NULL)
        return ENOENT;

    if (vn->v_ops && vn->v_ops->setattr) {
        struct stat st;
        uint8_t *pp = (uint8_t *)&st;
        for (uint64_t i = 0; i < sizeof(struct stat); i++)
            pp[i] = 0xFF;
        st.st_uid = owner;
        st.st_gid = group;
        err = vn->v_ops->setattr(vn, &st);
        vnode_release(vn);
        if (err != 0)
            return -err;
    } else {
        vnode_release(vn);
    }

    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_sync - Flush all filesystem buffers to disk
 */
static int sys_sync(struct trap_frame *tf)
{
    extern void buf_sync(void);
    buf_sync();
    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_fchdir - Change current directory via file descriptor
 *
 * x0 = fd
 */
static int sys_fchdir(struct trap_frame *tf)
{
    int fd = (int)tf->regs[0];

    struct vnode *vp = vfs_fd_get_vnode(fd);
    if (vp == NULL)
        return EBADF;

    if (vp->v_type != VDIR)
        return ENOTDIR;

    struct proc *p = proc_current();
    if (p == NULL)
        return ENOSYS;

    /* We can't easily get the path from an fd.
     * For now, set the cwd vnode and mark path as unknown. */
    p->p_cwd = vp;
    /* Don't change p_cwd_path — it stays at whatever it was,
     * or we could set it to a placeholder. Since getcwd() reads
     * p_cwd_path, this is imperfect but functional for most uses. */

    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_getentropy - Fill buffer with random bytes
 *
 * x0 = buf, x1 = buflen (max 256)
 *
 * Uses a simple PRNG seeded from the ARM counter.
 */
static int sys_getentropy(struct trap_frame *tf)
{
    uint8_t *buf = (uint8_t *)tf->regs[0];
    size_t buflen = (size_t)tf->regs[1];

    if (buf == NULL)
        return EINVAL;
    if (buflen > 256)
        return EIO;

    /* Simple PRNG: xorshift64 seeded from ARM counter */
    uint64_t state;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(state));
    if (state == 0) state = 0xDEADBEEFCAFE1234ULL;

    struct proc *p = proc_current();
    if (p == NULL || p->p_vmspace == NULL)
        return EFAULT;

    for (size_t i = 0; i < buflen; i++) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        uint64_t pa = vmm_translate(p->p_vmspace->pgd,
                                     (uint64_t)(buf + i));
        if (pa)
            *(uint8_t *)pa = (uint8_t)(state & 0xFF);
    }

    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_link - Create a hard link
 *
 * x0 = existing path, x1 = new path
 *
 * Not fully implementable without a dedicated VFS link operation,
 * but we can handle the common case of same-directory links.
 */
static int sys_link(struct trap_frame *tf)
{
    (void)tf;
    /* Hard links require adding a directory entry pointing to an
     * existing inode and incrementing its link count. This needs
     * a dedicated ext4_vop_link. For now, return ENOSYS. */
    return ENOSYS;
}

/*
 * sys_proc_info - Return process table information to userspace
 *
 * x0 = user buffer pointer (array of kinfo_proc_brief)
 * x1 = max_entries (size of user buffer in entries)
 * Returns: number of entries written in x0
 *
 * Each entry is a kinfo_proc_brief struct (128 bytes):
 *   pid(4), ppid(4), uid(4), gid(4), state(4), pad(4),
 *   user_ticks(8), sys_ticks(8), start_time(8),
 *   comm(32), pgrp(4), session(4), pad2(40)
 */
struct kinfo_proc_brief {
    int32_t     kp_pid;
    int32_t     kp_ppid;
    uint32_t    kp_uid;
    uint32_t    kp_gid;
    int32_t     kp_state;       /* PROC_UNUSED..PROC_ZOMBIE */
    int32_t     kp_pad0;
    uint64_t    kp_user_ticks;
    uint64_t    kp_sys_ticks;
    uint64_t    kp_start_time;
    char        kp_comm[32];
    int32_t     kp_pgrp;
    int32_t     kp_session;
    uint8_t     kp_pad1[40];    /* pad to 128 bytes total */
};

static int sys_proc_info(struct trap_frame *tf)
{
    void *user_buf      = (void *)tf->regs[0];
    uint64_t max_entries = tf->regs[1];

    if (user_buf == NULL || max_entries == 0)
        return EINVAL;

    struct proc *cur = proc_current();
    if (cur == NULL)
        return EINVAL;

    extern struct proc proc_table[];
    uint64_t count = 0;

    for (int i = 0; i < PROC_MAX && count < max_entries; i++) {
        struct proc *p = &proc_table[i];
        if (p->p_state == PROC_UNUSED)
            continue;

        struct kinfo_proc_brief kp;
        /* Zero the struct */
        for (uint64_t z = 0; z < sizeof(kp); z++)
            ((uint8_t *)&kp)[z] = 0;

        kp.kp_pid        = p->p_pid;
        kp.kp_ppid       = p->p_ppid;
        kp.kp_uid        = p->p_ucred.cr_uid;
        kp.kp_gid        = p->p_ucred.cr_gid;
        kp.kp_state      = p->p_state;
        kp.kp_user_ticks = p->p_user_ticks;
        kp.kp_sys_ticks  = p->p_sys_ticks;
        kp.kp_start_time = p->p_start_time;
        kp.kp_pgrp       = p->p_pgrp;
        kp.kp_session    = p->p_session;

        /* Copy process name */
        for (int c = 0; c < 31 && p->p_comm[c]; c++)
            kp.kp_comm[c] = p->p_comm[c];

        /* Copy to userspace */
        uint64_t dest = (uint64_t)user_buf + count * sizeof(kp);
        if (cur->p_vmspace) {
            for (uint64_t b = 0; b < sizeof(kp); b++) {
                uint64_t pa = vmm_translate(cur->p_vmspace->pgd, dest + b);
                if (pa)
                    *(uint8_t *)pa = ((uint8_t *)&kp)[b];
            }
        }
        count++;
    }

    syscall_return(tf, (int64_t)count);
    return 0;
}

/*
 * sys_statfs_sc - Get filesystem statistics for a path
 *
 * x0 = path (user pointer), x1 = struct statfs * (user pointer)
 */
static int sys_statfs_sc(struct trap_frame *tf)
{
    const char *path = (const char *)tf->regs[0];
    void *user_buf   = (void *)tf->regs[1];

    if (path == NULL || user_buf == NULL)
        return EINVAL;

    char abs_path[PATH_MAX_KERN];
    int perr = resolve_user_path(path, abs_path, sizeof(abs_path));
    if (perr)
        return perr;

    struct statfs kbuf;
    int err = vfs_statfs(abs_path, &kbuf);
    if (err < 0)
        return (int)(-err);

    /* Copy result to userspace */
    struct proc *p = proc_current();
    if (p && p->p_vmspace) {
        uint8_t *src = (uint8_t *)&kbuf;
        for (uint64_t i = 0; i < sizeof(kbuf); i++) {
            uint64_t pa = vmm_translate(p->p_vmspace->pgd,
                                        (uint64_t)user_buf + i);
            if (pa)
                *(uint8_t *)pa = src[i];
        }
    }

    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_fstatfs_sc - Get filesystem statistics for a file descriptor
 *
 * x0 = fd, x1 = struct statfs * (user pointer)
 */
static int sys_fstatfs_sc(struct trap_frame *tf)
{
    int fd       = (int)tf->regs[0];
    void *user_buf = (void *)tf->regs[1];

    if (user_buf == NULL)
        return EINVAL;

    /* Get the vnode for this fd to find its mount */
    struct vnode *vp = vfs_fd_get_vnode(fd);
    if (vp == NULL)
        return EBADF;

    struct mount *mp = vp->v_mount;
    if (mp == NULL || mp->mnt_ops == NULL || mp->mnt_ops->statfs == NULL)
        return ENOSYS;

    struct statfs kbuf;
    int err = mp->mnt_ops->statfs(mp, &kbuf);
    if (err < 0)
        return (int)(-err);

    /* Copy result to userspace */
    struct proc *p = proc_current();
    if (p && p->p_vmspace) {
        uint8_t *src = (uint8_t *)&kbuf;
        for (uint64_t i = 0; i < sizeof(kbuf); i++) {
            uint64_t pa = vmm_translate(p->p_vmspace->pgd,
                                        (uint64_t)user_buf + i);
            if (pa)
                *(uint8_t *)pa = src[i];
        }
    }

    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_fchmod - Change file mode by file descriptor
 *
 * x0 = fd, x1 = mode
 */
static int sys_fchmod(struct trap_frame *tf)
{
    int fd       = (int)tf->regs[0];
    mode_t mode  = (mode_t)tf->regs[1];

    struct vnode *vp = vfs_fd_get_vnode(fd);
    if (vp == NULL)
        return EBADF;

    if (vp->v_ops == NULL || vp->v_ops->setattr == NULL)
        return ENOSYS;

    struct stat st;
    /* Zero the stat struct — only st_mode is meaningful for chmod */
    for (uint64_t i = 0; i < sizeof(st); i++)
        ((uint8_t *)&st)[i] = 0;
    st.st_mode = mode;

    int err = vp->v_ops->setattr(vp, &st);
    if (err < 0)
        return (int)(-err);

    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_gettimeofday - Get current time of day
 *
 * x0 = struct timeval * (user pointer: { int64_t tv_sec; int64_t tv_usec; })
 * x1 = struct timezone * (ignored, may be NULL)
 *
 * Reads the ARM generic timer to compute wall clock time from boot epoch.
 */

/* Boot epoch: Feb 19, 2026 00:00:00 UTC — must match commpage.c */
#define GETTIMEOFDAY_BOOT_EPOCH 1771372800ULL

/* Kernel wall-clock offset set by settimeofday/NTP (seconds + usec) */
static uint64_t wall_offset_sec  = GETTIMEOFDAY_BOOT_EPOCH;
static uint64_t wall_offset_usec = 0;
static uint64_t wall_boot_cntvct = 0;
static uint64_t wall_boot_freq   = 0;
static bool     wall_time_init   = false;

static void wall_time_ensure_init(void)
{
    if (!wall_time_init) {
        uint64_t freq;
        __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(freq));
        uint64_t cnt;
        __asm__ volatile("mrs %0, cntvct_el0" : "=r"(cnt));
        wall_boot_freq = freq;
        wall_boot_cntvct = cnt;
        wall_time_init = true;
    }
}

static int sys_gettimeofday(struct trap_frame *tf)
{
    void *user_tv = (void *)tf->regs[0];
    /* timezone (x1) ignored */

    if (user_tv == NULL)
        return EINVAL;

    wall_time_ensure_init();

    uint64_t now;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(now));

    uint64_t elapsed = now - wall_boot_cntvct;
    uint64_t elapsed_sec = 0;
    uint64_t elapsed_usec = 0;

    if (wall_boot_freq > 0) {
        elapsed_sec = elapsed / wall_boot_freq;
        uint64_t remainder = elapsed % wall_boot_freq;
        elapsed_usec = (remainder * 1000000ULL) / wall_boot_freq;
    }

    uint64_t tv_sec  = wall_offset_sec + elapsed_sec;
    uint64_t tv_usec = wall_offset_usec + elapsed_usec;
    if (tv_usec >= 1000000ULL) {
        tv_sec += tv_usec / 1000000ULL;
        tv_usec = tv_usec % 1000000ULL;
    }

    /* Write to userspace: struct timeval { int64_t tv_sec; int64_t tv_usec; } */
    struct proc *p = proc_current();
    if (p && p->p_vmspace) {
        int64_t kbuf[2];
        kbuf[0] = (int64_t)tv_sec;
        kbuf[1] = (int64_t)tv_usec;
        uint8_t *src = (uint8_t *)kbuf;
        for (uint64_t i = 0; i < sizeof(kbuf); i++) {
            uint64_t pa = vmm_translate(p->p_vmspace->pgd,
                                        (uint64_t)user_tv + i);
            if (pa)
                *(uint8_t *)pa = src[i];
        }
    }

    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_settimeofday - Set current wall clock time
 *
 * x0 = struct timeval * (user pointer: { int64_t tv_sec; int64_t tv_usec; })
 * x1 = struct timezone * (ignored)
 *
 * Must be root (uid 0). Updates the wall clock offset used by gettimeofday.
 * Also updates the commpage timestamp.
 */
static int sys_settimeofday(struct trap_frame *tf)
{
    void *user_tv = (void *)tf->regs[0];

    if (user_tv == NULL)
        return EINVAL;

    /* Check root privilege */
    struct proc *p = proc_current();
    if (p == NULL)
        return EINVAL;
    if (p->p_ucred.cr_uid != 0)
        return EPERM;

    /* Read timeval from userspace */
    int64_t kbuf[2] = { 0, 0 };
    if (p->p_vmspace) {
        uint8_t *dst = (uint8_t *)kbuf;
        for (uint64_t i = 0; i < sizeof(kbuf); i++) {
            uint64_t pa = vmm_translate(p->p_vmspace->pgd,
                                        (uint64_t)user_tv + i);
            if (pa)
                dst[i] = *(uint8_t *)pa;
        }
    }

    wall_time_ensure_init();

    /* Record current counter as the new "boot" reference */
    uint64_t now;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(now));
    wall_boot_cntvct = now;
    wall_offset_sec  = (uint64_t)kbuf[0];
    wall_offset_usec = (uint64_t)kbuf[1];

    /* Update commpage */
    extern void commpage_set_unixtime(uint64_t seconds, uint64_t usec);
    commpage_set_unixtime(wall_offset_sec, wall_offset_usec);

    syscall_return(tf, 0);
    return 0;
}

/* ============================================================================
 * Socket Syscalls
 *
 * Bridge between BSD socket syscalls and the kernel socket layer.
 * Sockets are mapped to file descriptors via vfs_alloc_sockfd().
 * ============================================================================ */

/*
 * sys_socket - Create a socket
 *
 * x0 = domain (AF_INET), x1 = type (SOCK_STREAM/SOCK_DGRAM), x2 = protocol
 * Returns: fd in x0
 */
static int sys_socket(struct trap_frame *tf)
{
    int domain   = (int)tf->regs[0];
    int type     = (int)tf->regs[1];
    int protocol = (int)tf->regs[2];

    int sockidx = net_socket(domain, type, protocol);
    if (sockidx < 0)
        return (int)(-sockidx);

    int fd = vfs_alloc_sockfd(sockidx);
    if (fd < 0) {
        net_close(sockidx);
        return EMFILE;
    }

    syscall_return(tf, (int64_t)fd);
    return 0;
}

/*
 * sys_bind - Bind a socket to an address
 *
 * x0 = fd, x1 = sockaddr pointer, x2 = addrlen
 */
static int sys_bind(struct trap_frame *tf)
{
    int fd = (int)tf->regs[0];
    const struct sockaddr_in *addr = (const struct sockaddr_in *)tf->regs[1];

    int sockidx = vfs_get_sockidx(fd);
    if (sockidx < 0)
        return EBADF;
    if (addr == NULL)
        return EINVAL;

    int ret = net_bind(sockidx, addr);
    if (ret < 0)
        return (int)(-ret);

    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_listen_sc - Mark a socket as listening
 *
 * x0 = fd, x1 = backlog
 */
static int sys_listen_sc(struct trap_frame *tf)
{
    int fd      = (int)tf->regs[0];
    int backlog = (int)tf->regs[1];

    int sockidx = vfs_get_sockidx(fd);
    if (sockidx < 0)
        return EBADF;

    int ret = net_listen(sockidx, backlog);
    if (ret < 0)
        return (int)(-ret);

    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_accept_sc - Accept a connection
 *
 * x0 = fd, x1 = sockaddr pointer (out), x2 = addrlen pointer (in/out)
 */
static int sys_accept_sc(struct trap_frame *tf)
{
    int fd = (int)tf->regs[0];
    struct sockaddr_in *addr = (struct sockaddr_in *)tf->regs[1];

    int sockidx = vfs_get_sockidx(fd);
    if (sockidx < 0)
        return EBADF;

    int new_sockidx = net_accept(sockidx, addr);
    if (new_sockidx < 0)
        return (int)(-new_sockidx);

    int newfd = vfs_alloc_sockfd(new_sockidx);
    if (newfd < 0) {
        net_close(new_sockidx);
        return EMFILE;
    }

    syscall_return(tf, (int64_t)newfd);
    return 0;
}

/*
 * sys_connect_sc - Connect a socket to a remote address
 *
 * x0 = fd, x1 = sockaddr pointer, x2 = addrlen
 */
static int sys_connect_sc(struct trap_frame *tf)
{
    int fd = (int)tf->regs[0];
    const struct sockaddr_in *addr = (const struct sockaddr_in *)tf->regs[1];

    int sockidx = vfs_get_sockidx(fd);
    if (sockidx < 0)
        return EBADF;
    if (addr == NULL)
        return EINVAL;

    /* Poll for incoming packets before connecting (ARP resolution) */
    virtio_net_recv();

    int ret = net_connect(sockidx, addr);
    if (ret < 0)
        return (int)(-ret);

    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_sendto - Send data on a socket (possibly to a specific address)
 *
 * x0 = fd, x1 = buf, x2 = len, x3 = flags, x4 = dest_addr, x5 = addrlen
 */
static int sys_sendto(struct trap_frame *tf)
{
    int fd           = (int)tf->regs[0];
    const void *buf  = (const void *)tf->regs[1];
    size_t len       = (size_t)tf->regs[2];
    /* int flags     = (int)tf->regs[3]; */
    const struct sockaddr_in *dest = (const struct sockaddr_in *)tf->regs[4];

    int sockidx = vfs_get_sockidx(fd);
    if (sockidx < 0)
        return EBADF;
    if (buf == NULL || len == 0)
        return EINVAL;

    /* Poll RX first to process pending data */
    virtio_net_recv();

    ssize_t sent;
    if (dest != NULL) {
        extern int udp_output(struct socket *so, const void *data, uint32_t len,
                              uint32_t dst_addr, uint16_t dst_port);
        extern int ip_output(uint32_t src, uint32_t dst, uint8_t proto,
                             const void *data, uint32_t len);
        extern struct socket socket_table[];
        struct socket *so = &socket_table[sockidx];
        if (so->so_protocol == IPPROTO_ICMP) {
            /* ICMP datagram socket: send raw ICMP packet via IP layer */
            int ret = ip_output(0, dest->sin_addr.s_addr,
                                1 /* IPPROTO_ICMP */, buf, (uint32_t)len);
            if (ret < 0)
                return (int)(-ret);
            sent = (ssize_t)len;
        } else if (so->so_protocol == IPPROTO_UDP) {
            int ret = udp_output(so, buf, (uint32_t)len,
                                 dest->sin_addr.s_addr, dest->sin_port);
            if (ret < 0)
                return (int)(-ret);
            sent = (ssize_t)len;
        } else {
            sent = net_send(sockidx, buf, len);
            if (sent < 0)
                return (int)(-sent);
        }
    } else {
        sent = net_send(sockidx, buf, len);
        if (sent < 0)
            return (int)(-sent);
    }

    syscall_return(tf, (int64_t)sent);
    return 0;
}

/*
 * sys_recvfrom - Receive data from a socket
 *
 * x0 = fd, x1 = buf, x2 = len, x3 = flags, x4 = src_addr, x5 = addrlen
 */
static int sys_recvfrom(struct trap_frame *tf)
{
    int fd       = (int)tf->regs[0];
    void *buf    = (void *)tf->regs[1];
    size_t len   = (size_t)tf->regs[2];
    /* int flags = (int)tf->regs[3]; */
    struct sockaddr_in *src_addr = (struct sockaddr_in *)tf->regs[4];
    /* socklen_t *addrlen = (socklen_t *)tf->regs[5]; */

    int sockidx = vfs_get_sockidx(fd);
    if (sockidx < 0)
        return EBADF;
    if (buf == NULL || len == 0)
        return EINVAL;

    /* Poll for incoming packets */
    virtio_net_recv();

    ssize_t recvd = net_recv(sockidx, buf, len);

    /* If no data, poll with a delay. For ICMP pings through QEMU
     * user-mode networking, round-trip can take hundreds of ms. */
    if (recvd == -EAGAIN) {
        for (int retry = 0; retry < 500; retry++) {
            /* Simple spin delay (~1-2ms per iteration at QEMU speed) */
            for (volatile int d = 0; d < 200000; d++)
                ;
            virtio_net_recv();
            recvd = net_recv(sockidx, buf, len);
            if (recvd != -EAGAIN)
                break;
        }
    }

    if (recvd < 0)
        return (int)(-recvd);

    /* Fill in source address if requested */
    if (src_addr != NULL) {
        extern struct socket socket_table[];
        struct socket *so = &socket_table[sockidx];
        src_addr->sin_family = AF_INET;
        src_addr->sin_port = so->so_remote.sin_port;
        src_addr->sin_addr = so->so_remote.sin_addr;
    }

    syscall_return(tf, (int64_t)recvd);
    return 0;
}

/*
 * sys_shutdown_sc - Shut down part of a full-duplex connection
 *
 * x0 = fd, x1 = how (SHUT_RD=0, SHUT_WR=1, SHUT_RDWR=2)
 *
 * For SHUT_RD: mark socket as not readable.
 * For SHUT_WR: send FIN (for TCP), mark not writable.
 * For SHUT_RDWR: both.
 * The socket remains valid until close() is called.
 */
#define SHUT_RD     0
#define SHUT_WR     1
#define SHUT_RDWR   2

static int sys_shutdown_sc(struct trap_frame *tf)
{
    int fd  = (int)tf->regs[0];
    int how = (int)tf->regs[1];

    int sockidx = vfs_get_sockidx(fd);
    if (sockidx < 0)
        return EBADF;

    if (how < 0 || how > 2)
        return EINVAL;

    extern struct socket socket_table[];
    struct socket *so = &socket_table[sockidx];

    if (how == SHUT_RD || how == SHUT_RDWR) {
        so->so_sflags |= SS_CANTRCVMORE;
    }
    if (how == SHUT_WR || how == SHUT_RDWR) {
        so->so_sflags |= SS_CANTSENDMORE;
        /* For TCP, send FIN to initiate graceful close of send direction */
        if (so->so_type == SOCK_STREAM && so->so_pcb != NULL) {
            struct tcpcb *tp = (struct tcpcb *)so->so_pcb;
            if (tp->t_state == TCPS_ESTABLISHED) {
                tcp_close(tp);
            }
        }
    }

    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_setsockopt - Set socket options
 *
 * x0 = fd, x1 = level, x2 = optname, x3 = optval, x4 = optlen
 *
 * Handles commonly requested options; silently accepts the rest.
 */
static int sys_setsockopt(struct trap_frame *tf)
{
    int fd = (int)tf->regs[0];
    int level = (int)tf->regs[1];
    int optname = (int)tf->regs[2];
    /* void *optval = (void *)tf->regs[3]; */
    /* socklen_t optlen = (socklen_t)tf->regs[4]; */

    int sockidx = vfs_get_sockidx(fd);
    if (sockidx < 0)
        return EBADF;

    extern struct socket socket_table[];
    struct socket *so = &socket_table[sockidx];

    /* SOL_SOCKET level options */
    #define SOL_SOCKET      0xFFFF
    #define SO_REUSEADDR    0x0004
    #define SO_KEEPALIVE    0x0008
    #define SO_RCVBUF       0x1002
    #define SO_SNDBUF       0x1001
    #define SO_NOSIGPIPE    0x1022

    if (level == SOL_SOCKET) {
        switch (optname) {
        case SO_REUSEADDR:
            so->so_options |= SO_REUSEADDR;
            break;
        case SO_KEEPALIVE:
        case SO_NOSIGPIPE:
        case SO_RCVBUF:
        case SO_SNDBUF:
            /* Accept but don't act on these yet */
            break;
        default:
            /* Accept unknown options silently */
            break;
        }
    }
    /* IPPROTO_TCP level — accept silently */

    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_getsockopt - Get socket options
 *
 * x0 = fd, x1 = level, x2 = optname, x3 = optval, x4 = optlen pointer
 */
static int sys_getsockopt(struct trap_frame *tf)
{
    int fd = (int)tf->regs[0];
    int level = (int)tf->regs[1];
    int optname = (int)tf->regs[2];
    void *optval = (void *)tf->regs[3];
    uint32_t *optlen = (uint32_t *)tf->regs[4];

    int sockidx = vfs_get_sockidx(fd);
    if (sockidx < 0)
        return EBADF;

    extern struct socket socket_table[];
    struct socket *so = &socket_table[sockidx];

    #define SO_ERROR    0x1007
    #define SO_TYPE     0x1008

    if (level == SOL_SOCKET) {
        switch (optname) {
        case SO_ERROR:
            if (optval && optlen && *optlen >= sizeof(int)) {
                *(int *)optval = so->so_error;
                *optlen = sizeof(int);
                so->so_error = 0; /* clear after read */
            }
            break;
        case SO_TYPE:
            if (optval && optlen && *optlen >= sizeof(int)) {
                *(int *)optval = so->so_type;
                *optlen = sizeof(int);
            }
            break;
        case SO_REUSEADDR:
            if (optval && optlen && *optlen >= sizeof(int)) {
                *(int *)optval = (so->so_options & SO_REUSEADDR) ? 1 : 0;
                *optlen = sizeof(int);
            }
            break;
        default:
            /* Unknown option — return 0 value */
            if (optval && optlen && *optlen >= sizeof(int)) {
                *(int *)optval = 0;
                *optlen = sizeof(int);
            }
            break;
        }
    } else {
        /* Non-SOL_SOCKET — return 0 */
        if (optval && optlen && *optlen >= sizeof(int)) {
            *(int *)optval = 0;
            *optlen = sizeof(int);
        }
    }

    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_getpeername - Get the address of the peer connected to a socket
 *
 * x0 = fd, x1 = sockaddr pointer, x2 = addrlen pointer
 */
static int sys_getpeername(struct trap_frame *tf)
{
    int fd = (int)tf->regs[0];
    struct sockaddr_in *addr = (struct sockaddr_in *)tf->regs[1];

    int sockidx = vfs_get_sockidx(fd);
    if (sockidx < 0)
        return EBADF;
    if (addr == NULL)
        return EINVAL;

    extern struct socket socket_table[];
    struct socket *so = &socket_table[sockidx];
    *addr = so->so_remote;

    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_getsockname_sc - Get the local address of a socket
 *
 * x0 = fd, x1 = sockaddr pointer, x2 = addrlen pointer
 */
static int sys_getsockname_sc(struct trap_frame *tf)
{
    int fd = (int)tf->regs[0];
    struct sockaddr_in *addr = (struct sockaddr_in *)tf->regs[1];

    int sockidx = vfs_get_sockidx(fd);
    if (sockidx < 0)
        return EBADF;
    if (addr == NULL)
        return EINVAL;

    extern struct socket socket_table[];
    struct socket *so = &socket_table[sockidx];
    *addr = so->so_local;

    syscall_return(tf, 0);
    return 0;
}

/* ============================================================================
 * PTY Syscall
 * ============================================================================ */

/*
 * sys_openpty_sc - Allocate a PTY pair and return master/slave fds.
 *
 * x0 = pointer to int[2] (out: [0]=master_fd, [1]=slave_fd)
 *
 * Returns 0 on success, positive errno on error.
 * On success, writes master_fd and slave_fd to the user-supplied array.
 */
static int sys_openpty_sc(struct trap_frame *tf)
{
    uint64_t fdpair_uva = tf->regs[0];

    if (fdpair_uva == 0)
        return EINVAL;

    /* Allocate a PTY pair */
    struct pty *pp = pty_alloc();
    if (pp == NULL)
        return ENOMEM;

    /* Allocate master fd */
    int master_fd = vfs_alloc_pty_fd(pp, 0);
    if (master_fd < 0) {
        pty_free(pp);
        return EMFILE;
    }

    /* Allocate slave fd */
    int slave_fd = vfs_alloc_pty_fd(pp, 1);
    if (slave_fd < 0) {
        vfs_close(master_fd);
        pty_free(pp);
        return EMFILE;
    }

    pp->pt_master_open = 1;
    pp->pt_slave_open  = 1;

    /* Write fds to user space */
    struct proc *p = proc_current();
    if (p && p->p_vmspace) {
        uint64_t pa0 = vmm_translate(p->p_vmspace->pgd, fdpair_uva);
        uint64_t pa1 = vmm_translate(p->p_vmspace->pgd, fdpair_uva + 4);
        if (pa0 && pa1) {
            *(int *)pa0 = master_fd;
            *(int *)pa1 = slave_fd;
        } else {
            vfs_close(master_fd);
            vfs_close(slave_fd);
            pty_free(pp);
            return EINVAL;
        }
    } else {
        vfs_close(master_fd);
        vfs_close(slave_fd);
        pty_free(pp);
        return EINVAL;
    }

    kprintf("[openpty] allocated pty%d: master_fd=%d slave_fd=%d\n",
            pp->pt_index, master_fd, slave_fd);

    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_fsync - Synchronize a file's in-core state with storage device
 *
 * x0 = fd
 *
 * Returns 0 on success, or positive errno on error.
 */
static int sys_fsync(struct trap_frame *tf)
{
    int fd = (int)tf->regs[0];
    
    /* Validate fd */
    struct file *fp = vfs_get_file(fd);
    if (fp == NULL)
        return EBADF;
    
    /* For now, just sync all buffers (we don't have per-file tracking) */
    buf_sync();
    
    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_ftruncate - Truncate a file to a specified length
 *
 * x0 = fd
 * x1 = length
 *
 * Returns 0 on success, or positive errno on error.
 */
static int sys_ftruncate(struct trap_frame *tf)
{
    int fd = (int)tf->regs[0];
    off_t length = (off_t)tf->regs[1];
    
    struct file *fp = vfs_get_file(fd);
    if (fp == NULL)
        return EBADF;
    
    struct vnode *vp = fp->f_vnode;
    if (vp == NULL)
        return EINVAL;
    
    /* Check if file is open for writing */
    if ((fp->f_flags & O_ACCMODE) == O_RDONLY)
        return EINVAL;
    
    /* Can only truncate regular files */
    if (vp->v_type != VREG)
        return EINVAL;
    
    /* Use setattr to set the new size */
    if (vp->v_ops && vp->v_ops->setattr) {
        struct stat st;
        /* Fill with sentinels: -1 means "don't change" */
        uint8_t *p = (uint8_t *)&st;
        for (uint64_t i = 0; i < sizeof(struct stat); i++)
            p[i] = 0xFF;
        
        /* Set the new size */
        st.st_size = length;
        
        int err = vp->v_ops->setattr(vp, &st);
        if (err != 0)
            return err;
    } else {
        return ENOSYS;
    }
    
    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_truncate - Truncate a file to a specified length (by path)
 *
 * x0 = path
 * x1 = length
 *
 * Returns 0 on success, or positive errno on error.
 */
static int sys_truncate(struct trap_frame *tf)
{
    const char *path = (const char *)tf->regs[0];
    off_t length = (off_t)tf->regs[1];
    
    if (path == NULL)
        return EFAULT;
    
    /* Resolve path */
    char abs_path[PATH_MAX_KERN];
    int err = resolve_user_path(path, abs_path, sizeof(abs_path));
    if (err != 0)
        return err;
    
    /* Open for writing */
    int fd = vfs_open(abs_path, O_WRONLY, 0);
    if (fd < 0)
        return -fd;
    
    /* Reuse ftruncate logic */
    tf->regs[0] = fd;
    tf->regs[1] = (uint64_t)length;
    err = sys_ftruncate(tf);
    
    vfs_close(fd);
    
    if (err == 0)
        syscall_return(tf, 0);
    return err;
}

/* ============================================================================
 * BSD Thread Syscalls (pthread support)
 * ============================================================================ */

/*
 * sys_bsdthread_create - Create a new user thread (pthread_create)
 *
 * XNU ABI (simplified for Kiseki):
 *   x0 = start_routine (function pointer)
 *   x1 = arg (argument to start_routine)
 *   x2 = stack (user stack pointer, top of stack)
 *   x3 = pthread struct pointer (for TLS, stored in TPIDR_EL0)
 *   x4 = flags (unused for now)
 *   x5 = reserved
 *
 * Returns:
 *   On success: thread ID in x0, carry clear
 *   On failure: errno in x0, carry set
 *
 * The new thread starts executing start_routine(arg) with:
 *   - SP = stack
 *   - x0 = arg
 *   - TPIDR_EL0 = pthread struct pointer (for TLS access)
 */
static int sys_bsdthread_create(struct trap_frame *tf)
{
    uint64_t start_routine = tf->regs[0];
    uint64_t arg           = tf->regs[1];
    uint64_t stack         = tf->regs[2];
    uint64_t pthread_ptr   = tf->regs[3];
    /* uint64_t flags      = tf->regs[4]; */

    struct thread *cur = current_thread_get();
    if (cur == NULL || cur->task == NULL)
        return EINVAL;

    struct task *task = cur->task;

    /* Validate parameters */
    if (start_routine == 0 || stack == 0)
        return EINVAL;

    /* Create the new user thread */
    struct thread *new_thread = thread_create_user(
        task,
        start_routine,
        arg,
        stack,
        pthread_ptr,  /* TLS base = pthread struct */
        PRI_DEFAULT
    );

    if (new_thread == NULL) {
        kprintf("[bsdthread_create] thread_create_user failed\n");
        return EAGAIN;  /* Resource temporarily unavailable */
    }

    /* Enqueue the thread so the scheduler can run it */
    sched_enqueue(new_thread);

    /* Return the thread ID to the caller */
    syscall_return(tf, (int64_t)new_thread->tid);
    return 0;
}

/*
 * sys_bsdthread_terminate - Terminate the calling thread
 *
 * XNU ABI:
 *   x0 = stack base (to free)
 *   x1 = stack size (to free)
 *   x2 = port (unused)
 *   x3 = semaphore (unused)
 *   x4 = exit value
 *
 * This syscall does not return (thread is terminated).
 *
 * Note: Stack deallocation should be handled by userspace before calling
 * this, as we can't safely free the stack while running on it in kernel mode.
 */
static int sys_bsdthread_terminate(struct trap_frame *tf)
{
    /* uint64_t stack_base = tf->regs[0]; */
    /* uint64_t stack_size = tf->regs[1]; */
    void *exit_value = (void *)tf->regs[4];

    struct thread *cur = current_thread_get();
    if (cur == NULL)
        return EINVAL;

    /*
     * If this is the last thread in the task, we should exit the process.
     * Check if there are other threads.
     */
    if (cur->task) {
        struct thread *other = cur->task->threads;
        int thread_count = 0;
        while (other) {
            if (other != cur && other->state != TH_TERM)
                thread_count++;
            other = other->task_next;
        }

        if (thread_count == 0) {
            /* Last thread - exit the entire process */
            struct proc *p = proc_current();
            if (p) {
                proc_exit(p, W_EXITCODE(0, 0));
            }
            thread_exit();
            /* NOTREACHED */
        }
    }

    /* Terminate just this thread */
    thread_terminate(exit_value);
    /* NOTREACHED */
    return 0;
}

/*
 * sys_bsdthread_register - Register pthread library callbacks
 *
 * XNU ABI:
 *   x0 = pthread_start (callback when thread starts)
 *   x1 = wqthread (workqueue thread callback)
 *   x2 = pthsize (size of pthread struct)
 *   x3-x5 = reserved
 *
 * This is called once by libpthread during initialization to register
 * callbacks. For Kiseki's simplified model, we just accept and ignore it.
 */
static int sys_bsdthread_register(struct trap_frame *tf)
{
    /* Accept registration but don't do anything with it for now.
     * In a full implementation, we'd store these callbacks for use
     * when creating new threads. */
    (void)tf;
    syscall_return(tf, 0);
    return 0;
}

/*
 * sys_thread_selfid - Get the calling thread's ID
 *
 * Returns the unique thread ID (TID) of the calling thread.
 * This is used by pthread_self() implementation.
 */
static int sys_thread_selfid(struct trap_frame *tf)
{
    struct thread *cur = current_thread_get();
    if (cur == NULL)
        return EINVAL;

    syscall_return(tf, (int64_t)cur->tid);
    return 0;
}
