/*
 * Kiseki OS - Process Management
 *
 * BSD process abstraction layered on top of Mach tasks/threads.
 * Each proc owns a Mach task, a VM space, file descriptor table,
 * credential, and signal state.
 *
 * Process hierarchy: init (PID 1) -> all user processes.
 * Lifecycle: fork -> exec -> wait -> exit.
 *
 * Reference: XNU bsd/sys/proc_internal.h, FreeBSD sys/proc.h
 */

#ifndef _KERN_PROC_H
#define _KERN_PROC_H

#include <kiseki/types.h>
#include <kern/vmm.h>
#include <kern/thread.h>
#include <kern/sync.h>
#include <bsd/signal.h>
#include <bsd/security.h>
#include <fs/vfs.h>

/* ============================================================================
 * Process Limits
 * ============================================================================ */

#define PROC_MAX            256     /* Maximum concurrent processes */
#define PROC_NAME_MAX       32      /* Max process name length */
#define PROC_FD_MAX         VFS_MAX_FD  /* Max open file descriptors per proc */
#define PROC_CHILDREN_MAX   128     /* Max children per proc (soft limit) */

/* ============================================================================
 * Process States
 * ============================================================================ */

#define PROC_UNUSED         0       /* Slot is free */
#define PROC_EMBRYO         1       /* Being created */
#define PROC_RUNNING        2       /* Active (has runnable threads) */
#define PROC_SLEEPING       3       /* All threads blocked */
#define PROC_STOPPED        4       /* Stopped by signal (SIGSTOP/SIGTSTP) */
#define PROC_ZOMBIE         5       /* Exited, waiting for parent to wait() */

/* ============================================================================
 * File Descriptor Table
 * ============================================================================ */

struct filedesc {
    struct file     *fd_ofiles[PROC_FD_MAX];    /* Open file pointers */
    uint32_t        fd_nfiles;                  /* Number of allocated slots */
    spinlock_t      fd_lock;                    /* Protects table */
};

/* ============================================================================
 * Process Structure
 *
 * The BSD-layer process descriptor. Contains a pointer to the Mach task
 * (which holds threads and VM space) plus BSD-specific state.
 * ============================================================================ */

struct proc {
    /* Identity */
    pid_t           p_pid;                      /* Process ID */
    pid_t           p_ppid;                     /* Parent process ID */
    char            p_comm[PROC_NAME_MAX];      /* Process name (command) */
    int             p_state;                    /* PROC_RUNNING, etc. */

    /* Mach layer */
    struct task     *p_task;                    /* Mach task (owns threads + VM) */
    struct vm_space *p_vmspace;                 /* User virtual address space */

    /* Credentials */
    struct ucred    p_ucred;                    /* User credentials */

    /* File descriptors */
    struct filedesc p_fd;                       /* Open file table */

    /* Signal state */
    struct sigacts  p_sigacts;                  /* Signal actions and pending set */

    /* Process hierarchy */
    struct proc     *p_parent;                  /* Parent process */
    struct proc     *p_children;                /* First child (linked list) */
    struct proc     *p_sibling;                 /* Next sibling (same parent) */

    /* Exit state */
    int             p_exitstatus;               /* Exit status (for wait) */
    bool            p_exited;                   /* Has called exit */

    /* Synchronization */
    spinlock_t      p_lock;                     /* Protects mutable fields */
    condvar_t       p_waitcv;                   /* Parent waits here for child exit */
    mutex_t         p_waitmtx;                  /* Mutex for p_waitcv */

    /* Resource accounting */
    uint64_t        p_start_time;               /* Time of fork/exec (ticks) */
    uint64_t        p_user_ticks;               /* Ticks in user mode */
    uint64_t        p_sys_ticks;                /* Ticks in kernel mode */

    /* Mach-O loader state (set by execve) */
    uint64_t        p_entry_point;              /* User entry point address */
    bool            p_needs_dyld;               /* Needs dynamic linker */
    char            p_dylinker[256];            /* Path to dyld */

    /* Working directory */
    struct vnode    *p_cwd;                     /* Current working directory vnode */
    char            p_cwd_path[256];            /* Current working directory path */

    /* Process group & session */
    pid_t           p_pgrp;                     /* Process group ID */
    pid_t           p_session;                  /* Session ID */
    bool            p_session_leader;           /* Is this proc the session leader? */

    /* File creation mask */
    mode_t          p_umask;                    /* umask (default 022) */
};

/* ============================================================================
 * Process Table
 * ============================================================================ */

/* Global process table (defined in proc.c) */
extern struct proc  proc_table[PROC_MAX];
extern spinlock_t   proc_table_lock;

/* PID 0 = kernel "process" (swapper), PID 1 = init */
#define PID_KERNEL      0
#define PID_INIT        1

/* ============================================================================
 * Process API - Lifecycle
 * ============================================================================ */

/*
 * proc_init - Initialize the process subsystem
 *
 * Sets up the process table, creates the kernel process (PID 0).
 * Must be called once during kernel startup.
 */
void proc_init(void);

/*
 * proc_create - Create a new empty process
 *
 * @name:   Process name
 * @parent: Parent process (NULL for PID 0)
 *
 * Allocates a PID, creates a Mach task with a fresh VM space,
 * initializes file descriptor table with stdin/stdout/stderr
 * pointing to the console device.
 *
 * Returns the new proc on success, NULL on failure.
 */
struct proc *proc_create(const char *name, struct proc *parent);

/*
 * proc_exit - Terminate a process
 *
 * @p:      Process to terminate
 * @status: Exit status (encoded as wait(2) status)
 *
 * Closes all file descriptors, releases VM space, reparents children
 * to init (PID 1), transitions to PROC_ZOMBIE, and wakes parent
 * if waiting.
 */
void proc_exit(struct proc *p, int status);

/*
 * proc_wait - Wait for a child process to exit
 *
 * @parent: Calling process
 * @pid:    PID to wait for (-1 = any child)
 * @status: On success, filled with exit status
 * @options: WNOHANG, etc.
 *
 * Blocks until a matching child is in PROC_ZOMBIE state, then reaps it.
 * Returns the child's PID on success, negative errno on failure.
 */
pid_t proc_wait(struct proc *parent, pid_t pid, int *status, int options);

/* wait4 options */
#define WNOHANG     0x01    /* Don't block */
#define WUNTRACED   0x02    /* Report stopped children */

/* Wait status macros (matches POSIX) */
#define WEXITSTATUS(s)  (((s) >> 8) & 0xFF)
#define WTERMSIG(s)     ((s) & 0x7F)
#define WIFEXITED(s)    (WTERMSIG(s) == 0)
#define WIFSIGNALED(s)  (WTERMSIG(s) != 0 && WTERMSIG(s) != 0x7F)
#define WIFSTOPPED(s)   (WTERMSIG(s) == 0x7F)
#define W_EXITCODE(ret, sig) (((ret) << 8) | (sig))

/* ============================================================================
 * Process API - Lookup
 * ============================================================================ */

/*
 * proc_find - Find a process by PID
 *
 * Returns the proc pointer or NULL if not found.
 * Does NOT take a reference; caller must hold proc_table_lock if needed.
 */
struct proc *proc_find(pid_t pid);

/*
 * proc_current - Get the current process
 *
 * Returns the proc owning the currently running thread.
 */
struct proc *proc_current(void);

/* ============================================================================
 * Process API - PID Allocation
 * ============================================================================ */

/*
 * pid_alloc - Allocate the next available PID
 *
 * Returns a PID >= 1, or -1 if the process table is full.
 */
pid_t pid_alloc(void);

/*
 * pid_free - Return a PID to the free pool
 */
void pid_free(pid_t pid);

/* ============================================================================
 * Syscall Implementations (called from syscall dispatch)
 * ============================================================================ */

struct trap_frame;

/*
 * sys_fork_impl - Fork the current process
 *
 * Duplicates the VM space with COW, copies fd table, creates a
 * new thread in the child. Returns child PID to parent, 0 to child.
 *
 * @tf: Trap frame of the calling thread
 *
 * Returns 0 on success (result PID placed in tf->regs[0]),
 * or positive errno on failure.
 */
int sys_fork_impl(struct trap_frame *tf);

/*
 * sys_execve_impl - Replace current process image with a new Mach-O binary
 *
 * @tf:   Trap frame of the calling thread
 * @path: Path to executable
 * @argv: Argument vector (user pointers)
 * @envp: Environment vector (user pointers)
 *
 * Loads the Mach-O binary, sets up user stack with argc/argv/envp,
 * switches to the new VM space, and returns to user via eret at
 * the new entry point. Does not return on success.
 *
 * Returns positive errno on failure.
 */
int sys_execve_impl(struct trap_frame *tf, const char *path,
                    const char **argv, const char **envp);

/*
 * sys_wait4_impl - Wait for child process
 *
 * @tf: Trap frame
 *
 * Blocks until child exits, reaps zombie. Returns child PID in tf->regs[0].
 * Returns 0 on success, positive errno on failure.
 */
int sys_wait4_impl(struct trap_frame *tf);

/* ============================================================================
 * Init Process Bootstrap
 * ============================================================================ */

/*
 * kernel_init_process - Launch the first user process
 *
 * Called from kmain after all subsystems are initialized.
 * Tries to load /sbin/init, then /bin/sh as fallback.
 * Creates PID 1 and begins executing it.
 *
 * Does not return on success. Panics if no init can be loaded.
 */
void kernel_init_process(void) __noreturn;

/* ============================================================================
 * File Descriptor Helpers
 * ============================================================================ */

/*
 * fd_alloc - Allocate the lowest available file descriptor
 *
 * @p: Process
 *
 * Returns fd number (>= 0) or -EMFILE if full.
 */
int fd_alloc(struct proc *p);

/*
 * fd_dup_table - Duplicate a file descriptor table (for fork)
 *
 * @dst: Destination filedesc (already zeroed)
 * @src: Source filedesc
 *
 * Increments refcount on each open file. Returns 0 on success.
 */
int fd_dup_table(struct filedesc *dst, struct filedesc *src);

/*
 * fd_close_all - Close all file descriptors in a process
 *
 * @p: Process whose fds to close
 */
void fd_close_all(struct proc *p);

#endif /* _KERN_PROC_H */
