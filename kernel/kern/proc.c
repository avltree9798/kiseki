/*
 * Kiseki OS - Process Management
 *
 * BSD process implementation layered on Mach tasks/threads.
 * Handles fork, exec, wait, exit, and the first user process bootstrap.
 *
 * Process model:
 *   - Each proc contains a Mach task (threads + VM) and BSD state
 *     (credentials, file descriptors, signals).
 *   - fork() uses COW: marks all user pages read-only and bumps refcounts.
 *   - execve() loads a Mach-O binary, replaces the VM space, and sets up
 *     the user stack with argc/argv/envp.
 *   - wait4() blocks the parent until a child exits and becomes a zombie.
 *   - exit() closes fds, reparents children to init, and transitions to zombie.
 *
 * Reference: XNU bsd/kern/kern_fork.c, kern_exec.c, kern_exit.c
 */

#include <kiseki/types.h>
#include <kern/proc.h>
#include <kern/macho.h>
#include <kern/vmm.h>
#include <kern/pmm.h>
#include <kern/thread.h>
#include <kern/kprintf.h>
#include <kern/sync.h>
#include <fs/vfs.h>
#include <bsd/signal.h>
#include <machine/trap.h>

/* ============================================================================
 * Internal Helpers (no libc)
 * ============================================================================ */

static void *memset_p(void *dst, int val, uint64_t n)
{
    uint8_t *d = (uint8_t *)dst;
    while (n--)
        *d++ = (uint8_t)val;
    return dst;
}

static void *memcpy_p(void *dst, const void *src, uint64_t n)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    while (n--)
        *d++ = *s++;
    return dst;
}

static void strncpy_p(char *dst, const char *src, uint64_t n)
{
    uint64_t i;
    for (i = 0; i < n && src[i] != '\0'; i++)
        dst[i] = src[i];
    for (; i < n; i++)
        dst[i] = '\0';
}

static uint64_t strlen_p(const char *s)
{
    uint64_t len = 0;
    while (*s++)
        len++;
    return len;
}

/* ============================================================================
 * Global Process Table
 * ============================================================================ */

struct proc  proc_table[PROC_MAX];
spinlock_t   proc_table_lock = SPINLOCK_INIT;

/* Next PID to try allocating */
static pid_t next_pid = PID_INIT;  /* Start from 1; PID 0 is kernel */

/* ============================================================================
 * PID Allocation
 * ============================================================================ */

pid_t pid_alloc(void)
{
    uint64_t flags;
    spin_lock_irqsave(&proc_table_lock, &flags);

    /* Linear scan for a free slot. PIDs map 1:1 to table indices
     * for simplicity (PID N = proc_table[N]). */
    for (int i = 0; i < PROC_MAX; i++) {
        pid_t candidate = (next_pid + i) % PROC_MAX;
        if (candidate == PID_KERNEL)
            continue;  /* PID 0 reserved for kernel */
        if (proc_table[candidate].p_state == PROC_UNUSED) {
            next_pid = (candidate + 1) % PROC_MAX;
            spin_unlock_irqrestore(&proc_table_lock, flags);
            return candidate;
        }
    }

    spin_unlock_irqrestore(&proc_table_lock, flags);
    kprintf("proc: PID table exhausted\n");
    return -1;
}

void pid_free(pid_t pid)
{
    if (pid >= 0 && pid < PROC_MAX) {
        uint64_t flags;
        spin_lock_irqsave(&proc_table_lock, &flags);
        proc_table[pid].p_state = PROC_UNUSED;
        spin_unlock_irqrestore(&proc_table_lock, flags);
    }
}

/* ============================================================================
 * Process Lookup
 * ============================================================================ */

struct proc *proc_find(pid_t pid)
{
    if (pid < 0 || pid >= PROC_MAX)
        return NULL;
    struct proc *p = &proc_table[pid];
    if (p->p_state == PROC_UNUSED)
        return NULL;
    return p;
}

struct proc *proc_current(void)
{
    struct thread *th = current_thread_get();
    if (th == NULL || th->task == NULL)
        return NULL;

    pid_t pid = th->task->pid;
    if (pid < 0 || pid >= PROC_MAX)
        return NULL;
    return &proc_table[pid];
}

/* ============================================================================
 * File Descriptor Helpers
 * ============================================================================ */

int fd_alloc(struct proc *p)
{
    uint64_t flags;
    spin_lock_irqsave(&p->p_fd.fd_lock, &flags);

    for (uint32_t i = 0; i < PROC_FD_MAX; i++) {
        if (p->p_fd.fd_ofiles[i] == NULL) {
            spin_unlock_irqrestore(&p->p_fd.fd_lock, flags);
            return (int)i;
        }
    }

    spin_unlock_irqrestore(&p->p_fd.fd_lock, flags);
    return -EMFILE;
}

int fd_dup_table(struct filedesc *dst, struct filedesc *src)
{
    uint64_t sflags, dflags;
    spin_lock_irqsave(&src->fd_lock, &sflags);

    for (uint32_t i = 0; i < PROC_FD_MAX; i++) {
        dst->fd_ofiles[i] = src->fd_ofiles[i];
        if (dst->fd_ofiles[i] != NULL) {
            /*
             * Increment the file's reference count.
             * The file structure is shared after fork (like Unix).
             */
            uint64_t fflags;
            spin_lock_irqsave(&dst->fd_ofiles[i]->f_lock, &fflags);
            dst->fd_ofiles[i]->f_refcount++;
            spin_unlock_irqrestore(&dst->fd_ofiles[i]->f_lock, fflags);
        }
    }
    dst->fd_nfiles = src->fd_nfiles;

    spin_unlock_irqrestore(&src->fd_lock, sflags);
    (void)dflags;
    return 0;
}

void fd_close_all(struct proc *p)
{
    for (uint32_t i = 0; i < PROC_FD_MAX; i++) {
        if (p->p_fd.fd_ofiles[i] != NULL) {
            /*
             * Decrement refcount. If it drops to zero, the VFS layer
             * will release the underlying vnode. We go through vfs_close
             * which handles this.
             */
            vfs_close((int)i);
            p->p_fd.fd_ofiles[i] = NULL;
        }
    }
}

/* ============================================================================
 * Console File Stubs
 *
 * stdin/stdout/stderr for the first process point to the console
 * (UART). These are simple stub file structures.
 * ============================================================================ */

/* Console vnode and file descriptors are set up during proc_init.
 * For now, allocate static file structures for fd 0, 1, 2. */
static struct file console_stdin;
static struct file console_stdout;
static struct file console_stderr;

static void console_files_init(void)
{
    memset_p(&console_stdin, 0, sizeof(console_stdin));
    memset_p(&console_stdout, 0, sizeof(console_stdout));
    memset_p(&console_stderr, 0, sizeof(console_stderr));

    console_stdin.f_flags = O_RDONLY;
    console_stdin.f_refcount = 1;

    console_stdout.f_flags = O_WRONLY;
    console_stdout.f_refcount = 1;

    console_stderr.f_flags = O_WRONLY;
    console_stderr.f_refcount = 1;
}

/*
 * setup_stdio - Attach console stdin/stdout/stderr to a process
 */
static void setup_stdio(struct proc *p)
{
    p->p_fd.fd_ofiles[0] = &console_stdin;
    p->p_fd.fd_ofiles[1] = &console_stdout;
    p->p_fd.fd_ofiles[2] = &console_stderr;
    p->p_fd.fd_nfiles = 3;

    /* Bump refcounts for sharing */
    console_stdin.f_refcount++;
    console_stdout.f_refcount++;
    console_stderr.f_refcount++;
}

/* ============================================================================
 * proc_init - Initialize the process subsystem
 * ============================================================================ */

void proc_init(void)
{
    kprintf("[proc] Initializing process subsystem...\n");

    /* Zero the process table */
    memset_p(proc_table, 0, sizeof(proc_table));

    /* Initialize console file descriptors */
    console_files_init();

    /*
     * Create PID 0: the kernel "process".
     * It owns the kernel VM space and the boot thread.
     */
    struct proc *p0 = &proc_table[PID_KERNEL];
    p0->p_pid = PID_KERNEL;
    p0->p_ppid = PID_KERNEL;
    p0->p_state = PROC_RUNNING;
    strncpy_p(p0->p_comm, "kernel_task", PROC_NAME_MAX);
    p0->p_parent = NULL;
    p0->p_children = NULL;
    p0->p_sibling = NULL;
    spin_init(&p0->p_lock);
    condvar_init(&p0->p_waitcv);
    mutex_init(&p0->p_waitmtx);
    signal_init(&p0->p_sigacts);

    /* Kernel process credentials: root */
    p0->p_ucred.cr_uid = 0;
    p0->p_ucred.cr_gid = 0;
    p0->p_ucred.cr_ruid = 0;
    p0->p_ucred.cr_rgid = 0;
    p0->p_ucred.cr_svuid = 0;
    p0->p_ucred.cr_svgid = 0;

    /* Kernel process group/session/umask */
    p0->p_pgrp = 0;
    p0->p_session = 0;
    p0->p_session_leader = true;
    p0->p_umask = 022;
    p0->p_cwd_path[0] = '/';
    p0->p_cwd_path[1] = '\0';

}

/* ============================================================================
 * proc_create - Create a new process
 * ============================================================================ */

struct proc *proc_create(const char *name, struct proc *parent)
{
    pid_t pid = pid_alloc();
    if (pid < 0)
        return NULL;

    struct proc *p = &proc_table[pid];
    memset_p(p, 0, sizeof(*p));

    p->p_pid = pid;
    p->p_ppid = parent ? parent->p_pid : PID_KERNEL;
    p->p_state = PROC_EMBRYO;
    strncpy_p(p->p_comm, name, PROC_NAME_MAX - 1);

    /* Initialize synchronization */
    spin_init(&p->p_lock);
    spin_init(&p->p_fd.fd_lock);
    condvar_init(&p->p_waitcv);
    mutex_init(&p->p_waitmtx);

    /* Create a new Mach task with fresh VM space */
    p->p_vmspace = vmm_create_space();
    if (p->p_vmspace == NULL) {
        kprintf("proc: cannot create VM space for PID %d\n", pid);
        pid_free(pid);
        memset_p(p, 0, sizeof(*p));
        return NULL;
    }

    /* Inherit credentials from parent, or default to root */
    if (parent) {
        memcpy_p(&p->p_ucred, &parent->p_ucred, sizeof(struct ucred));
    } else {
        p->p_ucred.cr_uid = 0;
        p->p_ucred.cr_gid = 0;
        p->p_ucred.cr_ruid = 0;
        p->p_ucred.cr_rgid = 0;
    }

    /* Initialize signal state */
    signal_init(&p->p_sigacts);

    /* Process group: new process inherits parent's pgrp, or is own leader */
    if (parent) {
        p->p_pgrp = parent->p_pgrp;
        p->p_session = parent->p_session;
    } else {
        p->p_pgrp = pid;
        p->p_session = pid;
    }
    p->p_session_leader = false;

    /* File creation mask: inherit from parent or default 022 */
    p->p_umask = parent ? parent->p_umask : 022;

    /* Working directory path: inherit from parent or default "/" */
    if (parent && parent->p_cwd_path[0] != '\0') {
        strncpy_p(p->p_cwd_path, parent->p_cwd_path, sizeof(p->p_cwd_path) - 1);
        p->p_cwd_path[sizeof(p->p_cwd_path) - 1] = '\0';
    } else {
        p->p_cwd_path[0] = '/';
        p->p_cwd_path[1] = '\0';
    }

    /* Set up stdin/stdout/stderr pointing to console */
    setup_stdio(p);

    /* Link into parent's child list */
    p->p_parent = parent;
    if (parent) {
        uint64_t flags;
        spin_lock_irqsave(&parent->p_lock, &flags);
        p->p_sibling = parent->p_children;
        parent->p_children = p;
        spin_unlock_irqrestore(&parent->p_lock, flags);
    }

    p->p_state = PROC_RUNNING;

    return p;
}

/* ============================================================================
 * proc_exit - Terminate a process
 * ============================================================================ */

void proc_exit(struct proc *p, int status)
{
    if (p == NULL || p->p_state == PROC_UNUSED)
        return;

    /* Close all file descriptors */
    fd_close_all(p);

    /* Release current working directory vnode */
    if (p->p_cwd) {
        vnode_release(p->p_cwd);
        p->p_cwd = NULL;
    }

    /*
     * Reparent children to init (PID 1).
     * If we ARE init, orphan them (they become zombies that nobody reaps).
     */
    struct proc *init_proc = proc_find(PID_INIT);
    uint64_t flags;
    spin_lock_irqsave(&p->p_lock, &flags);

    struct proc *child = p->p_children;
    while (child) {
        struct proc *next = child->p_sibling;
        child->p_ppid = init_proc ? PID_INIT : PID_KERNEL;
        child->p_parent = init_proc;

        /* Link into init's child list */
        if (init_proc && init_proc != p) {
            uint64_t iflags;
            spin_lock_irqsave(&init_proc->p_lock, &iflags);
            child->p_sibling = init_proc->p_children;
            init_proc->p_children = child;
            spin_unlock_irqrestore(&init_proc->p_lock, iflags);

            /* If child is already a zombie, wake init to reap it */
            if (child->p_state == PROC_ZOMBIE) {
                condvar_signal(&init_proc->p_waitcv);
            }
        }

        child = next;
    }
    p->p_children = NULL;

    spin_unlock_irqrestore(&p->p_lock, flags);

    /* Destroy the user VM space.
     * IMPORTANT: Switch TTBR0 to the kernel PGD *before* freeing the L0 page.
     * Otherwise TTBR0 points to freed memory and any TLB miss (even for
     * kernel identity-mapped addresses in the lower half) will walk a
     * potentially-reused page as if it were a page table → corruption. */
    if (p->p_vmspace) {
        pte_t *kpgd = vmm_get_kernel_pgd();
        __asm__ volatile("msr ttbr0_el1, %0; isb" :: "r"((uint64_t)kpgd));
        vmm_destroy_space(p->p_vmspace);
        p->p_vmspace = NULL;
    }
    /* Clear task pointer to avoid dangling reference in scheduler */
    if (p->p_task)
        p->p_task->vm_space = NULL;

    /* Transition to zombie */
    p->p_exitstatus = status;
    p->p_exited = true;
    p->p_state = PROC_ZOMBIE;

    /* Wake parent if waiting */
    struct proc *parent = p->p_parent;
    if (parent) {
        condvar_signal(&parent->p_waitcv);
    }
}

/* ============================================================================
 * proc_wait - Wait for a child to exit (implements wait4)
 * ============================================================================ */

pid_t proc_wait(struct proc *parent, pid_t wait_pid, int *status, int options)
{
    if (parent == NULL)
        return -EINVAL;

retry:
    mutex_lock(&parent->p_waitmtx);

    /* Scan children for a zombie */
    uint64_t flags;
    spin_lock_irqsave(&parent->p_lock, &flags);

    struct proc *child = parent->p_children;
    struct proc *prev = NULL;
    bool has_children = false;

    while (child) {
        has_children = true;

        if (wait_pid == -1 || child->p_pid == wait_pid) {
            if (child->p_state == PROC_ZOMBIE) {
                pid_t cpid = child->p_pid;
                if (status)
                    *status = child->p_exitstatus;

                /* Remove child from parent's child list */
                if (prev)
                    prev->p_sibling = child->p_sibling;
                else
                    parent->p_children = child->p_sibling;

                spin_unlock_irqrestore(&parent->p_lock, flags);
                mutex_unlock(&parent->p_waitmtx);

                /* Fully reap: free PID and clear the slot */
                pid_free(cpid);
                return cpid;
            }
        }

        prev = child;
        child = child->p_sibling;
    }

    spin_unlock_irqrestore(&parent->p_lock, flags);

    /* No matching children at all */
    if (!has_children) {
        mutex_unlock(&parent->p_waitmtx);
        return -ECHILD;
    }

    /* WNOHANG: don't block */
    if (options & WNOHANG) {
        mutex_unlock(&parent->p_waitmtx);
        return 0;
    }

    /* Block until a child signals us */
    condvar_wait(&parent->p_waitcv, &parent->p_waitmtx);
    mutex_unlock(&parent->p_waitmtx);
    goto retry;
}

/* Missing errno used above */
#ifndef ECHILD
#define ECHILD  10
#endif

/* ============================================================================
 * sys_fork_impl - Fork the current process
 *
 * Full-copy fork (not COW — simpler for now, COW optimization later):
 *   1. Create a new proc (child) with fresh VM space
 *   2. Deep-copy all user pages from parent to child (vmm_copy_space)
 *   3. Copy the file descriptor table (refcount shared files)
 *   4. Create a new kernel thread for the child
 *   5. Place a copy of parent's trap frame on child's kernel stack
 *      with x0=0 (child return value)
 *   6. Set child thread's context so scheduler dispatches it to
 *      fork_child_return, which restores the trap frame and erets
 *   7. Enqueue child thread on the run queue
 *   8. Parent returns with child PID in x0
 * ============================================================================ */

/* Assembly trampoline: restores trap frame and erets to EL0 */
extern void fork_child_return(void);

int sys_fork_impl(struct trap_frame *tf)
{
    struct proc *parent = proc_current();
    if (parent == NULL)
        return EINVAL;

    /* 1. Create the child process (gets fresh VM space via proc_create) */
    struct proc *child = proc_create(parent->p_comm, parent);
    if (child == NULL)
        return ENOMEM;

    /* 2. Deep-copy parent's user pages into child's address space */
    if (parent->p_vmspace && child->p_vmspace) {
        if (vmm_copy_space(child->p_vmspace, parent->p_vmspace) != 0) {
            kprintf("[fork] vmm_copy_space failed\n");
            /* Cleanup child: free VM space, PID, clear proc slot */
            vmm_destroy_space(child->p_vmspace);
            child->p_vmspace = NULL;
            pid_free(child->p_pid);
            memset_p(child, 0, sizeof(*child));
            return ENOMEM;
        }
    }

    /* 3. Copy file descriptor table (bumps refcounts on shared files) */
    fd_dup_table(&child->p_fd, &parent->p_fd);

    /* Copy signal state */
    memcpy_p(&child->p_sigacts, &parent->p_sigacts, sizeof(struct sigacts));

    /* Copy working directory */
    if (parent->p_cwd) {
        child->p_cwd = parent->p_cwd;
        vnode_ref(child->p_cwd);
    }

    /* 4. Create a Mach task for the child */
    static struct task child_tasks[PROC_MAX];
    struct task *ctask = &child_tasks[child->p_pid];
    memset_p(ctask, 0, sizeof(*ctask));
    ctask->pid = child->p_pid;
    ctask->vm_space = child->p_vmspace;
    ctask->uid = parent->p_ucred.cr_uid;
    ctask->gid = parent->p_ucred.cr_gid;
    ctask->euid = parent->p_ucred.cr_uid;
    ctask->egid = parent->p_ucred.cr_gid;
    strncpy_p(ctask->name, child->p_comm, sizeof(ctask->name) - 1);
    child->p_task = ctask;

    /* 5. Create a kernel thread for the child */
    struct thread *child_thread = thread_create("fork_child", NULL, NULL,
                                                PRI_DEFAULT);
    if (child_thread == NULL) {
        kprintf("[fork] cannot create child thread\n");
        return ENOMEM;
    }
    child_thread->task = ctask;
    ctask->threads = child_thread;

    /*
     * 6. Place a copy of the parent's trap frame at the TOP of the
     *    child's kernel stack. fork_child_return expects SP to point
     *    to a valid trap frame when it runs RESTORE_REGS.
     *
     *    Child's kernel stack layout:
     *      kernel_stack + kernel_stack_size - TF_SIZE  = trap frame
     *      kernel_stack + kernel_stack_size             = stack top
     */
    uint64_t child_kstack_top = (uint64_t)child_thread->kernel_stack +
                                child_thread->kernel_stack_size;
    uint64_t child_tf_base = child_kstack_top - TF_SIZE;
    struct trap_frame *child_tf = (struct trap_frame *)child_tf_base;

    /* Copy parent's trap frame */
    memcpy_p(child_tf, tf, TF_SIZE);

    /* Child returns 0 from fork (x0 = 0) */
    child_tf->regs[0] = 0;

    /* Clear carry flag for success */
    child_tf->spsr &= ~(1UL << 29);

    /*
     * 7. Set up the child thread's saved context so the scheduler's
     *    context_switch() dispatches it to fork_child_return.
     *
     *    context.x30 (LR) = fork_child_return
     *    context.sp        = child_tf_base (where the trap frame lives)
     *    context.x19       = child->p_vmspace (for TTBR0 switch in trampoline)
     */
    child_thread->context.x30 = (uint64_t)fork_child_return;
    child_thread->context.sp  = child_tf_base;
    child_thread->context.x19 = (uint64_t)child->p_vmspace;
    child_thread->context.x29 = 0;  /* FP sentinel */

    /* 8. Enqueue the child thread so the scheduler can run it */
    child_thread->state = TH_RUN;
    sched_enqueue(child_thread);

    /* Parent return value: child's PID */
    tf->regs[0] = (uint64_t)child->p_pid;
    tf->spsr &= ~(1UL << 29);  /* Clear carry for parent too */

    return 0;
}

/* ============================================================================
 * sys_execve_impl - Replace process image with a Mach-O binary
 *
 * XNU-compatible exec flow:
 *   1. Load the Mach-O binary via macho_load()
 *      (macho_load handles dyld loading internally via recursive parse)
 *   2. Allocate user stack with guard page
 *   3. Set up the user stack with argc/argv/envp/apple strings
 *   4. If dyld was loaded, push mach_header pointer below argc
 *      (XNU convention: dyld reads this to find the main binary)
 *   5. Set trap frame: ELR = entry point, SP = user stack
 *   6. Return (eret will jump to user mode)
 *
 * Stack layout when dyld is loaded (XNU convention):
 *
 *   sp -> [ mach_header of main binary ]   <- dyld reads this
 *          [ argc                       ]
 *          [ argv[0] pointer            ]
 *          [ ...                        ]
 *          [ NULL (argv terminator)     ]
 *          [ envp[0] pointer            ]
 *          [ ...                        ]
 *          [ NULL (envp terminator)     ]
 *          [ apple[0] pointer           ]
 *          [ ...                        ]
 *          [ NULL (apple terminator)    ]
 *          [ string data area           ]
 *
 * Stack layout for static binaries (no dyld):
 *
 *   sp -> [ argc                       ]
 *          [ argv[0] pointer            ]
 *          [ ...                        ]
 *          (same as above, no mach_header push)
 *
 * ============================================================================ */

/* Default user stack size: 8MB */
#define USER_STACK_SIZE     (8UL * 1024 * 1024)
#define USER_STACK_GUARD    PAGE_SIZE   /* Guard page at bottom of stack */

/*
 * write_user_u64 - Write a uint64_t to user virtual address
 *
 * Translates VA to PA via the process page tables and writes directly
 * to the physical address (identity-mapped in kernel address space).
 */
static void write_user_u64(struct vm_space *space, uint64_t va, uint64_t val)
{
    uint64_t pa = vmm_translate(space->pgd, va);
    if (pa) {
        /*
         * Kernel uses identity mapping (PA == VA for RAM), so we can
         * write directly to the physical address. vmm_translate returns
         * the full PA including page offset.
         */
        *(volatile uint64_t *)pa = val;
    }
}

/*
 * write_user_bytes - Write bytes to user virtual address
 */
static void write_user_bytes(struct vm_space *space, uint64_t va,
                             const void *src, uint64_t len)
{
    uint64_t pa = vmm_translate(space->pgd, va);
    if (pa) {
        /*
         * Kernel uses identity mapping (PA == VA for RAM).
         */
        memcpy_p((void *)pa, src, len);
    }
}

int sys_execve_impl(struct trap_frame *tf, const char *path,
                    const char **argv, const char **envp)
{
    struct proc *p = proc_current();
    if (p == NULL)
        return EINVAL;

    /*
     * Copy path, argv, and envp from user space into kernel buffers
     * BEFORE destroying the old VM space. These pointers are in user
     * memory that will be freed when we replace the address space.
     *
     * We allocate a 16KB scratch page and pack everything into it:
     *   [0..255]       = path string
     *   [256..8191]    = argv string data (packed)
     *   [8192..12287]  = envp string data (packed)
     *   [12288..13311] = argv pointer offsets (128 * 8 = 1024 bytes)
     *   [13312..14335] = envp pointer offsets (128 * 8 = 1024 bytes)
     */
    uint64_t scratch_pa = pmm_alloc_pages(2); /* 16KB */
    if (scratch_pa == 0)
        return ENOMEM;
    char *scratch = (char *)scratch_pa;
    memset_p(scratch, 0, 4 * PAGE_SIZE);

    /* Copy path */
    char *k_path = scratch;
    {
        uint64_t i = 0;
        while (i < 255 && path[i] != '\0') {
            k_path[i] = path[i];
            i++;
        }
        k_path[i] = '\0';
    }

    /* Copy argv strings */
    int k_argc = 0;
    char *argv_buf = scratch + 256;
    uint64_t *argv_offsets = (uint64_t *)(scratch + 12288);
    uint64_t argv_pos = 0;
    #define ARGV_BUF_SIZE 7936  /* 8192 - 256 */
    if (argv) {
        while (argv[k_argc] != NULL && k_argc < 64) {
            const char *s = argv[k_argc];
            uint64_t slen = 0;
            while (s[slen] != '\0')
                slen++;
            slen++; /* include null */
            if (argv_pos + slen > ARGV_BUF_SIZE)
                break;
            argv_offsets[k_argc] = argv_pos;
            for (uint64_t j = 0; j < slen; j++)
                argv_buf[argv_pos + j] = s[j];
            argv_pos += slen;
            k_argc++;
        }
    }

    /* Copy envp strings */
    int k_envc = 0;
    char *envp_buf = scratch + 8192;
    uint64_t *envp_offsets = (uint64_t *)(scratch + 13312);
    uint64_t envp_pos = 0;
    #define ENVP_BUF_SIZE 4096
    if (envp) {
        while (envp[k_envc] != NULL && k_envc < 64) {
            const char *s = envp[k_envc];
            uint64_t slen = 0;
            while (s[slen] != '\0')
                slen++;
            slen++;
            if (envp_pos + slen > ENVP_BUF_SIZE)
                break;
            envp_offsets[k_envc] = envp_pos;
            for (uint64_t j = 0; j < slen; j++)
                envp_buf[envp_pos + j] = s[j];
            envp_pos += slen;
            k_envc++;
        }
    }

    /*
     * Create a fresh VM space for the new image.
     * IMPORTANT: Switch to kernel page tables before destroying the old
     * space, otherwise kernel VA accesses (e.g., reading kernel_pgd in
     * vmm_create_space) will fault because the old TTBR0 points to
     * freed page tables.
     */
    if (p->p_vmspace) {
        /* Switch TTBR0 to kernel PGD so kernel VA accesses work */
        pte_t *kpgd = vmm_get_kernel_pgd();
        __asm__ volatile("msr ttbr0_el1, %0; isb" :: "r"((uint64_t)kpgd));
        vmm_destroy_space(p->p_vmspace);
    }
    p->p_vmspace = vmm_create_space();
    if (p->p_vmspace == NULL) {
        kprintf("[exec] Cannot create new VM space\n");
        pmm_free_pages(scratch_pa, 2);
        return ENOMEM;
    }

    /* Keep task->vm_space in sync so the scheduler uses the right TTBR0 */
    if (p->p_task)
        p->p_task->vm_space = p->p_vmspace;

    /*
     * Load the Mach-O binary.
     * macho_load handles everything: segment mapping, dyld loading
     * (recursive), entry point resolution. If the binary uses LC_MAIN
     * and has LC_LOAD_DYLINKER, the entry_point will be dyld's entry
     * and mach_header will be the main binary's __TEXT base.
     */
    /*
     * Allocate load_result_t from PMM instead of the stack.
     * The struct is ~17KB (contains dylib_paths[64][256]) and would
     * overflow the 16KB kernel stack.
     */
    uint64_t lr_pa = pmm_alloc_pages(3); /* 32KB = 8 pages, order 3 (load_result_t is ~17KB) */
    if (lr_pa == 0) {
        kprintf("[exec] OOM for load_result\n");
        pmm_free_pages(scratch_pa, 2);
        return ENOMEM;
    }
    load_result_t *result = (load_result_t *)lr_pa;

    load_return_t lret = macho_load(k_path, p->p_vmspace, result);
    if (lret != LOAD_SUCCESS) {
        kprintf("[exec] macho_load failed: %d\n", lret);
        pmm_free_pages(lr_pa, 3);
        pmm_free_pages(scratch_pa, 2);
        /* Return appropriate errno: ENOEXEC for bad format, ENOENT otherwise */
        if (lret == LOAD_BADMACHO || lret == LOAD_BADARCH)
            return ENOEXEC;
        return ENOENT;
    }

    /* Store exec info in the proc */
    p->p_entry_point = result->entry_point;
    p->p_needs_dyld = result->needs_dynlinker;
    if (result->needs_dynlinker) {
        strncpy_p(p->p_dylinker, result->dylinker_path,
                  sizeof(p->p_dylinker) - 1);
    }

    /*
     * Allocate and map the user stack.
     */
    uint64_t stack_top = USER_STACK_TOP;
    uint64_t stack_size = result->user_stack_size > 0 ?
                          ALIGN_UP(result->user_stack_size, PAGE_SIZE) :
                          USER_STACK_SIZE;
    uint64_t stack_bottom = stack_top - stack_size;
    int ret;

    for (uint64_t va = stack_bottom + USER_STACK_GUARD;
         va < stack_top; va += PAGE_SIZE) {
        uint64_t pa = pmm_alloc_page();
        if (pa == 0) {
            kprintf("[exec] OOM allocating user stack\n");
            pmm_free_pages(lr_pa, 3);
            pmm_free_pages(scratch_pa, 2);
            return ENOMEM;
        }
        /* Identity mapping: PA == VA for RAM */
        uint8_t *kva = (uint8_t *)pa;
        memset_p(kva, 0, PAGE_SIZE);

        ret = vmm_map_page(p->p_vmspace->pgd, va, pa, PTE_USER_RW);
        if (ret != 0) {
            pmm_free_page(pa);
            pmm_free_pages(lr_pa, 3);
            pmm_free_pages(scratch_pa, 2);
            return ENOMEM;
        }
    }

    /*
     * Build the user stack with argc/argv/envp.
     *
     * Phase 1: Copy string data onto the stack (high addresses).
     * Phase 2: Build pointer arrays + argc (lower addresses).
     * Phase 3: If dyld was loaded, push mach_header below argc.
     */
    uint64_t sp = stack_top;

    /*
     * Use the kernel-buffered copies of argv/envp (copied before
     * the old VM space was destroyed).
     */
    int argc = k_argc;
    int envc = k_envc;

    /* --- Phase 1: Copy string data from kernel buffers to user stack --- */
    uint64_t str_ptr = sp - 256;  /* Leave headroom at top */
    uint64_t argv_ptrs[64];
    uint64_t envp_ptrs[64];

    memset_p(argv_ptrs, 0, sizeof(argv_ptrs));
    memset_p(envp_ptrs, 0, sizeof(envp_ptrs));

    /* Copy argv strings from kernel buffer */
    for (int i = argc - 1; i >= 0; i--) {
        const char *s = argv_buf + argv_offsets[i];
        uint64_t slen = strlen_p(s) + 1;
        str_ptr -= slen;
        str_ptr &= ~0xFUL;
        write_user_bytes(p->p_vmspace, str_ptr, s, slen);
        argv_ptrs[i] = str_ptr;
    }

    /* Copy envp strings from kernel buffer */
    for (int i = envc - 1; i >= 0; i--) {
        const char *s = envp_buf + envp_offsets[i];
        uint64_t slen = strlen_p(s) + 1;
        str_ptr -= slen;
        str_ptr &= ~0xFUL;
        write_user_bytes(p->p_vmspace, str_ptr, s, slen);
        envp_ptrs[i] = str_ptr;
    }

    /*
     * Apple strings: XNU passes executable_path, stack_guard, etc.
     * For now we pass the executable path as apple[0].
     */
    uint64_t apple_ptrs[4];
    int apple_count = 0;
    {
        /* "executable_path=<path>" */
        static const char exec_key[] = "executable_path=";
        uint64_t klen = strlen_p(exec_key);
        uint64_t plen = strlen_p(k_path);
        uint64_t total = klen + plen + 1;
        str_ptr -= total;
        str_ptr &= ~0xFUL;
        write_user_bytes(p->p_vmspace, str_ptr, exec_key, klen);
        write_user_bytes(p->p_vmspace, str_ptr + klen, k_path, plen + 1);
        apple_ptrs[apple_count++] = str_ptr;
    }

    /* --- Phase 2: Build pointer frame --- */
    uint64_t frame_size = (1 + (uint64_t)argc + 1 +
                           (uint64_t)envc + 1 +
                           (uint64_t)apple_count + 1) * sizeof(uint64_t);
    sp = str_ptr - frame_size;
    sp &= ~0xFUL;  /* 16-byte align */

    uint64_t frame_ptr = sp;

    /* argc */
    write_user_u64(p->p_vmspace, frame_ptr, (uint64_t)argc);
    frame_ptr += sizeof(uint64_t);

    /* argv pointers */
    for (int i = 0; i < argc; i++) {
        write_user_u64(p->p_vmspace, frame_ptr, argv_ptrs[i]);
        frame_ptr += sizeof(uint64_t);
    }
    /* argv NULL terminator */
    write_user_u64(p->p_vmspace, frame_ptr, 0);
    frame_ptr += sizeof(uint64_t);

    /* envp pointers */
    for (int i = 0; i < envc; i++) {
        write_user_u64(p->p_vmspace, frame_ptr, envp_ptrs[i]);
        frame_ptr += sizeof(uint64_t);
    }
    /* envp NULL terminator */
    write_user_u64(p->p_vmspace, frame_ptr, 0);
    frame_ptr += sizeof(uint64_t);

    /* apple pointers */
    for (int i = 0; i < apple_count; i++) {
        write_user_u64(p->p_vmspace, frame_ptr, apple_ptrs[i]);
        frame_ptr += sizeof(uint64_t);
    }
    /* apple NULL terminator */
    write_user_u64(p->p_vmspace, frame_ptr, 0);

    /*
     * --- Phase 3: Push mach_header for dyld (XNU convention) ---
     *
     * If a dynamic linker was loaded, the kernel pushes one extra
     * pointer-sized value below argc: the address of the main binary's
     * Mach-O header. This is how dyld finds the executable.
     *
     * sp -> [ mach_header_addr ]   <- only when dynlinker is present
     *       [ argc             ]
     *       [ argv[0]          ]
     *       ...
     */
    if (result->dynlinker) {
        sp -= sizeof(uint64_t);
        /* DO NOT re-align: mach_header must be contiguous with argc.
         * See kernel_init_process for detailed explanation. */
        write_user_u64(p->p_vmspace, sp, result->mach_header);
    }

    /*
     * Map the CommPage into this process's address space.
     */
    extern void commpage_map(struct vm_space *space);
    commpage_map(p->p_vmspace);

    /* Update process state */
    strncpy_p(p->p_comm, k_path, PROC_NAME_MAX - 1);

    /* Switch to the new VM space */
    vmm_switch_space(p->p_vmspace);

    /*
     * Set up the trap frame for return to user mode.
     *
     * ELR_EL1 = entry point (dyld's entry or direct main entry)
     * SP_EL0  = user stack pointer
     * SPSR    = EL0t (return to EL0 with SP_EL0)
     */
    memset_p(tf->regs, 0, sizeof(tf->regs));
    tf->elr = result->entry_point;
    tf->sp = sp;
    tf->spsr = 0x00000000;  /* EL0t: DAIF clear, AArch64, EL0 */

    pmm_free_pages(lr_pa, 3);
    pmm_free_pages(scratch_pa, 2);
    return 0;
}

/* ============================================================================
 * sys_wait4_impl - Wait for child process
 * ============================================================================ */

int sys_wait4_impl(struct trap_frame *tf)
{
    struct proc *p = proc_current();
    if (p == NULL)
        return EINVAL;

    pid_t wait_pid = (pid_t)tf->regs[0];       /* x0 = pid */
    uint64_t status_uaddr = tf->regs[1];        /* x1 = &status (user ptr) */
    int options = (int)tf->regs[2];              /* x2 = options */

    int status = 0;
    pid_t result = proc_wait(p, wait_pid, &status, options);

    if (result < 0) {
        return (int)(-result);  /* Return positive errno */
    }

    /* Copy status to user space if pointer is non-NULL */
    if (status_uaddr != 0 && p->p_vmspace) {
        uint64_t pa = vmm_translate(p->p_vmspace->pgd, status_uaddr);
        if (pa) {
            /* Identity mapping: PA == VA for RAM.
             * vmm_translate already includes page offset in pa. */
            *(int *)pa = status;
        }
    }

    tf->regs[0] = (uint64_t)result;  /* Return child PID */
    return 0;
}

/* ============================================================================
 * kernel_init_process - Launch the first user process
 *
 * Called from kmain after all subsystems are initialized.
 * Creates PID 1, loads a Mach-O binary (with dyld if needed),
 * sets up the stack per XNU conventions, and enters user mode.
 *
 * The stack is set up identically to sys_execve_impl:
 *   - If dyld was loaded: sp points to mach_header, then argc, argv...
 *   - If no dyld (static): sp points to argc, argv...
 * ============================================================================ */

/* Paths to try for init, in order */
static const char *init_paths[] = {
    "/sbin/init",
    "/bin/hello",
    "/bin/bash",
    "/bin/sh",
    "/sbin/launchd",
    NULL
};

/* Default environment for init */
static const char *init_envp[] = {
    "PATH=/bin:/sbin:/usr/bin:/usr/sbin",
    "HOME=/root",
    "USER=root",
    "SHELL=/bin/bash",
    "TERM=vt100",
    NULL
};

/*
 * Static task structure for PID 1 (init).
 *
 * kernel_init_process() runs on the boot CPU's idle thread, which has
 * task = NULL.  Before entering user mode via eret we must set up a
 * proper thread→task→pid chain so that syscalls (which call
 * proc_current() → current_thread_get()→task→pid) can find the proc
 * entry for PID 1.
 *
 * We allocate a dedicated thread + task for init instead of reusing the
 * idle thread, because the idle thread must remain available to the
 * scheduler.  However, we don't context-switch to this thread normally;
 * we simply install it as current_thread and eret directly to user mode.
 * When a syscall re-enters the kernel, TPIDR_EL1 still holds the same
 * cpu_data, and current_thread points to init_thread.
 */
static struct task init_task;

void kernel_init_process(void)
{
    kprintf("\n[init] Bootstrapping first user process...\n");

    /* Create PID 1 */
    struct proc *init = proc_create("init", &proc_table[PID_KERNEL]);
    if (init == NULL)
        panic("Cannot create init process");

    if (init->p_pid != PID_INIT) {
        kprintf("[init] Warning: init got PID %d (expected %d)\n",
                init->p_pid, PID_INIT);
    }

    /* Allocate load_result_t from PMM (too large for 16KB kernel stack) */
    uint64_t lr_pa = pmm_alloc_pages(3); /* 32KB = order 3 (load_result_t is ~17KB) */
    if (lr_pa == 0)
        panic("OOM for load_result");
    load_result_t *result = (load_result_t *)lr_pa;

    /* Try each init path */
    load_return_t lret;
    const char *chosen_path = NULL;

    for (int i = 0; init_paths[i] != NULL; i++) {
        lret = macho_load(init_paths[i], init->p_vmspace, result);
        if (lret == LOAD_SUCCESS) {
            chosen_path = init_paths[i];
            break;
        }
    }

    if (chosen_path == NULL)
        panic("No init program found. Tried /bin/bash, /bin/sh, "
              "/sbin/init, /sbin/launchd");

    /* Store exec info */
    init->p_entry_point = result->entry_point;
    init->p_needs_dyld = result->needs_dynlinker;
    if (result->needs_dynlinker) {
        strncpy_p(init->p_dylinker, result->dylinker_path,
                  sizeof(init->p_dylinker) - 1);
    }

    /*
     * Allocate user stack for init.
     */
    uint64_t stack_top = USER_STACK_TOP;
    uint64_t stack_size = result->user_stack_size > 0 ?
                          ALIGN_UP(result->user_stack_size, PAGE_SIZE) :
                          USER_STACK_SIZE;
    uint64_t stack_bottom = stack_top - stack_size;

    for (uint64_t va = stack_bottom + USER_STACK_GUARD;
         va < stack_top; va += PAGE_SIZE) {
        uint64_t pa = pmm_alloc_page();
        if (pa == 0)
            panic("OOM allocating init stack");

        /* Identity mapping: PA == VA for RAM */
        uint8_t *kva = (uint8_t *)pa;
        memset_p(kva, 0, PAGE_SIZE);

        if (vmm_map_page(init->p_vmspace->pgd, va, pa, PTE_USER_RW) != 0)
            panic("Cannot map init stack page");
    }

    /*
     * Set up argc/argv/envp/apple on the stack.
     *
     * init gets: argc=1, argv={"chosen_path"}, envp=init_envp,
     *            apple={"executable_path=..."}
     */
    uint64_t sp = stack_top;
    uint64_t str_ptr = sp - 256;  /* Headroom at top */

    /* --- Copy argv strings --- */
    str_ptr -= strlen_p(chosen_path) + 1;
    str_ptr &= ~0xFUL;
    uint64_t argv0_va = str_ptr;
    write_user_bytes(init->p_vmspace, str_ptr, chosen_path,
                     strlen_p(chosen_path) + 1);

    /* --- Copy envp strings --- */
    int envc = 0;
    uint64_t envp_vas[16];
    while (init_envp[envc] != NULL && envc < 16) {
        uint64_t slen = strlen_p(init_envp[envc]) + 1;
        str_ptr -= slen;
        str_ptr &= ~0xFUL;
        write_user_bytes(init->p_vmspace, str_ptr,
                         init_envp[envc], slen);
        envp_vas[envc] = str_ptr;
        envc++;
    }

    /* --- Copy apple strings --- */
    /* "executable_path=<path>" */
    static const char exec_key[] = "executable_path=";
    uint64_t klen = strlen_p(exec_key);
    uint64_t plen = strlen_p(chosen_path);
    str_ptr -= klen + plen + 1;
    str_ptr &= ~0xFUL;
    uint64_t apple0_va = str_ptr;
    write_user_bytes(init->p_vmspace, str_ptr, exec_key, klen);
    write_user_bytes(init->p_vmspace, str_ptr + klen,
                     chosen_path, plen + 1);

    /* --- Build pointer frame --- */
    /* argc(1) + argv[0] + NULL + envp[0..n] + NULL + apple[0] + NULL */
    uint64_t frame_size = (1 + 1 + 1 + (uint64_t)envc + 1 + 1 + 1) *
                          sizeof(uint64_t);
    sp = str_ptr - frame_size;
    sp &= ~0xFUL;

    uint64_t fp = sp;

    /* argc */
    write_user_u64(init->p_vmspace, fp, 1);
    fp += 8;

    /* argv[0] */
    write_user_u64(init->p_vmspace, fp, argv0_va);
    fp += 8;

    /* argv NULL */
    write_user_u64(init->p_vmspace, fp, 0);
    fp += 8;

    /* envp[0..n] */
    for (int i = 0; i < envc; i++) {
        write_user_u64(init->p_vmspace, fp, envp_vas[i]);
        fp += 8;
    }

    /* envp NULL */
    write_user_u64(init->p_vmspace, fp, 0);
    fp += 8;

    /* apple[0] */
    write_user_u64(init->p_vmspace, fp, apple0_va);
    fp += 8;

    /* apple NULL */
    write_user_u64(init->p_vmspace, fp, 0);

    /*
     * If dyld was loaded, push mach_header below argc (XNU convention).
     * This is the very first thing dyld reads from the stack.
     */
    if (result->dynlinker) {
        /*
         * Push mach_header pointer below argc on the stack.
         * XNU convention: dyld's _start reads [sp]=mach_header, [sp+8]=argc.
         */
        sp -= sizeof(uint64_t);
        write_user_u64(init->p_vmspace, sp, result->mach_header);
    }

    /* Map CommPage */
    extern void commpage_map(struct vm_space *space);
    commpage_map(init->p_vmspace);

    strncpy_p(init->p_comm, chosen_path, PROC_NAME_MAX - 1);

    /* Switch to init's address space */
    vmm_switch_space(init->p_vmspace);

    /*
     * Set up a proper thread → task → pid chain for PID 1.
     *
     * The boot path runs on the idle thread (task = NULL).  Syscalls
     * from user mode call proc_current() which walks:
     *   TPIDR_EL1 → cpu_data → current_thread → task → pid → proc_table[pid]
     *
     * We create a dedicated thread for the init process and install it
     * as the CPU's current_thread.  This thread's kernel stack will be
     * used when syscalls trap back into the kernel (SP_EL1 is set by
     * the exception vectors from the thread's kernel stack).
     */
    memset_p(&init_task, 0, sizeof(init_task));
    init_task.pid = init->p_pid;
    init_task.vm_space = init->p_vmspace;
    init_task.uid = 0;
    init_task.gid = 0;
    init_task.euid = 0;
    init_task.egid = 0;
    strncpy_p(init_task.name, "init", sizeof(init_task.name) - 1);

    /* Create a kernel thread for init.
     * We won't use its entry function — we eret to user mode directly.
     * But it gives us a kernel stack for handling syscall traps. */
    struct thread *init_thread = thread_create("init", NULL, NULL, PRI_DEFAULT);
    if (init_thread == NULL)
        panic("Cannot create init thread");
    init_thread->task = &init_task;

    /* Link proc and task */
    init->p_task = &init_task;
    init_task.threads = init_thread;

    /* Install init_thread as the current thread on this CPU.
     * This means all subsequent current_thread_get() calls (including
     * from within syscall handlers) will see this thread. */
    {
        struct cpu_data *cd;
        __asm__ volatile("mrs %0, tpidr_el1" : "=r"(cd));
        cd->current_thread = init_thread;
    }

    kprintf("[init] === End of kernel bootstrap ===\n\n");

    /*
     * Drop to EL0 via eret.
     *
     * Set up the registers:
     *   ELR_EL1 = entry point (dyld or direct)
     *   SP_EL0  = user stack pointer
     *   SPSR_EL1 = 0 (EL0t, interrupts enabled)
     *
     * We also set SP (SP_EL1) to the top of init_thread's kernel stack.
     * This is critical: when an exception occurs from EL0, the CPU
     * switches to SP_EL1, so it must point to a valid kernel stack.
     */
    uint64_t kstack_top = (uint64_t)init_thread->kernel_stack +
                          init_thread->kernel_stack_size;

    /* Capture entry point and free the load result before eret */
    uint64_t entry = result->entry_point;
    pmm_free_pages(lr_pa, 3);

    __asm__ volatile(
        "mov  sp, %2\n"                /* SP_EL1 = kernel stack top */
        "msr  spsr_el1, xzr\n"         /* SPSR = 0 (EL0t) */
        "msr  elr_el1, %0\n"           /* ELR = entry point */
        "msr  sp_el0, %1\n"            /* SP_EL0 = user stack */
        "mov  x0, xzr\n"               /* Clear all GPRs */
        "mov  x1, xzr\n"
        "mov  x2, xzr\n"
        "mov  x3, xzr\n"
        "mov  x4, xzr\n"
        "mov  x5, xzr\n"
        "mov  x6, xzr\n"
        "mov  x7, xzr\n"
        "mov  x8, xzr\n"
        "mov  x9, xzr\n"
        "mov  x10, xzr\n"
        "mov  x11, xzr\n"
        "mov  x12, xzr\n"
        "mov  x13, xzr\n"
        "mov  x14, xzr\n"
        "mov  x15, xzr\n"
        "mov  x16, xzr\n"
        "mov  x17, xzr\n"
        "mov  x18, xzr\n"
        "mov  x19, xzr\n"
        "mov  x20, xzr\n"
        "mov  x21, xzr\n"
        "mov  x22, xzr\n"
        "mov  x23, xzr\n"
        "mov  x24, xzr\n"
        "mov  x25, xzr\n"
        "mov  x26, xzr\n"
        "mov  x27, xzr\n"
        "mov  x28, xzr\n"
        "mov  x29, xzr\n"
        "mov  x30, xzr\n"
        "eret\n"
        :
        : "r"(entry), "r"(sp), "r"(kstack_top)
        : "memory"
    );

    __builtin_unreachable();
}
