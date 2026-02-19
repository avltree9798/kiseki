/*
 * Kiseki OS - Thread & Scheduler Definitions
 *
 * Implements the Mach threading model (1:1 user:kernel threads).
 * Scheduler: Multilevel Feedback Queue (MLFQ) with priority aging.
 */

#ifndef _KERN_THREAD_H
#define _KERN_THREAD_H

#include <kiseki/types.h>
#include <kiseki/platform.h>
#include <kern/sync.h>

/* Thread states */
#define TH_RUN          0   /* Runnable (on a run queue or currently running) */
#define TH_WAIT         1   /* Blocked (sleeping on a wait channel) */
#define TH_IDLE         2   /* Idle thread (runs when nothing else to do) */
#define TH_TERM         3   /* Terminated (waiting to be reaped) */

/* Scheduling policies */
#define SCHED_OTHER     0   /* Standard timesharing (MLFQ) */
#define SCHED_FIFO      1   /* Real-time FIFO (no preemption within priority) */
#define SCHED_RR        2   /* Real-time round-robin */

/* Priority levels */
#define PRI_MIN         0
#define PRI_DEFAULT     64
#define PRI_MAX         127
#define PRI_REALTIME    96
#define PRI_IDLE        0

/* Scheduler quantum */
#define SCHED_QUANTUM_DEFAULT   10  /* 10ms = 10 timer ticks at 100Hz */

/* Number of priority queues in MLFQ */
#define MLFQ_LEVELS     128

/* Maximum threads */
#define MAX_THREADS     256

/*
 * Saved context for context_switch.S
 * Must match the callee-saved register save/restore in context_switch.S.
 */
struct cpu_context {
    uint64_t x19;
    uint64_t x20;
    uint64_t x21;
    uint64_t x22;
    uint64_t x23;
    uint64_t x24;
    uint64_t x25;
    uint64_t x26;
    uint64_t x27;
    uint64_t x28;
    uint64_t x29;   /* FP */
    uint64_t x30;   /* LR (return address) */
    uint64_t sp;
};

/*
 * thread_t - Kernel thread structure
 */
struct thread {
    uint64_t            tid;                /* Unique thread ID */
    int                 state;              /* TH_RUN, TH_WAIT, etc. */
    int                 priority;           /* Base priority (0-127) */
    int                 effective_priority; /* After priority inheritance */
    int                 sched_policy;       /* SCHED_OTHER/FIFO/RR */
    int                 quantum;            /* Remaining time quantum (ticks) */
    int                 cpu;                /* CPU core this thread is running on */

    struct cpu_context  context;            /* Saved registers for context switch */
    uint64_t            *kernel_stack;      /* Kernel stack base */
    uint64_t            kernel_stack_size;

    /* Process linkage */
    struct task         *task;              /* Owning task (process) */

    /* Wait channel (when state == TH_WAIT) */
    void                *wait_channel;      /* What we're sleeping on */
    const char          *wait_reason;       /* Debug string */

    /* Scheduler queue linkage */
    struct thread       *run_next;          /* Next in run queue */

    /* Mutex wait queue linkage */
    struct thread       *wait_next;         /* Next in wait queue */

    /* Continuation (Mach stackless switch optimization) */
    uint64_t            continuation;       /* Function pointer */
};

/*
 * task_t - Mach task (process container)
 *
 * A task contains one or more threads and owns a VM space.
 */
struct ipc_space;  /* Forward declaration */

struct task {
    pid_t               pid;
    char                name[32];
    struct vm_space     *vm_space;           /* Virtual address space */
    struct thread       *threads;            /* List of threads in this task */
    mach_port_t         task_port;           /* Mach task port */
    struct ipc_space    *ipc_space;          /* Mach IPC port namespace */
    /* Security */
    uid_t               uid;
    gid_t               gid;
    uid_t               euid;
    gid_t               egid;
};

/*
 * cpu_data_t - Per-CPU data (stored in TPIDR_EL1)
 */
struct cpu_data {
    uint32_t            cpu_id;
    struct thread       *current_thread;
    struct thread       *idle_thread;

    /* Per-CPU MLFQ run queues */
    struct thread       *run_queue[MLFQ_LEVELS];
    uint32_t            run_count;

    /* Scheduling state */
    bool                need_resched;
    uint64_t            idle_ticks;
    uint64_t            total_ticks;
};

/* ============================================================================
 * Thread API
 * ============================================================================ */

/* Initialize the threading subsystem */
void thread_init(void);

/* Create a new kernel thread */
struct thread *thread_create(const char *name, void (*entry)(void *), void *arg,
                            int priority);

/* Terminate the current thread */
void thread_exit(void) __noreturn;

/* Block the current thread (sleep) */
void thread_block(const char *reason);

/* Unblock a thread (wake up) */
void thread_unblock(struct thread *th);

/* Get current thread */
struct thread *current_thread_get(void);

/* ============================================================================
 * Scheduler API
 * ============================================================================ */

/* Initialize the scheduler */
void sched_init(void);

/* Per-CPU scheduler init */
void sched_init_percpu(void);

/* Timer tick handler (called from timer_handler) */
void sched_tick(void);

/* Voluntary context switch (yield) */
void sched_yield(void);

/* Pick next thread and switch to it */
void sched_switch(void);

/* Add thread to run queue */
void sched_enqueue(struct thread *th);

/* Remove thread from run queue */
void sched_dequeue(struct thread *th);

/* ============================================================================
 * Context switch (assembly, in context_switch.S)
 * ============================================================================ */
extern void context_switch(struct cpu_context *old, struct cpu_context *new_ctx);

#endif /* _KERN_THREAD_H */
