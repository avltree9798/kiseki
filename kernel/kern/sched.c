/*
 * Kiseki OS - Scheduler Implementation (MLFQ)
 *
 * Multilevel Feedback Queue scheduler with:
 *   - 128 priority levels (0=lowest, 127=highest)
 *   - Per-CPU run queues
 *   - Priority aging to prevent starvation
 *   - Preemptive scheduling on timer tick
 */

#include <kiseki/types.h>
#include <kiseki/platform.h>
#include <kern/thread.h>
#include <kern/sync.h>
#include <kern/pmm.h>
#include <kern/vmm.h>
#include <kern/kprintf.h>
#include <drivers/timer.h>

/* Per-CPU data array */
static struct cpu_data cpu_data_array[MAX_CPUS];

/* Thread table */
static struct thread thread_pool[MAX_THREADS];
static uint64_t next_tid = 1;
static spinlock_t thread_lock = SPINLOCK_INIT;

/* Sleep queue - threads waiting for timed wakeup */
static struct thread *sleep_queue = NULL;
static spinlock_t sleep_lock = SPINLOCK_INIT;

/* --- Per-CPU data access via TPIDR_EL1 --- */

static inline void set_cpu_data(struct cpu_data *data)
{
    __asm__ volatile("msr tpidr_el1, %0" :: "r"(data));
}

static inline struct cpu_data *get_cpu_data(void)
{
    struct cpu_data *data;
    __asm__ volatile("mrs %0, tpidr_el1" : "=r"(data));
    return data;
}

static inline uint32_t get_cpu_id(void)
{
    uint64_t mpidr;
    __asm__ volatile("mrs %0, mpidr_el1" : "=r"(mpidr));
    return (uint32_t)(mpidr & 0xFF);
}

/* --- Idle thread function --- */

static void idle_thread_func(void *arg __unused)
{
    for (;;) {
        __asm__ volatile("wfi");
        /* On wakeup from WFI, check if we need to reschedule */
        struct cpu_data *cd = get_cpu_data();
        if (cd->need_resched)
            sched_yield();
    }
}

/* --- Thread allocation --- */

static struct thread *alloc_thread(void)
{
    uint64_t flags;
    spin_lock_irqsave(&thread_lock, &flags);

    for (int i = 0; i < MAX_THREADS; i++) {
        if (thread_pool[i].state == TH_TERM || thread_pool[i].tid == 0) {
            struct thread *th = &thread_pool[i];
            th->tid = next_tid++;
            spin_unlock_irqrestore(&thread_lock, flags);
            return th;
        }
    }

    spin_unlock_irqrestore(&thread_lock, flags);
    return NULL;
}

/* --- Entry trampoline for new threads --- */

struct thread_start_args {
    void (*entry)(void *);
    void *arg;
};

/*
 * This runs as the LR target of a new thread after its first context switch.
 * x19 = entry function, x20 = arg (saved by thread_create into context).
 */
static void thread_trampoline(void)
{
    struct cpu_data *cd = get_cpu_data();
    struct thread *th = cd->current_thread;

    /* Enable interrupts (new threads start with IRQs masked) */
    __asm__ volatile("msr daifclr, #0x2");

    /* Call the actual thread function.
     * Entry and arg are stored in x19/x20 (callee-saved, set by thread_create). */
    void (*entry)(void *) = (void (*)(void *))th->context.x19;
    void *arg = (void *)th->context.x20;
    entry(arg);

    /* If the function returns, terminate the thread */
    thread_exit();
}

/* ============================================================================
 * Thread API
 * ============================================================================ */

void thread_init(void)
{
    /* Clear thread pool */
    for (int i = 0; i < MAX_THREADS; i++) {
        thread_pool[i].tid = 0;
        thread_pool[i].state = TH_TERM;
    }

    kprintf("[sched] Thread subsystem initialized (%d max threads)\n", MAX_THREADS);
}

struct thread *thread_create(const char *name, void (*entry)(void *), void *arg,
                            int priority)
{
    (void)name;  /* Name stored in task->name, not thread */

    struct thread *th = alloc_thread();
    if (!th)
        return NULL;

    /* Allocate kernel stack (4 pages = 16KB) */
    uint64_t stack_pa = pmm_alloc_pages(2);  /* 2^2 = 4 pages */
    if (!stack_pa) {
        th->tid = 0;
        th->state = TH_TERM;
        return NULL;
    }

    th->kernel_stack = (uint64_t *)stack_pa;
    th->kernel_stack_size = 4 * PAGE_SIZE;
    th->priority = priority;
    th->effective_priority = priority;
    th->sched_policy = SCHED_OTHER;
    th->quantum = SCHED_QUANTUM_DEFAULT;
    th->state = TH_RUN;
    th->task = NULL;
    th->wait_channel = NULL;
    th->wait_reason = NULL;
    th->run_next = NULL;
    th->wait_next = NULL;
    th->continuation = 0;
    th->cpu = -1;

    /* Set up initial context so first context switch enters thread_trampoline.
     * SP = top of kernel stack
     * LR (x30) = thread_trampoline
     * x19 = entry function pointer
     * x20 = arg
     */
    uint64_t stack_top = stack_pa + th->kernel_stack_size;
    th->context.sp = stack_top;
    th->context.x30 = (uint64_t)thread_trampoline;
    th->context.x19 = (uint64_t)entry;
    th->context.x20 = (uint64_t)arg;
    th->context.x29 = 0;  /* FP = 0 (stack frame sentinel) */

    return th;
}

void thread_exit(void)
{
    struct cpu_data *cd = get_cpu_data();
    struct thread *th = cd->current_thread;

    /* Mark as terminated */
    th->state = TH_TERM;

    /* Free kernel stack */
    if (th->kernel_stack) {
        pmm_free_pages((uint64_t)th->kernel_stack, 2); /* order 2 = 4 pages */
        th->kernel_stack = NULL;
        th->kernel_stack_size = 0;
    }

    /* Switch to next thread (never returns) */
    sched_switch();

    /* Should never reach here */
    panic("thread_exit: sched_switch returned");
    __builtin_unreachable();
}

void thread_block(const char *reason)
{
    struct cpu_data *cd = get_cpu_data();
    struct thread *th = cd->current_thread;

    th->state = TH_WAIT;
    th->wait_reason = reason;

    sched_switch();
}

void thread_unblock(struct thread *th)
{
    if (th->state != TH_WAIT)
        return;

    th->state = TH_RUN;
    th->wait_channel = NULL;
    th->wait_reason = NULL;
    th->wakeup_tick = 0;

    sched_enqueue(th);
}

/*
 * thread_sleep_ticks - Sleep the current thread for a number of timer ticks
 *
 * @ticks: Number of timer ticks to sleep (at 100Hz, 100 ticks = 1 second)
 */
void thread_sleep_ticks(uint64_t ticks)
{
    struct cpu_data *cd = get_cpu_data();
    struct thread *th = cd->current_thread;
    uint64_t flags;

    if (ticks == 0)
        return;

    /* Calculate absolute wakeup time */
    th->wakeup_tick = timer_get_ticks() + ticks;
    th->state = TH_WAIT;
    th->wait_reason = "sleep";

    /* Add to sleep queue (sorted by wakeup time for efficiency) */
    spin_lock_irqsave(&sleep_lock, &flags);

    struct thread **pp = &sleep_queue;
    while (*pp && (*pp)->wakeup_tick <= th->wakeup_tick)
        pp = &(*pp)->sleep_next;

    th->sleep_next = *pp;
    *pp = th;

    spin_unlock_irqrestore(&sleep_lock, flags);

    /* Switch to another thread */
    sched_switch();
}

struct thread *current_thread_get(void)
{
    struct cpu_data *cd = get_cpu_data();
    return cd ? cd->current_thread : NULL;
}

/* ============================================================================
 * Scheduler
 * ============================================================================ */

void sched_init(void)
{
    /* Initialize per-CPU data for boot CPU */
    struct cpu_data *cd = &cpu_data_array[0];
    cd->cpu_id = 0;
    cd->run_count = 0;
    cd->need_resched = false;
    cd->idle_ticks = 0;
    cd->total_ticks = 0;

    for (int i = 0; i < MLFQ_LEVELS; i++)
        cd->run_queue[i] = NULL;

    /* Create idle thread for core 0 */
    cd->idle_thread = thread_create("idle/0", idle_thread_func, NULL, PRI_IDLE);
    if (!cd->idle_thread)
        panic("sched_init: cannot create idle thread");
    cd->idle_thread->state = TH_IDLE;
    cd->idle_thread->cpu = 0;

    /* Boot thread becomes the "current" thread temporarily */
    cd->current_thread = cd->idle_thread;

    /* Store per-CPU data pointer in TPIDR_EL1 */
    set_cpu_data(cd);

    kprintf("[sched] Scheduler initialized on core 0\n");
}

void sched_init_percpu(void)
{
    uint32_t cpuid = get_cpu_id();
    struct cpu_data *cd = &cpu_data_array[cpuid];

    cd->cpu_id = cpuid;
    cd->run_count = 0;
    cd->need_resched = false;
    cd->idle_ticks = 0;
    cd->total_ticks = 0;

    for (int i = 0; i < MLFQ_LEVELS; i++)
        cd->run_queue[i] = NULL;

    /* Create idle thread for this core */
    char name[16];
    /* Simple name without snprintf */
    name[0] = 'i'; name[1] = 'd'; name[2] = 'l'; name[3] = 'e';
    name[4] = '/'; name[5] = '0' + (char)cpuid; name[6] = '\0';

    cd->idle_thread = thread_create(name, idle_thread_func, NULL, PRI_IDLE);
    if (cd->idle_thread) {
        cd->idle_thread->state = TH_IDLE;
        cd->idle_thread->cpu = cpuid;
    }

    cd->current_thread = cd->idle_thread;
    set_cpu_data(cd);
}

void sched_enqueue(struct thread *th)
{
    struct cpu_data *cd = get_cpu_data();
    int pri = th->effective_priority;

    /* Add to tail of priority queue */
    th->run_next = NULL;
    if (cd->run_queue[pri] == NULL) {
        cd->run_queue[pri] = th;
    } else {
        struct thread *tail = cd->run_queue[pri];
        while (tail->run_next)
            tail = tail->run_next;
        tail->run_next = th;
    }
    cd->run_count++;

    /* Check if we need to preempt current thread */
    if (cd->current_thread && pri > cd->current_thread->effective_priority)
        cd->need_resched = true;
}

void sched_dequeue(struct thread *th)
{
    struct cpu_data *cd = get_cpu_data();
    int pri = th->effective_priority;

    struct thread **pp = &cd->run_queue[pri];
    while (*pp) {
        if (*pp == th) {
            *pp = th->run_next;
            th->run_next = NULL;
            cd->run_count--;
            return;
        }
        pp = &(*pp)->run_next;
    }
}

/*
 * sched_pick_next - Find highest-priority runnable thread
 *
 * Scans from highest priority down.
 */
static struct thread *sched_pick_next(struct cpu_data *cd)
{
    for (int i = MLFQ_LEVELS - 1; i >= 0; i--) {
        if (cd->run_queue[i]) {
            struct thread *th = cd->run_queue[i];
            cd->run_queue[i] = th->run_next;
            th->run_next = NULL;
            cd->run_count--;
            return th;
        }
    }
    return cd->idle_thread;
}

void sched_switch(void)
{
    struct cpu_data *cd = get_cpu_data();
    struct thread *old = cd->current_thread;
    struct thread *new_thread;

    cd->need_resched = false;

    /* Put old thread back on run queue if still runnable */
    if (old && old->state == TH_RUN && old != cd->idle_thread)
        sched_enqueue(old);

    /* Pick next thread */
    new_thread = sched_pick_next(cd);
    if (new_thread == old)
        return;  /* Same thread, no switch needed */

    new_thread->cpu = cd->cpu_id;
    new_thread->quantum = SCHED_QUANTUM_DEFAULT;
    cd->current_thread = new_thread;

    /*
     * Switch VM space (TTBR0) if the new thread belongs to a different
     * task (process). This is critical for multi-process scheduling:
     * each process has its own user page tables.
     *
     * We compare the vm_space pointers to avoid unnecessary TTBR0 writes.
     * The idle thread (task=NULL) uses whatever TTBR0 was last set.
     */
    struct vm_space *old_vm = (old && old->task) ? old->task->vm_space : NULL;
    struct vm_space *new_vm = (new_thread && new_thread->task) ?
                              new_thread->task->vm_space : NULL;
    if (new_vm && new_vm->pgd && new_vm != old_vm) {
        vmm_switch_space(new_vm);
    }

    /* Perform the actual context switch (assembly) */
    if (old)
        context_switch(&old->context, &new_thread->context);
    else
        context_switch(&cd->idle_thread->context, &new_thread->context);
}

void sched_yield(void)
{
    sched_switch();
}

/*
 * sched_wakeup_sleepers - Wake threads whose sleep time has expired
 *
 * Called from sched_tick() to check the sleep queue.
 */
static void sched_wakeup_sleepers(void)
{
    uint64_t now = timer_get_ticks();
    uint64_t flags;

    spin_lock_irqsave(&sleep_lock, &flags);

    /* Wake all threads at the front of the queue whose time has come */
    while (sleep_queue && sleep_queue->wakeup_tick <= now) {
        struct thread *th = sleep_queue;
        sleep_queue = th->sleep_next;
        th->sleep_next = NULL;
        th->wakeup_tick = 0;
        th->state = TH_RUN;
        th->wait_reason = NULL;

        spin_unlock_irqrestore(&sleep_lock, flags);
        sched_enqueue(th);
        spin_lock_irqsave(&sleep_lock, &flags);
    }

    spin_unlock_irqrestore(&sleep_lock, flags);
}

/*
 * sched_tick - Called from timer interrupt handler (100 Hz)
 *
 * Decrements current thread's quantum. If expired, marks for reschedule.
 * Also performs priority aging for starvation prevention.
 */
void sched_tick(void)
{
    struct cpu_data *cd = get_cpu_data();
    if (!cd)
        return;

    cd->total_ticks++;

    /* Check for sleeping threads to wake up */
    sched_wakeup_sleepers();

    struct thread *th = cd->current_thread;
    if (!th || th == cd->idle_thread) {
        cd->idle_ticks++;
        /* Check if there's work to do */
        if (cd->run_count > 0)
            cd->need_resched = true;
        return;
    }

    /* Decrement quantum */
    th->quantum--;
    if (th->quantum <= 0) {
        /* MLFQ: lower priority slightly (aging in reverse) */
        if (th->sched_policy == SCHED_OTHER && th->effective_priority > PRI_MIN) {
            th->effective_priority--;
        }
        cd->need_resched = true;
    }

    /* Priority aging: every 100 ticks, boost starved threads */
    if ((cd->total_ticks % 100) == 0) {
        for (int i = 0; i < MLFQ_LEVELS - 1; i++) {
            struct thread *t = cd->run_queue[i];
            while (t) {
                struct thread *next = t->run_next;
                if (t->sched_policy == SCHED_OTHER) {
                    /* Boost toward base priority */
                    if (t->effective_priority < t->priority)
                        t->effective_priority++;
                }
                t = next;
            }
        }
    }
}
