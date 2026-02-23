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
#include <drivers/gic.h>

/* Per-CPU data array */
static struct cpu_data cpu_data_array[MAX_CPUS];

/* Thread table */
static struct thread thread_pool[MAX_THREADS];
static uint64_t next_tid = 1;
static spinlock_t thread_lock = SPINLOCK_INIT;

/* Sleep queue - threads waiting for timed wakeup */
static struct thread *sleep_queue = NULL;
static spinlock_t sleep_lock = SPINLOCK_INIT;

/* --- Forward declarations for SMP load balancing --- */
static uint32_t sched_find_least_loaded_cpu(uint32_t affinity);
static void sched_enqueue_cpu(struct thread *th, uint32_t cpu_id, bool send_ipi);
static struct thread *sched_steal_work(uint32_t my_cpu);

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
        struct cpu_data *cd = get_cpu_data();
        
        /* Try to steal work from busy CPUs before going idle */
        struct thread *stolen = sched_steal_work(cd->cpu_id);
        if (stolen) {
            /* Enqueue stolen thread on our run queue and reschedule */
            sched_enqueue_cpu(stolen, cd->cpu_id, false);
            sched_yield();
            continue;
        }
        
        /* No work available, wait for interrupt */
        __asm__ volatile("wfi");
        
        /* On wakeup from WFI, check if we need to reschedule */
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

            /*
             * Free the old kernel stack if this is a terminated thread
             * being reused. We couldn't free it in thread_exit() because
             * the thread was still running on it.
             */
            if (th->state == TH_TERM && th->kernel_stack) {
                pmm_free_pages((uint64_t)th->kernel_stack, 2);
                th->kernel_stack = NULL;
                th->kernel_stack_size = 0;
            }

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

    /*
     * DO NOT free the kernel stack here - we are still running on it!
     * The stack will be freed by the reaper thread or when the thread
     * structure is recycled.
     */

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
    cd->online = false;  /* Not online until fully initialized */
    spin_init(&cd->run_lock);
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
    cd->idle_thread->cpu_affinity = 0;  /* Can run on any CPU */

    /* Boot thread becomes the "current" thread temporarily */
    cd->current_thread = cd->idle_thread;

    /* Store per-CPU data pointer in TPIDR_EL1 */
    set_cpu_data(cd);
    
    /* Mark CPU 0 as online now that initialization is complete */
    cd->online = true;

    kprintf("[sched] Scheduler initialized on core 0\n");
}

void sched_init_percpu(void)
{
    uint32_t cpuid = get_cpu_id();
    struct cpu_data *cd = &cpu_data_array[cpuid];

    cd->cpu_id = cpuid;
    cd->online = false;  /* Not online until fully initialized */
    spin_init(&cd->run_lock);
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
        cd->idle_thread->cpu_affinity = 0;
    }

    cd->current_thread = cd->idle_thread;
    set_cpu_data(cd);
    
    /* Mark this CPU as online now that initialization is complete */
    cd->online = true;
}

/* ============================================================================
 * SMP Load Balancing
 *
 * macOS-style work distribution:
 *   1. New threads go to the least-loaded CPU (that matches affinity)
 *   2. Idle CPUs steal work from busy CPUs (work-stealing)
 *   3. IPIs wake up remote CPUs when work is enqueued
 * ============================================================================ */

/*
 * sched_find_least_loaded_cpu - Find the CPU with the lowest run_count
 *
 * @affinity: CPU affinity mask (0 = any CPU, else bitmask of allowed CPUs)
 * Returns: CPU ID with lowest load (that matches affinity)
 */
static uint32_t sched_find_least_loaded_cpu(uint32_t affinity)
{
    uint32_t best_cpu = get_cpu_id();  /* Default to current CPU */
    uint32_t min_load = 0xFFFFFFFF;
    
    for (uint32_t cpu = 0; cpu < MAX_CPUS; cpu++) {
        struct cpu_data *cd = &cpu_data_array[cpu];
        
        /* Skip CPUs that aren't online yet */
        if (!cd->online)
            continue;
        
        /* Check affinity - if affinity is 0, allow any CPU */
        if (affinity != 0 && !(affinity & (1u << cpu)))
            continue;
        
        uint32_t load = cd->run_count;
        
        /* Prefer CPUs that are idle (run_count == 0) */
        if (load < min_load) {
            min_load = load;
            best_cpu = cpu;
        }
    }
    
    return best_cpu;
}

/*
 * sched_enqueue_cpu - Enqueue a thread onto a specific CPU's run queue
 *
 * @th: Thread to enqueue
 * @cpu_id: Target CPU
 * @send_ipi: If true, send IPI_RESCHEDULE to wake the target CPU
 */
static void sched_enqueue_cpu(struct thread *th, uint32_t cpu_id, bool send_ipi)
{
    struct cpu_data *cd = &cpu_data_array[cpu_id];
    int pri = th->effective_priority;
    uint64_t flags;
    
    /*
     * Memory barrier: ensure all writes to the thread structure (e.g., 
     * context setup in fork) are visible before we take the lock and
     * make the thread visible to other CPUs.
     */
    __asm__ volatile("dmb ish" ::: "memory");
    
    spin_lock_irqsave(&cd->run_lock, &flags);
    
    /* Add to tail of priority queue */
    th->run_next = NULL;
    th->cpu = cpu_id;
    
    if (cd->run_queue[pri] == NULL) {
        cd->run_queue[pri] = th;
    } else {
        struct thread *tail = cd->run_queue[pri];
        while (tail->run_next)
            tail = tail->run_next;
        tail->run_next = th;
    }
    cd->run_count++;
    
    /* Check if we need to preempt the target CPU's current thread */
    bool need_ipi = false;
    if (cd->current_thread) {
        if (pri > cd->current_thread->effective_priority) {
            cd->need_resched = true;
            need_ipi = true;
        } else if (cd->current_thread == cd->idle_thread) {
            /* CPU is idle, wake it up */
            cd->need_resched = true;
            need_ipi = true;
        }
    }
    
    spin_unlock_irqrestore(&cd->run_lock, flags);
    
    /* Send IPI to wake the target CPU if it's different from current */
    if (send_ipi && need_ipi && cpu_id != get_cpu_id()) {
        gic_send_sgi(IPI_RESCHEDULE, 1u << cpu_id);
    }
}

/*
 * sched_steal_work - Try to steal a thread from another CPU's run queue
 *
 * Called by idle CPUs to find work. Scans other CPUs for threads to steal.
 * Steals the lowest-priority thread from the busiest CPU.
 *
 * @my_cpu: The CPU trying to steal work
 * Returns: Stolen thread or NULL if nothing available
 */
static struct thread *sched_steal_work(uint32_t my_cpu)
{
    struct thread *victim = NULL;
    uint32_t busiest_cpu = my_cpu;
    uint32_t max_load = 0;
    
    /* Find the busiest CPU */
    for (uint32_t cpu = 0; cpu < MAX_CPUS; cpu++) {
        if (cpu == my_cpu)
            continue;
        struct cpu_data *cd = &cpu_data_array[cpu];
        
        /* Skip CPUs that aren't online yet */
        if (!cd->online)
            continue;
        
        if (cd->run_count > max_load) {
            max_load = cd->run_count;
            busiest_cpu = cpu;
        }
    }
    
    /* Only steal if the busiest CPU has at least 2 runnable threads */
    if (busiest_cpu == my_cpu || max_load < 2)
        return NULL;
    
    struct cpu_data *cd = &cpu_data_array[busiest_cpu];
    uint64_t flags;
    
    spin_lock_irqsave(&cd->run_lock, &flags);
    
    /* Find the lowest-priority thread to steal (scan from pri 0 up) */
    for (int pri = 0; pri < MLFQ_LEVELS; pri++) {
        if (cd->run_queue[pri]) {
            struct thread *th = cd->run_queue[pri];
            
            /* Check affinity - can we run this thread? */
            if (th->cpu_affinity != 0 && !(th->cpu_affinity & (1u << my_cpu)))
                continue;
            
            /* Remove from victim's run queue */
            cd->run_queue[pri] = th->run_next;
            th->run_next = NULL;
            cd->run_count--;
            victim = th;
            break;
        }
    }
    
    spin_unlock_irqrestore(&cd->run_lock, flags);
    
    return victim;
}

void sched_enqueue(struct thread *th)
{
    uint32_t target_cpu;
    uint32_t my_cpu = get_cpu_id();
    
    /*
     * SMP Load Balancing:
     * - If thread has never run (cpu == -1), place on least-loaded CPU
     * - If thread has a CPU affinity, honor it
     * - Otherwise, keep on same CPU (cache affinity)
     */
    if (th->cpu == -1) {
        /* New thread: find least-loaded CPU */
        target_cpu = sched_find_least_loaded_cpu(th->cpu_affinity);
    } else if ((uint32_t)th->cpu >= MAX_CPUS) {
        /* Invalid CPU, use current CPU */
        target_cpu = my_cpu;
    } else {
        /* Existing thread: stay on same CPU (cache affinity) */
        target_cpu = (uint32_t)th->cpu;
        
        /* But if affinity changed, re-evaluate */
        if (th->cpu_affinity != 0 && !(th->cpu_affinity & (1u << th->cpu))) {
            target_cpu = sched_find_least_loaded_cpu(th->cpu_affinity);
        }
    }
    
    /* Use the locked enqueue that handles cross-CPU placement */
    sched_enqueue_cpu(th, target_cpu, true);
}

void sched_dequeue(struct thread *th)
{
    /* Find which CPU this thread is queued on */
    uint32_t cpu_id = th->cpu;
    if (cpu_id >= MAX_CPUS)
        cpu_id = get_cpu_id();  /* Fallback to current CPU */
    
    struct cpu_data *cd = &cpu_data_array[cpu_id];
    int pri = th->effective_priority;
    uint64_t flags;

    spin_lock_irqsave(&cd->run_lock, &flags);

    struct thread **pp = &cd->run_queue[pri];
    while (*pp) {
        if (*pp == th) {
            *pp = th->run_next;
            th->run_next = NULL;
            cd->run_count--;
            spin_unlock_irqrestore(&cd->run_lock, flags);
            return;
        }
        pp = &(*pp)->run_next;
    }

    spin_unlock_irqrestore(&cd->run_lock, flags);
}

void sched_switch(void)
{
    struct cpu_data *cd = get_cpu_data();
    struct thread *old = cd->current_thread;
    struct thread *new_thread;
    uint64_t flags;

    cd->need_resched = false;

    spin_lock_irqsave(&cd->run_lock, &flags);

    /* Put old thread back on run queue if still runnable */
    if (old && old->state == TH_RUN && old != cd->idle_thread) {
        /* Re-enqueue on local CPU (no IPI needed, we're local) */
        int pri = old->effective_priority;
        old->run_next = NULL;
        if (cd->run_queue[pri] == NULL) {
            cd->run_queue[pri] = old;
        } else {
            struct thread *tail = cd->run_queue[pri];
            while (tail->run_next)
                tail = tail->run_next;
            tail->run_next = old;
        }
        cd->run_count++;
    }

    /* Pick next thread (inline to avoid nested lock) */
    new_thread = NULL;
    for (int i = MLFQ_LEVELS - 1; i >= 0; i--) {
        if (cd->run_queue[i]) {
            new_thread = cd->run_queue[i];
            cd->run_queue[i] = new_thread->run_next;
            new_thread->run_next = NULL;
            cd->run_count--;
            break;
        }
    }
    if (!new_thread)
        new_thread = cd->idle_thread;

    spin_unlock_irqrestore(&cd->run_lock, flags);

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
 * Uses SMP-aware placement to distribute woken threads.
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
        
        /*
         * Use SMP-aware enqueue: if thread has never run, place on
         * least-loaded CPU. Otherwise keep cache affinity.
         */
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
        uint64_t aging_flags;
        spin_lock_irqsave(&cd->run_lock, &aging_flags);
        
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
        
        spin_unlock_irqrestore(&cd->run_lock, aging_flags);
    }
}

/* ============================================================================
 * User Thread Creation (bsdthread_create support)
 * ============================================================================ */

/*
 * user_thread_return - Entry point for newly created user threads
 *
 * Similar to fork_child_return, but for pthread_create'd threads.
 * The thread was set up with:
 *   - context.x30 = user_thread_return
 *   - context.sp  = top of kernel stack (where trap frame is placed)
 *   - context.x19 = pointer to task's vm_space (for TTBR0 switch)
 *   - context.x20 = TLS base address (for TPIDR_EL0)
 *
 * Assembly trampoline defined in vectors.S
 */
extern void user_thread_return(void);

/*
 * thread_find - Find a thread by TID
 */
struct thread *thread_find(uint64_t tid)
{
    for (int i = 0; i < MAX_THREADS; i++) {
        if (thread_pool[i].tid == tid && thread_pool[i].state != TH_TERM)
            return &thread_pool[i];
    }
    return NULL;
}

/*
 * thread_create_user - Create a user-mode thread within an existing task
 *
 * @task:     The Mach task this thread belongs to
 * @entry:    User-space entry point (start_routine)
 * @arg:      Argument to pass to entry (in x0)
 * @stack:    User stack pointer (top of stack)
 * @tls_base: Thread-local storage base address (TPIDR_EL0)
 * @priority: Thread priority
 *
 * Sets up the thread to start executing at `entry` in user mode with
 * `arg` in x0 and stack at `stack`. The TLS base is set in TPIDR_EL0.
 *
 * Returns the new thread on success, NULL on failure.
 */
struct thread *thread_create_user(struct task *task, uint64_t entry,
                                  uint64_t arg, uint64_t stack,
                                  uint64_t tls_base, int priority)
{
    if (task == NULL || task->vm_space == NULL)
        return NULL;

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
    th->task = task;
    th->wait_channel = NULL;
    th->wait_reason = NULL;
    th->run_next = NULL;
    th->wait_next = NULL;
    th->continuation = 0;
    th->cpu = -1;
    th->tls_base = tls_base;
    th->detached = false;
    th->joined = false;
    th->exit_value = NULL;
    th->join_waiter = NULL;

    /*
     * Set up a trap frame at the top of the kernel stack.
     * This is what user_thread_return will restore via RESTORE_REGS.
     */
    uint64_t kstack_top = stack_pa + th->kernel_stack_size;

    /* TF_SIZE is defined in machine/trap.h - it's the size of trap_frame */
    /* trap_frame is: 31 regs (x0-x30) + sp + elr + spsr = 34 * 8 = 272 bytes */
    #define TF_SIZE_LOCAL 272

    uint64_t tf_base = kstack_top - TF_SIZE_LOCAL;
    struct {
        uint64_t regs[31];  /* x0-x30 */
        uint64_t sp;
        uint64_t elr;
        uint64_t spsr;
    } *user_tf = (void *)tf_base;

    /* Zero out the trap frame */
    for (int i = 0; i < 31; i++)
        user_tf->regs[i] = 0;

    /* x0 = arg (first argument to start_routine) */
    user_tf->regs[0] = arg;

    /* User stack pointer */
    user_tf->sp = stack;

    /* User entry point */
    user_tf->elr = entry;

    /* SPSR: EL0t (user mode), IRQs enabled */
    /* SPSR_EL1 for EL0: M[4:0] = 0b00000 (EL0t), DAIF = 0 (all enabled) */
    user_tf->spsr = 0x0;

    /*
     * Set up the kernel-mode context for the first context switch.
     * context_switch will restore this, then "return" to user_thread_return.
     *
     * context.x30 (LR) = user_thread_return
     * context.sp       = tf_base (where the trap frame lives)
     * context.x19      = task->vm_space (for TTBR0 switch)
     * context.x20      = tls_base (for TPIDR_EL0 setup)
     */
    th->context.x30 = (uint64_t)user_thread_return;
    th->context.sp  = tf_base;
    th->context.x19 = (uint64_t)task->vm_space;
    th->context.x20 = tls_base;
    th->context.x29 = 0;  /* FP sentinel */

    /* Link thread into task's thread list */
    th->task_next = task->threads;
    task->threads = th;

    return th;
}

/*
 * thread_terminate - Terminate the current user thread
 *
 * @retval: Return value for pthread_join
 *
 * This is called from bsdthread_terminate syscall or when a thread's
 * start_routine returns.
 */
void thread_terminate(void *retval)
{
    struct cpu_data *cd = get_cpu_data();
    struct thread *th = cd->current_thread;

    /* Store exit value for join */
    th->exit_value = retval;

    /* Wake up any thread waiting to join us */
    if (th->join_waiter) {
        thread_unblock(th->join_waiter);
        th->join_waiter = NULL;
    }

    /* Remove from task's thread list */
    if (th->task) {
        struct thread **pp = &th->task->threads;
        while (*pp) {
            if (*pp == th) {
                *pp = th->task_next;
                break;
            }
            pp = &(*pp)->task_next;
        }
    }

    /* Mark as terminated */
    th->state = TH_TERM;

    /* Switch to next thread (never returns) */
    sched_switch();

    /* Should never reach here */
    panic("thread_terminate: sched_switch returned");
    __builtin_unreachable();
}
