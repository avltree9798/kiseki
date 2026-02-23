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
#include <machine/trap.h>
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
            /*
             * CRITICAL: Mark the slot as no longer TH_TERM *inside* the lock.
             * Without this, another CPU calling alloc_thread() concurrently
             * could see state==TH_TERM on this same slot (since thread_create
             * only sets state=TH_RUN after alloc_thread returns and the lock
             * is released), causing two CPUs to receive the same thread struct.
             * TH_NEW (== TH_RUN) reserves the slot until thread_create fills
             * in the rest of the fields.
             */
            th->state = TH_RUN;
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
 * thread_sleep_on - Sleep the current thread on a wait channel.
 *
 * XNU equivalent: assert_wait(event, THREAD_UNINT) + thread_block(THREAD_CONTINUE_NULL)
 * BSD equivalent: tsleep(chan, pri, wmsg, 0) — untimed, uninterruptible.
 *
 * The caller passes an arbitrary address as the wait channel. When another
 * thread (or interrupt handler) calls thread_wakeup_on() with the same
 * address, all threads sleeping on that channel are placed back on the
 * run queue.
 *
 * @chan:   Wait channel (any kernel address; typically &some_struct_field)
 * @reason: Debug string stored in th->wait_reason for ps/debugging
 */
void thread_sleep_on(void *chan, const char *reason)
{
    struct cpu_data *cd = get_cpu_data();
    struct thread *th = cd->current_thread;

    th->wait_channel = chan;
    th->wait_reason = reason;
    th->state = TH_WAIT;

    sched_switch();
}

/*
 * thread_wakeup_on - Wake all threads sleeping on a wait channel.
 *
 * XNU equivalent: thread_wakeup_prim(event, FALSE, THREAD_AWAKENED)
 * BSD equivalent: wakeup(chan)
 *
 * Scans the thread table for any thread in TH_WAIT state whose
 * wait_channel matches @chan, and moves each to the run queue.
 *
 * This is O(MAX_THREADS) which matches XNU's simple hash-bucket scan.
 * For Kiseki's 256-thread pool this is trivially fast.
 *
 * Safe to call from interrupt context (does not block).
 *
 * @chan: Wait channel to wake (must match what was passed to thread_sleep_on)
 */
void thread_wakeup_on(void *chan)
{
    for (int i = 0; i < MAX_THREADS; i++) {
        struct thread *th = &thread_pool[i];
        if (th->state == TH_WAIT && th->wait_channel == chan) {
            thread_unblock(th);
        }
    }
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

    /*
     * XNU-style boot flow: the idle thread keeps its PMM-allocated stack.
     * The boot stack is abandoned entirely when kmain() calls load_context()
     * to jump into the bootstrap thread. No boot stack adoption needed.
     *
     * The idle thread will be scheduled normally by the scheduler when
     * no other threads are runnable. Its context was set up by
     * thread_create() with SP = PMM stack top and LR = thread_trampoline.
     */
    kprintf("[sched] Idle thread (tid=%lu) kstack=[0x%lx..0x%lx]\n",
            cd->idle_thread->tid,
            (uint64_t)cd->idle_thread->kernel_stack,
            (uint64_t)cd->idle_thread->kernel_stack +
            cd->idle_thread->kernel_stack_size);

    /*
     * Set idle thread as current_thread temporarily.
     * kmain() will later set current_thread = bootstrap_thread before
     * calling load_context().
     */
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

        /*
         * XNU-style: idle thread keeps its PMM-allocated stack.
         * The secondary CPU's boot stack will be abandoned when we
         * call load_context() below to switch into the idle thread.
         */
        kprintf("[sched] CPU%d idle thread (tid=%lu) kstack=[0x%lx..0x%lx]\n",
                cpuid, cd->idle_thread->tid,
                (uint64_t)cd->idle_thread->kernel_stack,
                (uint64_t)cd->idle_thread->kernel_stack +
                cd->idle_thread->kernel_stack_size);
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
     * - If thread has a CPU affinity, honour it
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

    /*
     * CRITICAL: Mask IRQs for the entire pick-next + context-switch
     * sequence. This prevents a timer IRQ from triggering a NESTED
     * sched_switch (via trap_irq_el1 → sched_switch) between the
     * moment we release the run_lock and the moment context_switch
     * saves the old thread's context. A nested sched_switch would
     * save the idle thread's context at a deep nested SP, and then
     * when the outer sched_switch resumes after eret, it would call
     * context_switch AGAIN, overwriting the context with the outer
     * SP — but the stack frames from the nested path (which the
     * thread might have been resumed into) are now lost, leading to
     * corrupted return addresses (x30=0x0) when the frames unwind.
     *
     * This mirrors XNU's approach: machine_switch_context() runs
     * with interrupts disabled across the entire switch path.
     *
     * We save DAIF once, mask IRQs, and only restore DAIF after
     * context_switch returns (on the RESUMED thread's path).
     */
    __asm__ volatile("mrs %0, daif" : "=r"(flags));
    __asm__ volatile("msr daifset, #0x2" ::: "memory"); /* Mask IRQs */

    spin_lock(&cd->run_lock);

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

    spin_unlock(&cd->run_lock);
    /* NOTE: IRQs remain MASKED — we only release the spinlock here,
     * not the IRQ state. IRQs will be restored after context_switch. */

    if (new_thread == old) {
        /* Same thread, no switch needed — restore IRQs and return */
        __asm__ volatile("msr daif, %0" :: "r"(flags) : "memory");
        return;
    }

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
#if DEBUG
    /* Critical validation only - no verbose prints per context switch */
    {
        /* Validate new context.sp is within new thread's kernel stack */
        uint64_t new_klo = (uint64_t)new_thread->kernel_stack;
        uint64_t new_khi = new_klo + new_thread->kernel_stack_size;
        uint64_t nsp = new_thread->context.sp;
        if (nsp < new_klo || nsp > new_khi) {
            kprintf("[CTX] BUG: new tid=%lu ctx.sp=0x%lx OUTSIDE kstack [0x%lx..0x%lx]\n",
                    new_thread->tid, nsp, new_klo, new_khi);
            panic("sched_switch: new thread SP outside its kernel stack");
        }

        /* Validate x30 is a kernel address (not user) */
        uint64_t x30_val = new_thread->context.x30;
        if (x30_val != 0) {
            bool is_kernel = (x30_val >= RAM_BASE && x30_val < (RAM_BASE + RAM_SIZE));
            if (!is_kernel) {
                pid_t new_pid = (new_thread->task) ? new_thread->task->pid : -1;
                kprintf("[CTX] BUG: new tid=%lu pid=%d x30=0x%lx NOT in kernel RAM!\n",
                        new_thread->tid, new_pid, x30_val);
                panic("sched_switch: switching to thread with non-kernel x30");
            }
        }
    }
#endif

    if (old)
        context_switch(&old->context, &new_thread->context);
    else
        context_switch(&cd->idle_thread->context, &new_thread->context);

    /*
     * We are now running on the RESUMED thread (not necessarily 'old').
     * Restore IRQs. The 'flags' variable is on the resumed thread's
     * stack frame, so it contains the DAIF state that was saved when
     * THIS thread called sched_switch (which may be a different
     * invocation than the one above — it's whichever invocation saved
     * this thread's context).
     */
    __asm__ volatile("msr daif, %0" :: "r"(flags) : "memory");

#if DEBUG
    /*
     * Validate the sched_switch stack frame BEFORE the compiler's
     * epilogue loads x29/x30 from it. The compiler saves x29 at [sp]
     * and x30 at [sp+8] in the prologue (stp x29, x30, [sp, #-N]!).
     * If these were corrupted while this thread was switched out,
     * the epilogue's ldp will load bad values and ret will crash.
     *
     * We read them directly from the stack here.
     */
    {
        uint64_t sp_val;
        __asm__ volatile("mov %0, sp" : "=r"(sp_val));
        uint64_t *frame = (uint64_t *)sp_val;
        uint64_t saved_x29 = frame[0];
        uint64_t saved_x30 = frame[1];

        /* x30 (LR) must be a kernel address [0x40000000, 0x80000000) */
        if (saved_x30 < RAM_BASE || saved_x30 >= (RAM_BASE + RAM_SIZE)) {
            kprintf("\n!!! SCHED_SWITCH STACK CORRUPTION !!!\n");
            kprintf("  Resumed thread's stack frame at SP=0x%lx has:\n", sp_val);
            kprintf("    [sp+0x00] saved_x29 = 0x%lx (expected kernel FP or 0)\n", saved_x29);
            kprintf("    [sp+0x08] saved_x30 = 0x%lx (expected kernel LR)\n", saved_x30);
            for (int i = 2; i < 8; i++)
                kprintf("    [sp+0x%02x] = 0x%lx\n", i * 8, frame[i]);
            struct cpu_data *cd2 = get_cpu_data();
            struct thread *cur = cd2 ? cd2->current_thread : NULL;
            kprintf("  CPU=%d current_tid=%lu\n",
                    cd2 ? (int)cd2->cpu_id : -1, cur ? cur->tid : 0);
            if (cur) {
                kprintf("  kstack=[0x%lx..0x%lx]\n",
                        (uint64_t)cur->kernel_stack,
                        (uint64_t)cur->kernel_stack + cur->kernel_stack_size);
            }
            /* Also dump a wider range around the frame to find the corruption source */
            kprintf("  Wider stack dump:\n");
            for (int i = -4; i < 16; i++) {
                uint64_t addr = sp_val + (int64_t)(i * 8);
                if (addr >= RAM_BASE && addr < (RAM_BASE + RAM_SIZE))
                    kprintf("    [0x%lx] = 0x%lx\n", addr, *(uint64_t *)addr);
            }
            panic("sched_switch: stack frame corrupted while thread was switched out");
        }
    }

    /* Validate resumed SP is in our kernel stack (silent unless error) */
    {
        if (old && old->kernel_stack) {
            uint64_t resumed_sp;
            __asm__ volatile("mov %0, sp" : "=r"(resumed_sp));
            uint64_t klo = (uint64_t)old->kernel_stack;
            uint64_t khi = klo + old->kernel_stack_size;
            if (resumed_sp < klo || resumed_sp > khi) {
                kprintf("[CTX]   !!! BUG: RESUMED hw_sp=0x%lx OUTSIDE kstack [0x%lx..0x%lx] !!!\n",
                        resumed_sp, klo, khi);
                panic("sched_switch: resumed with SP outside kernel stack");
            }
        }
    }
#endif
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

#if DEBUG
    /* Periodic thread state dump - every 2000 ticks (~2 seconds at 1kHz) */
    if ((cd->total_ticks % 2000) == 0) {
        kprintf("\n=== Thread state dump (tick %lu, cpu=%d) ===\n",
                cd->total_ticks, cd->cpu_id);
        kprintf("  Current: tid=%lu pid=%d\n",
                th ? th->tid : 0,
                (th && th->task) ? th->task->pid : -1);
        /* Show run queue info for all online CPUs */
        for (uint32_t c = 0; c < MAX_CPUS; c++) {
            struct cpu_data *cdi = &cpu_data_array[c];
            if (!cdi->online) continue;
            struct thread *cur = cdi->current_thread;
            kprintf("  CPU%d: run_count=%d current_tid=%lu idle_tid=%lu\n",
                    c, cdi->run_count,
                    cur ? cur->tid : 0,
                    cdi->idle_thread ? cdi->idle_thread->tid : 0);
        }
        extern struct thread thread_pool[];
        for (int i = 0; i < MAX_THREADS; i++) {
            struct thread *t = &thread_pool[i];
            if (t->tid == 0)
                continue;
            const char *state_str = "???";
            switch (t->state) {
                case TH_RUN:  state_str = "RUN"; break;
                case TH_WAIT: state_str = "WAIT"; break;
                case TH_IDLE: state_str = "IDLE"; break;
            }
            pid_t tpid = t->task ? t->task->pid : -1;
            kprintf("  tid=%lu pid=%d cpu=%d state=%s prio=%d",
                    t->tid, tpid, t->cpu, state_str, t->effective_priority);
            if (t->state == TH_WAIT && t->wait_reason)
                kprintf(" wait=\"%s\"", t->wait_reason);
            if (t->state == TH_WAIT && t->wait_channel)
                kprintf(" chan=0x%lx", (uint64_t)t->wait_channel);
            kprintf(" ctx.x30=0x%lx ctx.sp=0x%lx\n",
                    t->context.x30, t->context.sp);
        }
        kprintf("=== end thread dump ===\n\n");
    }
#endif
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

    /* Use the real TF_SIZE from machine/trap.h (36 * 8 = 288 bytes) */
    /* trap_frame: 31 regs (x0-x30) + sp + elr + spsr + esr + far */
    uint64_t tf_base = kstack_top - TF_SIZE;
    struct trap_frame *user_tf = (struct trap_frame *)tf_base;

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

    /* Zero the remaining trap frame fields (not restored by RESTORE_REGS
     * but must be initialized so the frame is clean) */
    user_tf->esr = 0;
    user_tf->far = 0;

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
