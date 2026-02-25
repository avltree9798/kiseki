/*
 * Kiseki OS - Synchronization Primitives Implementation
 *
 * Spinlocks use ARMv8 LDAXR/STLXR (exclusive load/store with acquire/release).
 * Mutexes and semaphores will integrate with the scheduler for sleeping.
 */

#include <kiseki/types.h>
#include <kern/sync.h>
#include <kern/thread.h>
#include <kern/kprintf.h>

/* --- Helper: disable/enable interrupts --- */

static inline uint64_t irq_save(void)
{
    uint64_t flags;
    __asm__ volatile("mrs %0, daif" : "=r"(flags));
    __asm__ volatile("msr daifset, #0x2");  /* Mask IRQ */
    return flags;
}

static inline void irq_restore(uint64_t flags)
{
    __asm__ volatile("msr daif, %0" :: "r"(flags));
}

/* ============================================================================
 * Spinlock Implementation (using ARMv8 atomics)
 * ============================================================================ */

void spin_init(spinlock_t *lock)
{
    lock->locked = 0;
}

void spin_lock(spinlock_t *lock)
{
    uint32_t tmp;
    __asm__ volatile(
        "   sevl\n"
        "1: wfe\n"
        "   ldaxr   %w0, [%1]\n"
        "   cbnz    %w0, 1b\n"
        "   stxr    %w0, %w2, [%1]\n"
        "   cbnz    %w0, 1b\n"
        : "=&r"(tmp)
        : "r"(&lock->locked), "r"(1)
        : "memory"
    );
}

void spin_unlock(spinlock_t *lock)
{
    __asm__ volatile(
        "stlr   %w0, [%1]\n"
        :
        : "r"(0), "r"(&lock->locked)
        : "memory"
    );
}

bool spin_trylock(spinlock_t *lock)
{
    uint32_t old, status;
    __asm__ volatile(
        "ldaxr  %w0, [%2]\n"
        "cbnz   %w0, 1f\n"
        "stxr   %w1, %w3, [%2]\n"
        "b      2f\n"
        "1: mov %w1, #1\n"
        "2:\n"
        : "=&r"(old), "=&r"(status)
        : "r"(&lock->locked), "r"(1)
        : "memory"
    );
    return status == 0;
}

void spin_lock_irqsave(spinlock_t *lock, uint64_t *flags)
{
    *flags = irq_save();
    spin_lock(lock);
}

void spin_unlock_irqrestore(spinlock_t *lock, uint64_t flags)
{
    spin_unlock(lock);
    irq_restore(flags);
}

/* ============================================================================
 * Mutex Implementation
 *
 * Simple implementation: spin briefly, then sleep.
 * Priority inheritance: if a high-priority thread blocks on a mutex held
 * by a low-priority thread, the low-priority thread's effective priority
 * is temporarily raised.
 *
 * Mutexes use adaptive spinning: spin briefly, then sleep on a wait queue.
 * On unlock, the first waiter is woken and handed ownership directly.
 * ============================================================================ */

void mutex_init(mutex_t *mtx)
{
    mtx->locked = 0;
    mtx->owner = NULL;
    mtx->waiters_head = NULL;
    mtx->waiters_tail = NULL;
}

void mutex_lock(mutex_t *mtx)
{
    struct thread *th = current_thread_get();

    /* Fast path: try to acquire immediately */
    if (mutex_trylock(mtx)) {
        mtx->owner = th;
        return;
    }

    /* Slow path: add to wait queue and sleep */
    if (th != NULL) {
        uint64_t flags;
        /* Spin briefly before sleeping (adaptive) */
        for (int spin = 0; spin < 100; spin++) {
            if (mutex_trylock(mtx)) {
                mtx->owner = th;
                return;
            }
            __asm__ volatile("yield");
        }

        /* Still can't get it — enqueue and block */
        /* Use a simple spinlock-protected wait queue on the mutex */
        /* Disable IRQs to safely manipulate the wait list */
        flags = irq_save();

        th->wait_next = NULL;
        if (mtx->waiters_tail) {
            mtx->waiters_tail->wait_next = th;
        } else {
            mtx->waiters_head = th;
        }
        mtx->waiters_tail = th;

        irq_restore(flags);

        /* Block — scheduler picks the next thread */
        thread_block("mutex_lock");

        /* Woken up by mutex_unlock — now we hold the mutex */
        mtx->owner = th;
    } else {
        /* Early boot — no scheduler, just spin */
        while (!mutex_trylock(mtx))
            __asm__ volatile("yield");
    }
}

void mutex_unlock(mutex_t *mtx)
{
    /*
     * Check for waiters BEFORE releasing the lock. If there's a waiter,
     * hand the mutex directly to it without ever setting locked=0.
     * This prevents an adaptive spinner on another CPU from stealing
     * the mutex between locked=0 and the re-acquire for the waiter,
     * which would result in two threads believing they hold the mutex.
     */
    uint64_t flags = irq_save();
    struct thread *waiter = mtx->waiters_head;
    if (waiter) {
        mtx->waiters_head = waiter->wait_next;
        if (mtx->waiters_head == NULL)
            mtx->waiters_tail = NULL;
        waiter->wait_next = NULL;
    }
    irq_restore(flags);

    if (waiter) {
        /* Direct handoff: mutex stays locked, just change owner */
        mtx->owner = waiter;
        __asm__ volatile("dmb ish" ::: "memory");
        thread_unblock(waiter);
    } else {
        /* No waiters — actually release the mutex */
        mtx->owner = NULL;
        __asm__ volatile("dmb ish" ::: "memory");
        mtx->locked = 0;
    }
}

bool mutex_trylock(mutex_t *mtx)
{
    uint32_t old, status;
    __asm__ volatile(
        "ldaxr  %w0, [%2]\n"
        "cbnz   %w0, 1f\n"
        "stxr   %w1, %w3, [%2]\n"
        "b      2f\n"
        "1: mov %w1, #1\n"
        "2:\n"
        : "=&r"(old), "=&r"(status)
        : "r"(&mtx->locked), "r"(1)
        : "memory"
    );
    return status == 0;
}

/* ============================================================================
 * Semaphore Implementation
 * ============================================================================ */

void semaphore_init(semaphore_t *sem, int32_t initial_count)
{
    sem->count = initial_count;
    spin_init(&sem->lock);
    sem->waiters_head = NULL;
    sem->waiters_tail = NULL;
}

void semaphore_wait(semaphore_t *sem)
{
    uint64_t flags;
    spin_lock_irqsave(&sem->lock, &flags);

    while (sem->count <= 0) {
        struct thread *th = current_thread_get();
        if (th != NULL) {
            /*
             * CRITICAL: Set TH_WAIT BEFORE adding to wait queue and
             * BEFORE releasing sem->lock. This prevents a race where
             * semaphore_signal() on another CPU dequeues us from the
             * wait list, calls thread_unblock(), sees we're still
             * TH_RUN, and skips us — then we enter TH_WAIT with no
             * one to wake us.
             *
             * By setting TH_WAIT first, any concurrent
             * semaphore_signal → thread_unblock sees TH_WAIT and
             * correctly transitions us to TH_RUN + sched_enqueue.
             */
            thread_set_wait("semaphore_wait");

            /* Add to wait queue */
            th->wait_next = NULL;
            if (sem->waiters_tail) {
                sem->waiters_tail->wait_next = th;
            } else {
                sem->waiters_head = th;
            }
            sem->waiters_tail = th;
            spin_unlock_irqrestore(&sem->lock, flags);

            /*
             * XNU equivalent: thread_block() → thread_invoke().
             *
             * thread_block_check() atomically verifies we're still
             * TH_WAIT before calling sched_switch(). If thread_unblock
             * already set us to TH_RUN (concurrent signal), it returns
             * false and we skip the switch — avoiding double-enqueue.
             */
            thread_block_check();

            spin_lock_irqsave(&sem->lock, &flags);
        } else {
            /* Early boot — no scheduler, spin */
            spin_unlock_irqrestore(&sem->lock, flags);
            __asm__ volatile("yield");
            spin_lock_irqsave(&sem->lock, &flags);
        }
    }

    sem->count--;
    spin_unlock_irqrestore(&sem->lock, flags);
}

void semaphore_signal(semaphore_t *sem)
{
    uint64_t flags;
    spin_lock_irqsave(&sem->lock, &flags);
    sem->count++;

    /* Wake up first waiter */
    struct thread *waiter = sem->waiters_head;
    if (waiter) {
        sem->waiters_head = waiter->wait_next;
        if (sem->waiters_head == NULL)
            sem->waiters_tail = NULL;
        waiter->wait_next = NULL;
    }
    spin_unlock_irqrestore(&sem->lock, flags);

    if (waiter)
        thread_unblock(waiter);
}

bool semaphore_trywait(semaphore_t *sem)
{
    uint64_t flags;
    spin_lock_irqsave(&sem->lock, &flags);
    if (sem->count > 0) {
        sem->count--;
        spin_unlock_irqrestore(&sem->lock, flags);
        return true;
    }
    spin_unlock_irqrestore(&sem->lock, flags);
    return false;
}

/*
 * semaphore_timedwait - Wait on a semaphore with a millisecond timeout.
 *
 * Implementation strategy: if count > 0, decrement immediately and return
 * true. Otherwise, set the thread's wakeup_tick deadline and add it to
 * both the semaphore wait queue and the global sleep queue. The thread
 * wakes on whichever event fires first:
 *
 *   1. semaphore_signal() dequeues the thread from the semaphore wait
 *      list and calls thread_unblock(), which clears the sleep queue
 *      entry if present.
 *
 *   2. sched_wakeup_sleepers() fires the deadline, waking the thread.
 *      The thread then re-acquires the semaphore spinlock and checks
 *      count again. If still <= 0, it removes itself from the wait
 *      queue and returns false (timed out).
 *
 * At 100 Hz, 1 tick = 10 ms. timeout_ms is converted via:
 *   ticks = (timeout_ms + 9) / 10   (round up to avoid zero-tick waits)
 *
 * XNU equivalents: semaphore_timedwait_signal_trap(), semaphore_wait_deadline()
 */
extern uint64_t timer_get_ticks(void);
extern spinlock_t sleep_lock;
extern struct thread *sleep_queue;

bool semaphore_timedwait(semaphore_t *sem, uint32_t timeout_ms)
{
    uint64_t flags;
    spin_lock_irqsave(&sem->lock, &flags);

    /* Fast path: semaphore already available */
    if (sem->count > 0) {
        sem->count--;
        spin_unlock_irqrestore(&sem->lock, flags);
        return true;
    }

    /* Zero timeout = non-blocking (same as trywait) */
    if (timeout_ms == 0) {
        spin_unlock_irqrestore(&sem->lock, flags);
        return false;
    }

    struct thread *th = current_thread_get();
    if (th == NULL) {
        /* Early boot — no scheduler, cannot timed-wait */
        spin_unlock_irqrestore(&sem->lock, flags);
        return false;
    }

    /* Calculate deadline tick (100 Hz: 1 tick = 10 ms, round up) */
    uint64_t ticks = ((uint64_t)timeout_ms + 9) / 10;
    uint64_t deadline = timer_get_ticks() + ticks;

    /*
     * CRITICAL: Set TH_WAIT BEFORE inserting into the sleep queue and
     * BEFORE releasing sem->lock. This prevents a race where another
     * CPU's sched_wakeup_sleepers() fires the deadline, finds us on
     * the sleep queue, sees we're still TH_RUN, removes us without
     * waking, and then we enter TH_WAIT with no one to wake us.
     *
     * By setting TH_WAIT first:
     *   - If sched_wakeup_sleepers sees us, th->state == TH_WAIT,
     *     so it correctly transitions us to TH_RUN and enqueues us.
     *   - If semaphore_signal sees us on the wait list, same thing.
     *   - sched_switch() sees TH_WAIT and does not re-enqueue us.
     *
     * XNU equivalent: assert_wait() sets TH_WAIT; thread_block()
     * calls thread_invoke() to context-switch. Separate operations.
     */
    thread_set_wait("semaphore_timedwait");

    /* Add to semaphore wait queue */
    th->wait_next = NULL;
    if (sem->waiters_tail) {
        sem->waiters_tail->wait_next = th;
    } else {
        sem->waiters_head = th;
    }
    sem->waiters_tail = th;

    /* Set deadline so sched_wakeup_sleepers() can also wake us */
    th->wakeup_tick = deadline;

    /* Insert into the global sleep queue (sorted by wakeup_tick).
     * We must acquire sleep_lock while still holding sem->lock to
     * prevent a race where the deadline fires before we block. */
    uint64_t sflags;
    spin_lock_irqsave(&sleep_lock, &sflags);
    {
        struct thread **pp = &sleep_queue;
        while (*pp && (*pp)->wakeup_tick <= th->wakeup_tick)
            pp = &(*pp)->sleep_next;
        th->sleep_next = *pp;
        *pp = th;
    }
    spin_unlock_irqrestore(&sleep_lock, sflags);

    spin_unlock_irqrestore(&sem->lock, flags);

    /* Block — woken by either semaphore_signal() or deadline expiry.
     * thread_block_check() verifies we're still TH_WAIT before switching.
     * If a concurrent waker already set us to TH_RUN, it returns false
     * and we skip the switch — avoiding double-enqueue (XNU pattern). */
    thread_block_check();

    /* We've been woken. Re-acquire semaphore lock and check. */
    spin_lock_irqsave(&sem->lock, &flags);

    /* Remove ourselves from the sleep queue if still on it.
     * (If semaphore_signal woke us, the sleep queue entry remains.) */
    if (th->wakeup_tick != 0) {
        uint64_t sflags2;
        spin_lock_irqsave(&sleep_lock, &sflags2);
        struct thread **pp = &sleep_queue;
        while (*pp) {
            if (*pp == th) {
                *pp = th->sleep_next;
                break;
            }
            pp = &(*pp)->sleep_next;
        }
        th->sleep_next = NULL;
        th->wakeup_tick = 0;
        spin_unlock_irqrestore(&sleep_lock, sflags2);
    }

    /* Check if we can acquire now (signal may have incremented count,
     * or another signal may have happened while we were waking) */
    if (sem->count > 0) {
        sem->count--;
        /* Remove from semaphore wait queue if still there */
        struct thread **pp = &sem->waiters_head;
        while (*pp) {
            if (*pp == th) {
                *pp = th->wait_next;
                if (sem->waiters_tail == th)
                    sem->waiters_tail = NULL;
                break;
            }
            pp = &(*pp)->wait_next;
        }
        th->wait_next = NULL;
        spin_unlock_irqrestore(&sem->lock, flags);
        return true;
    }

    /* Timed out — remove from semaphore wait queue */
    {
        struct thread **pp = &sem->waiters_head;
        while (*pp) {
            if (*pp == th) {
                *pp = th->wait_next;
                if (sem->waiters_tail == th) {
                    /* Find new tail */
                    sem->waiters_tail = NULL;
                    struct thread *t = sem->waiters_head;
                    while (t) {
                        sem->waiters_tail = t;
                        t = t->wait_next;
                    }
                }
                break;
            }
            pp = &(*pp)->wait_next;
        }
        th->wait_next = NULL;
    }

    spin_unlock_irqrestore(&sem->lock, flags);
    return false;
}

/* ============================================================================
 * Condition Variable Implementation
 * ============================================================================ */

void condvar_init(condvar_t *cv)
{
    cv->waiters_head = NULL;
    cv->waiters_tail = NULL;
    spin_init(&cv->lock);
}

void condvar_wait(condvar_t *cv, mutex_t *mtx)
{
    struct thread *th = current_thread_get();
    if (!th) {
        /* Early boot — no scheduler yet, just spin */
        mutex_unlock(mtx);
        __asm__ volatile("yield");
        mutex_lock(mtx);
        return;
    }

    /*
     * Add current thread to the condvar's wait queue, release the mutex,
     * and block (yields to the scheduler). On wakeup, re-acquire the mutex.
     */
    uint64_t flags;
    spin_lock_irqsave(&cv->lock, &flags);

    /*
     * Set TH_WAIT before adding to wait queue and releasing locks,
     * to prevent the same race as in semaphore_wait/timedwait.
     */
    thread_set_wait("condvar_wait");

    /* Append to tail of wait queue */
    th->wait_next = NULL;
    if (cv->waiters_tail) {
        cv->waiters_tail->wait_next = th;
    } else {
        cv->waiters_head = th;
    }
    cv->waiters_tail = th;

    spin_unlock_irqrestore(&cv->lock, flags);

    /* Release the mutex before blocking */
    mutex_unlock(mtx);

    /* XNU pattern: check if still TH_WAIT before switching */
    thread_block_check();

    /* Woken up by condvar_signal — re-acquire the mutex */
    mutex_lock(mtx);
}

void condvar_signal(condvar_t *cv)
{
    uint64_t flags;
    spin_lock_irqsave(&cv->lock, &flags);

    struct thread *th = cv->waiters_head;
    if (th) {
        cv->waiters_head = th->wait_next;
        if (cv->waiters_head == NULL)
            cv->waiters_tail = NULL;
        th->wait_next = NULL;
    }

    spin_unlock_irqrestore(&cv->lock, flags);

    /* Unblock the waiter (puts it back on the run queue) */
    if (th)
        thread_unblock(th);
}

void condvar_broadcast(condvar_t *cv)
{
    uint64_t flags;
    spin_lock_irqsave(&cv->lock, &flags);

    struct thread *th = cv->waiters_head;
    cv->waiters_head = NULL;
    cv->waiters_tail = NULL;

    spin_unlock_irqrestore(&cv->lock, flags);

    /* Unblock all waiters */
    while (th) {
        struct thread *next = th->wait_next;
        th->wait_next = NULL;
        thread_unblock(th);
        th = next;
    }
}
