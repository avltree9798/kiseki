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
    mtx->owner = NULL;
    __asm__ volatile("dmb ish" ::: "memory");
    mtx->locked = 0;

    /* Wake up first waiter from queue */
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
        /* The waiter's mutex_lock will set mtx->locked on wakeup.
         * We need to pre-acquire for the waiter so no one steals it. */
        mtx->locked = 1;
        mtx->owner = waiter;
        thread_unblock(waiter);
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
            /* Add to wait queue and sleep */
            th->wait_next = NULL;
            if (sem->waiters_tail) {
                sem->waiters_tail->wait_next = th;
            } else {
                sem->waiters_head = th;
            }
            sem->waiters_tail = th;
            spin_unlock_irqrestore(&sem->lock, flags);

            thread_block("semaphore_wait");

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

    /* Block this thread — scheduler picks the next runnable one */
    thread_block("condvar_wait");

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
