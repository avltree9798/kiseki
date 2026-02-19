/*
 * Kiseki OS - Synchronization Primitives
 *
 * XNU-compatible locking: spinlocks, mutexes, semaphores, condition variables.
 *
 * Spinlocks:   For short critical sections (IRQs disabled while held)
 * Mutexes:     For long critical sections (can sleep, priority inheritance)
 * Semaphores:  Counting semaphores (mapped to Mach semaphore traps)
 * CondVars:    Wait queues for event-based sleeping
 */

#ifndef _KERN_SYNC_H
#define _KERN_SYNC_H

#include <kiseki/types.h>

/* ============================================================================
 * Spinlock (hw_lock) - Non-sleeping, IRQ-disabling
 * ============================================================================ */

typedef struct {
    volatile uint32_t locked;
    uint32_t _pad;
} spinlock_t;

#define SPINLOCK_INIT { .locked = 0 }

void spin_init(spinlock_t *lock);
void spin_lock(spinlock_t *lock);
void spin_unlock(spinlock_t *lock);
bool spin_trylock(spinlock_t *lock);

/* Lock with IRQ save/restore */
void spin_lock_irqsave(spinlock_t *lock, uint64_t *flags);
void spin_unlock_irqrestore(spinlock_t *lock, uint64_t flags);

/* ============================================================================
 * Mutex (lck_mtx) - Sleeping lock with priority inheritance
 * ============================================================================ */

struct thread;  /* Forward declaration */

typedef struct {
    volatile uint32_t locked;
    volatile uint32_t _pad;
    struct thread *owner;           /* Current owner (for priority inheritance) */
    struct thread *waiters_head;    /* Queue of threads waiting */
    struct thread *waiters_tail;
} mutex_t;

#define MUTEX_INIT { .locked = 0, .owner = NULL, .waiters_head = NULL, .waiters_tail = NULL }

void mutex_init(mutex_t *mtx);
void mutex_lock(mutex_t *mtx);
void mutex_unlock(mutex_t *mtx);
bool mutex_trylock(mutex_t *mtx);

/* ============================================================================
 * Semaphore - Counting semaphore (Mach compatible)
 * ============================================================================ */

typedef struct {
    volatile int32_t count;
    uint32_t _pad;
    spinlock_t lock;
    struct thread *waiters_head;
    struct thread *waiters_tail;
} semaphore_t;

void semaphore_init(semaphore_t *sem, int32_t initial_count);
void semaphore_wait(semaphore_t *sem);
void semaphore_signal(semaphore_t *sem);
bool semaphore_trywait(semaphore_t *sem);

/* ============================================================================
 * Condition Variable - Event-based wait queues
 * ============================================================================ */

typedef struct {
    struct thread *waiters_head;
    struct thread *waiters_tail;
    spinlock_t lock;
} condvar_t;

void condvar_init(condvar_t *cv);
void condvar_wait(condvar_t *cv, mutex_t *mtx);
void condvar_signal(condvar_t *cv);
void condvar_broadcast(condvar_t *cv);

#endif /* _KERN_SYNC_H */
