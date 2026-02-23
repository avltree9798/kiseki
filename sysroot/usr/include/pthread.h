/*
 * Kiseki OS - POSIX Threads (pthread)
 *
 * Basic pthread implementation for macOS compatibility.
 * Uses bsdthread_create/bsdthread_terminate syscalls.
 */

#ifndef _LIBSYSTEM_PTHREAD_H
#define _LIBSYSTEM_PTHREAD_H

#include <types.h>
#include <time.h>

/* ============================================================================
 * Thread Types
 * ============================================================================ */

typedef unsigned long pthread_t;
typedef unsigned long pthread_attr_t;

/* ============================================================================
 * Mutex Types
 * ============================================================================ */

#define PTHREAD_MUTEX_NORMAL        0
#define PTHREAD_MUTEX_ERRORCHECK    1
#define PTHREAD_MUTEX_RECURSIVE     2
#define PTHREAD_MUTEX_DEFAULT       PTHREAD_MUTEX_NORMAL

typedef struct {
    int             type;
    int             locked;
    pthread_t       owner;
    int             recursion;
    volatile int    spinlock;
} pthread_mutex_t;

typedef struct {
    int type;
} pthread_mutexattr_t;

#define PTHREAD_MUTEX_INITIALIZER { PTHREAD_MUTEX_DEFAULT, 0, 0, 0, 0 }

/* ============================================================================
 * Condition Variable Types
 * ============================================================================ */

typedef struct {
    volatile int    waiters;
    volatile int    signal_count;
    pthread_mutex_t *mutex;
} pthread_cond_t;

typedef struct {
    int pshared;
} pthread_condattr_t;

#define PTHREAD_COND_INITIALIZER { 0, 0, NULL }

/* ============================================================================
 * Read-Write Lock Types
 * ============================================================================ */

typedef struct {
    volatile int    readers;
    volatile int    writer;
    volatile int    writer_waiting;
    pthread_t       writer_tid;
    volatile int    spinlock;
} pthread_rwlock_t;

typedef struct {
    int pshared;
} pthread_rwlockattr_t;

#define PTHREAD_RWLOCK_INITIALIZER { 0, 0, 0, 0, 0 }

/* ============================================================================
 * Thread-Specific Data (TLS)
 * ============================================================================ */

typedef unsigned int pthread_key_t;

#define PTHREAD_KEYS_MAX 128

/* ============================================================================
 * Once Control
 * ============================================================================ */

typedef struct {
    volatile int done;
    volatile int in_progress;
} pthread_once_t;

#define PTHREAD_ONCE_INIT { 0, 0 }

/* ============================================================================
 * Barrier Types
 * ============================================================================ */

typedef struct {
    unsigned int    count;
    unsigned int    current;
    unsigned int    cycle;
    pthread_mutex_t mutex;
    pthread_cond_t  cond;
} pthread_barrier_t;

typedef struct {
    int pshared;
} pthread_barrierattr_t;

#define PTHREAD_BARRIER_SERIAL_THREAD (-1)

/* ============================================================================
 * Spinlock Types
 * ============================================================================ */

typedef volatile int pthread_spinlock_t;

/* ============================================================================
 * Detach State
 * ============================================================================ */

#define PTHREAD_CREATE_JOINABLE     0
#define PTHREAD_CREATE_DETACHED     1

/* ============================================================================
 * Scope
 * ============================================================================ */

#define PTHREAD_SCOPE_SYSTEM        0
#define PTHREAD_SCOPE_PROCESS       1

/* ============================================================================
 * Cancel State/Type
 * ============================================================================ */

#define PTHREAD_CANCEL_ENABLE       0
#define PTHREAD_CANCEL_DISABLE      1
#define PTHREAD_CANCEL_DEFERRED     0
#define PTHREAD_CANCEL_ASYNCHRONOUS 1
#define PTHREAD_CANCELED            ((void *)-1)

/* ============================================================================
 * Process Shared
 * ============================================================================ */

#define PTHREAD_PROCESS_PRIVATE     0
#define PTHREAD_PROCESS_SHARED      1

/* ============================================================================
 * Thread Functions
 * ============================================================================ */

/* Thread creation and termination */
int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                   void *(*start_routine)(void *), void *arg);
void pthread_exit(void *retval) __attribute__((noreturn));
int pthread_join(pthread_t thread, void **retval);
int pthread_detach(pthread_t thread);
int pthread_cancel(pthread_t thread);

/* Thread identification */
pthread_t pthread_self(void);
int pthread_equal(pthread_t t1, pthread_t t2);

/* Thread attributes */
int pthread_attr_init(pthread_attr_t *attr);
int pthread_attr_destroy(pthread_attr_t *attr);
int pthread_attr_setdetachstate(pthread_attr_t *attr, int detachstate);
int pthread_attr_getdetachstate(const pthread_attr_t *attr, int *detachstate);
int pthread_attr_setstacksize(pthread_attr_t *attr, size_t stacksize);
int pthread_attr_getstacksize(const pthread_attr_t *attr, size_t *stacksize);
int pthread_attr_setstack(pthread_attr_t *attr, void *stackaddr, size_t stacksize);
int pthread_attr_getstack(const pthread_attr_t *attr, void **stackaddr, size_t *stacksize);

/* Cancel state */
int pthread_setcancelstate(int state, int *oldstate);
int pthread_setcanceltype(int type, int *oldtype);
void pthread_testcancel(void);

/* Scheduling */
int pthread_setschedparam(pthread_t thread, int policy,
                          const struct sched_param *param);
int pthread_getschedparam(pthread_t thread, int *policy,
                          struct sched_param *param);
int pthread_yield(void);

/* ============================================================================
 * Mutex Functions
 * ============================================================================ */

int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr);
int pthread_mutex_destroy(pthread_mutex_t *mutex);
int pthread_mutex_lock(pthread_mutex_t *mutex);
int pthread_mutex_trylock(pthread_mutex_t *mutex);
int pthread_mutex_unlock(pthread_mutex_t *mutex);
int pthread_mutex_timedlock(pthread_mutex_t *mutex, const struct timespec *abstime);

/* Mutex attributes */
int pthread_mutexattr_init(pthread_mutexattr_t *attr);
int pthread_mutexattr_destroy(pthread_mutexattr_t *attr);
int pthread_mutexattr_settype(pthread_mutexattr_t *attr, int type);
int pthread_mutexattr_gettype(const pthread_mutexattr_t *attr, int *type);
int pthread_mutexattr_setpshared(pthread_mutexattr_t *attr, int pshared);
int pthread_mutexattr_getpshared(const pthread_mutexattr_t *attr, int *pshared);

/* ============================================================================
 * Condition Variable Functions
 * ============================================================================ */

int pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr);
int pthread_cond_destroy(pthread_cond_t *cond);
int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);
int pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex,
                           const struct timespec *abstime);
int pthread_cond_signal(pthread_cond_t *cond);
int pthread_cond_broadcast(pthread_cond_t *cond);

/* Condition variable attributes */
int pthread_condattr_init(pthread_condattr_t *attr);
int pthread_condattr_destroy(pthread_condattr_t *attr);
int pthread_condattr_setpshared(pthread_condattr_t *attr, int pshared);
int pthread_condattr_getpshared(const pthread_condattr_t *attr, int *pshared);

/* ============================================================================
 * Read-Write Lock Functions
 * ============================================================================ */

int pthread_rwlock_init(pthread_rwlock_t *rwlock, const pthread_rwlockattr_t *attr);
int pthread_rwlock_destroy(pthread_rwlock_t *rwlock);
int pthread_rwlock_rdlock(pthread_rwlock_t *rwlock);
int pthread_rwlock_tryrdlock(pthread_rwlock_t *rwlock);
int pthread_rwlock_wrlock(pthread_rwlock_t *rwlock);
int pthread_rwlock_trywrlock(pthread_rwlock_t *rwlock);
int pthread_rwlock_unlock(pthread_rwlock_t *rwlock);
int pthread_rwlock_timedrdlock(pthread_rwlock_t *rwlock, const struct timespec *abstime);
int pthread_rwlock_timedwrlock(pthread_rwlock_t *rwlock, const struct timespec *abstime);

/* Read-write lock attributes */
int pthread_rwlockattr_init(pthread_rwlockattr_t *attr);
int pthread_rwlockattr_destroy(pthread_rwlockattr_t *attr);
int pthread_rwlockattr_setpshared(pthread_rwlockattr_t *attr, int pshared);
int pthread_rwlockattr_getpshared(const pthread_rwlockattr_t *attr, int *pshared);

/* ============================================================================
 * Thread-Specific Data Functions
 * ============================================================================ */

int pthread_key_create(pthread_key_t *key, void (*destructor)(void *));
int pthread_key_delete(pthread_key_t key);
void *pthread_getspecific(pthread_key_t key);
int pthread_setspecific(pthread_key_t key, const void *value);

/* ============================================================================
 * Once Functions
 * ============================================================================ */

int pthread_once(pthread_once_t *once_control, void (*init_routine)(void));

/* ============================================================================
 * Barrier Functions
 * ============================================================================ */

int pthread_barrier_init(pthread_barrier_t *barrier,
                         const pthread_barrierattr_t *attr, unsigned int count);
int pthread_barrier_destroy(pthread_barrier_t *barrier);
int pthread_barrier_wait(pthread_barrier_t *barrier);

/* Barrier attributes */
int pthread_barrierattr_init(pthread_barrierattr_t *attr);
int pthread_barrierattr_destroy(pthread_barrierattr_t *attr);
int pthread_barrierattr_setpshared(pthread_barrierattr_t *attr, int pshared);
int pthread_barrierattr_getpshared(const pthread_barrierattr_t *attr, int *pshared);

/* ============================================================================
 * Spinlock Functions
 * ============================================================================ */

int pthread_spin_init(pthread_spinlock_t *lock, int pshared);
int pthread_spin_destroy(pthread_spinlock_t *lock);
int pthread_spin_lock(pthread_spinlock_t *lock);
int pthread_spin_trylock(pthread_spinlock_t *lock);
int pthread_spin_unlock(pthread_spinlock_t *lock);

/* ============================================================================
 * Scheduling Parameter
 * ============================================================================ */

struct sched_param {
    int sched_priority;
};

#define SCHED_OTHER     0
#define SCHED_FIFO      1
#define SCHED_RR        2

/* ============================================================================
 * Cleanup Handlers
 * ============================================================================ */

void pthread_cleanup_push(void (*routine)(void *), void *arg);
void pthread_cleanup_pop(int execute);

/* ============================================================================
 * Non-portable Extensions
 * ============================================================================ */

/* Get/set thread name (macOS/BSD extension) */
int pthread_setname_np(const char *name);
int pthread_getname_np(pthread_t thread, char *name, size_t len);

/* macOS-specific thread ID */
int pthread_threadid_np(pthread_t thread, uint64_t *thread_id);

/* Get stack address and size of current thread */
void *pthread_get_stackaddr_np(pthread_t thread);
size_t pthread_get_stacksize_np(pthread_t thread);

#endif /* _LIBSYSTEM_PTHREAD_H */
