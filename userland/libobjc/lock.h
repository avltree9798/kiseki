/**
 * libobjc requires recursive mutexes.  These are delegated to the underlying
 * threading implementation.  This file contains a VERY thin wrapper over the
 * Windows and POSIX mutex APIs.
 */

#ifndef __LIBOBJC_LOCK_H_INCLUDED__
#define __LIBOBJC_LOCK_H_INCLUDED__
#ifdef _WIN32
#	include "safewindows.h"
typedef CRITICAL_SECTION mutex_t;
#	define INIT_LOCK(x) InitializeCriticalSection(&(x))
#	define LOCK(x) EnterCriticalSection(x)
#	define UNLOCK(x) LeaveCriticalSection(x)
#	define DESTROY_LOCK(x) DeleteCriticalSection(x)
#else

#	include <pthread.h>

typedef pthread_mutex_t mutex_t;
// Always use the portable init_recursive_mutex() path.
// We CANNOT use static initialisers like PTHREAD_RECURSIVE_MUTEX_INITIALIZER
// because libobjc's C++ files are compiled against macOS SDK headers (where
// pthread_mutex_t is 64 bytes and the static initialiser writes a magic sig
// 0x32AAABA2), but at runtime we link against Kiseki's libSystem where
// pthread_mutex_t is 24 bytes with type==2 for recursive.  The ABI mismatch
// causes the recursive-ownership check in pthread_mutex_lock to fail,
// leading to deadlock on the second recursive acquisition.
#		define INIT_LOCK(x) init_recursive_mutex(&(x))

static inline void init_recursive_mutex(pthread_mutex_t *x)
{
	pthread_mutexattr_t recursiveAttributes;
	pthread_mutexattr_init(&recursiveAttributes);
	pthread_mutexattr_settype(&recursiveAttributes, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(x, &recursiveAttributes);
	pthread_mutexattr_destroy(&recursiveAttributes);
}

#	define LOCK(x) pthread_mutex_lock(x)
#	define UNLOCK(x) pthread_mutex_unlock(x)
#	define DESTROY_LOCK(x) pthread_mutex_destroy(x)
#endif

__attribute__((unused)) static void objc_release_lock(void *x)
{
	mutex_t *lock = *(mutex_t**)x;
	UNLOCK(lock);
}
/**
 * Concatenate strings during macro expansion.
 */
#define LOCK_HOLDERN_NAME_CAT(x, y) x ## y
/**
 * Concatenate string with unique variable during macro expansion.
 */
#define LOCK_HOLDER_NAME_COUNTER(x, y) LOCK_HOLDERN_NAME_CAT(x, y)
/**
 * Create a unique name for a lock holder variable
 */
#define LOCK_HOLDER_NAME(x) LOCK_HOLDER_NAME_COUNTER(x, __COUNTER__)

/**
 * Acquires the lock and automatically releases it at the end of the current
 * scope.
 */
#define LOCK_FOR_SCOPE(lock) \
	__attribute__((cleanup(objc_release_lock)))\
	__attribute__((unused)) mutex_t *LOCK_HOLDER_NAME(lock_pointer) = lock;\
	LOCK(lock)

/**
 * The global runtime mutex.
 */
extern mutex_t runtime_mutex;

#define LOCK_RUNTIME() LOCK(&runtime_mutex)
#define UNLOCK_RUNTIME() UNLOCK(&runtime_mutex)
#define LOCK_RUNTIME_FOR_SCOPE() LOCK_FOR_SCOPE(&runtime_mutex)

#ifdef __cplusplus
/**
 * C++ wrapper around our mutex, for use with std::lock_guard and friends.
 */
class RecursiveMutex
{
	/// The underlying mutex
	mutex_t mutex;

	public:
	/**
	 * Explicit initialisation of the underlying lock, so that this can be a
	 * global.
	 */
	void init()
	{
		INIT_LOCK(mutex);
	}

	/// Acquire the lock.
	void lock()
	{
		LOCK(&mutex);
	}

	/// Release the lock.
	void unlock()
	{
		UNLOCK(&mutex);
	}
};
#endif

#endif // __LIBOBJC_LOCK_H_INCLUDED__
