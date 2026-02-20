/*
 * Kiseki OS - Assertions
 */

#ifndef _LIBSYSTEM_ASSERT_H
#define _LIBSYSTEM_ASSERT_H

/* Assertion failure handler (provided by libc) */
void __assert_fail(const char *expr, const char *file, int line, const char *func)
    __attribute__((noreturn));

#ifdef NDEBUG
#define assert(expr) ((void)0)
#else
#define assert(expr) \
    ((expr) ? (void)0 : __assert_fail(#expr, __FILE__, __LINE__, __func__))
#endif

/* Static assertion (C11) */
#define static_assert _Static_assert

#endif /* _LIBSYSTEM_ASSERT_H */
