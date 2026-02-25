/*
 * Kiseki OS - Userland Type Definitions
 *
 * Freestanding types for userspace. Mirrors kernel types.h
 * but without kernel-internal definitions.
 */

#ifndef _LIBSYSTEM_TYPES_H
#define _LIBSYSTEM_TYPES_H

/* --- Fixed-width integer types ---
 * AArch64 LP64: char=1, short=2, int=4, long=8, pointer=8
 */
typedef unsigned char       uint8_t;
typedef unsigned short      uint16_t;
typedef unsigned int        uint32_t;
typedef unsigned long       uint64_t;

typedef signed char         int8_t;
typedef signed short        int16_t;
typedef signed int          int32_t;
typedef signed long         int64_t;

/* --- Size types --- */
#ifndef _LIBSYSTEM_SIZE_T_DEFINED
#define _LIBSYSTEM_SIZE_T_DEFINED
typedef uint64_t            size_t;
#endif
typedef int64_t             ssize_t;
typedef uint64_t            uintptr_t;
typedef int64_t             intptr_t;
#ifndef _LIBSYSTEM_PTRDIFF_T_DEFINED
#define _LIBSYSTEM_PTRDIFF_T_DEFINED
typedef int64_t             ptrdiff_t;
#endif
typedef int64_t             off_t;

/* --- Boolean --- */
#ifndef __bool_true_false_are_defined
#ifdef __TINYC__
/* TCC doesn't have _Bool, use int */
typedef int                 bool;
#else
typedef _Bool               bool;
#endif
#define true                1
#define false               0
#define __bool_true_false_are_defined 1
#endif

/* --- NULL --- */
#ifndef NULL
#define NULL                ((void *)0)
#endif

/* --- POSIX types --- */
typedef int32_t             pid_t;
typedef uint32_t            uid_t;
typedef uint32_t            gid_t;
typedef uint16_t            mode_t;     /* Darwin: __uint16_t */
typedef int32_t             dev_t;      /* Darwin: __int32_t */
typedef uint64_t            ino_t;      /* Darwin 64-bit: __darwin_ino64_t */
typedef uint16_t            nlink_t;    /* Darwin: __uint16_t */
typedef int64_t             blkcnt_t;
typedef int32_t             blksize_t;  /* Darwin: __int32_t */
typedef int64_t             time_t;

/* --- Time types --- */
struct timespec {
    time_t      tv_sec;         /* Seconds */
    long        tv_nsec;        /* Nanoseconds */
};

typedef int32_t             suseconds_t;    /* Darwin: __int32_t (NOT int64_t!) */
typedef uint32_t            useconds_t;
typedef uint32_t            id_t;

/* --- Variadic arguments --- */
#include <stdarg.h>

/* --- Limits (guarded to avoid redefinition with <limits.h>) --- */
#ifndef INT_MAX
#define INT_MAX             0x7fffffff
#endif
#ifndef INT_MIN
#define INT_MIN             (-INT_MAX - 1)
#endif
#ifndef UINT_MAX
#define UINT_MAX            0xffffffffU
#endif
#ifndef LONG_MAX
#define LONG_MAX            0x7fffffffffffffffL
#endif
#ifndef LONG_MIN
#define LONG_MIN            (-LONG_MAX - 1L)
#endif
#ifndef ULONG_MAX
#define ULONG_MAX           0xffffffffffffffffUL
#endif
#ifndef LLONG_MAX
#define LLONG_MAX           0x7fffffffffffffffLL
#endif
#ifndef LLONG_MIN
#define LLONG_MIN           (-LLONG_MAX - 1LL)
#endif
#ifndef ULLONG_MAX
#define ULLONG_MAX          0xffffffffffffffffULL
#endif
#ifndef CHAR_BIT
#define CHAR_BIT            8
#endif
#ifndef PATH_MAX
#define PATH_MAX            1024
#endif
#ifndef NAME_MAX
#define NAME_MAX            255
#endif

/* --- Convenience --- */
#ifndef offsetof
#define offsetof(type, member)  __builtin_offsetof(type, member)
#endif

#endif /* _LIBSYSTEM_TYPES_H */
