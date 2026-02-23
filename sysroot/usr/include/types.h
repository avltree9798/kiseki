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
typedef uint64_t            size_t;
typedef int64_t             ssize_t;
typedef uint64_t            uintptr_t;
typedef int64_t             intptr_t;
typedef int64_t             ptrdiff_t;
typedef int64_t             off_t;

/* --- Boolean --- */
#ifdef __TINYC__
/* TCC doesn't have _Bool, use int */
typedef int                 bool;
#else
typedef _Bool               bool;
#endif
#define true                1
#define false               0

/* --- NULL --- */
#define NULL                ((void *)0)

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

/* --- Limits --- */
#define INT_MAX             0x7fffffff
#define INT_MIN             (-INT_MAX - 1)
#define UINT_MAX            0xffffffffU
#define LONG_MAX            0x7fffffffffffffffL
#define LONG_MIN            (-LONG_MAX - 1L)
#define ULONG_MAX           0xffffffffffffffffUL
#define LLONG_MAX           0x7fffffffffffffffLL
#define LLONG_MIN           (-LLONG_MAX - 1LL)
#define ULLONG_MAX          0xffffffffffffffffULL
#define CHAR_BIT            8
#define PATH_MAX            1024
#define NAME_MAX            255

/* --- Convenience --- */
#define offsetof(type, member)  __builtin_offsetof(type, member)

#endif /* _LIBSYSTEM_TYPES_H */
