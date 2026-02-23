/*
 * Kiseki OS - Fundamental Type Definitions
 *
 * Freestanding types for the kernel. No libc dependency.
 */

#ifndef _KISEKI_TYPES_H
#define _KISEKI_TYPES_H

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
typedef _Bool               bool;
#define true                1
#define false               0

/* --- NULL --- */
#define NULL                ((void *)0)

/* --- Darwin-compatible types (must match real macOS arm64 ABI) --- */
typedef uint32_t            uid_t;
typedef uint32_t            gid_t;
typedef int32_t             pid_t;
typedef int32_t             dev_t;      /* Darwin: __int32_t */
typedef uint64_t            ino_t;      /* Darwin 64-bit: __darwin_ino64_t */
typedef uint16_t            mode_t;     /* Darwin: __uint16_t */
typedef uint16_t            nlink_t;    /* Darwin: __uint16_t */
typedef int64_t             blkcnt_t;
typedef int32_t             blksize_t;  /* Darwin: __int32_t */
typedef int64_t             time_t;

/* --- Time types --- */
struct timespec {
    time_t      tv_sec;         /* Seconds */
    int64_t     tv_nsec;        /* Nanoseconds (long on Darwin) */
};

/* --- Mach types --- */
typedef uint32_t            mach_port_t;
typedef uint32_t            mach_msg_return_t;
typedef uint32_t            kern_return_t;
typedef uint64_t            mach_vm_address_t;
typedef uint64_t            mach_vm_size_t;
typedef uint32_t            natural_t;
typedef int32_t             integer_t;

/* --- Kernel return codes --- */
#define KERN_SUCCESS            0
#define KERN_INVALID_ADDRESS    1
#define KERN_PROTECTION_FAILURE 2
#define KERN_NO_SPACE           3
#define KERN_INVALID_ARGUMENT   4
#define KERN_FAILURE            5
#define KERN_RESOURCE_SHORTAGE  6
#define KERN_NOT_RECEIVER       7
#define KERN_NO_ACCESS          8
#define KERN_NAME_EXISTS        13
#define KERN_ABORTED            14
#define KERN_INVALID_NAME       15
#define KERN_INVALID_TASK       16
#define KERN_INVALID_RIGHT      17
#define KERN_INVALID_VALUE      18
#define KERN_NOT_SUPPORTED      46
#define KERN_NOT_FOUND          56

/* --- Convenience macros --- */
#define ARRAY_SIZE(a)       (sizeof(a) / sizeof((a)[0]))
#define ALIGN_UP(x, a)      (((x) + ((a) - 1)) & ~((a) - 1))
#define ALIGN_DOWN(x, a)    ((x) & ~((a) - 1))
#define MIN(a, b)           ((a) < (b) ? (a) : (b))
#define MAX(a, b)           ((a) > (b) ? (a) : (b))
#define BIT(n)              (1UL << (n))

/* --- Compiler attributes --- */
#define __packed            __attribute__((packed))
#define __aligned(n)        __attribute__((aligned(n)))
#define __noreturn          __attribute__((noreturn))
#define __unused            __attribute__((unused))
#define __weak              __attribute__((weak))
#define __section(s)        __attribute__((section(s)))
#define __likely(x)         __builtin_expect(!!(x), 1)
#define __unlikely(x)       __builtin_expect(!!(x), 0)

/* --- Page size --- */
#define PAGE_SHIFT          12
#define PAGE_SIZE           (1UL << PAGE_SHIFT)     /* 4096 */
#define PAGE_MASK           (~(PAGE_SIZE - 1))

#endif /* _KISEKI_TYPES_H */
