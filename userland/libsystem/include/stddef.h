/*
 * Kiseki OS - Standard Definitions
 */

#ifndef _LIBSYSTEM_STDDEF_H
#define _LIBSYSTEM_STDDEF_H

/* Size types */
typedef unsigned long       size_t;
typedef long                ptrdiff_t;

/* Wide character type */
typedef int                 wchar_t;

/* NULL */
#ifndef NULL
#define NULL                ((void *)0)
#endif

/* offsetof */
#ifdef __TINYC__
#define offsetof(type, member)  ((size_t)&((type *)0)->member)
#else
#define offsetof(type, member)  __builtin_offsetof(type, member)
#endif

#endif /* _LIBSYSTEM_STDDEF_H */
