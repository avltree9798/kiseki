/*
 * Kiseki OS - Standard Definitions
 */

#ifndef _LIBSYSTEM_STDDEF_H
#define _LIBSYSTEM_STDDEF_H

/* Size types — guard against redefinition from types.h */
#ifndef _LIBSYSTEM_SIZE_T_DEFINED
#define _LIBSYSTEM_SIZE_T_DEFINED
typedef unsigned long       size_t;
#endif
#ifndef _LIBSYSTEM_PTRDIFF_T_DEFINED
#define _LIBSYSTEM_PTRDIFF_T_DEFINED
typedef long                ptrdiff_t;
#endif

/* Wide character type */
typedef int                 wchar_t;

/* NULL */
#ifndef NULL
#define NULL                ((void *)0)
#endif

/* offsetof */
#ifndef offsetof
#ifdef __TINYC__
#define offsetof(type, member)  ((size_t)&((type *)0)->member)
#else
#define offsetof(type, member)  __builtin_offsetof(type, member)
#endif
#endif

#endif /* _LIBSYSTEM_STDDEF_H */
