/*
 * Kiseki OS - Variable Arguments
 *
 * Provides va_list and related macros.
 *
 * IMPORTANT: On Darwin ARM64, va_list is just a char* pointer, not the
 * full AAPCS struct. Both TCC and clang must use the same layout for
 * cross-compiled code to work correctly.
 */

#ifndef _LIBSYSTEM_STDARG_H
#define _LIBSYSTEM_STDARG_H

#ifdef __TINYC__
/*
 * TCC on Darwin ARM64: Use simple pointer-based va_list like clang.
 * Arguments are passed in x0-x7 and spill to stack. The callee saves
 * register args to stack, and va_list points to them.
 */
#ifndef _VA_LIST_DEFINED
#define _VA_LIST_DEFINED
typedef char *va_list;
#endif

/* 
 * TCC's __va_start and __va_arg are builtins that use AAPCS conventions.
 * For Darwin compatibility, we override with pointer arithmetic.
 * On ARM64, variadic args after register args go on stack, 8-byte aligned.
 */
#define va_start(ap, last) \
    ((ap) = (char *)&(last) + ((sizeof(last) + 7) & ~7))
#define va_arg(ap, type) \
    (*(type *)((ap) += ((sizeof(type) + 7) & ~7), (ap) - ((sizeof(type) + 7) & ~7)))
#define va_end(ap)          ((void)0)
#define va_copy(dest, src)  ((dest) = (src))

#else
/* GCC/Clang builtins */
typedef __builtin_va_list   va_list;
#define va_start(ap, last)  __builtin_va_start(ap, last)
#define va_end(ap)          __builtin_va_end(ap)
#define va_arg(ap, type)    __builtin_va_arg(ap, type)
#define va_copy(dest, src)  __builtin_va_copy(dest, src)
#endif

#endif /* _LIBSYSTEM_STDARG_H */
