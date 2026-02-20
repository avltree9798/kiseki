/*
 * Kiseki OS - Variable Arguments
 *
 * Provides va_list and related macros.
 * Works with both GCC/Clang builtins and TCC.
 */

#ifndef _LIBSYSTEM_STDARG_H
#define _LIBSYSTEM_STDARG_H

#ifdef __TINYC__
/* TCC uses its own va_list implementation */
#ifndef _VA_LIST_DEFINED
#define _VA_LIST_DEFINED
typedef struct {
    void *__stack;
    void *__gr_top;
    void *__vr_top;
    int   __gr_offs;
    int   __vr_offs;
} va_list[1];
#endif

#define va_start(ap, last)  __va_start(ap, last)
#define va_arg(ap, type)    __va_arg(ap, type)
#define va_end(ap)          ((void)0)
#define va_copy(dest, src)  ((dest)[0] = (src)[0])

#else
/* GCC/Clang builtins */
typedef __builtin_va_list   va_list;
#define va_start(ap, last)  __builtin_va_start(ap, last)
#define va_end(ap)          __builtin_va_end(ap)
#define va_arg(ap, type)    __builtin_va_arg(ap, type)
#define va_copy(dest, src)  __builtin_va_copy(dest, src)
#endif

#endif /* _LIBSYSTEM_STDARG_H */
