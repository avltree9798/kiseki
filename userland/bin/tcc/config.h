/*
 * TCC Configuration for Kiseki OS - ARM64 Mach-O
 */

#ifndef _TCC_CONFIG_H
#define _TCC_CONFIG_H

/* Target: ARM64 with Mach-O output */
#define TCC_TARGET_ARM64        1
#define TCC_TARGET_MACHO        1

/* Version info */
#define TCC_VERSION             "0.9.27-kiseki"

/*
 * Cross-compilation support:
 * When running as a cross-compiler on macOS, use KISEKI_SYSROOT env var
 * or compile with -DKISEKI_SYSROOT="/path/to/kiseki"
 *
 * When running natively on Kiseki, paths are absolute.
 */
#ifdef KISEKI_SYSROOT
/* Cross-compiler mode - prepend sysroot to paths */
#define CONFIG_TCCDIR           KISEKI_SYSROOT "/usr/lib/tcc"
#define CONFIG_TCC_SYSINCLUDEPATHS  KISEKI_SYSROOT "/usr/include"
#define CONFIG_TCC_LIBPATHS         KISEKI_SYSROOT "/usr/lib"
#define CONFIG_TCC_CRTPREFIX        KISEKI_SYSROOT "/usr/lib"
#define CONFIG_SYSROOT          KISEKI_SYSROOT
#else
/* Native mode - paths are absolute on Kiseki */
#define CONFIG_TCCDIR           "/usr/lib/tcc"
#define CONFIG_TCC_SYSINCLUDEPATHS  "/usr/include"
#define CONFIG_TCC_LIBPATHS         "/usr/lib"
#define CONFIG_TCC_CRTPREFIX        "/usr/lib"
#define CONFIG_SYSROOT          ""
#endif

/* No ELF interpreter on Mach-O */
#define CONFIG_TCC_ELFINTERP    ""

/* Build as single compilation unit */
#define ONE_SOURCE              1

/* Static linking (no dlfcn) */
#define CONFIG_TCC_STATIC       1

/* Disable features not needed/available */
#undef CONFIG_TCC_BCHECK        /* No bounds checking */
#undef CONFIG_TCC_BACKTRACE     /* No backtrace support */
#undef TCC_IS_NATIVE            /* Not native (cross-compile initially) */

/* Standard types (in case stdint.h is not available) */
#ifndef __STDC_VERSION__
typedef signed char         int8_t;
typedef unsigned char       uint8_t;
typedef signed short        int16_t;
typedef unsigned short      uint16_t;
typedef signed int          int32_t;
typedef unsigned int        uint32_t;
typedef signed long long    int64_t;
typedef unsigned long long  uint64_t;
typedef unsigned long       size_t;
typedef signed long         ssize_t;
typedef long                intptr_t;
typedef unsigned long       uintptr_t;
#endif

#endif /* _TCC_CONFIG_H */
