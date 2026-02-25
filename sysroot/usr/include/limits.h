/*
 * Kiseki OS — <limits.h>
 *
 * Implementation limits for integral types (matching Darwin/arm64).
 */

#ifndef _LIMITS_H_
#define _LIMITS_H_

/* char */
#define CHAR_BIT    8
#define SCHAR_MIN   (-128)
#define SCHAR_MAX   127
#define UCHAR_MAX   255
#define CHAR_MIN    SCHAR_MIN
#define CHAR_MAX    SCHAR_MAX

/* short */
#define SHRT_MIN    (-32768)
#define SHRT_MAX    32767
#define USHRT_MAX   65535

/* int */
#define INT_MIN     (-2147483647 - 1)
#define INT_MAX     2147483647
#define UINT_MAX    4294967295U

/* long (64-bit on arm64) */
#define LONG_MIN    (-9223372036854775807L - 1L)
#define LONG_MAX    9223372036854775807L
#define ULONG_MAX   18446744073709551615UL

/* long long */
#define LLONG_MIN   (-9223372036854775807LL - 1LL)
#define LLONG_MAX   9223372036854775807LL
#define ULLONG_MAX  18446744073709551615ULL

/* POSIX required */
#define SSIZE_MAX   LONG_MAX
#define PATH_MAX    1024
#define NAME_MAX    255

/* MB_LEN_MAX */
#define MB_LEN_MAX  6

#endif /* _LIMITS_H_ */
