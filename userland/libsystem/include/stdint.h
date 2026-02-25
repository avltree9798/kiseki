/*
 * Kiseki OS — <stdint.h>
 *
 * Fixed-width integer types. Delegates to <types.h> which defines
 * all the standard integer types for our platform.
 */

#ifndef _STDINT_H_
#define _STDINT_H_

#include <types.h>

/* Minimum-width integer types (same as exact-width on AArch64) */
typedef int8_t      int_least8_t;
typedef int16_t     int_least16_t;
typedef int32_t     int_least32_t;
typedef int64_t     int_least64_t;
typedef uint8_t     uint_least8_t;
typedef uint16_t    uint_least16_t;
typedef uint32_t    uint_least32_t;
typedef uint64_t    uint_least64_t;

/* Fastest minimum-width integer types */
typedef int8_t      int_fast8_t;
typedef int16_t     int_fast16_t;
typedef int32_t     int_fast32_t;
typedef int64_t     int_fast64_t;
typedef uint8_t     uint_fast8_t;
typedef uint16_t    uint_fast16_t;
typedef uint32_t    uint_fast32_t;
typedef uint64_t    uint_fast64_t;

/* Greatest-width integer types */
typedef int64_t     intmax_t;
typedef uint64_t    uintmax_t;

/* Limits of exact-width integer types */
#define INT8_MIN    (-128)
#define INT8_MAX    127
#define UINT8_MAX   255
#define INT16_MIN   (-32768)
#define INT16_MAX   32767
#define UINT16_MAX  65535
#define INT32_MIN   (-2147483647 - 1)
#define INT32_MAX   2147483647
#define UINT32_MAX  4294967295U
#define INT64_MIN   (-9223372036854775807LL - 1LL)
#define INT64_MAX   9223372036854775807LL
#define UINT64_MAX  18446744073709551615ULL

#define INTPTR_MIN  INT64_MIN
#define INTPTR_MAX  INT64_MAX
#define UINTPTR_MAX UINT64_MAX

#define INTMAX_MIN  INT64_MIN
#define INTMAX_MAX  INT64_MAX
#define UINTMAX_MAX UINT64_MAX

#define SIZE_MAX    UINT64_MAX
#define PTRDIFF_MIN INT64_MIN
#define PTRDIFF_MAX INT64_MAX

#endif /* _STDINT_H_ */
