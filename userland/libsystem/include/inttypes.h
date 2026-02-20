/*
 * Kiseki OS - Integer Type Formatting
 */

#ifndef _LIBSYSTEM_INTTYPES_H
#define _LIBSYSTEM_INTTYPES_H

#include <types.h>

/* Printf format macros for signed integers */
#define PRId8   "d"
#define PRId16  "d"
#define PRId32  "d"
#define PRId64  "ld"

#define PRIi8   "i"
#define PRIi16  "i"
#define PRIi32  "i"
#define PRIi64  "li"

/* Printf format macros for unsigned integers */
#define PRIu8   "u"
#define PRIu16  "u"
#define PRIu32  "u"
#define PRIu64  "lu"

#define PRIo8   "o"
#define PRIo16  "o"
#define PRIo32  "o"
#define PRIo64  "lo"

#define PRIx8   "x"
#define PRIx16  "x"
#define PRIx32  "x"
#define PRIx64  "lx"

#define PRIX8   "X"
#define PRIX16  "X"
#define PRIX32  "X"
#define PRIX64  "lX"

/* Printf format macros for pointers */
#define PRIdPTR "ld"
#define PRIiPTR "li"
#define PRIuPTR "lu"
#define PRIoPTR "lo"
#define PRIxPTR "lx"
#define PRIXPTR "lX"

/* Scanf format macros */
#define SCNd8   "hhd"
#define SCNd16  "hd"
#define SCNd32  "d"
#define SCNd64  "ld"

#define SCNi8   "hhi"
#define SCNi16  "hi"
#define SCNi32  "i"
#define SCNi64  "li"

#define SCNu8   "hhu"
#define SCNu16  "hu"
#define SCNu32  "u"
#define SCNu64  "lu"

#define SCNo8   "hho"
#define SCNo16  "ho"
#define SCNo32  "o"
#define SCNo64  "lo"

#define SCNx8   "hhx"
#define SCNx16  "hx"
#define SCNx32  "x"
#define SCNx64  "lx"

/* intmax_t types */
typedef int64_t  intmax_t;
typedef uint64_t uintmax_t;

#define PRIdMAX "ld"
#define PRIiMAX "li"
#define PRIuMAX "lu"
#define PRIoMAX "lo"
#define PRIxMAX "lx"
#define PRIXMAX "lX"

/* Conversion functions */
intmax_t  imaxabs(intmax_t j);
intmax_t  strtoimax(const char *nptr, char **endptr, int base);
uintmax_t strtoumax(const char *nptr, char **endptr, int base);

#endif /* _LIBSYSTEM_INTTYPES_H */
