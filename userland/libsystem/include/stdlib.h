/*
 * Kiseki OS - Standard Library
 */

#ifndef _LIBSYSTEM_STDLIB_H
#define _LIBSYSTEM_STDLIB_H

#include <types.h>

#define EXIT_SUCCESS    0
#define EXIT_FAILURE    1

#define RAND_MAX        0x7fffffff

/* Memory allocation */
void   *malloc(size_t size);
void    free(void *ptr);
void   *realloc(void *ptr, size_t size);
void   *calloc(size_t nmemb, size_t size);

/* Process termination */
void    exit(int status) __attribute__((noreturn));
void    _Exit(int status) __attribute__((noreturn));
void    abort(void) __attribute__((noreturn));
int     atexit(void (*function)(void));

/* String to number conversion */
int     atoi(const char *nptr);
long    atol(const char *nptr);
double  atof(const char *nptr);
long    strtol(const char *nptr, char **endptr, int base);
unsigned long strtoul(const char *nptr, char **endptr, int base);
long long strtoll(const char *nptr, char **endptr, int base);
unsigned long long strtoull(const char *nptr, char **endptr, int base);
double  strtod(const char *nptr, char **endptr);
float   strtof(const char *nptr, char **endptr);
long double strtold(const char *nptr, char **endptr);

/* Environment */
char   *getenv(const char *name);
int     setenv(const char *name, const char *value, int overwrite);
int     unsetenv(const char *name);

/* Math-like */
int     abs(int j);
long    labs(long j);

/* Random numbers */
int     rand(void);
void    srand(unsigned int seed);

/* Sorting and searching */
void    qsort(void *base, size_t nmemb, size_t size,
              int (*compar)(const void *, const void *));
void   *bsearch(const void *key, const void *base, size_t nmemb,
                size_t size, int (*compar)(const void *, const void *));

/* Number to string */
char   *itoa(int value, char *str, int base);

#endif /* _LIBSYSTEM_STDLIB_H */
