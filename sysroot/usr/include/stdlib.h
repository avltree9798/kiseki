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
long long llabs(long long j);

/* Division with quotient and remainder */
typedef struct { int quot; int rem; } div_t;
typedef struct { long quot; long rem; } ldiv_t;
typedef struct { long long quot; long long rem; } lldiv_t;

div_t   div(int numer, int denom);
ldiv_t  ldiv(long numer, long denom);
lldiv_t lldiv(long long numer, long long denom);

/* Random numbers */
int     rand(void);
void    srand(unsigned int seed);
int     rand_r(unsigned int *seedp);
long    random(void);
void    srandom(unsigned int seed);

/* Sorting and searching */
void    qsort(void *base, size_t nmemb, size_t size,
              int (*compar)(const void *, const void *));
void   *bsearch(const void *key, const void *base, size_t nmemb,
                size_t size, int (*compar)(const void *, const void *));

/* Number to string */
char   *itoa(int value, char *str, int base);

/* Path resolution */
char   *realpath(const char *path, char *resolved_path);

/* Temporary files/directories */
int     mkstemp(char *tmpl);
int     mkostemp(char *tmpl, int flags);
char   *mkdtemp(char *tmpl);

/* Aligned memory allocation */
int     posix_memalign(void **memptr, size_t alignment, size_t size);
void   *aligned_alloc(size_t alignment, size_t size);

/* System */
int     system(const char *command);
int     getloadavg(double loadavg[], int nelem);

/* Resource limits */
struct rlimit {
    unsigned long rlim_cur;
    unsigned long rlim_max;
};

#define RLIMIT_CPU      0
#define RLIMIT_FSIZE    1
#define RLIMIT_DATA     2
#define RLIMIT_STACK    3
#define RLIMIT_CORE     4
#define RLIMIT_RSS      5
#define RLIMIT_MEMLOCK  6
#define RLIMIT_NPROC    7
#define RLIMIT_NOFILE   8
#define RLIM_INFINITY   ((unsigned long)-1)

int     getrlimit(int resource, struct rlimit *rlim);
int     setrlimit(int resource, const struct rlimit *rlim);

#endif /* _LIBSYSTEM_STDLIB_H */
