/*
 * Kiseki OS - Standard Library Implementation
 *
 * malloc/free using a linked-list free-block allocator backed by mmap.
 * Number parsing, environment, qsort, random.
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <syscall.h>

/* ============================================================================
 * Memory Allocator
 *
 * Strategy: linked-list of free blocks, backed by anonymous mmap pages.
 * Each block has a header with size and free/used flag. Free blocks are
 * coalesced on free(). New pages are requested via mmap when needed.
 *
 * Block layout:
 *   [header (16 bytes)] [user data ...]
 *
 * We keep a global linked list of all blocks (free and used).
 * ============================================================================ */

#define BLOCK_MAGIC     0xA110CA7E
#define MIN_ALLOC_SIZE  16
#define MMAP_THRESHOLD  4096    /* Minimum mmap request */

typedef struct block_header {
    size_t                  size;       /* Size of user data (not including header) */
    struct block_header    *next;       /* Next block in global list */
    uint32_t                magic;      /* BLOCK_MAGIC */
    uint32_t                free;       /* 1 = free, 0 = used */
} block_header_t;

#define HEADER_SIZE     sizeof(block_header_t)

/* Global block list */
static block_header_t *_heap_head = NULL;

/* Round up to 16-byte alignment */
static inline size_t _align16(size_t n)
{
    return (n + 15) & ~(size_t)15;
}

/* Request new memory from kernel via mmap */
static void *_mmap_alloc(size_t size)
{
    /* Round up to page size */
    size_t pages = (size + 4095) & ~(size_t)4095;
    if (pages < MMAP_THRESHOLD)
        pages = MMAP_THRESHOLD;

    long ret = syscall6(SYS_mmap,
                        0,                              /* addr: let kernel choose */
                        (long)pages,                    /* length */
                        PROT_READ | PROT_WRITE,         /* prot */
                        MAP_PRIVATE | MAP_ANON,         /* flags */
                        -1,                             /* fd */
                        0);                             /* offset */

    if (ret < 0 || ret == (long)MAP_FAILED) {
        errno = ENOMEM;
        return NULL;
    }
    return (void *)ret;
}

/* Find a free block that can satisfy the request */
static block_header_t *_find_free(size_t size)
{
    block_header_t *cur = _heap_head;
    while (cur) {
        if (cur->free && cur->size >= size)
            return cur;
        cur = cur->next;
    }
    return NULL;
}

/* Split a block if it's significantly larger than needed */
static void _split_block(block_header_t *block, size_t size)
{
    if (block->size >= size + HEADER_SIZE + MIN_ALLOC_SIZE) {
        block_header_t *new_block = (block_header_t *)((char *)block + HEADER_SIZE + size);
        new_block->size = block->size - size - HEADER_SIZE;
        new_block->next = block->next;
        new_block->magic = BLOCK_MAGIC;
        new_block->free = 1;

        block->size = size;
        block->next = new_block;
    }
}

/* Coalesce adjacent free blocks */
static void _coalesce(void)
{
    block_header_t *cur = _heap_head;
    while (cur && cur->next) {
        if (cur->free && cur->next->free) {
            /* Merge cur and cur->next */
            cur->size += HEADER_SIZE + cur->next->size;
            cur->next = cur->next->next;
            /* Don't advance; check if we can merge more */
        } else {
            cur = cur->next;
        }
    }
}

void *malloc(size_t size)
{
    if (size == 0)
        return NULL;

    size = _align16(size);

    /* Try to find a free block */
    block_header_t *block = _find_free(size);
    if (block) {
        _split_block(block, size);
        block->free = 0;
        return (char *)block + HEADER_SIZE;
    }

    /* Allocate new memory from kernel */
    size_t alloc_size = HEADER_SIZE + size;
    /* Add extra space to reduce mmap calls */
    size_t mmap_size = alloc_size;
    if (mmap_size < 65536)
        mmap_size = 65536;

    void *mem = _mmap_alloc(mmap_size);
    if (mem == NULL)
        return NULL;

    block = (block_header_t *)mem;
    block->size = mmap_size - HEADER_SIZE;
    block->next = _heap_head;
    block->magic = BLOCK_MAGIC;
    block->free = 0;

    _heap_head = block;

    _split_block(block, size);

    return (char *)block + HEADER_SIZE;
}

void free(void *ptr)
{
    if (ptr == NULL)
        return;

    block_header_t *block = (block_header_t *)((char *)ptr - HEADER_SIZE);

    /* Validate */
    if (block->magic != BLOCK_MAGIC)
        return;     /* Corrupt or double-free; silently ignore */

    block->free = 1;

    _coalesce();
}

void *realloc(void *ptr, size_t size)
{
    if (ptr == NULL)
        return malloc(size);

    if (size == 0) {
        free(ptr);
        return NULL;
    }

    block_header_t *block = (block_header_t *)((char *)ptr - HEADER_SIZE);
    if (block->magic != BLOCK_MAGIC) {
        errno = EINVAL;
        return NULL;
    }

    size = _align16(size);

    /* If current block is large enough, reuse it */
    if (block->size >= size) {
        _split_block(block, size);
        return ptr;
    }

    /* Try to merge with next free block */
    if (block->next && block->next->free &&
        block->size + HEADER_SIZE + block->next->size >= size) {
        block->size += HEADER_SIZE + block->next->size;
        block->next = block->next->next;
        _split_block(block, size);
        return ptr;
    }

    /* Allocate new block and copy */
    void *new_ptr = malloc(size);
    if (new_ptr == NULL)
        return NULL;

    memcpy(new_ptr, ptr, block->size);
    free(ptr);
    return new_ptr;
}

void *calloc(size_t nmemb, size_t size)
{
    size_t total = nmemb * size;
    /* Check overflow */
    if (nmemb != 0 && total / nmemb != size) {
        errno = ENOMEM;
        return NULL;
    }

    void *ptr = malloc(total);
    if (ptr)
        memset(ptr, 0, total);
    return ptr;
}

/* ============================================================================
 * Process termination
 * ============================================================================ */

#define MAX_ATEXIT  32

static void (*_atexit_funcs[MAX_ATEXIT])(void);
static int _atexit_count = 0;

int atexit(void (*function)(void))
{
    if (_atexit_count >= MAX_ATEXIT)
        return -1;
    _atexit_funcs[_atexit_count++] = function;
    return 0;
}

void exit(int status)
{
    /* Call atexit handlers in reverse order */
    while (_atexit_count > 0) {
        _atexit_count--;
        if (_atexit_funcs[_atexit_count])
            _atexit_funcs[_atexit_count]();
    }

    _exit(status);
    __builtin_unreachable();
}

void _Exit(int status)
{
    _exit(status);
    __builtin_unreachable();
}

void abort(void)
{
    /* Send SIGABRT to self */
    kill(getpid(), SIGABRT);
    /* If signal was caught/ignored, force exit */
    _exit(134);     /* 128 + SIGABRT(6) */
    __builtin_unreachable();
}

/* ============================================================================
 * String to number conversion
 * ============================================================================ */

static inline int _isspace(int c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
           c == '\f' || c == '\v';
}

static inline int _isdigit(int c)
{
    return c >= '0' && c <= '9';
}

static inline int _isalpha(int c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static inline int _digit_val(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'z') return c - 'a' + 10;
    if (c >= 'A' && c <= 'Z') return c - 'A' + 10;
    return -1;
}

unsigned long strtoul(const char *nptr, char **endptr, int base)
{
    const char *s = nptr;
    unsigned long result = 0;
    int neg = 0;

    /* Skip whitespace */
    while (_isspace(*s))
        s++;

    /* Sign */
    if (*s == '-') {
        neg = 1;
        s++;
    } else if (*s == '+') {
        s++;
    }

    /* Auto-detect base */
    if (base == 0) {
        if (*s == '0') {
            s++;
            if (*s == 'x' || *s == 'X') {
                base = 16;
                s++;
            } else {
                base = 8;
            }
        } else {
            base = 10;
        }
    } else if (base == 16) {
        if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
            s += 2;
    }

    unsigned long cutoff = ULONG_MAX / (unsigned long)base;
    int cutlim = (int)(ULONG_MAX % (unsigned long)base);
    int overflow = 0;

    const char *start = s;
    while (*s) {
        int d = _digit_val(*s);
        if (d < 0 || d >= base)
            break;

        if (result > cutoff || (result == cutoff && d > cutlim)) {
            overflow = 1;
        }

        result = result * (unsigned long)base + (unsigned long)d;
        s++;
    }

    if (s == start) {
        /* No digits consumed; return 0, endptr at nptr */
        if (endptr)
            *endptr = (char *)nptr;
        return 0;
    }

    if (endptr)
        *endptr = (char *)s;

    if (overflow) {
        errno = ERANGE;
        return ULONG_MAX;
    }

    return neg ? (unsigned long)(-(long)result) : result;
}

long strtol(const char *nptr, char **endptr, int base)
{
    const char *s = nptr;
    int neg = 0;

    while (_isspace(*s))
        s++;

    if (*s == '-') {
        neg = 1;
        s++;
    } else if (*s == '+') {
        s++;
    }

    unsigned long uval = strtoul(s, endptr, base);

    /* Fix endptr if we consumed a sign */
    if (endptr && *endptr == s) {
        *endptr = (char *)nptr;
        return 0;
    }

    if (neg) {
        if (uval > (unsigned long)LONG_MAX + 1UL) {
            errno = ERANGE;
            return LONG_MIN;
        }
        return -(long)uval;
    } else {
        if (uval > (unsigned long)LONG_MAX) {
            errno = ERANGE;
            return LONG_MAX;
        }
        return (long)uval;
    }
}

long long strtoll(const char *nptr, char **endptr, int base)
{
    /* On LP64, long long == long */
    return (long long)strtol(nptr, endptr, base);
}

unsigned long long strtoull(const char *nptr, char **endptr, int base)
{
    return (unsigned long long)strtoul(nptr, endptr, base);
}

int atoi(const char *nptr)
{
    return (int)strtol(nptr, NULL, 10);
}

long atol(const char *nptr)
{
    return strtol(nptr, NULL, 10);
}

/* ============================================================================
 * Environment
 * ============================================================================ */

/* environ is set by crt0 */
char **environ = NULL;

/* Storage for setenv (static for simplicity) */
#define ENV_MAX 256
static char *_env_storage[ENV_MAX + 1];
static int _env_owns_table = 0;

static void _ensure_env_table(void)
{
    if (_env_owns_table)
        return;

    /* Copy the environment to our own storage */
    int i = 0;
    if (environ) {
        for (; environ[i] && i < ENV_MAX; i++)
            _env_storage[i] = environ[i];
    }
    _env_storage[i] = NULL;
    environ = _env_storage;
    _env_owns_table = 1;
}

char *getenv(const char *name)
{
    if (environ == NULL || name == NULL)
        return NULL;

    size_t len = strlen(name);

    for (char **ep = environ; *ep; ep++) {
        if (strncmp(*ep, name, len) == 0 && (*ep)[len] == '=')
            return *ep + len + 1;
    }
    return NULL;
}

int setenv(const char *name, const char *value, int overwrite)
{
    if (name == NULL || *name == '\0' || strchr(name, '=')) {
        errno = EINVAL;
        return -1;
    }

    _ensure_env_table();

    size_t namelen = strlen(name);

    /* Find existing entry */
    int i;
    for (i = 0; environ[i]; i++) {
        if (strncmp(environ[i], name, namelen) == 0 && environ[i][namelen] == '=') {
            if (!overwrite)
                return 0;

            /* Replace */
            size_t vallen = strlen(value);
            char *new_entry = malloc(namelen + 1 + vallen + 1);
            if (!new_entry) {
                errno = ENOMEM;
                return -1;
            }
            memcpy(new_entry, name, namelen);
            new_entry[namelen] = '=';
            memcpy(new_entry + namelen + 1, value, vallen + 1);
            environ[i] = new_entry;
            return 0;
        }
    }

    /* Add new entry */
    if (i >= ENV_MAX) {
        errno = ENOMEM;
        return -1;
    }

    size_t vallen = strlen(value);
    char *new_entry = malloc(namelen + 1 + vallen + 1);
    if (!new_entry) {
        errno = ENOMEM;
        return -1;
    }
    memcpy(new_entry, name, namelen);
    new_entry[namelen] = '=';
    memcpy(new_entry + namelen + 1, value, vallen + 1);
    environ[i] = new_entry;
    environ[i + 1] = NULL;
    return 0;
}

int unsetenv(const char *name)
{
    if (name == NULL || *name == '\0' || strchr(name, '=')) {
        errno = EINVAL;
        return -1;
    }

    if (environ == NULL)
        return 0;

    _ensure_env_table();

    size_t namelen = strlen(name);

    char **ep = environ;
    while (*ep) {
        if (strncmp(*ep, name, namelen) == 0 && (*ep)[namelen] == '=') {
            /* Shift entries down */
            char **p = ep;
            while (*p) {
                *p = *(p + 1);
                p++;
            }
        } else {
            ep++;
        }
    }
    return 0;
}

/* ============================================================================
 * Math-like
 * ============================================================================ */

int abs(int j)
{
    return j < 0 ? -j : j;
}

long labs(long j)
{
    return j < 0 ? -j : j;
}

/* ============================================================================
 * Random numbers (simple LCG)
 * ============================================================================ */

static unsigned int _rand_state = 1;

int rand(void)
{
    _rand_state = _rand_state * 1103515245 + 12345;
    return (int)((_rand_state >> 16) & RAND_MAX);
}

void srand(unsigned int seed)
{
    _rand_state = seed;
}

/* ============================================================================
 * qsort - Quicksort implementation
 * ============================================================================ */

static void _swap(void *a, void *b, size_t size)
{
    unsigned char *pa = (unsigned char *)a;
    unsigned char *pb = (unsigned char *)b;
    while (size--) {
        unsigned char t = *pa;
        *pa++ = *pb;
        *pb++ = t;
    }
}

static void _qsort_inner(void *base, size_t nmemb, size_t size,
                          int (*compar)(const void *, const void *))
{
    if (nmemb <= 1)
        return;

    /* Insertion sort for small arrays */
    if (nmemb <= 16) {
        unsigned char *arr = (unsigned char *)base;
        for (size_t i = 1; i < nmemb; i++) {
            size_t j = i;
            while (j > 0 && compar(arr + j * size, arr + (j - 1) * size) < 0) {
                _swap(arr + j * size, arr + (j - 1) * size, size);
                j--;
            }
        }
        return;
    }

    unsigned char *arr = (unsigned char *)base;

    /* Median-of-three pivot */
    size_t mid = nmemb / 2;
    if (compar(arr, arr + mid * size) > 0)
        _swap(arr, arr + mid * size, size);
    if (compar(arr, arr + (nmemb - 1) * size) > 0)
        _swap(arr, arr + (nmemb - 1) * size, size);
    if (compar(arr + mid * size, arr + (nmemb - 1) * size) > 0)
        _swap(arr + mid * size, arr + (nmemb - 1) * size, size);

    /* Move pivot to arr[nmemb-2] */
    _swap(arr + mid * size, arr + (nmemb - 2) * size, size);
    void *pivot = arr + (nmemb - 2) * size;

    size_t i = 0;
    size_t j = nmemb - 2;

    for (;;) {
        while (compar(arr + (++i) * size, pivot) < 0)
            ;
        while (j > 0 && compar(arr + (--j) * size, pivot) > 0)
            ;
        if (i >= j)
            break;
        _swap(arr + i * size, arr + j * size, size);
    }

    /* Restore pivot */
    _swap(arr + i * size, arr + (nmemb - 2) * size, size);

    _qsort_inner(arr, i, size, compar);
    _qsort_inner(arr + (i + 1) * size, nmemb - i - 1, size, compar);
}

void qsort(void *base, size_t nmemb, size_t size,
           int (*compar)(const void *, const void *))
{
    if (base == NULL || nmemb <= 1 || size == 0 || compar == NULL)
        return;
    _qsort_inner(base, nmemb, size, compar);
}

/* ============================================================================
 * bsearch - Binary search
 * ============================================================================ */

void *bsearch(const void *key, const void *base, size_t nmemb,
              size_t size, int (*compar)(const void *, const void *))
{
    const unsigned char *arr = (const unsigned char *)base;
    size_t lo = 0, hi = nmemb;

    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int cmp = compar(key, arr + mid * size);
        if (cmp < 0)
            hi = mid;
        else if (cmp > 0)
            lo = mid + 1;
        else
            return (void *)(arr + mid * size);
    }
    return NULL;
}

/* ============================================================================
 * itoa - number to string
 * ============================================================================ */

char *itoa(int value, char *str, int base)
{
    if (base < 2 || base > 36) {
        *str = '\0';
        return str;
    }

    char *p = str;
    int neg = 0;
    unsigned int uval;

    if (value < 0 && base == 10) {
        neg = 1;
        uval = (unsigned int)(-(value + 1)) + 1;
    } else {
        uval = (unsigned int)value;
    }

    /* Generate digits in reverse */
    char buf[34];
    int i = 0;
    do {
        int d = (int)(uval % (unsigned)base);
        buf[i++] = d < 10 ? '0' + d : 'a' + d - 10;
        uval /= (unsigned)base;
    } while (uval > 0);

    if (neg)
        *p++ = '-';

    while (i > 0)
        *p++ = buf[--i];
    *p = '\0';

    return str;
}

/* ============================================================================
 * Floating-point string to number conversion
 * ============================================================================ */

double atof(const char *nptr)
{
    return strtod(nptr, NULL);
}

double strtod(const char *nptr, char **endptr)
{
    const char *s = nptr;
    double result = 0.0;
    double frac = 0.0;
    int neg = 0;
    int exp_neg = 0;
    int exp_val = 0;
    int has_digits = 0;

    /* Skip whitespace */
    while (_isspace(*s))
        s++;

    /* Sign */
    if (*s == '-') {
        neg = 1;
        s++;
    } else if (*s == '+') {
        s++;
    }

    /* Integer part */
    while (_isdigit(*s)) {
        result = result * 10.0 + (*s - '0');
        has_digits = 1;
        s++;
    }

    /* Fractional part */
    if (*s == '.') {
        s++;
        double divisor = 10.0;
        while (_isdigit(*s)) {
            frac += (*s - '0') / divisor;
            divisor *= 10.0;
            has_digits = 1;
            s++;
        }
    }

    result += frac;

    /* Exponent */
    if (*s == 'e' || *s == 'E') {
        s++;
        if (*s == '-') {
            exp_neg = 1;
            s++;
        } else if (*s == '+') {
            s++;
        }
        while (_isdigit(*s)) {
            exp_val = exp_val * 10 + (*s - '0');
            s++;
        }
        
        /* Apply exponent via repeated multiplication/division */
        double multiplier = 1.0;
        for (int i = 0; i < exp_val; i++)
            multiplier *= 10.0;
        
        if (exp_neg)
            result /= multiplier;
        else
            result *= multiplier;
    }

    if (!has_digits) {
        if (endptr)
            *endptr = (char *)nptr;
        return 0.0;
    }

    if (endptr)
        *endptr = (char *)s;

    return neg ? -result : result;
}

float strtof(const char *nptr, char **endptr)
{
    return (float)strtod(nptr, endptr);
}

long double strtold(const char *nptr, char **endptr)
{
    return (long double)strtod(nptr, endptr);
}

/* ============================================================================
 * Math functions (minimal implementations for TCC)
 * ============================================================================ */

/* ldexp: x * 2^exp */
double ldexp(double x, int exp)
{
    /* Simple implementation - multiply/divide by 2 repeatedly */
    if (exp > 0) {
        while (exp-- > 0)
            x *= 2.0;
    } else {
        while (exp++ < 0)
            x /= 2.0;
    }
    return x;
}

float ldexpf(float x, int exp)
{
    return (float)ldexp((double)x, exp);
}

/* ============================================================================
 * Assertion handler
 * ============================================================================ */

void __assert_fail(const char *expr, const char *file, int line, const char *func)
{
    /* Print to stderr (fd 2) */
    const char *msg1 = "Assertion failed: ";
    const char *msg2 = ", file ";
    const char *msg3 = ", line ";
    const char *msg4 = ", function ";
    const char *msg5 = "\n";
    
    write(2, msg1, strlen(msg1));
    write(2, expr, strlen(expr));
    write(2, msg2, strlen(msg2));
    write(2, file, strlen(file));
    write(2, msg3, strlen(msg3));
    
    /* Convert line to string */
    char line_buf[16];
    itoa(line, line_buf, 10);
    write(2, line_buf, strlen(line_buf));
    
    if (func) {
        write(2, msg4, strlen(msg4));
        write(2, func, strlen(func));
    }
    write(2, msg5, 1);
    
    abort();
}
