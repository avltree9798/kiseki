/*
 * Kiseki OS - libSystem.B.dylib
 *
 * Complete freestanding C library for Mach-O userland binaries.
 * Built with macOS clang as an MH_DYLIB, installed to /usr/lib/libSystem.B.dylib.
 *
 * All syscalls go through svc #0x80 with the BSD syscall number in x16.
 * Error convention: kernel sets PSTATE carry flag on error, x0 = positive errno.
 */

/* ============================================================================
 * Compiler intrinsics and attribute macros
 * ============================================================================ */

typedef __builtin_va_list   va_list;
#define va_start(ap, last)  __builtin_va_start(ap, last)
#define va_end(ap)          __builtin_va_end(ap)
#define va_arg(ap, type)    __builtin_va_arg(ap, type)
#define va_copy(dest, src)  __builtin_va_copy(dest, src)

#define EXPORT __attribute__((visibility("default")))
#define NORETURN __attribute__((noreturn))
#define USED __attribute__((used))

#define NULL ((void *)0)

typedef unsigned char       uint8_t;
typedef unsigned short      uint16_t;
typedef unsigned int        uint32_t;
typedef unsigned long       uint64_t;
typedef signed char         int8_t;
typedef signed short        int16_t;
typedef signed int          int32_t;
typedef signed long         int64_t;
typedef unsigned long       size_t;
typedef signed long         ssize_t;
typedef unsigned long       uintptr_t;
typedef signed long         intptr_t;
typedef signed long         off_t;
typedef signed long         time_t;

#define INT_MAX     0x7fffffff
#define INT_MIN     (-INT_MAX - 1)
#define UINT_MAX    0xffffffffU
#define LONG_MAX    0x7fffffffffffffffL
#define LONG_MIN    (-LONG_MAX - 1L)
#define ULONG_MAX   0xffffffffffffffffUL

#define EOF         (-1)
#define BUFSIZ      1024
#define FOPEN_MAX   64

#define SEEK_SET    0
#define SEEK_CUR    1
#define SEEK_END    2

/* ============================================================================
 * Syscall numbers (BSD positive)
 * ============================================================================ */

#define SYS_exit        1
#define SYS_fork        2
#define SYS_read        3
#define SYS_write       4
#define SYS_open        5
#define SYS_close       6
#define SYS_wait4       7
#define SYS_getpid      20
#define SYS_setuid      23
#define SYS_getuid      24
#define SYS_geteuid     25
#define SYS_kill        37
#define SYS_getppid_nr  39
#define SYS_getgid      47
#define SYS_setgid      181
#define SYS_dup         41
#define SYS_pipe        42
#define SYS_getegid     43
#define SYS_ioctl       54
#define SYS_execve      59
#define SYS_munmap      73
#define SYS_mprotect    74
#define SYS_fstat       153
#define SYS_lseek       199
#define SYS_mmap        197
#define SYS_sysctl      202
#define SYS_openpty     501

/* open flags */
#define O_RDONLY    0x0000
#define O_WRONLY    0x0001
#define O_RDWR      0x0002
#define O_APPEND    0x0008
#define O_CREAT     0x0200
#define O_TRUNC     0x0400
#define O_EXCL      0x0800

/* mmap constants */
#define PROT_NONE       0x00
#define PROT_READ       0x01
#define PROT_WRITE      0x02
#define PROT_EXEC       0x04
#define MAP_SHARED      0x0001
#define MAP_PRIVATE     0x0002
#define MAP_FIXED       0x0010
#define MAP_ANON        0x1000
#define MAP_ANONYMOUS   MAP_ANON
#define MAP_FAILED      ((void *)-1)

/* errno values */
#define EPERM           1
#define ENOENT          2
#define ESRCH           3
#define EINTR           4
#define EIO             5
#define ENXIO           6
#define E2BIG           7
#define ENOEXEC         8
#define EBADF           9
#define ECHILD          10
#define EDEADLK         11
#define ENOMEM          12
#define EACCES          13
#define EFAULT          14
#define ENOTBLK         15
#define EBUSY           16
#define EEXIST          17
#define EXDEV           18
#define ENODEV          19
#define ENOTDIR         20
#define EISDIR          21
#define EINVAL          22
#define ENFILE          23
#define EMFILE          24
#define ENOTTY          25
#define ETXTBSY         26
#define EFBIG           27
#define ENOSPC          28
#define ESPIPE          29
#define EROFS           30
#define EMLINK          31
#define EPIPE           32
#define EDOM            33
#define ERANGE          34
#define EAGAIN          35
#define EINPROGRESS     36
#define EALREADY        37
#define ENOTSOCK        38
#define EDESTADDRREQ    39
#define EMSGSIZE        40
#define ENAMETOOLONG    63
#define ENOTEMPTY       66
#define ENOSYS          78

/* TIOCGETA ioctl for isatty */
#define TIOCGETA        0x40487413

/* ============================================================================
 * Syscall interface
 *
 * ARM64 svc #0x80 calling convention:
 *   x16 = syscall number
 *   x0-x5 = arguments
 *   Returns: x0 = result / errno
 *   Carry flag (NZCV bit 29) set on error
 * ============================================================================ */

static inline long __syscall(long number, long a0, long a1, long a2,
                             long a3, long a4, long a5)
{
    register long x16 __asm__("x16") = number;
    register long x0  __asm__("x0")  = a0;
    register long x1  __asm__("x1")  = a1;
    register long x2  __asm__("x2")  = a2;
    register long x3  __asm__("x3")  = a3;
    register long x4  __asm__("x4")  = a4;
    register long x5  __asm__("x5")  = a5;
    register long nzcv;

    __asm__ volatile(
        "svc    #0x80\n\t"
        "mrs    %[nzcv], nzcv"
        : [nzcv] "=r" (nzcv),
          "+r" (x0)
        : "r" (x16), "r" (x1), "r" (x2), "r" (x3), "r" (x4), "r" (x5)
        : "memory", "cc"
    );

    /* Carry flag is bit 29 of NZCV */
    if (nzcv & (1L << 29))
        return -x0;    /* Error: return -errno */
    return x0;          /* Success */
}

#define syscall0(n)                 __syscall((n), 0, 0, 0, 0, 0, 0)
#define syscall1(n, a)              __syscall((n), (long)(a), 0, 0, 0, 0, 0)
#define syscall2(n, a, b)           __syscall((n), (long)(a), (long)(b), 0, 0, 0, 0)
#define syscall3(n, a, b, c)        __syscall((n), (long)(a), (long)(b), (long)(c), 0, 0, 0)
#define syscall4(n, a, b, c, d)     __syscall((n), (long)(a), (long)(b), (long)(c), (long)(d), 0, 0)
#define syscall5(n, a, b, c, d, e)  __syscall((n), (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), 0)
#define syscall6(n, a, b, c, d, e, f) __syscall((n), (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), (long)(f))

/* Helper: convert syscall return to libc convention (-1 + errno) */
static inline long _check(long ret)
{
    extern int errno;
    if (ret < 0) {
        errno = (int)(-ret);
        return -1;
    }
    return ret;
}

/* ============================================================================
 * errno
 * ============================================================================ */

EXPORT int errno = 0;

/*
 * __error() — returns pointer to errno.
 * macOS libc exports this as ___error in the symbol table.
 * Used by code compiled against macOS SDK (e.g., bash).
 */
EXPORT int *__error(void)
{
    return &errno;
}

/* ============================================================================
 * Stack protector support
 * ============================================================================ */

EXPORT unsigned long __stack_chk_guard = 0x595e9fbd94fda766UL;

EXPORT NORETURN void __stack_chk_fail(void)
{
    /* Stack smashing detected - abort */
    static const char msg[] = "*** stack smashing detected ***\n";
    syscall3(SYS_write, 2, (long)msg, sizeof(msg) - 1);
    syscall1(SYS_exit, 134);
    __builtin_unreachable();
}

/* ============================================================================
 * dyld stub binder
 * ============================================================================ */

EXPORT void dyld_stub_binder(void)
{
    /* No-op / trap - Kiseki's dyld does eager binding */
    __builtin_trap();
}

/* ============================================================================
 * String functions
 * ============================================================================ */

EXPORT size_t strlen(const char *s)
{
    const char *p = s;
    while (*p) p++;
    return (size_t)(p - s);
}

EXPORT int strcmp(const char *s1, const char *s2)
{
    while (*s1 && *s1 == *s2) { s1++; s2++; }
    return (unsigned char)*s1 - (unsigned char)*s2;
}

EXPORT int strncmp(const char *s1, const char *s2, size_t n)
{
    if (n == 0) return 0;
    while (n-- > 1 && *s1 && *s1 == *s2) { s1++; s2++; }
    return (unsigned char)*s1 - (unsigned char)*s2;
}

EXPORT char *strcpy(char *dst, const char *src)
{
    char *ret = dst;
    while ((*dst++ = *src++) != '\0') ;
    return ret;
}

EXPORT char *strncpy(char *dst, const char *src, size_t n)
{
    char *ret = dst;
    while (n > 0 && *src) { *dst++ = *src++; n--; }
    while (n > 0) { *dst++ = '\0'; n--; }
    return ret;
}

EXPORT char *strcat(char *dst, const char *src)
{
    char *ret = dst;
    while (*dst) dst++;
    while ((*dst++ = *src++) != '\0') ;
    return ret;
}

EXPORT char *strncat(char *dst, const char *src, size_t n)
{
    char *ret = dst;
    while (*dst) dst++;
    while (n > 0 && *src) { *dst++ = *src++; n--; }
    *dst = '\0';
    return ret;
}

EXPORT char *strchr(const char *s, int c)
{
    char ch = (char)c;
    while (*s) {
        if (*s == ch) return (char *)s;
        s++;
    }
    return ch == '\0' ? (char *)s : NULL;
}

EXPORT char *strrchr(const char *s, int c)
{
    char ch = (char)c;
    const char *last = NULL;
    while (*s) {
        if (*s == ch) last = s;
        s++;
    }
    if (ch == '\0') return (char *)s;
    return (char *)last;
}

EXPORT char *strstr(const char *haystack, const char *needle)
{
    if (*needle == '\0') return (char *)haystack;
    size_t nlen = strlen(needle);
    while (*haystack) {
        if (*haystack == *needle && strncmp(haystack, needle, nlen) == 0)
            return (char *)haystack;
        haystack++;
    }
    return NULL;
}

EXPORT size_t strspn(const char *s, const char *accept)
{
    const char *p = s;
    while (*p) {
        const char *a = accept;
        int found = 0;
        while (*a) {
            if (*p == *a) { found = 1; break; }
            a++;
        }
        if (!found) break;
        p++;
    }
    return (size_t)(p - s);
}

EXPORT size_t strcspn(const char *s, const char *reject)
{
    const char *p = s;
    while (*p) {
        const char *r = reject;
        while (*r) {
            if (*p == *r) return (size_t)(p - s);
            r++;
        }
        p++;
    }
    return (size_t)(p - s);
}

/* Forward declarations needed for strdup */
extern void *memcpy(void *dst, const void *src, size_t n);

EXPORT char *strdup(const char *s)
{
    extern void *malloc(size_t);
    size_t len = strlen(s) + 1;
    char *n = (char *)malloc(len);
    if (n) memcpy(n, s, len);
    return n;
}

/* ============================================================================
 * Memory functions
 * ============================================================================ */

EXPORT void *memcpy(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;

    /* Word-aligned fast path */
    if (n >= 8 && ((uintptr_t)d & 7) == 0 && ((uintptr_t)s & 7) == 0) {
        uint64_t *d64 = (uint64_t *)d;
        const uint64_t *s64 = (const uint64_t *)s;
        while (n >= 8) { *d64++ = *s64++; n -= 8; }
        d = (unsigned char *)d64;
        s = (const unsigned char *)s64;
    }
    while (n--) *d++ = *s++;
    return dst;
}

EXPORT void *memmove(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    if (d == s || n == 0) return dst;
    if (d < s) {
        while (n--) *d++ = *s++;
    } else {
        d += n; s += n;
        while (n--) *--d = *--s;
    }
    return dst;
}

EXPORT void *memset(void *dst, int c, size_t n)
{
    unsigned char *p = (unsigned char *)dst;
    unsigned char val = (unsigned char)c;

    /* Word-aligned fast path for zero fill */
    if (n >= 8 && ((uintptr_t)p & 7) == 0) {
        uint64_t fill = 0;
        if (val != 0) {
            fill = val;
            fill |= fill << 8;
            fill |= fill << 16;
            fill |= fill << 32;
        }
        uint64_t *p64 = (uint64_t *)p;
        while (n >= 8) { *p64++ = fill; n -= 8; }
        p = (unsigned char *)p64;
    }
    while (n--) *p++ = val;
    return dst;
}

EXPORT int memcmp(const void *s1, const void *s2, size_t n)
{
    const unsigned char *p1 = (const unsigned char *)s1;
    const unsigned char *p2 = (const unsigned char *)s2;
    while (n--) {
        if (*p1 != *p2) return *p1 - *p2;
        p1++; p2++;
    }
    return 0;
}

EXPORT void *memchr(const void *s, int c, size_t n)
{
    const unsigned char *p = (const unsigned char *)s;
    unsigned char val = (unsigned char)c;
    while (n--) {
        if (*p == val) return (void *)p;
        p++;
    }
    return NULL;
}

/* __bzero - clang sometimes emits calls to this */
EXPORT void __bzero(void *dst, size_t n)
{
    memset(dst, 0, n);
}

/* bzero */
EXPORT void bzero(void *dst, size_t n)
{
    memset(dst, 0, n);
}

/* memset_pattern variants - clang may emit these */
EXPORT void memset_pattern4(void *dst, const void *pattern, size_t n)
{
    const unsigned char *p = (const unsigned char *)pattern;
    unsigned char *d = (unsigned char *)dst;
    while (n >= 4) { d[0] = p[0]; d[1] = p[1]; d[2] = p[2]; d[3] = p[3]; d += 4; n -= 4; }
    while (n--) *d++ = p[n % 4]; /* handle tail */
}

EXPORT void memset_pattern8(void *dst, const void *pattern, size_t n)
{
    const unsigned char *p = (const unsigned char *)pattern;
    unsigned char *d = (unsigned char *)dst;
    while (n >= 8) { for (int i = 0; i < 8; i++) d[i] = p[i]; d += 8; n -= 8; }
    for (size_t i = 0; i < n; i++) d[i] = p[i];
}

EXPORT void memset_pattern16(void *dst, const void *pattern, size_t n)
{
    const unsigned char *p = (const unsigned char *)pattern;
    unsigned char *d = (unsigned char *)dst;
    while (n >= 16) { for (int i = 0; i < 16; i++) d[i] = p[i]; d += 16; n -= 16; }
    for (size_t i = 0; i < n; i++) d[i] = p[i];
}

/* ============================================================================
 * Low-level I/O wrappers
 * ============================================================================ */

EXPORT ssize_t write(int fd, const void *buf, size_t count)
{
    return (ssize_t)_check(syscall3(SYS_write, fd, buf, count));
}

EXPORT ssize_t read(int fd, void *buf, size_t count)
{
    return (ssize_t)_check(syscall3(SYS_read, fd, buf, count));
}

EXPORT int open(const char *pathname, int flags, ...)
{
    long mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    return (int)_check(syscall3(SYS_open, pathname, flags, mode));
}

EXPORT int close(int fd)
{
    return (int)_check(syscall1(SYS_close, fd));
}

EXPORT off_t lseek(int fd, off_t offset, int whence)
{
    return (off_t)_check(syscall3(SYS_lseek, fd, offset, whence));
}

EXPORT int dup(int oldfd)
{
    return (int)_check(syscall1(SYS_dup, oldfd));
}

EXPORT int pipe(int pipefd[2])
{
    return (int)_check(syscall1(SYS_pipe, pipefd));
}

EXPORT int ioctl(int fd, unsigned long request, ...)
{
    va_list ap;
    va_start(ap, request);
    long arg = va_arg(ap, long);
    va_end(ap);
    return (int)_check(syscall3(SYS_ioctl, fd, request, arg));
}

EXPORT int isatty(int fd)
{
    char buf[128]; /* large enough for struct termios */
    long ret = syscall3(SYS_ioctl, fd, TIOCGETA, buf);
    if (ret < 0) {
        errno = ENOTTY;
        return 0;
    }
    return 1;
}

EXPORT void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    long ret = syscall6(SYS_mmap, addr, length, prot, flags, fd, offset);
    if (ret < 0) {
        errno = (int)(-ret);
        return MAP_FAILED;
    }
    return (void *)ret;
}

EXPORT int munmap(void *addr, size_t length)
{
    return (int)_check(syscall2(SYS_munmap, addr, length));
}

EXPORT int mprotect(void *addr, size_t length, int prot)
{
    return (int)_check(syscall3(SYS_mprotect, addr, length, prot));
}

/* fstat */
EXPORT int fstat(int fd, void *statbuf)
{
    return (int)_check(syscall2(SYS_fstat, fd, statbuf));
}

/* ============================================================================
 * Process control
 * ============================================================================ */

EXPORT NORETURN void _exit(int status)
{
    syscall1(SYS_exit, status);
    __builtin_unreachable();
}

EXPORT int fork(void)
{
    return (int)_check(syscall0(SYS_fork));
}

EXPORT int execve(const char *pathname, char *const argv[], char *const envp[])
{
    return (int)_check(syscall3(SYS_execve, pathname, argv, envp));
}

EXPORT int getpid(void)
{
    return (int)syscall0(SYS_getpid);
}

EXPORT int getuid(void)
{
    return (int)syscall0(SYS_getuid);
}

EXPORT int geteuid(void)
{
    return (int)syscall0(SYS_geteuid);
}

EXPORT int setuid(int uid)
{
    return (int)_check(syscall1(SYS_setuid, uid));
}

EXPORT int setgid(int gid)
{
    return (int)_check(syscall1(SYS_setgid, gid));
}

EXPORT int getgid(void)
{
    return (int)syscall0(SYS_getgid);
}

EXPORT int getppid(void)
{
    return (int)syscall0(SYS_getppid_nr);
}

EXPORT int gethostname(char *name, unsigned long namelen)
{
    /* Read hostname from /etc/hostname, fallback to "kiseki" */
    int fd = (int)_check(syscall3(SYS_open, "/etc/hostname", 0 /*O_RDONLY*/, 0));
    if (fd >= 0) {
        long n = (long)syscall3(SYS_read, fd, name, namelen - 1);
        syscall1(SYS_close, fd);
        if (n > 0) {
            /* Strip trailing newline */
            if (name[n - 1] == '\n') n--;
            name[n] = '\0';
            return 0;
        }
    }
    /* Fallback */
    const char *def = "kiseki";
    unsigned long len = 6;
    if (len >= namelen) len = namelen - 1;
    for (unsigned long i = 0; i < len; i++)
        name[i] = def[i];
    name[len] = '\0';
    return 0;
}

EXPORT int kill(int pid, int sig)
{
    return (int)_check(syscall2(SYS_kill, pid, sig));
}

EXPORT int wait4(int pid, int *status, int options, void *rusage)
{
    return (int)_check(syscall4(SYS_wait4, pid, status, options, rusage));
}

/* ============================================================================
 * Memory allocator
 *
 * Free-list allocator backed by mmap. Each block has a header with
 * size and free flag. Freed blocks are coalesced.
 * ============================================================================ */

#define BLOCK_MAGIC     0xA110CA7EUL
#define MIN_ALLOC_SIZE  16
#define MMAP_MIN_SIZE   65536

typedef struct block_header {
    size_t              size;
    struct block_header *next;
    uint32_t            magic;
    uint32_t            free;
} block_header_t;

#define HEADER_SIZE sizeof(block_header_t)

static block_header_t *_heap_head = NULL;

static inline size_t _align16(size_t n) { return (n + 15) & ~(size_t)15; }

static void *_mmap_pages(size_t size)
{
    size_t pages = (size + 4095) & ~(size_t)4095;
    if (pages < MMAP_MIN_SIZE)
        pages = MMAP_MIN_SIZE;

    long ret = syscall6(SYS_mmap, 0, pages, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANON, -1, 0);
    if (ret < 0)
        return NULL;
    return (void *)ret;
}

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

static void _split_block(block_header_t *block, size_t size)
{
    if (block->size >= size + HEADER_SIZE + MIN_ALLOC_SIZE) {
        block_header_t *nb = (block_header_t *)((char *)block + HEADER_SIZE + size);
        nb->size = block->size - size - HEADER_SIZE;
        nb->next = block->next;
        nb->magic = BLOCK_MAGIC;
        nb->free = 1;
        block->size = size;
        block->next = nb;
    }
}

static void _coalesce(void)
{
    block_header_t *cur = _heap_head;
    while (cur && cur->next) {
        if (cur->free && cur->next->free) {
            cur->size += HEADER_SIZE + cur->next->size;
            cur->next = cur->next->next;
        } else {
            cur = cur->next;
        }
    }
}

EXPORT void *malloc(size_t size)
{
    if (size == 0)
        return NULL;

    size = _align16(size);

    block_header_t *block = _find_free(size);
    if (block) {
        _split_block(block, size);
        block->free = 0;
        return (char *)block + HEADER_SIZE;
    }

    size_t alloc_size = HEADER_SIZE + size;
    size_t mmap_size = alloc_size < MMAP_MIN_SIZE ? MMAP_MIN_SIZE : alloc_size;

    void *mem = _mmap_pages(mmap_size);
    if (mem == NULL) {
        errno = ENOMEM;
        return NULL;
    }

    block = (block_header_t *)mem;
    /* Use actual mapped size (page-aligned) */
    size_t actual = (mmap_size + 4095) & ~(size_t)4095;
    if (actual < MMAP_MIN_SIZE)
        actual = MMAP_MIN_SIZE;
    block->size = actual - HEADER_SIZE;
    block->next = _heap_head;
    block->magic = BLOCK_MAGIC;
    block->free = 0;
    _heap_head = block;

    _split_block(block, size);
    return (char *)block + HEADER_SIZE;
}

EXPORT void free(void *ptr)
{
    if (ptr == NULL)
        return;
    block_header_t *block = (block_header_t *)((char *)ptr - HEADER_SIZE);
    if (block->magic != BLOCK_MAGIC)
        return;
    block->free = 1;
    _coalesce();
}

EXPORT void *realloc(void *ptr, size_t size)
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

    if (block->size >= size) {
        _split_block(block, size);
        return ptr;
    }

    /* Try merging with next block */
    if (block->next && block->next->free &&
        block->size + HEADER_SIZE + block->next->size >= size) {
        block->size += HEADER_SIZE + block->next->size;
        block->next = block->next->next;
        _split_block(block, size);
        return ptr;
    }

    void *new_ptr = malloc(size);
    if (new_ptr == NULL)
        return NULL;
    memcpy(new_ptr, ptr, block->size < size ? block->size : size);
    free(ptr);
    return new_ptr;
}

EXPORT void *calloc(size_t nmemb, size_t size)
{
    size_t total = nmemb * size;
    if (nmemb != 0 && total / nmemb != size) {
        errno = ENOMEM;
        return NULL;
    }
    void *ptr = malloc(total);
    if (ptr)
        memset(ptr, 0, total);
    return ptr;
}

/* atexit registration (exit/abort defined later, after fflush) */

#define MAX_ATEXIT 32
static void (*_atexit_funcs[MAX_ATEXIT])(void);
static int _atexit_count = 0;

EXPORT int atexit(void (*func)(void))
{
    if (_atexit_count >= MAX_ATEXIT)
        return -1;
    _atexit_funcs[_atexit_count++] = func;
    return 0;
}

/* ============================================================================
 * String to number conversion
 * ============================================================================ */

static inline int _isspace(int c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

static inline int _digit_val(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'z') return c - 'a' + 10;
    if (c >= 'A' && c <= 'Z') return c - 'A' + 10;
    return -1;
}

EXPORT unsigned long strtoul(const char *nptr, char **endptr, int base)
{
    const char *s = nptr;
    unsigned long result = 0;
    int neg = 0;

    while (_isspace(*s)) s++;

    if (*s == '-') { neg = 1; s++; }
    else if (*s == '+') { s++; }

    if (base == 0) {
        if (*s == '0') {
            s++;
            if (*s == 'x' || *s == 'X') { base = 16; s++; }
            else { base = 8; }
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
        if (d < 0 || d >= base) break;
        if (result > cutoff || (result == cutoff && d > cutlim))
            overflow = 1;
        result = result * (unsigned long)base + (unsigned long)d;
        s++;
    }

    if (s == start) {
        if (endptr) *endptr = (char *)nptr;
        return 0;
    }

    if (endptr) *endptr = (char *)s;

    if (overflow) {
        errno = ERANGE;
        return ULONG_MAX;
    }

    return neg ? (unsigned long)(-(long)result) : result;
}

EXPORT long strtol(const char *nptr, char **endptr, int base)
{
    const char *s = nptr;
    int neg = 0;

    while (_isspace(*s)) s++;

    if (*s == '-') { neg = 1; s++; }
    else if (*s == '+') { s++; }

    unsigned long uval = strtoul(s, endptr, base);

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

EXPORT int atoi(const char *nptr) { return (int)strtol(nptr, NULL, 10); }
EXPORT long atol(const char *nptr) { return strtol(nptr, NULL, 10); }

/* ============================================================================
 * FILE I/O
 * ============================================================================ */

/* FILE flags */
#define _F_READ     0x01
#define _F_WRITE    0x02
#define _F_APPEND   0x04
#define _F_EOF      0x08
#define _F_ERROR    0x10
#define _F_UNBUF    0x20
#define _F_LINEBUF  0x40
#define _F_MYBUF    0x80

typedef struct _kiseki_FILE {
    int     fd;
    int     flags;
    char    *buf;
    size_t  bufsiz;
    size_t  buf_pos;
    size_t  buf_len;
    int     ungetc_buf;
} FILE;

static FILE _stdin_file  = { 0, _F_READ  | _F_LINEBUF, NULL, 0, 0, 0, EOF };
static FILE _stdout_file = { 1, _F_WRITE | _F_LINEBUF, NULL, 0, 0, 0, EOF };
static FILE _stderr_file = { 2, _F_WRITE | _F_UNBUF,   NULL, 0, 0, 0, EOF };

/*
 * Export under both standard and Apple names.
 * macOS <stdio.h> defines: #define stdin __stdinp, etc.
 * So binaries compiled against the macOS SDK import ___stdinp, not _stdin.
 * We export both names for compatibility.
 */
EXPORT FILE *__stdinp  = &_stdin_file;
EXPORT FILE *__stdoutp = &_stdout_file;
EXPORT FILE *__stderrp = &_stderr_file;

/* Also export the standard names for code that doesn't use macOS headers */
EXPORT FILE *stdin  = &_stdin_file;
EXPORT FILE *stdout = &_stdout_file;
EXPORT FILE *stderr = &_stderr_file;

/* File table for fopen */
static FILE _file_table[FOPEN_MAX];
static int  _file_table_inited = 0;

static void _init_file_table(void)
{
    if (_file_table_inited) return;
    for (int i = 0; i < FOPEN_MAX; i++)
        _file_table[i].fd = -1;
    _file_table_inited = 1;
}

static FILE *_alloc_file(void)
{
    _init_file_table();
    for (int i = 0; i < FOPEN_MAX; i++) {
        if (_file_table[i].fd == -1)
            return &_file_table[i];
    }
    return NULL;
}

/* ============================================================================
 * fflush
 * ============================================================================ */

EXPORT int fflush(FILE *stream)
{
    if (stream == NULL) {
        fflush(stdout);
        fflush(stderr);
        for (int i = 0; i < FOPEN_MAX; i++) {
            if (_file_table[i].fd >= 0 && (_file_table[i].flags & _F_WRITE))
                fflush(&_file_table[i]);
        }
        return 0;
    }

    if (!(stream->flags & _F_WRITE)) return 0;

    if (stream->buf && stream->buf_pos > 0) {
        ssize_t ret = write(stream->fd, stream->buf, stream->buf_pos);
        if (ret < 0) {
            stream->flags |= _F_ERROR;
            return EOF;
        }
        stream->buf_pos = 0;
    }
    return 0;
}

/* ============================================================================
 * exit / abort (defined here after fflush so we can call fflush(NULL))
 * ============================================================================ */

EXPORT NORETURN void exit(int status)
{
    /* Call atexit handlers in reverse */
    while (_atexit_count > 0) {
        _atexit_count--;
        if (_atexit_funcs[_atexit_count])
            _atexit_funcs[_atexit_count]();
    }
    /* Flush all stdio streams */
    fflush(NULL);
    _exit(status);
    __builtin_unreachable();
}

EXPORT NORETURN void abort(void)
{
    static const char msg[] = "Abort\n";
    syscall3(SYS_write, 2, (long)msg, sizeof(msg) - 1);
    _exit(134); /* 128 + SIGABRT(6) */
    __builtin_unreachable();
}

static void _ensure_write_buf(FILE *stream)
{
    if (stream->buf == NULL && !(stream->flags & _F_UNBUF)) {
        stream->buf = (char *)malloc(BUFSIZ);
        if (stream->buf) {
            stream->bufsiz = BUFSIZ;
            stream->flags |= _F_MYBUF;
        }
    }
}

/* ============================================================================
 * Character I/O
 * ============================================================================ */

EXPORT int fputc(int c, FILE *stream)
{
    unsigned char ch = (unsigned char)c;

    if (stream->flags & _F_UNBUF) {
        ssize_t ret = write(stream->fd, &ch, 1);
        if (ret != 1) { stream->flags |= _F_ERROR; return EOF; }
        return ch;
    }

    _ensure_write_buf(stream);

    if (stream->buf == NULL) {
        ssize_t ret = write(stream->fd, &ch, 1);
        return ret == 1 ? ch : EOF;
    }

    stream->buf[stream->buf_pos++] = ch;

    if (stream->buf_pos >= stream->bufsiz ||
        ((stream->flags & _F_LINEBUF) && ch == '\n')) {
        if (fflush(stream) == EOF) return EOF;
    }

    return ch;
}

EXPORT int putchar(int c) { return fputc(c, stdout); }

EXPORT int fputs(const char *s, FILE *stream)
{
    while (*s) {
        if (fputc(*s++, stream) == EOF) return EOF;
    }
    return 0;
}

EXPORT int puts(const char *s)
{
    if (fputs(s, stdout) == EOF) return EOF;
    if (fputc('\n', stdout) == EOF) return EOF;
    return 0;
}

EXPORT int fgetc(FILE *stream)
{
    if (stream->ungetc_buf != EOF) {
        int c = stream->ungetc_buf;
        stream->ungetc_buf = EOF;
        return c;
    }
    unsigned char ch;
    ssize_t ret = read(stream->fd, &ch, 1);
    if (ret <= 0) {
        stream->flags |= (ret == 0) ? _F_EOF : _F_ERROR;
        return EOF;
    }
    return ch;
}

EXPORT int getchar(void) { return fgetc(stdin); }

EXPORT int ungetc(int c, FILE *stream)
{
    if (c == EOF) return EOF;
    stream->ungetc_buf = c;
    stream->flags &= ~_F_EOF;
    return c;
}

EXPORT char *fgets(char *s, int size, FILE *stream)
{
    if (size <= 0) return NULL;
    if (size == 1) { s[0] = '\0'; return s; }
    char *p = s;
    int n = size - 1;
    while (n > 0) {
        int c = fgetc(stream);
        if (c == EOF) {
            if (p == s) return NULL;
            break;
        }
        *p++ = (char)c;
        n--;
        if (c == '\n') break;
    }
    *p = '\0';
    return s;
}

/* ============================================================================
 * File open/close
 * ============================================================================ */

static int _parse_mode(const char *mode, int *oflags)
{
    int f = 0;
    int ff = 0;

    switch (*mode) {
    case 'r': f = O_RDONLY; ff = _F_READ; break;
    case 'w': f = O_WRONLY | O_CREAT | O_TRUNC; ff = _F_WRITE; break;
    case 'a': f = O_WRONLY | O_CREAT | O_APPEND; ff = _F_WRITE | _F_APPEND; break;
    default: return -1;
    }
    mode++;
    if (*mode == 'b') mode++;
    if (*mode == '+') {
        f = (f & ~(O_RDONLY | O_WRONLY)) | O_RDWR;
        ff |= _F_READ | _F_WRITE;
        mode++;
    }
    if (*mode == 'b') mode++;
    *oflags = f;
    return ff;
}

EXPORT FILE *fopen(const char *pathname, const char *mode)
{
    int oflags;
    int file_flags = _parse_mode(mode, &oflags);
    if (file_flags < 0) { errno = EINVAL; return NULL; }

    int fd = open(pathname, oflags, 0666);
    if (fd < 0) return NULL;

    FILE *fp = _alloc_file();
    if (fp == NULL) { close(fd); errno = EMFILE; return NULL; }

    fp->fd = fd;
    fp->flags = file_flags;
    fp->buf = NULL;
    fp->bufsiz = 0;
    fp->buf_pos = 0;
    fp->buf_len = 0;
    fp->ungetc_buf = EOF;
    return fp;
}

EXPORT int fclose(FILE *stream)
{
    if (stream == NULL) return EOF;
    fflush(stream);
    int ret = close(stream->fd);
    if (stream->flags & _F_MYBUF)
        free(stream->buf);
    stream->fd = -1;
    stream->buf = NULL;
    stream->flags = 0;
    return ret < 0 ? EOF : 0;
}

EXPORT size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    size_t total = size * nmemb;
    if (total == 0) return 0;

    unsigned char *buf = (unsigned char *)ptr;
    size_t done = 0;
    while (done < total) {
        int c = fgetc(stream);
        if (c == EOF) break;
        buf[done++] = (unsigned char)c;
    }
    return done / size;
}

EXPORT size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    size_t total = size * nmemb;
    if (total == 0) return 0;

    const unsigned char *buf = (const unsigned char *)ptr;
    size_t done = 0;
    while (done < total) {
        if (fputc(buf[done], stream) == EOF) break;
        done++;
    }
    return done / size;
}

EXPORT int fseek(FILE *stream, long offset, int whence)
{
    fflush(stream);
    stream->buf_pos = 0;
    stream->buf_len = 0;
    stream->ungetc_buf = EOF;
    stream->flags &= ~(_F_EOF | _F_ERROR);
    off_t ret = lseek(stream->fd, (off_t)offset, whence);
    return ret < 0 ? -1 : 0;
}

EXPORT long ftell(FILE *stream)
{
    off_t pos = lseek(stream->fd, 0, SEEK_CUR);
    if (pos < 0) return -1L;
    if (stream->flags & _F_WRITE)
        pos += (off_t)stream->buf_pos;
    return (long)pos;
}

EXPORT int feof(FILE *stream) { return (stream->flags & _F_EOF) ? 1 : 0; }
EXPORT int ferror(FILE *stream) { return (stream->flags & _F_ERROR) ? 1 : 0; }
EXPORT void clearerr(FILE *stream) { stream->flags &= ~(_F_EOF | _F_ERROR); }
EXPORT int fileno(FILE *stream) { return stream->fd; }

/* ============================================================================
 * printf engine
 *
 * Supports: %d %i %u %x %X %o %s %c %p %ld %lu %lx %lX %lld %llu %n %%
 * Width, precision, zero-padding, left-align, plus, space, hash
 * ============================================================================ */

typedef struct {
    void (*putch)(char c, void *ctx);
    void *ctx;
    int count;
} _fmt_out;

static void _fmt_emit(_fmt_out *out, char c) { out->putch(c, out->ctx); out->count++; }

static void _fmt_pad(_fmt_out *out, char c, int n) { while (n-- > 0) _fmt_emit(out, c); }

static void _fmt_puts(_fmt_out *out, const char *s, int width, int prec, int left)
{
    size_t len = strlen(s);
    if (prec >= 0 && (size_t)prec < len) len = (size_t)prec;
    int pad = width - (int)len;
    if (pad < 0) pad = 0;
    if (!left) _fmt_pad(out, ' ', pad);
    for (size_t i = 0; i < len; i++) _fmt_emit(out, s[i]);
    if (left) _fmt_pad(out, ' ', pad);
}

static void _fmt_num(_fmt_out *out, uint64_t val, int base,
                     int is_signed, int is_neg,
                     int width, int prec, int left,
                     int zeropad, int plus, int space,
                     int hash, int upper)
{
    char buf[66];
    char *p = buf + sizeof(buf);
    *--p = '\0';
    const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";

    if (val == 0) {
        if (prec != 0) *--p = '0';
    } else {
        while (val > 0) { *--p = digits[val % (unsigned)base]; val /= (unsigned)base; }
    }

    int num_digits = (int)(buf + sizeof(buf) - 1 - p);
    int prec_pad = 0;
    if (prec > num_digits) prec_pad = prec - num_digits;

    const char *prefix = "";
    int prefix_len = 0;
    if (hash) {
        if (base == 8 && prec_pad == 0 && num_digits > 0) {
            prefix = "0"; prefix_len = 1;
        } else if (base == 16 && num_digits > 0) {
            prefix = upper ? "0X" : "0x"; prefix_len = 2;
        }
    }

    char sign_ch = 0;
    if (is_signed) {
        if (is_neg) sign_ch = '-';
        else if (plus) sign_ch = '+';
        else if (space) sign_ch = ' ';
    }

    int sign_len = sign_ch ? 1 : 0;
    int total = sign_len + prefix_len + prec_pad + num_digits;
    int pad = width - total;
    if (pad < 0) pad = 0;

    if (!left && !zeropad) _fmt_pad(out, ' ', pad);
    if (sign_ch) _fmt_emit(out, sign_ch);
    for (int i = 0; i < prefix_len; i++) _fmt_emit(out, prefix[i]);
    if (!left && zeropad) _fmt_pad(out, '0', pad);
    _fmt_pad(out, '0', prec_pad);
    while (*p) _fmt_emit(out, *p++);
    if (left) _fmt_pad(out, ' ', pad);
}

static int _fmt_core(_fmt_out *out, const char *fmt, va_list ap)
{
    out->count = 0;

    while (*fmt) {
        if (*fmt != '%') { _fmt_emit(out, *fmt++); continue; }
        fmt++;

        /* Flags */
        int left = 0, zeropad = 0, plus = 0, space = 0, hash = 0;
        for (;;) {
            if      (*fmt == '-') { left = 1; fmt++; }
            else if (*fmt == '0') { zeropad = 1; fmt++; }
            else if (*fmt == '+') { plus = 1; fmt++; }
            else if (*fmt == ' ') { space = 1; fmt++; }
            else if (*fmt == '#') { hash = 1; fmt++; }
            else break;
        }
        if (left) zeropad = 0;

        /* Width */
        int width = 0;
        if (*fmt == '*') {
            width = va_arg(ap, int);
            if (width < 0) { left = 1; width = -width; }
            fmt++;
        } else {
            while (*fmt >= '0' && *fmt <= '9') {
                width = width * 10 + (*fmt - '0');
                fmt++;
            }
        }

        /* Precision */
        int prec = -1;
        if (*fmt == '.') {
            fmt++;
            prec = 0;
            if (*fmt == '*') {
                prec = va_arg(ap, int);
                if (prec < 0) prec = -1;
                fmt++;
            } else {
                while (*fmt >= '0' && *fmt <= '9') {
                    prec = prec * 10 + (*fmt - '0');
                    fmt++;
                }
            }
            if (prec >= 0) zeropad = 0;
        }

        /* Length modifier */
        int length = 0; /* 0=int, 1=long, 2=long long */
        if (*fmt == 'l') {
            length = 1; fmt++;
            if (*fmt == 'l') { length = 2; fmt++; }
        } else if (*fmt == 'h') {
            length = -1; fmt++;
            if (*fmt == 'h') { length = -2; fmt++; }
        } else if (*fmt == 'z' || *fmt == 'j' || *fmt == 't') {
            length = 1; fmt++; /* size_t/intmax_t/ptrdiff_t = long on LP64 */
        }

        /* Conversion */
        switch (*fmt) {
        case 'd': case 'i': {
            int64_t val;
            if (length == 2) val = va_arg(ap, long long);
            else if (length == 1) val = va_arg(ap, long);
            else val = va_arg(ap, int);
            int neg = val < 0;
            uint64_t uval = neg ? (uint64_t)(-val) : (uint64_t)val;
            _fmt_num(out, uval, 10, 1, neg, width, prec, left, zeropad, plus, space, hash, 0);
            break;
        }
        case 'u': {
            uint64_t val;
            if (length == 2) val = va_arg(ap, unsigned long long);
            else if (length == 1) val = va_arg(ap, unsigned long);
            else val = va_arg(ap, unsigned int);
            _fmt_num(out, val, 10, 0, 0, width, prec, left, zeropad, plus, space, hash, 0);
            break;
        }
        case 'x': case 'X': {
            uint64_t val;
            if (length == 2) val = va_arg(ap, unsigned long long);
            else if (length == 1) val = va_arg(ap, unsigned long);
            else val = va_arg(ap, unsigned int);
            _fmt_num(out, val, 16, 0, 0, width, prec, left, zeropad, plus, space, hash, *fmt == 'X');
            break;
        }
        case 'o': {
            uint64_t val;
            if (length == 2) val = va_arg(ap, unsigned long long);
            else if (length == 1) val = va_arg(ap, unsigned long);
            else val = va_arg(ap, unsigned int);
            _fmt_num(out, val, 8, 0, 0, width, prec, left, zeropad, plus, space, hash, 0);
            break;
        }
        case 'p': {
            void *ptr = va_arg(ap, void *);
            if (ptr == NULL) {
                _fmt_puts(out, "0x0", width, -1, left);
            } else {
                /* emit 0x prefix then hex number */
                _fmt_emit(out, '0');
                _fmt_emit(out, 'x');
                _fmt_num(out, (uint64_t)(uintptr_t)ptr, 16, 0, 0,
                         width > 2 ? width - 2 : 0, prec, left, zeropad, 0, 0, 0, 0);
            }
            break;
        }
        case 's': {
            const char *s = va_arg(ap, const char *);
            if (s == NULL) s = "(null)";
            _fmt_puts(out, s, width, prec, left);
            break;
        }
        case 'c': {
            char c = (char)va_arg(ap, int);
            if (!left) _fmt_pad(out, ' ', width - 1);
            _fmt_emit(out, c);
            if (left) _fmt_pad(out, ' ', width - 1);
            break;
        }
        case '%':
            _fmt_emit(out, '%');
            break;
        case 'n': {
            if (length == 2) *va_arg(ap, long long *) = out->count;
            else if (length == 1) *va_arg(ap, long *) = out->count;
            else *va_arg(ap, int *) = out->count;
            break;
        }
        case '\0':
            return out->count;
        default:
            _fmt_emit(out, '%');
            _fmt_emit(out, *fmt);
            break;
        }
        fmt++;
    }
    return out->count;
}

/* --- FILE* output callback --- */
struct _file_ctx { FILE *fp; };
static void _file_putch(char c, void *ctx) {
    struct _file_ctx *fc = (struct _file_ctx *)ctx;
    fputc(c, fc->fp);
}

EXPORT int vfprintf(FILE *stream, const char *fmt, va_list ap)
{
    struct _file_ctx ctx = { .fp = stream };
    _fmt_out out = { .putch = _file_putch, .ctx = &ctx, .count = 0 };
    return _fmt_core(&out, fmt, ap);
}

EXPORT int fprintf(FILE *stream, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int ret = vfprintf(stream, fmt, ap);
    va_end(ap);
    return ret;
}

EXPORT int vprintf(const char *fmt, va_list ap)
{
    return vfprintf(stdout, fmt, ap);
}

EXPORT int printf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int ret = vprintf(fmt, ap);
    va_end(ap);
    return ret;
}

/* --- String output callback --- */
struct _str_ctx { char *buf; size_t size; size_t pos; };
static void _str_putch(char c, void *ctx) {
    struct _str_ctx *sc = (struct _str_ctx *)ctx;
    if (sc->pos + 1 < sc->size)
        sc->buf[sc->pos] = c;
    sc->pos++;
}

EXPORT int vsnprintf(char *str, size_t size, const char *fmt, va_list ap)
{
    struct _str_ctx ctx = { .buf = str, .size = size, .pos = 0 };
    _fmt_out out = { .putch = _str_putch, .ctx = &ctx, .count = 0 };
    int ret = _fmt_core(&out, fmt, ap);
    if (size > 0) {
        if (ctx.pos < size) str[ctx.pos] = '\0';
        else str[size - 1] = '\0';
    }
    return ret;
}

EXPORT int snprintf(char *str, size_t size, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int ret = vsnprintf(str, size, fmt, ap);
    va_end(ap);
    return ret;
}

EXPORT int vsprintf(char *str, const char *fmt, va_list ap)
{
    return vsnprintf(str, (size_t)-1, fmt, ap);
}

EXPORT int sprintf(char *str, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int ret = vsprintf(str, fmt, ap);
    va_end(ap);
    return ret;
}

/* ============================================================================
 * strerror / perror
 * ============================================================================ */

static const char *_errstr[] = {
    [0]         = "Success",
    [EPERM]     = "Operation not permitted",
    [ENOENT]    = "No such file or directory",
    [ESRCH]     = "No such process",
    [EINTR]     = "Interrupted system call",
    [EIO]       = "Input/output error",
    [ENXIO]     = "Device not configured",
    [E2BIG]     = "Argument list too long",
    [ENOEXEC]   = "Exec format error",
    [EBADF]     = "Bad file descriptor",
    [ECHILD]    = "No child processes",
    [EDEADLK]   = "Resource deadlock avoided",
    [ENOMEM]    = "Cannot allocate memory",
    [EACCES]    = "Permission denied",
    [EFAULT]    = "Bad address",
    [ENOTBLK]   = "Block device required",
    [EBUSY]     = "Device / Resource busy",
    [EEXIST]    = "File exists",
    [EXDEV]     = "Cross-device link",
    [ENODEV]    = "Operation not supported by device",
    [ENOTDIR]   = "Not a directory",
    [EISDIR]    = "Is a directory",
    [EINVAL]    = "Invalid argument",
    [ENFILE]    = "Too many open files in system",
    [EMFILE]    = "Too many open files",
    [ENOTTY]    = "Inappropriate ioctl for device",
    [ETXTBSY]   = "Text file busy",
    [EFBIG]     = "File too large",
    [ENOSPC]    = "No space left on device",
    [ESPIPE]    = "Illegal seek",
    [EROFS]     = "Read-only file system",
    [EMLINK]    = "Too many links",
    [EPIPE]     = "Broken pipe",
    [EDOM]      = "Numerical argument out of domain",
    [ERANGE]    = "Result too large",
    [EAGAIN]    = "Resource temporarily unavailable",
    [EINPROGRESS] = "Operation now in progress",
    [EALREADY]  = "Operation already in progress",
    [ENOTSOCK]  = "Socket operation on non-socket",
    [EDESTADDRREQ] = "Destination address required",
    [EMSGSIZE]  = "Message too long",
    [ENAMETOOLONG] = "File name too long",
    [ENOTEMPTY] = "Directory not empty",
    [ENOSYS]    = "Function not implemented",
};

#define NERRSTR (sizeof(_errstr) / sizeof(_errstr[0]))

static char _unknown_err[48];

EXPORT char *strerror(int errnum)
{
    if (errnum >= 0 && (size_t)errnum < NERRSTR && _errstr[errnum])
        return (char *)_errstr[errnum];

    /* Format "Unknown error: NNN" manually */
    char *p = _unknown_err;
    const char *pfx = "Unknown error: ";
    while (*pfx) *p++ = *pfx++;
    if (errnum < 0) { *p++ = '-'; errnum = -errnum; }
    char digs[12];
    int i = 0;
    do { digs[i++] = '0' + (errnum % 10); errnum /= 10; } while (errnum > 0);
    while (i > 0) *p++ = digs[--i];
    *p = '\0';
    return _unknown_err;
}

EXPORT void perror(const char *s)
{
    if (s && *s) {
        fputs(s, stderr);
        fputs(": ", stderr);
    }
    fputs(strerror(errno), stderr);
    fputc('\n', stderr);
}

/* ============================================================================
 * Environment
 * ============================================================================ */

/* environ is set by crt0 or by the dynamic linker */
EXPORT char **environ = NULL;

#define ENV_MAX 256
static char *_env_storage[ENV_MAX + 1];
static int _env_owns = 0;

static void _ensure_env(void)
{
    if (_env_owns) return;
    int i = 0;
    if (environ) {
        for (; environ[i] && i < ENV_MAX; i++)
            _env_storage[i] = environ[i];
    }
    _env_storage[i] = NULL;
    environ = _env_storage;
    _env_owns = 1;
}

EXPORT char *getenv(const char *name)
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

EXPORT int setenv(const char *name, const char *value, int overwrite)
{
    if (name == NULL || *name == '\0' || strchr(name, '=')) {
        errno = EINVAL;
        return -1;
    }

    _ensure_env();
    size_t nlen = strlen(name);

    /* Find existing */
    int i;
    for (i = 0; environ[i]; i++) {
        if (strncmp(environ[i], name, nlen) == 0 && environ[i][nlen] == '=') {
            if (!overwrite) return 0;
            size_t vlen = strlen(value);
            char *entry = (char *)malloc(nlen + 1 + vlen + 1);
            if (!entry) { errno = ENOMEM; return -1; }
            memcpy(entry, name, nlen);
            entry[nlen] = '=';
            memcpy(entry + nlen + 1, value, vlen + 1);
            environ[i] = entry;
            return 0;
        }
    }

    if (i >= ENV_MAX) { errno = ENOMEM; return -1; }

    size_t vlen = strlen(value);
    char *entry = (char *)malloc(nlen + 1 + vlen + 1);
    if (!entry) { errno = ENOMEM; return -1; }
    memcpy(entry, name, nlen);
    entry[nlen] = '=';
    memcpy(entry + nlen + 1, value, vlen + 1);
    environ[i] = entry;
    environ[i + 1] = NULL;
    return 0;
}

/* ============================================================================
 * sysctl
 * ============================================================================ */

EXPORT int sysctl(int *name, unsigned int namelen, void *oldp,
                  size_t *oldlenp, void *newp, size_t newlen)
{
    return (int)_check(syscall6(SYS_sysctl, name, namelen, oldp, oldlenp, newp, newlen));
}

/* ============================================================================
 * ctype-like helpers (not full locale, but needed internally & by programs)
 * ============================================================================ */

EXPORT int isalpha(int c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
EXPORT int isdigit(int c) { return c >= '0' && c <= '9'; }
EXPORT int isalnum(int c) { return isalpha(c) || isdigit(c); }
EXPORT int isspace(int c) { return _isspace(c); }
EXPORT int isupper(int c) { return c >= 'A' && c <= 'Z'; }
EXPORT int islower(int c) { return c >= 'a' && c <= 'z'; }
EXPORT int isprint(int c) { return c >= 0x20 && c <= 0x7e; }
EXPORT int iscntrl(int c) { return (c >= 0 && c < 0x20) || c == 0x7f; }
EXPORT int ispunct(int c) { return isprint(c) && !isalnum(c) && !isspace(c); }
EXPORT int isxdigit(int c) { return isdigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }
EXPORT int toupper(int c) { return (c >= 'a' && c <= 'z') ? c - 32 : c; }
EXPORT int tolower(int c) { return (c >= 'A' && c <= 'Z') ? c + 32 : c; }

/* ============================================================================
 * Miscellaneous C library functions
 * ============================================================================ */

EXPORT int abs(int j) { return j < 0 ? -j : j; }
EXPORT long labs(long j) { return j < 0 ? -j : j; }

EXPORT void qsort(void *base, size_t nmemb, size_t size,
                  int (*compar)(const void *, const void *))
{
    if (base == NULL || nmemb <= 1 || size == 0 || compar == NULL) return;

    /* Simple insertion sort - correct for any size */
    unsigned char *arr = (unsigned char *)base;
    for (size_t i = 1; i < nmemb; i++) {
        size_t j = i;
        while (j > 0 && compar(arr + j * size, arr + (j - 1) * size) < 0) {
            /* swap */
            for (size_t k = 0; k < size; k++) {
                unsigned char t = arr[j * size + k];
                arr[j * size + k] = arr[(j - 1) * size + k];
                arr[(j - 1) * size + k] = t;
            }
            j--;
        }
    }
}

EXPORT void *bsearch(const void *key, const void *base, size_t nmemb,
                     size_t size, int (*compar)(const void *, const void *))
{
    const unsigned char *arr = (const unsigned char *)base;
    size_t lo = 0, hi = nmemb;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int cmp = compar(key, arr + mid * size);
        if (cmp < 0) hi = mid;
        else if (cmp > 0) lo = mid + 1;
        else return (void *)(arr + mid * size);
    }
    return NULL;
}

/* Random number generator (simple LCG) */
static unsigned int _rand_state = 1;
EXPORT int rand(void) {
    _rand_state = _rand_state * 1103515245 + 12345;
    return (int)((_rand_state >> 16) & 0x7fffffff);
}
EXPORT void srand(unsigned int seed) { _rand_state = seed; }

/* strtok */
static char *_strtok_last = NULL;

EXPORT char *strtok(char *str, const char *delim)
{
    if (str == NULL) str = _strtok_last;
    if (str == NULL) return NULL;

    str += strspn(str, delim);
    if (*str == '\0') { _strtok_last = NULL; return NULL; }

    char *start = str;
    str += strcspn(str, delim);
    if (*str) { *str = '\0'; _strtok_last = str + 1; }
    else { _strtok_last = NULL; }
    return start;
}

/* strtok_r */
EXPORT char *strtok_r(char *str, const char *delim, char **saveptr)
{
    if (str == NULL) str = *saveptr;
    if (str == NULL) return NULL;

    str += strspn(str, delim);
    if (*str == '\0') { *saveptr = NULL; return NULL; }

    char *start = str;
    str += strcspn(str, delim);
    if (*str) { *str = '\0'; *saveptr = str + 1; }
    else { *saveptr = NULL; }
    return start;
}

/* strndup */
EXPORT char *strndup(const char *s, size_t n)
{
    size_t len = strlen(s);
    if (len > n) len = n;
    char *dup = (char *)malloc(len + 1);
    if (dup) { memcpy(dup, s, len); dup[len] = '\0'; }
    return dup;
}

/* strpbrk */
EXPORT char *strpbrk(const char *s, const char *accept)
{
    while (*s) {
        const char *a = accept;
        while (*a) { if (*s == *a) return (char *)s; a++; }
        s++;
    }
    return NULL;
}

/* strtoll / strtoull */
EXPORT long long strtoll(const char *nptr, char **endptr, int base)
{
    return (long long)strtol(nptr, endptr, base);
}

EXPORT unsigned long long strtoull(const char *nptr, char **endptr, int base)
{
    return (unsigned long long)strtoul(nptr, endptr, base);
}

/* itoa */
EXPORT char *itoa(int value, char *str, int base)
{
    if (base < 2 || base > 36) { *str = '\0'; return str; }
    char *p = str;
    int neg = 0;
    unsigned int uval;
    if (value < 0 && base == 10) { neg = 1; uval = (unsigned int)(-(value + 1)) + 1; }
    else { uval = (unsigned int)value; }

    char buf[34];
    int i = 0;
    do {
        int d = (int)(uval % (unsigned)base);
        buf[i++] = d < 10 ? '0' + d : 'a' + d - 10;
        uval /= (unsigned)base;
    } while (uval > 0);

    if (neg) *p++ = '-';
    while (i > 0) *p++ = buf[--i];
    *p = '\0';
    return str;
}

/* ============================================================================
 * sleep (minimal)
 * ============================================================================ */

/* We don't have SYS_nanosleep in the syscall numbers given, but programs
 * may reference sleep. Provide a busy-wait or no-op for now. */
struct _timespec { time_t tv_sec; long tv_nsec; };

#define SYS_nanosleep 240

EXPORT unsigned int sleep(unsigned int seconds)
{
    struct _timespec req = { seconds, 0 };
    struct _timespec rem = { 0, 0 };
    long ret = syscall2(SYS_nanosleep, &req, &rem);
    if (ret < 0) return (unsigned int)rem.tv_sec;
    return 0;
}

/* ============================================================================
 * signal (stubs)
 * ============================================================================ */

typedef void (*sighandler_t)(int);
#define SIG_DFL ((sighandler_t)0)
#define SIG_IGN ((sighandler_t)1)
#define SIG_ERR ((sighandler_t)-1)

EXPORT sighandler_t signal(int signum, sighandler_t handler)
{
    (void)signum;
    (void)handler;
    /* Stub: Kiseki signal handling is kernel-side */
    return SIG_DFL;
}

/* ============================================================================
 * Exported aliases and additional symbols
 *
 * Some binaries reference __exit (double underscore), which is _exit
 * in the symbol table (C name _exit -> symbol __exit).
 * Since we're defining C functions, clang will automatically prefix
 * with underscore. E.g., C "exit" -> symbol "_exit".
 * ============================================================================ */

/*
 * Note on symbol naming:
 *
 * In Mach-O, C symbols get a leading underscore automatically.
 * So our C function "printf" exports as "_printf" in the symbol table.
 * "exit" exports as "_exit", "__exit" exports as "___exit", etc.
 *
 * The following ensures all required symbols exist:
 * - _printf, _puts, _putchar   -> from printf(), puts(), putchar() above
 * - _exit, __exit              -> from exit() and _exit() above
 * - _write, _read, ...         -> from write(), read(), ... above
 * - _malloc, _free, ...        -> from malloc(), free(), ... above
 * - _errno                     -> from int errno above
 * - ___stack_chk_fail          -> from __stack_chk_fail() above
 * - ___stack_chk_guard         -> from unsigned long __stack_chk_guard above
 * - _dyld_stub_binder          -> from dyld_stub_binder() above
 * - ___bzero                   -> from __bzero() above
 * - _memset_pattern4/8/16      -> from memset_pattern4/8/16() above
 */

/* ============================================================================
 * Additional process / system stubs that common programs may need
 * ============================================================================ */

EXPORT int getegid(void)
{
    return (int)syscall0(SYS_getegid);
}

/* geteuid, getgid, getppid moved to process lifecycle section above */

/* ============================================================================
 * setjmp / longjmp stubs
 * These are typically implemented in assembly, but we provide minimal stubs.
 * Real programs needing these will need proper assembly implementations.
 * ============================================================================ */

typedef long jmp_buf[32]; /* Enough to save callee-saved regs on arm64 */

EXPORT int setjmp(jmp_buf buf)
{
    (void)buf;
    return 0; /* Stub */
}

EXPORT void longjmp(jmp_buf buf, int val)
{
    (void)buf;
    (void)val;
    abort(); /* Can't actually longjmp without proper asm support */
}

/* ============================================================================
 * __cxa_atexit (C++ ABI support - needed by some C programs too)
 * ============================================================================ */

EXPORT int __cxa_atexit(void (*func)(void *), void *arg, void *dso_handle)
{
    (void)arg;
    (void)dso_handle;
    /* Simplify: treat as atexit */
    return atexit((void (*)(void))func);
}

/* ============================================================================
 * Additional string functions
 * ============================================================================ */

EXPORT size_t strlcpy(char *dst, const char *src, size_t dstsize)
{
    size_t srclen = strlen(src);
    if (dstsize > 0) {
        size_t cplen = srclen < dstsize - 1 ? srclen : dstsize - 1;
        memcpy(dst, src, cplen);
        dst[cplen] = '\0';
    }
    return srclen;
}

EXPORT size_t strlcat(char *dst, const char *src, size_t dstsize)
{
    size_t dlen = strlen(dst);
    size_t slen = strlen(src);
    if (dlen >= dstsize) return dstsize + slen;
    size_t avail = dstsize - dlen - 1;
    size_t cplen = slen < avail ? slen : avail;
    memcpy(dst + dlen, src, cplen);
    dst[dlen + cplen] = '\0';
    return dlen + slen;
}

/* ============================================================================
 * sscanf (minimal implementation for %d %s %c %x)
 * ============================================================================ */

EXPORT int sscanf(const char *str, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    int count = 0;
    const char *s = str;

    while (*fmt && *s) {
        if (*fmt == '%') {
            fmt++;
            /* Skip width */
            while (*fmt >= '0' && *fmt <= '9') fmt++;

            switch (*fmt) {
            case 'd': case 'i': {
                int *p = va_arg(ap, int *);
                long val = strtol(s, (char **)&s, 10);
                *p = (int)val;
                count++;
                break;
            }
            case 'u': {
                unsigned int *p = va_arg(ap, unsigned int *);
                unsigned long val = strtoul(s, (char **)&s, 10);
                *p = (unsigned int)val;
                count++;
                break;
            }
            case 'x': case 'X': {
                unsigned int *p = va_arg(ap, unsigned int *);
                unsigned long val = strtoul(s, (char **)&s, 16);
                *p = (unsigned int)val;
                count++;
                break;
            }
            case 'l': {
                fmt++;
                if (*fmt == 'd') {
                    long *p = va_arg(ap, long *);
                    *p = strtol(s, (char **)&s, 10);
                    count++;
                } else if (*fmt == 'u') {
                    unsigned long *p = va_arg(ap, unsigned long *);
                    *p = strtoul(s, (char **)&s, 10);
                    count++;
                }
                break;
            }
            case 's': {
                char *p = va_arg(ap, char *);
                while (*s && _isspace(*s)) s++;
                while (*s && !_isspace(*s)) *p++ = *s++;
                *p = '\0';
                count++;
                break;
            }
            case 'c': {
                char *p = va_arg(ap, char *);
                *p = *s++;
                count++;
                break;
            }
            case '%':
                if (*s == '%') s++;
                else goto done;
                break;
            default:
                goto done;
            }
            fmt++;
        } else if (_isspace(*fmt)) {
            while (_isspace(*fmt)) fmt++;
            while (_isspace(*s)) s++;
        } else {
            if (*s != *fmt) break;
            s++;
            fmt++;
        }
    }
done:
    va_end(ap);
    return count;
}

/* ============================================================================
 * rewind / remove / rename (stdio)
 * ============================================================================ */

EXPORT void rewind(FILE *stream)
{
    fseek(stream, 0L, SEEK_SET);
    stream->flags &= ~_F_ERROR;
}

EXPORT int remove(const char *pathname)
{
    /* Try unlink, then rmdir */
    long ret = syscall1(10 /* SYS_unlink */, pathname);
    if (ret < 0)
        ret = syscall1(137 /* SYS_rmdir */, pathname);
    if (ret < 0) {
        errno = (int)(-ret);
        return -1;
    }
    return 0;
}

/* ============================================================================
 * access / unlink / chdir / getcwd (POSIX)
 * ============================================================================ */

EXPORT int access(const char *pathname, int mode)
{
    return (int)_check(syscall2(33 /* SYS_access */, pathname, mode));
}

EXPORT int unlink(const char *pathname)
{
    return (int)_check(syscall1(10 /* SYS_unlink */, pathname));
}

EXPORT int chdir(const char *path)
{
    return (int)_check(syscall1(12 /* SYS_chdir */, path));
}

EXPORT char *getcwd(char *buf, size_t size)
{
    long ret = syscall2(304 /* SYS_getcwd */, buf, size);
    if (ret < 0) { errno = (int)(-ret); return NULL; }
    return buf;
}

EXPORT int mkdir(const char *pathname, unsigned int mode)
{
    return (int)_check(syscall2(136 /* SYS_mkdir */, pathname, mode));
}

EXPORT int rmdir(const char *pathname)
{
    return (int)_check(syscall1(137 /* SYS_rmdir */, pathname));
}

EXPORT int chmod(const char *pathname, unsigned int mode)
{
    return (int)_check(syscall2(15 /* SYS_chmod */, pathname, mode));
}

EXPORT int link(const char *oldpath, const char *newpath)
{
    return (int)_check(syscall2(9 /* SYS_link */, oldpath, newpath));
}

EXPORT int symlink(const char *target, const char *linkpath)
{
    return (int)_check(syscall2(57 /* SYS_symlink */, target, linkpath));
}

EXPORT ssize_t readlink(const char *pathname, char *buf, size_t bufsiz)
{
    return (ssize_t)_check(syscall3(58 /* SYS_readlink */, pathname, buf, bufsiz));
}

/* ============================================================================
 * dup2 / fcntl
 * ============================================================================ */

EXPORT int dup2(int oldfd, int newfd)
{
    return (int)_check(syscall2(90 /* SYS_dup2 */, oldfd, newfd));
}

EXPORT int fcntl(int fd, int cmd, ...)
{
    va_list ap;
    va_start(ap, cmd);
    long arg = va_arg(ap, long);
    va_end(ap);
    return (int)_check(syscall3(92 /* SYS_fcntl */, fd, cmd, arg));
}

/* ============================================================================
 * stat / lstat / fstat wrappers
 * ============================================================================ */

EXPORT int stat(const char *pathname, void *statbuf)
{
    return (int)_check(syscall2(338 /* SYS_stat */, pathname, statbuf));
}

EXPORT int lstat(const char *pathname, void *statbuf)
{
    return (int)_check(syscall2(340 /* SYS_lstat */, pathname, statbuf));
}

EXPORT int statfs(const char *path, void *buf)
{
    return (int)_check(syscall2(157 /* SYS_statfs */, path, buf));
}

EXPORT int fstatfs(int fd, void *buf)
{
    return (int)_check(syscall2(158 /* SYS_fstatfs */, fd, buf));
}

EXPORT int fchmod(int fd, unsigned int mode)
{
    return (int)_check(syscall2(124 /* SYS_fchmod */, fd, mode));
}

EXPORT int gettimeofday(void *tv, void *tz)
{
    return (int)_check(syscall2(116 /* SYS_gettimeofday */, tv, tz));
}

EXPORT int settimeofday(const void *tv, const void *tz)
{
    return (int)_check(syscall2(122 /* SYS_settimeofday */, tv, tz));
}

/* ============================================================================
 * waitpid / wait
 * ============================================================================ */

EXPORT int waitpid(int pid, int *status, int options)
{
    return wait4(pid, status, options, NULL);
}

/* ============================================================================
 * pread / pwrite
 * ============================================================================ */

EXPORT ssize_t pread(int fd, void *buf, size_t count, off_t offset)
{
    return (ssize_t)_check(syscall4(173 /* SYS_pread */, fd, buf, count, offset));
}

EXPORT ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset)
{
    return (ssize_t)_check(syscall4(174 /* SYS_pwrite */, fd, buf, count, offset));
}

/* ============================================================================
 * select (stub)
 * ============================================================================ */

EXPORT int select(int nfds, void *readfds, void *writefds, void *exceptfds,
                  void *timeout)
{
    return (int)_check(syscall5(93 /* SYS_select */, nfds, readfds, writefds,
                                exceptfds, timeout));
}

/* ============================================================================
 * fdopen
 * ============================================================================ */

EXPORT FILE *fdopen(int fd, const char *mode)
{
    int oflags;
    int file_flags = _parse_mode(mode, &oflags);
    if (file_flags < 0) { errno = EINVAL; return NULL; }
    (void)oflags;

    FILE *fp = _alloc_file();
    if (fp == NULL) { errno = EMFILE; return NULL; }

    fp->fd = fd;
    fp->flags = file_flags;
    fp->buf = NULL;
    fp->bufsiz = 0;
    fp->buf_pos = 0;
    fp->buf_len = 0;
    fp->ungetc_buf = EOF;
    return fp;
}

/* ============================================================================
 * putc / getc (aliases)
 * ============================================================================ */

EXPORT int putc(int c, FILE *stream) { return fputc(c, stream); }
EXPORT int getc(FILE *stream) { return fgetc(stream); }

/* ============================================================================
 * dprintf
 * ============================================================================ */

struct _fd_ctx { int fd; };
static void _fd_putch(char c, void *ctx)
{
    struct _fd_ctx *fc = (struct _fd_ctx *)ctx;
    write(fc->fd, &c, 1);
}

EXPORT int dprintf(int fd, const char *fmt, ...)
{
    struct _fd_ctx ctx = { .fd = fd };
    _fmt_out out = { .putch = _fd_putch, .ctx = &ctx, .count = 0 };
    va_list ap;
    va_start(ap, fmt);
    int ret = _fmt_core(&out, fmt, ap);
    va_end(ap);
    return ret;
}

/* ============================================================================
 * setsid / setpgid / getpgrp
 * ============================================================================ */

EXPORT int setsid(void) { return (int)_check(syscall0(147)); }
EXPORT int setpgid(int pid, int pgid) { return (int)_check(syscall2(82, pid, pgid)); }
EXPORT int getpgrp(void) { return (int)syscall0(81); }

/* ============================================================================
 * execvp / execv
 * ============================================================================ */

EXPORT int execvp(const char *file, char *const argv[])
{
    if (strchr(file, '/'))
        return execve(file, argv, environ);

    const char *path = getenv("PATH");
    if (path == NULL) path = "/bin:/usr/bin";

    char buf[1024];
    const char *p = path;

    while (*p) {
        const char *end = p;
        while (*end && *end != ':') end++;

        size_t dirlen = (size_t)(end - p);
        if (dirlen == 0) { buf[0] = '.'; dirlen = 1; }
        else { if (dirlen >= 1022) dirlen = 1022; memcpy(buf, p, dirlen); }

        buf[dirlen] = '/';
        size_t flen = strlen(file);
        if (dirlen + 1 + flen >= 1024) { p = *end ? end + 1 : end; continue; }
        memcpy(buf + dirlen + 1, file, flen);
        buf[dirlen + 1 + flen] = '\0';

        execve(buf, argv, environ);
        p = *end ? end + 1 : end;
    }
    return -1;
}

EXPORT int execv(const char *pathname, char *const argv[])
{
    return execve(pathname, argv, environ);
}

/* ============================================================================
 * umask
 * ============================================================================ */

EXPORT unsigned int umask(unsigned int mask)
{
    return (unsigned int)syscall1(60 /* SYS_umask */, mask);
}

/* ============================================================================
 * nanosleep
 * ============================================================================ */

EXPORT int nanosleep(const struct _timespec *req, struct _timespec *rem)
{
    return (int)_check(syscall2(SYS_nanosleep, req, rem));
}

/* ============================================================================
 * usleep
 * ============================================================================ */

EXPORT int usleep(unsigned int usec)
{
    struct _timespec req = {
        .tv_sec = usec / 1000000,
        .tv_nsec = (long)(usec % 1000000) * 1000
    };
    long ret = syscall2(SYS_nanosleep, &req, NULL);
    if (ret < 0) { errno = (int)(-ret); return -1; }
    return 0;
}

/* ============================================================================
 * Fortified (_chk) string/memory functions
 *
 * macOS SDK headers rewrite memcpy/strcpy/strncpy/strcat/snprintf/memmove
 * into __*_chk variants when _FORTIFY_SOURCE is enabled (which it is by
 * default). These take an extra `dest_len` parameter from
 * __builtin_object_size. We just validate and delegate to the real function.
 * ============================================================================ */

EXPORT void *__memcpy_chk(void *dst, const void *src, size_t copy_len, size_t dst_len)
{
    if (copy_len > dst_len)
        __builtin_trap();
    return memcpy(dst, src, copy_len);
}

EXPORT void *__memmove_chk(void *dst, const void *src, size_t len, size_t dst_len)
{
    if (len > dst_len)
        __builtin_trap();
    return memmove(dst, src, len);
}

EXPORT char *__strcpy_chk(char *dst, const char *src, size_t dst_len)
{
    size_t src_len = strlen(src) + 1;
    if (src_len > dst_len)
        __builtin_trap();
    return strcpy(dst, src);
}

EXPORT char *__strncpy_chk(char *dst, const char *src, size_t len, size_t dst_len)
{
    if (len > dst_len)
        __builtin_trap();
    return strncpy(dst, src, len);
}

EXPORT char *__strcat_chk(char *dst, const char *src, size_t dst_len)
{
    size_t dlen = strlen(dst);
    size_t slen = strlen(src) + 1;
    if (dlen + slen > dst_len)
        __builtin_trap();
    return strcat(dst, src);
}

EXPORT int __snprintf_chk(char *str, size_t maxlen, int flags, size_t slen,
                          const char *fmt, ...)
{
    (void)flags;
    if (maxlen > slen)
        __builtin_trap();
    va_list ap;
    va_start(ap, fmt);
    int ret = vsnprintf(str, maxlen, fmt, ap);
    va_end(ap);
    return ret;
}

/* ============================================================================
 * unsetenv
 * ============================================================================ */

EXPORT int unsetenv(const char *name)
{
    if (name == NULL || *name == '\0' || strchr(name, '=')) {
        errno = EINVAL;
        return -1;
    }

    size_t nlen = strlen(name);
    char **ep = environ;
    if (!ep) return 0;

    while (*ep) {
        if (strncmp(*ep, name, nlen) == 0 && (*ep)[nlen] == '=') {
            /* Shift remaining entries down */
            char **p = ep;
            while (*p) { *p = *(p + 1); p++; }
        } else {
            ep++;
        }
    }
    return 0;
}

/* ============================================================================
 * termios (tcgetattr, tcsetattr, tcgetpgrp, tcsetpgrp)
 *
 * These use ioctl(2) to get/set terminal attributes via the kernel TTY layer.
 * Struct layout matches macOS arm64 exactly (72 bytes).
 * ============================================================================ */

/* Minimal termios struct — matches macOS arm64 layout */
typedef unsigned long tcflag_t;
typedef unsigned char cc_t;
typedef unsigned long speed_t;

#define NCCS 20

struct termios {
    tcflag_t c_iflag;
    tcflag_t c_oflag;
    tcflag_t c_cflag;
    tcflag_t c_lflag;
    cc_t     c_cc[NCCS];
    speed_t  c_ispeed;
    speed_t  c_ospeed;
};

/* ioctl commands — use hardcoded values matching macOS arm64 */
#define TIOCSETA    0x80487414UL
#define TIOCSETAW   0x80487415UL
#define TIOCSETAF   0x80487416UL
#define TIOCGPGRP   0x40047477UL
#define TIOCSPGRP   0x80047476UL

#define TCSANOW     0
#define TCSADRAIN   1
#define TCSAFLUSH   2

EXPORT int tcgetattr(int fd, struct termios *t)
{
    if (!t) { errno = EINVAL; return -1; }
    return (int)_check(syscall3(SYS_ioctl, fd, (long)TIOCGETA, (long)t));
}

EXPORT int tcsetattr(int fd, int optional_actions, const struct termios *t)
{
    if (!t) { errno = EINVAL; return -1; }
    unsigned long cmd;
    switch (optional_actions) {
    case TCSADRAIN:  cmd = TIOCSETAW; break;
    case TCSAFLUSH:  cmd = TIOCSETAF; break;
    default:         cmd = TIOCSETA;  break;
    }
    return (int)_check(syscall3(SYS_ioctl, fd, (long)cmd, (long)t));
}

EXPORT int tcgetpgrp(int fd)
{
    int pgrp = 0;
    long ret = syscall3(SYS_ioctl, fd, (long)TIOCGPGRP, (long)&pgrp);
    if (ret < 0) { errno = (int)(-ret); return -1; }
    return pgrp;
}

EXPORT int tcsetpgrp(int fd, int pgrp)
{
    return (int)_check(syscall3(SYS_ioctl, fd, (long)TIOCSPGRP, (long)&pgrp));
}

/* ============================================================================
 * sigaction
 * ============================================================================ */

struct sigaction_s {
    void     (*sa_handler)(int);
    void     (*sa_sigaction)(int, void *, void *);
    int      sa_mask;
    int      sa_flags;
};

EXPORT int sigaction(int signum, const struct sigaction_s *act, struct sigaction_s *oldact)
{
    (void)signum;
    if (oldact) {
        memset(oldact, 0, sizeof(*oldact));
        oldact->sa_handler = SIG_DFL;
    }
    (void)act;
    return 0;  /* Stub */
}

/* ============================================================================
 * Directory operations (opendir, readdir, closedir)
 *
 * These use the SYS_getdirentries syscall (196) under the hood.
 * For now, provide minimal stubs that bash can call without crashing.
 * We'll implement real directory reading when the kernel supports it.
 * ============================================================================ */

/*
 * Darwin arm64 dirent: 1048 bytes per entry.
 * d_ino(8), d_seekoff(8), d_reclen(2), d_namlen(2), d_type(1), d_name(1024)
 */
typedef struct _DIR {
    int    fd;
    char   buf[8192];    /* Must hold at least a few 1048-byte dirents */
    int    buflen;
    int    offset;
    int    eof;
} DIR;

struct dirent {
    unsigned long long d_ino;       /*   0: (8) */
    unsigned long long d_seekoff;   /*   8: (8) */
    unsigned short     d_reclen;    /*  16: (2) */
    unsigned short     d_namlen;    /*  18: (2) */
    unsigned char      d_type;      /*  20: (1) */
    char               d_name[1024];/*  21: (1024) */
};                                  /* 1048: Total */

/* SYS_getdirentries = 196 on XNU (not yet in our kernel) */
#ifndef SYS_getdirentries
#define SYS_getdirentries 196
#endif

/* O_RDONLY for open */
#ifndef O_RDONLY
#define O_RDONLY 0
#endif

/* O_DIRECTORY flag */
#ifndef O_DIRECTORY
#define O_DIRECTORY 0x100000
#endif

EXPORT DIR *opendir(const char *name)
{
    int fd = (int)_check(syscall3(SYS_open, (long)name, O_RDONLY, 0));
    if (fd < 0)
        return NULL;

    DIR *d = (DIR *)malloc(sizeof(DIR));
    if (!d) {
        syscall1(SYS_close, fd);
        return NULL;
    }
    d->fd = fd;
    d->buflen = 0;
    d->offset = 0;
    d->eof = 0;
    return d;
}

EXPORT struct dirent *readdir(DIR *d)
{
    if (!d || d->eof) return NULL;

    /* Need more data? */
    if (d->offset >= d->buflen) {
        long basep = 0;
        long n = syscall4(SYS_getdirentries, d->fd, (long)d->buf,
                         sizeof(d->buf), (long)&basep);
        if (n <= 0) {
            d->eof = 1;
            return NULL;
        }
        d->buflen = (int)n;
        d->offset = 0;
    }

    struct dirent *de = (struct dirent *)(d->buf + d->offset);
    if (de->d_reclen == 0) {
        d->eof = 1;
        return NULL;
    }
    d->offset += de->d_reclen;
    return de;
}

EXPORT int closedir(DIR *d)
{
    if (!d) return -1;
    int fd = d->fd;
    free(d);
    return (int)_check(syscall1(SYS_close, fd));
}

/* ============================================================================
 * Socket Functions (BSD Socket API)
 * ============================================================================ */

EXPORT int socket(int domain, int type, int protocol)
{
    return (int)_check(syscall3(97 /* SYS_socket */, domain, type, protocol));
}

EXPORT int bind(int sockfd, const void *addr, unsigned int addrlen)
{
    return (int)_check(syscall3(104 /* SYS_bind */, sockfd, addr, addrlen));
}

EXPORT int listen_sc(int sockfd, int backlog)
{
    return (int)_check(syscall2(106 /* SYS_listen */, sockfd, backlog));
}

/* listen is a reserved name in some contexts; we export both */
EXPORT int listen(int sockfd, int backlog)
{
    return (int)_check(syscall2(106 /* SYS_listen */, sockfd, backlog));
}

EXPORT int accept(int sockfd, void *addr, void *addrlen)
{
    return (int)_check(syscall3(30 /* SYS_accept */, sockfd, addr, addrlen));
}

EXPORT int connect(int sockfd, const void *addr, unsigned int addrlen)
{
    return (int)_check(syscall3(98 /* SYS_connect */, sockfd, addr, addrlen));
}

EXPORT long sendto(int sockfd, const void *buf, unsigned long len, int flags,
                   const void *dest_addr, unsigned int addrlen)
{
    return _check(syscall6(133 /* SYS_sendto */, sockfd, buf, len,
                           flags, dest_addr, addrlen));
}

EXPORT long recvfrom(int sockfd, void *buf, unsigned long len, int flags,
                     void *src_addr, void *addrlen)
{
    return _check(syscall6(29 /* SYS_recvfrom */, sockfd, buf, len,
                           flags, src_addr, addrlen));
}

EXPORT long send(int sockfd, const void *buf, unsigned long len, int flags)
{
    return sendto(sockfd, buf, len, flags, (void *)0, 0);
}

EXPORT long recv(int sockfd, void *buf, unsigned long len, int flags)
{
    return recvfrom(sockfd, buf, len, flags, (void *)0, (void *)0);
}

EXPORT int shutdown(int sockfd, int how)
{
    return (int)_check(syscall2(134 /* SYS_shutdown */, sockfd, how));
}

EXPORT int setsockopt(int sockfd, int level, int optname,
                      const void *optval, unsigned int optlen)
{
    return (int)_check(syscall5(105 /* SYS_setsockopt */, sockfd, level,
                                optname, optval, optlen));
}

EXPORT int getsockopt(int sockfd, int level, int optname,
                      void *optval, void *optlen)
{
    return (int)_check(syscall5(118 /* SYS_getsockopt */, sockfd, level,
                                optname, optval, optlen));
}

EXPORT int getpeername(int sockfd, void *addr, void *addrlen)
{
    return (int)_check(syscall3(31 /* SYS_getpeername */, sockfd, addr, addrlen));
}

EXPORT int getsockname(int sockfd, void *addr, void *addrlen)
{
    return (int)_check(syscall3(32 /* SYS_getsockname */, sockfd, addr, addrlen));
}

/* ============================================================================
 * Internet Address Functions
 * ============================================================================ */

static inline unsigned short _htons(unsigned short h)
{
    return (unsigned short)((h >> 8) | (h << 8));
}

static inline unsigned int _htonl(unsigned int h)
{
    return ((h & 0xFF000000U) >> 24) |
           ((h & 0x00FF0000U) >> 8)  |
           ((h & 0x0000FF00U) << 8)  |
           ((h & 0x000000FFU) << 24);
}

static inline unsigned int _ntohl(unsigned int n)
{
    return _htonl(n);
}

EXPORT unsigned short htons(unsigned short h) { return _htons(h); }
EXPORT unsigned short ntohs(unsigned short n) { return _htons(n); }
EXPORT unsigned int htonl(unsigned int h) { return _htonl(h); }
EXPORT unsigned int ntohl(unsigned int n) { return _htonl(n); }

/*
 * inet_addr - Convert "a.b.c.d" to network byte order uint32.
 */
EXPORT unsigned int inet_addr(const char *cp)
{
    unsigned int a = 0, b = 0, c = 0, d = 0;
    int i = 0;

    /* Parse a */
    while (cp[i] >= '0' && cp[i] <= '9')
        a = a * 10 + (unsigned int)(cp[i++] - '0');
    if (cp[i] != '.') return 0xFFFFFFFFU;
    i++;
    /* Parse b */
    while (cp[i] >= '0' && cp[i] <= '9')
        b = b * 10 + (unsigned int)(cp[i++] - '0');
    if (cp[i] != '.') return 0xFFFFFFFFU;
    i++;
    /* Parse c */
    while (cp[i] >= '0' && cp[i] <= '9')
        c = c * 10 + (unsigned int)(cp[i++] - '0');
    if (cp[i] != '.') return 0xFFFFFFFFU;
    i++;
    /* Parse d */
    while (cp[i] >= '0' && cp[i] <= '9')
        d = d * 10 + (unsigned int)(cp[i++] - '0');

    if (a > 255 || b > 255 || c > 255 || d > 255)
        return 0xFFFFFFFFU;

    return _htonl((a << 24) | (b << 16) | (c << 8) | d);
}

/*
 * inet_ntoa - Convert network address to dotted-decimal string.
 * Returns pointer to static buffer (not thread-safe).
 */
static char _inet_ntoa_buf[16];
EXPORT char *inet_ntoa_r(unsigned int addr, char *buf, int bufsz)
{
    unsigned int h = _ntohl(addr);
    int pos = 0;
    unsigned int parts[4] = {
        (h >> 24) & 0xFF,
        (h >> 16) & 0xFF,
        (h >> 8) & 0xFF,
        h & 0xFF
    };
    for (int i = 0; i < 4; i++) {
        if (i > 0 && pos < bufsz - 1) buf[pos++] = '.';
        unsigned int v = parts[i];
        char tmp[4];
        int len = 0;
        if (v == 0) {
            tmp[len++] = '0';
        } else {
            while (v > 0) {
                tmp[len++] = '0' + (char)(v % 10);
                v /= 10;
            }
        }
        for (int j = len - 1; j >= 0 && pos < bufsz - 1; j--)
            buf[pos++] = tmp[j];
    }
    buf[pos] = '\0';
    return buf;
}

EXPORT char *inet_ntoa(unsigned int addr)
{
    return inet_ntoa_r(addr, _inet_ntoa_buf, sizeof(_inet_ntoa_buf));
}

EXPORT int inet_pton(int af, const char *src, void *dst)
{
    if (af != 2 /* AF_INET */ || !src || !dst)
        return 0;
    unsigned int addr = inet_addr(src);
    if (addr == 0xFFFFFFFFU && strcmp(src, "255.255.255.255") != 0)
        return 0;
    *(unsigned int *)dst = addr;
    return 1;
}

EXPORT const char *inet_ntop(int af, const void *src, char *dst, unsigned int size)
{
    if (af != 2 /* AF_INET */ || !src || !dst || size < 16)
        return (void *)0;
    unsigned int addr = *(const unsigned int *)src;
    inet_ntoa_r(addr, dst, (int)size);
    return dst;
}

/* ============================================================================
 * time() - Get current time in seconds since epoch
 *
 * Uses SYS_gettimeofday (116) which returns seconds + microseconds.
 * If the syscall is not yet implemented, falls back to returning 0.
 * ============================================================================ */

struct _timeval { long tv_sec; long tv_usec; };

EXPORT long time(long *tloc)
{
    struct _timeval tv = { 0, 0 };
    long ret = syscall2(116 /* SYS_gettimeofday */, &tv, NULL);
    long t;
    if (ret < 0) {
        /* Fallback: return 0 (boot time) */
        t = 0;
    } else {
        t = tv.tv_sec;
    }
    if (tloc)
        *tloc = t;
    return t;
}

/* ============================================================================
 * popen / pclose - Pipe to/from a process
 *
 * Simplified implementation using fork/exec/pipe.
 * ============================================================================ */

/* Track open popen streams */
#define POPEN_MAX 16
static struct {
    void *fp;
    int   pid;
} _popen_table[POPEN_MAX];

EXPORT void *popen(const char *command, const char *type)
{
    if (!command || !type)
        return (void *)0;

    int pipefd[2];
    if (pipe(pipefd) < 0)
        return (void *)0;

    int reading = (type[0] == 'r');
    int child_fd = reading ? 1 : 0;   /* child writes to pipe (reading) or reads from pipe */
    int parent_fd = reading ? 0 : 1;

    int pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return (void *)0;
    }

    if (pid == 0) {
        /* Child */
        close(pipefd[parent_fd]);
        dup2(pipefd[1 - parent_fd], child_fd);
        close(pipefd[1 - parent_fd]);
        char *argv[4];
        argv[0] = "/bin/bash";
        argv[1] = "-c";
        argv[2] = (char *)command;
        argv[3] = (void *)0;
        execve("/bin/bash", argv, environ);
        _exit(127);
    }

    /* Parent */
    close(pipefd[1 - parent_fd]);
    void *fp = fdopen(pipefd[parent_fd], type);
    if (!fp) {
        close(pipefd[parent_fd]);
        return (void *)0;
    }

    /* Save pid for pclose */
    for (int i = 0; i < POPEN_MAX; i++) {
        if (!_popen_table[i].fp) {
            _popen_table[i].fp = fp;
            _popen_table[i].pid = pid;
            break;
        }
    }

    return fp;
}

EXPORT int pclose(void *stream)
{
    if (!stream)
        return -1;

    int pid = -1;
    for (int i = 0; i < POPEN_MAX; i++) {
        if (_popen_table[i].fp == stream) {
            pid = _popen_table[i].pid;
            _popen_table[i].fp = (void *)0;
            _popen_table[i].pid = 0;
            break;
        }
    }

    fclose(stream);

    if (pid < 0)
        return -1;

    int status = 0;
    waitpid(pid, &status, 0);
    return status;
}

/* ============================================================================
 * PTY Support
 * ============================================================================ */

/*
 * openpty - Allocate a pseudo-terminal pair.
 *
 * @master_fd: Filled with the master side file descriptor
 * @slave_fd:  Filled with the slave side file descriptor
 * @name:      Unused (kept for API compat)
 * @termp:     Unused (kept for API compat)
 * @winp:      Unused (kept for API compat)
 *
 * Returns 0 on success, -1 on error (errno set).
 */
EXPORT int openpty(int *master_fd, int *slave_fd,
                   char *name __attribute__((unused)),
                   void *termp __attribute__((unused)),
                   void *winp __attribute__((unused)))
{
    int fds[2];
    long ret = __syscall(SYS_openpty, (long)(unsigned long)fds, 0, 0, 0, 0, 0);
    if (ret != 0) {
        errno = (int)ret;
        return -1;
    }
    if (master_fd)
        *master_fd = fds[0];
    if (slave_fd)
        *slave_fd = fds[1];
    return 0;
}

/* ============================================================================
 * End of libSystem.B.dylib implementation
 * ============================================================================ */
