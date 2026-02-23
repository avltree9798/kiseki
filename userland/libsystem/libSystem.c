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
typedef signed long         clock_t;
typedef unsigned int        uid_t;
typedef unsigned int        gid_t;
typedef int                 pid_t;

#define CLOCKS_PER_SEC  1000000

#define INT_MAX     0x7fffffff
#define INT_MIN     (-INT_MAX - 1)
#define UINT_MAX    0xffffffffU
#define LONG_MAX    0x7fffffffffffffffL
#define LONG_MIN    (-LONG_MAX - 1L)
#define ULONG_MAX   0xffffffffffffffffUL

#define EOF         (-1)
#define BUFSIZ      1024
#define FOPEN_MAX   64
#define L_tmpnam    32

#define SEEK_SET    0
#define SEEK_CUR    1
#define SEEK_END    2

/* File position type */
typedef long fpos_t;

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
#define SYS_getentropy  500
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
 *
 * This symbol is required by ld64 as an "initial-undefined" for all dylibs.
 * It's defined in stub_binder.s to satisfy the linker's initial-undefines.
 * Kiseki's dyld does eager binding, so this is never actually called.
 * ============================================================================ */

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

/* Forward declarations needed by various functions */
extern void *memcpy(void *dst, const void *src, size_t n);
extern int execl(const char *pathname, const char *arg0, ...);
extern int waitpid(int pid, int *status, int options);

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

    /* Flush buffer contents, handling partial writes */
    while (stream->buf && stream->buf_pos > 0) {
        ssize_t ret = write(stream->fd, stream->buf, stream->buf_pos);
        if (ret < 0) {
            stream->flags |= _F_ERROR;
            return EOF;
        }
        if (ret == 0) {
            /* Can't make progress - treat as error */
            stream->flags |= _F_ERROR;
            return EOF;
        }
        if ((size_t)ret < stream->buf_pos) {
            /* Partial write - shift remaining data to front of buffer */
            size_t remaining = stream->buf_pos - (size_t)ret;
            for (size_t i = 0; i < remaining; i++)
                stream->buf[i] = stream->buf[(size_t)ret + i];
            stream->buf_pos = remaining;
        } else {
            stream->buf_pos = 0;
        }
    }
    return 0;
}

/* ============================================================================
 * exit / abort (defined here after fflush so we can call fflush(NULL))
 * ============================================================================ */

EXPORT NORETURN void exit(int status)
{
#ifdef DEBUG
    /* Debug: show we're in exit and stdout buffer state */
    const char *msg1 = "libSystem: exit() called, status=";
    syscall3(SYS_write, 2, (long)msg1, 33);
    char digit = '0' + (status % 10);
    syscall3(SYS_write, 2, (long)&digit, 1);
    syscall3(SYS_write, 2, (long)"\n", 1);
    
    const char *msg2 = "libSystem: stdout->buf_pos=";
    syscall3(SYS_write, 2, (long)msg2, 27);
    /* Print buf_pos as decimal */
    size_t pos = stdout->buf_pos;
    char numbuf[16];
    int idx = 0;
    if (pos == 0) numbuf[idx++] = '0';
    else {
        char tmp[16];
        int ti = 0;
        while (pos > 0) { tmp[ti++] = '0' + (pos % 10); pos /= 10; }
        while (ti > 0) numbuf[idx++] = tmp[--ti];
    }
    syscall3(SYS_write, 2, (long)numbuf, idx);
    syscall3(SYS_write, 2, (long)"\n", 1);
#endif
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

#ifdef DEBUG
    static int _fputc_debug_count = 0;
    if (_fputc_debug_count < 3) {
        _fputc_debug_count++;
        const char *msg = "libSystem: fputc called, fd=";
        syscall3(SYS_write, 2, (long)msg, 28);
        char d = '0' + stream->fd;
        syscall3(SYS_write, 2, (long)&d, 1);
        syscall3(SYS_write, 2, (long)" flags=0x", 9);
        /* print flags as hex */
        char hbuf[8];
        int hx = stream->flags;
        for (int i = 3; i >= 0; i--) {
            int nib = (hx >> (i*4)) & 0xF;
            hbuf[3-i] = nib < 10 ? '0'+nib : 'a'+nib-10;
        }
        syscall3(SYS_write, 2, (long)hbuf, 4);
        syscall3(SYS_write, 2, (long)"\n", 1);
    }
#endif

    if (stream->flags & _F_UNBUF) {
        ssize_t ret = write(stream->fd, &ch, 1);
        if (ret != 1) { stream->flags |= _F_ERROR; return EOF; }
        return ch;
    }

    _ensure_write_buf(stream);

    if (stream->buf == NULL) {
#ifdef DEBUG
        const char *msg2 = "libSystem: fputc - buf NULL, direct write\n";
        syscall3(SYS_write, 2, (long)msg2, 42);
#endif
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

/*
 * setvbuf - Set buffering mode for a stream.
 *
 * @stream: FILE stream
 * @buf:    User-provided buffer (or NULL)
 * @mode:   _IOFBF (full), _IOLBF (line), or _IONBF (none)
 * @size:   Buffer size (ignored if buf is NULL and mode is _IONBF)
 */
#define _IOFBF  0   /* Fully buffered */
#define _IOLBF  1   /* Line buffered */
#define _IONBF  2   /* Unbuffered */

EXPORT int setvbuf(FILE *stream, char *buf, int mode, size_t size)
{
    if (stream == NULL)
        return -1;
    
    /* Flush any existing data */
    fflush(stream);
    
    /* Free old buffer if we own it */
    if (stream->flags & _F_MYBUF) {
        free(stream->buf);
        stream->buf = NULL;
        stream->flags &= ~_F_MYBUF;
    }
    
    /* Set buffering mode */
    stream->flags &= ~(_F_UNBUF | _F_LINEBUF);
    
    switch (mode) {
    case _IONBF:
        stream->flags |= _F_UNBUF;
        stream->buf = NULL;
        stream->bufsiz = 0;
        break;
    case _IOLBF:
        stream->flags |= _F_LINEBUF;
        /* Fall through to set buffer */
    case _IOFBF:
        if (buf != NULL) {
            stream->buf = buf;
            stream->bufsiz = size;
        } else if (size > 0) {
            stream->buf = (char *)malloc(size);
            if (stream->buf) {
                stream->bufsiz = size;
                stream->flags |= _F_MYBUF;
            }
        }
        break;
    default:
        return -1;
    }
    
    stream->buf_pos = 0;
    stream->buf_len = 0;
    return 0;
}

/*
 * setbuf - Set buffer for a stream (simplified setvbuf).
 */
EXPORT void setbuf(FILE *stream, char *buf)
{
    if (buf == NULL)
        setvbuf(stream, NULL, _IONBF, 0);
    else
        setvbuf(stream, buf, _IOFBF, BUFSIZ);
}

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
#ifdef DEBUG
    const char *msg = "libSystem: vfprintf fmt='";
    syscall3(SYS_write, 2, (long)msg, 25);
    /* Print first 20 chars of fmt */
    int flen = 0;
    while (fmt[flen] && flen < 20) flen++;
    syscall3(SYS_write, 2, (long)fmt, flen);
    syscall3(SYS_write, 2, (long)"'\n", 2);
#endif
    int ret = _fmt_core(&out, fmt, ap);
#ifdef DEBUG
    const char *msg2 = "libSystem: vfprintf returned ";
    syscall3(SYS_write, 2, (long)msg2, 29);
    char dbuf[12];
    int di = 0;
    int rv = ret;
    if (rv == 0) dbuf[di++] = '0';
    else {
        char tmp[12]; int ti = 0;
        while (rv > 0) { tmp[ti++] = '0' + (rv % 10); rv /= 10; }
        while (ti > 0) dbuf[di++] = tmp[--ti];
    }
    syscall3(SYS_write, 2, (long)dbuf, di);
    syscall3(SYS_write, 2, (long)"\n", 1);
#endif
    return ret;
}

/* Standard fprintf using va_list (for clang-compiled code) */
EXPORT int fprintf(FILE *stream, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int ret = vfprintf(stream, fmt, ap);
    va_end(ap);
    return ret;
}

/* TCC-compatible fprintf */
EXPORT int _fprintf_tcc(FILE *stream, const char *fmt, void *a1, void *a2, void *a3,
                        void *a4, void *a5, void *a6)
{
    void *args[8] __attribute__((aligned(8)));
    args[0] = a1;
    args[1] = a2;
    args[2] = a3;
    args[3] = a4;
    args[4] = a5;
    args[5] = a6;
    args[6] = NULL;
    args[7] = NULL;
    
    va_list ap;
    *(void **)&ap = (void *)args;
    
    return vfprintf(stream, fmt, ap);
}

EXPORT int vprintf(const char *fmt, va_list ap)
{
#ifdef DEBUG
    const char *msg = "libSystem: vprintf stdout=0x";
    syscall3(SYS_write, 2, (long)msg, 28);
    /* Print stdout pointer as hex */
    uint64_t p = (uint64_t)stdout;
    char hbuf[16];
    for (int i = 15; i >= 0; i--) {
        int nib = (p >> (i*4)) & 0xF;
        hbuf[15-i] = nib < 10 ? '0'+nib : 'a'+nib-10;
    }
    syscall3(SYS_write, 2, (long)hbuf, 16);
    syscall3(SYS_write, 2, (long)"\n", 1);
#endif
    return vfprintf(stdout, fmt, ap);
}

/*
 * Standard printf using va_list (for clang-compiled code).
 * Darwin ARM64 ABI passes variadic args on the stack.
 */
EXPORT int printf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int ret = vfprintf(stdout, fmt, ap);
    va_end(ap);
    return ret;
}

/*
 * TCC-compatible printf: accepts explicit arguments in registers.
 * TCC passes variadic args in registers x1-x7, not on stack.
 * TCC's headers should #define printf _printf_tcc to use this.
 */
EXPORT int _printf_tcc(const char *fmt, void *a1, void *a2, void *a3, void *a4,
                       void *a5, void *a6, void *a7)
{
    void *args[8] __attribute__((aligned(8)));
    args[0] = a1;
    args[1] = a2;
    args[2] = a3;
    args[3] = a4;
    args[4] = a5;
    args[5] = a6;
    args[6] = a7;
    args[7] = NULL;
    
    va_list ap;
    *(void **)&ap = (void *)args;
    
    return vfprintf(stdout, fmt, ap);
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
 * BSD Rune/Locale Support (macOS ctype compatibility)
 *
 * macOS uses _RuneLocale for locale-aware character classification.
 * We implement a minimal C locale (ASCII only) for compatibility.
 * ============================================================================ */

/* Character type flags used by ___maskrune */
#define _CTYPE_A    0x00000100  /* Alpha */
#define _CTYPE_C    0x00000200  /* Control */
#define _CTYPE_D    0x00000400  /* Digit */
#define _CTYPE_G    0x00000800  /* Graph */
#define _CTYPE_L    0x00001000  /* Lower */
#define _CTYPE_P    0x00002000  /* Punct */
#define _CTYPE_S    0x00004000  /* Space */
#define _CTYPE_U    0x00008000  /* Upper */
#define _CTYPE_X    0x00010000  /* Hex digit */
#define _CTYPE_B    0x00020000  /* Blank */
#define _CTYPE_R    0x00040000  /* Print */

/*
 * _RuneLocale structure - simplified version for C locale only.
 * The full BSD version is more complex with variable-length encoding support.
 */
typedef struct {
    char            __magic[8];
    char            __encoding[32];
    unsigned int    __runetype[256];    /* Character type for each byte */
    int             __maplower[256];    /* Lowercase mapping */
    int             __mapupper[256];    /* Uppercase mapping */
} _RuneLocale;

/* C locale character type table */
static const unsigned int _c_runetype[256] = {
    /* 0x00-0x1F: Control characters */
    _CTYPE_C, _CTYPE_C, _CTYPE_C, _CTYPE_C, _CTYPE_C, _CTYPE_C, _CTYPE_C, _CTYPE_C,
    _CTYPE_C, _CTYPE_C|_CTYPE_S|_CTYPE_B, _CTYPE_C|_CTYPE_S, _CTYPE_C|_CTYPE_S, _CTYPE_C|_CTYPE_S, _CTYPE_C|_CTYPE_S, _CTYPE_C, _CTYPE_C,
    _CTYPE_C, _CTYPE_C, _CTYPE_C, _CTYPE_C, _CTYPE_C, _CTYPE_C, _CTYPE_C, _CTYPE_C,
    _CTYPE_C, _CTYPE_C, _CTYPE_C, _CTYPE_C, _CTYPE_C, _CTYPE_C, _CTYPE_C, _CTYPE_C,
    /* 0x20-0x2F: Space and punctuation */
    _CTYPE_S|_CTYPE_B|_CTYPE_R, _CTYPE_P|_CTYPE_G|_CTYPE_R, _CTYPE_P|_CTYPE_G|_CTYPE_R, _CTYPE_P|_CTYPE_G|_CTYPE_R,
    _CTYPE_P|_CTYPE_G|_CTYPE_R, _CTYPE_P|_CTYPE_G|_CTYPE_R, _CTYPE_P|_CTYPE_G|_CTYPE_R, _CTYPE_P|_CTYPE_G|_CTYPE_R,
    _CTYPE_P|_CTYPE_G|_CTYPE_R, _CTYPE_P|_CTYPE_G|_CTYPE_R, _CTYPE_P|_CTYPE_G|_CTYPE_R, _CTYPE_P|_CTYPE_G|_CTYPE_R,
    _CTYPE_P|_CTYPE_G|_CTYPE_R, _CTYPE_P|_CTYPE_G|_CTYPE_R, _CTYPE_P|_CTYPE_G|_CTYPE_R, _CTYPE_P|_CTYPE_G|_CTYPE_R,
    /* 0x30-0x3F: Digits and punctuation */
    _CTYPE_D|_CTYPE_G|_CTYPE_R|_CTYPE_X, _CTYPE_D|_CTYPE_G|_CTYPE_R|_CTYPE_X, _CTYPE_D|_CTYPE_G|_CTYPE_R|_CTYPE_X, _CTYPE_D|_CTYPE_G|_CTYPE_R|_CTYPE_X,
    _CTYPE_D|_CTYPE_G|_CTYPE_R|_CTYPE_X, _CTYPE_D|_CTYPE_G|_CTYPE_R|_CTYPE_X, _CTYPE_D|_CTYPE_G|_CTYPE_R|_CTYPE_X, _CTYPE_D|_CTYPE_G|_CTYPE_R|_CTYPE_X,
    _CTYPE_D|_CTYPE_G|_CTYPE_R|_CTYPE_X, _CTYPE_D|_CTYPE_G|_CTYPE_R|_CTYPE_X, _CTYPE_P|_CTYPE_G|_CTYPE_R, _CTYPE_P|_CTYPE_G|_CTYPE_R,
    _CTYPE_P|_CTYPE_G|_CTYPE_R, _CTYPE_P|_CTYPE_G|_CTYPE_R, _CTYPE_P|_CTYPE_G|_CTYPE_R, _CTYPE_P|_CTYPE_G|_CTYPE_R,
    /* 0x40-0x4F: @ and uppercase A-O */
    _CTYPE_P|_CTYPE_G|_CTYPE_R, _CTYPE_A|_CTYPE_U|_CTYPE_G|_CTYPE_R|_CTYPE_X, _CTYPE_A|_CTYPE_U|_CTYPE_G|_CTYPE_R|_CTYPE_X, _CTYPE_A|_CTYPE_U|_CTYPE_G|_CTYPE_R|_CTYPE_X,
    _CTYPE_A|_CTYPE_U|_CTYPE_G|_CTYPE_R|_CTYPE_X, _CTYPE_A|_CTYPE_U|_CTYPE_G|_CTYPE_R|_CTYPE_X, _CTYPE_A|_CTYPE_U|_CTYPE_G|_CTYPE_R|_CTYPE_X, _CTYPE_A|_CTYPE_U|_CTYPE_G|_CTYPE_R,
    _CTYPE_A|_CTYPE_U|_CTYPE_G|_CTYPE_R, _CTYPE_A|_CTYPE_U|_CTYPE_G|_CTYPE_R, _CTYPE_A|_CTYPE_U|_CTYPE_G|_CTYPE_R, _CTYPE_A|_CTYPE_U|_CTYPE_G|_CTYPE_R,
    _CTYPE_A|_CTYPE_U|_CTYPE_G|_CTYPE_R, _CTYPE_A|_CTYPE_U|_CTYPE_G|_CTYPE_R, _CTYPE_A|_CTYPE_U|_CTYPE_G|_CTYPE_R, _CTYPE_A|_CTYPE_U|_CTYPE_G|_CTYPE_R,
    /* 0x50-0x5F: Uppercase P-Z and punctuation */
    _CTYPE_A|_CTYPE_U|_CTYPE_G|_CTYPE_R, _CTYPE_A|_CTYPE_U|_CTYPE_G|_CTYPE_R, _CTYPE_A|_CTYPE_U|_CTYPE_G|_CTYPE_R, _CTYPE_A|_CTYPE_U|_CTYPE_G|_CTYPE_R,
    _CTYPE_A|_CTYPE_U|_CTYPE_G|_CTYPE_R, _CTYPE_A|_CTYPE_U|_CTYPE_G|_CTYPE_R, _CTYPE_A|_CTYPE_U|_CTYPE_G|_CTYPE_R, _CTYPE_A|_CTYPE_U|_CTYPE_G|_CTYPE_R,
    _CTYPE_A|_CTYPE_U|_CTYPE_G|_CTYPE_R, _CTYPE_A|_CTYPE_U|_CTYPE_G|_CTYPE_R, _CTYPE_A|_CTYPE_U|_CTYPE_G|_CTYPE_R, _CTYPE_P|_CTYPE_G|_CTYPE_R,
    _CTYPE_P|_CTYPE_G|_CTYPE_R, _CTYPE_P|_CTYPE_G|_CTYPE_R, _CTYPE_P|_CTYPE_G|_CTYPE_R, _CTYPE_P|_CTYPE_G|_CTYPE_R,
    /* 0x60-0x6F: ` and lowercase a-o */
    _CTYPE_P|_CTYPE_G|_CTYPE_R, _CTYPE_A|_CTYPE_L|_CTYPE_G|_CTYPE_R|_CTYPE_X, _CTYPE_A|_CTYPE_L|_CTYPE_G|_CTYPE_R|_CTYPE_X, _CTYPE_A|_CTYPE_L|_CTYPE_G|_CTYPE_R|_CTYPE_X,
    _CTYPE_A|_CTYPE_L|_CTYPE_G|_CTYPE_R|_CTYPE_X, _CTYPE_A|_CTYPE_L|_CTYPE_G|_CTYPE_R|_CTYPE_X, _CTYPE_A|_CTYPE_L|_CTYPE_G|_CTYPE_R|_CTYPE_X, _CTYPE_A|_CTYPE_L|_CTYPE_G|_CTYPE_R,
    _CTYPE_A|_CTYPE_L|_CTYPE_G|_CTYPE_R, _CTYPE_A|_CTYPE_L|_CTYPE_G|_CTYPE_R, _CTYPE_A|_CTYPE_L|_CTYPE_G|_CTYPE_R, _CTYPE_A|_CTYPE_L|_CTYPE_G|_CTYPE_R,
    _CTYPE_A|_CTYPE_L|_CTYPE_G|_CTYPE_R, _CTYPE_A|_CTYPE_L|_CTYPE_G|_CTYPE_R, _CTYPE_A|_CTYPE_L|_CTYPE_G|_CTYPE_R, _CTYPE_A|_CTYPE_L|_CTYPE_G|_CTYPE_R,
    /* 0x70-0x7F: Lowercase p-z, punctuation, and DEL */
    _CTYPE_A|_CTYPE_L|_CTYPE_G|_CTYPE_R, _CTYPE_A|_CTYPE_L|_CTYPE_G|_CTYPE_R, _CTYPE_A|_CTYPE_L|_CTYPE_G|_CTYPE_R, _CTYPE_A|_CTYPE_L|_CTYPE_G|_CTYPE_R,
    _CTYPE_A|_CTYPE_L|_CTYPE_G|_CTYPE_R, _CTYPE_A|_CTYPE_L|_CTYPE_G|_CTYPE_R, _CTYPE_A|_CTYPE_L|_CTYPE_G|_CTYPE_R, _CTYPE_A|_CTYPE_L|_CTYPE_G|_CTYPE_R,
    _CTYPE_A|_CTYPE_L|_CTYPE_G|_CTYPE_R, _CTYPE_A|_CTYPE_L|_CTYPE_G|_CTYPE_R, _CTYPE_A|_CTYPE_L|_CTYPE_G|_CTYPE_R, _CTYPE_P|_CTYPE_G|_CTYPE_R,
    _CTYPE_P|_CTYPE_G|_CTYPE_R, _CTYPE_P|_CTYPE_G|_CTYPE_R, _CTYPE_P|_CTYPE_G|_CTYPE_R, _CTYPE_C,
    /* 0x80-0xFF: High bytes (non-ASCII, all zero for C locale) */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

/* C locale case mapping tables */
static const int _c_maplower[256] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 'a',  'b',  'c',  'd',  'e',  'f',  'g',  'h',  'i',  'j',  'k',  'l',  'm',  'n',  'o',
    'p',  'q',  'r',  's',  't',  'u',  'v',  'w',  'x',  'y',  'z',  0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 'a',  'b',  'c',  'd',  'e',  'f',  'g',  'h',  'i',  'j',  'k',  'l',  'm',  'n',  'o',
    'p',  'q',  'r',  's',  't',  'u',  'v',  'w',  'x',  'y',  'z',  0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
};

static const int _c_mapupper[256] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 'A',  'B',  'C',  'D',  'E',  'F',  'G',  'H',  'I',  'J',  'K',  'L',  'M',  'N',  'O',
    'P',  'Q',  'R',  'S',  'T',  'U',  'V',  'W',  'X',  'Y',  'Z',  0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 'A',  'B',  'C',  'D',  'E',  'F',  'G',  'H',  'I',  'J',  'K',  'L',  'M',  'N',  'O',
    'P',  'Q',  'R',  'S',  'T',  'U',  'V',  'W',  'X',  'Y',  'Z',  0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
};

/* Default C locale - exported as _DefaultRuneLocale */
static _RuneLocale _c_locale = {
    .__magic = "RuneMagA",
    .__encoding = "NONE",
    .__runetype = {0},  /* Will be initialized */
    .__maplower = {0},
    .__mapupper = {0},
};

/* Export the default locale */
EXPORT _RuneLocale _DefaultRuneLocale;

/* Initialize the default locale at load time */
__attribute__((constructor))
static void _init_default_rune_locale(void)
{
    memcpy(_DefaultRuneLocale.__magic, "RuneMagA", 8);
    strcpy(_DefaultRuneLocale.__encoding, "NONE");
    memcpy((void *)_DefaultRuneLocale.__runetype, _c_runetype, sizeof(_c_runetype));
    memcpy((void *)_DefaultRuneLocale.__maplower, _c_maplower, sizeof(_c_maplower));
    memcpy((void *)_DefaultRuneLocale.__mapupper, _c_mapupper, sizeof(_c_mapupper));
}

/*
 * ___maskrune - Check if character has given type mask.
 * Used by macOS ctype macros like isalpha(), isdigit(), etc.
 */
EXPORT int __maskrune(int c, unsigned long mask)
{
    if (c < 0 || c > 255)
        return 0;
    return (_DefaultRuneLocale.__runetype[c] & mask) != 0;
}

/*
 * ___tolower - Locale-aware lowercase conversion.
 */
EXPORT int __tolower(int c)
{
    if (c < 0 || c > 255)
        return c;
    return _DefaultRuneLocale.__maplower[c];
}

/*
 * ___toupper - Locale-aware uppercase conversion.
 */
EXPORT int __toupper(int c)
{
    if (c < 0 || c > 255)
        return c;
    return _DefaultRuneLocale.__mapupper[c];
}

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

EXPORT int rand_r(unsigned int *seedp) {
    *seedp = *seedp * 1103515245 + 12345;
    return (int)((*seedp >> 16) & 0x7fffffff);
}

/* BSD random() - better RNG with larger state */
static unsigned long _random_state = 1;

EXPORT long random(void) {
    /* Simple LCG for now - could be improved */
    _random_state = _random_state * 6364136223846793005UL + 1442695040888963407UL;
    return (long)((_random_state >> 33) & 0x7fffffff);
}

EXPORT void srandom(unsigned int seed) {
    _random_state = seed;
}

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

EXPORT int raise(int sig)
{
    return kill(getpid(), sig);
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

/*
 * system() - Execute a shell command.
 *
 * Forks, execs /bin/sh -c command, and waits for completion.
 * Returns the exit status of the command, or -1 on error.
 */
EXPORT int system(const char *command)
{
    if (command == NULL) {
        /* Check if shell is available */
        return 1;  /* We have /bin/sh */
    }
    
    int pid = fork();
    if (pid < 0)
        return -1;
    
    if (pid == 0) {
        /* Child process */
        execl("/bin/sh", "sh", "-c", command, (char *)NULL);
        _exit(127);  /* exec failed */
    }
    
    /* Parent: wait for child */
    int status = 0;
    if (waitpid(pid, &status, 0) < 0)
        return -1;
    
    return status;
}

/*
 * ___darwin_check_fd_set_overflow - macOS security check for select().
 *
 * This function checks if fd exceeds FD_SETSIZE to prevent buffer overflows.
 * We always return 0 (success) since our fd_set handling is safe.
 */
EXPORT int __darwin_check_fd_set_overflow(int fd, const void *fdset, int is_write)
{
    (void)fd;
    (void)fdset;
    (void)is_write;
    return 0;  /* Always safe */
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
 * scanf / fscanf - read formatted input from stdin/file
 *
 * Darwin ARM64 variadic calling convention passes variadic arguments on the
 * stack, not in registers. TCC currently passes them in registers. Until TCC
 * is fixed, we use explicit pointer arguments since ARM64 passes up to 8
 * arguments in registers x0-x7.
 * ============================================================================ */

/* Core implementation */
static int _scanf_core(const char *buf, const char *fmt, void **args, int nargs)
{
    int idx = 0, count = 0;
    const char *s = buf;

    while (*fmt && *s && idx < nargs) {
        if (*fmt == '%') {
            fmt++;
            while (*fmt >= '0' && *fmt <= '9') fmt++;

            switch (*fmt) {
            case 'd': case 'i': {
                int *p = (int *)args[idx++];
                if (p) { *p = (int)strtol(s, (char **)&s, 10); count++; }
                break;
            }
            case 'u': {
                unsigned *p = (unsigned *)args[idx++];
                if (p) { *p = (unsigned)strtoul(s, (char **)&s, 10); count++; }
                break;
            }
            case 'x': case 'X': {
                unsigned *p = (unsigned *)args[idx++];
                if (p) { *p = (unsigned)strtoul(s, (char **)&s, 16); count++; }
                break;
            }
            case 'l':
                fmt++;
                if (*fmt == 'd') {
                    long *p = (long *)args[idx++];
                    if (p) { *p = strtol(s, (char **)&s, 10); count++; }
                } else if (*fmt == 'u' || *fmt == 'x') {
                    unsigned long *p = (unsigned long *)args[idx++];
                    if (p) { *p = strtoul(s, (char **)&s, *fmt == 'x' ? 16 : 10); count++; }
                }
                break;
            case 's': {
                char *p = (char *)args[idx++];
                if (p) {
                    while (*s && _isspace(*s)) s++;
                    while (*s && !_isspace(*s)) *p++ = *s++;
                    *p = '\0';
                    count++;
                }
                break;
            }
            case 'c': {
                char *p = (char *)args[idx++];
                if (p) { *p = *s++; count++; }
                break;
            }
            case '%':
                if (*s == '%') s++;
                else return count;
                break;
            default:
                return count;
            }
            fmt++;
        } else if (_isspace(*fmt)) {
            while (_isspace(*fmt)) fmt++;
            while (_isspace(*s)) s++;
        } else {
            if (*s != *fmt) break;
            s++; fmt++;
        }
    }
    return count;
}

/* scanf: x0=fmt, x1-x7 = up to 7 pointer args */
EXPORT int scanf(const char *fmt, void *a1, void *a2, void *a3, void *a4,
                 void *a5, void *a6, void *a7)
{
    char buf[1024];
    if (fgets(buf, sizeof(buf), stdin) == NULL)
        return EOF;
    
    /* Strip trailing newline */
    size_t len = 0;
    while (buf[len]) len++;
    if (len > 0 && buf[len-1] == '\n') buf[len-1] = '\0';

    void *args[7] = { a1, a2, a3, a4, a5, a6, a7 };
    return _scanf_core(buf, fmt, args, 7);
}

/* fscanf: x0=stream, x1=fmt, x2-x7 = up to 6 pointer args */
EXPORT int fscanf(FILE *stream, const char *fmt, void *a1, void *a2, void *a3,
                  void *a4, void *a5, void *a6)
{
    char buf[1024];
    if (fgets(buf, sizeof(buf), stream) == NULL)
        return EOF;
    
    size_t len = 0;
    while (buf[len]) len++;
    if (len > 0 && buf[len-1] == '\n') buf[len-1] = '\0';

    void *args[6] = { a1, a2, a3, a4, a5, a6 };
    return _scanf_core(buf, fmt, args, 6);
}

/*
 * vscanf / vfscanf / vsscanf - va_list versions for clang-compiled code.
 * These use the standard va_list calling convention (Darwin: stack-based).
 * TCC-compiled code should use scanf/fscanf/sscanf with explicit args.
 */
EXPORT int vsscanf(const char *str, const char *fmt, va_list ap)
{
    /* Build args array from va_list */
    void *args[16];
    for (int i = 0; i < 16; i++)
        args[i] = va_arg(ap, void *);
    return _scanf_core(str, fmt, args, 16);
}

EXPORT int vfscanf(FILE *stream, const char *fmt, va_list ap)
{
    char buf[1024];
    if (fgets(buf, sizeof(buf), stream) == NULL)
        return EOF;
    
    size_t len = 0;
    while (buf[len]) len++;
    if (len > 0 && buf[len-1] == '\n') buf[len-1] = '\0';
    
    void *args[16];
    for (int i = 0; i < 16; i++)
        args[i] = va_arg(ap, void *);
    return _scanf_core(buf, fmt, args, 16);
}

EXPORT int vscanf(const char *fmt, va_list ap)
{
    return vfscanf(stdin, fmt, ap);
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

EXPORT int rename(const char *oldpath, const char *newpath)
{
    long ret = syscall2(128 /* SYS_rename */, oldpath, newpath);
    if (ret < 0) {
        errno = (int)(-ret);
        return -1;
    }
    return 0;
}

EXPORT void sync(void)
{
    syscall0(36 /* SYS_sync */);
}

/* Forward declarations for functions used below but defined later */
FILE *fdopen(int fd, const char *mode);
int dup2(int oldfd, int newfd);

/* ============================================================================
 * freopen - reopen a stream with a different file
 * ============================================================================ */

EXPORT FILE *freopen(const char *pathname, const char *mode, FILE *stream)
{
    if (stream == NULL)
        return NULL;
    
    /* Close the existing stream (but don't free the FILE struct) */
    fflush(stream);
    if (stream->fd >= 0) {
        syscall1(SYS_close, stream->fd);
    }
    if ((stream->flags & _F_MYBUF) && stream->buf) {
        free(stream->buf);
    }
    
    /* Parse mode */
    int flags = 0;
    int fflags = 0;
    
    if (mode[0] == 'r') {
        flags |= _F_READ;
        fflags = O_RDONLY;
        if (mode[1] == '+' || (mode[1] && mode[2] == '+')) {
            flags |= _F_WRITE;
            fflags = O_RDWR;
        }
    } else if (mode[0] == 'w') {
        flags |= _F_WRITE;
        fflags = O_WRONLY | O_CREAT | O_TRUNC;
        if (mode[1] == '+' || (mode[1] && mode[2] == '+')) {
            flags |= _F_READ;
            fflags = O_RDWR | O_CREAT | O_TRUNC;
        }
    } else if (mode[0] == 'a') {
        flags |= _F_WRITE | _F_APPEND;
        fflags = O_WRONLY | O_CREAT | O_APPEND;
        if (mode[1] == '+' || (mode[1] && mode[2] == '+')) {
            flags |= _F_READ;
            fflags = O_RDWR | O_CREAT | O_APPEND;
        }
    } else {
        return NULL;
    }
    
    /* Open the new file */
    long fd = syscall3(SYS_open, pathname, fflags, 0666);
    if (fd < 0) {
        errno = (int)(-fd);
        return NULL;
    }
    
    /* Reinitialize the stream */
    stream->fd = (int)fd;
    stream->flags = flags;
    stream->buf = (char *)malloc(BUFSIZ);
    stream->bufsiz = stream->buf ? BUFSIZ : 0;
    stream->buf_pos = 0;
    stream->buf_len = 0;
    stream->ungetc_buf = EOF;
    if (stream->buf)
        stream->flags |= _F_MYBUF;
    
    return stream;
}

/* ============================================================================
 * fgetpos / fsetpos - file position
 * ============================================================================ */

EXPORT int fgetpos(FILE *stream, fpos_t *pos)
{
    if (stream == NULL || pos == NULL)
        return -1;
    
    long p = ftell(stream);
    if (p < 0)
        return -1;
    
    *pos = (fpos_t)p;
    return 0;
}

EXPORT int fsetpos(FILE *stream, const fpos_t *pos)
{
    if (stream == NULL || pos == NULL)
        return -1;
    
    return fseek(stream, (long)*pos, SEEK_SET);
}

/* ============================================================================
 * tmpfile / tmpnam - temporary files
 * ============================================================================ */

static int _tmpfile_counter = 0;

EXPORT FILE *tmpfile(void)
{
    char name[32];
    int n = _tmpfile_counter++;
    
    /* Generate unique name */
    snprintf(name, sizeof(name), "/tmp/tmp.%d.%d", getpid(), n);
    
    /* Open with O_CREAT | O_EXCL | O_RDWR */
    long fd = syscall3(SYS_open, name, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        errno = (int)(-fd);
        return NULL;
    }
    
    /* Unlink immediately so it's deleted when closed */
    syscall1(10 /* SYS_unlink */, name);
    
    /* Create FILE wrapper */
    return fdopen((int)fd, "w+");
}

EXPORT char *tmpnam(char *s)
{
    static char static_buf[L_tmpnam];
    char *buf = s ? s : static_buf;
    int n = _tmpfile_counter++;
    
    snprintf(buf, L_tmpnam, "/tmp/tmp.%d.%d", getpid(), n);
    return buf;
}

/* ============================================================================
 * getline / getdelim - read line with dynamic allocation (POSIX)
 * ============================================================================ */

EXPORT ssize_t getdelim(char **lineptr, size_t *n, int delim, FILE *stream)
{
    if (lineptr == NULL || n == NULL || stream == NULL) {
        errno = EINVAL;
        return -1;
    }
    
    /* Allocate initial buffer if needed */
    if (*lineptr == NULL || *n == 0) {
        *n = 128;
        *lineptr = (char *)malloc(*n);
        if (*lineptr == NULL) {
            errno = ENOMEM;
            return -1;
        }
    }
    
    size_t pos = 0;
    int c;
    
    while ((c = fgetc(stream)) != EOF) {
        /* Grow buffer if needed */
        if (pos + 2 > *n) {
            size_t new_size = *n * 2;
            char *new_buf = (char *)realloc(*lineptr, new_size);
            if (new_buf == NULL) {
                errno = ENOMEM;
                return -1;
            }
            *lineptr = new_buf;
            *n = new_size;
        }
        
        (*lineptr)[pos++] = (char)c;
        
        if (c == delim)
            break;
    }
    
    if (pos == 0 && c == EOF)
        return -1;
    
    (*lineptr)[pos] = '\0';
    return (ssize_t)pos;
}

EXPORT ssize_t getline(char **lineptr, size_t *n, FILE *stream)
{
    return getdelim(lineptr, n, '\n', stream);
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

EXPORT int chown(const char *pathname, unsigned int owner, unsigned int group)
{
    return (int)_check(syscall3(16 /* SYS_chown */, pathname, owner, group));
}

EXPORT int fchown(int fd, unsigned int owner, unsigned int group)
{
    return (int)_check(syscall3(123 /* SYS_fchown */, fd, owner, group));
}

EXPORT int lchown(const char *pathname, unsigned int owner, unsigned int group)
{
    return (int)_check(syscall3(254 /* SYS_lchown */, pathname, owner, group));
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

/*
 * execl - Execute a file with argument list.
 * execl(path, arg0, arg1, ..., NULL)
 */
EXPORT int execl(const char *pathname, const char *arg0, ...)
{
    va_list ap;
    int argc = 1;  /* Count arg0 */
    
    /* Count arguments */
    va_start(ap, arg0);
    while (va_arg(ap, const char *) != NULL)
        argc++;
    va_end(ap);
    
    /* Build argv array */
    char *argv[argc + 1];
    argv[0] = (char *)arg0;
    
    va_start(ap, arg0);
    for (int i = 1; i < argc; i++)
        argv[i] = va_arg(ap, char *);
    argv[argc] = NULL;
    va_end(ap);
    
    return execve(pathname, argv, environ);
}

/*
 * execle - Execute a file with argument list and environment.
 * execle(path, arg0, arg1, ..., NULL, envp)
 */
EXPORT int execle(const char *pathname, const char *arg0, ...)
{
    va_list ap;
    int argc = 1;
    
    /* Count arguments (stop at NULL) */
    va_start(ap, arg0);
    while (va_arg(ap, const char *) != NULL)
        argc++;
    va_end(ap);
    
    /* Build argv and get envp */
    char *argv[argc + 1];
    argv[0] = (char *)arg0;
    
    va_start(ap, arg0);
    for (int i = 1; i < argc; i++)
        argv[i] = va_arg(ap, char *);
    argv[argc] = NULL;
    char *const *envp = va_arg(ap, char *const *);
    va_end(ap);
    
    return execve(pathname, argv, envp);
}

/*
 * execlp - Execute a file from PATH with argument list.
 * execlp(file, arg0, arg1, ..., NULL)
 */
EXPORT int execlp(const char *file, const char *arg0, ...)
{
    va_list ap;
    int argc = 1;
    
    /* Count arguments */
    va_start(ap, arg0);
    while (va_arg(ap, const char *) != NULL)
        argc++;
    va_end(ap);
    
    /* Build argv array */
    char *argv[argc + 1];
    argv[0] = (char *)arg0;
    
    va_start(ap, arg0);
    for (int i = 1; i < argc; i++)
        argv[i] = va_arg(ap, char *);
    argv[argc] = NULL;
    va_end(ap);
    
    return execvp(file, argv);
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
 * getopt - POSIX command-line option parsing
 * ============================================================================ */

EXPORT char *optarg = NULL;
EXPORT int optind = 1;
EXPORT int opterr = 1;
EXPORT int optopt = 0;

EXPORT int getopt(int argc, char * const argv[], const char *optstring)
{
    static int sp = 1;  /* position within current argument */

    if (sp == 1) {
        /* Check if we're at end or current arg isn't an option */
        if (optind >= argc || argv[optind][0] != '-' || argv[optind][1] == '\0')
            return -1;
        /* Check for "--" end of options marker */
        if (argv[optind][1] == '-' && argv[optind][2] == '\0') {
            optind++;
            return -1;
        }
    }

    int c = argv[optind][sp];
    const char *cp = strchr(optstring, c);

    if (c == ':' || cp == NULL) {
        /* Invalid option */
        optopt = c;
        if (opterr && *optstring != ':')
            fprintf(stderr, "%s: illegal option -- %c\n", argv[0], c);
        if (argv[optind][++sp] == '\0') {
            optind++;
            sp = 1;
        }
        return '?';
    }

    if (cp[1] == ':') {
        /* Option requires argument */
        if (argv[optind][sp + 1] != '\0') {
            /* Argument is rest of current argv element */
            optarg = &argv[optind][sp + 1];
        } else if (++optind >= argc) {
            /* No argument available */
            optopt = c;
            sp = 1;
            if (*optstring == ':')
                return ':';
            if (opterr)
                fprintf(stderr, "%s: option requires an argument -- %c\n", argv[0], c);
            return '?';
        } else {
            /* Argument is next argv element */
            optarg = argv[optind];
        }
        optind++;
        sp = 1;
    } else {
        /* Option doesn't take argument */
        if (argv[optind][++sp] == '\0') {
            optind++;
            sp = 1;
        }
        optarg = NULL;
    }

    return c;
}

/* ============================================================================
 * Password database (getpwuid, getpwnam) - reads /etc/passwd
 * ============================================================================ */

struct passwd {
    char *pw_name;      /* username */
    char *pw_passwd;    /* password (usually 'x') */
    int   pw_uid;       /* user ID */
    int   pw_gid;       /* group ID */
    char *pw_gecos;     /* real name */
    char *pw_dir;       /* home directory */
    char *pw_shell;     /* shell */
};

static struct passwd _pw_entry;
static char _pw_buf[512];

/* Parse a line from /etc/passwd into struct passwd */
static int _parse_passwd_line(char *line, struct passwd *pw)
{
    char *fields[7];
    int i = 0;
    char *p = line;

    /* Split by ':' */
    fields[i++] = p;
    while (*p && i < 7) {
        if (*p == ':') {
            *p = '\0';
            fields[i++] = p + 1;
        }
        p++;
    }

    if (i < 7)
        return -1;

    /* Strip newline from last field */
    p = fields[6];
    while (*p && *p != '\n' && *p != '\r') p++;
    *p = '\0';

    pw->pw_name = fields[0];
    pw->pw_passwd = fields[1];
    pw->pw_uid = atoi(fields[2]);
    pw->pw_gid = atoi(fields[3]);
    pw->pw_gecos = fields[4];
    pw->pw_dir = fields[5];
    pw->pw_shell = fields[6];

    return 0;
}

EXPORT struct passwd *getpwuid(int uid)
{
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd < 0)
        return NULL;

    ssize_t n = read(fd, _pw_buf, sizeof(_pw_buf) - 1);
    close(fd);
    if (n <= 0)
        return NULL;
    _pw_buf[n] = '\0';

    /* Process line by line */
    char *line = _pw_buf;
    while (*line) {
        char *next = line;
        while (*next && *next != '\n') next++;
        if (*next == '\n') *next++ = '\0';

        /* Make a copy for parsing (since strtok modifies it) */
        char linecopy[256];
        strncpy(linecopy, line, sizeof(linecopy) - 1);
        linecopy[sizeof(linecopy) - 1] = '\0';

        if (_parse_passwd_line(line, &_pw_entry) == 0) {
            if (_pw_entry.pw_uid == uid)
                return &_pw_entry;
        }

        line = next;
    }

    return NULL;
}

EXPORT struct passwd *getpwnam(const char *name)
{
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd < 0)
        return NULL;

    ssize_t n = read(fd, _pw_buf, sizeof(_pw_buf) - 1);
    close(fd);
    if (n <= 0)
        return NULL;
    _pw_buf[n] = '\0';

    /* Process line by line */
    char *line = _pw_buf;
    while (*line) {
        char *next = line;
        while (*next && *next != '\n') next++;
        if (*next == '\n') *next++ = '\0';

        if (_parse_passwd_line(line, &_pw_entry) == 0) {
            if (strcmp(_pw_entry.pw_name, name) == 0)
                return &_pw_entry;
        }

        line = next;
    }

    return NULL;
}

/* ============================================================================
 * Minimal termcap implementation for VT100/ANSI terminals
 *
 * Kiseki runs on QEMU with a VT100-compatible terminal, so we hardcode
 * ANSI escape sequences. This is sufficient for vi and similar programs.
 * ============================================================================ */

/* Static buffer for termcap string storage */
static char _tc_buf[256];
static char *_tc_ptr = _tc_buf;

/* VT100/ANSI capabilities we support */
static struct {
    const char *cap;    /* capability name */
    const char *value;  /* escape sequence */
} _tc_strings[] = {
    { "cm", "\033[%i%d;%dH" },  /* cursor motion (row;col) - %i means 1-based */
    { "cl", "\033[H\033[J" },   /* clear screen and home */
    { "ce", "\033[K" },         /* clear to end of line */
    { "ho", "\033[H" },         /* home cursor */
    { "up", "\033[A" },         /* cursor up */
    { "do", "\033[B" },         /* cursor down */
    { "nd", "\033[C" },         /* cursor right (non-destructive) */
    { "le", "\b" },             /* cursor left */
    { "al", "\033[L" },         /* add line */
    { "dl", "\033[M" },         /* delete line */
    { "sr", "\033M" },          /* scroll reverse (up) */
    { "so", "\033[7m" },        /* standout mode (reverse video) */
    { "se", "\033[m" },         /* end standout mode */
    { "us", "\033[4m" },        /* underline start */
    { "ue", "\033[m" },         /* underline end */
    { "vi", "\033[?25l" },      /* cursor invisible */
    { "ve", "\033[?25h" },      /* cursor visible */
    { "vb", "\007" },           /* visual bell (actually audible) */
    { NULL, NULL }
};

static struct {
    const char *cap;
    int value;
} _tc_numbers[] = {
    { "li", 24 },               /* lines (default, may be overridden by TIOCGWINSZ) */
    { "co", 80 },               /* columns */
    { NULL, 0 }
};

/*
 * tgetent - Load terminal entry.
 * We ignore the terminal name and always use VT100/ANSI.
 * Returns 1 on success, 0 if not found, -1 on error.
 */
EXPORT int tgetent(char *bp, const char *name)
{
    (void)bp;
    (void)name;
    _tc_ptr = _tc_buf;  /* reset string buffer */
    return 1;           /* always succeed */
}

/*
 * tgetstr - Get string capability.
 * Returns pointer to the escape sequence, or NULL if not found.
 * The area pointer is updated to point past the stored string.
 */
EXPORT char *tgetstr(const char *id, char **area)
{
    for (int i = 0; _tc_strings[i].cap; i++) {
        if (strcmp(id, _tc_strings[i].cap) == 0) {
            const char *val = _tc_strings[i].value;
            char *ret = *area;
            while (*val)
                *(*area)++ = *val++;
            *(*area)++ = '\0';
            return ret;
        }
    }
    return NULL;
}

/*
 * tgetnum - Get numeric capability.
 * Returns the value, or -1 if not found.
 */
EXPORT int tgetnum(const char *id)
{
    /* First try to get actual terminal size via ioctl */
    if (strcmp(id, "li") == 0 || strcmp(id, "co") == 0) {
        /* struct winsize for TIOCGWINSZ */
        struct { unsigned short ws_row, ws_col, ws_xpixel, ws_ypixel; } ws;
        #define TIOCGWINSZ 0x40087468
        if (ioctl(0, TIOCGWINSZ, &ws) == 0) {
            if (strcmp(id, "li") == 0 && ws.ws_row > 0)
                return ws.ws_row;
            if (strcmp(id, "co") == 0 && ws.ws_col > 0)
                return ws.ws_col;
        }
    }

    /* Fall back to defaults */
    for (int i = 0; _tc_numbers[i].cap; i++) {
        if (strcmp(id, _tc_numbers[i].cap) == 0)
            return _tc_numbers[i].value;
    }
    return -1;
}

/*
 * tgetflag - Get boolean capability.
 * Returns 1 if present, 0 if not.
 */
EXPORT int tgetflag(const char *id)
{
    /* VT100 has auto margins */
    if (strcmp(id, "am") == 0) return 1;
    return 0;
}

/*
 * tgoto - Produce cursor motion string.
 * The cm capability uses printf-style %d for row and column.
 * %i means arguments are 1-based (add 1 to each).
 *
 * Returns pointer to static buffer with the formatted string.
 */
EXPORT char *tgoto(const char *cm, int col, int row)
{
    static char result[32];
    char *p = result;
    int args[2] = { row, col };
    int arg_idx = 0;
    int add_one = 0;

    if (cm == NULL)
        return NULL;

    while (*cm && (p - result) < 30) {
        if (*cm == '%') {
            cm++;
            switch (*cm) {
            case 'd':
                /* Output decimal number */
                {
                    int val = args[arg_idx++] + add_one;
                    if (val >= 100) *p++ = '0' + (val / 100) % 10;
                    if (val >= 10) *p++ = '0' + (val / 10) % 10;
                    *p++ = '0' + val % 10;
                }
                cm++;
                break;
            case 'i':
                /* 1-based indexing */
                add_one = 1;
                cm++;
                break;
            case '%':
                *p++ = '%';
                cm++;
                break;
            default:
                *p++ = '%';
                break;
            }
        } else {
            *p++ = *cm++;
        }
    }
    *p = '\0';
    return result;
}

/*
 * tputs - Output a termcap string with padding.
 * We ignore padding (modern terminals don't need it).
 */
EXPORT int tputs(const char *str, int affcnt, int (*putc_func)(int))
{
    (void)affcnt;
    if (str == NULL)
        return 0;

    while (*str) {
        putc_func((unsigned char)*str);
        str++;
    }
    return 0;
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
 * Entropy
 * ============================================================================ */

/*
 * getentropy - Fill a buffer with random bytes from the kernel.
 *
 * @buf:    Buffer to fill
 * @buflen: Number of bytes (must be <= 256 per POSIX)
 *
 * Returns 0 on success, -1 on error (errno set).
 */
EXPORT int getentropy(void *buf, unsigned long buflen)
{
    if (buflen > 256) {
        errno = EIO;
        return -1;
    }
    long ret = syscall2(SYS_getentropy, (long)(unsigned long)buf, (long)buflen);
    if (ret < 0) {
        errno = (int)(-ret);
        return -1;
    }
    return 0;
}

/* ============================================================================
 * Floating-point string to number conversion
 * ============================================================================ */

static inline int _isspace_fp(int c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
           c == '\f' || c == '\v';
}

static inline int _isdigit_fp(int c)
{
    return c >= '0' && c <= '9';
}

/* Forward declaration */
EXPORT double strtod(const char *nptr, char **endptr);

EXPORT double atof(const char *nptr)
{
    return strtod(nptr, NULL);
}

EXPORT double strtod(const char *nptr, char **endptr)
{
    const char *s = nptr;
    double result = 0.0;
    double frac = 0.0;
    int neg = 0;
    int exp_neg = 0;
    int exp_val = 0;
    int has_digits = 0;

    /* Skip whitespace */
    while (_isspace_fp(*s))
        s++;

    /* Sign */
    if (*s == '-') {
        neg = 1;
        s++;
    } else if (*s == '+') {
        s++;
    }

    /* Integer part */
    while (_isdigit_fp(*s)) {
        result = result * 10.0 + (*s - '0');
        has_digits = 1;
        s++;
    }

    /* Fractional part */
    if (*s == '.') {
        s++;
        double divisor = 10.0;
        while (_isdigit_fp(*s)) {
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
        while (_isdigit_fp(*s)) {
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

EXPORT float strtof(const char *nptr, char **endptr)
{
    return (float)strtod(nptr, endptr);
}

EXPORT long double strtold(const char *nptr, char **endptr)
{
    return (long double)strtod(nptr, endptr);
}

/* ============================================================================
 * Math functions (minimal implementations)
 * ============================================================================ */

/* ldexp: x * 2^exp */
EXPORT double ldexp(double x, int exp)
{
    if (exp > 0) {
        while (exp-- > 0)
            x *= 2.0;
    } else {
        while (exp++ < 0)
            x /= 2.0;
    }
    return x;
}

EXPORT float ldexpf(float x, int exp)
{
    return (float)ldexp((double)x, exp);
}

/* ============================================================================
 * Time functions
 * ============================================================================ */

/* Days in each month (non-leap year) */
static const int _days_in_month_lut[] = {
    31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

/* Days before each month (non-leap year) */
static const int _days_before_month_lut[] = {
    0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
};

static int _is_leap_year(int year)
{
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

/* Static struct for gmtime/localtime */
static struct {
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
} _tm_buf;

/* Convert time_t to struct tm (UTC) */
EXPORT void *gmtime_r(const time_t *timep, void *result)
{
    time_t t = *timep;
    int days, rem;
    int y;
    
    /* Cast to our temp struct for manipulation */
    struct {
        int tm_sec, tm_min, tm_hour, tm_mday, tm_mon, tm_year, tm_wday, tm_yday, tm_isdst;
    } *tm = result;

    days = (int)(t / 86400);
    rem = (int)(t % 86400);
    if (rem < 0) {
        rem += 86400;
        days--;
    }

    tm->tm_hour = rem / 3600;
    rem %= 3600;
    tm->tm_min = rem / 60;
    tm->tm_sec = rem % 60;

    /* January 1, 1970 was a Thursday (day 4) */
    tm->tm_wday = (days + 4) % 7;
    if (tm->tm_wday < 0)
        tm->tm_wday += 7;

    y = 1970;
    while (days < 0 || days >= (_is_leap_year(y) ? 366 : 365)) {
        int newy;
        int leaps;

        newy = y + days / 365;
        if (days < 0)
            --newy;
        leaps = (newy - 1) / 4 - (newy - 1) / 100 + (newy - 1) / 400;
        leaps -= (y - 1) / 4 - (y - 1) / 100 + (y - 1) / 400;
        days -= (newy - y) * 365 + leaps;
        y = newy;
    }

    tm->tm_year = y - 1900;
    tm->tm_yday = days;

    const int *ip = _days_before_month_lut;
    int leap = _is_leap_year(y);
    for (tm->tm_mon = 0; tm->tm_mon < 11; tm->tm_mon++) {
        int mdays = ip[tm->tm_mon + 1] - ip[tm->tm_mon];
        if (tm->tm_mon == 1 && leap)
            mdays++;
        if (days < mdays)
            break;
        days -= mdays;
    }
    tm->tm_mday = days + 1;
    tm->tm_isdst = 0;

    return result;
}

EXPORT void *gmtime(const time_t *timep)
{
    return gmtime_r(timep, &_tm_buf);
}

/* localtime - for now, same as gmtime (no timezone support) */
EXPORT void *localtime_r(const time_t *timep, void *result)
{
    return gmtime_r(timep, result);
}

EXPORT void *localtime(const time_t *timep)
{
    return localtime_r(timep, &_tm_buf);
}

/* clock - returns processor time used by the program */
EXPORT clock_t clock(void)
{
    /* 
     * Returns approximate processor time.
     * We use gettimeofday as an approximation since we don't track CPU time.
     * Real implementation would use getrusage or similar.
     */
    struct _timeval tv = { 0, 0 };
    if (syscall2(116 /* SYS_gettimeofday */, &tv, NULL) < 0)
        return (clock_t)-1;
    /* Convert to CLOCKS_PER_SEC (1000000) */
    return (clock_t)(tv.tv_sec * 1000000 + tv.tv_usec);
}

/* difftime - compute difference between two times */
EXPORT double difftime(time_t time1, time_t time0)
{
    return (double)(time1 - time0);
}

/* Helper: days in month (uses existing _is_leap_year) */
static int _days_in_month(int mon, int year)
{
    static const int days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (mon == 1 && _is_leap_year(year))
        return 29;
    return days[mon];
}

/* mktime - convert struct tm to time_t */
EXPORT time_t mktime(void *tm_ptr)
{
    struct {
        int tm_sec, tm_min, tm_hour, tm_mday, tm_mon, tm_year;
        int tm_wday, tm_yday, tm_isdst;
    } *tm = tm_ptr;
    
    /* Normalize values */
    int year = tm->tm_year + 1900;
    int mon = tm->tm_mon;
    int day = tm->tm_mday;
    int hour = tm->tm_hour;
    int min = tm->tm_min;
    int sec = tm->tm_sec;
    
    /* Normalize seconds -> minutes */
    while (sec < 0) { sec += 60; min--; }
    while (sec >= 60) { sec -= 60; min++; }
    
    /* Normalize minutes -> hours */
    while (min < 0) { min += 60; hour--; }
    while (min >= 60) { min -= 60; hour++; }
    
    /* Normalize hours -> days */
    while (hour < 0) { hour += 24; day--; }
    while (hour >= 24) { hour -= 24; day++; }
    
    /* Normalize months -> years */
    while (mon < 0) { mon += 12; year--; }
    while (mon >= 12) { mon -= 12; year++; }
    
    /* Normalize days */
    while (day < 1) {
        mon--;
        if (mon < 0) { mon = 11; year--; }
        day += _days_in_month(mon, year);
    }
    while (day > _days_in_month(mon, year)) {
        day -= _days_in_month(mon, year);
        mon++;
        if (mon > 11) { mon = 0; year++; }
    }
    
    /* Calculate days since epoch (1970-01-01) */
    long days = 0;
    
    /* Years */
    for (int y = 1970; y < year; y++) {
        days += _is_leap_year(y) ? 366 : 365;
    }
    for (int y = year; y < 1970; y++) {
        days -= _is_leap_year(y) ? 366 : 365;
    }
    
    /* Months */
    for (int m = 0; m < mon; m++) {
        days += _days_in_month(m, year);
    }
    
    /* Days */
    days += day - 1;
    
    /* Calculate time_t */
    time_t t = days * 86400 + hour * 3600 + min * 60 + sec;
    
    /* Update tm structure with normalized values */
    tm->tm_sec = sec;
    tm->tm_min = min;
    tm->tm_hour = hour;
    tm->tm_mday = day;
    tm->tm_mon = mon;
    tm->tm_year = year - 1900;
    
    /* Calculate day of week: 1970-01-01 was Thursday (4) */
    int total_days = (int)(t / 86400);
    tm->tm_wday = (total_days + 4) % 7;
    if (tm->tm_wday < 0) tm->tm_wday += 7;
    
    /* Calculate day of year */
    tm->tm_yday = 0;
    for (int m = 0; m < mon; m++) {
        tm->tm_yday += _days_in_month(m, year);
    }
    tm->tm_yday += day - 1;
    
    tm->tm_isdst = 0;  /* No DST support yet */
    
    return t;
}

/* asctime_r - convert struct tm to string (reentrant) */
EXPORT char *asctime_r(const void *tm_ptr, char *buf)
{
    const struct {
        int tm_sec, tm_min, tm_hour, tm_mday, tm_mon, tm_year;
        int tm_wday, tm_yday, tm_isdst;
    } *tm = tm_ptr;
    
    static const char *wday[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    static const char *mon[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    
    /* Format: "Day Mon DD HH:MM:SS YYYY\n" */
    snprintf(buf, 26, "%s %s %2d %02d:%02d:%02d %04d\n",
             wday[tm->tm_wday % 7],
             mon[tm->tm_mon % 12],
             tm->tm_mday,
             tm->tm_hour,
             tm->tm_min,
             tm->tm_sec,
             tm->tm_year + 1900);
    
    return buf;
}

/* Static buffer for asctime */
static char _asctime_buf[26];

/* asctime - convert struct tm to string */
EXPORT char *asctime(const void *tm)
{
    return asctime_r(tm, _asctime_buf);
}

/* ctime_r - convert time_t to string (reentrant) */
EXPORT char *ctime_r(const time_t *timep, char *buf)
{
    struct {
        int tm_sec, tm_min, tm_hour, tm_mday, tm_mon, tm_year;
        int tm_wday, tm_yday, tm_isdst;
    } tm_storage;
    
    localtime_r(timep, &tm_storage);
    return asctime_r(&tm_storage, buf);
}

/* ctime - convert time_t to string */
EXPORT char *ctime(const time_t *timep)
{
    return ctime_r(timep, _asctime_buf);
}

/* clock_gettime - get time from specified clock */
EXPORT int clock_gettime(int clk_id, void *tp_ptr)
{
    struct { time_t tv_sec; long tv_nsec; } *tp = tp_ptr;
    struct _timeval tv = { 0, 0 };
    
    switch (clk_id) {
    case 0:  /* CLOCK_REALTIME */
    case 1:  /* CLOCK_MONOTONIC - use realtime as approximation */
        if (syscall2(116 /* SYS_gettimeofday */, &tv, NULL) < 0) {
            errno = EIO;
            return -1;
        }
        tp->tv_sec = tv.tv_sec;
        tp->tv_nsec = tv.tv_usec * 1000;
        return 0;
        
    case 2:  /* CLOCK_PROCESS_CPUTIME_ID */
    case 3:  /* CLOCK_THREAD_CPUTIME_ID */
        /* Approximate with wall clock time for now */
        if (syscall2(116 /* SYS_gettimeofday */, &tv, NULL) < 0) {
            errno = EIO;
            return -1;
        }
        tp->tv_sec = tv.tv_sec;
        tp->tv_nsec = tv.tv_usec * 1000;
        return 0;
        
    default:
        errno = EINVAL;
        return -1;
    }
}

/* clock_settime - set time for specified clock */
EXPORT int clock_settime(int clk_id, const void *tp_ptr)
{
    const struct { time_t tv_sec; long tv_nsec; } *tp = tp_ptr;
    
    if (clk_id != 0) {  /* Only CLOCK_REALTIME can be set */
        errno = EINVAL;
        return -1;
    }
    
    struct _timeval tv;
    tv.tv_sec = tp->tv_sec;
    tv.tv_usec = tp->tv_nsec / 1000;
    
    return (int)_check(syscall2(122 /* SYS_settimeofday */, &tv, NULL));
}

/* clock_getres - get resolution of specified clock */
EXPORT int clock_getres(int clk_id, void *res_ptr)
{
    struct { time_t tv_sec; long tv_nsec; } *res = res_ptr;
    
    switch (clk_id) {
    case 0:  /* CLOCK_REALTIME */
    case 1:  /* CLOCK_MONOTONIC */
    case 2:  /* CLOCK_PROCESS_CPUTIME_ID */
    case 3:  /* CLOCK_THREAD_CPUTIME_ID */
        if (res) {
            res->tv_sec = 0;
            res->tv_nsec = 1000;  /* 1 microsecond resolution */
        }
        return 0;
        
    default:
        errno = EINVAL;
        return -1;
    }
}

/* timespec_get - C11 time function */
EXPORT int timespec_get(void *ts_ptr, int base)
{
    if (base != 1) {  /* TIME_UTC = 1 */
        return 0;  /* Failure */
    }
    
    if (clock_gettime(0 /* CLOCK_REALTIME */, ts_ptr) < 0)
        return 0;
    
    return base;  /* Success returns base */
}

/* strftime - format time as string */
EXPORT size_t strftime(char *s, size_t max, const char *fmt, const void *tm_ptr)
{
    const struct {
        int tm_sec, tm_min, tm_hour, tm_mday, tm_mon, tm_year;
        int tm_wday, tm_yday, tm_isdst;
    } *tm = tm_ptr;
    
    static const char *day_abbr[] = {"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
    static const char *day_full[] = {"Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"};
    static const char *mon_abbr[] = {"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};
    static const char *mon_full[] = {"January","February","March","April","May","June","July","August","September","October","November","December"};
    
    char *p = s;
    char *end = s + max - 1;
    
    while (*fmt && p < end) {
        if (*fmt != '%') {
            *p++ = *fmt++;
            continue;
        }
        fmt++;
        
        char buf[32];
        const char *src = buf;
        
        switch (*fmt) {
        case 'Y': snprintf(buf, sizeof(buf), "%04d", tm->tm_year + 1900); break;
        case 'y': snprintf(buf, sizeof(buf), "%02d", tm->tm_year % 100); break;
        case 'm': snprintf(buf, sizeof(buf), "%02d", tm->tm_mon + 1); break;
        case 'd': snprintf(buf, sizeof(buf), "%02d", tm->tm_mday); break;
        case 'H': snprintf(buf, sizeof(buf), "%02d", tm->tm_hour); break;
        case 'M': snprintf(buf, sizeof(buf), "%02d", tm->tm_min); break;
        case 'S': snprintf(buf, sizeof(buf), "%02d", tm->tm_sec); break;
        case 'j': snprintf(buf, sizeof(buf), "%03d", tm->tm_yday + 1); break;
        case 'w': snprintf(buf, sizeof(buf), "%d", tm->tm_wday); break;
        case 'a': src = day_abbr[tm->tm_wday % 7]; break;
        case 'A': src = day_full[tm->tm_wday % 7]; break;
        case 'b': case 'h': src = mon_abbr[tm->tm_mon % 12]; break;
        case 'B': src = mon_full[tm->tm_mon % 12]; break;
        case 'e': snprintf(buf, sizeof(buf), "%2d", tm->tm_mday); break;
        case 'I': snprintf(buf, sizeof(buf), "%02d", tm->tm_hour % 12 ? tm->tm_hour % 12 : 12); break;
        case 'p': src = tm->tm_hour < 12 ? "AM" : "PM"; break;
        case 'n': src = "\n"; break;
        case 't': src = "\t"; break;
        case '%': src = "%"; break;
        default: buf[0] = '%'; buf[1] = *fmt; buf[2] = '\0'; break;
        }
        fmt++;
        
        while (*src && p < end)
            *p++ = *src++;
    }
    
    *p = '\0';
    return p - s;
}

/* ============================================================================
 * Timer functions (stubs for compatibility)
 * ============================================================================ */

/* timer_create - create a POSIX timer (stub) */
EXPORT int timer_create(int clockid, void *sevp, void **timerid)
{
    (void)clockid; (void)sevp; (void)timerid;
    errno = ENOSYS;
    return -1;
}

/* timer_delete - delete a POSIX timer (stub) */
EXPORT int timer_delete(void *timerid)
{
    (void)timerid;
    errno = ENOSYS;
    return -1;
}

/* timer_settime - arm/disarm a POSIX timer (stub) */
EXPORT int timer_settime(void *timerid, int flags, const void *new_value, void *old_value)
{
    (void)timerid; (void)flags; (void)new_value; (void)old_value;
    errno = ENOSYS;
    return -1;
}

/* timer_gettime - get time remaining on a POSIX timer (stub) */
EXPORT int timer_gettime(void *timerid, void *curr_value)
{
    (void)timerid; (void)curr_value;
    errno = ENOSYS;
    return -1;
}

/* getitimer - get value of interval timer */
EXPORT int getitimer(int which, void *curr_value)
{
    (void)which; (void)curr_value;
    errno = ENOSYS;
    return -1;
}

/* setitimer - set value of interval timer */
EXPORT int setitimer(int which, const void *new_value, void *old_value)
{
    (void)which; (void)new_value; (void)old_value;
    errno = ENOSYS;
    return -1;
}

/* ============================================================================
 * Additional unistd.h functions
 * ============================================================================ */

/* ftruncate - truncate a file to a specified length */
EXPORT int ftruncate(int fd, off_t length)
{
    return (int)_check(syscall2(201 /* SYS_ftruncate */, fd, length));
}

/* truncate - truncate a file to a specified length */
EXPORT int truncate(const char *path, off_t length)
{
    return (int)_check(syscall2(200 /* SYS_truncate */, path, length));
}

/* sethostname - set name of current host */
EXPORT int sethostname(const char *name, size_t len)
{
    int mib[2] = { 1 /* CTL_KERN */, 10 /* KERN_HOSTNAME */ };
    return sysctl(mib, 2, NULL, NULL, (void *)name, len);
}

/* getdomainname - get NIS domain name (stub) */
EXPORT int getdomainname(char *name, size_t len)
{
    if (len > 0) name[0] = '\0';
    return 0;
}

/* setdomainname - set NIS domain name (stub) */
EXPORT int setdomainname(const char *name, size_t len)
{
    (void)name; (void)len;
    return 0;
}

/* getpagesize - get system page size */
EXPORT int getpagesize(void)
{
    return 4096;  /* ARM64 4KB pages */
}

/* getdtablesize - get file descriptor table size */
EXPORT int getdtablesize(void)
{
    return 256;  /* VFS_MAX_FD */
}

/* Note: sync() is already defined earlier in the file */

/* fsync - sync a single file */
EXPORT int fsync(int fd)
{
    return (int)_check(syscall1(95 /* SYS_fsync */, fd));
}

/* fdatasync - sync file data (same as fsync for us) */
EXPORT int fdatasync(int fd)
{
    return fsync(fd);
}

/* chroot - change root directory */
EXPORT int chroot(const char *path)
{
    return (int)_check(syscall1(61 /* SYS_chroot */, path));
}

/* fchdir - change working directory via fd */
EXPORT int fchdir(int fd)
{
    return (int)_check(syscall1(13 /* SYS_fchdir */, fd));
}

/* seteuid/setegid/setreuid/setregid (setuid/setgid already defined) */
EXPORT int seteuid(uid_t euid)
{
    return (int)_check(syscall1(183 /* SYS_seteuid */, euid));
}

EXPORT int setegid(gid_t egid)
{
    return (int)_check(syscall1(182 /* SYS_setegid */, egid));
}

EXPORT int setreuid(uid_t ruid, uid_t euid)
{
    return (int)_check(syscall2(126 /* SYS_setreuid */, ruid, euid));
}

EXPORT int setregid(gid_t rgid, gid_t egid)
{
    return (int)_check(syscall2(127 /* SYS_setregid */, rgid, egid));
}

/* getgroups - get supplementary group IDs */
EXPORT int getgroups(int size, gid_t *list)
{
    return (int)_check(syscall2(79 /* SYS_getgroups */, size, list));
}

/* setgroups - set supplementary group IDs */
EXPORT int setgroups(int size, const gid_t *list)
{
    return (int)_check(syscall2(80 /* SYS_setgroups */, size, list));
}

/* nice - change process priority */
EXPORT int nice(int inc)
{
    /* Not really implemented in kernel, stub that succeeds */
    (void)inc;
    return 0;
}

/* alarm - set alarm clock (stub) */
EXPORT unsigned int alarm(unsigned int seconds)
{
    /* Not implemented - would need kernel support */
    (void)seconds;
    return 0;
}

/* pause - wait for a signal (stub) */
EXPORT int pause(void)
{
    /* Block forever - would need proper signal support */
    while (1) {
        struct _timespec ts = { 3600, 0 };
        nanosleep(&ts, NULL);
    }
    return -1;
}

/* fpathconf - get configuration values for file */
EXPORT long fpathconf(int fd, int name)
{
    (void)fd;
    switch (name) {
    case 1:  /* _PC_LINK_MAX */
        return 32767;
    case 2:  /* _PC_MAX_CANON */
        return 255;
    case 3:  /* _PC_MAX_INPUT */
        return 255;
    case 4:  /* _PC_NAME_MAX */
        return 255;
    case 5:  /* _PC_PATH_MAX */
        return 1024;
    case 6:  /* _PC_PIPE_BUF */
        return 4096;
    default:
        errno = EINVAL;
        return -1;
    }
}

/* pathconf - get configuration values for path */
EXPORT long pathconf(const char *path, int name)
{
    (void)path;
    return fpathconf(-1, name);
}

/* confstr - get configuration strings */
EXPORT size_t confstr(int name, char *buf, size_t len)
{
    const char *val = NULL;
    
    switch (name) {
    case 1:  /* _CS_PATH */
        val = "/bin:/usr/bin";
        break;
    default:
        errno = EINVAL;
        return 0;
    }
    
    size_t vlen = strlen(val) + 1;
    if (buf && len > 0) {
        size_t copy = len < vlen ? len : vlen;
        memcpy(buf, val, copy);
        if (len < vlen) buf[len - 1] = '\0';
    }
    return vlen;
}

/* ============================================================================
 * Additional stdlib.h functions
 * ============================================================================ */

/* div/ldiv/lldiv - compute quotient and remainder */
typedef struct { int quot; int rem; } div_t;
typedef struct { long quot; long rem; } ldiv_t;
typedef struct { long long quot; long long rem; } lldiv_t;

EXPORT div_t div(int numer, int denom)
{
    div_t result;
    result.quot = numer / denom;
    result.rem = numer % denom;
    return result;
}

EXPORT ldiv_t ldiv(long numer, long denom)
{
    ldiv_t result;
    result.quot = numer / denom;
    result.rem = numer % denom;
    return result;
}

EXPORT lldiv_t lldiv(long long numer, long long denom)
{
    lldiv_t result;
    result.quot = numer / denom;
    result.rem = numer % denom;
    return result;
}

/* llabs - absolute value of long long */
EXPORT long long llabs(long long n)
{
    return n < 0 ? -n : n;
}

/* imaxabs - absolute value of intmax_t */
EXPORT long long imaxabs(long long n)
{
    return llabs(n);
}

/* realpath - resolve pathname */
EXPORT char *realpath(const char *path, char *resolved_path)
{
    static char _realpath_buf[1024];
    char *buf = resolved_path ? resolved_path : _realpath_buf;
    
    /* Handle absolute paths */
    if (path[0] == '/') {
        /* Start with root */
        buf[0] = '\0';
    } else {
        /* Start with cwd */
        if (getcwd(buf, 1024) == NULL)
            return NULL;
    }
    
    const char *p = path;
    while (*p) {
        /* Skip leading slashes */
        while (*p == '/') p++;
        if (*p == '\0') break;
        
        /* Find end of component */
        const char *end = p;
        while (*end && *end != '/') end++;
        size_t len = end - p;
        
        if (len == 1 && p[0] == '.') {
            /* "." - stay in current dir */
        } else if (len == 2 && p[0] == '.' && p[1] == '.') {
            /* ".." - go up one level */
            char *slash = strrchr(buf, '/');
            if (slash && slash != buf)
                *slash = '\0';
            else if (slash == buf)
                buf[1] = '\0';
        } else {
            /* Regular component */
            size_t buflen = strlen(buf);
            if (buflen == 0 || buf[buflen - 1] != '/') {
                if (buflen + 1 < 1024) {
                    buf[buflen++] = '/';
                    buf[buflen] = '\0';
                }
            }
            if (buflen + len < 1024) {
                memcpy(buf + buflen, p, len);
                buf[buflen + len] = '\0';
            }
        }
        p = end;
    }
    
    /* Ensure we have at least "/" */
    if (buf[0] == '\0') {
        buf[0] = '/';
        buf[1] = '\0';
    }
    
    /* Verify path exists */
    struct { uint32_t st_dev; uint16_t st_mode; char _pad[136]; } st;
    if (stat(buf, &st) < 0)
        return NULL;
    
    return buf;
}

/* mkstemp - create temporary file */
EXPORT int mkstemp(char *template)
{
    size_t len = strlen(template);
    if (len < 6) {
        errno = EINVAL;
        return -1;
    }
    
    /* Check for XXXXXX suffix */
    char *p = template + len - 6;
    for (int i = 0; i < 6; i++) {
        if (p[i] != 'X') {
            errno = EINVAL;
            return -1;
        }
    }
    
    /* Generate random suffix */
    static const char chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    unsigned char randbuf[6];
    getentropy(randbuf, 6);
    
    for (int attempt = 0; attempt < 100; attempt++) {
        for (int i = 0; i < 6; i++) {
            p[i] = chars[(randbuf[i] + attempt * i) % 62];
        }
        
        int fd = open(template, O_RDWR | O_CREAT | O_EXCL, 0600);
        if (fd >= 0)
            return fd;
        
        if (errno != EEXIST)
            return -1;
    }
    
    errno = EEXIST;
    return -1;
}

/* mkostemp - create temporary file with flags */
EXPORT int mkostemp(char *template, int flags)
{
    size_t len = strlen(template);
    if (len < 6) {
        errno = EINVAL;
        return -1;
    }
    
    char *p = template + len - 6;
    for (int i = 0; i < 6; i++) {
        if (p[i] != 'X') {
            errno = EINVAL;
            return -1;
        }
    }
    
    static const char chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    unsigned char randbuf[6];
    getentropy(randbuf, 6);
    
    for (int attempt = 0; attempt < 100; attempt++) {
        for (int i = 0; i < 6; i++) {
            p[i] = chars[(randbuf[i] + attempt * i) % 62];
        }
        
        int fd = open(template, O_RDWR | O_CREAT | O_EXCL | flags, 0600);
        if (fd >= 0)
            return fd;
        
        if (errno != EEXIST)
            return -1;
    }
    
    errno = EEXIST;
    return -1;
}

/* mkdtemp - create temporary directory */
EXPORT char *mkdtemp(char *template)
{
    size_t len = strlen(template);
    if (len < 6) {
        errno = EINVAL;
        return NULL;
    }
    
    char *p = template + len - 6;
    for (int i = 0; i < 6; i++) {
        if (p[i] != 'X') {
            errno = EINVAL;
            return NULL;
        }
    }
    
    static const char chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    unsigned char randbuf[6];
    getentropy(randbuf, 6);
    
    for (int attempt = 0; attempt < 100; attempt++) {
        for (int i = 0; i < 6; i++) {
            p[i] = chars[(randbuf[i] + attempt * i) % 62];
        }
        
        if (mkdir(template, 0700) == 0)
            return template;
        
        if (errno != EEXIST)
            return NULL;
    }
    
    errno = EEXIST;
    return NULL;
}

/* getloadavg - get system load averages (stub) */
EXPORT int getloadavg(double *loadavg, int nelem)
{
    for (int i = 0; i < nelem && i < 3; i++)
        loadavg[i] = 0.0;
    return nelem < 3 ? nelem : 3;
}

/* posix_memalign - allocate aligned memory */
EXPORT int posix_memalign(void **memptr, size_t alignment, size_t size)
{
    if (alignment < sizeof(void *) || (alignment & (alignment - 1)) != 0) {
        return EINVAL;
    }
    
    /* Allocate extra space for alignment and store original pointer */
    void *mem = malloc(size + alignment + sizeof(void *));
    if (mem == NULL)
        return ENOMEM;
    
    /* Align the pointer */
    uintptr_t addr = (uintptr_t)mem + sizeof(void *);
    uintptr_t aligned = (addr + alignment - 1) & ~(alignment - 1);
    
    /* Store original pointer just before aligned address */
    ((void **)aligned)[-1] = mem;
    
    *memptr = (void *)aligned;
    return 0;
}

/* aligned_alloc - allocate aligned memory (C11) */
EXPORT void *aligned_alloc(size_t alignment, size_t size)
{
    void *ptr;
    if (posix_memalign(&ptr, alignment, size) != 0)
        return NULL;
    return ptr;
}

/* ============================================================================
 * Resource limits (stubs)
 * ============================================================================ */

struct rlimit {
    unsigned long rlim_cur;  /* Soft limit */
    unsigned long rlim_max;  /* Hard limit */
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

EXPORT int getrlimit(int resource, struct rlimit *rlim)
{
    if (!rlim) {
        errno = EFAULT;
        return -1;
    }
    
    switch (resource) {
    case RLIMIT_NOFILE:
        rlim->rlim_cur = 256;
        rlim->rlim_max = 256;
        break;
    case RLIMIT_STACK:
        rlim->rlim_cur = 8 * 1024 * 1024;  /* 8MB */
        rlim->rlim_max = 64 * 1024 * 1024; /* 64MB */
        break;
    default:
        rlim->rlim_cur = RLIM_INFINITY;
        rlim->rlim_max = RLIM_INFINITY;
        break;
    }
    return 0;
}

EXPORT int setrlimit(int resource, const struct rlimit *rlim)
{
    (void)resource; (void)rlim;
    /* Silently succeed - we don't actually enforce limits */
    return 0;
}

/* getrusage - get resource usage (stub) */
struct rusage {
    struct _timeval ru_utime;
    struct _timeval ru_stime;
    long ru_maxrss;
    long ru_ixrss;
    long ru_idrss;
    long ru_isrss;
    long ru_minflt;
    long ru_majflt;
    long ru_nswap;
    long ru_inblock;
    long ru_oublock;
    long ru_msgsnd;
    long ru_msgrcv;
    long ru_nsignals;
    long ru_nvcsw;
    long ru_nivcsw;
};

EXPORT int getrusage(int who, struct rusage *usage)
{
    (void)who;
    if (!usage) {
        errno = EFAULT;
        return -1;
    }
    memset(usage, 0, sizeof(*usage));
    return 0;
}

/* ============================================================================
 * Assertion handler
 * ============================================================================ */

EXPORT NORETURN void __assert_fail(const char *expr, const char *file, int line, const char *func)
{
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
    char *p = line_buf + 15;
    *p = '\0';
    int n = line;
    if (n == 0) {
        *--p = '0';
    } else {
        while (n > 0) {
            *--p = '0' + (n % 10);
            n /= 10;
        }
    }
    write(2, p, strlen(p));
    
    if (func) {
        write(2, msg4, strlen(msg4));
        write(2, func, strlen(func));
    }
    write(2, msg5, 1);
    
    abort();
}

/* ============================================================================
 * End of libSystem.B.dylib implementation
 * ============================================================================ */
