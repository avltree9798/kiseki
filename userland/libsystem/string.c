/*
 * Kiseki OS - String Operations Implementation
 */

#include <string.h>
#include <stdlib.h>
#include <errno.h>

/* ============================================================================
 * String length and comparison
 * ============================================================================ */

size_t strlen(const char *s)
{
    const char *p = s;
    while (*p)
        p++;
    return (size_t)(p - s);
}

int strcmp(const char *s1, const char *s2)
{
    while (*s1 && *s1 == *s2) {
        s1++;
        s2++;
    }
    return (unsigned char)*s1 - (unsigned char)*s2;
}

int strncmp(const char *s1, const char *s2, size_t n)
{
    if (n == 0)
        return 0;
    while (n-- > 1 && *s1 && *s1 == *s2) {
        s1++;
        s2++;
    }
    return (unsigned char)*s1 - (unsigned char)*s2;
}

/* ============================================================================
 * String copy
 * ============================================================================ */

char *strcpy(char *dst, const char *src)
{
    char *ret = dst;
    while ((*dst++ = *src++) != '\0')
        ;
    return ret;
}

char *strncpy(char *dst, const char *src, size_t n)
{
    char *ret = dst;
    while (n > 0 && *src) {
        *dst++ = *src++;
        n--;
    }
    while (n > 0) {
        *dst++ = '\0';
        n--;
    }
    return ret;
}

/* ============================================================================
 * String concatenation
 * ============================================================================ */

char *strcat(char *dst, const char *src)
{
    char *ret = dst;
    while (*dst)
        dst++;
    while ((*dst++ = *src++) != '\0')
        ;
    return ret;
}

char *strncat(char *dst, const char *src, size_t n)
{
    char *ret = dst;
    while (*dst)
        dst++;
    while (n > 0 && *src) {
        *dst++ = *src++;
        n--;
    }
    *dst = '\0';
    return ret;
}

/* ============================================================================
 * Memory operations
 * ============================================================================ */

void *memcpy(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;

    /* Word-aligned fast path */
    if (n >= 8 && ((uintptr_t)d & 7) == 0 && ((uintptr_t)s & 7) == 0) {
        uint64_t *d64 = (uint64_t *)d;
        const uint64_t *s64 = (const uint64_t *)s;
        while (n >= 8) {
            *d64++ = *s64++;
            n -= 8;
        }
        d = (unsigned char *)d64;
        s = (const unsigned char *)s64;
    }

    while (n--)
        *d++ = *s++;

    return dst;
}

void *memmove(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;

    if (d == s || n == 0)
        return dst;

    if (d < s) {
        while (n--)
            *d++ = *s++;
    } else {
        d += n;
        s += n;
        while (n--)
            *--d = *--s;
    }

    return dst;
}

void *memset(void *s, int c, size_t n)
{
    unsigned char *p = (unsigned char *)s;
    unsigned char val = (unsigned char)c;

    /* Word-aligned fast path for zero fill */
    if (val == 0 && n >= 8 && ((uintptr_t)p & 7) == 0) {
        uint64_t *p64 = (uint64_t *)p;
        while (n >= 8) {
            *p64++ = 0;
            n -= 8;
        }
        p = (unsigned char *)p64;
    }

    while (n--)
        *p++ = val;

    return s;
}

int memcmp(const void *s1, const void *s2, size_t n)
{
    const unsigned char *p1 = (const unsigned char *)s1;
    const unsigned char *p2 = (const unsigned char *)s2;

    while (n--) {
        if (*p1 != *p2)
            return *p1 - *p2;
        p1++;
        p2++;
    }
    return 0;
}

void *memchr(const void *s, int c, size_t n)
{
    const unsigned char *p = (const unsigned char *)s;
    unsigned char val = (unsigned char)c;

    while (n--) {
        if (*p == val)
            return (void *)p;
        p++;
    }
    return NULL;
}

/* ============================================================================
 * String search
 * ============================================================================ */

char *strchr(const char *s, int c)
{
    char ch = (char)c;
    while (*s) {
        if (*s == ch)
            return (char *)s;
        s++;
    }
    return ch == '\0' ? (char *)s : NULL;
}

char *strrchr(const char *s, int c)
{
    char ch = (char)c;
    const char *last = NULL;

    while (*s) {
        if (*s == ch)
            last = s;
        s++;
    }
    if (ch == '\0')
        return (char *)s;

    return (char *)last;
}

char *strstr(const char *haystack, const char *needle)
{
    size_t nlen;

    if (*needle == '\0')
        return (char *)haystack;

    nlen = strlen(needle);

    while (*haystack) {
        if (*haystack == *needle && strncmp(haystack, needle, nlen) == 0)
            return (char *)haystack;
        haystack++;
    }
    return NULL;
}

char *strdup(const char *s)
{
    size_t len = strlen(s) + 1;
    char *new = malloc(len);
    if (new)
        memcpy(new, s, len);
    return new;
}

char *strndup(const char *s, size_t n)
{
    size_t len = strlen(s);
    if (len > n)
        len = n;
    char *new = malloc(len + 1);
    if (new) {
        memcpy(new, s, len);
        new[len] = '\0';
    }
    return new;
}

/* ============================================================================
 * Tokenize
 * ============================================================================ */

static char *_strtok_last = NULL;

char *strtok(char *str, const char *delim)
{
    return strtok_r(str, delim, &_strtok_last);
}

char *strtok_r(char *str, const char *delim, char **saveptr)
{
    char *start;

    if (str == NULL)
        str = *saveptr;
    if (str == NULL)
        return NULL;

    /* Skip leading delimiters */
    str += strspn(str, delim);
    if (*str == '\0') {
        *saveptr = NULL;
        return NULL;
    }

    start = str;

    /* Find end of token */
    str += strcspn(str, delim);
    if (*str) {
        *str = '\0';
        *saveptr = str + 1;
    } else {
        *saveptr = NULL;
    }

    return start;
}

/* ============================================================================
 * Error string
 * ============================================================================ */

static const char *_error_strings[] = {
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

#define NERROR_STRINGS  (sizeof(_error_strings) / sizeof(_error_strings[0]))

static char _unknown_error[32];

char *strerror(int errnum)
{
    if (errnum >= 0 && (size_t)errnum < NERROR_STRINGS && _error_strings[errnum])
        return (char *)_error_strings[errnum];

    /* Format "Unknown error: %d" manually */
    char *p = _unknown_error;
    const char *prefix = "Unknown error: ";
    while (*prefix)
        *p++ = *prefix++;

    /* Simple int-to-string */
    if (errnum < 0) {
        *p++ = '-';
        errnum = -errnum;
    }
    char digits[12];
    int i = 0;
    do {
        digits[i++] = '0' + (errnum % 10);
        errnum /= 10;
    } while (errnum > 0);
    while (i > 0)
        *p++ = digits[--i];
    *p = '\0';

    return _unknown_error;
}

/* ============================================================================
 * Span / break
 * ============================================================================ */

size_t strspn(const char *s, const char *accept)
{
    const char *p = s;
    while (*p) {
        const char *a = accept;
        bool found = false;
        while (*a) {
            if (*p == *a) {
                found = true;
                break;
            }
            a++;
        }
        if (!found)
            break;
        p++;
    }
    return (size_t)(p - s);
}

size_t strcspn(const char *s, const char *reject)
{
    const char *p = s;
    while (*p) {
        const char *r = reject;
        while (*r) {
            if (*p == *r)
                return (size_t)(p - s);
            r++;
        }
        p++;
    }
    return (size_t)(p - s);
}

char *strpbrk(const char *s, const char *accept)
{
    while (*s) {
        const char *a = accept;
        while (*a) {
            if (*s == *a)
                return (char *)s;
            a++;
        }
        s++;
    }
    return NULL;
}
