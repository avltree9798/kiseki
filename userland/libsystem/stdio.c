/*
 * Kiseki OS - Standard I/O Implementation
 *
 * Full printf with width, precision, padding, left-align, and all specifiers.
 * FILE-based I/O with buffering.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <syscall.h>

/* ============================================================================
 * Standard streams
 * ============================================================================ */

static FILE _stdin_file  = {
    .fd = 0, .flags = _FILE_READ | _FILE_LINEBUF, .buf = NULL,
    .bufsiz = 0, .buf_pos = 0, .buf_len = 0, .ungetc_buf = EOF
};
static FILE _stdout_file = {
    .fd = 1, .flags = _FILE_WRITE | _FILE_LINEBUF, .buf = NULL,
    .bufsiz = 0, .buf_pos = 0, .buf_len = 0, .ungetc_buf = EOF
};
static FILE _stderr_file = {
    .fd = 2, .flags = _FILE_WRITE | _FILE_UNBUF, .buf = NULL,
    .bufsiz = 0, .buf_pos = 0, .buf_len = 0, .ungetc_buf = EOF
};

FILE *stdin  = &_stdin_file;
FILE *stdout = &_stdout_file;
FILE *stderr = &_stderr_file;

/* Table of open FILEs for fopen/fclose */
static FILE _file_table[FOPEN_MAX];
static int  _file_table_init = 0;

static void _init_file_table(void)
{
    if (_file_table_init)
        return;
    for (int i = 0; i < FOPEN_MAX; i++)
        _file_table[i].fd = -1;
    _file_table_init = 1;
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
 * Low-level write helpers
 * ============================================================================ */

static ssize_t _file_write_raw(FILE *stream, const void *buf, size_t n)
{
    return write(stream->fd, buf, n);
}

static ssize_t _file_read_raw(FILE *stream, void *buf, size_t n)
{
    return read(stream->fd, buf, n);
}

/* ============================================================================
 * Buffered output
 * ============================================================================ */

int fflush(FILE *stream)
{
    if (stream == NULL) {
        /* Flush all writable streams */
        fflush(stdout);
        fflush(stderr);
        for (int i = 0; i < FOPEN_MAX; i++) {
            if (_file_table[i].fd >= 0 && (_file_table[i].flags & _FILE_WRITE))
                fflush(&_file_table[i]);
        }
        return 0;
    }

    if (!(stream->flags & _FILE_WRITE))
        return 0;

    if (stream->buf && stream->buf_pos > 0) {
        ssize_t ret = _file_write_raw(stream, stream->buf, stream->buf_pos);
        if (ret < 0) {
            stream->flags |= _FILE_ERROR;
            errno = -(int)ret;
            return EOF;
        }
        stream->buf_pos = 0;
    }
    return 0;
}

/* Ensure stream has a write buffer allocated */
static void _ensure_write_buf(FILE *stream)
{
    if (stream->buf == NULL && !(stream->flags & _FILE_UNBUF)) {
        stream->buf = malloc(BUFSIZ);
        if (stream->buf) {
            stream->bufsiz = BUFSIZ;
            stream->flags |= _FILE_MYBUF;
        }
    }
}

/* ============================================================================
 * Character I/O
 * ============================================================================ */

int fputc(int c, FILE *stream)
{
    unsigned char ch = (unsigned char)c;

    if (stream->flags & _FILE_UNBUF) {
        /* Unbuffered: write directly */
        ssize_t ret = _file_write_raw(stream, &ch, 1);
        if (ret != 1) {
            stream->flags |= _FILE_ERROR;
            return EOF;
        }
        return ch;
    }

    _ensure_write_buf(stream);

    if (stream->buf == NULL) {
        /* Couldn't allocate buffer, write directly */
        ssize_t ret = _file_write_raw(stream, &ch, 1);
        return ret == 1 ? ch : EOF;
    }

    stream->buf[stream->buf_pos++] = ch;

    /* Flush on buffer full or newline (line buffered) */
    if (stream->buf_pos >= stream->bufsiz ||
        ((stream->flags & _FILE_LINEBUF) && ch == '\n')) {
        if (fflush(stream) == EOF)
            return EOF;
    }

    return ch;
}

int putchar(int c)
{
    return fputc(c, stdout);
}

int putc(int c, FILE *stream)
{
    return fputc(c, stream);
}

int fputs(const char *s, FILE *stream)
{
    while (*s) {
        if (fputc(*s++, stream) == EOF)
            return EOF;
    }
    return 0;
}

int puts(const char *s)
{
    if (fputs(s, stdout) == EOF)
        return EOF;
    if (fputc('\n', stdout) == EOF)
        return EOF;
    return 0;
}

/* ============================================================================
 * Character input
 * ============================================================================ */

int fgetc(FILE *stream)
{
    /* Check ungetc buffer first */
    if (stream->ungetc_buf != EOF) {
        int c = stream->ungetc_buf;
        stream->ungetc_buf = EOF;
        return c;
    }

    unsigned char ch;
    ssize_t ret = _file_read_raw(stream, &ch, 1);
    if (ret <= 0) {
        stream->flags |= (ret == 0) ? _FILE_EOF : _FILE_ERROR;
        return EOF;
    }
    return ch;
}

int getchar(void)
{
    return fgetc(stdin);
}

int getc(FILE *stream)
{
    return fgetc(stream);
}

int ungetc(int c, FILE *stream)
{
    if (c == EOF)
        return EOF;
    stream->ungetc_buf = c;
    stream->flags &= ~_FILE_EOF;
    return c;
}

char *fgets(char *s, int size, FILE *stream)
{
    if (size <= 0)
        return NULL;
    if (size == 1) {
        s[0] = '\0';
        return s;
    }

    char *p = s;
    int n = size - 1;

    while (n > 0) {
        int c = fgetc(stream);
        if (c == EOF) {
            if (p == s)
                return NULL;
            break;
        }
        *p++ = (char)c;
        n--;
        if (c == '\n')
            break;
    }
    *p = '\0';
    return s;
}

/* ============================================================================
 * File open/close
 * ============================================================================ */

static int _parse_mode(const char *mode, int *flags)
{
    int f = 0;
    int file_flags = 0;

    switch (*mode) {
    case 'r':
        f = O_RDONLY;
        file_flags = _FILE_READ;
        break;
    case 'w':
        f = O_WRONLY | O_CREAT | O_TRUNC;
        file_flags = _FILE_WRITE;
        break;
    case 'a':
        f = O_WRONLY | O_CREAT | O_APPEND;
        file_flags = _FILE_WRITE | _FILE_APPEND;
        break;
    default:
        return -1;
    }
    mode++;

    if (*mode == 'b')
        mode++;         /* Binary mode: no-op on our OS */

    if (*mode == '+') {
        f = (f & ~(O_RDONLY | O_WRONLY)) | O_RDWR;
        file_flags |= _FILE_READ | _FILE_WRITE;
        mode++;
    }

    if (*mode == 'b')
        mode++;

    *flags = f;
    return file_flags;
}

FILE *fopen(const char *pathname, const char *mode)
{
    int oflags;
    int file_flags = _parse_mode(mode, &oflags);
    if (file_flags < 0) {
        errno = EINVAL;
        return NULL;
    }

    int fd = open(pathname, oflags, 0666);
    if (fd < 0)
        return NULL;

    FILE *fp = _alloc_file();
    if (fp == NULL) {
        close(fd);
        errno = EMFILE;
        return NULL;
    }

    fp->fd = fd;
    fp->flags = file_flags;
    fp->buf = NULL;
    fp->bufsiz = 0;
    fp->buf_pos = 0;
    fp->buf_len = 0;
    fp->ungetc_buf = EOF;

    return fp;
}

FILE *fdopen(int fd, const char *mode)
{
    int oflags;
    int file_flags = _parse_mode(mode, &oflags);
    if (file_flags < 0) {
        errno = EINVAL;
        return NULL;
    }
    (void)oflags;   /* fd is already open */

    FILE *fp = _alloc_file();
    if (fp == NULL) {
        errno = EMFILE;
        return NULL;
    }

    fp->fd = fd;
    fp->flags = file_flags;
    fp->buf = NULL;
    fp->bufsiz = 0;
    fp->buf_pos = 0;
    fp->buf_len = 0;
    fp->ungetc_buf = EOF;

    return fp;
}

int fclose(FILE *stream)
{
    if (stream == NULL)
        return EOF;

    fflush(stream);

    int ret = close(stream->fd);

    if (stream->flags & _FILE_MYBUF)
        free(stream->buf);

    stream->fd = -1;
    stream->buf = NULL;
    stream->flags = 0;

    return ret < 0 ? EOF : 0;
}

/* ============================================================================
 * Block I/O
 * ============================================================================ */

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    size_t total = size * nmemb;
    if (total == 0)
        return 0;

    unsigned char *buf = (unsigned char *)ptr;
    size_t done = 0;

    while (done < total) {
        int c = fgetc(stream);
        if (c == EOF)
            break;
        buf[done++] = (unsigned char)c;
    }

    return done / size;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    size_t total = size * nmemb;
    if (total == 0)
        return 0;

    const unsigned char *buf = (const unsigned char *)ptr;
    size_t done = 0;

    while (done < total) {
        if (fputc(buf[done], stream) == EOF)
            break;
        done++;
    }

    return done / size;
}

/* ============================================================================
 * Seek / tell
 * ============================================================================ */

int fseek(FILE *stream, long offset, int whence)
{
    /* Flush output buffer and discard input buffer */
    fflush(stream);
    stream->buf_pos = 0;
    stream->buf_len = 0;
    stream->ungetc_buf = EOF;
    stream->flags &= ~(_FILE_EOF | _FILE_ERROR);

    off_t ret = lseek(stream->fd, (off_t)offset, whence);
    if (ret < 0)
        return -1;
    return 0;
}

long ftell(FILE *stream)
{
    off_t pos = lseek(stream->fd, 0, SEEK_CUR);
    if (pos < 0)
        return -1L;

    /* Adjust for buffered but unflushed data */
    if (stream->flags & _FILE_WRITE)
        pos += (off_t)stream->buf_pos;

    return (long)pos;
}

void rewind(FILE *stream)
{
    fseek(stream, 0L, SEEK_SET);
    stream->flags &= ~_FILE_ERROR;
}

int feof(FILE *stream)
{
    return (stream->flags & _FILE_EOF) ? 1 : 0;
}

int ferror(FILE *stream)
{
    return (stream->flags & _FILE_ERROR) ? 1 : 0;
}

void clearerr(FILE *stream)
{
    stream->flags &= ~(_FILE_EOF | _FILE_ERROR);
}

int fileno(FILE *stream)
{
    return stream->fd;
}

/* ============================================================================
 * printf Engine
 *
 * Full format support: %d %i %u %x %X %o %s %c %p %ld %lu %lx %lX %lld %llu
 * Width, precision, zero-padding, left-align (-), space, plus, hash (#)
 * ============================================================================ */

/* Output callback type for generic formatter */
typedef struct {
    void (*putch)(char c, void *ctx);
    void *ctx;
    int count;
} _fmt_output;

static void _fmt_putch(_fmt_output *out, char c)
{
    out->putch(c, out->ctx);
    out->count++;
}

/* Pad with a character */
static void _fmt_pad(_fmt_output *out, char c, int count)
{
    while (count-- > 0)
        _fmt_putch(out, c);
}

/* Output a string with width/precision */
static void _fmt_puts(_fmt_output *out, const char *s, int width,
                       int precision, int left_align)
{
    size_t len = strlen(s);
    if (precision >= 0 && (size_t)precision < len)
        len = (size_t)precision;

    int pad = width - (int)len;
    if (pad < 0) pad = 0;

    if (!left_align)
        _fmt_pad(out, ' ', pad);

    for (size_t i = 0; i < len; i++)
        _fmt_putch(out, s[i]);

    if (left_align)
        _fmt_pad(out, ' ', pad);
}

/* Output an unsigned number in the given base */
static void _fmt_num(_fmt_output *out, uint64_t val, int base,
                      int is_signed, int is_negative,
                      int width, int precision, int left_align,
                      int zero_pad, int plus_sign, int space_sign,
                      int hash_flag, int uppercase)
{
    char buf[66];   /* Enough for 64-bit binary + sign + prefix */
    char *p = buf + sizeof(buf);
    *--p = '\0';

    const char *digits = uppercase ? "0123456789ABCDEF" : "0123456789abcdef";

    if (val == 0) {
        if (precision != 0)
            *--p = '0';
    } else {
        while (val > 0) {
            *--p = digits[val % (unsigned)base];
            val /= (unsigned)base;
        }
    }

    /* Number of digit characters */
    int num_digits = (int)(buf + sizeof(buf) - 1 - p);

    /* Precision: minimum number of digits */
    int prec_pad = 0;
    if (precision > num_digits)
        prec_pad = precision - num_digits;

    /* Prefix for # flag */
    const char *prefix = "";
    int prefix_len = 0;
    if (hash_flag) {
        if (base == 8 && prec_pad == 0 && num_digits > 0) {
            prefix = "0";
            prefix_len = 1;
        } else if (base == 16 && num_digits > 0) {
            prefix = uppercase ? "0X" : "0x";
            prefix_len = 2;
        }
    }

    /* Sign character */
    char sign_ch = 0;
    if (is_signed) {
        if (is_negative)
            sign_ch = '-';
        else if (plus_sign)
            sign_ch = '+';
        else if (space_sign)
            sign_ch = ' ';
    }

    int sign_len = sign_ch ? 1 : 0;
    int total = sign_len + prefix_len + prec_pad + num_digits;

    int pad = width - total;
    if (pad < 0) pad = 0;

    if (!left_align && !zero_pad)
        _fmt_pad(out, ' ', pad);

    if (sign_ch)
        _fmt_putch(out, sign_ch);

    for (int i = 0; i < prefix_len; i++)
        _fmt_putch(out, prefix[i]);

    if (!left_align && zero_pad)
        _fmt_pad(out, '0', pad);

    _fmt_pad(out, '0', prec_pad);

    while (*p)
        _fmt_putch(out, *p++);

    if (left_align)
        _fmt_pad(out, ' ', pad);
}

/* Core vprintf engine */
static int _fmt_core(_fmt_output *out, const char *fmt, va_list ap)
{
    out->count = 0;

    while (*fmt) {
        if (*fmt != '%') {
            _fmt_putch(out, *fmt++);
            continue;
        }
        fmt++;  /* skip '%' */

        /* Flags */
        int left_align = 0;
        int zero_pad = 0;
        int plus_sign = 0;
        int space_sign = 0;
        int hash_flag = 0;

        for (;;) {
            if (*fmt == '-')      { left_align = 1; fmt++; }
            else if (*fmt == '0') { zero_pad = 1; fmt++; }
            else if (*fmt == '+') { plus_sign = 1; fmt++; }
            else if (*fmt == ' ') { space_sign = 1; fmt++; }
            else if (*fmt == '#') { hash_flag = 1; fmt++; }
            else break;
        }

        /* Left-align overrides zero-padding */
        if (left_align)
            zero_pad = 0;

        /* Width */
        int width = 0;
        if (*fmt == '*') {
            width = va_arg(ap, int);
            if (width < 0) {
                left_align = 1;
                width = -width;
            }
            fmt++;
        } else {
            while (*fmt >= '0' && *fmt <= '9') {
                width = width * 10 + (*fmt - '0');
                fmt++;
            }
        }

        /* Precision */
        int precision = -1;
        if (*fmt == '.') {
            fmt++;
            precision = 0;
            if (*fmt == '*') {
                precision = va_arg(ap, int);
                if (precision < 0)
                    precision = -1;
                fmt++;
            } else {
                while (*fmt >= '0' && *fmt <= '9') {
                    precision = precision * 10 + (*fmt - '0');
                    fmt++;
                }
            }
            /* Precision disables zero-padding for integers */
            if (precision >= 0)
                zero_pad = 0;
        }

        /* Length modifier */
        int length = 0;    /* 0=int, 1=long, 2=long long */
        if (*fmt == 'l') {
            length = 1;
            fmt++;
            if (*fmt == 'l') {
                length = 2;
                fmt++;
            }
        } else if (*fmt == 'h') {
            length = -1;    /* short */
            fmt++;
            if (*fmt == 'h') {
                length = -2; /* char */
                fmt++;
            }
        } else if (*fmt == 'z') {
            length = 1;     /* size_t = long on LP64 */
            fmt++;
        }

        /* Conversion specifier */
        switch (*fmt) {
        case 'd':
        case 'i': {
            int64_t val;
            if (length == 2)
                val = va_arg(ap, long long);
            else if (length == 1)
                val = va_arg(ap, long);
            else
                val = va_arg(ap, int);

            int neg = val < 0;
            uint64_t uval = neg ? (uint64_t)(-val) : (uint64_t)val;
            _fmt_num(out, uval, 10, 1, neg, width, precision,
                     left_align, zero_pad, plus_sign, space_sign,
                     hash_flag, 0);
            break;
        }

        case 'u': {
            uint64_t val;
            if (length == 2)
                val = va_arg(ap, unsigned long long);
            else if (length == 1)
                val = va_arg(ap, unsigned long);
            else
                val = va_arg(ap, unsigned int);

            _fmt_num(out, val, 10, 0, 0, width, precision,
                     left_align, zero_pad, plus_sign, space_sign,
                     hash_flag, 0);
            break;
        }

        case 'x':
        case 'X': {
            uint64_t val;
            if (length == 2)
                val = va_arg(ap, unsigned long long);
            else if (length == 1)
                val = va_arg(ap, unsigned long);
            else
                val = va_arg(ap, unsigned int);

            _fmt_num(out, val, 16, 0, 0, width, precision,
                     left_align, zero_pad, plus_sign, space_sign,
                     hash_flag, *fmt == 'X');
            break;
        }

        case 'o': {
            uint64_t val;
            if (length == 2)
                val = va_arg(ap, unsigned long long);
            else if (length == 1)
                val = va_arg(ap, unsigned long);
            else
                val = va_arg(ap, unsigned int);

            _fmt_num(out, val, 8, 0, 0, width, precision,
                     left_align, zero_pad, plus_sign, space_sign,
                     hash_flag, 0);
            break;
        }

        case 'p': {
            void *ptr = va_arg(ap, void *);
            if (ptr == NULL) {
                _fmt_puts(out, "(nil)", width, -1, left_align);
            } else {
                _fmt_putch(out, '0');
                _fmt_putch(out, 'x');
                _fmt_num(out, (uint64_t)(uintptr_t)ptr, 16, 0, 0,
                         width > 2 ? width - 2 : 0, precision,
                         left_align, zero_pad, 0, 0, 0, 0);
            }
            break;
        }

        case 's': {
            const char *s = va_arg(ap, const char *);
            if (s == NULL)
                s = "(null)";
            _fmt_puts(out, s, width, precision, left_align);
            break;
        }

        case 'c': {
            char c = (char)va_arg(ap, int);
            if (!left_align)
                _fmt_pad(out, ' ', width - 1);
            _fmt_putch(out, c);
            if (left_align)
                _fmt_pad(out, ' ', width - 1);
            break;
        }

        case '%':
            _fmt_putch(out, '%');
            break;

        case 'n': {
            if (length == 2)
                *va_arg(ap, long long *) = out->count;
            else if (length == 1)
                *va_arg(ap, long *) = out->count;
            else
                *va_arg(ap, int *) = out->count;
            break;
        }

        case '\0':
            /* Format string ended with '%' */
            return out->count;

        default:
            /* Unknown specifier, print it literally */
            _fmt_putch(out, '%');
            _fmt_putch(out, *fmt);
            break;
        }

        fmt++;
    }

    return out->count;
}

/* ============================================================================
 * printf variants
 * ============================================================================ */

/* Callback for FILE* output */
struct _file_ctx {
    FILE *fp;
};

static void _file_putch(char c, void *ctx)
{
    struct _file_ctx *fc = (struct _file_ctx *)ctx;
    fputc(c, fc->fp);
}

int vfprintf(FILE *stream, const char *fmt, va_list ap)
{
    struct _file_ctx ctx = { .fp = stream };
    _fmt_output out = { .putch = _file_putch, .ctx = &ctx, .count = 0 };
    return _fmt_core(&out, fmt, ap);
}

int fprintf(FILE *stream, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int ret = vfprintf(stream, fmt, ap);
    va_end(ap);
    return ret;
}

int vprintf(const char *fmt, va_list ap)
{
    return vfprintf(stdout, fmt, ap);
}

int printf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int ret = vprintf(fmt, ap);
    va_end(ap);
    return ret;
}

/* Callback for string output with bound */
struct _str_ctx {
    char *buf;
    size_t size;
    size_t pos;
};

static void _str_putch(char c, void *ctx)
{
    struct _str_ctx *sc = (struct _str_ctx *)ctx;
    if (sc->pos + 1 < sc->size)
        sc->buf[sc->pos] = c;
    sc->pos++;
}

int vsnprintf(char *str, size_t size, const char *fmt, va_list ap)
{
    struct _str_ctx ctx = { .buf = str, .size = size, .pos = 0 };
    _fmt_output out = { .putch = _str_putch, .ctx = &ctx, .count = 0 };
    int ret = _fmt_core(&out, fmt, ap);

    /* Null-terminate */
    if (size > 0) {
        if (ctx.pos < size)
            str[ctx.pos] = '\0';
        else
            str[size - 1] = '\0';
    }

    return ret;
}

int snprintf(char *str, size_t size, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int ret = vsnprintf(str, size, fmt, ap);
    va_end(ap);
    return ret;
}

int vsprintf(char *str, const char *fmt, va_list ap)
{
    return vsnprintf(str, (size_t)-1, fmt, ap);
}

int sprintf(char *str, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int ret = vsprintf(str, fmt, ap);
    va_end(ap);
    return ret;
}

/* dprintf - print to file descriptor */
struct _fd_ctx {
    int fd;
};

static void _fd_putch(char c, void *ctx)
{
    struct _fd_ctx *fc = (struct _fd_ctx *)ctx;
    write(fc->fd, &c, 1);
}

int dprintf(int fd, const char *fmt, ...)
{
    struct _fd_ctx ctx = { .fd = fd };
    _fmt_output out = { .putch = _fd_putch, .ctx = &ctx, .count = 0 };
    va_list ap;
    va_start(ap, fmt);
    int ret = _fmt_core(&out, fmt, ap);
    va_end(ap);
    return ret;
}

/* ============================================================================
 * perror, remove, rename
 * ============================================================================ */

void perror(const char *s)
{
    if (s && *s) {
        fputs(s, stderr);
        fputs(": ", stderr);
    }
    fputs(strerror(errno), stderr);
    fputc('\n', stderr);
}

int remove(const char *pathname)
{
    /* Try unlink first (works for files), then rmdir */
    int ret = unlink(pathname);
    if (ret < 0)
        ret = rmdir(pathname);
    return ret;
}

int rename(const char *oldpath, const char *newpath)
{
    long ret = syscall2(SYS_rename, (long)oldpath, (long)newpath);
    if (ret < 0) {
        errno = (int)(-ret);
        return -1;
    }
    return 0;
}
