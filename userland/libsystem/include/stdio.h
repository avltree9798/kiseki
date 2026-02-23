/*
 * Kiseki OS - Standard I/O
 */

#ifndef _LIBSYSTEM_STDIO_H
#define _LIBSYSTEM_STDIO_H

#include <types.h>

#define EOF         (-1)
#define BUFSIZ      1024

#define SEEK_SET    0
#define SEEK_CUR    1
#define SEEK_END    2

/* Buffering modes for setvbuf */
#define _IOFBF      0   /* Fully buffered */
#define _IOLBF      1   /* Line buffered */
#define _IONBF      2   /* Unbuffered */

/* Standard file descriptors */
#ifndef STDIN_FILENO
#define STDIN_FILENO    0
#define STDOUT_FILENO   1
#define STDERR_FILENO   2
#endif

/* Limits */
#define FOPEN_MAX       64      /* Max open FILE*s */
#define FILENAME_MAX    1024    /* Max filename length */
#define L_tmpnam        32      /* Max tmpnam buffer size */
#define TMP_MAX         10000   /* Max unique tmpnam names */

/* FILE flags (internal) */
#define _FILE_READ      0x01
#define _FILE_WRITE     0x02
#define _FILE_APPEND    0x04
#define _FILE_EOF       0x08
#define _FILE_ERROR     0x10
#define _FILE_UNBUF     0x20
#define _FILE_LINEBUF   0x40
#define _FILE_MYBUF     0x80    /* We allocated the buffer */

typedef struct _FILE {
    int         fd;             /* Underlying file descriptor */
    int         flags;          /* Mode and state flags */
    char       *buf;            /* I/O buffer */
    size_t      bufsiz;         /* Buffer size */
    size_t      buf_pos;        /* Current position in buffer */
    size_t      buf_len;        /* Valid bytes in buffer (for read) */
    int         ungetc_buf;     /* ungetc storage, EOF if empty */
} FILE;

/* File position type */
typedef long fpos_t;

extern FILE *stdin;
extern FILE *stdout;
extern FILE *stderr;

/* Formatted output */
#ifdef __TINYC__
/* TCC passes variadic args in registers, not on stack like Darwin ABI.
   Redirect to TCC-compatible versions that take explicit args. */
int     _printf_tcc(const char *fmt, void*, void*, void*, void*, void*, void*, void*);
int     _fprintf_tcc(FILE *stream, const char *fmt, void*, void*, void*, void*, void*, void*);
#define printf(fmt, ...)  _printf_tcc(fmt, ##__VA_ARGS__, 0, 0, 0, 0, 0, 0, 0)
#define fprintf(f, fmt, ...) _fprintf_tcc(f, fmt, ##__VA_ARGS__, 0, 0, 0, 0, 0, 0)
#else
int     printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
int     fprintf(FILE *stream, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
#endif
int     sprintf(char *str, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
int     snprintf(char *str, size_t size, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
int     vprintf(const char *fmt, va_list ap);
int     vfprintf(FILE *stream, const char *fmt, va_list ap);
int     vsprintf(char *str, const char *fmt, va_list ap);
int     vsnprintf(char *str, size_t size, const char *fmt, va_list ap);
int     dprintf(int fd, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

/* Formatted input */
int     scanf(const char *fmt, ...);
int     fscanf(FILE *stream, const char *fmt, ...);
int     sscanf(const char *str, const char *fmt, ...);
int     vscanf(const char *fmt, va_list ap);
int     vfscanf(FILE *stream, const char *fmt, va_list ap);
int     vsscanf(const char *str, const char *fmt, va_list ap);

/* Character output */
int     fputc(int c, FILE *stream);
int     fputs(const char *s, FILE *stream);
int     putchar(int c);
int     putc(int c, FILE *stream);
int     puts(const char *s);

/* Character input */
int     fgetc(FILE *stream);
int     getchar(void);
int     getc(FILE *stream);
int     ungetc(int c, FILE *stream);
char   *fgets(char *s, int size, FILE *stream);

/* File operations */
FILE   *fopen(const char *pathname, const char *mode);
int     fclose(FILE *stream);
size_t  fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
size_t  fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
int     fflush(FILE *stream);
int     fseek(FILE *stream, long offset, int whence);
long    ftell(FILE *stream);
void    rewind(FILE *stream);
int     feof(FILE *stream);
int     ferror(FILE *stream);
void    clearerr(FILE *stream);

/* Utility */
int     fileno(FILE *stream);
void    perror(const char *s);
int     remove(const char *pathname);
int     rename(const char *oldpath, const char *newpath);

/* Buffer control */
void    setbuf(FILE *stream, char *buf);
int     setvbuf(FILE *stream, char *buf, int mode, size_t size);

/* Stream operations */
FILE   *fdopen(int fd, const char *mode);
FILE   *freopen(const char *pathname, const char *mode, FILE *stream);

/* File position */
int     fgetpos(FILE *stream, fpos_t *pos);
int     fsetpos(FILE *stream, const fpos_t *pos);

/* Temporary files */
FILE   *tmpfile(void);
char   *tmpnam(char *s);

/* Line input (POSIX) */
ssize_t getline(char **lineptr, size_t *n, FILE *stream);
ssize_t getdelim(char **lineptr, size_t *n, int delim, FILE *stream);

/* Pipe I/O (POSIX) */
FILE   *popen(const char *command, const char *type);
int     pclose(FILE *stream);

#endif /* _LIBSYSTEM_STDIO_H */
