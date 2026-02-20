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

/* FILE flags */
#define _FILE_READ      0x01
#define _FILE_WRITE     0x02
#define _FILE_APPEND    0x04
#define _FILE_EOF       0x08
#define _FILE_ERROR     0x10
#define _FILE_UNBUF     0x20
#define _FILE_LINEBUF   0x40
#define _FILE_MYBUF     0x80    /* We allocated the buffer */

#define FOPEN_MAX       64      /* Max open FILE*s */

typedef struct _FILE {
    int         fd;             /* Underlying file descriptor */
    int         flags;          /* Mode and state flags */
    char       *buf;            /* I/O buffer */
    size_t      bufsiz;         /* Buffer size */
    size_t      buf_pos;        /* Current position in buffer */
    size_t      buf_len;        /* Valid bytes in buffer (for read) */
    int         ungetc_buf;     /* ungetc storage, EOF if empty */
} FILE;

extern FILE *stdin;
extern FILE *stdout;
extern FILE *stderr;

/* Formatted output */
int     printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
int     fprintf(FILE *stream, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
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

/* fdopen */
FILE   *fdopen(int fd, const char *mode);

#endif /* _LIBSYSTEM_STDIO_H */
