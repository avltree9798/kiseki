/*
 * Kiseki OS - Directory Reading
 */

#ifndef _LIBSYSTEM_DIRENT_H
#define _LIBSYSTEM_DIRENT_H

#include <types.h>

#define DT_UNKNOWN  0
#define DT_FIFO     1
#define DT_CHR      2
#define DT_DIR      4
#define DT_BLK      6
#define DT_REG      8
#define DT_LNK      10
#define DT_SOCK     12
#define DT_WHT      14

/*
 * Darwin arm64 ABI (64-bit ino_t variant, 1048 bytes per entry).
 *
 * d_ino(8), d_seekoff(8), d_reclen(2), d_namlen(2), d_type(1), d_name(1024)
 * Total: 1045 raw + 3 tail padding = 1048 bytes.
 */
#define MAXPATHLEN      1024
#define DIRENT_NAME_MAX MAXPATHLEN

struct dirent {
    uint64_t    d_ino;              /*   0: Inode number (8) */
    uint64_t    d_seekoff;          /*   8: Seek offset cookie (8) */
    uint16_t    d_reclen;           /*  16: Length of this record (2) */
    uint16_t    d_namlen;           /*  18: Length of d_name (2) */
    uint8_t     d_type;             /*  20: File type (DT_*) (1) */
    char        d_name[MAXPATHLEN]; /*  21: NUL-terminated name (1024) */
};                                  /* 1048: Total */

/*
 * DIR - opaque directory stream
 *
 * Buffer must hold at least one Darwin dirent (1048 bytes).
 * We use 4096 bytes to allow a few entries to batch.
 */
typedef struct {
    int             fd;                     /* Underlying file descriptor */
    size_t          buf_pos;                /* Current position in buffer */
    size_t          buf_len;                /* Valid bytes in buffer */
    char            buf[8192];              /* Kernel dirent buffer */
} DIR;

DIR            *opendir(const char *name);
struct dirent  *readdir(DIR *dirp);
int             closedir(DIR *dirp);
void            rewinddir(DIR *dirp);

#endif /* _LIBSYSTEM_DIRENT_H */
