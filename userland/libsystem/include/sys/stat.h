/*
 * Kiseki OS - File Status
 */

#ifndef _LIBSYSTEM_SYS_STAT_H
#define _LIBSYSTEM_SYS_STAT_H

#include <types.h>

/*
 * struct stat — Darwin arm64 ABI (64-bit ino_t variant).
 * Must match real macOS struct stat exactly (144 bytes).
 *
 * Field order verified against macOS 14 ARM64 SDK:
 *   dev(4), mode(2), nlink(2), ino(8), uid(4), gid(4), rdev(4), pad(4),
 *   atimespec(16), mtimespec(16), ctimespec(16), birthtimespec(16),
 *   size(8), blocks(8), blksize(4), flags(4), gen(4), lspare(4), qspare(16)
 *
 * Note: struct timespec is defined in types.h
 */

struct stat {
    dev_t               st_dev;             /*   0: Device ID (4) */
    mode_t              st_mode;            /*   4: Mode bits (2) */
    nlink_t             st_nlink;           /*   6: Hard link count (2) */
    ino_t               st_ino;             /*   8: Inode number (8) */
    uid_t               st_uid;             /*  16: Owner user ID (4) */
    gid_t               st_gid;             /*  20: Owner group ID (4) */
    dev_t               st_rdev;            /*  24: Device ID (special) (4) */
    uint32_t            __pad0;             /*  28: alignment padding (4) */
    struct timespec     st_atimespec;       /*  32: Last access time (16) */
    struct timespec     st_mtimespec;       /*  48: Last modification time (16) */
    struct timespec     st_ctimespec;       /*  64: Last status change time (16) */
    struct timespec     st_birthtimespec;   /*  80: Creation time (16) */
    off_t               st_size;            /*  96: File size in bytes (8) */
    blkcnt_t            st_blocks;          /* 104: 512-byte blocks (8) */
    blksize_t           st_blksize;         /* 112: Preferred I/O block size (4) */
    uint32_t            st_flags;           /* 116: User-defined flags (4) */
    uint32_t            st_gen;             /* 120: File generation number (4) */
    int32_t             st_lspare;          /* 124: Reserved (4) */
    int64_t             st_qspare[2];       /* 128: Reserved (16) */
};                                          /* 144: Total */

/* Darwin compat: access times via .tv_sec */
#define st_atime        st_atimespec.tv_sec
#define st_mtime        st_mtimespec.tv_sec
#define st_ctime        st_ctimespec.tv_sec
#define st_birthtime    st_birthtimespec.tv_sec

/* File type bits (in st_mode) */
#define S_IFMT      0170000     /* Type of file mask */
#define S_IFIFO     0010000     /* Named pipe (FIFO) */
#define S_IFCHR     0020000     /* Character device */
#define S_IFDIR     0040000     /* Directory */
#define S_IFBLK     0060000     /* Block device */
#define S_IFREG     0100000     /* Regular file */
#define S_IFLNK     0120000     /* Symbolic link */
#define S_IFSOCK    0140000     /* Socket */

/* File type test macros */
#define S_ISREG(m)  (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)  (((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m)  (((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m)  (((m) & S_IFMT) == S_IFBLK)
#define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#define S_ISLNK(m)  (((m) & S_IFMT) == S_IFLNK)
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)

/* Permission bits */
#define S_ISUID     0004000     /* Set-user-ID on exec */
#define S_ISGID     0002000     /* Set-group-ID on exec */
#define S_ISVTX     0001000     /* Sticky bit */

#define S_IRWXU     0000700     /* Owner: rwx */
#define S_IRUSR     0000400     /* Owner: read */
#define S_IWUSR     0000200     /* Owner: write */
#define S_IXUSR     0000100     /* Owner: execute */

#define S_IRWXG     0000070     /* Group: rwx */
#define S_IRGRP     0000040     /* Group: read */
#define S_IWGRP     0000020     /* Group: write */
#define S_IXGRP     0000010     /* Group: execute */

#define S_IRWXO     0000007     /* Other: rwx */
#define S_IROTH     0000004     /* Other: read */
#define S_IWOTH     0000002     /* Other: write */
#define S_IXOTH     0000001     /* Other: execute */

/* Functions */
int     stat(const char *pathname, struct stat *statbuf);
int     fstat(int fd, struct stat *statbuf);
int     lstat(const char *pathname, struct stat *statbuf);
int     mkdir(const char *pathname, mode_t mode);
int     chmod(const char *pathname, mode_t mode);
int     fchmod(int fd, mode_t mode);
mode_t  umask(mode_t mask);

#endif /* _LIBSYSTEM_SYS_STAT_H */
