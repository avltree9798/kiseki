/*
 * Kiseki OS - <sys/mount.h>
 *
 * Filesystem statistics structures and mount operations.
 * Matches the kernel's struct statfs layout (kernel/include/fs/vfs.h).
 */

#ifndef _SYS_MOUNT_H
#define _SYS_MOUNT_H

#include <types.h>

/*
 * struct statfs - Filesystem statistics.
 *
 * Layout must match the kernel definition exactly.
 */
struct statfs {
    uint64_t    f_blocks;       /* Total data blocks in filesystem */
    uint64_t    f_bfree;        /* Free blocks */
    uint64_t    f_bavail;       /* Free blocks available to non-root */
    uint64_t    f_files;        /* Total inodes */
    uint64_t    f_ffree;        /* Free inodes */
    uint32_t    f_bsize;        /* Filesystem block size */
    uint32_t    f_namelen;      /* Maximum filename length */
    char        f_fstype[16];   /* Filesystem type name */
};

/*
 * statfs - Get filesystem statistics for a path.
 *
 * @path: Path to any file on the filesystem
 * @buf:  Buffer to fill with statistics
 *
 * Returns 0 on success, -1 on error with errno set.
 */
int statfs(const char *path, struct statfs *buf);

/*
 * fstatfs - Get filesystem statistics for a file descriptor.
 *
 * @fd:  File descriptor
 * @buf: Buffer to fill with statistics
 *
 * Returns 0 on success, -1 on error with errno set.
 */
int fstatfs(int fd, struct statfs *buf);

#endif /* _SYS_MOUNT_H */
