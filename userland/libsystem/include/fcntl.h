/*
 * Kiseki OS - File Control
 *
 * XNU-compatible open flags and fcntl operations.
 */

#ifndef _LIBSYSTEM_FCNTL_H
#define _LIBSYSTEM_FCNTL_H

#include <types.h>

/* open() flags (XNU-compatible values) */
#define O_RDONLY        0x0000
#define O_WRONLY        0x0001
#define O_RDWR          0x0002
#define O_ACCMODE       0x0003  /* mask for above */

#define O_NONBLOCK      0x0004
#define O_APPEND        0x0008
#define O_SHLOCK        0x0010
#define O_EXLOCK        0x0020
#define O_ASYNC         0x0040
#define O_NOFOLLOW      0x0100
#define O_CREAT         0x0200
#define O_TRUNC         0x0400
#define O_EXCL          0x0800
#define O_NOCTTY        0x20000     /* Don't assign controlling terminal */
#define O_DIRECTORY     0x100000    /* Fail if not a directory */
#define O_SYMLINK       0x200000    /* Allow open of symlink itself */
#define O_CLOEXEC       0x1000000   /* Close on exec */

/* fcntl commands */
#define F_DUPFD         0       /* Duplicate file descriptor */
#define F_GETFD         1       /* Get file descriptor flags */
#define F_SETFD         2       /* Set file descriptor flags */
#define F_GETFL         3       /* Get file status flags */
#define F_SETFL         4       /* Set file status flags */
#define F_GETOWN        5       /* Get owner (pid) */
#define F_SETOWN        6       /* Set owner (pid) */
#define F_GETLK         7       /* Get record locking info */
#define F_SETLK         8       /* Set record locking info */
#define F_SETLKW        9       /* Set record locking, wait */
#define F_DUPFD_CLOEXEC 67      /* Duplicate with close-on-exec */

/* FD flags */
#define FD_CLOEXEC      1

/* File creation mode flags */
#define AT_FDCWD        (-2)

int     open(const char *pathname, int flags, ...);
int     fcntl(int fd, int cmd, ...);
int     creat(const char *pathname, mode_t mode);

#endif /* _LIBSYSTEM_FCNTL_H */
