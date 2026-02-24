/*
 * Kiseki OS - Virtual File System Layer
 *
 * BSD/XNU-style VFS abstraction. Provides a uniform interface over
 * multiple filesystem implementations (ext4, FAT, devfs, etc.).
 *
 * Architecture:
 *   vnode       - In-memory inode representation with refcounting
 *   vnode_ops   - Per-filesystem operation vectors
 *   mount       - A mounted filesystem instance
 *   fs_ops      - Filesystem-level operations (mount/unmount/sync)
 *   file        - Open file descriptor (vnode + offset + flags)
 *
 * Reference: McKusick et al., "Design and Implementation of the FreeBSD
 *            Operating System" Ch. 8; Apple XNU vfs_subr.c
 */

#ifndef _FS_VFS_H
#define _FS_VFS_H

#include <kiseki/types.h>
#include <kern/sync.h>

/* ============================================================================
 * Forward Declarations
 * ============================================================================ */

struct vnode;
struct mount;
struct dirent;
struct stat;

/* ============================================================================
 * Vnode Types
 * ============================================================================ */

enum vtype {
    VNON  = 0,      /* No type */
    VREG  = 1,      /* Regular file */
    VDIR  = 2,      /* Directory */
    VLNK  = 3,      /* Symbolic link */
    VBLK  = 4,      /* Block device */
    VCHR  = 5,      /* Character device */
    VFIFO = 6,      /* FIFO / named pipe */
    VSOCK = 7,      /* Socket */
};

/* ============================================================================
 * Vnode Operations
 * ============================================================================ */

struct vnode_ops {
    /*
     * lookup - Find a named entry in a directory vnode.
     *
     * @dir:     Directory vnode to search
     * @name:    Component name to look up
     * @namelen: Length of name (not including NUL)
     * @result:  On success, set to the found vnode (with ref incremented)
     *
     * Returns 0 on success, -errno on failure.
     */
    int (*lookup)(struct vnode *dir, const char *name, uint32_t namelen,
                  struct vnode **result);

    /*
     * read - Read data from a file vnode.
     *
     * @vp:     File vnode
     * @buf:    Destination buffer
     * @offset: Byte offset in file
     * @count:  Number of bytes to read
     *
     * Returns bytes read (>= 0), or -errno on error.
     */
    int64_t (*read)(struct vnode *vp, void *buf, uint64_t offset,
                    uint64_t count);

    /*
     * write - Write data to a file vnode.
     *
     * @vp:     File vnode
     * @buf:    Source buffer
     * @offset: Byte offset in file
     * @count:  Number of bytes to write
     *
     * Returns bytes written (>= 0), or -errno on error.
     */
    int64_t (*write)(struct vnode *vp, const void *buf, uint64_t offset,
                     uint64_t count);

    /*
     * readdir - Read directory entries.
     *
     * @dir:    Directory vnode
     * @buf:    Array of struct dirent to fill
     * @offset: Pointer to byte offset cookie; updated to next position
     * @count:  Maximum number of entries to return
     *
     * Returns number of entries read, or -errno on error.
     * The *offset value is updated to reflect the position after the
     * last entry read so that subsequent calls continue correctly.
     */
    int (*readdir)(struct vnode *dir, struct dirent *buf, uint64_t *offset,
                   uint32_t count);

    /*
     * create - Create a new regular file in a directory.
     *
     * @dir:    Parent directory vnode
     * @name:   Name of the new file
     * @namelen: Length of name
     * @mode:   Permission bits
     * @result: On success, set to the new file vnode
     *
     * Returns 0 on success, -errno on failure.
     */
    int (*create)(struct vnode *dir, const char *name, uint32_t namelen,
                  mode_t mode, struct vnode **result);

    /*
     * mkdir - Create a new directory.
     *
     * @dir:    Parent directory vnode
     * @name:   Name of the new directory
     * @namelen: Length of name
     * @mode:   Permission bits
     * @result: On success, set to the new directory vnode
     *
     * Returns 0 on success, -errno on failure.
     */
    int (*mkdir)(struct vnode *dir, const char *name, uint32_t namelen,
                 mode_t mode, struct vnode **result);

    /*
     * unlink - Remove a directory entry.
     *
     * @dir:     Parent directory vnode
     * @name:    Name of the entry to remove
     * @namelen: Length of name
     *
     * Returns 0 on success, -errno on failure.
     */
    int (*unlink)(struct vnode *dir, const char *name, uint32_t namelen);

    /*
     * getattr - Get file attributes (stat).
     *
     * @vp:   Vnode to query
     * @stat: Stat buffer to fill
     *
     * Returns 0 on success, -errno on failure.
     */
    int (*getattr)(struct vnode *vp, struct stat *st);

    /*
     * setattr - Set file attributes.
     *
     * @vp:   Vnode to modify
     * @stat: Stat buffer with new attributes
     *
     * Returns 0 on success, -errno on failure.
     */
    int (*setattr)(struct vnode *vp, struct stat *st);

    /*
     * readlink - Read the target of a symbolic link.
     *
     * @vp:     Symlink vnode
     * @buf:    Destination buffer
     * @buflen: Size of buffer
     *
     * Returns number of bytes placed in buf (not NUL-terminated),
     * or -errno on failure.
     */
    int (*readlink)(struct vnode *vp, char *buf, uint64_t buflen);
};

/* ============================================================================
 * Vnode
 * ============================================================================ */

struct vnode {
    enum vtype          v_type;         /* VREG, VDIR, VLNK, ... */
    uint32_t            v_refcount;     /* Reference count */
    uint64_t            v_ino;          /* Inode number */
    uint64_t            v_size;         /* File size in bytes */
    mode_t              v_mode;         /* Permission bits + type */
    uid_t               v_uid;          /* Owner user ID */
    gid_t               v_gid;          /* Owner group ID */
    nlink_t             v_nlink;        /* Hard link count */
    uint32_t            v_dev;          /* Device this vnode lives on */
    void               *v_data;         /* Filesystem-private data */
    struct vnode_ops   *v_ops;          /* Operation vector */
    struct mount       *v_mount;        /* Owning mount */
    spinlock_t          v_lock;         /* Protects v_refcount */
};

/* ============================================================================
 * Filesystem Operations
 * ============================================================================ */

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

struct fs_ops {
    /*
     * mount - Mount a filesystem on a device.
     *
     * @mp: Mount structure to initialize
     *
     * Returns 0 on success, -errno on failure.
     */
    int (*mount)(struct mount *mp);

    /*
     * unmount - Unmount a filesystem.
     *
     * @mp: Mount to unmount
     *
     * Returns 0 on success, -errno on failure.
     */
    int (*unmount)(struct mount *mp);

    /*
     * sync - Flush all dirty data to disk.
     *
     * @mp: Mount to sync
     *
     * Returns 0 on success, -errno on failure.
     */
    int (*sync)(struct mount *mp);

    /*
     * statfs - Get filesystem statistics.
     *
     * @mp:  Mount to query
     * @buf: Statfs buffer to fill
     *
     * Returns 0 on success, -errno on failure.
     */
    int (*statfs)(struct mount *mp, struct statfs *buf);
};

/* ============================================================================
 * Mount
 * ============================================================================ */

/* Maximum number of simultaneous mounts */
#define VFS_MAX_MOUNTS  16

struct mount {
    char                mnt_path[256];  /* Mount point path */
    struct vnode       *mnt_root;       /* Root vnode of this mount */
    struct fs_ops      *mnt_ops;        /* Filesystem-level operations */
    uint32_t            mnt_dev;        /* Block device number */
    uint32_t            mnt_flags;      /* Mount flags */
    void               *mnt_data;       /* Filesystem-private mount data */
    bool                mnt_active;     /* Slot is in use */
};

/* Mount flags */
#define MNT_RDONLY      0x00000001      /* Read-only mount */
#define MNT_NOSUID      0x00000008      /* Disallow setuid/setgid */
#define MNT_NOEXEC      0x00000004      /* Disallow execution */
#define MNT_NODEV       0x00000010      /* Disallow device special files */

/* ============================================================================
 * Directory Entry — Darwin arm64 ABI (64-bit ino_t variant, 1048 bytes)
 *
 * Verified against macOS 14 ARM64 SDK:
 *   d_ino(8), d_seekoff(8), d_reclen(2), d_namlen(2), d_type(1), d_name(1024)
 *   Total: 1045 raw + 3 tail padding = 1048 bytes
 * ============================================================================ */

#define MAXPATHLEN      1024    /* Darwin MAXPATHLEN */
#define VFS_NAME_MAX    255     /* Kept for internal convenience */

struct dirent {
    uint64_t    d_ino;              /*   0: Inode number (8) */
    uint64_t    d_seekoff;          /*   8: Seek offset cookie (8) */
    uint16_t    d_reclen;           /*  16: Length of this record (2) */
    uint16_t    d_namlen;           /*  18: Length of d_name (2) */
    uint8_t     d_type;             /*  20: DT_REG, DT_DIR, etc. (1) */
    char        d_name[MAXPATHLEN]; /*  21: NUL-terminated name (1024) */
};                                  /* 1048: Total (1045 + 3 tail pad) */

/* d_type values (POSIX-compatible) */
#define DT_UNKNOWN  0
#define DT_FIFO     1
#define DT_CHR      2
#define DT_DIR      4
#define DT_BLK      6
#define DT_REG      8
#define DT_LNK      10
#define DT_SOCK     12

/* ============================================================================
 * Stat Structure
 * ============================================================================ */

/*
 * struct stat — Darwin arm64 ABI (64-bit ino_t variant).
 * Must match real macOS struct stat exactly (144 bytes).
 *
 * Field order verified against macOS 14 ARM64 SDK:
 *   dev(4), mode(2), nlink(2), ino(8), uid(4), gid(4), rdev(4), pad(4),
 *   atimespec(16), mtimespec(16), ctimespec(16), birthtimespec(16),
 *   size(8), blocks(8), blksize(4), flags(4), gen(4), lspare(4), qspare(16)
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

/* ============================================================================
 * Open File Flags (XNU-compatible values)
 * ============================================================================ */

#define O_RDONLY    0x0000       /* Open for reading only */
#define O_WRONLY    0x0001       /* Open for writing only */
#define O_RDWR      0x0002       /* Open for reading and writing */
#define O_ACCMODE   0x0003       /* Mask for access mode */
#define O_NONBLOCK  0x0004       /* Non-blocking I/O */
#define O_APPEND    0x0008       /* Append on each write */
#define O_CREAT     0x0200       /* Create file if it doesn't exist */
#define O_TRUNC     0x0400       /* Truncate to zero length */
#define O_EXCL      0x0800       /* Error if O_CREAT and file exists */
#define O_NOCTTY    0x20000      /* Don't assign controlling terminal */
#define O_DIRECTORY 0x100000     /* Must be a directory */
#define O_SYMLINK   0x200000     /* Allow open of symlink itself */
#define O_CLOEXEC   0x1000000    /* Close on exec */

/* ============================================================================
 * File Descriptor
 * ============================================================================ */

#define VFS_MAX_FD  256         /* Max open files per process (placeholder) */

/* File descriptor flags (fd_flags) */
#define FD_CLOEXEC  1
#define FD_SOCKET   2           /* This fd is a socket (f_sockidx is valid) */

struct file {
    struct vnode   *f_vnode;    /* Underlying vnode */
    uint64_t        f_offset;   /* Current read/write position */
    uint32_t        f_flags;    /* O_RDONLY, O_WRONLY, O_RDWR, etc. */
    uint32_t        f_refcount; /* Reference count (dup/fork sharing) */
    int             f_sockidx;  /* Socket table index (when FD_SOCKET set) */
    void           *f_pipe;     /* Pipe data pointer (non-NULL for pipe fds) */
    uint32_t        f_pipe_dir; /* 0 = read end, 1 = write end */
    void           *f_pty;      /* PTY pair pointer (non-NULL for PTY fds) */
    uint32_t        f_pty_side; /* 0 = master, 1 = slave */
    spinlock_t      f_lock;     /* Protects f_offset, f_refcount */
};

/* ============================================================================
 * Filesystem Type Registration
 * ============================================================================ */

#define VFS_MAX_FSTYPES 8

struct fs_type {
    const char     *name;       /* e.g. "ext4", "fat32", "devfs" */
    struct fs_ops  *ops;        /* Filesystem operations */
    bool            active;     /* Slot is in use */
};

/* ============================================================================
 * Errno Values (kernel-internal, positive)
 * ============================================================================ */

#define ENOENT      2       /* No such file or directory */
#define EINTR       4       /* Interrupted system call */
#define EIO         5       /* I/O error */
#define ENOMEM      12      /* Out of memory */
#define EACCES      13      /* Permission denied */
#define EEXIST      17      /* File exists */
#define ENOTDIR     20      /* Not a directory */
#define EISDIR      21      /* Is a directory */
#define EINVAL      22      /* Invalid argument */
#define ENFILE      23      /* Too many open files in system */
#define EMFILE      24      /* Too many open files */
#define ENOSPC      28      /* No space left on device */
#define ENAMETOOLONG 63     /* File name too long */
#define ENOTEMPTY   66      /* Directory not empty */
#define ENOSYS      78      /* Function not implemented */
#define EBADF       9       /* Bad file descriptor */
#define EPERM       1       /* Operation not permitted */
#define EAGAIN      35      /* Resource temporarily unavailable */
#define ENOTCONN    57      /* Socket is not connected */
#define ECONNREFUSED 61     /* Connection refused */
#define EADDRINUSE  48      /* Address already in use */
#define ENETUNREACH 51      /* Network is unreachable */
#define ECONNRESET  54      /* Connection reset by peer */
#define ETIMEDOUT   60      /* Operation timed out */
#define EAFNOSUPPORT 47     /* Address family not supported */
#define EPROTONOSUPPORT 43  /* Protocol not supported */
#define ECHILD      10      /* No child processes */
#define ENOTTY      25      /* Inappropriate ioctl for device */
#define ESRCH       3       /* No such process */
#define EFAULT      14      /* Bad address */
#define ESPIPE      29      /* Illegal seek */
#define ERANGE      34      /* Result too large */
#define ENOEXEC     8       /* Exec format error */
#define EFBIG       27      /* File too large */
#define EPIPE       32      /* Broken pipe */
#define EOPNOTSUPP  45      /* Operation not supported */
#define EISCONN     56      /* Socket is already connected */

/* ============================================================================
 * VFS Public API
 * ============================================================================ */

/*
 * vfs_init - Initialize the VFS layer.
 *
 * Must be called once during kernel startup.
 */
void vfs_init(void);

/*
 * vfs_register_fs - Register a filesystem type.
 *
 * @name: Filesystem name (e.g. "ext4")
 * @ops:  Filesystem-level operations
 *
 * Returns 0 on success, -ENOMEM if table full.
 */
int vfs_register_fs(const char *name, struct fs_ops *ops);

/*
 * vfs_mount - Mount a filesystem at a path.
 *
 * @fsname: Registered filesystem name
 * @path:   Mount point path
 * @dev:    Block device number
 * @flags:  Mount flags (MNT_RDONLY, etc.)
 *
 * Returns 0 on success, -errno on failure.
 */
int vfs_mount(const char *fsname, const char *path, uint32_t dev,
              uint32_t flags);

/*
 * vfs_lookup - Resolve a path to a vnode.
 *
 * @path:   Absolute path (must start with '/')
 * @result: On success, set to the found vnode (with ref incremented)
 *
 * Returns 0 on success, -errno on failure.
 */
int vfs_lookup(const char *path, struct vnode **result);

/*
 * vfs_open - Open a file by path.
 *
 * @path:  Absolute path
 * @flags: O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, etc.
 * @mode:  Permission bits (used with O_CREAT)
 *
 * Returns a file descriptor (>= 0), or -errno on failure.
 */
int vfs_open(const char *path, uint32_t flags, mode_t mode);

/*
 * vfs_read - Read from an open file descriptor.
 *
 * @fd:    File descriptor
 * @buf:   Destination buffer
 * @count: Maximum bytes to read
 *
 * Returns bytes read (>= 0), or -errno on error.
 */
int64_t vfs_read(int fd, void *buf, uint64_t count);

/*
 * vfs_write - Write to an open file descriptor.
 *
 * @fd:    File descriptor
 * @buf:   Source buffer
 * @count: Bytes to write
 *
 * Returns bytes written (>= 0), or -errno on error.
 */
int64_t vfs_write(int fd, const void *buf, uint64_t count);

/*
 * vfs_close - Close an open file descriptor.
 *
 * @fd: File descriptor to close
 *
 * Returns 0 on success, -errno on failure.
 */
int vfs_close(int fd);

/*
 * vfs_readdir - Read directory entries.
 *
 * @fd:    File descriptor for an open directory
 * @buf:   Array of struct dirent to fill
 * @count: Maximum entries to return
 *
 * Returns number of entries read, or -errno on error.
 */
int vfs_readdir(int fd, struct dirent *buf, uint32_t count);

/*
 * vfs_mkdir - Create a directory.
 *
 * @path: Absolute path of directory to create
 * @mode: Permission bits
 *
 * Returns 0 on success, -errno on failure.
 */
int vfs_mkdir(const char *path, mode_t mode);

/*
 * vfs_create - Create a regular file.
 *
 * @path: Absolute path of file to create
 * @mode: Permission bits
 *
 * Returns 0 on success, -errno on failure.
 */
int vfs_create(const char *path, mode_t mode);

/*
 * vfs_unlink - Remove a file or empty directory.
 *
 * @path: Absolute path of entry to remove
 *
 * Returns 0 on success, -errno on failure.
 */
int vfs_unlink(const char *path);

/*
 * vfs_stat - Get file attributes by path.
 *
 * @path: Absolute path
 * @st:   Stat buffer to fill
 *
 * Returns 0 on success, -errno on failure.
 */
int vfs_stat(const char *path, struct stat *st);

/*
 * vfs_fstat - Get file attributes by file descriptor.
 *
 * @fd: File descriptor
 * @st: Stat buffer to fill
 *
 * Returns 0 on success, -errno on failure.
 */
int vfs_fstat(int fd, struct stat *st);

/*
 * vfs_lseek - Reposition file offset.
 *
 * @fd:     File descriptor
 * @offset: New offset
 * @whence: SEEK_SET, SEEK_CUR, or SEEK_END
 *
 * Returns new offset, or -errno on failure.
 */
int64_t vfs_lseek(int fd, int64_t offset, int whence);

#define SEEK_SET    0   /* Set offset to offset */
#define SEEK_CUR    1   /* Set offset to current + offset */
#define SEEK_END    2   /* Set offset to file size + offset */

/* ============================================================================
 * Vnode Helper Functions
 * ============================================================================ */

/*
 * vfs_fd_has_vnode - Check if a file descriptor has a backing vnode.
 *
 * @fd: File descriptor number
 *
 * Returns true if the fd is open and has a non-NULL vnode,
 * false if the fd is unused or has no vnode (e.g. console sentinel).
 * Used by the console fast path to distinguish real files from
 * console stdin/stdout/stderr.
 */
bool vfs_fd_has_vnode(int fd);

/*
 * vfs_fd_get_vnode - Get the vnode backing a file descriptor.
 *
 * @fd: File descriptor number
 *
 * Returns the vnode pointer, or NULL if the fd is invalid or has
 * no backing vnode (e.g. console sentinel or socket fd).
 */
struct vnode *vfs_fd_get_vnode(int fd);

/*
 * vnode_alloc - Allocate and initialize a new vnode.
 *
 * Returns a vnode with refcount = 1, or NULL on failure.
 */
struct vnode *vnode_alloc(void);

/*
 * vnode_ref - Increment a vnode's reference count.
 */
void vnode_ref(struct vnode *vp);

/*
 * vnode_release - Decrement a vnode's reference count.
 *
 * If refcount drops to zero, the vnode is freed.
 */
void vnode_release(struct vnode *vp);

/* ============================================================================
 * File Descriptor Flags (per-FD, independent of file status flags)
 * ============================================================================ */

/*
 * vfs_get_fd_flags - Get per-FD flags (e.g., FD_CLOEXEC).
 *
 * @fd: File descriptor
 *
 * Returns flags value, or -EBADF if fd is invalid.
 */
int vfs_get_fd_flags(int fd);

/*
 * vfs_set_fd_flags - Set per-FD flags (e.g., FD_CLOEXEC).
 *
 * @fd:    File descriptor
 * @flags: New flags value
 *
 * Returns 0 on success, -EBADF if fd is invalid.
 */
int vfs_set_fd_flags(int fd, uint8_t flags);

/*
 * vfs_get_file - Get the file structure for a file descriptor.
 *
 * @fd: File descriptor
 *
 * Returns pointer to struct file, or NULL if fd is invalid.
 */
struct file *vfs_get_file(int fd);

/*
 * vfs_get_file_flags - Get file status flags (O_APPEND, O_NONBLOCK, etc.).
 *
 * @fd: File descriptor
 *
 * Returns flags value (f_flags), or -EBADF if fd is invalid.
 */
int vfs_get_file_flags(int fd);

/*
 * vfs_set_file_flags - Set file status flags (O_APPEND, O_NONBLOCK).
 *
 * Only modifiable flags: O_APPEND, O_NONBLOCK.
 * Access mode (O_RDONLY/O_WRONLY/O_RDWR) cannot be changed.
 *
 * @fd:    File descriptor
 * @flags: New flags value (only modifiable bits are applied)
 *
 * Returns 0 on success, -EBADF if fd is invalid.
 */
int vfs_set_file_flags(int fd, uint32_t flags);

/*
 * vfs_dup_fd - Duplicate a file descriptor.
 *
 * @oldfd:  Source file descriptor
 * @minfd:  Minimum fd number for the new descriptor
 *
 * Returns the new fd number, or -errno on failure.
 */
int vfs_dup_fd(int oldfd, int minfd);

/*
 * vfs_alloc_sockfd - Allocate a file descriptor for a socket.
 *
 * @sockidx: The kernel socket table index to associate with this fd.
 *
 * Returns the new fd number, or -errno on failure.
 * The fd is marked with FD_SOCKET in fd_flags and f_sockidx is set.
 */
int vfs_alloc_sockfd(int sockidx);

/*
 * vfs_get_sockidx - Get the socket table index for a socket fd.
 *
 * Returns the socket index (>= 0) on success, or -1 if not a socket fd.
 */
int vfs_get_sockidx(int fd);

/*
 * vfs_free_fd - Free a file descriptor (for socket close).
 */
void vfs_free_fd(int fd);

/*
 * vfs_alloc_pipefd - Allocate a file descriptor for a pipe endpoint.
 *
 * @pipe_data: Pointer to the pipe_data structure
 * @dir: 0 = read end, 1 = write end
 *
 * Returns the new fd (>= 0) on success, or -errno on failure.
 */
int vfs_alloc_pipefd(void *pipe_data, int dir);

/*
 * vfs_get_pipe - Get the pipe data for a pipe fd.
 *
 * @fd: File descriptor
 * @dir: If non-NULL, filled with 0 (read) or 1 (write)
 *
 * Returns the pipe_data pointer, or NULL if not a pipe fd.
 */
void *vfs_get_pipe(int fd, int *dir);

/*
 * vfs_get_pty - Get the PTY pair for a PTY fd.
 *
 * @fd:   File descriptor
 * @side: If non-NULL, filled with 0 (master) or 1 (slave)
 *
 * Returns the pty struct pointer, or NULL if not a PTY fd.
 */
void *vfs_get_pty(int fd, int *side);

/*
 * vfs_alloc_pty_fd - Allocate a file descriptor for a PTY side.
 *
 * @pty_ptr: Pointer to the struct pty
 * @side:    0 = master, 1 = slave
 *
 * Returns the fd (>= 0), or -errno on error.
 */
int vfs_alloc_pty_fd(void *pty_ptr, int side);

/*
 * vfs_statfs - Get filesystem statistics for a path.
 *
 * @path: Absolute path to any file on the filesystem
 * @buf:  Statfs buffer to fill
 *
 * Finds the mount point covering the given path and calls the
 * filesystem's statfs operation.
 *
 * Returns 0 on success, -errno on failure.
 */
int vfs_statfs(const char *path, struct statfs *buf);

#endif /* _FS_VFS_H */
