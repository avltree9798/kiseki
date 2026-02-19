/*
 * Kiseki OS - Virtual File System Implementation
 *
 * Path resolution, mount table, vnode refcounting, and file descriptor
 * operations that delegate to filesystem-specific vnode_ops.
 */

#include <kiseki/types.h>
#include <kern/kprintf.h>
#include <kern/sync.h>
#include <fs/vfs.h>

/* ============================================================================
 * Internal State
 * ============================================================================ */

/* Mount table */
static struct mount     mount_table[VFS_MAX_MOUNTS];
static spinlock_t       mount_lock = SPINLOCK_INIT;
static uint32_t         mount_count;

/* Filesystem type registry */
static struct fs_type   fs_types[VFS_MAX_FSTYPES];
static spinlock_t       fs_type_lock = SPINLOCK_INIT;

/* Global file descriptor table (kernel-level, not per-process yet) */
static struct file      fd_table[VFS_MAX_FD];
static uint8_t          fd_flags[VFS_MAX_FD];   /* Per-FD flags (FD_CLOEXEC etc.) */
static spinlock_t       fd_lock = SPINLOCK_INIT;

/* Vnode pool */
#define VFS_MAX_VNODES  1024
static struct vnode     vnode_pool[VFS_MAX_VNODES];
static spinlock_t       vnode_pool_lock = SPINLOCK_INIT;

/* Root vnode (set by first mount at "/") */
static struct vnode    *root_vnode;

/* ============================================================================
 * String Helpers (freestanding -- no libc)
 * ============================================================================ */

static uint32_t
kstrlen(const char *s)
{
    uint32_t len = 0;
    while (s[len])
        len++;
    return len;
}

static int
kstrncmp(const char *a, const char *b, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) {
        if (a[i] != b[i])
            return (unsigned char)a[i] - (unsigned char)b[i];
        if (a[i] == '\0')
            return 0;
    }
    return 0;
}

static void
kstrcpy(char *dst, const char *src, uint32_t max)
{
    uint32_t i;
    for (i = 0; i < max - 1 && src[i]; i++)
        dst[i] = src[i];
    dst[i] = '\0';
}

static int
kstrcmp(const char *a, const char *b)
{
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

/* ============================================================================
 * Vnode Pool Management
 * ============================================================================ */

struct vnode *
vnode_alloc(void)
{
    spin_lock(&vnode_pool_lock);
    for (uint32_t i = 0; i < VFS_MAX_VNODES; i++) {
        if (vnode_pool[i].v_refcount == 0 && vnode_pool[i].v_type == VNON) {
            struct vnode *vp = &vnode_pool[i];
            vp->v_refcount = 1;
            vp->v_type = VNON;
            vp->v_ino = 0;
            vp->v_size = 0;
            vp->v_mode = 0;
            vp->v_uid = 0;
            vp->v_gid = 0;
            vp->v_nlink = 0;
            vp->v_dev = 0;
            vp->v_data = NULL;
            vp->v_ops = NULL;
            vp->v_mount = NULL;
            spin_init(&vp->v_lock);
            spin_unlock(&vnode_pool_lock);
            return vp;
        }
    }
    spin_unlock(&vnode_pool_lock);
    kprintf("vfs: vnode pool exhausted\n");
    return NULL;
}

void
vnode_ref(struct vnode *vp)
{
    if (vp == NULL)
        return;
    spin_lock(&vp->v_lock);
    vp->v_refcount++;
    spin_unlock(&vp->v_lock);
}

void
vnode_release(struct vnode *vp)
{
    if (vp == NULL)
        return;
    spin_lock(&vp->v_lock);
    if (vp->v_refcount > 0)
        vp->v_refcount--;
    if (vp->v_refcount == 0) {
        vp->v_type = VNON;
        vp->v_data = NULL;
        vp->v_ops = NULL;
        vp->v_mount = NULL;
        spin_unlock(&vp->v_lock);
        return;
    }
    spin_unlock(&vp->v_lock);
}

/* ============================================================================
 * File Descriptor Management
 * ============================================================================ */

static int
fd_alloc(void)
{
    spin_lock(&fd_lock);
    for (int i = 0; i < VFS_MAX_FD; i++) {
        if (fd_table[i].f_refcount == 0) {
            fd_table[i].f_refcount = 1;
            fd_table[i].f_offset = 0;
            fd_table[i].f_flags = 0;
            fd_table[i].f_vnode = NULL;
            fd_table[i].f_pipe = NULL;
            fd_table[i].f_pipe_dir = 0;
            fd_table[i].f_pty = NULL;
            fd_table[i].f_pty_side = 0;
            fd_table[i].f_sockidx = -1;
            fd_flags[i] = 0;
            spin_init(&fd_table[i].f_lock);
            spin_unlock(&fd_lock);
            return i;
        }
    }
    spin_unlock(&fd_lock);
    return -EMFILE;
}

static struct file *
fd_get(int fd)
{
    if (fd < 0 || fd >= VFS_MAX_FD)
        return NULL;
    if (fd_table[fd].f_refcount == 0)
        return NULL;
    return &fd_table[fd];
}

static void
fd_free(int fd)
{
    if (fd < 0 || fd >= VFS_MAX_FD)
        return;
    spin_lock(&fd_lock);
    fd_table[fd].f_refcount = 0;
    fd_table[fd].f_vnode = NULL;
    fd_table[fd].f_pty = NULL;
    fd_table[fd].f_pty_side = 0;
    spin_unlock(&fd_lock);
}

/*
 * vfs_fd_has_vnode - Check if a file descriptor has a backing vnode.
 *
 * Returns true if the fd is open and has a non-NULL f_vnode.
 * Console sentinel fds (0/1/2) have f_vnode=NULL but f_refcount=1.
 */
bool
vfs_fd_has_vnode(int fd)
{
    struct file *fp = fd_get(fd);
    if (fp == NULL)
        return false;
    return (fp->f_vnode != NULL);
}

/*
 * vfs_fd_get_vnode - Get the vnode backing a file descriptor.
 */
struct vnode *
vfs_fd_get_vnode(int fd)
{
    struct file *fp = fd_get(fd);
    if (fp == NULL)
        return NULL;
    return fp->f_vnode;
}

/*
 * Per-FD flags (FD_CLOEXEC etc.)
 */
int
vfs_get_fd_flags(int fd)
{
    if (fd < 0 || fd >= VFS_MAX_FD)
        return -EBADF;
    struct file *fp = fd_get(fd);
    if (fp == NULL)
        return -EBADF;
    return (int)fd_flags[fd];
}

int
vfs_set_fd_flags(int fd, uint8_t flags)
{
    if (fd < 0 || fd >= VFS_MAX_FD)
        return -EBADF;
    struct file *fp = fd_get(fd);
    if (fp == NULL)
        return -EBADF;
    fd_flags[fd] = flags;
    return 0;
}

/*
 * File status flags (O_APPEND, O_NONBLOCK, etc.)
 */
int
vfs_get_file_flags(int fd)
{
    struct file *fp = fd_get(fd);
    if (fp == NULL)
        return -EBADF;
    return (int)fp->f_flags;
}

int
vfs_set_file_flags(int fd, uint32_t flags)
{
    struct file *fp = fd_get(fd);
    if (fp == NULL)
        return -EBADF;
    /* Only allow modifying O_APPEND and O_NONBLOCK; preserve access mode */
    uint32_t changeable = O_APPEND | O_NONBLOCK;
    fp->f_flags = (fp->f_flags & ~changeable) | (flags & changeable);
    return 0;
}

/*
 * vfs_dup_fd - Duplicate a file descriptor to the lowest available fd >= minfd.
 */
int
vfs_dup_fd(int oldfd, int minfd)
{
    struct file *fp = fd_get(oldfd);
    if (fp == NULL)
        return -EBADF;

    spin_lock(&fd_lock);
    for (int i = minfd; i < VFS_MAX_FD; i++) {
        if (fd_table[i].f_refcount == 0) {
            /* Share the same file structure by copying fields */
            fd_table[i] = fd_table[oldfd];
            fd_table[i].f_refcount = 1;
            fd_flags[i] = 0;  /* New FD does not inherit FD_CLOEXEC */
            spin_init(&fd_table[i].f_lock);

            /* If backing a vnode, increment its refcount */
            if (fd_table[i].f_vnode)
                vnode_ref(fd_table[i].f_vnode);

            spin_unlock(&fd_lock);
            return i;
        }
    }
    spin_unlock(&fd_lock);
    return -EMFILE;
}

/* ============================================================================
 * Socket FD Helpers
 * ============================================================================ */

int
vfs_alloc_sockfd(int sockidx)
{
    int fd = fd_alloc();
    if (fd < 0)
        return fd;

    fd_table[fd].f_vnode = NULL;
    fd_table[fd].f_sockidx = sockidx;
    fd_flags[fd] = FD_SOCKET;

    return fd;
}

int
vfs_get_sockidx(int fd)
{
    if (fd < 0 || fd >= VFS_MAX_FD)
        return -1;
    if (fd_table[fd].f_refcount == 0)
        return -1;
    if (!(fd_flags[fd] & FD_SOCKET))
        return -1;
    return fd_table[fd].f_sockidx;
}

void
vfs_free_fd(int fd)
{
    fd_free(fd);
}

/* ============================================================================
 * Pipe FD Helpers
 * ============================================================================ */

#define FD_PIPE     0x04

int
vfs_alloc_pipefd(void *pipe_data, int dir)
{
    int fd = fd_alloc();
    if (fd < 0)
        return fd;

    fd_table[fd].f_vnode = NULL;
    fd_table[fd].f_pipe = pipe_data;
    fd_table[fd].f_pipe_dir = (uint32_t)dir;
    fd_flags[fd] |= FD_PIPE;

    return fd;
}

void *
vfs_get_pipe(int fd, int *dir)
{
    if (fd < 0 || fd >= VFS_MAX_FD)
        return NULL;
    if (fd_table[fd].f_refcount == 0)
        return NULL;
    if (fd_table[fd].f_pipe == NULL)
        return NULL;
    if (dir)
        *dir = (int)fd_table[fd].f_pipe_dir;
    return fd_table[fd].f_pipe;
}

void *
vfs_get_pty(int fd, int *side)
{
    if (fd < 0 || fd >= VFS_MAX_FD)
        return NULL;
    if (fd_table[fd].f_refcount == 0)
        return NULL;
    if (fd_table[fd].f_pty == NULL)
        return NULL;
    if (side)
        *side = (int)fd_table[fd].f_pty_side;
    return fd_table[fd].f_pty;
}

int
vfs_alloc_pty_fd(void *pty_ptr, int side)
{
    int fd = fd_alloc();
    if (fd < 0)
        return fd;
    fd_table[fd].f_pty = pty_ptr;
    fd_table[fd].f_pty_side = (uint32_t)side;
    fd_table[fd].f_flags = O_RDWR;
    return fd;
}

/* ============================================================================
 * Mount Point Lookup
 *
 * Find the mount whose mnt_path is the longest prefix of the given path.
 * Returns the mount and sets *remainder to the path after the mount point.
 * ============================================================================ */

static struct mount *
mount_find(const char *path, const char **remainder)
{
    struct mount *best = NULL;
    uint32_t best_len = 0;

    spin_lock(&mount_lock);
    for (uint32_t i = 0; i < VFS_MAX_MOUNTS; i++) {
        if (!mount_table[i].mnt_active)
            continue;

        uint32_t mlen = kstrlen(mount_table[i].mnt_path);

        /* Check if the mount path is a prefix of the lookup path */
        if (kstrncmp(mount_table[i].mnt_path, path, mlen) != 0)
            continue;

        /*
         * mnt_path "/" matches everything.
         * For other mount paths, the next char in path must be '/' or '\0'
         * to be a valid prefix (e.g. "/mnt" matches "/mnt/foo" but not
         * "/mntx").
         */
        if (mlen > 1 && path[mlen] != '/' && path[mlen] != '\0')
            continue;

        if (mlen > best_len) {
            best = &mount_table[i];
            best_len = mlen;
        }
    }
    spin_unlock(&mount_lock);

    if (best && remainder) {
        const char *r = path + best_len;
        /* Skip leading '/' in remainder */
        while (*r == '/')
            r++;
        *remainder = r;
    }

    return best;
}

/* ============================================================================
 * Path Resolution
 *
 * Walk '/' separated components from root, calling vnode_ops->lookup()
 * at each step.
 * ============================================================================ */

/*
 * resolve_path - Internal path resolution.
 *
 * @path:      Absolute path to resolve
 * @result:    On success, set to the resolved vnode (ref incremented)
 * @parent:    If non-NULL, set to the parent directory vnode
 * @last_comp: If non-NULL, set to point at the last component name
 * @last_len:  If non-NULL, set to the length of the last component
 *
 * Returns 0 on success, -errno on failure.
 */
static int
resolve_path(const char *path, struct vnode **result,
             struct vnode **parent, const char **last_comp,
             uint32_t *last_len)
{
    if (path == NULL || path[0] != '/')
        return -EINVAL;

    /* Find which mount covers this path */
    const char *remainder;
    struct mount *mp = mount_find(path, &remainder);
    if (mp == NULL || mp->mnt_root == NULL)
        return -ENOENT;

    struct vnode *current = mp->mnt_root;
    vnode_ref(current);

    /* If path is just "/" or the mount point itself with no remainder */
    if (*remainder == '\0') {
        if (parent)
            *parent = NULL;
        if (last_comp)
            *last_comp = NULL;
        if (last_len)
            *last_len = 0;
        *result = current;
        return 0;
    }

    const char *p = remainder;
    struct vnode *prev __unused = NULL;

    while (*p != '\0') {
        /* Skip leading slashes */
        while (*p == '/')
            p++;
        if (*p == '\0')
            break;

        /* Find end of this component */
        const char *comp = p;
        uint32_t clen = 0;
        while (p[clen] != '/' && p[clen] != '\0')
            clen++;

        /* Check if there are more components after this one */
        const char *next = comp + clen;
        while (*next == '/')
            next++;
        bool is_last = (*next == '\0');

        /* If caller wants parent + last component for create/unlink */
        if (is_last && (parent || last_comp)) {
            if (parent) {
                *parent = current;
                /* Don't release current -- caller gets the ref */
            }
            if (last_comp)
                *last_comp = comp;
            if (last_len)
                *last_len = clen;
            if (result)
                *result = NULL; /* Caller will do the final lookup */
            return 0;
        }

        /* Current must be a directory for lookup */
        if (current->v_type != VDIR) {
            vnode_release(current);
            return -ENOTDIR;
        }

        if (current->v_ops == NULL || current->v_ops->lookup == NULL) {
            vnode_release(current);
            return -ENOSYS;
        }

        prev = current;
        struct vnode *child = NULL;
        int err = current->v_ops->lookup(current, comp, clen, &child);
        if (err != 0) {
            vnode_release(current);
            return err;
        }

        vnode_release(current);
        current = child;
        p = comp + clen;
    }

    if (result)
        *result = current;
    if (parent)
        *parent = NULL;
    if (last_comp)
        *last_comp = NULL;
    if (last_len)
        *last_len = 0;
    return 0;
}

/* ============================================================================
 * VFS Initialization
 * ============================================================================ */

void
vfs_init(void)
{
    spin_init(&mount_lock);
    spin_init(&fs_type_lock);
    spin_init(&fd_lock);
    spin_init(&vnode_pool_lock);

    /* Zero out tables */
    for (uint32_t i = 0; i < VFS_MAX_MOUNTS; i++)
        mount_table[i].mnt_active = false;
    for (uint32_t i = 0; i < VFS_MAX_FSTYPES; i++)
        fs_types[i].active = false;
    for (int i = 0; i < VFS_MAX_FD; i++)
        fd_table[i].f_refcount = 0;

    /*
     * Reserve fds 0, 1, 2 for console stdin/stdout/stderr.
     * These are handled by the console fast path in sys_read/sys_write,
     * not by VFS vnodes. Marking them with refcount=1 and f_vnode=NULL
     * prevents fd_alloc() from ever returning them for file opens.
     */
    fd_table[0].f_refcount = 1;  /* stdin  - console */
    fd_table[0].f_vnode = NULL;
    fd_table[1].f_refcount = 1;  /* stdout - console */
    fd_table[1].f_vnode = NULL;
    fd_table[2].f_refcount = 1;  /* stderr - console */
    fd_table[2].f_vnode = NULL;
    for (uint32_t i = 0; i < VFS_MAX_VNODES; i++) {
        vnode_pool[i].v_refcount = 0;
        vnode_pool[i].v_type = VNON;
    }

    mount_count = 0;
    root_vnode = NULL;

    kprintf("vfs: initialized (max %d mounts, %d vnodes, %d fds)\n",
            VFS_MAX_MOUNTS, VFS_MAX_VNODES, VFS_MAX_FD);
}

/* ============================================================================
 * Filesystem Type Registration
 * ============================================================================ */

int
vfs_register_fs(const char *name, struct fs_ops *ops)
{
    if (name == NULL || ops == NULL)
        return -EINVAL;

    spin_lock(&fs_type_lock);
    for (uint32_t i = 0; i < VFS_MAX_FSTYPES; i++) {
        if (!fs_types[i].active) {
            fs_types[i].name = name;
            fs_types[i].ops = ops;
            fs_types[i].active = true;
            spin_unlock(&fs_type_lock);
            kprintf("vfs: registered filesystem '%s'\n", name);
            return 0;
        }
    }
    spin_unlock(&fs_type_lock);
    kprintf("vfs: fs type table full, cannot register '%s'\n", name);
    return -ENOMEM;
}

static struct fs_type *
fs_type_find(const char *name)
{
    for (uint32_t i = 0; i < VFS_MAX_FSTYPES; i++) {
        if (fs_types[i].active && kstrcmp(fs_types[i].name, name) == 0)
            return &fs_types[i];
    }
    return NULL;
}

/* ============================================================================
 * Mount / Unmount
 * ============================================================================ */

int
vfs_mount(const char *fsname, const char *path, uint32_t dev, uint32_t flags)
{
    if (fsname == NULL || path == NULL)
        return -EINVAL;

    struct fs_type *fst = fs_type_find(fsname);
    if (fst == NULL) {
        kprintf("vfs: unknown filesystem type '%s'\n", fsname);
        return -EINVAL;
    }

    spin_lock(&mount_lock);

    /* Find a free mount slot */
    struct mount *mp = NULL;
    for (uint32_t i = 0; i < VFS_MAX_MOUNTS; i++) {
        if (!mount_table[i].mnt_active) {
            mp = &mount_table[i];
            break;
        }
    }
    if (mp == NULL) {
        spin_unlock(&mount_lock);
        kprintf("vfs: mount table full\n");
        return -ENOMEM;
    }

    kstrcpy(mp->mnt_path, path, sizeof(mp->mnt_path));
    mp->mnt_ops = fst->ops;
    mp->mnt_dev = dev;
    mp->mnt_flags = flags;
    mp->mnt_data = NULL;
    mp->mnt_root = NULL;
    mp->mnt_active = true;
    mount_count++;

    spin_unlock(&mount_lock);

    /* Call filesystem-specific mount */
    if (mp->mnt_ops->mount == NULL) {
        mp->mnt_active = false;
        mount_count--;
        return -ENOSYS;
    }

    int err = mp->mnt_ops->mount(mp);
    if (err != 0) {
        kprintf("vfs: mount of '%s' on '%s' failed: %d\n", fsname, path, err);
        spin_lock(&mount_lock);
        mp->mnt_active = false;
        mount_count--;
        spin_unlock(&mount_lock);
        return err;
    }

    /* If mounted at "/", set root vnode */
    if (kstrcmp(path, "/") == 0) {
        root_vnode = mp->mnt_root;
    }

    kprintf("vfs: mounted '%s' on '%s' (dev %u)\n", fsname, path, dev);
    return 0;
}

/* ============================================================================
 * VFS Lookup
 * ============================================================================ */

int
vfs_lookup(const char *path, struct vnode **result)
{
    if (path == NULL || result == NULL)
        return -EINVAL;
    if (path[0] != '/')
        return -EINVAL;

    return resolve_path(path, result, NULL, NULL, NULL);
}

/* ============================================================================
 * File Operations
 * ============================================================================ */

int
vfs_open(const char *path, uint32_t flags, mode_t mode)
{
    if (path == NULL)
        return -EINVAL;

    struct vnode *vp = NULL;
    struct vnode *parent = NULL;
    const char *last_name = NULL;
    uint32_t last_len = 0;
    int err;

    if (flags & O_CREAT) {
        /*
         * For O_CREAT: resolve the parent directory, then either find
         * or create the last component.
         */
        err = resolve_path(path, &vp, &parent, &last_name, &last_len);
        if (err != 0)
            return err;

        if (parent != NULL && last_name != NULL) {
            /* Try to look up the last component */
            err = parent->v_ops->lookup(parent, last_name, last_len, &vp);
            if (err == -ENOENT) {
                /* File doesn't exist -- create it */
                if (parent->v_ops->create == NULL) {
                    vnode_release(parent);
                    return -ENOSYS;
                }
                err = parent->v_ops->create(parent, last_name, last_len,
                                             mode, &vp);
                if (err != 0) {
                    vnode_release(parent);
                    return err;
                }
            } else if (err != 0) {
                vnode_release(parent);
                return err;
            } else if (flags & O_EXCL) {
                /* File exists and O_EXCL is set */
                vnode_release(parent);
                vnode_release(vp);
                return -EEXIST;
            }
            vnode_release(parent);
        }
        /* If vp was resolved directly (e.g. path = "/"), use it */
    } else {
        /* Simple open -- resolve the full path */
        err = vfs_lookup(path, &vp);
        if (err != 0)
            return err;
    }

    if (vp == NULL)
        return -ENOENT;

    /* Check O_DIRECTORY */
    if ((flags & O_DIRECTORY) && vp->v_type != VDIR) {
        vnode_release(vp);
        return -ENOTDIR;
    }

    /* Allocate file descriptor */
    int fd = fd_alloc();
    if (fd < 0) {
        vnode_release(vp);
        return fd;
    }

    struct file *fp = &fd_table[fd];
    fp->f_vnode = vp;
    fp->f_flags = flags;
    fp->f_offset = 0;

    /* O_APPEND: set initial offset to end of file */
    if (flags & O_APPEND)
        fp->f_offset = vp->v_size;

    /* O_TRUNC: truncate file to zero length */
    if ((flags & O_TRUNC) && vp->v_type == VREG) {
        uint32_t accmode = flags & O_ACCMODE;
        if (accmode == O_WRONLY || accmode == O_RDWR) {
            if (vp->v_ops && vp->v_ops->setattr) {
                struct stat trunc_st;
                /* Fill with sentinels: -1 means "don't change" */
                uint8_t *p = (uint8_t *)&trunc_st;
                for (uint64_t i = 0; i < sizeof(struct stat); i++)
                    p[i] = 0xFF;
                /* Only truncate size to 0 */
                trunc_st.st_size = 0;
                vp->v_ops->setattr(vp, &trunc_st);
            }
        }
    }

    return fd;
}

int64_t
vfs_read(int fd, void *buf, uint64_t count)
{
    struct file *fp = fd_get(fd);
    if (fp == NULL)
        return -EBADF;

    struct vnode *vp = fp->f_vnode;
    if (vp == NULL)
        return -EBADF;

    /* Check that file is opened for reading */
    uint32_t accmode = fp->f_flags & O_ACCMODE;
    if (accmode == O_WRONLY)
        return -EBADF;

    if (vp->v_ops == NULL || vp->v_ops->read == NULL)
        return -ENOSYS;

    spin_lock(&fp->f_lock);
    int64_t nread = vp->v_ops->read(vp, buf, fp->f_offset, count);
    if (nread > 0)
        fp->f_offset += (uint64_t)nread;
    spin_unlock(&fp->f_lock);

    return nread;
}

int64_t
vfs_write(int fd, const void *buf, uint64_t count)
{
    struct file *fp = fd_get(fd);
    if (fp == NULL)
        return -EBADF;

    struct vnode *vp = fp->f_vnode;
    if (vp == NULL)
        return -EBADF;

    /* Check that file is opened for writing */
    uint32_t accmode = fp->f_flags & O_ACCMODE;
    if (accmode == O_RDONLY)
        return -EBADF;

    if (vp->v_ops == NULL || vp->v_ops->write == NULL)
        return -ENOSYS;

    spin_lock(&fp->f_lock);

    /* O_APPEND: always write at end */
    if (fp->f_flags & O_APPEND)
        fp->f_offset = vp->v_size;

    int64_t nwritten = vp->v_ops->write(vp, buf, fp->f_offset, count);
    if (nwritten > 0)
        fp->f_offset += (uint64_t)nwritten;
    spin_unlock(&fp->f_lock);

    return nwritten;
}

int
vfs_close(int fd)
{
    struct file *fp = fd_get(fd);
    if (fp == NULL)
        return -EBADF;

    struct vnode *vp = fp->f_vnode;
    fp->f_vnode = NULL;
    fd_free(fd);

    if (vp != NULL)
        vnode_release(vp);

    return 0;
}

int
vfs_readdir(int fd, struct dirent *buf, uint32_t count)
{
    struct file *fp = fd_get(fd);
    if (fp == NULL)
        return -EBADF;

    struct vnode *vp = fp->f_vnode;
    if (vp == NULL)
        return -EBADF;

    if (vp->v_type != VDIR)
        return -ENOTDIR;

    if (vp->v_ops == NULL || vp->v_ops->readdir == NULL)
        return -ENOSYS;

    spin_lock(&fp->f_lock);
    /* The readdir vop updates fp->f_offset to the next byte position */
    int nread = vp->v_ops->readdir(vp, buf, &fp->f_offset, count);
    spin_unlock(&fp->f_lock);

    return nread;
}

int
vfs_mkdir(const char *path, mode_t mode)
{
    if (path == NULL)
        return -EINVAL;

    struct vnode *parent = NULL;
    const char *last_name = NULL;
    uint32_t last_len = 0;
    struct vnode *dummy = NULL;

    int err = resolve_path(path, &dummy, &parent, &last_name, &last_len);
    if (err != 0)
        return err;

    if (parent == NULL || last_name == NULL) {
        /* Path already exists (resolved completely) */
        if (dummy)
            vnode_release(dummy);
        return -EEXIST;
    }

    if (parent->v_ops == NULL || parent->v_ops->mkdir == NULL) {
        vnode_release(parent);
        return -ENOSYS;
    }

    struct vnode *newdir = NULL;
    err = parent->v_ops->mkdir(parent, last_name, last_len, mode, &newdir);
    vnode_release(parent);
    if (newdir)
        vnode_release(newdir);

    return err;
}

int
vfs_create(const char *path, mode_t mode)
{
    /* Use vfs_open with O_CREAT | O_EXCL, then close the fd */
    int fd = vfs_open(path, O_CREAT | O_EXCL | O_WRONLY, mode);
    if (fd < 0)
        return fd;
    return vfs_close(fd);
}

int
vfs_unlink(const char *path)
{
    if (path == NULL)
        return -EINVAL;

    struct vnode *parent = NULL;
    const char *last_name = NULL;
    uint32_t last_len = 0;
    struct vnode *dummy = NULL;

    int err = resolve_path(path, &dummy, &parent, &last_name, &last_len);
    if (err != 0)
        return err;

    if (parent == NULL || last_name == NULL) {
        /* Can't unlink root or a mount point */
        if (dummy)
            vnode_release(dummy);
        return -EINVAL;
    }

    if (parent->v_ops == NULL || parent->v_ops->unlink == NULL) {
        vnode_release(parent);
        return -ENOSYS;
    }

    err = parent->v_ops->unlink(parent, last_name, last_len);
    vnode_release(parent);
    return err;
}

int
vfs_stat(const char *path, struct stat *st)
{
    if (path == NULL || st == NULL)
        return -EINVAL;

    struct vnode *vp = NULL;
    int err = vfs_lookup(path, &vp);
    if (err != 0)
        return err;

    if (vp->v_ops == NULL || vp->v_ops->getattr == NULL) {
        vnode_release(vp);
        return -ENOSYS;
    }

    err = vp->v_ops->getattr(vp, st);
    vnode_release(vp);
    return err;
}

int
vfs_fstat(int fd, struct stat *st)
{
    if (st == NULL)
        return -EINVAL;

    struct file *fp = fd_get(fd);
    if (fp == NULL)
        return -EBADF;

    struct vnode *vp = fp->f_vnode;
    if (vp == NULL)
        return -EBADF;

    if (vp->v_ops == NULL || vp->v_ops->getattr == NULL)
        return -ENOSYS;

    return vp->v_ops->getattr(vp, st);
}

int64_t
vfs_lseek(int fd, int64_t offset, int whence)
{
    struct file *fp = fd_get(fd);
    if (fp == NULL)
        return -EBADF;

    spin_lock(&fp->f_lock);

    int64_t new_offset;
    switch (whence) {
    case SEEK_SET:
        new_offset = offset;
        break;
    case SEEK_CUR:
        new_offset = (int64_t)fp->f_offset + offset;
        break;
    case SEEK_END:
        if (fp->f_vnode == NULL) {
            spin_unlock(&fp->f_lock);
            return -EBADF;
        }
        new_offset = (int64_t)fp->f_vnode->v_size + offset;
        break;
    default:
        spin_unlock(&fp->f_lock);
        return -EINVAL;
    }

    if (new_offset < 0) {
        spin_unlock(&fp->f_lock);
        return -EINVAL;
    }

    fp->f_offset = (uint64_t)new_offset;
    spin_unlock(&fp->f_lock);

    return new_offset;
}

/* ============================================================================
 * vfs_statfs - Get filesystem statistics for a path.
 * ============================================================================ */

int vfs_statfs(const char *path, struct statfs *buf)
{
    if (path == NULL || buf == NULL)
        return -EINVAL;

    struct mount *mp = mount_find(path, NULL);
    if (mp == NULL)
        return -ENOENT;

    if (mp->mnt_ops == NULL || mp->mnt_ops->statfs == NULL)
        return -ENOSYS;

    return mp->mnt_ops->statfs(mp, buf);
}
