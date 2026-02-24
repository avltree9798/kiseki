/*
 * Kiseki OS - Virtual File System Implementation
 *
 * Path resolution, mount table, vnode refcounting, and file descriptor
 * operations that delegate to filesystem-specific vnode_ops.
 */

#include <kiseki/types.h>
#include <kern/kprintf.h>
#include <kern/sync.h>
#include <kern/proc.h>
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

/* File pool - backing storage for open file descriptions */
#define VFS_MAX_FILES   512     /* Max open file descriptions */
static struct file      file_pool[VFS_MAX_FILES];
static spinlock_t       file_pool_lock = SPINLOCK_INIT;

/*
 * Per-process file descriptor table.
 *
 * All fd lookups go through the current process's p_fd (struct filedesc).
 * There is no global fd_table. This matches the XNU/BSD model where each
 * process has its own file descriptor namespace.
 *
 * During early boot (before proc subsystem is initialised), fd operations
 * are not used — kprintf goes directly to UART/fbconsole, not through fds.
 */

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
 * Permission Checking
 *
 * Unix permission model: owner/group/other with read/write/execute bits.
 * Root (uid 0) bypasses all permission checks.
 * ============================================================================ */

/* Access mode bits for vfs_check_permission */
#define VREAD   0x04
#define VWRITE  0x02
#define VEXEC   0x01

/*
 * vfs_check_permission - Check if current process can access vnode
 *
 * @vp:   Vnode to check
 * @mode: Access mode (VREAD, VWRITE, VEXEC, or combination)
 *
 * Returns 0 if access is allowed, -EACCES if denied.
 */
static int
vfs_check_permission(struct vnode *vp, int mode)
{
    struct proc *p = proc_current();
    if (p == NULL)
        return 0;  /* Kernel context - allow all */

    uid_t uid = p->p_ucred.cr_uid;
    gid_t gid = p->p_ucred.cr_gid;

    /* Root bypasses all permission checks */
    if (uid == 0)
        return 0;

    mode_t file_mode = vp->v_mode;
    mode_t perm_bits;

    if (uid == vp->v_uid) {
        /* Owner permissions (bits 8-6) */
        perm_bits = (file_mode >> 6) & 0x7;
    } else if (gid == vp->v_gid) {
        /* Group permissions (bits 5-3) */
        perm_bits = (file_mode >> 3) & 0x7;
    } else {
        /* Other permissions (bits 2-0) */
        perm_bits = file_mode & 0x7;
    }

    /* Check if requested access is allowed */
    if ((mode & VREAD) && !(perm_bits & 0x4))
        return -EACCES;
    if ((mode & VWRITE) && !(perm_bits & 0x2))
        return -EACCES;
    if ((mode & VEXEC) && !(perm_bits & 0x1))
        return -EACCES;

    return 0;
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
 *
 * Architecture:
 * - file_pool[]: Pool of struct file (open file descriptions, system-wide)
 * - p_fd.fd_ofiles[]: Per-process array of pointers into file_pool
 *
 * Multiple FDs can point to the same file (via dup/fork), sharing offset.
 * f_refcount tracks how many FDs reference each file description.
 * ============================================================================ */

/*
 * file_alloc - Allocate a new file description from the pool
 */
static struct file *
file_alloc(void)
{
    spin_lock(&file_pool_lock);
    for (int i = 0; i < VFS_MAX_FILES; i++) {
        if (file_pool[i].f_refcount == 0) {
            file_pool[i].f_refcount = 1;
            file_pool[i].f_offset = 0;
            file_pool[i].f_flags = 0;
            file_pool[i].f_vnode = NULL;
            file_pool[i].f_pipe = NULL;
            file_pool[i].f_pipe_dir = 0;
            file_pool[i].f_pty = NULL;
            file_pool[i].f_pty_side = 0;
            file_pool[i].f_sockidx = -1;
            spin_init(&file_pool[i].f_lock);
            spin_unlock(&file_pool_lock);
            return &file_pool[i];
        }
    }
    spin_unlock(&file_pool_lock);
    return NULL;
}

/*
 * file_ref - Increment reference count on a file description
 */
static void
file_ref(struct file *fp)
{
    if (fp == NULL)
        return;
    spin_lock(&fp->f_lock);
    fp->f_refcount++;
    spin_unlock(&fp->f_lock);
}

/*
 * file_unref - Decrement reference count, free if zero
 */
static void
file_unref(struct file *fp)
{
    if (fp == NULL)
        return;
    spin_lock(&fp->f_lock);
    if (fp->f_refcount > 0)
        fp->f_refcount--;
    spin_unlock(&fp->f_lock);
    /* Note: f_refcount==0 marks it as free in file_alloc */
}

/*
 * proc_fd_table - Get the current process's file descriptor table.
 *
 * Returns NULL during early boot when no process context exists.
 */
static struct filedesc *
proc_fd_table(void)
{
    struct proc *p = proc_current();
    if (p == NULL)
        return NULL;
    return &p->p_fd;
}

/*
 * vfs_fd_alloc - Allocate a file descriptor and associated file description
 *
 * Installs the new struct file into the current process's fd table
 * at the lowest available slot.
 */
static int
vfs_fd_alloc(void)
{
    struct filedesc *fdp = proc_fd_table();
    if (fdp == NULL)
        return -EBADF;  /* No process context */

    struct file *fp = file_alloc();
    if (fp == NULL)
        return -ENFILE;  /* File table full */

    uint64_t flags;
    spin_lock_irqsave(&fdp->fd_lock, &flags);
    for (int i = 0; i < PROC_FD_MAX; i++) {
        if (fdp->fd_ofiles[i] == NULL) {
            fdp->fd_ofiles[i] = fp;
            fdp->fd_oflags[i] = 0;
            if ((uint32_t)(i + 1) > fdp->fd_nfiles)
                fdp->fd_nfiles = (uint32_t)(i + 1);
            spin_unlock_irqrestore(&fdp->fd_lock, flags);
            return i;
        }
    }
    spin_unlock_irqrestore(&fdp->fd_lock, flags);
    file_unref(fp);  /* Release the file we allocated */
    return -EMFILE;  /* FD table full */
}

/*
 * fd_get - Get file description for a file descriptor
 *
 * Looks up in the current process's per-process fd table.
 */
static struct file *
fd_get(int fd)
{
    if (fd < 0 || fd >= PROC_FD_MAX)
        return NULL;
    struct filedesc *fdp = proc_fd_table();
    if (fdp == NULL)
        return NULL;
    return fdp->fd_ofiles[fd];  /* May be NULL if fd not open */
}

/*
 * fd_free - Release a file descriptor (decrements file refcount)
 */
static void
fd_free(int fd)
{
    if (fd < 0 || fd >= PROC_FD_MAX)
        return;
    struct filedesc *fdp = proc_fd_table();
    if (fdp == NULL)
        return;
    uint64_t flags;
    spin_lock_irqsave(&fdp->fd_lock, &flags);
    struct file *fp = fdp->fd_ofiles[fd];
    fdp->fd_ofiles[fd] = NULL;
    fdp->fd_oflags[fd] = 0;
    spin_unlock_irqrestore(&fdp->fd_lock, flags);
    if (fp)
        file_unref(fp);
}

/*
 * vfs_get_file - Get the file structure for a file descriptor.
 *
 * Public API wrapper around fd_get.
 */
struct file *
vfs_get_file(int fd)
{
    return fd_get(fd);
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
 * Per-FD flags (FD_CLOEXEC etc.) — stored in the per-process fd table.
 */
int
vfs_get_fd_flags(int fd)
{
    if (fd < 0 || fd >= PROC_FD_MAX)
        return -EBADF;
    struct filedesc *fdp = proc_fd_table();
    if (fdp == NULL)
        return -EBADF;
    if (fdp->fd_ofiles[fd] == NULL)
        return -EBADF;
    return (int)fdp->fd_oflags[fd];
}

int
vfs_set_fd_flags(int fd, uint8_t flags)
{
    if (fd < 0 || fd >= PROC_FD_MAX)
        return -EBADF;
    struct filedesc *fdp = proc_fd_table();
    if (fdp == NULL)
        return -EBADF;
    if (fdp->fd_ofiles[fd] == NULL)
        return -EBADF;
    fdp->fd_oflags[fd] = flags;
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
 *
 * The new FD points to the same file description as oldfd, sharing
 * the file offset, flags, and underlying vnode. This is POSIX dup() semantics.
 * Operates on the current process's per-process fd table.
 */
int
vfs_dup_fd(int oldfd, int minfd)
{
    struct filedesc *fdp = proc_fd_table();
    if (fdp == NULL)
        return -EBADF;

    struct file *fp = fd_get(oldfd);
    if (fp == NULL)
        return -EBADF;

    uint64_t flags;
    spin_lock_irqsave(&fdp->fd_lock, &flags);
    for (int i = minfd; i < PROC_FD_MAX; i++) {
        if (fdp->fd_ofiles[i] == NULL) {
            /* Point new FD to the same file description */
            fdp->fd_ofiles[i] = fp;
            fdp->fd_oflags[i] = 0;  /* New FD does not inherit FD_CLOEXEC */

            /* Increment file description refcount */
            file_ref(fp);

            if ((uint32_t)(i + 1) > fdp->fd_nfiles)
                fdp->fd_nfiles = (uint32_t)(i + 1);
            spin_unlock_irqrestore(&fdp->fd_lock, flags);
            return i;
        }
    }
    spin_unlock_irqrestore(&fdp->fd_lock, flags);
    return -EMFILE;
}

/* ============================================================================
 * Socket FD Helpers
 * ============================================================================ */

int
vfs_alloc_sockfd(int sockidx)
{
    int fd = vfs_fd_alloc();
    if (fd < 0)
        return fd;

    struct file *fp = fd_get(fd);
    fp->f_vnode = NULL;
    fp->f_sockidx = sockidx;

    struct filedesc *fdp = proc_fd_table();
    if (fdp)
        fdp->fd_oflags[fd] = FD_SOCKET;

    return fd;
}

int
vfs_get_sockidx(int fd)
{
    if (fd < 0 || fd >= PROC_FD_MAX)
        return -1;
    struct filedesc *fdp = proc_fd_table();
    if (fdp == NULL)
        return -1;
    struct file *fp = fdp->fd_ofiles[fd];
    if (fp == NULL)
        return -1;
    if (!(fdp->fd_oflags[fd] & FD_SOCKET))
        return -1;
    return fp->f_sockidx;
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
    int fd = vfs_fd_alloc();
    if (fd < 0)
        return fd;

    struct file *fp = fd_get(fd);
    fp->f_vnode = NULL;
    fp->f_pipe = pipe_data;
    fp->f_pipe_dir = (uint32_t)dir;

    struct filedesc *fdp = proc_fd_table();
    if (fdp)
        fdp->fd_oflags[fd] |= FD_PIPE;

    return fd;
}

void *
vfs_get_pipe(int fd, int *dir)
{
    if (fd < 0 || fd >= PROC_FD_MAX)
        return NULL;
    struct file *fp = fd_get(fd);
    if (fp == NULL)
        return NULL;
    if (fp->f_pipe == NULL)
        return NULL;
    if (dir)
        *dir = (int)fp->f_pipe_dir;
    return fp->f_pipe;
}

void *
vfs_get_pty(int fd, int *side)
{
    if (fd < 0 || fd >= PROC_FD_MAX)
        return NULL;
    struct file *fp = fd_get(fd);
    if (fp == NULL)
        return NULL;
    if (fp->f_pty == NULL)
        return NULL;
    if (side)
        *side = (int)fp->f_pty_side;
    return fp->f_pty;
}

int
vfs_alloc_pty_fd(void *pty_ptr, int side)
{
    int fd = vfs_fd_alloc();
    if (fd < 0)
        return fd;
    struct file *fp = fd_get(fd);
    fp->f_pty = pty_ptr;
    fp->f_pty_side = (uint32_t)side;
    fp->f_flags = O_RDWR;
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

        /* Check execute permission to traverse this directory */
        int perr = vfs_check_permission(current, VEXEC);
        if (perr != 0) {
            vnode_release(current);
            return perr;
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
    spin_init(&vnode_pool_lock);
    spin_init(&file_pool_lock);

    /* Zero out tables */
    for (uint32_t i = 0; i < VFS_MAX_MOUNTS; i++)
        mount_table[i].mnt_active = false;
    for (uint32_t i = 0; i < VFS_MAX_FSTYPES; i++)
        fs_types[i].active = false;
    for (int i = 0; i < VFS_MAX_FILES; i++)
        file_pool[i].f_refcount = 0;

    /*
     * No global fd table reservation needed.
     * Console fds 0/1/2 are set up per-process in setup_stdio() (proc.c).
     * Each process has its own fd namespace via p_fd (struct filedesc).
     */
    for (uint32_t i = 0; i < VFS_MAX_VNODES; i++) {
        vnode_pool[i].v_refcount = 0;
        vnode_pool[i].v_type = VNON;
    }

    mount_count = 0;
    root_vnode = NULL;

    kprintf("vfs: initialized (max %d mounts, %d vnodes, %d fds/proc)\n",
            VFS_MAX_MOUNTS, VFS_MAX_VNODES, PROC_FD_MAX);
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
                /* File doesn't exist -- need write permission on parent to create */
                err = vfs_check_permission(parent, VWRITE);
                if (err != 0) {
                    vnode_release(parent);
                    return err;
                }
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

    /* Check access permissions based on open mode */
    {
        uint32_t accmode = flags & O_ACCMODE;
        int perm = 0;
        if (accmode == O_RDONLY || accmode == O_RDWR)
            perm |= VREAD;
        if (accmode == O_WRONLY || accmode == O_RDWR)
            perm |= VWRITE;
        if (perm != 0) {
            err = vfs_check_permission(vp, perm);
            if (err != 0) {
                vnode_release(vp);
                return err;
            }
        }
    }

    /* Allocate file descriptor */
    int fd = vfs_fd_alloc();
    if (fd < 0) {
        vnode_release(vp);
        return fd;
    }

    struct file *fp = fd_get(fd);
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

    /*
     * Snapshot the current offset under the lock, then release the lock
     * before performing the actual I/O. This is critical because character
     * device reads (e.g., TTY via tty_read → tty_getc → thread_sleep_on)
     * may block, and sleeping while holding a spinlock is incorrect.
     *
     * This matches XNU's vn_read() pattern: the lock protects the offset
     * bookkeeping, not the I/O itself. For regular files, concurrent reads
     * on the same struct file may interleave, but POSIX does not guarantee
     * atomicity of concurrent reads sharing a file description anyway.
     */
    spin_lock(&fp->f_lock);
    uint64_t off = fp->f_offset;
    spin_unlock(&fp->f_lock);

    int64_t nread = vp->v_ops->read(vp, buf, off, count);

    if (nread > 0) {
        spin_lock(&fp->f_lock);
        fp->f_offset += (uint64_t)nread;
        spin_unlock(&fp->f_lock);
    }

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

    /*
     * Snapshot offset under the lock, same pattern as vfs_read.
     * For O_APPEND, set offset to the current file size.
     * TTY writes (tty_write → t_putc) typically don't block, but
     * consistency with the read path is important for correctness.
     */
    spin_lock(&fp->f_lock);
    if (fp->f_flags & O_APPEND)
        fp->f_offset = vp->v_size;
    uint64_t off = fp->f_offset;
    spin_unlock(&fp->f_lock);

    int64_t nwritten = vp->v_ops->write(vp, buf, off, count);

    if (nwritten > 0) {
        spin_lock(&fp->f_lock);
        fp->f_offset += (uint64_t)nwritten;
        spin_unlock(&fp->f_lock);
    }

    return nwritten;
}

int
vfs_close(int fd)
{
    struct file *fp = fd_get(fd);
    if (fp == NULL)
        return -EBADF;

    /*
     * Detach fd from the per-process table and decrement the file
     * description refcount. Only release the vnode when no more fds
     * reference this file description.
     *
     * This matches the POSIX/XNU model: dup()'d fds share a struct file.
     * close() on one fd must not destroy the vnode that other fds still use.
     */
    struct vnode *vp = fp->f_vnode;

    /* Remove the fd from the per-process table */
    struct filedesc *fdp = proc_fd_table();
    if (fdp) {
        uint64_t flags;
        spin_lock_irqsave(&fdp->fd_lock, &flags);
        fdp->fd_ofiles[fd] = NULL;
        fdp->fd_oflags[fd] = 0;
        spin_unlock_irqrestore(&fdp->fd_lock, flags);
    }

    /* Decrement refcount; release resources only when it hits zero */
    spin_lock(&fp->f_lock);
    if (fp->f_refcount > 0)
        fp->f_refcount--;
    if (fp->f_refcount == 0) {
        fp->f_vnode = NULL;
        fp->f_pipe = NULL;
        fp->f_pty = NULL;
        fp->f_sockidx = -1;
        spin_unlock(&fp->f_lock);

        if (vp != NULL)
            vnode_release(vp);
    } else {
        spin_unlock(&fp->f_lock);
    }

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

    /*
     * For readdir, the offset is a cookie that the filesystem uses to
     * track position. We snapshot it, pass a local copy to the vop,
     * and write back the updated value. This avoids holding the lock
     * across potentially blocking filesystem I/O.
     */
    spin_lock(&fp->f_lock);
    uint64_t dir_off = fp->f_offset;
    spin_unlock(&fp->f_lock);

    int nread = vp->v_ops->readdir(vp, buf, &dir_off, count);

    spin_lock(&fp->f_lock);
    fp->f_offset = dir_off;
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

    /* Check write permission on parent directory */
    err = vfs_check_permission(parent, VWRITE);
    if (err != 0) {
        vnode_release(parent);
        return err;
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

    /* Check write permission on parent directory */
    err = vfs_check_permission(parent, VWRITE);
    if (err != 0) {
        vnode_release(parent);
        return err;
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
