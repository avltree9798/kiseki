/*
 * Kiseki OS - Device Filesystem (devfs)
 *
 * A minimal synthetic filesystem mounted at /dev that provides
 * character device nodes. No on-disk backing; entries are created
 * in-memory during boot.
 *
 * Supported devices:
 *   /dev/console  - Console TTY (read/write/ioctl → tty subsystem)
 *   /dev/tty      - Alias for /dev/console
 *   /dev/null     - Data sink (writes succeed, reads return EOF)
 *   /dev/zero     - Zero source (reads return NUL bytes)
 *
 * Each device is represented by a vnode with v_type = VCHR and
 * v_data pointing to a devfs_node identifying the device.
 */

#include <kiseki/types.h>
#include <fs/vfs.h>
#include <kern/kprintf.h>
#include <kern/sync.h>
#include <kern/tty.h>

/* ============================================================================
 * Device Identifiers
 * ============================================================================ */

#define DEVFS_CONSOLE   1       /* /dev/console */
#define DEVFS_TTY       2       /* /dev/tty (alias for console) */
#define DEVFS_NULL      3       /* /dev/null */
#define DEVFS_ZERO      4       /* /dev/zero */

#define DEVFS_MAX_NODES 16

/* ============================================================================
 * devfs node — in-memory representation of a device entry
 * ============================================================================ */

struct devfs_node {
    const char     *name;       /* Device name (e.g. "console") */
    uint32_t        namelen;    /* Length of name */
    int             devid;      /* DEVFS_CONSOLE, DEVFS_NULL, etc. */
    struct vnode   *vp;         /* Cached vnode for this device */
    bool            active;     /* Slot is in use */
};

static struct devfs_node devfs_nodes[DEVFS_MAX_NODES];
static int devfs_node_count = 0;

/* The root directory vnode for devfs */
static struct vnode *devfs_root_vp = NULL;

/* Forward declarations */
static struct vnode_ops devfs_dir_ops;
static struct vnode_ops devfs_chr_ops;

/* ============================================================================
 * String Helpers (freestanding)
 * ============================================================================ */

static int
devfs_strncmp(const char *a, const char *b, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) {
        if (a[i] != b[i])
            return (unsigned char)a[i] - (unsigned char)b[i];
        if (a[i] == '\0')
            return 0;
    }
    return 0;
}

static uint32_t
devfs_strlen(const char *s)
{
    uint32_t len = 0;
    while (s[len])
        len++;
    return len;
}

static void
devfs_memset(void *dst, int val, uint64_t n)
{
    uint8_t *p = (uint8_t *)dst;
    for (uint64_t i = 0; i < n; i++)
        p[i] = (uint8_t)val;
}

/* ============================================================================
 * Device Node Registration
 * ============================================================================ */

static struct devfs_node *
devfs_add_node(const char *name, int devid)
{
    if (devfs_node_count >= DEVFS_MAX_NODES) {
        kprintf("[devfs] node table full\n");
        return NULL;
    }

    struct devfs_node *dn = &devfs_nodes[devfs_node_count];
    dn->name = name;
    dn->namelen = devfs_strlen(name);
    dn->devid = devid;
    dn->vp = NULL;
    dn->active = true;
    devfs_node_count++;

    return dn;
}

/* ============================================================================
 * Character Device Vnode Operations
 *
 * These implement read/write for each device type. The vnode's v_data
 * points to the devfs_node.
 * ============================================================================ */

/*
 * devfs_chr_read - Read from a character device.
 */
static int64_t
devfs_chr_read(struct vnode *vp, void *buf, uint64_t offset, uint64_t count)
{
    (void)offset;  /* Character devices don't use offset */

    struct devfs_node *dn = (struct devfs_node *)vp->v_data;
    if (dn == NULL)
        return -EIO;

    switch (dn->devid) {
    case DEVFS_CONSOLE:
    case DEVFS_TTY: {
        struct tty *tp = tty_get_console();
        return tty_read(tp, buf, count);
    }

    case DEVFS_NULL:
        /* Reading from /dev/null always returns EOF */
        return 0;

    case DEVFS_ZERO: {
        /* Reading from /dev/zero returns NUL bytes */
        devfs_memset(buf, 0, count);
        return (int64_t)count;
    }

    default:
        return -EIO;
    }
}

/*
 * devfs_chr_write - Write to a character device.
 */
static int64_t
devfs_chr_write(struct vnode *vp, const void *buf, uint64_t offset,
                uint64_t count)
{
    (void)offset;  /* Character devices don't use offset */

    struct devfs_node *dn = (struct devfs_node *)vp->v_data;
    if (dn == NULL)
        return -EIO;

    switch (dn->devid) {
    case DEVFS_CONSOLE:
    case DEVFS_TTY: {
        struct tty *tp = tty_get_console();
        return tty_write(tp, buf, count);
    }

    case DEVFS_NULL:
    case DEVFS_ZERO:
        /* Writes are discarded silently */
        return (int64_t)count;

    default:
        return -EIO;
    }
}

/*
 * devfs_chr_getattr - Return stat information for a character device.
 */
static int
devfs_chr_getattr(struct vnode *vp, struct stat *st)
{
    devfs_memset(st, 0, sizeof(*st));

    struct devfs_node *dn = (struct devfs_node *)vp->v_data;

    st->st_dev = 0;
    st->st_ino = (uint64_t)(100 + dn->devid);  /* Synthetic inode */
    st->st_mode = 0020666;  /* S_IFCHR | rw-rw-rw- */
    st->st_nlink = 1;
    st->st_uid = 0;
    st->st_gid = 0;
    st->st_rdev = 0;  /* Could encode major/minor here */
    st->st_size = 0;
    st->st_blocks = 0;
    st->st_blksize = 4096;

    return 0;
}

static struct vnode_ops devfs_chr_ops = {
    .lookup  = NULL,
    .read    = devfs_chr_read,
    .write   = devfs_chr_write,
    .readdir = NULL,
    .create  = NULL,
    .mkdir   = NULL,
    .unlink  = NULL,
    .getattr = devfs_chr_getattr,
    .setattr = NULL,
};

/* ============================================================================
 * Directory Vnode Operations (the /dev directory itself)
 * ============================================================================ */

/*
 * devfs_dir_lookup - Look up a device by name in /dev.
 */
static int
devfs_dir_lookup(struct vnode *dir, const char *name, uint32_t namelen,
                 struct vnode **result)
{
    (void)dir;

    for (int i = 0; i < devfs_node_count; i++) {
        struct devfs_node *dn = &devfs_nodes[i];
        if (!dn->active)
            continue;
        if (dn->namelen == namelen &&
            devfs_strncmp(dn->name, name, namelen) == 0) {
            /* Return the cached vnode */
            if (dn->vp == NULL) {
                /* Shouldn't happen — created during mount */
                return -EIO;
            }
            vnode_ref(dn->vp);
            *result = dn->vp;
            return 0;
        }
    }

    return -ENOENT;
}

/*
 * devfs_dir_readdir - Read entries from /dev.
 */
static int
devfs_dir_readdir(struct vnode *dir, struct dirent *buf, uint64_t *offset,
                  uint32_t count)
{
    (void)dir;

    int start = (int)(*offset);
    int nread = 0;

    for (int i = start; i < devfs_node_count && (uint32_t)nread < count; i++) {
        struct devfs_node *dn = &devfs_nodes[i];
        if (!dn->active)
            continue;

        /* Clear the dirent (1048 bytes) */
        devfs_memset(&buf[nread], 0, sizeof(struct dirent));

        buf[nread].d_ino = (uint64_t)(100 + dn->devid);
        buf[nread].d_seekoff = (uint64_t)(i + 1);
        buf[nread].d_reclen = sizeof(struct dirent);
        buf[nread].d_namlen = (uint16_t)dn->namelen;
        buf[nread].d_type = DT_CHR;

        /* Copy name */
        for (uint32_t j = 0; j < dn->namelen && j < MAXPATHLEN - 1; j++)
            buf[nread].d_name[j] = dn->name[j];
        buf[nread].d_name[dn->namelen] = '\0';

        nread++;
        *offset = (uint64_t)(i + 1);
    }

    return nread;
}

/*
 * devfs_dir_getattr - Return stat for /dev directory.
 */
static int
devfs_dir_getattr(struct vnode *vp, struct stat *st)
{
    (void)vp;
    devfs_memset(st, 0, sizeof(*st));

    st->st_dev = 0;
    st->st_ino = 2;  /* Root inode of devfs */
    st->st_mode = 0040755;  /* S_IFDIR | rwxr-xr-x */
    st->st_nlink = 2 + (nlink_t)devfs_node_count;
    st->st_uid = 0;
    st->st_gid = 0;
    st->st_size = (off_t)(devfs_node_count * sizeof(struct dirent));
    st->st_blksize = 4096;

    return 0;
}

static struct vnode_ops devfs_dir_ops = {
    .lookup  = devfs_dir_lookup,
    .read    = NULL,
    .write   = NULL,
    .readdir = devfs_dir_readdir,
    .create  = NULL,
    .mkdir   = NULL,
    .unlink  = NULL,
    .getattr = devfs_dir_getattr,
    .setattr = NULL,
};

/* ============================================================================
 * devfs Mount Operation
 * ============================================================================ */

static int
devfs_mount(struct mount *mp)
{
    /* Allocate root directory vnode */
    struct vnode *root = vnode_alloc();
    if (root == NULL)
        return -ENOMEM;

    root->v_type = VDIR;
    root->v_mode = 0040755;
    root->v_ino = 2;
    root->v_size = 0;
    root->v_uid = 0;
    root->v_gid = 0;
    root->v_nlink = 2;
    root->v_ops = &devfs_dir_ops;
    root->v_mount = mp;
    root->v_data = NULL;

    mp->mnt_root = root;
    devfs_root_vp = root;

    /* Register standard device nodes */
    struct {
        const char *name;
        int devid;
    } devices[] = {
        { "console", DEVFS_CONSOLE },
        { "tty",     DEVFS_TTY     },
        { "null",    DEVFS_NULL    },
        { "zero",    DEVFS_ZERO    },
    };

    for (int i = 0; i < (int)(sizeof(devices) / sizeof(devices[0])); i++) {
        struct devfs_node *dn = devfs_add_node(devices[i].name,
                                               devices[i].devid);
        if (dn == NULL)
            continue;

        /* Create a vnode for this device */
        struct vnode *vp = vnode_alloc();
        if (vp == NULL) {
            kprintf("[devfs] failed to allocate vnode for %s\n",
                    devices[i].name);
            continue;
        }

        vp->v_type = VCHR;
        vp->v_mode = 0020666;  /* S_IFCHR | rw-rw-rw- */
        vp->v_ino = (uint64_t)(100 + devices[i].devid);
        vp->v_size = 0;
        vp->v_uid = 0;
        vp->v_gid = 0;
        vp->v_nlink = 1;
        vp->v_ops = &devfs_chr_ops;
        vp->v_mount = mp;
        vp->v_data = dn;

        dn->vp = vp;
    }

    kprintf("[devfs] mounted at %s (%d devices)\n",
            mp->mnt_path, devfs_node_count);

    return 0;
}

static int
devfs_unmount(struct mount *mp)
{
    (void)mp;
    /* devfs is never unmounted */
    return -EINVAL;
}

static int
devfs_statfs(struct mount *mp, struct statfs *buf)
{
    (void)mp;
    devfs_memset(buf, 0, sizeof(*buf));

    buf->f_blocks = 0;
    buf->f_bfree = 0;
    buf->f_bavail = 0;
    buf->f_files = (uint64_t)devfs_node_count;
    buf->f_ffree = (uint64_t)(DEVFS_MAX_NODES - devfs_node_count);
    buf->f_bsize = 4096;
    buf->f_namelen = 255;

    /* Copy "devfs" into f_fstype */
    const char *fsname = "devfs";
    for (int i = 0; i < 5; i++)
        buf->f_fstype[i] = fsname[i];
    buf->f_fstype[5] = '\0';

    return 0;
}

static struct fs_ops devfs_fsops = {
    .mount   = devfs_mount,
    .unmount = devfs_unmount,
    .sync    = NULL,
    .statfs  = devfs_statfs,
};

/* ============================================================================
 * devfs Initialization
 *
 * Called during boot to register the devfs filesystem type.
 * The actual mount at /dev happens separately from main.c.
 * ============================================================================ */

void devfs_init(void)
{
    /* Clear node table */
    for (int i = 0; i < DEVFS_MAX_NODES; i++)
        devfs_nodes[i].active = false;
    devfs_node_count = 0;

    vfs_register_fs("devfs", &devfs_fsops);
}

/* ============================================================================
 * devfs Query API (for sys_ioctl to detect console device vnodes)
 * ============================================================================ */

/*
 * devfs_is_console - Check if a vnode is a devfs console or tty device.
 *
 * Returns true if the vnode represents /dev/console or /dev/tty.
 */
bool devfs_is_console(struct vnode *vp)
{
    if (vp == NULL || vp->v_type != VCHR)
        return false;
    if (vp->v_ops != &devfs_chr_ops)
        return false;

    struct devfs_node *dn = (struct devfs_node *)vp->v_data;
    if (dn == NULL)
        return false;

    return (dn->devid == DEVFS_CONSOLE || dn->devid == DEVFS_TTY);
}
