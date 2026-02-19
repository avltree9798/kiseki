/*
 * Kiseki OS - BSD Security Subsystem Implementation
 *
 * Reference-counted credentials, UNIX permission checks, and SUID/SGID
 * handling. Implements the traditional UNIX DAC model.
 *
 * Credential allocation uses a fixed pool to avoid dynamic memory
 * allocation complexity in the early kernel. The pool size should be
 * sufficient for all concurrent processes.
 */

#include <kiseki/types.h>
#include <bsd/security.h>
#include <fs/vfs.h>
#include <kern/kprintf.h>
#include <kern/sync.h>

/* ============================================================================
 * Credential Pool
 *
 * Fixed-size pool of ucred structures. In a full kernel this would use
 * a slab allocator; here we use a simple free-list over a static array.
 * ============================================================================ */

#define UCRED_POOL_SIZE     128

static struct ucred ucred_pool[UCRED_POOL_SIZE];

/*
 * Free-list using an index chain. Each free slot stores the index of the
 * next free slot in free_next[]. A value of -1 means end of list.
 */
static int32_t ucred_free_next[UCRED_POOL_SIZE];
static int32_t ucred_free_head;
static spinlock_t ucred_lock = SPINLOCK_INIT;

/* ============================================================================
 * Initialization
 * ============================================================================ */

void security_init(void)
{
    /* Build the free list as a chain of indices */
    for (int i = 0; i < UCRED_POOL_SIZE - 1; i++) {
        ucred_pool[i].cr_ref = 0;
        ucred_free_next[i] = i + 1;
    }
    ucred_pool[UCRED_POOL_SIZE - 1].cr_ref = 0;
    ucred_free_next[UCRED_POOL_SIZE - 1] = -1;
    ucred_free_head = 0;

    kprintf("[security] credential pool initialized (%d entries)\n",
            UCRED_POOL_SIZE);
}

/* ============================================================================
 * Credential Allocation
 * ============================================================================ */

struct ucred *ucred_create(uid_t uid, gid_t gid)
{
    uint64_t flags;
    spin_lock_irqsave(&ucred_lock, &flags);

    if (ucred_free_head < 0) {
        spin_unlock_irqrestore(&ucred_lock, flags);
        kprintf("[security] ucred pool exhausted\n");
        return NULL;
    }

    int32_t idx = ucred_free_head;
    ucred_free_head = ucred_free_next[idx];
    struct ucred *cr = &ucred_pool[idx];

    spin_unlock_irqrestore(&ucred_lock, flags);

    /* Initialize all fields */
    cr->cr_uid   = uid;
    cr->cr_ruid  = uid;
    cr->cr_svuid = uid;
    cr->cr_gid   = gid;
    cr->cr_rgid  = gid;
    cr->cr_svgid = gid;
    cr->cr_ngroups = 0;
    cr->cr_ref = 1;

    /* Zero out supplementary groups */
    for (uint32_t i = 0; i < NGROUPS_MAX; i++)
        cr->cr_groups[i] = 0;

    return cr;
}

void ucred_ref(struct ucred *cr)
{
    if (cr == NULL)
        return;

    uint64_t flags;
    spin_lock_irqsave(&ucred_lock, &flags);
    cr->cr_ref++;
    spin_unlock_irqrestore(&ucred_lock, flags);
}

void ucred_release(struct ucred *cr)
{
    if (cr == NULL)
        return;

    uint64_t flags;
    spin_lock_irqsave(&ucred_lock, &flags);

    if (cr->cr_ref == 0) {
        spin_unlock_irqrestore(&ucred_lock, flags);
        kprintf("[security] WARNING: ucred_release on already-free cred\n");
        return;
    }

    cr->cr_ref--;
    if (cr->cr_ref == 0) {
        /* Return to free list using index */
        int32_t idx = (int32_t)(cr - ucred_pool);
        ucred_free_next[idx] = ucred_free_head;
        ucred_free_head = idx;
    }

    spin_unlock_irqrestore(&ucred_lock, flags);
}

/* ============================================================================
 * Group Membership
 * ============================================================================ */

bool groupmember(gid_t gid, struct ucred *cr)
{
    if (cr == NULL)
        return false;

    /* Check effective GID */
    if (cr->cr_gid == gid)
        return true;

    /* Check supplementary group list */
    for (uint32_t i = 0; i < cr->cr_ngroups; i++) {
        if (cr->cr_groups[i] == gid)
            return true;
    }

    return false;
}

/* ============================================================================
 * VFS Permission Check
 *
 * Traditional UNIX access control: check owner/group/other permission
 * bits against the requesting credential.
 *
 *   mode_t layout (low 12 bits):
 *     bits 8-6: owner rwx
 *     bits 5-3: group rwx
 *     bits 2-0: other rwx
 *
 * The @mode parameter uses VREAD/VWRITE/VEXEC (4/2/1) matching the
 * low 3 bits of each permission triad.
 * ============================================================================ */

int vfs_access(struct vnode *vp, int mode, struct ucred *cr)
{
    if (vp == NULL || cr == NULL)
        return -EINVAL;

    /* Root bypasses all permission checks */
    if (cr->cr_uid == 0)
        return 0;

    mode_t file_mode = vp->v_mode;
    int granted;

    if (cr->cr_uid == vp->v_uid) {
        /* Owner: use bits 8-6 */
        granted = (int)((file_mode >> 6) & 0x7);
    } else if (groupmember(vp->v_gid, cr)) {
        /* Group member: use bits 5-3 */
        granted = (int)((file_mode >> 3) & 0x7);
    } else {
        /* Other: use bits 2-0 */
        granted = (int)(file_mode & 0x7);
    }

    /* Check that all requested bits are present */
    if ((mode & granted) == mode)
        return 0;

    return -EACCES;
}

/* ============================================================================
 * Privilege Check
 *
 * Currently: UID 0 (root) holds all privileges. This is the traditional
 * UNIX superuser model. Future versions may implement capabilities or
 * a more fine-grained privilege system (like macOS entitlements).
 * ============================================================================ */

int priv_check(struct ucred *cr, int priv)
{
    (void)priv;     /* All privs granted to root, ignored for now */

    if (cr == NULL)
        return -EACCES;

    if (cr->cr_uid == 0)
        return 0;

    return -EACCES;
}

/* ============================================================================
 * SUID/SGID Handling
 *
 * Called during execve after loading the executable. If the file has
 * the S_ISUID or S_ISGID bit set, the effective UID/GID of the process
 * is changed to the file's owner/group.
 *
 * The saved UID/GID is updated so the process can later restore the
 * original effective ID via setuid()/setgid().
 * ============================================================================ */

void suid_check(struct ucred *cr, mode_t mode, uid_t uid, gid_t gid)
{
    if (cr == NULL)
        return;

    if (mode & S_ISUID) {
        kprintf("[security] SUID: setting effective uid %u -> %u\n",
                cr->cr_uid, uid);
        cr->cr_svuid = cr->cr_uid;  /* Save old effective UID */
        cr->cr_uid = uid;           /* Set new effective UID */
    }

    if (mode & S_ISGID) {
        kprintf("[security] SGID: setting effective gid %u -> %u\n",
                cr->cr_gid, gid);
        cr->cr_svgid = cr->cr_gid;  /* Save old effective GID */
        cr->cr_gid = gid;           /* Set new effective GID */
    }
}
