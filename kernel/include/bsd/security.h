/*
 * Kiseki OS - BSD Security Subsystem
 *
 * User credentials, privilege checks, and permission enforcement.
 * Implements UNIX DAC (Discretionary Access Control) model:
 *   - Reference-counted ucred with real/effective/saved UIDs and GIDs
 *   - VFS permission checks (owner/group/other)
 *   - Privilege escalation via SUID/SGID
 *   - Root (UID 0) bypass for privileged operations
 *
 * Reference: XNU bsd/sys/ucred.h, FreeBSD sys/ucred.h
 */

#ifndef _BSD_SECURITY_H
#define _BSD_SECURITY_H

#include <kiseki/types.h>

/* ============================================================================
 * Constants
 * ============================================================================ */

/* Maximum supplementary groups per credential */
#define NGROUPS_MAX     16

/* Privilege constants for priv_check() */
#define PRIV_ROOT       0       /* Generic root privilege */
#define PRIV_NET_RAW    1       /* Create raw sockets */
#define PRIV_VFS_MOUNT  2       /* Mount filesystems */
#define PRIV_PROC_SIGNAL 3      /* Signal arbitrary processes */
#define PRIV_KERN_SYSCTL 4      /* Modify sysctl values */

/* Access mode bits for vfs_access() (match POSIX) */
#define VREAD           0x04    /* Read permission */
#define VWRITE          0x02    /* Write permission */
#define VEXEC           0x01    /* Execute/search permission */

/* Mode bits for SUID/SGID */
#define S_ISUID         0004000 /* Set-user-ID on execution */
#define S_ISGID         0002000 /* Set-group-ID on execution */
#define S_ISVTX         0001000 /* Sticky bit */

/* Permission bits (standard POSIX) */
#define S_IRWXU         0000700 /* Owner: rwx */
#define S_IRUSR         0000400 /* Owner: read */
#define S_IWUSR         0000200 /* Owner: write */
#define S_IXUSR         0000100 /* Owner: execute */

#define S_IRWXG         0000070 /* Group: rwx */
#define S_IRGRP         0000040 /* Group: read */
#define S_IWGRP         0000020 /* Group: write */
#define S_IXGRP         0000010 /* Group: execute */

#define S_IRWXO         0000007 /* Other: rwx */
#define S_IROTH         0000004 /* Other: read */
#define S_IWOTH         0000002 /* Other: write */
#define S_IXOTH         0000001 /* Other: execute */

/* ============================================================================
 * User Credentials (ucred)
 *
 * Reference-counted credential structure. Shared by processes after
 * fork until one of them changes credentials (copy-on-write semantics).
 * ============================================================================ */

struct vnode;   /* Forward declaration */

struct ucred {
    uid_t       cr_uid;                 /* Effective user ID */
    gid_t       cr_gid;                 /* Effective group ID */
    uid_t       cr_ruid;                /* Real user ID */
    gid_t       cr_rgid;                /* Real group ID */
    uid_t       cr_svuid;               /* Saved user ID */
    gid_t       cr_svgid;               /* Saved group ID */
    gid_t       cr_groups[NGROUPS_MAX]; /* Supplementary group list */
    uint32_t    cr_ngroups;             /* Number of supplementary groups */
    uint32_t    cr_ref;                 /* Reference count */
};

/* ============================================================================
 * Credential Management API
 * ============================================================================ */

/*
 * ucred_create - Allocate and initialize a new credential
 *
 * @uid:  Effective/real/saved UID
 * @gid:  Effective/real/saved GID
 *
 * Creates a credential with all three UID/GID fields set to the same
 * value and an empty supplementary group list. Reference count = 1.
 *
 * Returns a new ucred, or NULL on allocation failure.
 */
struct ucred *ucred_create(uid_t uid, gid_t gid);

/*
 * ucred_ref - Increment credential reference count.
 *
 * @cr: Credential to reference.
 */
void ucred_ref(struct ucred *cr);

/*
 * ucred_release - Decrement credential reference count.
 *
 * If the reference count drops to zero, the credential is freed.
 *
 * @cr: Credential to release.
 */
void ucred_release(struct ucred *cr);

/* ============================================================================
 * Permission Check API
 * ============================================================================ */

/*
 * vfs_access - Check file permission bits against a credential
 *
 * @vp:   Vnode to check (uses v_uid, v_gid, v_mode)
 * @mode: Desired access (VREAD, VWRITE, VEXEC, or combination)
 * @cr:   Credential of the requesting process
 *
 * Checks owner/group/other permission bits in the traditional UNIX
 * manner. Root (UID 0) bypasses all permission checks.
 *
 * Returns 0 if access is granted, -EACCES if denied.
 */
int vfs_access(struct vnode *vp, int mode, struct ucred *cr);

/*
 * priv_check - Check if a credential holds a given privilege
 *
 * @cr:   Credential to check
 * @priv: Privilege constant (PRIV_ROOT, PRIV_NET_RAW, etc.)
 *
 * Currently, UID 0 holds all privileges. Future: capability-based.
 *
 * Returns 0 if privileged, -EACCES if not.
 */
int priv_check(struct ucred *cr, int priv);

/*
 * groupmember - Check if a credential is a member of a group
 *
 * @gid: Group ID to check
 * @cr:  Credential to check against
 *
 * Checks both the effective GID and the supplementary group list.
 *
 * Returns true if the credential is a member, false otherwise.
 */
bool groupmember(gid_t gid, struct ucred *cr);

/* ============================================================================
 * SUID/SGID Helpers
 * ============================================================================ */

/*
 * suid_check - Apply SUID/SGID bits during execve
 *
 * @cr:   Credential to modify (should be a fresh copy)
 * @mode: File mode bits of the executable (from vnode v_mode)
 * @uid:  Owner UID of the executable (from vnode v_uid)
 * @gid:  Owner GID of the executable (from vnode v_gid)
 *
 * If S_ISUID is set, changes cr_uid (effective UID) to @uid.
 * If S_ISGID is set, changes cr_gid (effective GID) to @gid.
 * Saved UID/GID are updated to match the new effective values.
 */
void suid_check(struct ucred *cr, mode_t mode, uid_t uid, gid_t gid);

/* ============================================================================
 * Security Subsystem Initialization
 * ============================================================================ */

/*
 * security_init - Initialize the security subsystem
 *
 * Sets up the credential allocator. Called once during kernel startup.
 */
void security_init(void);

#endif /* _BSD_SECURITY_H */
