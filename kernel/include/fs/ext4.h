/*
 * Kiseki OS - Ext4 On-Disk Structures
 *
 * Byte-accurate definitions of the ext4 filesystem on-disk format,
 * per the ext4 specification (kernel.org/doc/html/latest/filesystems/ext4/).
 *
 * All multi-byte fields are little-endian on disk. On AArch64 (LE) we can
 * read them directly.  All structures are __packed.
 */

#ifndef _FS_EXT4_H
#define _FS_EXT4_H

#include <kiseki/types.h>

/* ============================================================================
 * Fundamental Constants
 * ============================================================================ */

#define EXT4_SUPER_MAGIC        0xEF53

/* Superblock is always at byte offset 1024 from start of partition */
#define EXT4_SUPERBLOCK_OFFSET  1024
#define EXT4_SUPERBLOCK_SIZE    1024

/* Special inode numbers */
#define EXT4_BAD_INO            1       /* Bad blocks inode */
#define EXT4_ROOT_INO           2       /* Root directory inode */
#define EXT4_USR_QUOTA_INO      3       /* User quota inode */
#define EXT4_GRP_QUOTA_INO      4       /* Group quota inode */
#define EXT4_BOOT_LOADER_INO    5       /* Boot loader inode */
#define EXT4_UNDEL_DIR_INO      6       /* Undelete directory inode */
#define EXT4_RESIZE_INO         7       /* Reserved group descriptors inode */
#define EXT4_JOURNAL_INO        8       /* Journal inode */
#define EXT4_EXCLUDE_INO        9       /* Snapshot exclusion inode */
#define EXT4_REPLICA_INO        10      /* Snapshot replica inode */

/* Directory entry file type values (ext4_dir_entry_2.file_type) */
#define EXT4_FT_UNKNOWN         0
#define EXT4_FT_REG_FILE        1
#define EXT4_FT_DIR             2
#define EXT4_FT_CHRDEV          3
#define EXT4_FT_BLKDEV          4
#define EXT4_FT_FIFO            5
#define EXT4_FT_SOCK            6
#define EXT4_FT_SYMLINK         7

/* Maximum filename length in a directory entry */
#define EXT4_NAME_LEN           255

/* ============================================================================
 * Inode Mode Bits (POSIX + ext4 compatible)
 * ============================================================================ */

/* File type mask and values */
#define EXT4_S_IFMT     0xF000  /* File type mask */
#define EXT4_S_IFSOCK   0xC000  /* Socket */
#define EXT4_S_IFLNK    0xA000  /* Symbolic link */
#define EXT4_S_IFREG    0x8000  /* Regular file */
#define EXT4_S_IFBLK    0x6000  /* Block device */
#define EXT4_S_IFDIR    0x4000  /* Directory */
#define EXT4_S_IFCHR    0x2000  /* Character device */
#define EXT4_S_IFIFO    0x1000  /* FIFO */

/* Setuid / setgid / sticky */
#define EXT4_S_ISUID    0x0800  /* Set-user-ID on execution */
#define EXT4_S_ISGID    0x0400  /* Set-group-ID on execution */
#define EXT4_S_ISVTX    0x0200  /* Sticky bit */

/* Owner permissions */
#define EXT4_S_IRUSR    0x0100  /* Owner: read */
#define EXT4_S_IWUSR    0x0080  /* Owner: write */
#define EXT4_S_IXUSR    0x0040  /* Owner: execute */

/* Group permissions */
#define EXT4_S_IRGRP    0x0020  /* Group: read */
#define EXT4_S_IWGRP    0x0010  /* Group: write */
#define EXT4_S_IXGRP    0x0008  /* Group: execute */

/* Others permissions */
#define EXT4_S_IROTH    0x0004  /* Others: read */
#define EXT4_S_IWOTH    0x0002  /* Others: write */
#define EXT4_S_IXOTH    0x0001  /* Others: execute */

/* Type test macros */
#define EXT4_S_ISREG(m)  (((m) & EXT4_S_IFMT) == EXT4_S_IFREG)
#define EXT4_S_ISDIR(m)  (((m) & EXT4_S_IFMT) == EXT4_S_IFDIR)
#define EXT4_S_ISLNK(m)  (((m) & EXT4_S_IFMT) == EXT4_S_IFLNK)
#define EXT4_S_ISBLK(m)  (((m) & EXT4_S_IFMT) == EXT4_S_IFBLK)
#define EXT4_S_ISCHR(m)  (((m) & EXT4_S_IFMT) == EXT4_S_IFCHR)
#define EXT4_S_ISFIFO(m) (((m) & EXT4_S_IFMT) == EXT4_S_IFIFO)
#define EXT4_S_ISSOCK(m) (((m) & EXT4_S_IFMT) == EXT4_S_IFSOCK)

/* ============================================================================
 * Inode Flags (i_flags)
 * ============================================================================ */

#define EXT4_SECRM_FL           0x00000001  /* Secure deletion */
#define EXT4_UNRM_FL            0x00000002  /* Undelete */
#define EXT4_COMPR_FL           0x00000004  /* Compress file */
#define EXT4_SYNC_FL            0x00000008  /* Synchronous updates */
#define EXT4_IMMUTABLE_FL       0x00000010  /* Immutable file */
#define EXT4_APPEND_FL          0x00000020  /* Append-only writes */
#define EXT4_NODUMP_FL          0x00000040  /* Do not dump */
#define EXT4_NOATIME_FL         0x00000080  /* Do not update atime */
#define EXT4_DIRTY_FL           0x00000100  /* Dirty (compressed) */
#define EXT4_COMPRBLK_FL        0x00000200  /* Compressed blocks */
#define EXT4_NOCOMPR_FL         0x00000400  /* Access raw compressed data */
#define EXT4_ENCRYPT_FL         0x00000800  /* Encrypted inode */
#define EXT4_INDEX_FL           0x00001000  /* Hash-indexed directory */
#define EXT4_IMAGIC_FL          0x00002000  /* AFS directory */
#define EXT4_JOURNAL_DATA_FL    0x00004000  /* Journal file data */
#define EXT4_NOTAIL_FL          0x00008000  /* File tail not merged */
#define EXT4_DIRSYNC_FL         0x00010000  /* Dirsync behaviour */
#define EXT4_TOPDIR_FL          0x00020000  /* Top of directory hierarchies */
#define EXT4_HUGE_FILE_FL       0x00040000  /* Set for huge files */
#define EXT4_EXTENTS_FL         0x00080000  /* Inode uses extents */
#define EXT4_VERITY_FL          0x00100000  /* Verity protected inode */
#define EXT4_EA_INODE_FL        0x00200000  /* Inode stores large xattr */
#define EXT4_INLINE_DATA_FL     0x10000000  /* Inode has inline data */
#define EXT4_PROJINHERIT_FL     0x20000000  /* Project hierarchy */
#define EXT4_RESERVED_FL        0x80000000  /* Reserved */

/* ============================================================================
 * Feature Flags
 * ============================================================================ */

/* Compatible features - mount OK even if kernel doesn't understand */
#define EXT4_FEATURE_COMPAT_DIR_PREALLOC    0x0001
#define EXT4_FEATURE_COMPAT_IMAGIC_INODES   0x0002
#define EXT4_FEATURE_COMPAT_HAS_JOURNAL     0x0004
#define EXT4_FEATURE_COMPAT_EXT_ATTR        0x0008
#define EXT4_FEATURE_COMPAT_RESIZE_INODE    0x0010
#define EXT4_FEATURE_COMPAT_DIR_INDEX       0x0020
#define EXT4_FEATURE_COMPAT_SPARSE_SUPER2   0x0200

/* Incompatible features - must understand these to mount */
#define EXT4_FEATURE_INCOMPAT_COMPRESSION   0x0001
#define EXT4_FEATURE_INCOMPAT_FILETYPE      0x0002
#define EXT4_FEATURE_INCOMPAT_RECOVER       0x0004
#define EXT4_FEATURE_INCOMPAT_JOURNAL_DEV   0x0008
#define EXT4_FEATURE_INCOMPAT_META_BG       0x0010
#define EXT4_FEATURE_INCOMPAT_EXTENTS       0x0040
#define EXT4_FEATURE_INCOMPAT_64BIT         0x0080
#define EXT4_FEATURE_INCOMPAT_MMP           0x0100
#define EXT4_FEATURE_INCOMPAT_FLEX_BG       0x0200
#define EXT4_FEATURE_INCOMPAT_EA_INODE      0x0400
#define EXT4_FEATURE_INCOMPAT_DIRDATA       0x1000
#define EXT4_FEATURE_INCOMPAT_CSUM_SEED     0x2000
#define EXT4_FEATURE_INCOMPAT_LARGEDIR      0x4000
#define EXT4_FEATURE_INCOMPAT_INLINE_DATA   0x8000
#define EXT4_FEATURE_INCOMPAT_ENCRYPT       0x10000

/* Read-only compatible features - mount read-only if not understood */
#define EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER     0x0001
#define EXT4_FEATURE_RO_COMPAT_LARGE_FILE       0x0002
#define EXT4_FEATURE_RO_COMPAT_BTREE_DIR        0x0004
#define EXT4_FEATURE_RO_COMPAT_HUGE_FILE        0x0008
#define EXT4_FEATURE_RO_COMPAT_GDT_CSUM         0x0010
#define EXT4_FEATURE_RO_COMPAT_DIR_NLINK        0x0020
#define EXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE      0x0040
#define EXT4_FEATURE_RO_COMPAT_QUOTA            0x0100
#define EXT4_FEATURE_RO_COMPAT_BIGALLOC         0x0200
#define EXT4_FEATURE_RO_COMPAT_METADATA_CSUM    0x0400
#define EXT4_FEATURE_RO_COMPAT_READONLY         0x1000
#define EXT4_FEATURE_RO_COMPAT_PROJECT          0x2000

/* ============================================================================
 * Superblock (struct ext4_super_block) - 1024 bytes at offset 1024
 *
 * Fields are in on-disk byte order (little-endian).
 * ============================================================================ */

struct ext4_super_block {
    /* 0x000 */
    uint32_t    s_inodes_count;         /* Total inode count */
    uint32_t    s_blocks_count_lo;      /* Total block count (low 32 bits) */
    uint32_t    s_r_blocks_count_lo;    /* Reserved block count (low 32) */
    uint32_t    s_free_blocks_count_lo; /* Free block count (low 32) */
    /* 0x010 */
    uint32_t    s_free_inodes_count;    /* Free inode count */
    uint32_t    s_first_data_block;     /* First data block (0 or 1) */
    uint32_t    s_log_block_size;       /* Block size = 1024 << s_log_block_size */
    uint32_t    s_log_cluster_size;     /* Cluster size (if bigalloc) */
    /* 0x020 */
    uint32_t    s_blocks_per_group;     /* Blocks per block group */
    uint32_t    s_clusters_per_group;   /* Clusters per group (if bigalloc) */
    uint32_t    s_inodes_per_group;     /* Inodes per block group */
    uint32_t    s_mtime;                /* Last mount time */
    /* 0x030 */
    uint32_t    s_wtime;                /* Last write time */
    uint16_t    s_mnt_count;            /* Mount count since last fsck */
    uint16_t    s_max_mnt_count;        /* Max mounts before fsck */
    uint16_t    s_magic;                /* Magic number (0xEF53) */
    uint16_t    s_state;                /* Filesystem state */
    uint16_t    s_errors;               /* Behaviour when errors detected */
    uint16_t    s_minor_rev_level;      /* Minor revision level */
    /* 0x040 */
    uint32_t    s_lastcheck;            /* Time of last fsck */
    uint32_t    s_checkinterval;        /* Max time between fscks */
    uint32_t    s_creator_os;           /* OS that created FS */
    uint32_t    s_rev_level;            /* Revision level (0 or 1) */
    /* 0x050 */
    uint16_t    s_def_resuid;           /* Default uid for reserved blocks */
    uint16_t    s_def_resgid;           /* Default gid for reserved blocks */

    /*
     * EXT4_DYNAMIC_REV (rev_level >= 1) superblock fields
     */
    /* 0x054 */
    uint32_t    s_first_ino;            /* First non-reserved inode */
    uint16_t    s_inode_size;           /* Size of inode structure (bytes) */
    uint16_t    s_block_group_nr;       /* Block group # of this superblock */
    uint32_t    s_feature_compat;       /* Compatible feature set */
    /* 0x060 */
    uint32_t    s_feature_incompat;     /* Incompatible feature set */
    uint32_t    s_feature_ro_compat;    /* Read-only compatible feature set */
    /* 0x068 */
    uint8_t     s_uuid[16];             /* 128-bit filesystem UUID */
    /* 0x078 */
    char        s_volume_name[16];      /* Volume label */
    /* 0x088 */
    char        s_last_mounted[64];     /* Directory where last mounted */
    /* 0x0C8 */
    uint32_t    s_algorithm_usage_bitmap; /* For compression */

    /*
     * Performance hints
     */
    /* 0x0CC */
    uint8_t     s_prealloc_blocks;      /* Blocks to preallocate for files */
    uint8_t     s_prealloc_dir_blocks;  /* Blocks to preallocate for dirs */
    uint16_t    s_reserved_gdt_blocks;  /* Reserved GDT blocks for resize */

    /*
     * Journal fields
     */
    /* 0x0D0 */
    uint8_t     s_journal_uuid[16];     /* Journal superblock UUID */
    /* 0x0E0 */
    uint32_t    s_journal_inum;         /* Journal inode number */
    uint32_t    s_journal_dev;          /* Journal device number */
    uint32_t    s_last_orphan;          /* Head of orphan inode list */
    /* 0x0EC */
    uint32_t    s_hash_seed[4];         /* HTREE hash seed */
    /* 0x0FC */
    uint8_t     s_def_hash_version;     /* Default hash algorithm */
    uint8_t     s_jnl_backup_type;      /* Journal backup type */
    uint16_t    s_desc_size;            /* Group descriptor size */
    /* 0x100 */
    uint32_t    s_default_mount_opts;   /* Default mount options */
    uint32_t    s_first_meta_bg;        /* First metablock group */
    uint32_t    s_mkfs_time;            /* Filesystem creation time */
    /* 0x10C */
    uint32_t    s_jnl_blocks[17];       /* Backup of journal inode */

    /*
     * 64-bit support (if INCOMPAT_64BIT)
     */
    /* 0x150 */
    uint32_t    s_blocks_count_hi;      /* Total block count (high 32 bits) */
    uint32_t    s_r_blocks_count_hi;    /* Reserved blocks (high 32) */
    uint32_t    s_free_blocks_count_hi; /* Free blocks (high 32) */
    uint16_t    s_min_extra_isize;      /* All inodes have at least this */
    uint16_t    s_want_extra_isize;     /* New inodes should reserve this */
    /* 0x160 */
    uint32_t    s_flags;                /* Miscellaneous flags */
    uint16_t    s_raid_stride;          /* RAID stride in blocks */
    uint16_t    s_mmp_interval;         /* MMP check wait (seconds) */
    uint64_t    s_mmp_block;            /* Block for MMP data */
    /* 0x170 */
    uint32_t    s_raid_stripe_width;    /* Blocks on all data disks (RAID) */
    uint8_t     s_log_groups_per_flex;  /* FLEX_BG group size */
    uint8_t     s_checksum_type;        /* Metadata checksum algorithm */
    uint16_t    s_reserved_pad;
    /* 0x178 */
    uint64_t    s_kbytes_written;       /* KB written to FS lifetime */
    /* 0x180 */
    uint32_t    s_snapshot_inum;        /* Active snapshot inode */
    uint32_t    s_snapshot_id;          /* Active snapshot sequential ID */
    uint64_t    s_snapshot_r_blocks_count; /* Reserved blocks for snapshot */
    /* 0x190 */
    uint32_t    s_snapshot_list;        /* Head of snapshot list inode */
    uint32_t    s_error_count;          /* Number of errors seen */
    uint32_t    s_first_error_time;     /* Time of first error */
    uint32_t    s_first_error_ino;      /* Inode involved in first error */
    /* 0x1A0 */
    uint64_t    s_first_error_block;    /* Block involved in first error */
    uint8_t     s_first_error_func[32]; /* Function where error happened */
    /* 0x1C8 */
    uint32_t    s_first_error_line;     /* Line number of first error */
    uint32_t    s_last_error_time;      /* Time of most recent error */
    /* 0x1D0 */
    uint32_t    s_last_error_ino;       /* Inode in most recent error */
    uint32_t    s_last_error_line;      /* Line number of most recent error */
    uint64_t    s_last_error_block;     /* Block in most recent error */
    /* 0x1E0 */
    uint8_t     s_last_error_func[32];  /* Function of most recent error */
    /* 0x200 */
    uint8_t     s_mount_opts[64];       /* ASCIIZ string of mount options */
    /* 0x240 */
    uint32_t    s_usr_quota_inum;       /* Inode for tracking user quota */
    uint32_t    s_grp_quota_inum;       /* Inode for tracking group quota */
    uint32_t    s_overhead_blocks;      /* Overhead blocks in FS */
    uint32_t    s_backup_bgs[2];        /* Groups with sparse_super2 SBs */
    /* 0x254 */
    uint8_t     s_encrypt_algos[4];     /* Encryption algorithms in use */
    uint8_t     s_encrypt_pw_salt[16];  /* Salt for string2key algorithm */
    /* 0x268 */
    uint32_t    s_lpf_ino;             /* Lost+found inode number */
    uint32_t    s_prj_quota_inum;      /* Inode for tracking project quota */
    /* 0x270 */
    uint32_t    s_checksum_seed;       /* crc32c(uuid) if CSUM_SEED set */
    /* 0x274 */
    uint8_t     s_wtime_hi;
    uint8_t     s_mtime_hi;
    uint8_t     s_mkfs_time_hi;
    uint8_t     s_lastcheck_hi;
    uint8_t     s_first_error_time_hi;
    uint8_t     s_last_error_time_hi;
    uint8_t     s_pad[2];
    /* 0x27C */
    uint16_t    s_encoding;            /* Filename charset encoding */
    uint16_t    s_encoding_flags;      /* Filename charset encoding flags */
    uint32_t    s_orphan_file_inum;    /* Orphan file inode number */
    /* 0x284 */
    uint32_t    s_reserved[94];        /* Padding to end of block */
    /* 0x3FC */
    uint32_t    s_checksum;            /* crc32c(superblock) */
} __packed;

/* ============================================================================
 * Block Group Descriptor (struct ext4_group_desc)
 *
 * 32 bytes for non-64bit FS, 64 bytes for 64bit FS (s_desc_size >= 64)
 * ============================================================================ */

struct ext4_group_desc {
    /* 0x00 */
    uint32_t    bg_block_bitmap_lo;     /* Block bitmap block (low 32) */
    uint32_t    bg_inode_bitmap_lo;     /* Inode bitmap block (low 32) */
    uint32_t    bg_inode_table_lo;      /* Inode table start block (low 32) */
    uint16_t    bg_free_blocks_count_lo;/* Free blocks count (low 16) */
    uint16_t    bg_free_inodes_count_lo;/* Free inodes count (low 16) */
    uint16_t    bg_used_dirs_count_lo;  /* Directories count (low 16) */
    uint16_t    bg_flags;               /* EXT4_BG_* flags */
    uint32_t    bg_exclude_bitmap_lo;   /* Snapshot exclusion bitmap (low 32) */
    uint16_t    bg_block_bitmap_csum_lo;/* Block bitmap checksum (low 16) */
    uint16_t    bg_inode_bitmap_csum_lo;/* Inode bitmap checksum (low 16) */
    uint16_t    bg_itable_unused_lo;    /* Unused inodes count (low 16) */
    uint16_t    bg_checksum;            /* crc16(s_uuid+group+desc) */

    /* 64-bit fields (only if s_desc_size >= 64 && INCOMPAT_64BIT) */
    /* 0x20 */
    uint32_t    bg_block_bitmap_hi;     /* Block bitmap block (high 32) */
    uint32_t    bg_inode_bitmap_hi;     /* Inode bitmap block (high 32) */
    uint32_t    bg_inode_table_hi;      /* Inode table start block (high 32) */
    uint16_t    bg_free_blocks_count_hi;/* Free blocks count (high 16) */
    uint16_t    bg_free_inodes_count_hi;/* Free inodes count (high 16) */
    uint16_t    bg_used_dirs_count_hi;  /* Directories count (high 16) */
    uint16_t    bg_itable_unused_hi;    /* Unused inodes count (high 16) */
    uint32_t    bg_exclude_bitmap_hi;   /* Snapshot exclusion bitmap (high) */
    uint16_t    bg_block_bitmap_csum_hi;/* Block bitmap checksum (high 16) */
    uint16_t    bg_inode_bitmap_csum_hi;/* Inode bitmap checksum (high 16) */
    uint32_t    bg_reserved;
} __packed;

/* ============================================================================
 * Inode (struct ext4_inode) - typically 128 or 256 bytes on disk
 *
 * The i_block[60] region is reused for:
 *   - Direct/indirect block pointers (ext2/ext3 compat)
 *   - Extent tree (if EXTENTS_FL is set)
 *   - Inline data (if INLINE_DATA_FL is set)
 * ============================================================================ */

#define EXT4_NDIR_BLOCKS        12
#define EXT4_IND_BLOCK          EXT4_NDIR_BLOCKS        /* 12 */
#define EXT4_DIND_BLOCK         (EXT4_IND_BLOCK + 1)    /* 13 */
#define EXT4_TIND_BLOCK         (EXT4_DIND_BLOCK + 1)   /* 14 */
#define EXT4_N_BLOCKS           (EXT4_TIND_BLOCK + 1)   /* 15 */

struct ext4_inode {
    /* 0x00 */
    uint16_t    i_mode;             /* File mode (type + permissions) */
    uint16_t    i_uid;              /* Owner uid (low 16 bits) */
    uint32_t    i_size_lo;          /* Size in bytes (low 32 bits) */
    uint32_t    i_atime;            /* Last access time */
    uint32_t    i_ctime;            /* Inode change time */
    /* 0x10 */
    uint32_t    i_mtime;            /* Last modification time */
    uint32_t    i_dtime;            /* Deletion time */
    uint16_t    i_gid;              /* Group id (low 16 bits) */
    uint16_t    i_links_count;      /* Hard links count */
    uint32_t    i_blocks_lo;        /* Blocks count (in 512-byte units) */
    /* 0x20 */
    uint32_t    i_flags;            /* File flags (EXT4_*_FL) */
    union {
        struct {
            uint32_t l_i_version;   /* Inode version (Linux) */
        } linux1;
        struct {
            uint32_t h_i_translator;
        } hurd1;
        struct {
            uint32_t m_i_reserved1;
        } masix1;
    } osd1;                         /* OS-dependent value 1 */
    /* 0x28 */
    uint32_t    i_block[EXT4_N_BLOCKS]; /* Block map or extent tree (60 bytes) */
    /* 0x64 */
    uint32_t    i_generation;       /* File version (for NFS) */
    uint32_t    i_file_acl_lo;      /* Extended attribute block (low 32) */
    uint32_t    i_size_high;        /* File size high 32 bits (reg files) */
    /* 0x70 */
    uint32_t    i_obso_faddr;       /* Obsoleted fragment address */
    union {
        struct {
            uint16_t l_i_blocks_high;   /* Blocks count high bits */
            uint16_t l_i_file_acl_high; /* File ACL high bits */
            uint16_t l_i_uid_high;      /* Owner uid high 16 bits */
            uint16_t l_i_gid_high;      /* Group id high 16 bits */
            uint16_t l_i_checksum_lo;   /* crc32c(uuid+inum+inode) low */
            uint16_t l_i_reserved;
        } linux2;
        struct {
            uint16_t h_i_reserved1;
            uint16_t h_i_mode_high;
            uint16_t h_i_uid_high;
            uint16_t h_i_gid_high;
            uint32_t h_i_author;
        } hurd2;
        struct {
            uint16_t h_i_reserved1;
            uint16_t m_i_file_acl_high;
            uint32_t m_i_reserved2[2];
        } masix2;
    } osd2;                         /* OS-dependent value 2 */
    /* 0x80 */
    uint16_t    i_extra_isize;      /* Size of extra inode fields */
    uint16_t    i_checksum_hi;      /* crc32c(uuid+inum+inode) high */
    uint32_t    i_ctime_extra;      /* Extra change time (nsec << 2 | epoch) */
    uint32_t    i_mtime_extra;      /* Extra modification time */
    uint32_t    i_atime_extra;      /* Extra access time */
    /* 0x90 */
    uint32_t    i_crtime;           /* File creation time */
    uint32_t    i_crtime_extra;     /* Extra file creation time */
    uint32_t    i_version_hi;       /* Inode version high 32 bits */
    uint32_t    i_projid;           /* Project ID */
} __packed;

/* ============================================================================
 * Extent Tree Structures
 *
 * Stored in the i_block[15] area (60 bytes) of the inode.
 * The header is followed by either ext4_extent (leaf) or
 * ext4_extent_idx (internal node) entries.
 *
 * Layout:  [ext4_extent_header][entries...]
 * ============================================================================ */

/* Extent tree magic number (in eh_magic) */
#define EXT4_EXT_MAGIC  0xF30A

struct ext4_extent_header {
    uint16_t    eh_magic;       /* Magic (0xF30A) */
    uint16_t    eh_entries;     /* Number of valid entries following */
    uint16_t    eh_max;         /* Capacity of entries */
    uint16_t    eh_depth;       /* Depth: 0 = leaf (extents), >0 = index */
    uint32_t    eh_generation;  /* Tree generation (for COW) */
} __packed;

/*
 * ext4_extent_idx - Internal node entry (eh_depth > 0)
 *
 * Points to a child node block.
 */
struct ext4_extent_idx {
    uint32_t    ei_block;       /* Logical block this index covers */
    uint32_t    ei_leaf_lo;     /* Physical block of child node (low 32) */
    uint16_t    ei_leaf_hi;     /* Physical block of child node (high 16) */
    uint16_t    ei_unused;
} __packed;

/*
 * ext4_extent - Leaf node entry (eh_depth == 0)
 *
 * Maps a contiguous range of logical blocks to physical blocks.
 */
struct ext4_extent {
    uint32_t    ee_block;       /* First logical block this extent covers */
    uint16_t    ee_len;         /* Number of blocks covered */
    uint16_t    ee_start_hi;    /* Physical block (high 16 bits) */
    uint32_t    ee_start_lo;    /* Physical block (low 32 bits) */
} __packed;

/* Maximum uninitialized extent length (bit 15 set means uninitialized) */
#define EXT4_EXT_INIT_MAX_LEN   32768
#define EXT4_EXT_IS_UNWRITTEN(ext) ((ext)->ee_len > EXT4_EXT_INIT_MAX_LEN)
#define EXT4_EXT_GET_LEN(ext) \
    ((ext)->ee_len <= EXT4_EXT_INIT_MAX_LEN ? \
     (ext)->ee_len : ((ext)->ee_len - EXT4_EXT_INIT_MAX_LEN))

/* Helper to get full 48-bit physical block from extent */
#define EXT4_EXTENT_PBLOCK(ext) \
    ((uint64_t)(ext)->ee_start_lo | ((uint64_t)(ext)->ee_start_hi << 32))

/* Helper to get full 48-bit physical block from index */
#define EXT4_IDX_PBLOCK(idx) \
    ((uint64_t)(idx)->ei_leaf_lo | ((uint64_t)(idx)->ei_leaf_hi << 32))

/* ============================================================================
 * Directory Entry (struct ext4_dir_entry_2)
 *
 * Variable-length, 4-byte aligned. rec_len covers padding.
 * ============================================================================ */

struct ext4_dir_entry_2 {
    uint32_t    inode;          /* Inode number (0 = deleted entry) */
    uint16_t    rec_len;        /* Record length (to next entry) */
    uint8_t     name_len;       /* Filename length */
    uint8_t     file_type;      /* EXT4_FT_* type */
    char        name[];         /* Filename (NOT NUL-terminated on disk) */
} __packed;

/* Minimum directory entry size: header (8 bytes) + 1 byte name, rounded up */
#define EXT4_DIR_ENTRY_MIN_SIZE     12  /* 8 + 4-byte alignment */

/* Actual size needed for a name of length n */
#define EXT4_DIR_REC_LEN(namelen) \
    (((8 + (namelen)) + 3) & ~3)

/* ============================================================================
 * Ext4 Driver API (implemented in kernel/fs/ext4/ext4.c)
 * ============================================================================ */

/*
 * ext4_fs_init - Register ext4 filesystem with VFS.
 *
 * Call once during kernel startup, after vfs_init().
 */
void ext4_fs_init(void);

#endif /* _FS_EXT4_H */
