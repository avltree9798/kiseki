/*
 * Kiseki OS - Ext4 Filesystem Driver
 *
 * Read-write ext4 implementation supporting:
 *   - Extent-based file layout (single-level and multi-level trees) [read]
 *   - Direct block mapping (i_block[0..11]) [write, new files]
 *   - Linear directory iteration (ext4_dir_entry_2)
 *   - 64-bit block addressing (INCOMPAT_64BIT)
 *   - Large inodes (s_inode_size > 128)
 *   - Block/inode allocation via bitmap
 *   - File creation, writing, mkdir, unlink, setattr
 *
 * All disk I/O goes through the buffer cache (buf_read / buf_write).
 */

#include <kiseki/types.h>
#include <kern/kprintf.h>
#include <kern/sync.h>
#include <fs/vfs.h>
#include <fs/ext4.h>
#include <fs/buf.h>

/* ============================================================================
 * Internal Ext4 State
 * ============================================================================ */

/*
 * Per-mount ext4 private data, stored in mount->mnt_data.
 */
struct ext4_mount_info {
    struct ext4_super_block sb;         /* In-memory superblock copy */
    uint32_t    block_size;             /* Filesystem block size (bytes) */
    uint32_t    block_size_shift;       /* log2(block_size) */
    uint32_t    inodes_per_group;       /* Inodes per block group */
    uint32_t    blocks_per_group;       /* Blocks per block group */
    uint32_t    inode_size;             /* On-disk inode size */
    uint32_t    group_count;            /* Number of block groups */
    uint32_t    desc_size;              /* Group descriptor size */
    uint32_t    dev;                    /* Block device number */
    uint64_t    first_data_block;       /* First data block (0 or 1) */

    /*
     * Group descriptor table (read into memory at mount time).
     * We store raw bytes; each descriptor is desc_size bytes.
     */
    uint8_t    *group_descs;
    uint32_t    gd_buf_size;            /* Total bytes for group desc table */
};

/*
 * Per-vnode ext4 private data, stored in vnode->v_data.
 */
struct ext4_vnode_data {
    struct ext4_inode   inode;          /* On-disk inode (copy) */
    uint64_t            ino;            /* Inode number */
    struct ext4_mount_info *mi;         /* Back-pointer to mount info */
};

/* Pool for vnode-private data */
#define EXT4_MAX_VNODES 1024
static struct ext4_vnode_data ext4_vdata_pool[EXT4_MAX_VNODES];
static spinlock_t ext4_vdata_lock = SPINLOCK_INIT;

/* Forward declarations — read ops */
static int ext4_vop_lookup(struct vnode *dir, const char *name,
                           uint32_t namelen, struct vnode **result);
static int64_t ext4_vop_read(struct vnode *vp, void *buf, uint64_t offset,
                             uint64_t count);
static int ext4_vop_readdir(struct vnode *dir, struct dirent *buf,
                            uint64_t *offsetp, uint32_t count);
static int ext4_vop_getattr(struct vnode *vp, struct stat *st);

/* Forward declarations — write ops */
static int ext4_vop_create(struct vnode *dir, const char *name,
                           uint32_t namelen, mode_t mode,
                           struct vnode **result);
static int64_t ext4_vop_write(struct vnode *vp, const void *buf,
                              uint64_t offset, uint64_t count);
static int ext4_vop_mkdir(struct vnode *dir, const char *name,
                          uint32_t namelen, mode_t mode,
                          struct vnode **result);
static int ext4_vop_unlink(struct vnode *dir, const char *name,
                           uint32_t namelen);
static int ext4_vop_setattr(struct vnode *vp, struct stat *st);
static int ext4_vop_readlink(struct vnode *vp, char *buf, uint64_t buflen);

/* Forward declarations — needed by write helpers before definition */
static uint64_t ext4_inode_size(struct ext4_inode *ip);
static uint64_t ext4_group_block_bitmap(struct ext4_mount_info *mi, uint32_t group);
static struct ext4_group_desc *ext4_get_group_desc(struct ext4_mount_info *mi, uint32_t group);
static int ext4_write_group_desc(struct ext4_mount_info *mi, uint32_t group);
static uint64_t ext4_alloc_block(struct ext4_mount_info *mi, uint32_t pref_group);
static int ext4_write_fs_block(struct ext4_mount_info *mi, uint64_t fs_block,
                               uint32_t offset, const void *src, uint32_t len);

static int ext4_fs_mount(struct mount *mp);
static int ext4_fs_unmount(struct mount *mp);
static int ext4_fs_sync(struct mount *mp);
static int ext4_fs_statfs(struct mount *mp, struct statfs *buf);

/* ============================================================================
 * Operations Tables
 * ============================================================================ */

static struct vnode_ops ext4_vnode_ops = {
    .lookup     = ext4_vop_lookup,
    .read       = ext4_vop_read,
    .write      = ext4_vop_write,
    .readdir    = ext4_vop_readdir,
    .create     = ext4_vop_create,
    .mkdir      = ext4_vop_mkdir,
    .unlink     = ext4_vop_unlink,
    .getattr    = ext4_vop_getattr,
    .setattr    = ext4_vop_setattr,
    .readlink   = ext4_vop_readlink,
};

static struct fs_ops ext4_fs_ops = {
    .mount      = ext4_fs_mount,
    .unmount    = ext4_fs_unmount,
    .sync       = ext4_fs_sync,
    .statfs     = ext4_fs_statfs,
};

/* ============================================================================
 * String Helpers (freestanding)
 * ============================================================================ */

static int
ext4_memcmp(const void *a, const void *b, uint32_t n)
{
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;
    for (uint32_t i = 0; i < n; i++) {
        if (pa[i] != pb[i])
            return pa[i] - pb[i];
    }
    return 0;
}

static void
ext4_memcpy(void *dst, const void *src, uint64_t n)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    for (uint64_t i = 0; i < n; i++)
        d[i] = s[i];
}

static void
ext4_memset(void *dst, uint8_t val, uint64_t n)
{
    uint8_t *d = (uint8_t *)dst;
    for (uint64_t i = 0; i < n; i++)
        d[i] = val;
}

/* ============================================================================
 * Vnode Data Pool
 * ============================================================================ */

static struct ext4_vnode_data *
ext4_vdata_alloc(void)
{
    spin_lock(&ext4_vdata_lock);
    for (uint32_t i = 0; i < EXT4_MAX_VNODES; i++) {
        if (ext4_vdata_pool[i].ino == 0) {
            ext4_memset(&ext4_vdata_pool[i], 0,
                        sizeof(struct ext4_vnode_data));
            ext4_vdata_pool[i].ino = (uint64_t)-1; /* mark as claimed */
            spin_unlock(&ext4_vdata_lock);
            return &ext4_vdata_pool[i];
        }
    }
    spin_unlock(&ext4_vdata_lock);
    kprintf("ext4: vdata pool exhausted\n");
    return NULL;
}

static void
ext4_vdata_free(struct ext4_vnode_data *vd)
{
    if (vd == NULL)
        return;
    spin_lock(&ext4_vdata_lock);
    vd->ino = 0;
    spin_unlock(&ext4_vdata_lock);
}

/* ============================================================================
 * Block Addressing Helpers
 * ============================================================================ */

/*
 * Convert a filesystem block number to a buffer-cache block number.
 *
 * The buffer cache uses BUF_BLOCK_SIZE (4096) byte blocks.
 * The ext4 filesystem may use 1024, 2048, 4096, or larger block sizes.
 *
 * For block_size <= 4096: multiple fs blocks may fit in one buf block.
 * For block_size == 4096: 1:1 mapping.
 * For block_size > 4096:  one fs block spans multiple buf blocks.
 */
static uint64_t __unused
ext4_fs_block_to_buf_block(struct ext4_mount_info *mi, uint64_t fs_block)
{
    if (mi->block_size <= BUF_BLOCK_SIZE) {
        /*
         * e.g. block_size=1024: fs_block N starts at byte N*1024,
         * which is in buf block (N*1024)/4096 = N/4.
         */
        return (fs_block * mi->block_size) / BUF_BLOCK_SIZE;
    } else {
        /* block_size > 4096: fs_block N starts at buf block N*(block_size/4096) */
        return fs_block * (mi->block_size / BUF_BLOCK_SIZE);
    }
}

/*
 * Byte offset within a buf block for a given filesystem block.
 */
static uint32_t __unused
ext4_fs_block_offset_in_buf(struct ext4_mount_info *mi, uint64_t fs_block)
{
    if (mi->block_size <= BUF_BLOCK_SIZE) {
        return (uint32_t)((fs_block * mi->block_size) % BUF_BLOCK_SIZE);
    }
    return 0; /* block_size >= 4096 means fs block is buf-aligned */
}

/*
 * Read bytes from a filesystem block into a buffer.
 * Handles the mapping from fs blocks to buf blocks.
 *
 * @mi:        Mount info
 * @fs_block:  Filesystem block number
 * @offset:    Byte offset within the fs block
 * @dst:       Destination buffer
 * @len:       Bytes to read
 *
 * Returns 0 on success, -EIO on failure.
 */
static int
ext4_read_fs_block(struct ext4_mount_info *mi, uint64_t fs_block,
                   uint32_t offset, void *dst, uint32_t len)
{
    uint64_t byte_offset = fs_block * mi->block_size + offset;
    uint8_t *out = (uint8_t *)dst;

    while (len > 0) {
        uint64_t buf_blk = byte_offset / BUF_BLOCK_SIZE;
        uint32_t buf_off = (uint32_t)(byte_offset % BUF_BLOCK_SIZE);
        uint32_t chunk = BUF_BLOCK_SIZE - buf_off;
        if (chunk > len)
            chunk = len;

        struct buf *bp = buf_read(mi->dev, buf_blk);
        if (bp == NULL)
            return -EIO;

        ext4_memcpy(out, bp->data + buf_off, chunk);
        buf_release(bp);

        out += chunk;
        byte_offset += chunk;
        len -= chunk;
    }

    return 0;
}

/* ============================================================================
 * Superblock & Group Descriptor Helpers
 * ============================================================================ */

/*
 * Get a group descriptor by group number.
 */
static struct ext4_group_desc *
ext4_get_group_desc(struct ext4_mount_info *mi, uint32_t group)
{
    if (group >= mi->group_count)
        return NULL;
    return (struct ext4_group_desc *)(mi->group_descs +
                                      (uint64_t)group * mi->desc_size);
}

/*
 * Get the inode table start block for a group (full 64-bit).
 */
static uint64_t
ext4_group_inode_table(struct ext4_mount_info *mi, uint32_t group)
{
    struct ext4_group_desc *gd = ext4_get_group_desc(mi, group);
    if (gd == NULL)
        return 0;

    uint64_t blk = gd->bg_inode_table_lo;
    if (mi->desc_size >= 64)
        blk |= (uint64_t)gd->bg_inode_table_hi << 32;
    return blk;
}

/* ============================================================================
 * Inode I/O
 * ============================================================================ */

/*
 * ext4_inode_to_block - Compute the block group and offset for an inode number.
 *
 * @mi:     Mount info
 * @ino:    Inode number (1-based)
 * @group:  Output: block group index
 * @index:  Output: index within the block group's inode table
 */
static void
ext4_inode_to_block(struct ext4_mount_info *mi, uint64_t ino,
                    uint32_t *group, uint32_t *index)
{
    *group = (uint32_t)((ino - 1) / mi->inodes_per_group);
    *index = (uint32_t)((ino - 1) % mi->inodes_per_group);
}

/*
 * ext4_read_inode - Read an inode from disk.
 *
 * @mi:  Mount info
 * @ino: Inode number (1-based)
 * @out: Destination inode structure
 *
 * Returns 0 on success, -errno on failure.
 */
static int
ext4_read_inode(struct ext4_mount_info *mi, uint64_t ino,
                struct ext4_inode *out)
{
    if (ino == 0 || ino > mi->sb.s_inodes_count)
        return -EINVAL;

    uint32_t group, index;
    ext4_inode_to_block(mi, ino, &group, &index);

    uint64_t table_block = ext4_group_inode_table(mi, group);
    if (table_block == 0)
        return -EIO;

    /*
     * Compute byte offset of this inode within the filesystem:
     *   table_block * block_size + index * inode_size
     */
    uint64_t byte_off = table_block * mi->block_size +
                        (uint64_t)index * mi->inode_size;

    /* Read the inode through the buffer cache */
    uint64_t buf_blk = byte_off / BUF_BLOCK_SIZE;
    uint32_t buf_off = (uint32_t)(byte_off % BUF_BLOCK_SIZE);

    /*
     * The inode might span a buf block boundary. Read up to inode_size
     * bytes, but only copy sizeof(struct ext4_inode) into the output.
     */
    uint32_t to_read = mi->inode_size;
    if (to_read > sizeof(struct ext4_inode))
        to_read = sizeof(struct ext4_inode);

    ext4_memset(out, 0, sizeof(struct ext4_inode));

    uint8_t *dst = (uint8_t *)out;
    uint32_t remaining = to_read;

    while (remaining > 0) {
        struct buf *bp = buf_read(mi->dev, buf_blk);
        if (bp == NULL)
            return -EIO;

        uint32_t chunk = BUF_BLOCK_SIZE - buf_off;
        if (chunk > remaining)
            chunk = remaining;

        ext4_memcpy(dst, bp->data + buf_off, chunk);
        buf_release(bp);

        dst += chunk;
        remaining -= chunk;
        buf_blk++;
        buf_off = 0;
    }

    return 0;
}

/* ============================================================================
 * Extent Tree
 * ============================================================================ */

/*
 * ext4_extent_read - Map a logical block to a physical block using the
 *                    extent tree.
 *
 * Supports:
 *   - Leaf-only trees (depth == 0): direct extents in inode
 *   - Multi-level trees (depth > 0): index nodes pointing to extent blocks
 *
 * @mi:        Mount info
 * @inode:     Inode containing the extent tree
 * @logical:   Logical block number within the file
 * @physical:  Output: physical block number on disk
 *
 * Returns 0 on success, -ENOENT if block is not mapped (hole),
 *         -EIO on I/O error, -EINVAL on corrupt tree.
 */
static int
ext4_extent_read(struct ext4_mount_info *mi, struct ext4_inode *inode,
                 uint64_t logical, uint64_t *physical)
{
    struct ext4_extent_header *eh;
    uint8_t node_buf[mi->block_size];

    /* Start with the extent tree root in the inode's i_block area */
    eh = (struct ext4_extent_header *)inode->i_block;

    if (eh->eh_magic != EXT4_EXT_MAGIC) {
        kprintf("ext4: bad extent magic 0x%x (expected 0x%x)\n",
                eh->eh_magic, EXT4_EXT_MAGIC);
        return -EINVAL;
    }

    uint16_t depth = eh->eh_depth;

    /* Walk internal index nodes */
    while (depth > 0) {
        struct ext4_extent_idx *idx_entries =
            (struct ext4_extent_idx *)(eh + 1);
        uint16_t nentries = eh->eh_entries;

        if (nentries == 0)
            return -ENOENT;

        /*
         * Binary-style search: find the last index whose ei_block <= logical.
         * Entries are sorted by ei_block.
         */
        uint16_t chosen = 0;
        for (uint16_t i = 1; i < nentries; i++) {
            if (idx_entries[i].ei_block <= (uint32_t)logical)
                chosen = i;
            else
                break;
        }

        /* Read the child node block */
        uint64_t child_block = EXT4_IDX_PBLOCK(&idx_entries[chosen]);
        int err = ext4_read_fs_block(mi, child_block, 0,
                                     node_buf, mi->block_size);
        if (err != 0)
            return err;

        eh = (struct ext4_extent_header *)node_buf;
        if (eh->eh_magic != EXT4_EXT_MAGIC) {
            kprintf("ext4: bad extent index magic at depth %u\n", depth);
            return -EINVAL;
        }

        depth--;
    }

    /* Now at a leaf node -- search extents */
    struct ext4_extent *extents = (struct ext4_extent *)(eh + 1);
    uint16_t nentries = eh->eh_entries;

    for (uint16_t i = 0; i < nentries; i++) {
        uint32_t ee_block = extents[i].ee_block;
        uint16_t ee_len = EXT4_EXT_GET_LEN(&extents[i]);
        uint64_t ee_start = EXT4_EXTENT_PBLOCK(&extents[i]);

        if (logical >= ee_block && logical < ee_block + ee_len) {
            *physical = ee_start + (logical - ee_block);
            return 0;
        }
    }

    /* Logical block falls in a hole (sparse file) */
    return -ENOENT;
}

/*
 * ext4_extent_alloc_block - Allocate a block and add it to the extent tree.
 *
 * For simple (depth=0) extent trees, this either:
 *   - Extends the last extent if the new block is contiguous
 *   - Adds a new extent entry if there's room
 *
 * @mi:         Mount info
 * @inode:      Inode to modify (will be written back by caller)
 * @logical:    Logical block number to allocate
 * @pref_group: Preferred block group for allocation
 * @physical:   Output: physical block number allocated
 *
 * Returns 0 on success, -ENOSPC if no space, -EFBIG if extent tree is full.
 */
static int
ext4_extent_alloc_block(struct ext4_mount_info *mi, struct ext4_inode *inode,
                        uint64_t logical, uint32_t pref_group, uint64_t *physical)
{
    struct ext4_extent_header *eh = (struct ext4_extent_header *)inode->i_block;

    if (eh->eh_magic != EXT4_EXT_MAGIC)
        return -EINVAL;

    /* Only support depth=0 (leaf-only) extent trees for now */
    if (eh->eh_depth > 0) {
        kprintf("ext4: extent tree depth>0 not supported for allocation\n");
        return -ENOSYS;
    }

    struct ext4_extent *extents = (struct ext4_extent *)(eh + 1);
    uint16_t nentries = eh->eh_entries;
    uint16_t max_entries = eh->eh_max;

    /* Try to extend the last extent if the block is contiguous */
    if (nentries > 0) {
        struct ext4_extent *last = &extents[nentries - 1];
        uint32_t last_logical_end = last->ee_block + EXT4_EXT_GET_LEN(last);
        uint64_t last_phys_end = EXT4_EXTENT_PBLOCK(last) + EXT4_EXT_GET_LEN(last);

        if (logical == last_logical_end) {
            /* Check if we can extend (length < max and physical block is contiguous) */
            uint16_t cur_len = EXT4_EXT_GET_LEN(last);
            if (cur_len < EXT4_EXT_INIT_MAX_LEN) {
                /* Try to allocate the next contiguous physical block */
                /* First check if it's free */
                uint32_t group = (uint32_t)((last_phys_end - mi->first_data_block) /
                                            mi->blocks_per_group);
                uint32_t block_in_group = (uint32_t)((last_phys_end - mi->first_data_block) %
                                                     mi->blocks_per_group);

                uint64_t bitmap_block = ext4_group_block_bitmap(mi, group);
                if (bitmap_block != 0) {
                    uint8_t bitmap[mi->block_size];
                    if (ext4_read_fs_block(mi, bitmap_block, 0, bitmap, mi->block_size) == 0) {
                        uint32_t byte_idx = block_in_group / 8;
                        uint8_t bit_mask = (uint8_t)(1 << (block_in_group % 8));

                        if (byte_idx < mi->block_size && !(bitmap[byte_idx] & bit_mask)) {
                            /* Block is free! Allocate it */
                            bitmap[byte_idx] |= bit_mask;
                            if (ext4_write_fs_block(mi, bitmap_block, 0, bitmap, mi->block_size) == 0) {
                                /* Update group descriptor */
                                struct ext4_group_desc *gd = ext4_get_group_desc(mi, group);
                                if (gd && gd->bg_free_blocks_count_lo > 0)
                                    gd->bg_free_blocks_count_lo--;
                                ext4_write_group_desc(mi, group);

                                /* Update superblock free count */
                                if (mi->sb.s_free_blocks_count_lo > 0)
                                    mi->sb.s_free_blocks_count_lo--;

                                /* Extend the extent */
                                last->ee_len = cur_len + 1;
                                inode->i_blocks_lo += (mi->block_size / 512);

                                *physical = last_phys_end;
                                return 0;
                            }
                        }
                    }
                }
            }
        }
    }

    /* Can't extend last extent, need to add a new one */
    if (nentries >= max_entries) {
        kprintf("ext4: extent tree full (%u/%u entries)\n", nentries, max_entries);
        return -EFBIG;
    }

    /* Allocate a new block */
    uint64_t new_block = ext4_alloc_block(mi, pref_group);
    if (new_block == 0)
        return -ENOSPC;

    /* Add new extent entry */
    struct ext4_extent *new_ext = &extents[nentries];
    new_ext->ee_block = (uint32_t)logical;
    new_ext->ee_len = 1;
    new_ext->ee_start_lo = (uint32_t)(new_block & 0xFFFFFFFF);
    new_ext->ee_start_hi = (uint16_t)(new_block >> 32);

    eh->eh_entries = nentries + 1;
    inode->i_blocks_lo += (mi->block_size / 512);

    *physical = new_block;
    return 0;
}

/*
 * ext4_get_indirect_block - Get a block number from an indirect block.
 *
 * Reads the indirect block and returns the block number at the given index.
 * Returns 0 if the entry is not allocated (hole).
 */
static uint32_t
ext4_get_indirect_block(struct ext4_mount_info *mi, uint32_t indirect_block,
                        uint32_t index)
{
    if (indirect_block == 0)
        return 0;

    uint32_t ptrs_per_block = mi->block_size / sizeof(uint32_t);
    if (index >= ptrs_per_block)
        return 0;

    uint32_t block_num = 0;
    int err = ext4_read_fs_block(mi, indirect_block,
                                  index * sizeof(uint32_t),
                                  &block_num, sizeof(block_num));
    if (err != 0)
        return 0;

    return block_num;
}

/*
 * ext4_set_indirect_block - Set a block number in an indirect block.
 *
 * Writes the block number at the given index in the indirect block.
 * Returns 0 on success, error code on failure.
 */
static int
ext4_set_indirect_block(struct ext4_mount_info *mi, uint32_t indirect_block,
                        uint32_t index, uint32_t block_num)
{
    if (indirect_block == 0)
        return -EINVAL;

    uint32_t ptrs_per_block = mi->block_size / sizeof(uint32_t);
    if (index >= ptrs_per_block)
        return -EINVAL;

    return ext4_write_fs_block(mi, indirect_block,
                                index * sizeof(uint32_t),
                                &block_num, sizeof(block_num));
}

/*
 * ext4_bmap - Map a logical file block to a physical disk block.
 *
 * Handles both extent-based and legacy block-mapped inodes.
 * Supports direct blocks (0-11), single indirect (12), double indirect (13),
 * and triple indirect (14) for legacy block mapping.
 */
static int
ext4_bmap(struct ext4_mount_info *mi, struct ext4_inode *inode,
          uint64_t logical, uint64_t *physical)
{
    if (inode->i_flags & EXT4_EXTENTS_FL) {
        return ext4_extent_read(mi, inode, logical, physical);
    }

    uint32_t ptrs_per_block = mi->block_size / sizeof(uint32_t);

    /* Direct blocks: i_block[0..11] */
    if (logical < EXT4_NDIR_BLOCKS) {
        uint32_t blk = inode->i_block[logical];
        if (blk == 0)
            return -ENOENT; /* Hole */
        *physical = blk;
        return 0;
    }

    logical -= EXT4_NDIR_BLOCKS;

    /* Single indirect: i_block[12] -> block of pointers */
    if (logical < ptrs_per_block) {
        uint32_t blk = ext4_get_indirect_block(mi, inode->i_block[EXT4_IND_BLOCK],
                                                (uint32_t)logical);
        if (blk == 0)
            return -ENOENT;
        *physical = blk;
        return 0;
    }

    logical -= ptrs_per_block;

    /* Double indirect: i_block[13] -> block of indirect blocks */
    if (logical < ptrs_per_block * ptrs_per_block) {
        uint32_t idx1 = (uint32_t)(logical / ptrs_per_block);
        uint32_t idx2 = (uint32_t)(logical % ptrs_per_block);

        uint32_t ind_block = ext4_get_indirect_block(mi,
                                inode->i_block[EXT4_DIND_BLOCK], idx1);
        if (ind_block == 0)
            return -ENOENT;

        uint32_t blk = ext4_get_indirect_block(mi, ind_block, idx2);
        if (blk == 0)
            return -ENOENT;
        *physical = blk;
        return 0;
    }

    logical -= ptrs_per_block * ptrs_per_block;

    /* Triple indirect: i_block[14] -> block of double indirect blocks */
    if (logical < (uint64_t)ptrs_per_block * ptrs_per_block * ptrs_per_block) {
        uint32_t idx1 = (uint32_t)(logical / (ptrs_per_block * ptrs_per_block));
        uint32_t rem = (uint32_t)(logical % (ptrs_per_block * ptrs_per_block));
        uint32_t idx2 = rem / ptrs_per_block;
        uint32_t idx3 = rem % ptrs_per_block;

        uint32_t dind_block = ext4_get_indirect_block(mi,
                                inode->i_block[EXT4_TIND_BLOCK], idx1);
        if (dind_block == 0)
            return -ENOENT;

        uint32_t ind_block = ext4_get_indirect_block(mi, dind_block, idx2);
        if (ind_block == 0)
            return -ENOENT;

        uint32_t blk = ext4_get_indirect_block(mi, ind_block, idx3);
        if (blk == 0)
            return -ENOENT;
        *physical = blk;
        return 0;
    }

    /* File too large */
    return -EFBIG;
}

/* ============================================================================
 * Write Helpers — Block/Inode I/O
 * ============================================================================ */

/*
 * ext4_write_fs_block - Write bytes to a filesystem block through buffer cache.
 *
 * @mi:        Mount info
 * @fs_block:  Filesystem block number
 * @offset:    Byte offset within the fs block
 * @src:       Source buffer
 * @len:       Bytes to write
 *
 * Returns 0 on success, -EIO on failure.
 */
static int
ext4_write_fs_block(struct ext4_mount_info *mi, uint64_t fs_block,
                    uint32_t offset, const void *src, uint32_t len)
{
    uint64_t byte_offset = fs_block * mi->block_size + offset;
    const uint8_t *in = (const uint8_t *)src;

    while (len > 0) {
        uint64_t buf_blk = byte_offset / BUF_BLOCK_SIZE;
        uint32_t buf_off = (uint32_t)(byte_offset % BUF_BLOCK_SIZE);
        uint32_t chunk = BUF_BLOCK_SIZE - buf_off;
        if (chunk > len)
            chunk = len;

        struct buf *bp = buf_read(mi->dev, buf_blk);
        if (bp == NULL)
            return -EIO;

        ext4_memcpy(bp->data + buf_off, in, chunk);
        buf_write(bp);     /* mark dirty */
        buf_release(bp);

        in += chunk;
        byte_offset += chunk;
        len -= chunk;
    }

    return 0;
}

/*
 * ext4_write_inode - Write an inode back to disk.
 *
 * @mi:    Mount info
 * @ino:   Inode number (1-based)
 * @inode: Inode structure to write
 *
 * Returns 0 on success, -errno on failure.
 */
static int
ext4_write_inode(struct ext4_mount_info *mi, uint64_t ino,
                 struct ext4_inode *inode)
{
    if (ino == 0 || ino > mi->sb.s_inodes_count)
        return -EINVAL;

    uint32_t group, index;
    ext4_inode_to_block(mi, ino, &group, &index);

    uint64_t table_block = ext4_group_inode_table(mi, group);
    if (table_block == 0)
        return -EIO;

    uint64_t byte_off = table_block * mi->block_size +
                        (uint64_t)index * mi->inode_size;

    uint32_t to_write = mi->inode_size;
    if (to_write > sizeof(struct ext4_inode))
        to_write = sizeof(struct ext4_inode);

    uint64_t buf_blk = byte_off / BUF_BLOCK_SIZE;
    uint32_t buf_off = (uint32_t)(byte_off % BUF_BLOCK_SIZE);

    uint8_t *src = (uint8_t *)inode;
    uint32_t remaining = to_write;

    while (remaining > 0) {
        struct buf *bp = buf_read(mi->dev, buf_blk);
        if (bp == NULL)
            return -EIO;

        uint32_t chunk = BUF_BLOCK_SIZE - buf_off;
        if (chunk > remaining)
            chunk = remaining;

        ext4_memcpy(bp->data + buf_off, src, chunk);
        buf_write(bp);     /* mark dirty */
        buf_release(bp);

        src += chunk;
        remaining -= chunk;
        buf_blk++;
        buf_off = 0;
    }

    return 0;
}

/*
 * ext4_write_superblock - Write the in-memory superblock back to disk.
 */
static int
ext4_write_superblock(struct ext4_mount_info *mi)
{
    uint64_t buf_blk = EXT4_SUPERBLOCK_OFFSET / BUF_BLOCK_SIZE;
    uint32_t sb_off = EXT4_SUPERBLOCK_OFFSET % BUF_BLOCK_SIZE;

    struct buf *bp = buf_read(mi->dev, buf_blk);
    if (bp == NULL)
        return -EIO;

    ext4_memcpy(bp->data + sb_off, &mi->sb, sizeof(struct ext4_super_block));
    buf_write(bp);
    buf_release(bp);
    return 0;
}

/*
 * ext4_write_group_desc - Write a group descriptor back to disk.
 */
static int
ext4_write_group_desc(struct ext4_mount_info *mi, uint32_t group)
{
    if (group >= mi->group_count)
        return -EINVAL;

    /* GDT starts at block 1 (for block_size >= 4096) or 2 (1024) */
    uint64_t gdt_fs_block;
    if (mi->block_size == 1024)
        gdt_fs_block = 2;
    else
        gdt_fs_block = 1;

    uint64_t gd_byte_offset = gdt_fs_block * mi->block_size +
                              (uint64_t)group * mi->desc_size;

    uint64_t buf_blk = gd_byte_offset / BUF_BLOCK_SIZE;
    uint32_t buf_off = (uint32_t)(gd_byte_offset % BUF_BLOCK_SIZE);

    struct ext4_group_desc *gd = ext4_get_group_desc(mi, group);
    if (gd == NULL)
        return -EIO;

    /* Write desc_size bytes */
    struct buf *bp = buf_read(mi->dev, buf_blk);
    if (bp == NULL)
        return -EIO;

    uint32_t to_write = mi->desc_size;
    uint32_t chunk = BUF_BLOCK_SIZE - buf_off;
    if (chunk > to_write)
        chunk = to_write;

    ext4_memcpy(bp->data + buf_off, gd, chunk);
    buf_write(bp);
    buf_release(bp);

    /* Handle spanning buffer boundary (unlikely but correct) */
    if (chunk < to_write) {
        bp = buf_read(mi->dev, buf_blk + 1);
        if (bp == NULL)
            return -EIO;
        ext4_memcpy(bp->data, (uint8_t *)gd + chunk, to_write - chunk);
        buf_write(bp);
        buf_release(bp);
    }

    return 0;
}

/* ============================================================================
 * Block & Inode Allocators
 * ============================================================================ */

/*
 * ext4_group_block_bitmap - Get block bitmap block for a group (64-bit).
 */
static uint64_t
ext4_group_block_bitmap(struct ext4_mount_info *mi, uint32_t group)
{
    struct ext4_group_desc *gd = ext4_get_group_desc(mi, group);
    if (gd == NULL)
        return 0;
    uint64_t blk = gd->bg_block_bitmap_lo;
    if (mi->desc_size >= 64)
        blk |= (uint64_t)gd->bg_block_bitmap_hi << 32;
    return blk;
}

/*
 * ext4_group_inode_bitmap - Get inode bitmap block for a group (64-bit).
 */
static uint64_t
ext4_group_inode_bitmap(struct ext4_mount_info *mi, uint32_t group)
{
    struct ext4_group_desc *gd = ext4_get_group_desc(mi, group);
    if (gd == NULL)
        return 0;
    uint64_t blk = gd->bg_inode_bitmap_lo;
    if (mi->desc_size >= 64)
        blk |= (uint64_t)gd->bg_inode_bitmap_hi << 32;
    return blk;
}

/*
 * ext4_group_free_blocks - Get free block count for a group.
 */
static uint32_t
ext4_group_free_blocks(struct ext4_mount_info *mi, uint32_t group)
{
    struct ext4_group_desc *gd = ext4_get_group_desc(mi, group);
    if (gd == NULL)
        return 0;
    uint32_t cnt = gd->bg_free_blocks_count_lo;
    if (mi->desc_size >= 64)
        cnt |= (uint32_t)gd->bg_free_blocks_count_hi << 16;
    return cnt;
}

/*
 * ext4_group_free_inodes - Get free inode count for a group.
 */
static uint32_t
ext4_group_free_inodes(struct ext4_mount_info *mi, uint32_t group)
{
    struct ext4_group_desc *gd = ext4_get_group_desc(mi, group);
    if (gd == NULL)
        return 0;
    uint32_t cnt = gd->bg_free_inodes_count_lo;
    if (mi->desc_size >= 64)
        cnt |= (uint32_t)gd->bg_free_inodes_count_hi << 16;
    return cnt;
}

/*
 * ext4_alloc_block - Allocate a free block from a block group.
 *
 * Scans the block bitmap for group @pref_group first, then falls back
 * to other groups. Updates the bitmap, group descriptor, and superblock.
 *
 * Returns the allocated physical block number, or 0 on ENOSPC.
 */
static uint64_t
ext4_alloc_block(struct ext4_mount_info *mi, uint32_t pref_group)
{
    for (uint32_t attempt = 0; attempt < mi->group_count; attempt++) {
        uint32_t group = (pref_group + attempt) % mi->group_count;

        if (ext4_group_free_blocks(mi, group) == 0)
            continue;

        uint64_t bitmap_block = ext4_group_block_bitmap(mi, group);
        if (bitmap_block == 0)
            continue;

        /* Read the bitmap block */
        uint8_t bitmap[mi->block_size];
        int err = ext4_read_fs_block(mi, bitmap_block, 0, bitmap,
                                     mi->block_size);
        if (err != 0)
            continue;

        /* Scan for a free bit */
        uint32_t max_bits = mi->blocks_per_group;
        for (uint32_t i = 0; i < max_bits; i++) {
            uint32_t byte_idx = i / 8;
            uint8_t bit_mask = (uint8_t)(1 << (i % 8));

            if (byte_idx >= mi->block_size)
                break;

            if (!(bitmap[byte_idx] & bit_mask)) {
                /* Found free block — mark it allocated */
                bitmap[byte_idx] |= bit_mask;
                err = ext4_write_fs_block(mi, bitmap_block, 0, bitmap,
                                          mi->block_size);
                if (err != 0)
                    continue;

                /* Update group descriptor */
                struct ext4_group_desc *gd = ext4_get_group_desc(mi, group);
                if (gd->bg_free_blocks_count_lo > 0)
                    gd->bg_free_blocks_count_lo--;
                ext4_write_group_desc(mi, group);

                /* Update superblock */
                if (mi->sb.s_free_blocks_count_lo > 0)
                    mi->sb.s_free_blocks_count_lo--;
                /* (Defer superblock write to sync) */

                /* Compute physical block number */
                uint64_t phys_block = (uint64_t)group * mi->blocks_per_group +
                                      mi->first_data_block + i;
                return phys_block;
            }
        }
    }

    return 0; /* ENOSPC */
}

/*
 * ext4_free_block - Free a previously allocated block.
 *
 * Clears the block bitmap bit and updates group/superblock free counts.
 */
static int
ext4_free_block(struct ext4_mount_info *mi, uint64_t phys_block)
{
    if (phys_block == 0)
        return 0;

    /* Determine which group this block belongs to */
    uint64_t rel = phys_block - mi->first_data_block;
    uint32_t group = (uint32_t)(rel / mi->blocks_per_group);
    uint32_t index = (uint32_t)(rel % mi->blocks_per_group);

    if (group >= mi->group_count)
        return -EINVAL;

    uint64_t bitmap_block = ext4_group_block_bitmap(mi, group);
    if (bitmap_block == 0)
        return -EIO;

    /* Read bitmap, clear bit, write back */
    uint8_t bitmap[mi->block_size];
    int err = ext4_read_fs_block(mi, bitmap_block, 0, bitmap, mi->block_size);
    if (err != 0)
        return err;

    uint32_t byte_idx = index / 8;
    uint8_t bit_mask = (uint8_t)(1 << (index % 8));

    if (byte_idx < mi->block_size && (bitmap[byte_idx] & bit_mask)) {
        bitmap[byte_idx] &= ~bit_mask;
        err = ext4_write_fs_block(mi, bitmap_block, 0, bitmap, mi->block_size);
        if (err != 0)
            return err;

        /* Update group descriptor */
        struct ext4_group_desc *gd = ext4_get_group_desc(mi, group);
        gd->bg_free_blocks_count_lo++;
        ext4_write_group_desc(mi, group);

        /* Update superblock */
        mi->sb.s_free_blocks_count_lo++;
    }

    return 0;
}

/*
 * ext4_alloc_inode - Allocate a free inode from a block group.
 *
 * Scans the inode bitmap for group @pref_group first, then falls back
 * to other groups. Updates the bitmap, group descriptor, and superblock.
 *
 * Returns the allocated inode number (1-based), or 0 on failure.
 */
static uint64_t
ext4_alloc_inode(struct ext4_mount_info *mi, uint32_t pref_group)
{
    /* Skip reserved inodes (first s_first_ino - 1 are reserved) */
    uint32_t first_ino = mi->sb.s_first_ino;
    if (first_ino == 0)
        first_ino = 11; /* Default for rev 0 */

    for (uint32_t attempt = 0; attempt < mi->group_count; attempt++) {
        uint32_t group = (pref_group + attempt) % mi->group_count;

        if (ext4_group_free_inodes(mi, group) == 0)
            continue;

        uint64_t bitmap_block = ext4_group_inode_bitmap(mi, group);
        if (bitmap_block == 0)
            continue;

        /* Read the inode bitmap */
        uint8_t bitmap[mi->block_size];
        int err = ext4_read_fs_block(mi, bitmap_block, 0, bitmap,
                                     mi->block_size);
        if (err != 0)
            continue;

        /* Scan for a free bit */
        uint32_t max_bits = mi->inodes_per_group;
        for (uint32_t i = 0; i < max_bits; i++) {
            /* Compute the inode number this bit represents */
            uint64_t ino = (uint64_t)group * mi->inodes_per_group + i + 1;
            if (ino < first_ino)
                continue;  /* Skip reserved inodes */

            uint32_t byte_idx = i / 8;
            uint8_t bit_mask = (uint8_t)(1 << (i % 8));

            if (byte_idx >= mi->block_size)
                break;

            if (!(bitmap[byte_idx] & bit_mask)) {
                /* Found free inode — mark it allocated */
                bitmap[byte_idx] |= bit_mask;
                err = ext4_write_fs_block(mi, bitmap_block, 0, bitmap,
                                          mi->block_size);
                if (err != 0)
                    continue;

                /* Update group descriptor */
                struct ext4_group_desc *gd = ext4_get_group_desc(mi, group);
                if (gd->bg_free_inodes_count_lo > 0)
                    gd->bg_free_inodes_count_lo--;
                ext4_write_group_desc(mi, group);

                /* Update superblock */
                if (mi->sb.s_free_inodes_count > 0)
                    mi->sb.s_free_inodes_count--;

                return ino;
            }
        }
    }

    return 0; /* No free inodes */
}

/*
 * ext4_free_inode - Free a previously allocated inode.
 */
static int
ext4_free_inode(struct ext4_mount_info *mi, uint64_t ino)
{
    if (ino == 0 || ino > mi->sb.s_inodes_count)
        return -EINVAL;

    uint32_t group, index;
    ext4_inode_to_block(mi, ino, &group, &index);

    uint64_t bitmap_block = ext4_group_inode_bitmap(mi, group);
    if (bitmap_block == 0)
        return -EIO;

    uint8_t bitmap[mi->block_size];
    int err = ext4_read_fs_block(mi, bitmap_block, 0, bitmap, mi->block_size);
    if (err != 0)
        return err;

    uint32_t byte_idx = index / 8;
    uint8_t bit_mask = (uint8_t)(1 << (index % 8));

    if (byte_idx < mi->block_size && (bitmap[byte_idx] & bit_mask)) {
        bitmap[byte_idx] &= ~bit_mask;
        err = ext4_write_fs_block(mi, bitmap_block, 0, bitmap, mi->block_size);
        if (err != 0)
            return err;

        struct ext4_group_desc *gd = ext4_get_group_desc(mi, group);
        gd->bg_free_inodes_count_lo++;
        ext4_write_group_desc(mi, group);

        mi->sb.s_free_inodes_count++;
    }

    return 0;
}

/* ============================================================================
 * Directory Entry Helpers
 * ============================================================================ */

/*
 * ext4_dir_add_entry - Add a new directory entry to a directory.
 *
 * Scans existing directory blocks for space (a deleted or padding entry
 * with enough room), then appends to a new block if needed.
 *
 * @mi:       Mount info
 * @dip:      Directory inode (in memory, will be updated)
 * @dir_ino:  Directory inode number
 * @name:     Name of the new entry
 * @namelen:  Length of name
 * @ino:      Inode number for the new entry
 * @ftype:    EXT4_FT_* file type
 *
 * Returns 0 on success, -errno on failure.
 */
static int
ext4_dir_add_entry(struct ext4_mount_info *mi, struct ext4_inode *dip,
                   uint64_t dir_ino, const char *name, uint32_t namelen,
                   uint64_t ino, uint8_t ftype)
{
    uint32_t bs = mi->block_size;
    uint32_t needed = EXT4_DIR_REC_LEN(namelen);
    uint64_t dir_size = ext4_inode_size(dip);
    uint64_t nblocks = (dir_size + bs - 1) / bs;

    /* First, try to find space in existing directory blocks */
    for (uint64_t blk_idx = 0; blk_idx < nblocks; blk_idx++) {
        uint64_t phys_block;
        int err = ext4_bmap(mi, dip, blk_idx, &phys_block);
        if (err != 0)
            continue;

        uint8_t block_buf[bs];
        err = ext4_read_fs_block(mi, phys_block, 0, block_buf, bs);
        if (err != 0)
            continue;

        uint32_t offset = 0;
        while (offset < bs) {
            struct ext4_dir_entry_2 *de =
                (struct ext4_dir_entry_2 *)(block_buf + offset);

            if (de->rec_len < 8 || de->rec_len + offset > bs)
                break;

            /* Check if this entry has enough trailing space */
            uint32_t actual_len;
            if (de->inode == 0) {
                /* Deleted entry — entire rec_len is available */
                actual_len = 0;
            } else {
                actual_len = EXT4_DIR_REC_LEN(de->name_len);
            }

            uint32_t free_space = de->rec_len - actual_len;
            if (free_space >= needed) {
                /* Found space! Split the entry. */
                if (de->inode != 0) {
                    /* Shrink existing entry to actual size */
                    uint16_t old_rec_len = de->rec_len;
                    de->rec_len = (uint16_t)actual_len;

                    /* New entry starts after the shrunk entry */
                    struct ext4_dir_entry_2 *new_de =
                        (struct ext4_dir_entry_2 *)(block_buf + offset +
                                                    actual_len);
                    new_de->inode = (uint32_t)ino;
                    new_de->rec_len = (uint16_t)(old_rec_len - actual_len);
                    new_de->name_len = (uint8_t)namelen;
                    new_de->file_type = ftype;
                    ext4_memcpy(new_de->name, name, namelen);
                } else {
                    /* Reuse deleted entry (inode == 0) */
                    de->inode = (uint32_t)ino;
                    de->name_len = (uint8_t)namelen;
                    de->file_type = ftype;
                    ext4_memcpy(de->name, name, namelen);
                    /* rec_len stays the same */
                }

                /* Write the block back */
                return ext4_write_fs_block(mi, phys_block, 0, block_buf, bs);
            }

            offset += de->rec_len;
        }
    }

    /*
     * No space in existing blocks — allocate a new directory block.
     * The new block index is nblocks (the next logical block).
     */
    if (nblocks >= EXT4_NDIR_BLOCKS) {
        kprintf("ext4: directory too large for direct blocks\n");
        return -ENOSPC;
    }

    /* Determine which group this directory is in for preferred allocation */
    uint32_t dgroup, dindex;
    ext4_inode_to_block(mi, dir_ino, &dgroup, &dindex);

    uint64_t new_phys = ext4_alloc_block(mi, dgroup);
    if (new_phys == 0)
        return -ENOSPC;

    /* Store the block in the directory inode's direct blocks */
    dip->i_block[nblocks] = (uint32_t)new_phys;

    /* If the directory was using extents, we must NOT do this.
     * For newly created directories (by us), we use direct block mapping.
     * For existing directories that use extents, appending a new block
     * to the extent tree is not implemented — this is a limitation.
     * In practice, mkdisk.sh creates directories small enough. */

    /* Fill the new block with a single entry covering the whole block */
    uint8_t new_block[bs];
    ext4_memset(new_block, 0, bs);

    struct ext4_dir_entry_2 *new_de = (struct ext4_dir_entry_2 *)new_block;
    new_de->inode = (uint32_t)ino;
    new_de->rec_len = (uint16_t)bs;
    new_de->name_len = (uint8_t)namelen;
    new_de->file_type = ftype;
    ext4_memcpy(new_de->name, name, namelen);

    int err = ext4_write_fs_block(mi, new_phys, 0, new_block, bs);
    if (err != 0)
        return err;

    /* Update directory size */
    uint64_t new_size = (nblocks + 1) * bs;
    dip->i_size_lo = (uint32_t)(new_size & 0xFFFFFFFF);
    /* directories don't use i_size_high */

    /* Update block count (in 512-byte sectors) */
    dip->i_blocks_lo += (bs / 512);

    /* Write updated directory inode */
    return ext4_write_inode(mi, dir_ino, dip);
}

/*
 * ext4_dir_remove_entry - Remove a directory entry by name.
 *
 * Marks the entry as deleted by setting inode=0 and merging it
 * with the previous entry's rec_len.
 *
 * Returns 0 on success, -ENOENT if not found, -errno on error.
 */
static int
ext4_dir_remove_entry(struct ext4_mount_info *mi, struct ext4_inode *dip,
                      const char *name, uint32_t namelen)
{
    uint32_t bs = mi->block_size;
    uint64_t dir_size = ext4_inode_size(dip);
    uint64_t nblocks = (dir_size + bs - 1) / bs;

    for (uint64_t blk_idx = 0; blk_idx < nblocks; blk_idx++) {
        uint64_t phys_block;
        int err = ext4_bmap(mi, dip, blk_idx, &phys_block);
        if (err != 0)
            continue;

        uint8_t block_buf[bs];
        err = ext4_read_fs_block(mi, phys_block, 0, block_buf, bs);
        if (err != 0)
            continue;

        uint32_t offset = 0;
        struct ext4_dir_entry_2 *prev_de = NULL;

        while (offset < bs) {
            struct ext4_dir_entry_2 *de =
                (struct ext4_dir_entry_2 *)(block_buf + offset);

            if (de->rec_len < 8 || de->rec_len + offset > bs)
                break;

            if (de->inode != 0 &&
                de->name_len == (uint8_t)namelen &&
                ext4_memcmp(de->name, name, namelen) == 0) {
                /* Found the entry — remove it */
                if (prev_de != NULL) {
                    /* Merge with previous entry */
                    prev_de->rec_len += de->rec_len;
                } else {
                    /* First entry in block — just zero the inode */
                    de->inode = 0;
                    de->name_len = 0;
                    de->file_type = 0;
                }
                /* Write the block back */
                return ext4_write_fs_block(mi, phys_block, 0,
                                           block_buf, bs);
            }

            prev_de = de;
            offset += de->rec_len;
        }
    }

    return -ENOENT;
}

/*
 * ext4_truncate_blocks - Free all data blocks of an inode (for unlink/truncate).
 *
 * Only handles direct blocks (i_block[0..11]).
 * For extent-based inodes, we walk the extent tree.
 */
static int
ext4_truncate_blocks(struct ext4_mount_info *mi, struct ext4_inode *ip)
{
    if (ip->i_flags & EXT4_EXTENTS_FL) {
        /*
         * Walk the extent tree and free all leaf extents.
         * For simplicity, only handle depth-0 (inline extents in inode).
         */
        struct ext4_extent_header *eh =
            (struct ext4_extent_header *)ip->i_block;

        if (eh->eh_magic == EXT4_EXT_MAGIC && eh->eh_depth == 0) {
            struct ext4_extent *exts = (struct ext4_extent *)(eh + 1);
            uint16_t nentries = eh->eh_entries;

            for (uint16_t i = 0; i < nentries; i++) {
                uint64_t start = EXT4_EXTENT_PBLOCK(&exts[i]);
                uint16_t len = EXT4_EXT_GET_LEN(&exts[i]);
                for (uint16_t j = 0; j < len; j++)
                    ext4_free_block(mi, start + j);
            }
            eh->eh_entries = 0;
        }
        /* Multi-level extent trees: we don't free internal blocks.
         * This is a simplification; the blocks will be leaked. */
    } else {
        /* Direct blocks */
        for (uint32_t i = 0; i < EXT4_NDIR_BLOCKS; i++) {
            if (ip->i_block[i] != 0) {
                ext4_free_block(mi, ip->i_block[i]);
                ip->i_block[i] = 0;
            }
        }
        /* Indirect blocks (i_block[12..14]) not handled */
    }

    ip->i_size_lo = 0;
    ip->i_size_high = 0;
    ip->i_blocks_lo = 0;

    return 0;
}

/* ============================================================================
 * Inode -> Vnode Conversion
 * ============================================================================ */

static enum vtype
ext4_mode_to_vtype(uint16_t mode)
{
    switch (mode & EXT4_S_IFMT) {
    case EXT4_S_IFREG:  return VREG;
    case EXT4_S_IFDIR:  return VDIR;
    case EXT4_S_IFLNK:  return VLNK;
    case EXT4_S_IFBLK:  return VBLK;
    case EXT4_S_IFCHR:  return VCHR;
    case EXT4_S_IFIFO:  return VFIFO;
    case EXT4_S_IFSOCK: return VSOCK;
    default:            return VNON;
    }
}

static uint8_t
ext4_ft_to_dtype(uint8_t ft)
{
    switch (ft) {
    case EXT4_FT_REG_FILE: return DT_REG;
    case EXT4_FT_DIR:      return DT_DIR;
    case EXT4_FT_CHRDEV:   return DT_CHR;
    case EXT4_FT_BLKDEV:   return DT_BLK;
    case EXT4_FT_FIFO:     return DT_FIFO;
    case EXT4_FT_SOCK:     return DT_SOCK;
    case EXT4_FT_SYMLINK:  return DT_LNK;
    default:               return DT_UNKNOWN;
    }
}

/*
 * ext4_inode_size - Get the full 64-bit file size from an inode.
 */
static uint64_t
ext4_inode_size(struct ext4_inode *ip)
{
    uint64_t size = ip->i_size_lo;
    if (EXT4_S_ISREG(ip->i_mode))
        size |= (uint64_t)ip->i_size_high << 32;
    return size;
}

/*
 * ext4_get_vnode - Get or create a vnode for the given inode number.
 *
 * Reads the inode from disk, allocates a vnode, populates it.
 */
static int
ext4_get_vnode(struct ext4_mount_info *mi, struct mount *mp,
               uint64_t ino, struct vnode **result)
{
    struct ext4_inode disk_inode;
    int err = ext4_read_inode(mi, ino, &disk_inode);
    if (err != 0)
        return err;

    struct ext4_vnode_data *vd = ext4_vdata_alloc();
    if (vd == NULL)
        return -ENOMEM;

    ext4_memcpy(&vd->inode, &disk_inode, sizeof(struct ext4_inode));
    vd->ino = ino;
    vd->mi = mi;

    struct vnode *vp = vnode_alloc();
    if (vp == NULL) {
        ext4_vdata_free(vd);
        return -ENOMEM;
    }

    vp->v_type = ext4_mode_to_vtype(disk_inode.i_mode);
    vp->v_ino = ino;
    vp->v_size = ext4_inode_size(&disk_inode);
    vp->v_mode = disk_inode.i_mode;
    vp->v_uid = disk_inode.i_uid;
    vp->v_gid = disk_inode.i_gid;
    vp->v_nlink = disk_inode.i_links_count;
    vp->v_dev = mi->dev;
    vp->v_data = vd;
    vp->v_ops = &ext4_vnode_ops;
    vp->v_mount = mp;

    /* Merge high bits of uid/gid (Linux ext4) */
    vp->v_uid |= (uint32_t)disk_inode.osd2.linux2.l_i_uid_high << 16;
    vp->v_gid |= (uint32_t)disk_inode.osd2.linux2.l_i_gid_high << 16;

    *result = vp;
    return 0;
}

/* ============================================================================
 * Vnode Operations Implementation
 * ============================================================================ */

/*
 * ext4_vop_lookup - Look up a name in a directory.
 */
static int
ext4_vop_lookup(struct vnode *dir, const char *name, uint32_t namelen,
                struct vnode **result)
{
    if (dir->v_type != VDIR)
        return -ENOTDIR;

    struct ext4_vnode_data *dvd = (struct ext4_vnode_data *)dir->v_data;
    if (dvd == NULL)
        return -EIO;

    struct ext4_mount_info *mi = dvd->mi;
    struct ext4_inode *dip = &dvd->inode;
    uint64_t dir_size = ext4_inode_size(dip);
    uint32_t fs_block_size = mi->block_size;

    /* Iterate through all directory blocks */
    uint64_t nblocks = (dir_size + fs_block_size - 1) / fs_block_size;

    for (uint64_t blk_idx = 0; blk_idx < nblocks; blk_idx++) {
        uint64_t phys_block;
        int err = ext4_bmap(mi, dip, blk_idx, &phys_block);
        if (err != 0) {
            if (err == -ENOENT)
                continue; /* Hole in directory -- skip */
            return err;
        }

        /* Read the directory block */
        uint8_t block_buf[fs_block_size];
        err = ext4_read_fs_block(mi, phys_block, 0, block_buf, fs_block_size);
        if (err != 0)
            return err;

        /* Walk directory entries in this block */
        uint32_t offset = 0;
        while (offset < fs_block_size) {
            struct ext4_dir_entry_2 *de =
                (struct ext4_dir_entry_2 *)(block_buf + offset);

            /* Sanity check rec_len */
            if (de->rec_len < 8 || de->rec_len + offset > fs_block_size)
                break;

            if (de->inode != 0 &&
                de->name_len == (uint8_t)namelen &&
                ext4_memcmp(de->name, name, namelen) == 0) {
                /* Found it */
                return ext4_get_vnode(mi, dir->v_mount,
                                     de->inode, result);
            }

            offset += de->rec_len;
        }
    }

    return -ENOENT;
}

/*
 * ext4_vop_read - Read data from a regular file.
 */
static int64_t
ext4_vop_read(struct vnode *vp, void *buf, uint64_t offset, uint64_t count)
{
    if (vp->v_type != VREG)
        return -EISDIR;

    struct ext4_vnode_data *vd = (struct ext4_vnode_data *)vp->v_data;
    if (vd == NULL)
        return -EIO;

    struct ext4_mount_info *mi = vd->mi;
    struct ext4_inode *ip = &vd->inode;
    uint64_t file_size = ext4_inode_size(ip);

    /* Clamp read to file size */
    if (offset >= file_size)
        return 0;
    if (offset + count > file_size)
        count = file_size - offset;
    if (count == 0)
        return 0;

    uint8_t *out = (uint8_t *)buf;
    uint64_t bytes_read = 0;
    uint32_t bs = mi->block_size;

    while (bytes_read < count) {
        uint64_t file_pos = offset + bytes_read;
        uint64_t logical_block = file_pos / bs;
        uint32_t block_offset = (uint32_t)(file_pos % bs);
        uint32_t chunk = bs - block_offset;
        if (chunk > count - bytes_read)
            chunk = (uint32_t)(count - bytes_read);

        uint64_t phys_block;
        int err = ext4_bmap(mi, ip, logical_block, &phys_block);
        if (err == -ENOENT) {
            /* Hole -- return zeros */
            ext4_memset(out + bytes_read, 0, chunk);
        } else if (err != 0) {
            return (bytes_read > 0) ? (int64_t)bytes_read : err;
        } else {
            err = ext4_read_fs_block(mi, phys_block, block_offset,
                                     out + bytes_read, chunk);
            if (err != 0)
                return (bytes_read > 0) ? (int64_t)bytes_read : err;
        }

        bytes_read += chunk;
    }

    return (int64_t)bytes_read;
}

/*
 * ext4_vop_readdir - Read directory entries into struct dirent array.
 *
 * @offset is treated as a byte offset into the directory (cookie).
 */
static int
ext4_vop_readdir(struct vnode *dir, struct dirent *buf, uint64_t *offsetp,
                 uint32_t count)
{
    if (dir->v_type != VDIR)
        return -ENOTDIR;

    struct ext4_vnode_data *dvd = (struct ext4_vnode_data *)dir->v_data;
    if (dvd == NULL)
        return -EIO;

    struct ext4_mount_info *mi = dvd->mi;
    struct ext4_inode *dip = &dvd->inode;
    uint64_t dir_size = ext4_inode_size(dip);
    uint32_t bs = mi->block_size;

    uint64_t pos = *offsetp;
    if (pos >= dir_size)
        return 0;

    uint32_t entries_read = 0;

    while (pos < dir_size && entries_read < count) {
        uint64_t logical_block = pos / bs;
        uint32_t block_offset = (uint32_t)(pos % bs);

        uint64_t phys_block;
        int err = ext4_bmap(mi, dip, logical_block, &phys_block);
        if (err != 0) {
            if (err == -ENOENT) {
                pos = (logical_block + 1) * bs;
                continue;
            }
            *offsetp = pos;
            return (entries_read > 0) ? (int)entries_read : err;
        }

        uint8_t block_buf[bs];
        err = ext4_read_fs_block(mi, phys_block, 0, block_buf, bs);
        if (err != 0) {
            *offsetp = pos;
            return (entries_read > 0) ? (int)entries_read : err;
        }

        uint32_t off = block_offset;
        while (off < bs && entries_read < count) {
            struct ext4_dir_entry_2 *de =
                (struct ext4_dir_entry_2 *)(block_buf + off);

            if (de->rec_len < 8 || off + de->rec_len > bs) {
                /* Corrupt or end of useful entries in this block;
                 * advance to the next block to avoid infinite loop. */
                off = bs;
                break;
            }

            if (de->inode != 0) {
                struct dirent *d = &buf[entries_read];
                ext4_memset(d, 0, sizeof(struct dirent));
                d->d_ino = de->inode;
                d->d_seekoff = logical_block * bs + off + de->rec_len;
                d->d_reclen = sizeof(struct dirent);
                d->d_type = ext4_ft_to_dtype(de->file_type);

                uint32_t cplen = de->name_len;
                if (cplen > MAXPATHLEN - 1)
                    cplen = MAXPATHLEN - 1;
                d->d_namlen = (uint16_t)cplen;
                ext4_memcpy(d->d_name, de->name, cplen);
                d->d_name[cplen] = '\0';

                entries_read++;
            }

            off += de->rec_len;
        }

        /* Update pos to the byte offset after the last entry processed */
        pos = logical_block * bs + off;

        /* If off reached or exceeded block size, move to next block */
        if (off >= bs)
            pos = (logical_block + 1) * bs;
    }

    *offsetp = pos;
    return (int)entries_read;
}

/*
 * ext4_vop_getattr - Fill a struct stat from the vnode.
 *
 * Fills the Darwin arm64 144-byte struct stat layout.
 */
static int
ext4_vop_getattr(struct vnode *vp, struct stat *st)
{
    struct ext4_vnode_data *vd = (struct ext4_vnode_data *)vp->v_data;
    if (vd == NULL)
        return -EIO;

    struct ext4_inode *ip = &vd->inode;

    ext4_memset(st, 0, sizeof(struct stat));
    st->st_dev = (dev_t)vp->v_dev;
    st->st_mode = (mode_t)ip->i_mode;
    st->st_nlink = (nlink_t)ip->i_links_count;
    st->st_ino = vp->v_ino;
    st->st_uid = vp->v_uid;
    st->st_gid = vp->v_gid;
    st->st_rdev = 0;
    st->st_size = (int64_t)ext4_inode_size(ip);
    st->st_blocks = ip->i_blocks_lo;
    st->st_blksize = (blksize_t)vd->mi->block_size;

    /* Times: ext4 stores seconds in i_atime/i_mtime/i_ctime/i_crtime */
    st->st_atimespec.tv_sec = (int64_t)ip->i_atime;
    st->st_atimespec.tv_nsec = 0;
    st->st_mtimespec.tv_sec = (int64_t)ip->i_mtime;
    st->st_mtimespec.tv_nsec = 0;
    st->st_ctimespec.tv_sec = (int64_t)ip->i_ctime;
    st->st_ctimespec.tv_nsec = 0;
    st->st_birthtimespec.tv_sec = (int64_t)ip->i_crtime;
    st->st_birthtimespec.tv_nsec = 0;

    /* Darwin extra fields */
    st->st_flags = 0;
    st->st_gen = 0;

    return 0;
}

/* ============================================================================
 * Write Vnode Operations Implementation
 * ============================================================================ */

/*
 * ext4_vop_create - Create a new regular file in a directory.
 *
 * Allocates a new inode, initializes it as a regular file, adds a
 * directory entry, and returns a vnode for the new file.
 */
static int
ext4_vop_create(struct vnode *dir, const char *name, uint32_t namelen,
                mode_t mode, struct vnode **result)
{
    if (dir->v_type != VDIR)
        return -ENOTDIR;

    struct ext4_vnode_data *dvd = (struct ext4_vnode_data *)dir->v_data;
    if (dvd == NULL)
        return -EIO;

    struct ext4_mount_info *mi = dvd->mi;
    uint64_t dir_ino = dvd->ino;

    /* Determine preferred group (same as parent directory) */
    uint32_t pref_group, pref_idx;
    ext4_inode_to_block(mi, dir_ino, &pref_group, &pref_idx);

    /* Allocate a new inode */
    uint64_t new_ino = ext4_alloc_inode(mi, pref_group);
    if (new_ino == 0)
        return -ENOSPC;

    /* Initialize the new inode on disk */
    struct ext4_inode new_inode;
    ext4_memset(&new_inode, 0, sizeof(new_inode));
    new_inode.i_mode = (uint16_t)(EXT4_S_IFREG | (mode & 0x0FFF));
    new_inode.i_uid = dir->v_uid;   /* Inherit owner from parent */
    new_inode.i_gid = dir->v_gid;   /* Inherit group from parent */
    new_inode.i_links_count = 1;
    new_inode.i_flags = 0;          /* Use direct blocks, not extents */
    new_inode.i_size_lo = 0;
    new_inode.i_size_high = 0;
    new_inode.i_blocks_lo = 0;

    /* Set timestamps from ARM generic timer */
    {
        uint64_t cntfrq, cntvct;
        __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(cntfrq));
        __asm__ volatile("mrs %0, cntvct_el0" : "=r"(cntvct));
        uint32_t now = 0;
        if (cntfrq > 0)
            now = (uint32_t)(1771372800ULL + cntvct / cntfrq);
        new_inode.i_atime = now;
        new_inode.i_ctime = now;
        new_inode.i_mtime = now;
        new_inode.i_crtime = now;
    }

    int err = ext4_write_inode(mi, new_ino, &new_inode);
    if (err != 0) {
        ext4_free_inode(mi, new_ino);
        return err;
    }

    /* Add directory entry */
    err = ext4_dir_add_entry(mi, &dvd->inode, dir_ino, name, namelen,
                             new_ino, EXT4_FT_REG_FILE);
    if (err != 0) {
        ext4_free_inode(mi, new_ino);
        return err;
    }

    /* Update parent directory's in-memory inode from disk
     * (ext4_dir_add_entry may have modified it) */
    ext4_read_inode(mi, dir_ino, &dvd->inode);
    dir->v_size = ext4_inode_size(&dvd->inode);

    /* Create a vnode for the new file */
    return ext4_get_vnode(mi, dir->v_mount, new_ino, result);
}

/*
 * ext4_vop_write - Write data to a regular file.
 *
 * Supports two modes:
 *   1. Extent-based files: can only overwrite within existing extents
 *      (extending extent-based files is not supported)
 *   2. Direct-block files (i_block[0..11]): can allocate new blocks
 *
 * Files created by this driver use direct blocks, but files created
 * by mkfs.ext4/debugfs use extents by default.
 */
static int64_t
ext4_vop_write(struct vnode *vp, const void *buf, uint64_t offset,
               uint64_t count)
{
    if (vp->v_type != VREG)
        return -EISDIR;

    struct ext4_vnode_data *vd = (struct ext4_vnode_data *)vp->v_data;
    if (vd == NULL)
        return -EIO;

    struct ext4_mount_info *mi = vd->mi;
    struct ext4_inode *ip = &vd->inode;
    uint32_t bs = mi->block_size;
    int uses_extents = (ip->i_flags & EXT4_EXTENTS_FL) != 0;

#ifdef DEBUG
    kprintf("[ext4] write: ino=%lu offset=%lu count=%lu extents=%d\n",
            (unsigned long)vd->ino, (unsigned long)offset,
            (unsigned long)count, uses_extents);
#endif

    /* Determine the preferred block group for allocation */
    uint32_t pref_group, pref_idx;
    ext4_inode_to_block(mi, vd->ino, &pref_group, &pref_idx);

    const uint8_t *in = (const uint8_t *)buf;
    uint64_t bytes_written = 0;

    while (bytes_written < count) {
        uint64_t file_pos = offset + bytes_written;
        uint64_t logical_block = file_pos / bs;
        uint32_t block_offset = (uint32_t)(file_pos % bs);
        uint32_t chunk = bs - block_offset;
        if (chunk > count - bytes_written)
            chunk = (uint32_t)(count - bytes_written);

        uint64_t phys_block = 0;

        if (uses_extents) {
            /*
             * Extent-based file: use ext4_bmap() to find the physical block.
             * If the block isn't mapped, allocate it via extent tree.
             */
            int err = ext4_bmap(mi, ip, logical_block, &phys_block);
            if (err == -ENOENT) {
                /* Block not mapped — allocate via extent tree */
                err = ext4_extent_alloc_block(mi, ip, logical_block, pref_group,
                                              &phys_block);
                if (err != 0) {
                    if (bytes_written > 0)
                        break;
                    return err;
                }

                /* Zero the new block if we're writing a partial block */
                if (block_offset > 0 || chunk < bs) {
                    uint8_t zeros[bs];
                    ext4_memset(zeros, 0, bs);
                    int zerr = ext4_write_fs_block(mi, phys_block, 0, zeros, bs);
                    if (zerr != 0) {
                        if (bytes_written > 0)
                            break;
                        return zerr;
                    }
                }
            } else if (err != 0) {
                if (bytes_written > 0)
                    break;
                return err;
            }
        } else {
            /*
             * Legacy block-mapped file: supports direct blocks (0-11),
             * single indirect (12), double indirect (13), triple indirect (14).
             */
            uint32_t ptrs_per_block = bs / sizeof(uint32_t);
            uint64_t max_blocks = EXT4_NDIR_BLOCKS +
                                  ptrs_per_block +
                                  (uint64_t)ptrs_per_block * ptrs_per_block +
                                  (uint64_t)ptrs_per_block * ptrs_per_block * ptrs_per_block;

            if (logical_block >= max_blocks) {
                if (bytes_written > 0)
                    break;
                return -EFBIG;
            }

            /* Try to map existing block first */
            int map_err = ext4_bmap(mi, ip, logical_block, &phys_block);
            if (map_err == 0) {
                /* Block already allocated, use it */
            } else if (map_err == -ENOENT) {
                /* Block not allocated, need to allocate */
                phys_block = ext4_alloc_block(mi, pref_group);
                if (phys_block == 0) {
                    if (bytes_written > 0)
                        break;
                    return -ENOSPC;
                }

                /* Store the block number in the appropriate location */
                if (logical_block < EXT4_NDIR_BLOCKS) {
                    /* Direct block */
                    ip->i_block[logical_block] = (uint32_t)phys_block;
                } else {
                    uint64_t idx = logical_block - EXT4_NDIR_BLOCKS;

                    if (idx < ptrs_per_block) {
                        /* Single indirect */
                        if (ip->i_block[EXT4_IND_BLOCK] == 0) {
                            /* Allocate the indirect block */
                            uint64_t ind_blk = ext4_alloc_block(mi, pref_group);
                            if (ind_blk == 0) {
                                if (bytes_written > 0)
                                    break;
                                return -ENOSPC;
                            }
                            ip->i_block[EXT4_IND_BLOCK] = (uint32_t)ind_blk;
                            ip->i_blocks_lo += (bs / 512);
                            /* Zero the indirect block */
                            uint8_t zeros[bs];
                            ext4_memset(zeros, 0, bs);
                            ext4_write_fs_block(mi, ind_blk, 0, zeros, bs);
                        }
                        ext4_set_indirect_block(mi, ip->i_block[EXT4_IND_BLOCK],
                                                (uint32_t)idx, (uint32_t)phys_block);
                    } else {
                        idx -= ptrs_per_block;

                        if (idx < (uint64_t)ptrs_per_block * ptrs_per_block) {
                            /* Double indirect */
                            uint32_t idx1 = (uint32_t)(idx / ptrs_per_block);
                            uint32_t idx2 = (uint32_t)(idx % ptrs_per_block);

                            if (ip->i_block[EXT4_DIND_BLOCK] == 0) {
                                uint64_t dind_blk = ext4_alloc_block(mi, pref_group);
                                if (dind_blk == 0) {
                                    if (bytes_written > 0)
                                        break;
                                    return -ENOSPC;
                                }
                                ip->i_block[EXT4_DIND_BLOCK] = (uint32_t)dind_blk;
                                ip->i_blocks_lo += (bs / 512);
                                uint8_t zeros[bs];
                                ext4_memset(zeros, 0, bs);
                                ext4_write_fs_block(mi, dind_blk, 0, zeros, bs);
                            }

                            uint32_t ind_blk = ext4_get_indirect_block(mi,
                                                ip->i_block[EXT4_DIND_BLOCK], idx1);
                            if (ind_blk == 0) {
                                ind_blk = (uint32_t)ext4_alloc_block(mi, pref_group);
                                if (ind_blk == 0) {
                                    if (bytes_written > 0)
                                        break;
                                    return -ENOSPC;
                                }
                                ip->i_blocks_lo += (bs / 512);
                                uint8_t zeros[bs];
                                ext4_memset(zeros, 0, bs);
                                ext4_write_fs_block(mi, ind_blk, 0, zeros, bs);
                                ext4_set_indirect_block(mi,
                                    ip->i_block[EXT4_DIND_BLOCK], idx1, ind_blk);
                            }
                            ext4_set_indirect_block(mi, ind_blk, idx2,
                                                    (uint32_t)phys_block);
                        } else {
                            /* Triple indirect - similar pattern */
                            idx -= (uint64_t)ptrs_per_block * ptrs_per_block;
                            uint32_t idx1 = (uint32_t)(idx / (ptrs_per_block * ptrs_per_block));
                            uint32_t rem = (uint32_t)(idx % (ptrs_per_block * ptrs_per_block));
                            uint32_t idx2 = rem / ptrs_per_block;
                            uint32_t idx3 = rem % ptrs_per_block;

                            if (ip->i_block[EXT4_TIND_BLOCK] == 0) {
                                uint64_t tind_blk = ext4_alloc_block(mi, pref_group);
                                if (tind_blk == 0) {
                                    if (bytes_written > 0)
                                        break;
                                    return -ENOSPC;
                                }
                                ip->i_block[EXT4_TIND_BLOCK] = (uint32_t)tind_blk;
                                ip->i_blocks_lo += (bs / 512);
                                uint8_t zeros[bs];
                                ext4_memset(zeros, 0, bs);
                                ext4_write_fs_block(mi, tind_blk, 0, zeros, bs);
                            }

                            uint32_t dind_blk = ext4_get_indirect_block(mi,
                                                ip->i_block[EXT4_TIND_BLOCK], idx1);
                            if (dind_blk == 0) {
                                dind_blk = (uint32_t)ext4_alloc_block(mi, pref_group);
                                if (dind_blk == 0) {
                                    if (bytes_written > 0)
                                        break;
                                    return -ENOSPC;
                                }
                                ip->i_blocks_lo += (bs / 512);
                                uint8_t zeros[bs];
                                ext4_memset(zeros, 0, bs);
                                ext4_write_fs_block(mi, dind_blk, 0, zeros, bs);
                                ext4_set_indirect_block(mi,
                                    ip->i_block[EXT4_TIND_BLOCK], idx1, dind_blk);
                            }

                            uint32_t ind_blk = ext4_get_indirect_block(mi, dind_blk, idx2);
                            if (ind_blk == 0) {
                                ind_blk = (uint32_t)ext4_alloc_block(mi, pref_group);
                                if (ind_blk == 0) {
                                    if (bytes_written > 0)
                                        break;
                                    return -ENOSPC;
                                }
                                ip->i_blocks_lo += (bs / 512);
                                uint8_t zeros[bs];
                                ext4_memset(zeros, 0, bs);
                                ext4_write_fs_block(mi, ind_blk, 0, zeros, bs);
                                ext4_set_indirect_block(mi, dind_blk, idx2, ind_blk);
                            }
                            ext4_set_indirect_block(mi, ind_blk, idx3,
                                                    (uint32_t)phys_block);
                        }
                    }
                }

                ip->i_blocks_lo += (bs / 512);

                /* Zero the new block if writing a partial block */
                if (block_offset > 0 || chunk < bs) {
                    uint8_t zeros[bs];
                    ext4_memset(zeros, 0, bs);
                    int err = ext4_write_fs_block(mi, phys_block, 0, zeros, bs);
                    if (err != 0) {
                        if (bytes_written > 0)
                            break;
                        return err;
                    }
                }
            } else {
                /* Error mapping block */
                if (bytes_written > 0)
                    break;
                return map_err;
            }
        }

        /* Write the data */
        int err = ext4_write_fs_block(mi, phys_block, block_offset,
                                      in + bytes_written, chunk);
        if (err != 0) {
            if (bytes_written > 0)
                break;
            return err;
        }

        bytes_written += chunk;
    }

    /* Update file size if we extended past the end */
    uint64_t new_end = offset + bytes_written;
    uint64_t old_size = ext4_inode_size(ip);
    if (new_end > old_size) {
        ip->i_size_lo = (uint32_t)(new_end & 0xFFFFFFFF);
        ip->i_size_high = (uint32_t)(new_end >> 32);
        vp->v_size = new_end;
    }

    /* Write the updated inode back to disk */
    ext4_write_inode(mi, vd->ino, ip);

#ifdef DEBUG
    kprintf("[ext4] write done: ino=%lu written=%lu newsize=%lu\n",
            (unsigned long)vd->ino, (unsigned long)bytes_written,
            (unsigned long)vp->v_size);
#endif

    return (int64_t)bytes_written;
}

/*
 * ext4_vop_mkdir - Create a new directory.
 *
 * Allocates a new inode, creates a directory block with '.' and '..'
 * entries, adds an entry in the parent directory.
 */
static int
ext4_vop_mkdir(struct vnode *dir, const char *name, uint32_t namelen,
               mode_t mode, struct vnode **result)
{
    if (dir->v_type != VDIR)
        return -ENOTDIR;

    struct ext4_vnode_data *dvd = (struct ext4_vnode_data *)dir->v_data;
    if (dvd == NULL)
        return -EIO;

    struct ext4_mount_info *mi = dvd->mi;
    uint64_t dir_ino = dvd->ino;
    uint32_t bs = mi->block_size;

    /* Determine preferred group */
    uint32_t pref_group, pref_idx;
    ext4_inode_to_block(mi, dir_ino, &pref_group, &pref_idx);

    /* Allocate a new inode */
    uint64_t new_ino = ext4_alloc_inode(mi, pref_group);
    if (new_ino == 0)
        return -ENOSPC;

    /* Allocate a block for the directory data (. and ..) */
    uint64_t data_block = ext4_alloc_block(mi, pref_group);
    if (data_block == 0) {
        ext4_free_inode(mi, new_ino);
        return -ENOSPC;
    }

    /* Build the directory block with '.' and '..' entries */
    uint8_t dir_block[bs];
    ext4_memset(dir_block, 0, bs);

    /* '.' entry — points to self */
    struct ext4_dir_entry_2 *dot = (struct ext4_dir_entry_2 *)dir_block;
    dot->inode = (uint32_t)new_ino;
    dot->rec_len = 12;  /* EXT4_DIR_REC_LEN(1) = 12 */
    dot->name_len = 1;
    dot->file_type = EXT4_FT_DIR;
    dot->name[0] = '.';

    /* '..' entry — points to parent */
    struct ext4_dir_entry_2 *dotdot =
        (struct ext4_dir_entry_2 *)(dir_block + 12);
    dotdot->inode = (uint32_t)dir_ino;
    dotdot->rec_len = (uint16_t)(bs - 12);  /* Rest of block */
    dotdot->name_len = 2;
    dotdot->file_type = EXT4_FT_DIR;
    dotdot->name[0] = '.';
    dotdot->name[1] = '.';

    /* Write the directory block */
    int err = ext4_write_fs_block(mi, data_block, 0, dir_block, bs);
    if (err != 0) {
        ext4_free_block(mi, data_block);
        ext4_free_inode(mi, new_ino);
        return err;
    }

    /* Initialize the new directory inode */
    struct ext4_inode new_inode;
    ext4_memset(&new_inode, 0, sizeof(new_inode));
    new_inode.i_mode = (uint16_t)(EXT4_S_IFDIR | (mode & 0x0FFF));
    new_inode.i_uid = dir->v_uid;
    new_inode.i_gid = dir->v_gid;
    new_inode.i_links_count = 2;    /* '.' and parent's entry */
    new_inode.i_flags = 0;          /* Direct blocks, not extents */
    new_inode.i_size_lo = bs;       /* One block of directory data */
    new_inode.i_blocks_lo = bs / 512;
    new_inode.i_block[0] = (uint32_t)data_block;

    err = ext4_write_inode(mi, new_ino, &new_inode);
    if (err != 0) {
        ext4_free_block(mi, data_block);
        ext4_free_inode(mi, new_ino);
        return err;
    }

    /* Add entry in parent directory */
    err = ext4_dir_add_entry(mi, &dvd->inode, dir_ino, name, namelen,
                             new_ino, EXT4_FT_DIR);
    if (err != 0) {
        ext4_free_block(mi, data_block);
        ext4_free_inode(mi, new_ino);
        return err;
    }

    /* Increment parent's link count (for the '..' entry) */
    dvd->inode.i_links_count++;
    ext4_write_inode(mi, dir_ino, &dvd->inode);
    dir->v_nlink = dvd->inode.i_links_count;

    /* Update parent directory's in-memory state */
    dir->v_size = ext4_inode_size(&dvd->inode);

    /* Update group descriptor used_dirs_count */
    uint32_t new_group, new_idx;
    ext4_inode_to_block(mi, new_ino, &new_group, &new_idx);
    struct ext4_group_desc *gd = ext4_get_group_desc(mi, new_group);
    if (gd != NULL) {
        gd->bg_used_dirs_count_lo++;
        ext4_write_group_desc(mi, new_group);
    }

    /* Create a vnode for the new directory */
    return ext4_get_vnode(mi, dir->v_mount, new_ino, result);
}

/*
 * ext4_vop_unlink - Remove a file or empty directory.
 *
 * Removes the directory entry, decrements the link count, and frees
 * the inode and data blocks if nlink reaches 0.
 */
static int
ext4_vop_unlink(struct vnode *dir, const char *name, uint32_t namelen)
{
    if (dir->v_type != VDIR)
        return -ENOTDIR;

    struct ext4_vnode_data *dvd = (struct ext4_vnode_data *)dir->v_data;
    if (dvd == NULL)
        return -EIO;

    struct ext4_mount_info *mi = dvd->mi;
    uint64_t dir_ino = dvd->ino;

    /* First, look up the entry to get its inode number */
    struct vnode *target = NULL;
    int err = ext4_vop_lookup(dir, name, namelen, &target);
    if (err != 0)
        return err;

    struct ext4_vnode_data *tvd = (struct ext4_vnode_data *)target->v_data;
    uint64_t target_ino = tvd->ino;
    struct ext4_inode *tip = &tvd->inode;

    /* Check if trying to unlink a non-empty directory */
    if (target->v_type == VDIR) {
        uint64_t tdir_size = ext4_inode_size(tip);
        /* A directory with only '.' and '..' has size == block_size
         * and 2 entries. Check link count == 2 as a simpler heuristic. */
        if (tip->i_links_count > 2 || tdir_size > mi->block_size) {
            /* Might not be empty — do a proper check */
            uint32_t bs = mi->block_size;
            uint64_t nblocks = (tdir_size + bs - 1) / bs;
            uint32_t entry_count = 0;

            for (uint64_t blk = 0; blk < nblocks && entry_count <= 2; blk++) {
                uint64_t phys;
                if (ext4_bmap(mi, tip, blk, &phys) != 0)
                    continue;
                uint8_t blkbuf[bs];
                if (ext4_read_fs_block(mi, phys, 0, blkbuf, bs) != 0)
                    continue;
                uint32_t off = 0;
                while (off < bs) {
                    struct ext4_dir_entry_2 *de =
                        (struct ext4_dir_entry_2 *)(blkbuf + off);
                    if (de->rec_len < 8 || de->rec_len + off > bs)
                        break;
                    if (de->inode != 0)
                        entry_count++;
                    off += de->rec_len;
                }
            }
            if (entry_count > 2) {
                vnode_release(target);
                return -ENOTEMPTY;
            }
        }
    }

    /* Remove the directory entry */
    err = ext4_dir_remove_entry(mi, &dvd->inode, name, namelen);
    if (err != 0) {
        vnode_release(target);
        return err;
    }

    /* Decrement link count */
    if (tip->i_links_count > 0)
        tip->i_links_count--;

    /* If this was a directory, also decrement parent's link count */
    if (target->v_type == VDIR) {
        if (dvd->inode.i_links_count > 0) {
            dvd->inode.i_links_count--;
            ext4_write_inode(mi, dir_ino, &dvd->inode);
            dir->v_nlink = dvd->inode.i_links_count;
        }

        /* Decrement used_dirs_count */
        uint32_t tgroup, tidx;
        ext4_inode_to_block(mi, target_ino, &tgroup, &tidx);
        struct ext4_group_desc *gd = ext4_get_group_desc(mi, tgroup);
        if (gd != NULL && gd->bg_used_dirs_count_lo > 0) {
            gd->bg_used_dirs_count_lo--;
            ext4_write_group_desc(mi, tgroup);
        }

        /* For a directory, the link count is typically:
         * 2 (. and parent-entry) at creation. When we remove the parent
         * entry, it drops to 1. The '.' entry still references it.
         * We treat it as unlinked when nlink <= 1 for dirs. */
        if (tip->i_links_count <= 1) {
            ext4_truncate_blocks(mi, tip);
            tip->i_links_count = 0;
            tip->i_dtime = 1; /* Mark deletion time (non-zero) */
            ext4_write_inode(mi, target_ino, tip);
            ext4_free_inode(mi, target_ino);
        } else {
            ext4_write_inode(mi, target_ino, tip);
        }
    } else {
        /* Regular file or other */
        if (tip->i_links_count == 0) {
            ext4_truncate_blocks(mi, tip);
            tip->i_dtime = 1;
            ext4_write_inode(mi, target_ino, tip);
            ext4_free_inode(mi, target_ino);
        } else {
            ext4_write_inode(mi, target_ino, tip);
        }
    }

    target->v_nlink = tip->i_links_count;
    vnode_release(target);
    return 0;
}

/*
 * ext4_vop_setattr - Set file attributes (chmod/chown/truncate).
 *
 * The caller passes a struct stat with the desired attributes.
 * We update the fields that are non-zero / meaningful.
 */
static int
ext4_vop_setattr(struct vnode *vp, struct stat *st)
{
    struct ext4_vnode_data *vd = (struct ext4_vnode_data *)vp->v_data;
    if (vd == NULL)
        return -EIO;

    struct ext4_mount_info *mi = vd->mi;
    struct ext4_inode *ip = &vd->inode;

    /* chmod: update mode bits (preserve file type)
     * Sentinel: (mode_t)-1 means don't change */
    if (st->st_mode != (mode_t)-1) {
        uint16_t new_mode = (ip->i_mode & EXT4_S_IFMT) |
                            (st->st_mode & 0x0FFF);
        ip->i_mode = new_mode;
        vp->v_mode = new_mode;
    }

    /* chown: update uid/gid
     * Sentinel: (uid_t)-1 / (gid_t)-1 means don't change */
    if (st->st_uid != (uid_t)-1) {
        ip->i_uid = (uint16_t)(st->st_uid & 0xFFFF);
        vp->v_uid = st->st_uid;
    }
    if (st->st_gid != (gid_t)-1) {
        ip->i_gid = (uint16_t)(st->st_gid & 0xFFFF);
        vp->v_gid = st->st_gid;
    }

    /* truncate: update file size
     * Sentinel: (off_t)-1 means don't change */
    if (st->st_size != (off_t)-1 &&
        st->st_size >= 0 &&
        (uint64_t)st->st_size != ext4_inode_size(ip)) {
        uint64_t new_size = (uint64_t)st->st_size;
        uint64_t old_size = ext4_inode_size(ip);

        if (new_size < old_size) {
            /* Shrinking: free blocks beyond the new size */
            uint32_t bs = mi->block_size;
            uint64_t new_blocks = (new_size + bs - 1) / bs;
            uint64_t old_blocks = (old_size + bs - 1) / bs;

            if (new_size == 0) {
                ext4_truncate_blocks(mi, ip);
            } else {
                /* Free blocks from new_blocks to old_blocks-1 */
                for (uint64_t b = new_blocks; b < old_blocks; b++) {
                    if (b < EXT4_NDIR_BLOCKS && ip->i_block[b] != 0) {
                        ext4_free_block(mi, ip->i_block[b]);
                        ip->i_block[b] = 0;
                        if (ip->i_blocks_lo >= bs / 512)
                            ip->i_blocks_lo -= (bs / 512);
                    }
                }
            }
        }
        /* Extending: blocks will be allocated on write */

        ip->i_size_lo = (uint32_t)(new_size & 0xFFFFFFFF);
        ip->i_size_high = (uint32_t)(new_size >> 32);
        vp->v_size = new_size;
    }

    /* Write updated inode */
    return ext4_write_inode(mi, vd->ino, ip);
}

/* ============================================================================
 * ext4_vop_readlink - Read the target of a symbolic link.
 *
 * For short symlinks (target < 60 bytes), the target is stored inline
 * in the inode's i_block[] array. For longer symlinks, the target is
 * stored in data blocks accessed via the normal block mapping.
 * ============================================================================ */

static int
ext4_vop_readlink(struct vnode *vp, char *buf, uint64_t buflen)
{
    if (vp == NULL || buf == NULL || buflen == 0)
        return -EINVAL;

    if (vp->v_type != VLNK)
        return -EINVAL;

    struct ext4_vnode_data *vd = (struct ext4_vnode_data *)vp->v_data;
    if (vd == NULL)
        return -EIO;

    struct ext4_inode *ip = &vd->inode;
    uint64_t link_size = ext4_inode_size(ip);

    if (link_size == 0)
        return 0;

    uint64_t to_copy = link_size;
    if (to_copy > buflen)
        to_copy = buflen;

    /*
     * Inline symlink: if the link target fits in i_block[] (60 bytes)
     * and the inode has no data blocks allocated, the target is stored
     * directly in the i_block array.
     */
    if (link_size < EXT4_N_BLOCKS * sizeof(uint32_t) && ip->i_blocks_lo == 0) {
        /* Inline symlink — target stored in i_block[] */
        const char *target = (const char *)ip->i_block;
        for (uint64_t i = 0; i < to_copy; i++)
            buf[i] = target[i];
        return (int)to_copy;
    }

    /*
     * Block-based symlink: read from data blocks via normal block mapping.
     */
    struct ext4_mount_info *mi = vd->mi;
    uint32_t bs = mi->block_size;
    uint64_t offset = 0;
    uint64_t nread = 0;

    while (nread < to_copy) {
        uint64_t logical = offset / bs;
        uint32_t blk_off = (uint32_t)(offset % bs);
        uint32_t chunk = bs - blk_off;
        if (chunk > (uint32_t)(to_copy - nread))
            chunk = (uint32_t)(to_copy - nread);

        uint64_t phys;
        int err = ext4_bmap(mi, ip, logical, &phys);
        if (err != 0)
            break;

        err = ext4_read_fs_block(mi, phys, blk_off,
                                 (uint8_t *)buf + nread, chunk);
        if (err != 0)
            break;

        nread += chunk;
        offset += chunk;
    }

    return (int)nread;
}

/* ============================================================================
 * Filesystem Operations Implementation
 * ============================================================================ */

/*
 * ext4_fs_mount - Mount an ext4 filesystem.
 *
 * Reads the superblock from byte offset 1024, validates the magic number
 * and feature flags, reads the block group descriptor table, and sets up
 * the root vnode (inode 2).
 */
static int
ext4_fs_mount(struct mount *mp)
{
    /*
     * Allocate mount info.  In a real kernel this would use kmalloc;
     * here we use a static instance (one ext4 mount at a time).
     */
    static struct ext4_mount_info mount_info;
    struct ext4_mount_info *mi = &mount_info;
    ext4_memset(mi, 0, sizeof(*mi));
    mi->dev = mp->mnt_dev;

    /*
     * Step 1: Read the superblock.
     *
     * The superblock is at byte offset 1024 from the start of the device.
     * With 4096-byte buf blocks, it's in buf block 0 at offset 1024.
     */
    struct buf *bp = buf_read(mi->dev, EXT4_SUPERBLOCK_OFFSET / BUF_BLOCK_SIZE);
    if (bp == NULL) {
        kprintf("ext4: failed to read superblock\n");
        return -EIO;
    }

    uint32_t sb_off = EXT4_SUPERBLOCK_OFFSET % BUF_BLOCK_SIZE;
    ext4_memcpy(&mi->sb, bp->data + sb_off, sizeof(struct ext4_super_block));
    buf_release(bp);

    /* Validate magic */
    if (mi->sb.s_magic != EXT4_SUPER_MAGIC) {
        kprintf("ext4: bad magic 0x%x (expected 0x%x)\n",
                mi->sb.s_magic, EXT4_SUPER_MAGIC);
        return -EINVAL;
    }

    /* Compute derived values */
    mi->block_size = 1024U << mi->sb.s_log_block_size;
    mi->block_size_shift = 10 + mi->sb.s_log_block_size;
    mi->inodes_per_group = mi->sb.s_inodes_per_group;
    mi->blocks_per_group = mi->sb.s_blocks_per_group;
    mi->first_data_block = mi->sb.s_first_data_block;

    /* Inode size: rev 0 uses 128, dynamic rev uses s_inode_size */
    if (mi->sb.s_rev_level == 0)
        mi->inode_size = 128;
    else
        mi->inode_size = mi->sb.s_inode_size;

    /* Group descriptor size: 32 bytes standard, or s_desc_size if 64-bit */
    mi->desc_size = 32;
    if ((mi->sb.s_feature_incompat & EXT4_FEATURE_INCOMPAT_64BIT) &&
        mi->sb.s_desc_size > 32)
        mi->desc_size = mi->sb.s_desc_size;

    /* Number of block groups */
    uint64_t total_blocks = mi->sb.s_blocks_count_lo;
    if (mi->sb.s_feature_incompat & EXT4_FEATURE_INCOMPAT_64BIT)
        total_blocks |= (uint64_t)mi->sb.s_blocks_count_hi << 32;

    mi->group_count = (uint32_t)((total_blocks - mi->first_data_block +
                       mi->blocks_per_group - 1) / mi->blocks_per_group);

    kprintf("ext4: block_size=%u, inode_size=%u, groups=%u, "
            "inodes_per_group=%u\n",
            mi->block_size, mi->inode_size, mi->group_count,
            mi->inodes_per_group);

    /* Check for unsupported required features */
    uint32_t supported_incompat =
        EXT4_FEATURE_INCOMPAT_FILETYPE |
        EXT4_FEATURE_INCOMPAT_EXTENTS |
        EXT4_FEATURE_INCOMPAT_64BIT |
        EXT4_FEATURE_INCOMPAT_FLEX_BG |
        EXT4_FEATURE_INCOMPAT_RECOVER;

    uint32_t unsupported = mi->sb.s_feature_incompat & ~supported_incompat;
    if (unsupported) {
        kprintf("ext4: unsupported incompat features 0x%x\n", unsupported);
        /* Mount read-only anyway; warn but continue */
    }

    /*
     * Step 2: Read block group descriptor table.
     *
     * The group descriptor table starts in the block immediately after
     * the superblock.  For block_size=1024, that's block 2.
     * For block_size>=4096, the superblock (at byte 1024) fits in block 0,
     * so the GDT starts at block 1.
     */
    mi->gd_buf_size = mi->group_count * mi->desc_size;

    /*
     * Use a static buffer for group descriptors (sized for a reasonable max).
     * In production, this would be dynamically allocated.
     */
    #define EXT4_MAX_GD_SIZE    (4096 * 64)  /* 256KB, enough for ~4K groups */
    static uint8_t gd_buffer[EXT4_MAX_GD_SIZE];

    if (mi->gd_buf_size > EXT4_MAX_GD_SIZE) {
        kprintf("ext4: group descriptor table too large (%u bytes)\n",
                mi->gd_buf_size);
        return -ENOMEM;
    }
    mi->group_descs = gd_buffer;

    /*
     * The GDT starts at the block after the superblock block.
     * For block_size == 1024: superblock is in block 1 (byte 1024),
     *   so GDT starts at block 2.
     * For block_size >= 4096: superblock is in block 0 (byte 1024 is
     *   within the first block), so GDT starts at block 1.
     */
    uint64_t gdt_fs_block;
    if (mi->block_size == 1024)
        gdt_fs_block = 2;
    else
        gdt_fs_block = 1;

    /* Read the GDT */
    uint32_t gdt_remaining = mi->gd_buf_size;
    uint8_t *gdt_ptr = mi->group_descs;
    uint64_t cur_fs_block = gdt_fs_block;

    while (gdt_remaining > 0) {
        uint32_t chunk = mi->block_size;
        if (chunk > gdt_remaining)
            chunk = gdt_remaining;

        int err = ext4_read_fs_block(mi, cur_fs_block, 0, gdt_ptr, chunk);
        if (err != 0) {
            kprintf("ext4: failed to read group descriptors at block %lu\n",
                    cur_fs_block);
            return err;
        }

        gdt_ptr += chunk;
        gdt_remaining -= chunk;
        cur_fs_block++;
    }

    kprintf("ext4: read %u group descriptors (%u bytes)\n",
            mi->group_count, mi->gd_buf_size);

    /*
     * Step 3: Read root inode (inode 2) and create root vnode.
     */
    mp->mnt_data = mi;

    struct vnode *root_vp = NULL;
    int err = ext4_get_vnode(mi, mp, EXT4_ROOT_INO, &root_vp);
    if (err != 0) {
        kprintf("ext4: failed to read root inode: %d\n", err);
        return err;
    }

    if (root_vp->v_type != VDIR) {
        kprintf("ext4: root inode is not a directory (type=%d)\n",
                root_vp->v_type);
        vnode_release(root_vp);
        return -EINVAL;
    }

    mp->mnt_root = root_vp;

    kprintf("ext4: mounted successfully (root inode %lu, size %lu)\n",
            root_vp->v_ino, root_vp->v_size);
    return 0;
}

static int
ext4_fs_unmount(struct mount *mp)
{
    if (mp->mnt_root) {
        vnode_release(mp->mnt_root);
        mp->mnt_root = NULL;
    }
    mp->mnt_data = NULL;
    kprintf("ext4: unmounted\n");
    return 0;
}

static int
ext4_fs_sync(struct mount *mp)
{
    struct ext4_mount_info *mi = (struct ext4_mount_info *)mp->mnt_data;
    if (mi == NULL)
        return -EIO;

    /* Write the superblock (free counts may have changed) */
    ext4_write_superblock(mi);

    /* Flush the buffer cache (writes all dirty blocks to disk) */
    buf_sync();

    return 0;
}

static int
ext4_fs_statfs(struct mount *mp, struct statfs *buf)
{
    struct ext4_mount_info *mi = (struct ext4_mount_info *)mp->mnt_data;
    if (mi == NULL)
        return -EIO;

    ext4_memset(buf, 0, sizeof(struct statfs));

    uint64_t total_blocks = mi->sb.s_blocks_count_lo;
    uint64_t free_blocks = mi->sb.s_free_blocks_count_lo;
    uint64_t reserved = mi->sb.s_r_blocks_count_lo;

    if (mi->sb.s_feature_incompat & EXT4_FEATURE_INCOMPAT_64BIT) {
        total_blocks |= (uint64_t)mi->sb.s_blocks_count_hi << 32;
        free_blocks |= (uint64_t)mi->sb.s_free_blocks_count_hi << 32;
        reserved |= (uint64_t)mi->sb.s_r_blocks_count_hi << 32;
    }

    buf->f_blocks = total_blocks;
    buf->f_bfree = free_blocks;
    buf->f_bavail = (free_blocks > reserved) ? (free_blocks - reserved) : 0;
    buf->f_files = mi->sb.s_inodes_count;
    buf->f_ffree = mi->sb.s_free_inodes_count;
    buf->f_bsize = mi->block_size;
    buf->f_namelen = EXT4_NAME_LEN;

    /* Copy filesystem type name */
    buf->f_fstype[0]  = 'e';
    buf->f_fstype[1]  = 'x';
    buf->f_fstype[2]  = 't';
    buf->f_fstype[3]  = '4';
    buf->f_fstype[4]  = '\0';

    return 0;
}

/* ============================================================================
 * Module Initialization
 * ============================================================================ */

void
ext4_fs_init(void)
{
    /* Zero out the vdata pool */
    ext4_memset(ext4_vdata_pool, 0, sizeof(ext4_vdata_pool));
    spin_init(&ext4_vdata_lock);

    /* Register ext4 with the VFS */
    int err = vfs_register_fs("ext4", &ext4_fs_ops);
    if (err != 0)
        kprintf("ext4: failed to register filesystem: %d\n", err);
}
