/*
 * Kiseki OS - Buffer Cache Interface
 *
 * BSD-style block buffer cache. Provides a fixed pool of memory buffers
 * that cache disk blocks, with LRU eviction for reuse.
 *
 * Each buffer holds BUF_BLOCK_SIZE bytes (4096 = 8 sectors of 512 bytes).
 * Buffers are identified by (dev, block_no) pairs.
 *
 * Reference: Lions' Commentary on UNIX 6th Edition (buf.h),
 *            McKusick et al., "The Design and Implementation of the
 *            FreeBSD Operating System" Chapter 6.
 */

#ifndef _FS_BUF_H
#define _FS_BUF_H

#include <kiseki/types.h>

/* ============================================================================
 * Buffer Constants
 * ============================================================================ */

/* Number of buffers in the cache pool */
#define BUF_POOL_SIZE       256

/* Bytes per buffer (8 disk sectors of 512 bytes) */
#define BUF_BLOCK_SIZE      4096

/* Sectors per buffer block */
#define BUF_SECTORS         (BUF_BLOCK_SIZE / 512)

/* ============================================================================
 * Buffer Flags
 * ============================================================================ */

#define B_VALID     0x01    /* Buffer contains valid data from disk */
#define B_DIRTY     0x02    /* Buffer has been modified (needs writeback) */
#define B_BUSY      0x04    /* Buffer is locked by a consumer */

/* ============================================================================
 * Buffer Structure
 * ============================================================================ */

struct buf {
    uint32_t flags;             /* B_VALID | B_DIRTY | B_BUSY */
    uint32_t dev;               /* Device number */
    uint64_t block_no;          /* Block number (in BUF_BLOCK_SIZE units) */
    uint32_t refcount;          /* Reference count */
    uint32_t _pad;
    uint8_t  *data;             /* Pointer to BUF_BLOCK_SIZE-byte data area */

    /* LRU doubly-linked list pointers (most-recently-used at head) */
    struct buf *lru_next;
    struct buf *lru_prev;

    /* Hash bucket chain for O(1) lookup by (dev, block_no) */
    struct buf *hash_next;
};

/* ============================================================================
 * Buffer Cache API
 * ============================================================================ */

/*
 * buf_init - Initialize the buffer cache
 *
 * Must be called once during kernel startup, after PMM is available.
 * Allocates the buffer pool and data areas, initializes LRU list and
 * hash table.
 */
void buf_init(void);

/*
 * buf_read - Get a buffer for the given block, reading from disk if needed
 *
 * @dev:      Device number
 * @block_no: Block number (in BUF_BLOCK_SIZE units)
 *
 * Looks up the block in the cache. On a cache hit, returns the existing
 * buffer (marking it B_BUSY). On a miss, evicts the LRU non-busy buffer
 * (flushing it if dirty), reads the block from disk, and returns it.
 *
 * The returned buffer is locked (B_BUSY). Caller must call buf_release()
 * when done.
 *
 * Returns NULL on failure (I/O error or all buffers busy).
 */
struct buf *buf_read(uint32_t dev, uint64_t block_no);

/*
 * buf_write - Mark a buffer as dirty (schedule writeback)
 *
 * @bp: Buffer to mark dirty
 *
 * The actual disk write happens during eviction or when buf_sync()
 * is called. The buffer remains B_BUSY; caller still owns it.
 */
void buf_write(struct buf *bp);

/*
 * buf_release - Release a buffer (unlock it)
 *
 * @bp: Buffer to release
 *
 * Clears B_BUSY and moves the buffer to the head of the LRU list
 * (most recently used). Does NOT flush dirty data.
 */
void buf_release(struct buf *bp);

/*
 * buf_sync - Flush all dirty buffers to disk
 *
 * Iterates the entire pool and writes back any buffer marked B_DIRTY.
 * Called during system shutdown or explicit sync requests.
 */
void buf_sync(void);

#endif /* _FS_BUF_H */
