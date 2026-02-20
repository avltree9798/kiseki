/*
 * Kiseki OS - Buffer Cache Implementation
 *
 * Fixed pool of 256 buffers (each 4096 bytes), organized as:
 *   - Hash table for O(1) lookup by (dev, block_no)
 *   - LRU doubly-linked list for eviction (tail = least recently used)
 *
 * Thread safety: a single spinlock protects all cache metadata.
 * Individual buffers are further protected by the B_BUSY flag.
 *
 * A background kernel thread (bufsync) periodically flushes dirty
 * buffers to disk, similar to BSD's syncer or macOS's buffer flushing.
 */

#include <kiseki/types.h>
#include <kern/kprintf.h>
#include <kern/sync.h>
#include <kern/thread.h>
#include <fs/buf.h>
#include <drivers/blkdev.h>

/* Interval between background syncs (in timer ticks, ~30 seconds) */
#define BUFSYNC_INTERVAL    (30 * 100)  /* 100 ticks/sec assumed */

/* ============================================================================
 * Hash Table
 * ============================================================================ */

#define BUF_HASH_BUCKETS    64
#define BUF_HASH(dev, blk)  (((uint64_t)(dev) ^ (blk)) % BUF_HASH_BUCKETS)

static struct buf *hash_table[BUF_HASH_BUCKETS];

/* ============================================================================
 * Buffer Pool and LRU List
 * ============================================================================ */

/* Static pool of buffer headers */
static struct buf buf_pool[BUF_POOL_SIZE];

/* Static pool of data backing each buffer */
static uint8_t buf_data[BUF_POOL_SIZE][BUF_BLOCK_SIZE] __aligned(PAGE_SIZE);

/* LRU list: head = most recently used, tail = least recently used */
static struct buf *lru_head;
static struct buf *lru_tail;

/* Global cache lock */
static spinlock_t buf_lock = SPINLOCK_INIT;

/* ============================================================================
 * Internal: LRU List Manipulation
 *
 * All functions below assume buf_lock is held.
 * ============================================================================ */

/* Remove buf from the LRU list (does not free it) */
static void lru_remove(struct buf *bp)
{
    if (bp->lru_prev)
        bp->lru_prev->lru_next = bp->lru_next;
    else
        lru_head = bp->lru_next;

    if (bp->lru_next)
        bp->lru_next->lru_prev = bp->lru_prev;
    else
        lru_tail = bp->lru_prev;

    bp->lru_next = NULL;
    bp->lru_prev = NULL;
}

/* Insert buf at the head of the LRU list (most recently used) */
static void lru_insert_head(struct buf *bp)
{
    bp->lru_prev = NULL;
    bp->lru_next = lru_head;
    if (lru_head)
        lru_head->lru_prev = bp;
    else
        lru_tail = bp;
    lru_head = bp;
}

/* ============================================================================
 * Internal: Hash Table Manipulation
 *
 * All functions below assume buf_lock is held.
 * ============================================================================ */

static struct buf *hash_lookup(uint32_t dev, uint64_t block_no)
{
    uint64_t bucket = BUF_HASH(dev, block_no);
    struct buf *bp = hash_table[bucket];
    while (bp) {
        if (bp->dev == dev && bp->block_no == block_no)
            return bp;
        bp = bp->hash_next;
    }
    return NULL;
}

static void hash_insert(struct buf *bp)
{
    uint64_t bucket = BUF_HASH(bp->dev, bp->block_no);
    bp->hash_next = hash_table[bucket];
    hash_table[bucket] = bp;
}

static void hash_remove(struct buf *bp)
{
    uint64_t bucket = BUF_HASH(bp->dev, bp->block_no);
    struct buf **pp = &hash_table[bucket];
    while (*pp) {
        if (*pp == bp) {
            *pp = bp->hash_next;
            bp->hash_next = NULL;
            return;
        }
        pp = &(*pp)->hash_next;
    }
}

/* ============================================================================
 * Internal: Disk I/O
 * ============================================================================ */

/*
 * buf_do_read - Read a block from disk into buffer
 *
 * Uses the block device abstraction layer.
 * Returns 0 on success, -1 on failure.
 */
static int buf_do_read(struct buf *bp)
{
    /* Convert block number to sector number */
    uint64_t sector = bp->block_no * BUF_SECTORS;
    int ret = blkdev_read(bp->dev, sector, bp->data, BUF_SECTORS);
    if (ret == 0)
        bp->flags |= B_VALID;
    return ret;
}

/*
 * buf_do_write - Write a buffer's data to disk
 *
 * Returns 0 on success, -1 on failure.
 */
static int buf_do_write(struct buf *bp)
{
    uint64_t sector = bp->block_no * BUF_SECTORS;
    int ret = blkdev_write(bp->dev, sector, bp->data, BUF_SECTORS);
    if (ret == 0)
        bp->flags &= ~B_DIRTY;
    return ret;
}

/* ============================================================================
 * Public API
 * ============================================================================ */

void buf_init(void)
{
    uint64_t flags;
    spin_lock_irqsave(&buf_lock, &flags);

    /* Initialize hash table */
    for (uint32_t i = 0; i < BUF_HASH_BUCKETS; i++)
        hash_table[i] = NULL;

    /* Initialize LRU list */
    lru_head = NULL;
    lru_tail = NULL;

    /* Initialize each buffer and add to the LRU list (all start as free) */
    for (uint32_t i = 0; i < BUF_POOL_SIZE; i++) {
        struct buf *bp = &buf_pool[i];
        bp->flags = 0;
        bp->dev = 0;
        bp->block_no = 0;
        bp->refcount = 0;
        bp->data = buf_data[i];
        bp->lru_next = NULL;
        bp->lru_prev = NULL;
        bp->hash_next = NULL;
        lru_insert_head(bp);
    }

    spin_unlock_irqrestore(&buf_lock, flags);

    kprintf("[buf] buffer cache initialized: %u buffers, %u bytes each\n",
            BUF_POOL_SIZE, BUF_BLOCK_SIZE);
}

struct buf *buf_read(uint32_t dev, uint64_t block_no)
{
    uint64_t flags;
    spin_lock_irqsave(&buf_lock, &flags);

    /* Cache hit? */
    struct buf *bp = hash_lookup(dev, block_no);
    if (bp) {
        /* Wait if busy (simple spin -- in production, sleep on condvar) */
        if (bp->flags & B_BUSY) {
            /*
             * For a single-threaded polling driver this shouldn't happen.
             * In a full implementation we'd sleep here. For now, fail.
             */
            spin_unlock_irqrestore(&buf_lock, flags);
            kprintf("[buf] block %lu busy, cannot acquire\n", block_no);
            return NULL;
        }

        bp->flags |= B_BUSY;
        bp->refcount++;
        /* Move to head of LRU (most recently used) */
        lru_remove(bp);
        lru_insert_head(bp);

        spin_unlock_irqrestore(&buf_lock, flags);
        return bp;
    }

    /*
     * Cache miss -- find a victim from the LRU tail (least recently used).
     * Skip buffers that are currently busy.
     */
    struct buf *victim = lru_tail;
    while (victim && (victim->flags & B_BUSY))
        victim = victim->lru_prev;

    if (!victim) {
        spin_unlock_irqrestore(&buf_lock, flags);
        kprintf("[buf] no free buffers available\n");
        return NULL;
    }

    bp = victim;

    /* If the victim is dirty, flush it to disk before reusing */
    if (bp->flags & B_DIRTY) {
        /*
         * We must drop the lock during I/O. Mark the buffer busy first
         * so nobody else can claim it.
         */
        bp->flags |= B_BUSY;
        spin_unlock_irqrestore(&buf_lock, flags);

        if (buf_do_write(bp) != 0)
            kprintf("[buf] warning: writeback failed for dev=%u blk=%lu\n",
                    bp->dev, bp->block_no);

        spin_lock_irqsave(&buf_lock, &flags);
    } else {
        bp->flags |= B_BUSY;
    }

    /* Remove from old hash bucket */
    hash_remove(bp);

    /* Reconfigure for new block */
    bp->dev = dev;
    bp->block_no = block_no;
    bp->flags = B_BUSY;   /* clear VALID and DIRTY */
    bp->refcount = 1;

    /* Insert into new hash bucket */
    hash_insert(bp);

    /* Move to head of LRU */
    lru_remove(bp);
    lru_insert_head(bp);

    /* Read the block from disk (drop lock during I/O) */
    spin_unlock_irqrestore(&buf_lock, flags);

    if (buf_do_read(bp) != 0) {
        kprintf("[buf] read failed for dev=%u blk=%lu\n", dev, block_no);
        /* Return the buffer anyway so caller can handle the error */
        spin_lock_irqsave(&buf_lock, &flags);
        bp->flags &= ~B_BUSY;
        bp->refcount = 0;
        hash_remove(bp);
        spin_unlock_irqrestore(&buf_lock, flags);
        return NULL;
    }

    return bp;
}

void buf_write(struct buf *bp)
{
    if (!bp)
        return;

    uint64_t flags;
    spin_lock_irqsave(&buf_lock, &flags);

    bp->flags |= B_DIRTY;

    spin_unlock_irqrestore(&buf_lock, flags);
}

void buf_release(struct buf *bp)
{
    if (!bp)
        return;

    uint64_t flags;
    spin_lock_irqsave(&buf_lock, &flags);

    bp->refcount--;
    if (bp->refcount == 0) {
        bp->flags &= ~B_BUSY;
        /* Move to head of LRU (most recently used) */
        lru_remove(bp);
        lru_insert_head(bp);
    }

    spin_unlock_irqrestore(&buf_lock, flags);
}

/*
 * buf_sync_internal - Flush all dirty buffers to disk.
 *
 * @quiet: if true, don't print status messages (for background sync)
 *
 * Returns number of buffers flushed.
 */
static uint32_t buf_sync_internal(bool quiet)
{
    uint32_t flushed = 0;

    for (uint32_t i = 0; i < BUF_POOL_SIZE; i++) {
        struct buf *bp = &buf_pool[i];
        uint64_t flags;

        spin_lock_irqsave(&buf_lock, &flags);

        if ((bp->flags & B_DIRTY) && !(bp->flags & B_BUSY)) {
            bp->flags |= B_BUSY;
            spin_unlock_irqrestore(&buf_lock, flags);

            if (buf_do_write(bp) != 0) {
                if (!quiet)
                    kprintf("[buf] sync: writeback failed for dev=%u blk=%lu\n",
                            bp->dev, bp->block_no);
            } else {
                flushed++;
            }

            spin_lock_irqsave(&buf_lock, &flags);
            bp->flags &= ~B_BUSY;
            spin_unlock_irqrestore(&buf_lock, flags);
        } else {
            spin_unlock_irqrestore(&buf_lock, flags);
        }
    }

    return flushed;
}

void buf_sync(void)
{
    kprintf("[buf] syncing dirty buffers...\n");
    uint32_t flushed = buf_sync_internal(false);
    kprintf("[buf] sync complete: %u buffers flushed\n", flushed);
}

/* ============================================================================
 * Background Sync Daemon (bufsync)
 *
 * Periodically flushes dirty buffers to disk. Similar to BSD's syncer
 * or the buffer flushing in macOS/Darwin.
 * ============================================================================ */

static void bufsync_thread(void *arg)
{
    (void)arg;

    kprintf("[bufsync] buffer sync daemon started\n");

    for (;;) {
        /* Sleep for the sync interval */
        thread_sleep_ticks(BUFSYNC_INTERVAL);

        /* Flush dirty buffers silently */
        (void)buf_sync_internal(true);
    }
}

void buf_start_sync_daemon(void)
{
    /* Use low priority (16) - above idle but not competing with normal tasks */
    struct thread *th = thread_create("bufsync", bufsync_thread, NULL, PRI_MIN + 16);
    if (th) {
        sched_enqueue(th);
        kprintf("[buf] started background sync daemon\n");
    } else {
        kprintf("[buf] warning: failed to start sync daemon\n");
    }
}
