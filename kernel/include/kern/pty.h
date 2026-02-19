/*
 * Kiseki OS - Pseudo-Terminal (PTY) Subsystem
 *
 * Implements BSD-style pseudo-terminal pairs for remote shell sessions (SSH).
 * Each PTY pair consists of:
 *   - Master side: read/write interface for the controlling process (e.g. sshd)
 *   - Slave side: appears as a regular TTY with full termios/line discipline
 *
 * Data flow:
 *   master write -> m2s buffer -> slave tty_read (with line discipline)
 *   slave tty_write -> s2m buffer -> master read
 *
 * The slave side reuses struct tty for termios, winsize, pgrp, and signal
 * generation — the same infrastructure used for the console UART TTY.
 *
 * Reference: Stevens APUE Chapter 19, XNU bsd/kern/tty_pty.c
 */

#ifndef _KERN_PTY_H
#define _KERN_PTY_H

#include <kiseki/types.h>
#include <kern/tty.h>
#include <kern/sync.h>

/* ============================================================================
 * PTY Configuration
 * ============================================================================ */

#define PTY_MAX         16          /* Maximum PTY pairs */
#define PTY_BUFSZ       4096        /* Ring buffer size per direction */

/* ============================================================================
 * PTY Pair Structure
 *
 * Bidirectional data path between master and slave.
 * ============================================================================ */

struct pty {
    bool            pt_active;      /* Slot is allocated */
    int             pt_index;       /* PTY index (0..PTY_MAX-1) */

    /* Slave TTY — full struct tty with termios, winsize, line discipline */
    struct tty      pt_slave_tty;

    /* Master -> Slave ring buffer (master write, slave read) */
    uint8_t         pt_m2s[PTY_BUFSZ];
    uint32_t        pt_m2s_head;    /* Write position */
    uint32_t        pt_m2s_tail;    /* Read position */
    uint32_t        pt_m2s_count;   /* Bytes in buffer */
    spinlock_t      pt_m2s_lock;

    /* Slave -> Master ring buffer (slave write, master read) */
    uint8_t         pt_s2m[PTY_BUFSZ];
    uint32_t        pt_s2m_head;    /* Write position */
    uint32_t        pt_s2m_tail;    /* Read position */
    uint32_t        pt_s2m_count;   /* Bytes in buffer */
    spinlock_t      pt_s2m_lock;

    /* Reference counts for master and slave sides */
    int             pt_master_open; /* Master side is open */
    int             pt_slave_open;  /* Slave side is open */
};

/* ============================================================================
 * PTY API
 * ============================================================================ */

/*
 * pty_init - Initialize the PTY subsystem.
 *
 * Clears the PTY pool. Called once during kernel startup.
 */
void pty_init(void);

/*
 * pty_alloc - Allocate a new PTY pair.
 *
 * Returns a pointer to the allocated pty struct, or NULL if
 * the pool is exhausted.
 */
struct pty *pty_alloc(void);

/*
 * pty_free - Release a PTY pair.
 *
 * @pp: PTY pair to release.
 */
void pty_free(struct pty *pp);

/*
 * pty_master_read - Read from master side (gets slave output).
 *
 * @pp:    PTY pair
 * @buf:   Kernel buffer to read into
 * @count: Maximum bytes to read
 *
 * Returns bytes read, or -EAGAIN if no data available.
 */
int64_t pty_master_read(struct pty *pp, void *buf, uint64_t count);

/*
 * pty_master_write - Write to master side (feeds slave input).
 *
 * @pp:    PTY pair
 * @buf:   Kernel buffer with data to write
 * @count: Bytes to write
 *
 * Returns bytes written, or -EAGAIN if buffer full.
 */
int64_t pty_master_write(struct pty *pp, const void *buf, uint64_t count);

/*
 * pty_slave_read - Read from slave side (with line discipline).
 *
 * Uses the slave's struct tty for termios processing (canonical mode,
 * echo, signal generation, etc.). Data comes from the m2s buffer
 * (written by master).
 *
 * @pp:    PTY pair
 * @ubuf:  User-space buffer
 * @count: Maximum bytes to read
 *
 * Returns bytes read, or negative errno.
 */
int64_t pty_slave_read(struct pty *pp, void *ubuf, uint64_t count);

/*
 * pty_slave_write - Write from slave side (with output processing).
 *
 * Applies OPOST/ONLCR processing and writes to s2m buffer
 * (readable by master).
 *
 * @pp:    PTY pair
 * @ubuf:  User-space buffer
 * @count: Bytes to write
 *
 * Returns bytes written, or negative errno.
 */
int64_t pty_slave_write(struct pty *pp, const void *ubuf, uint64_t count);

/*
 * pty_get_slave_tty - Get the slave TTY for ioctl handling.
 *
 * @pp: PTY pair
 *
 * Returns pointer to the slave's struct tty.
 */
static inline struct tty *pty_get_slave_tty(struct pty *pp)
{
    return &pp->pt_slave_tty;
}

#endif /* _KERN_PTY_H */
