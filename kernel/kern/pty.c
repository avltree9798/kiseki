/*
 * Kiseki OS - Pseudo-Terminal (PTY) Implementation
 *
 * Provides BSD-style PTY pairs for remote shell sessions.
 * Each pair has a master (controller) and slave (terminal) side.
 *
 * Data flow:
 *   master write -> m2s ring buffer -> slave reads (with line discipline)
 *   slave write -> s2m ring buffer -> master reads
 *
 * The slave side has a full struct tty with termios processing,
 * so shells and programs see it as a real terminal.
 */

#include <kern/pty.h>
#include <kern/kprintf.h>
#include <kern/proc.h>
#include <kern/vmm.h>
#include <kern/thread.h>
#include <drivers/uart.h>

/* ============================================================================
 * PTY Pool
 * ============================================================================ */

static struct pty pty_pool[PTY_MAX];
static spinlock_t pty_pool_lock = SPINLOCK_INIT;

/* ============================================================================
 * Initialization
 * ============================================================================ */

void pty_init(void)
{
    for (int i = 0; i < PTY_MAX; i++) {
        pty_pool[i].pt_active = false;
        pty_pool[i].pt_index  = i;
    }
    kprintf("[pty] PTY subsystem initialized (%d pairs)\n", PTY_MAX);
}

/* ============================================================================
 * PTY Allocation
 * ============================================================================ */

/*
 * Initialize slave TTY with sane defaults (same as console, but without
 * any UART binding — I/O goes through the ring buffers).
 */
static void pty_init_slave_tty(struct tty *tp)
{
    struct termios *t = &tp->t_termios;

    /* Zero everything */
    for (uint64_t i = 0; i < sizeof(*tp); i++)
        ((uint8_t *)tp)[i] = 0;

    /* Input flags */
    t->c_iflag = ICRNL | IXON | IXANY | IMAXBEL;

    /* Output flags */
    t->c_oflag = OPOST | ONLCR | OXTABS;

    /* Control flags */
    t->c_cflag = CS8 | CREAD | CLOCAL;

    /* Local flags: canonical, echo, signal processing */
    t->c_lflag = ECHO | ECHOE | ECHOK | ECHOKE | ECHOCTL |
                 ICANON | ISIG | IEXTEN;

    /* Control characters */
    t->c_cc[VEOF]     = 0x04;  /* Ctrl-D */
    t->c_cc[VEOL]     = 0xFF;
    t->c_cc[VEOL2]    = 0xFF;
    t->c_cc[VERASE]   = 0x7F;  /* DEL */
    t->c_cc[VWERASE]  = 0x17;  /* Ctrl-W */
    t->c_cc[VKILL]    = 0x15;  /* Ctrl-U */
    t->c_cc[VREPRINT] = 0x12;  /* Ctrl-R */
    t->c_cc[VINTR]    = 0x03;  /* Ctrl-C */
    t->c_cc[VQUIT]    = 0x1C;  /* Ctrl-\ */
    t->c_cc[VSUSP]    = 0x1A;  /* Ctrl-Z */
    t->c_cc[VDSUSP]   = 0x19;  /* Ctrl-Y */
    t->c_cc[VSTART]   = 0x11;  /* Ctrl-Q */
    t->c_cc[VSTOP]    = 0x13;  /* Ctrl-S */
    t->c_cc[VLNEXT]   = 0x16;  /* Ctrl-V */
    t->c_cc[VDISCARD] = 0x0F;  /* Ctrl-O */
    t->c_cc[VMIN]     = 1;
    t->c_cc[VTIME]    = 0;
    t->c_cc[VSTATUS]  = 0x14;  /* Ctrl-T */

    t->c_ispeed = B115200;
    t->c_ospeed = B115200;

    /* Default window size: 80x24 */
    tp->t_winsize.ws_row = 24;
    tp->t_winsize.ws_col = 80;

    tp->t_pgrp = 0;
    tp->t_session = 0;
    tp->t_flags = TTY_OPENED;
    tp->t_linepos = 0;
    tp->t_lineout = 0;
    tp->t_rawhead = 0;
    tp->t_rawtail = 0;
    tp->t_rawcount = 0;
}

struct pty *pty_alloc(void)
{
    uint64_t flags;
    spin_lock_irqsave(&pty_pool_lock, &flags);

    for (int i = 0; i < PTY_MAX; i++) {
        struct pty *pp = &pty_pool[i];
        if (!pp->pt_active) {
            pp->pt_active = true;

            /* Initialize ring buffers */
            pp->pt_m2s_head  = 0;
            pp->pt_m2s_tail  = 0;
            pp->pt_m2s_count = 0;
            spin_init(&pp->pt_m2s_lock);

            pp->pt_s2m_head  = 0;
            pp->pt_s2m_tail  = 0;
            pp->pt_s2m_count = 0;
            spin_init(&pp->pt_s2m_lock);

            pp->pt_master_open = 0;
            pp->pt_slave_open  = 0;

            /* Initialize slave TTY */
            pty_init_slave_tty(&pp->pt_slave_tty);

            spin_unlock_irqrestore(&pty_pool_lock, flags);

            kprintf("[pty] allocated pty%d\n", i);
            return pp;
        }
    }

    spin_unlock_irqrestore(&pty_pool_lock, flags);
    kprintf("[pty] pool exhausted\n");
    return NULL;
}

void pty_free(struct pty *pp)
{
    if (pp == NULL)
        return;

    uint64_t flags;
    spin_lock_irqsave(&pty_pool_lock, &flags);
    pp->pt_active = false;
    spin_unlock_irqrestore(&pty_pool_lock, flags);

    kprintf("[pty] freed pty%d\n", pp->pt_index);
}

/* ============================================================================
 * Master Side I/O
 *
 * Master read: drains s2m buffer (slave output).
 * Master write: fills m2s buffer (slave input).
 * ============================================================================ */

int64_t pty_master_read(struct pty *pp, void *buf, uint64_t count)
{
    uint8_t *dst = (uint8_t *)buf;
    uint32_t nread = 0;
    uint64_t flags;

    spin_lock_irqsave(&pp->pt_s2m_lock, &flags);

    while (nread < count && pp->pt_s2m_count > 0) {
        dst[nread] = pp->pt_s2m[pp->pt_s2m_tail];
        pp->pt_s2m_tail = (pp->pt_s2m_tail + 1) % PTY_BUFSZ;
        pp->pt_s2m_count--;
        nread++;
    }

    spin_unlock_irqrestore(&pp->pt_s2m_lock, flags);

    if (nread == 0) {
        /* Check if slave is still open */
        if (!pp->pt_slave_open)
            return 0;  /* EOF — slave closed */
        return -EAGAIN;
    }

    return (int64_t)nread;
}

int64_t pty_master_write(struct pty *pp, const void *buf, uint64_t count)
{
    const uint8_t *src = (const uint8_t *)buf;
    uint32_t nwritten = 0;
    uint64_t flags;

    spin_lock_irqsave(&pp->pt_m2s_lock, &flags);

    while (nwritten < count && pp->pt_m2s_count < PTY_BUFSZ) {
        pp->pt_m2s[pp->pt_m2s_head] = src[nwritten];
        pp->pt_m2s_head = (pp->pt_m2s_head + 1) % PTY_BUFSZ;
        pp->pt_m2s_count++;
        nwritten++;
    }

    spin_unlock_irqrestore(&pp->pt_m2s_lock, flags);

    if (nwritten == 0)
        return -EAGAIN;

    return (int64_t)nwritten;
}

/* ============================================================================
 * Slave Side I/O
 *
 * The slave side has a full TTY with line discipline. Data comes from
 * the m2s buffer (written by master) instead of from UART.
 *
 * This mirrors tty_read/tty_write in tty.c but reads from/writes to
 * the PTY ring buffers instead of UART.
 * ============================================================================ */

/*
 * pty_slave_getc - Get one character from the m2s buffer.
 *
 * Blocks (with yield) until data is available from the master.
 */
static char pty_slave_getc(struct pty *pp)
{
    for (;;) {
        uint64_t flags;
        spin_lock_irqsave(&pp->pt_m2s_lock, &flags);

        if (pp->pt_m2s_count > 0) {
            char c = (char)pp->pt_m2s[pp->pt_m2s_tail];
            pp->pt_m2s_tail = (pp->pt_m2s_tail + 1) % PTY_BUFSZ;
            pp->pt_m2s_count--;
            spin_unlock_irqrestore(&pp->pt_m2s_lock, flags);
            return c;
        }

        spin_unlock_irqrestore(&pp->pt_m2s_lock, flags);

        /* Check if master is gone */
        if (!pp->pt_master_open)
            return 0x04; /* EOF (Ctrl-D) */

        /* Yield while waiting for master to write */
        __asm__ volatile("yield");
    }
}

/*
 * pty_slave_putc - Output one character to the s2m buffer.
 *
 * Called during echo and output processing. The master reads this.
 */
static void pty_slave_putc(struct pty *pp, char c)
{
    uint64_t flags;
    spin_lock_irqsave(&pp->pt_s2m_lock, &flags);

    if (pp->pt_s2m_count < PTY_BUFSZ) {
        pp->pt_s2m[pp->pt_s2m_head] = (uint8_t)c;
        pp->pt_s2m_head = (pp->pt_s2m_head + 1) % PTY_BUFSZ;
        pp->pt_s2m_count++;
    }

    spin_unlock_irqrestore(&pp->pt_s2m_lock, flags);
}

/*
 * pty_slave_read - Read from slave TTY with line discipline.
 *
 * This is essentially tty_read() but adapted for PTY I/O.
 * In canonical mode, builds a line with editing support.
 * In raw mode, returns characters immediately.
 */
int64_t pty_slave_read(struct pty *pp, void *ubuf, uint64_t count)
{
    struct proc *p = proc_current();
    if (!p || !p->p_vmspace)
        return -EINVAL;

    uint64_t uva = (uint64_t)ubuf;
    struct tty *tp = &pp->pt_slave_tty;
    struct termios *t = &tp->t_termios;
    uint64_t nread = 0;

    if (t->c_lflag & ICANON) {
        /* Canonical mode: line-buffered */
        if (tp->t_lineout >= tp->t_linepos) {
            tp->t_linepos = 0;
            tp->t_lineout = 0;

            for (;;) {
                char c = pty_slave_getc(pp);

                /* Signal generation */
                if (t->c_lflag & ISIG) {
                    if (c == (char)t->c_cc[VINTR]) {
                        if (t->c_lflag & ECHO) {
                            pty_slave_putc(pp, '^');
                            pty_slave_putc(pp, 'C');
                            pty_slave_putc(pp, '\r');
                            pty_slave_putc(pp, '\n');
                        }
                        tp->t_linepos = 0;
                        tp->t_lineout = 0;
                        if (tp->t_pgrp > 0)
                            signal_send_pgid(tp->t_pgrp, SIGINT);
                        return -EINTR;
                    }
                    if (c == (char)t->c_cc[VQUIT]) {
                        if (t->c_lflag & ECHO) {
                            pty_slave_putc(pp, '^');
                            pty_slave_putc(pp, '\\');
                            pty_slave_putc(pp, '\r');
                            pty_slave_putc(pp, '\n');
                        }
                        tp->t_linepos = 0;
                        tp->t_lineout = 0;
                        if (tp->t_pgrp > 0)
                            signal_send_pgid(tp->t_pgrp, SIGQUIT);
                        return -EINTR;
                    }
                    if (c == (char)t->c_cc[VSUSP]) {
                        if (t->c_lflag & ECHO) {
                            pty_slave_putc(pp, '^');
                            pty_slave_putc(pp, 'Z');
                            pty_slave_putc(pp, '\r');
                            pty_slave_putc(pp, '\n');
                        }
                        tp->t_linepos = 0;
                        tp->t_lineout = 0;
                        if (tp->t_pgrp > 0)
                            signal_send_pgid(tp->t_pgrp, SIGTSTP);
                        return -EINTR;
                    }
                }

                /* EOF (Ctrl-D) */
                if (c == (char)t->c_cc[VEOF]) {
                    if (tp->t_linepos == 0)
                        return 0;  /* EOF */
                    break;
                }

                /* CR->NL mapping */
                if ((t->c_iflag & ICRNL) && c == '\r')
                    c = '\n';

                /* Erase */
                if (c == (char)t->c_cc[VERASE] || c == '\b' || c == 0x7F) {
                    if (tp->t_linepos > 0) {
                        tp->t_linepos--;
                        if (t->c_lflag & ECHOE) {
                            pty_slave_putc(pp, '\b');
                            pty_slave_putc(pp, ' ');
                            pty_slave_putc(pp, '\b');
                        }
                    }
                    continue;
                }

                /* Kill line */
                if (c == (char)t->c_cc[VKILL]) {
                    while (tp->t_linepos > 0) {
                        tp->t_linepos--;
                        if (t->c_lflag & ECHOK) {
                            pty_slave_putc(pp, '\b');
                            pty_slave_putc(pp, ' ');
                            pty_slave_putc(pp, '\b');
                        }
                    }
                    continue;
                }

                /* Word erase */
                if (c == (char)t->c_cc[VWERASE]) {
                    while (tp->t_linepos > 0 &&
                           tp->t_linebuf[tp->t_linepos - 1] == ' ') {
                        tp->t_linepos--;
                        if (t->c_lflag & ECHOE) {
                            pty_slave_putc(pp, '\b');
                            pty_slave_putc(pp, ' ');
                            pty_slave_putc(pp, '\b');
                        }
                    }
                    while (tp->t_linepos > 0 &&
                           tp->t_linebuf[tp->t_linepos - 1] != ' ') {
                        tp->t_linepos--;
                        if (t->c_lflag & ECHOE) {
                            pty_slave_putc(pp, '\b');
                            pty_slave_putc(pp, ' ');
                            pty_slave_putc(pp, '\b');
                        }
                    }
                    continue;
                }

                /* Echo */
                if (t->c_lflag & ECHO) {
                    if (c == '\n') {
                        pty_slave_putc(pp, '\n');
                        if (t->c_oflag & ONLCR)
                            pty_slave_putc(pp, '\r');
                    } else if ((unsigned char)c < 0x20 && c != '\t') {
                        if (t->c_lflag & ECHOCTL) {
                            pty_slave_putc(pp, '^');
                            pty_slave_putc(pp, c + '@');
                        }
                    } else {
                        pty_slave_putc(pp, c);
                    }
                }

                /* Buffer the character */
                if (tp->t_linepos < (int)(sizeof(tp->t_linebuf) - 1))
                    tp->t_linebuf[tp->t_linepos++] = c;

                /* Newline completes line */
                if (c == '\n')
                    break;
            }
        }

        /* Deliver from line buffer */
        int available = tp->t_linepos - tp->t_lineout;
        uint64_t to_copy = (uint64_t)available;
        if (to_copy > count)
            to_copy = count;

        for (uint64_t i = 0; i < to_copy; i++) {
            uint64_t pa = vmm_translate(p->p_vmspace->pgd, uva + i);
            if (pa == 0)
                break;
            *(uint8_t *)pa = (uint8_t)tp->t_linebuf[tp->t_lineout + (int)i];
            nread++;
        }
        tp->t_lineout += (int)nread;

    } else {
        /* Raw / cbreak mode */
        int vmin = t->c_cc[VMIN];
        if (vmin == 0) vmin = 1;

        while (nread < count && (int)nread < vmin) {
            char c = pty_slave_getc(pp);

            /* Signal generation in raw mode */
            if (t->c_lflag & ISIG) {
                if (c == (char)t->c_cc[VINTR]) {
                    if (tp->t_pgrp > 0)
                        signal_send_pgid(tp->t_pgrp, SIGINT);
                    return -EINTR;
                }
                if (c == (char)t->c_cc[VQUIT]) {
                    if (tp->t_pgrp > 0)
                        signal_send_pgid(tp->t_pgrp, SIGQUIT);
                    return -EINTR;
                }
                if (c == (char)t->c_cc[VSUSP]) {
                    if (tp->t_pgrp > 0)
                        signal_send_pgid(tp->t_pgrp, SIGTSTP);
                    return -EINTR;
                }
            }

            /* CR->NL mapping */
            if ((t->c_iflag & ICRNL) && c == '\r')
                c = '\n';

            /* Echo in raw mode */
            if (t->c_lflag & ECHO)
                pty_slave_putc(pp, c);

            /* Copy to user */
            uint64_t pa = vmm_translate(p->p_vmspace->pgd, uva + nread);
            if (pa == 0)
                break;
            *(uint8_t *)pa = (uint8_t)c;
            nread++;
        }
    }

    return (int64_t)nread;
}

/*
 * pty_slave_write - Write from slave with output processing.
 *
 * Applies OPOST/ONLCR and puts data into s2m buffer.
 */
int64_t pty_slave_write(struct pty *pp, const void *ubuf, uint64_t count)
{
    struct proc *p = proc_current();
    if (!p || !p->p_vmspace)
        return -EINVAL;

    uint64_t uva = (uint64_t)ubuf;
    struct termios *t = &pp->pt_slave_tty.t_termios;
    uint64_t nwritten = 0;

    for (uint64_t i = 0; i < count; i++) {
        uint64_t pa = vmm_translate(p->p_vmspace->pgd, uva + i);
        if (pa == 0)
            break;

        char c = *(const char *)pa;

        if (t->c_oflag & OPOST) {
            if (c == '\n' && (t->c_oflag & ONLCR)) {
                pty_slave_putc(pp, '\r');
                pty_slave_putc(pp, '\n');
            } else {
                pty_slave_putc(pp, c);
            }
        } else {
            pty_slave_putc(pp, c);
        }

        nwritten++;
    }

    return (int64_t)nwritten;
}
