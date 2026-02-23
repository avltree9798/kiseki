/*
 * Kiseki OS - TTY (Terminal) Subsystem Implementation
 *
 * Provides terminal line discipline with proper termios support.
 * The console TTY wraps the PL011 UART with canonical/raw modes,
 * echo control, signal generation, and window size tracking.
 *
 * This implements the same semantics as XNU's tty layer:
 *   - ICANON: line-buffered input with editing (backspace, kill)
 *   - !ICANON: raw input with VMIN/VTIME
 *   - ECHO/ECHOE: character echo and erase echo
 *   - ISIG: Ctrl-C -> SIGINT, Ctrl-\ -> SIGQUIT, Ctrl-Z -> SIGTSTP
 *   - OPOST/ONLCR: output processing (NL -> CR+NL)
 *   - ICRNL: input CR -> NL mapping
 */

#include <kern/tty.h>
#include <kern/kprintf.h>
#include <kern/proc.h>
#include <kern/vmm.h>
#include <kern/thread.h>
#include <drivers/uart.h>
#include <fs/vfs.h>

/* ============================================================================
 * Console TTY (the single terminal for QEMU serial / RPi UART)
 * ============================================================================ */

static struct tty console_tty;

/*
 * tty_init - Set up the console TTY with sane defaults.
 *
 * These defaults match what macOS/XNU sets for a new terminal:
 *   - Canonical mode with echo
 *   - CR->NL input mapping
 *   - NL->CRNL output processing
 *   - 8-bit no-parity
 *   - Standard control characters
 *   - 115200 baud
 *   - 80x24 window
 */
void tty_init(void)
{
    struct tty *tp = &console_tty;
    struct termios *t = &tp->t_termios;

    /* Clear everything */
    for (uint64_t i = 0; i < sizeof(*tp); i++)
        ((uint8_t *)tp)[i] = 0;

    /* Input flags: map CR to NL, enable flow control */
    t->c_iflag = ICRNL | IXON | IXANY | IMAXBEL;

    /* Output flags: post-process, NL->CRNL */
    t->c_oflag = OPOST | ONLCR | OXTABS;

    /* Control flags: 8-bit, enable receiver, local */
    t->c_cflag = CS8 | CREAD | CLOCAL;

    /* Local flags: canonical, echo, signal processing */
    t->c_lflag = ECHO | ECHOE | ECHOK | ECHOKE | ECHOCTL |
                 ICANON | ISIG | IEXTEN;

    /* Control characters - standard Unix defaults */
    t->c_cc[VEOF]     = 0x04;  /* Ctrl-D */
    t->c_cc[VEOL]     = 0xFF;  /* disabled */
    t->c_cc[VEOL2]    = 0xFF;  /* disabled */
    t->c_cc[VERASE]   = 0x7F;  /* DEL (backspace) */
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
    t->c_cc[VMIN]     = 1;     /* Min chars for raw read */
    t->c_cc[VTIME]    = 0;     /* No timeout */
    t->c_cc[VSTATUS]  = 0x14;  /* Ctrl-T */

    /* 115200 baud (matches QEMU PL011 default) */
    t->c_ispeed = B115200;
    t->c_ospeed = B115200;

    /* Default window size: 80x24 (standard VT100) */
    tp->t_winsize.ws_row = 24;
    tp->t_winsize.ws_col = 80;
    tp->t_winsize.ws_xpixel = 0;
    tp->t_winsize.ws_ypixel = 0;

    /* No foreground process group yet */
    tp->t_pgrp = 0;
    tp->t_session = 0;
    tp->t_flags = TTY_OPENED;

    /* Clear line buffer */
    tp->t_linepos = 0;
    tp->t_rawhead = 0;
    tp->t_rawtail = 0;
    tp->t_rawcount = 0;
}

struct tty *tty_get_console(void)
{
    return &console_tty;
}

/* ============================================================================
 * TTY ioctl
 * ============================================================================ */

/*
 * copy_to_user / copy_from_user helpers
 *
 * These translate user VA to PA via the current process's page tables
 * and copy data. This is needed because the kernel uses identity mapping
 * but user VAs are in a different address space.
 */
static int copy_to_user(uint64_t uva, const void *kbuf, size_t len)
{
    struct proc *p = proc_current();
    if (!p || !p->p_vmspace)
        return -EINVAL;

    const uint8_t *src = (const uint8_t *)kbuf;
    for (size_t i = 0; i < len; i++) {
        uint64_t pa = vmm_translate(p->p_vmspace->pgd, uva + i);
        if (pa == 0)
            return -EINVAL;
        *(uint8_t *)pa = src[i];
    }
    return 0;
}

static int copy_from_user(void *kbuf, uint64_t uva, size_t len)
{
    struct proc *p = proc_current();
    if (!p || !p->p_vmspace)
        return -EINVAL;

    uint8_t *dst = (uint8_t *)kbuf;
    for (size_t i = 0; i < len; i++) {
        uint64_t pa = vmm_translate(p->p_vmspace->pgd, uva + i);
        if (pa == 0)
            return -EINVAL;
        dst[i] = *(const uint8_t *)pa;
    }
    return 0;
}

int tty_ioctl(struct tty *tp, unsigned long cmd, uint64_t data)
{
    switch (cmd) {

    /* ---- Get terminal attributes ---- */
    case TIOCGETA: {
        int err = copy_to_user(data, &tp->t_termios, sizeof(struct termios));
        if (err < 0)
            return EINVAL;
        return 0;
    }

    /* ---- Set terminal attributes (immediate / drain / flush) ---- */
    case TIOCSETA:
    case TIOCSETAW:
    case TIOCSETAF: {
        struct termios new_t;
        int err = copy_from_user(&new_t, data, sizeof(struct termios));
        if (err < 0)
            return EINVAL;

        /* Preserve c_ispeed/c_ospeed if caller zeroed them */
        if (new_t.c_ispeed == 0)
            new_t.c_ispeed = tp->t_termios.c_ispeed;
        if (new_t.c_ospeed == 0)
            new_t.c_ospeed = tp->t_termios.c_ospeed;

        tp->t_termios = new_t;

        /* TIOCSETAF: also flush input buffer */
        if (cmd == TIOCSETAF) {
            tp->t_linepos = 0;
            tp->t_rawhead = 0;
            tp->t_rawtail = 0;
            tp->t_rawcount = 0;
        }
        return 0;
    }

    /* ---- Get window size ---- */
    case TIOCGWINSZ: {
        int err = copy_to_user(data, &tp->t_winsize, sizeof(struct winsize));
        if (err < 0)
            return EINVAL;
        return 0;
    }

    /* ---- Set window size ---- */
    case TIOCSWINSZ: {
        struct winsize new_ws;
        int err = copy_from_user(&new_ws, data, sizeof(struct winsize));
        if (err < 0)
            return EINVAL;
        /* Only send SIGWINCH if size actually changed */
        if (new_ws.ws_row != tp->t_winsize.ws_row ||
            new_ws.ws_col != tp->t_winsize.ws_col) {
            tp->t_winsize = new_ws;
            /* Send SIGWINCH to foreground process group */
            if (tp->t_pgrp > 0)
                signal_send_pgid(tp->t_pgrp, SIGWINCH);
        } else {
            tp->t_winsize = new_ws;
        }
        return 0;
    }

    /* ---- Set controlling terminal ---- */
    case TIOCSCTTY:
        tp->t_flags |= TTY_CTTY;
        {
            struct thread *cur = current_thread_get();
            if (cur && cur->task)
                tp->t_session = cur->task->pid;
        }
        return 0;

    /* ---- Release controlling terminal ---- */
    case TIOCNOTTY:
        tp->t_flags &= ~TTY_CTTY;
        tp->t_session = 0;
        tp->t_pgrp = 0;
        return 0;

    /* ---- Get foreground process group ---- */
    case TIOCGPGRP: {
        int pgrp = (int)tp->t_pgrp;
        /* If no pgrp set, return the calling process's pgrp */
        if (pgrp == 0) {
            struct proc *cp = proc_current();
            if (cp)
                pgrp = (int)cp->p_pgrp;
            else {
                struct thread *cur = current_thread_get();
                if (cur && cur->task)
                    pgrp = (int)cur->task->pid;
            }
        }
        int err = copy_to_user(data, &pgrp, sizeof(int));
        if (err < 0)
            return EINVAL;
        return 0;
    }

    /* ---- Set foreground process group ---- */
    case TIOCSPGRP: {
        int pgrp;
        int err = copy_from_user(&pgrp, data, sizeof(int));
        if (err < 0)
            return EINVAL;
        tp->t_pgrp = (pid_t)pgrp;
        return 0;
    }

    /* ---- Bytes available for reading ---- */
    case FIONREAD: {
        int avail;
        if (tp->t_termios.c_lflag & ICANON) {
            avail = tp->t_linepos;  /* Chars in line buffer */
        } else {
            avail = tp->t_rawcount; /* Chars in raw buffer */
        }
        int err = copy_to_user(data, &avail, sizeof(int));
        if (err < 0)
            return EINVAL;
        return 0;
    }

    /* ---- Set non-blocking I/O ---- */
    case FIONBIO:
        /* Handled at fd level, just return success */
        return 0;

    /* ---- Set/clear close-on-exec (at fd level) ---- */
    case FIOCLEX:
    case FIONCLEX:
        /* Handled at fd level by caller, just return success */
        return 0;

    /* ---- Output queue size ---- */
    case TIOCOUTQ: {
        int val = 0; /* UART has no software output queue */
        int err = copy_to_user(data, &val, sizeof(int));
        if (err < 0)
            return EINVAL;
        return 0;
    }

    default:
        kprintf("[tty] unknown ioctl cmd 0x%lx\n", cmd);
        return ENOTTY;
    }
}

/* ============================================================================
 * TTY Input from IRQ — signal generation and buffering
 *
 * Called from uart_irq_handler() in interrupt context.
 * Processes special characters (Ctrl-C, Ctrl-\, Ctrl-Z) for signal
 * generation regardless of whether any process is reading the TTY.
 * Buffers the character in the raw ring buffer for later tty_read().
 * ============================================================================ */

void tty_input_char(char c)
{
    struct tty *tp = &console_tty;
    struct termios *t = &tp->t_termios;

    /* Signal generation: check ISIG flag and special characters.
     * Uses tp->t_pgrp (the TTY's foreground process group), which is the
     * correct target per POSIX — NOT the currently running process. */
    if (t->c_lflag & ISIG) {
        if (c == (char)t->c_cc[VINTR] && tp->t_pgrp > 0) {
            signal_send_pgid(tp->t_pgrp, SIGINT);
            /* Don't buffer the character — it's consumed by signal */
            /* But we do need to echo ^C if ECHO is set */
            if (t->c_lflag & ECHO) {
                uart_putc('^');
                uart_putc('C');
                uart_putc('\r');
                uart_putc('\n');
            }
            /* Flush input buffers */
            tp->t_linepos = 0;
            tp->t_lineout = 0;
            return;
        }
        if (c == (char)t->c_cc[VQUIT] && tp->t_pgrp > 0) {
            signal_send_pgid(tp->t_pgrp, SIGQUIT);
            if (t->c_lflag & ECHO) {
                uart_putc('^');
                uart_putc('\\');
                uart_putc('\r');
                uart_putc('\n');
            }
            tp->t_linepos = 0;
            tp->t_lineout = 0;
            return;
        }
        if (c == (char)t->c_cc[VSUSP] && tp->t_pgrp > 0) {
            signal_send_pgid(tp->t_pgrp, SIGTSTP);
            if (t->c_lflag & ECHO) {
                uart_putc('^');
                uart_putc('Z');
                uart_putc('\r');
                uart_putc('\n');
            }
            tp->t_linepos = 0;
            tp->t_lineout = 0;
            return;
        }
    }

    /* Buffer the character in the raw ring buffer for tty_read() */
    if (tp->t_rawcount < (int)sizeof(tp->t_rawbuf)) {
        tp->t_rawbuf[tp->t_rawhead] = c;
        tp->t_rawhead = (tp->t_rawhead + 1) % (int)sizeof(tp->t_rawbuf);
        tp->t_rawcount++;
    }
    /* else: buffer full, character dropped */

    /*
     * Wake any thread sleeping in tty_getc() on &tp->t_rawcount.
     * This is the XNU wakeup(chan) pattern — called from IRQ context.
     */
    thread_wakeup_on(&tp->t_rawcount);
}

/* ============================================================================
 * TTY Read - Line discipline input processing
 * ============================================================================ */

/*
 * tty_getc - Get one character from the TTY's raw ring buffer.
 *
 * If the buffer is empty, the calling thread sleeps on the wait channel
 * &tp->t_rawcount via thread_sleep_on(). When the UART IRQ fires and
 * tty_input_char() places a character in the buffer, it calls
 * thread_wakeup_on(&tp->t_rawcount) to wake all sleeping readers.
 *
 * This is the standard XNU/BSD tsleep/wakeup pattern: the reader sleeps
 * on a wait channel and the interrupt handler wakes it. The CPU runs
 * the idle thread (which does WFI) while waiting, allowing the host/QEMU
 * to process I/O (network packets, serial input) without vCPU starvation.
 */
static char tty_getc(struct tty *tp)
{
    for (;;) {
        /* Check ring buffer first */
        if (tp->t_rawcount > 0) {
            char c = tp->t_rawbuf[tp->t_rawtail];
            tp->t_rawtail = (tp->t_rawtail + 1) % (int)sizeof(tp->t_rawbuf);
            tp->t_rawcount--;
            return c;
        }

        /* Fallback: if UART has data but IRQ hasn't fired yet, read directly */
        if (uart_rx_ready()) {
            char c = uart_getc();
            return c;
        }

        /*
         * No data available — sleep on &tp->t_rawcount until
         * tty_input_char() calls thread_wakeup_on() after buffering
         * a character. This deschedules the thread (TH_WAIT) so the
         * idle thread runs WFI, letting QEMU process I/O.
         */
        thread_sleep_on(&tp->t_rawcount, "tty_read");
    }
}

int64_t tty_read(struct tty *tp, void *ubuf, uint64_t count)
{
    struct proc *p = proc_current();
    if (!p || !p->p_vmspace)
        return -EINVAL;

    uint64_t uva = (uint64_t)ubuf;
    struct termios *t = &tp->t_termios;
    uint64_t nread = 0;

    if (t->c_lflag & ICANON) {
        /*
         * Canonical mode: line-buffered input.
         *
         * If there's unconsumed data in the line buffer from a previous
         * read, deliver that first. Otherwise, read a new line from UART
         * with editing support, then deliver from the buffer.
         *
         * This handles the common fgets() pattern of calling read(fd,buf,1)
         * repeatedly — the first call blocks for a line, subsequent calls
         * drain the buffer without re-reading.
         */

        /* If line buffer is empty or fully consumed, read a new line */
        if (tp->t_lineout >= tp->t_linepos) {
            tp->t_linepos = 0;
            tp->t_lineout = 0;

            for (;;) {
                char c = tty_getc(tp);

                /* Signal generation (ISIG) — use tp->t_pgrp (foreground pgrp) */
                if (t->c_lflag & ISIG) {
                    if (c == (char)t->c_cc[VINTR]) {
                        if (t->c_lflag & ECHO) {
                            uart_putc('^');
                            uart_putc('C');
                            uart_putc('\r');
                            uart_putc('\n');
                        }
                        tp->t_linepos = 0;
                        tp->t_lineout = 0;
                        if (tp->t_pgrp > 0)
                            signal_send_pgid(tp->t_pgrp, SIGINT);
                        return -EINTR;
                    }
                    if (c == (char)t->c_cc[VQUIT]) {
                        if (t->c_lflag & ECHO) {
                            uart_putc('^');
                            uart_putc('\\');
                            uart_putc('\r');
                            uart_putc('\n');
                        }
                        tp->t_linepos = 0;
                        tp->t_lineout = 0;
                        if (tp->t_pgrp > 0)
                            signal_send_pgid(tp->t_pgrp, SIGQUIT);
                        return -EINTR;
                    }
                    if (c == (char)t->c_cc[VSUSP]) {
                        if (t->c_lflag & ECHO) {
                            uart_putc('^');
                            uart_putc('Z');
                            uart_putc('\r');
                            uart_putc('\n');
                        }
                        tp->t_linepos = 0;
                        tp->t_lineout = 0;
                        if (tp->t_pgrp > 0)
                            signal_send_pgid(tp->t_pgrp, SIGTSTP);
                        return -EINTR;
                    }
                }

                /* EOF handling (Ctrl-D) */
                if (c == (char)t->c_cc[VEOF]) {
                    if (tp->t_linepos == 0)
                        return 0;  /* EOF at start = end of file */
                    break;         /* EOF with data = flush buffer */
                }

                /* Input CR->NL mapping */
                if ((t->c_iflag & ICRNL) && c == '\r')
                    c = '\n';

                /* Erase (backspace/DEL) */
                if (c == (char)t->c_cc[VERASE] || c == '\b' || c == 0x7F) {
                    if (tp->t_linepos > 0) {
                        tp->t_linepos--;
                        if (t->c_lflag & ECHOE) {
                            uart_putc('\b');
                            uart_putc(' ');
                            uart_putc('\b');
                        }
                    }
                    continue;
                }

                /* Kill line (Ctrl-U) */
                if (c == (char)t->c_cc[VKILL]) {
                    while (tp->t_linepos > 0) {
                        tp->t_linepos--;
                        if (t->c_lflag & ECHOK) {
                            uart_putc('\b');
                            uart_putc(' ');
                            uart_putc('\b');
                        }
                    }
                    if (t->c_lflag & ECHOK) {
                        uart_putc('\n');
                        uart_putc('\r');
                    }
                    continue;
                }

                /* Word erase (Ctrl-W) */
                if (c == (char)t->c_cc[VWERASE]) {
                    while (tp->t_linepos > 0 &&
                           tp->t_linebuf[tp->t_linepos - 1] == ' ') {
                        tp->t_linepos--;
                        if (t->c_lflag & ECHOE) {
                            uart_putc('\b');
                            uart_putc(' ');
                            uart_putc('\b');
                        }
                    }
                    while (tp->t_linepos > 0 &&
                           tp->t_linebuf[tp->t_linepos - 1] != ' ') {
                        tp->t_linepos--;
                        if (t->c_lflag & ECHOE) {
                            uart_putc('\b');
                            uart_putc(' ');
                            uart_putc('\b');
                        }
                    }
                    continue;
                }

                /* Echo */
                if (t->c_lflag & ECHO) {
                    if (c == '\n') {
                        uart_putc('\n');
                        if (t->c_oflag & ONLCR)
                            uart_putc('\r');
                    } else if ((unsigned char)c < 0x20 && c != '\t') {
                        if (t->c_lflag & ECHOCTL) {
                            uart_putc('^');
                            uart_putc(c + '@');
                        }
                    } else {
                        uart_putc(c);
                    }
                }

                /* Buffer the character */
                if (tp->t_linepos < (int)(sizeof(tp->t_linebuf) - 1))
                    tp->t_linebuf[tp->t_linepos++] = c;

                /* Newline completes the line */
                if (c == '\n')
                    break;
            }
        }

        /* Deliver from line buffer: copy min(available, count) bytes */
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
        /*
         * Raw / cbreak mode: return characters immediately.
         * VMIN = minimum chars, VTIME = timeout (tenths of sec).
         * For now, implement VMIN=1/VTIME=0 (blocking single-char read).
         */
        int vmin = t->c_cc[VMIN];
        if (vmin == 0) vmin = 1;

        while (nread < count && (int)nread < vmin) {
            char c = tty_getc(tp);

            /* Signal generation in raw mode — use tp->t_pgrp */
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

            /* Input CR->NL mapping */
            if ((t->c_iflag & ICRNL) && c == '\r')
                c = '\n';

            /* Echo in raw mode if ECHO is set */
            if (t->c_lflag & ECHO)
                uart_putc(c);

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

/* ============================================================================
 * TTY Write - Output processing
 * ============================================================================ */

int64_t tty_write(struct tty *tp, const void *ubuf, uint64_t count)
{
    struct proc *p = proc_current();
    if (!p || !p->p_vmspace)
        return -EINVAL;

    uint64_t uva = (uint64_t)ubuf;
    struct termios *t = &tp->t_termios;
    uint64_t nwritten = 0;

    for (uint64_t i = 0; i < count; i++) {
        uint64_t pa = vmm_translate(p->p_vmspace->pgd, uva + i);
        if (pa == 0)
            break;

        char c = *(const char *)pa;

        if (t->c_oflag & OPOST) {
            /* Output post-processing */
            if (c == '\n' && (t->c_oflag & ONLCR)) {
                uart_putc('\r');
                uart_putc('\n');
            } else {
                uart_putc(c);
            }
        } else {
            uart_putc(c);
        }

        nwritten++;
    }

    return (int64_t)nwritten;
}
