/*
 * Kiseki OS - TTY (Terminal) Subsystem
 *
 * Provides terminal line discipline, termios state, and ioctl handling.
 * Struct layouts match macOS arm64 exactly so userspace programs compiled
 * with the macOS SDK work unmodified.
 *
 * The console TTY wraps the UART driver with:
 *   - termios state (canonical mode, echo, signal generation)
 *   - winsize tracking
 *   - foreground process group
 *   - ioctl dispatch
 */

#ifndef _KERN_TTY_H
#define _KERN_TTY_H

#include <kiseki/types.h>

/* ============================================================================
 * termios — matches macOS arm64 layout exactly (72 bytes)
 *
 * On arm64 (LP64): tcflag_t = unsigned long (8 bytes)
 *                  cc_t     = unsigned char (1 byte)
 *                  speed_t  = unsigned long (8 bytes)
 * ============================================================================ */

typedef uint64_t tcflag_t;
typedef uint8_t  cc_t;
typedef uint64_t speed_t;

#define NCCS 20

struct termios {
    tcflag_t    c_iflag;        /* +0   input flags */
    tcflag_t    c_oflag;        /* +8   output flags */
    tcflag_t    c_cflag;        /* +16  control flags */
    tcflag_t    c_lflag;        /* +24  local flags */
    cc_t        c_cc[NCCS];     /* +32  control characters (20 bytes) */
    /* 4 bytes padding */       /* +52  (alignment to 8-byte boundary) */
    speed_t     c_ispeed;       /* +56  input speed */
    speed_t     c_ospeed;       /* +64  output speed */
};                              /* = 72 bytes total */

/* c_iflag bits */
#define IGNBRK      0x00000001
#define BRKINT      0x00000002
#define IGNPAR      0x00000004
#define PARMRK      0x00000008
#define INPCK       0x00000010
#define ISTRIP      0x00000020
#define INLCR       0x00000040
#define IGNCR       0x00000080
#define ICRNL       0x00000100
#define IXON        0x00000200
#define IXOFF       0x00000400
#define IXANY       0x00000800
#define IMAXBEL     0x00002000

/* c_oflag bits */
#define OPOST       0x00000001
#define ONLCR       0x00000002
#define OXTABS      0x00000004
#define ONOEOT      0x00000008

/* c_cflag bits */
#define CIGNORE     0x00000001
#define CSIZE       0x00000300
#define CS5         0x00000000
#define CS6         0x00000100
#define CS7         0x00000200
#define CS8         0x00000300
#define CSTOPB      0x00000400
#define CREAD       0x00000800
#define PARENB      0x00001000
#define PARODD      0x00002000
#define HUPCL       0x00004000
#define CLOCAL      0x00008000

/* c_lflag bits */
#define ECHOKE      0x00000001
#define ECHOE       0x00000002
#define ECHOK       0x00000004
#define ECHO        0x00000008
#define ECHONL      0x00000010
#define ECHOPRT     0x00000020
#define ECHOCTL     0x00000040
#define ISIG        0x00000080
#define ICANON      0x00000100
#define ALTWERASE   0x00000200
#define IEXTEN      0x00000400
#define EXTPROC     0x00000800
#define TOSTOP      0x00400000
#define FLUSHO      0x00800000
#define PENDIN      0x20000000
#define NOFLSH      0x80000000

/* c_cc indices */
#define VEOF        0
#define VEOL        1
#define VEOL2       2
#define VERASE      3
#define VWERASE     4
#define VKILL       5
#define VREPRINT    6
#define VINTR       8
#define VQUIT       9
#define VSUSP       10
#define VDSUSP      11
#define VSTART      12
#define VSTOP       13
#define VLNEXT      14
#define VDISCARD    15
#define VMIN        16
#define VTIME       17
#define VSTATUS     18

/* tcsetattr optional_actions */
#define TCSANOW     0
#define TCSADRAIN   1
#define TCSAFLUSH   2

/* Standard baud rate */
#define B9600       9600
#define B38400      38400
#define B115200     115200

/* ============================================================================
 * winsize — matches macOS arm64 layout exactly (8 bytes)
 * ============================================================================ */

struct winsize {
    uint16_t ws_row;        /* rows, in characters */
    uint16_t ws_col;        /* columns, in characters */
    uint16_t ws_xpixel;     /* horizontal size, pixels */
    uint16_t ws_ypixel;     /* vertical size, pixels */
};

/* ============================================================================
 * ioctl command encoding — matches macOS/XNU exactly
 * ============================================================================ */

#define IOCPARM_MASK    0x1fff
#define IOC_VOID        0x20000000UL
#define IOC_OUT         0x40000000UL
#define IOC_IN          0x80000000UL
#define IOC_INOUT       (IOC_IN | IOC_OUT)

#define _IOC(inout, group, num, len) \
    ((unsigned long)(inout) | (((unsigned long)(len) & IOCPARM_MASK) << 16) | \
     ((unsigned long)(group) << 8) | (unsigned long)(num))
#define _IO(g, n)       _IOC(IOC_VOID, (g), (n), 0)
#define _IOR(g, n, t)   _IOC(IOC_OUT,  (g), (n), sizeof(t))
#define _IOW(g, n, t)   _IOC(IOC_IN,   (g), (n), sizeof(t))
#define _IOWR(g, n, t)  _IOC(IOC_INOUT, (g), (n), sizeof(t))

/* Terminal ioctls */
#define TIOCGETA    _IOR('t', 19, struct termios)   /* 0x40487413 */
#define TIOCSETA    _IOW('t', 20, struct termios)   /* 0x80487414 */
#define TIOCSETAW   _IOW('t', 21, struct termios)   /* 0x80487415 */
#define TIOCSETAF   _IOW('t', 22, struct termios)   /* 0x80487416 */
#define TIOCGWINSZ  _IOR('t', 104, struct winsize)  /* 0x40087468 */
#define TIOCSWINSZ  _IOW('t', 103, struct winsize)  /* 0x80087467 */
#define TIOCSCTTY   _IO('t', 97)                    /* 0x20007461 */
#define TIOCNOTTY   _IO('t', 113)                   /* 0x20007471 */
#define TIOCGPGRP   _IOR('t', 119, int)             /* 0x40047477 */
#define TIOCSPGRP   _IOW('t', 118, int)             /* 0x80047476 */
#define TIOCOUTQ    _IOR('t', 115, int)             /* output queue size */

/* File ioctls */
#define FIONREAD    _IOR('f', 127, int)             /* 0x4004667F */
#define FIONBIO     _IOW('f', 126, int)             /* 0x8004667E */
#define FIOCLEX     _IO('f', 1)                     /* 0x20006601 */
#define FIONCLEX    _IO('f', 2)                     /* 0x20006602 */

/* ============================================================================
 * fcntl commands — matches macOS/XNU values
 * ============================================================================ */

#define F_DUPFD     0       /* Duplicate fd */
#define F_GETFD     1       /* Get fd flags */
#define F_SETFD     2       /* Set fd flags */
#define F_GETFL     3       /* Get file status flags */
#define F_SETFL     4       /* Set file status flags */
#define F_GETOWN    5       /* Get SIGIO/SIGURG process */
#define F_SETOWN    6       /* Set SIGIO/SIGURG process */

#define FD_CLOEXEC  1       /* Close-on-exec flag */

/* ============================================================================
 * TTY structure — per-terminal state
 * ============================================================================ */

struct tty {
    struct termios  t_termios;      /* Current terminal settings */
    struct winsize  t_winsize;      /* Terminal dimensions */
    pid_t           t_pgrp;         /* Foreground process group */
    pid_t           t_session;      /* Session leader PID */
    uint32_t        t_flags;        /* TTY flags */

    /* Line buffer for canonical mode */
    char            t_linebuf[1024];
    int             t_linepos;      /* Bytes written into line buffer (input side) */
    int             t_lineout;      /* Bytes consumed from line buffer (output side) */

    /* Input buffer for raw/cbreak mode */
    char            t_rawbuf[256];
    int             t_rawhead;
    int             t_rawtail;
    int             t_rawcount;

    /*
     * Wait channel for input: readers call thread_sleep_on(&tp->t_rawcount)
     * and the interrupt handler calls thread_wakeup_on(&tp->t_rawcount).
     * No extra field needed — the address of t_rawcount IS the wait channel.
     */
};

/* t_flags */
#define TTY_OPENED      0x0001
#define TTY_CTTY        0x0002      /* Is a controlling terminal */

/* ============================================================================
 * TTY API
 * ============================================================================ */

/*
 * tty_init - Initialize the console TTY with default settings.
 */
void tty_init(void);

/*
 * tty_get_console - Return the console TTY.
 */
struct tty *tty_get_console(void);

/*
 * tty_ioctl - Handle an ioctl on a TTY.
 *
 * @tp:   TTY structure
 * @cmd:  ioctl command
 * @data: User-space pointer to data (direction depends on cmd)
 *
 * Returns 0 on success, positive errno on error.
 */
int tty_ioctl(struct tty *tp, unsigned long cmd, uint64_t data);

/*
 * tty_read - Read from TTY respecting termios settings.
 *
 * In canonical mode (ICANON): reads a complete line.
 * In raw mode (!ICANON): reads available chars up to count.
 *
 * @tp:    TTY structure
 * @ubuf:  User-space buffer
 * @count: Maximum bytes to read
 *
 * Returns bytes read, or negative errno.
 */
int64_t tty_read(struct tty *tp, void *ubuf, uint64_t count);

/*
 * tty_write - Write to TTY respecting termios settings.
 *
 * Handles OPOST output processing (ONLCR, etc.)
 *
 * @tp:    TTY structure
 * @ubuf:  User-space buffer
 * @count: Bytes to write
 *
 * Returns bytes written, or negative errno.
 */
int64_t tty_write(struct tty *tp, const void *ubuf, uint64_t count);

#endif /* _KERN_TTY_H */
