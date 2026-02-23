/*
 * Kiseki OS - Terminal I/O
 *
 * Needed for job control and line editing in the shell.
 */

#ifndef _LIBSYSTEM_TERMIOS_H
#define _LIBSYSTEM_TERMIOS_H

#include <types.h>

/* Control characters array size */
#define NCCS    20

/* c_cc subscripts */
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
#define VSTART      12
#define VSTOP       13
#define VLNEXT      14
#define VDISCARD    15
#define VMIN        16
#define VTIME       17
#define VSTATUS     18

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
#define IUTF8       0x00004000

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
#define NOKERNINFO  0x02000000
#define PENDIN      0x20000000
#define NOFLSH      0x80000000

/* tcsetattr optional actions */
#define TCSANOW     0
#define TCSADRAIN   1
#define TCSAFLUSH   2

/* tcflush queue selectors */
#define TCIFLUSH    1
#define TCOFLUSH    2
#define TCIOFLUSH   3

/* ioctl request codes for terminal operations */
#define TIOCGETA    0x40487413  /* Get termios (tcgetattr) */
#define TIOCSETA    0x80487414  /* Set termios (tcsetattr TCSANOW) */
#define TIOCSETAW   0x80487415  /* Set termios (tcsetattr TCSADRAIN) */
#define TIOCSETAF   0x80487416  /* Set termios (tcsetattr TCSAFLUSH) */
#define TIOCGPGRP   0x40047477  /* Get foreground pgrp */
#define TIOCSPGRP   0x80047476  /* Set foreground pgrp */
#define TIOCGWINSZ  0x40087468  /* Get window size */
#define TIOCSWINSZ  0x80087467  /* Set window size */
#define TIOCSCTTY   0x20007461  /* Set controlling terminal */
#define TIOCNOTTY   0x20007471  /* Release controlling terminal */

/* Window size structure */
struct winsize {
    uint16_t    ws_row;
    uint16_t    ws_col;
    uint16_t    ws_xpixel;
    uint16_t    ws_ypixel;
};

typedef unsigned long   tcflag_t;
typedef unsigned char   cc_t;
typedef unsigned long   speed_t;

struct termios {
    tcflag_t    c_iflag;        /* Input flags */
    tcflag_t    c_oflag;        /* Output flags */
    tcflag_t    c_cflag;        /* Control flags */
    tcflag_t    c_lflag;        /* Local flags */
    cc_t        c_cc[NCCS];     /* Control characters */
    speed_t     c_ispeed;       /* Input speed */
    speed_t     c_ospeed;       /* Output speed */
};

int     tcgetattr(int fd, struct termios *termios_p);
int     tcsetattr(int fd, int optional_actions, const struct termios *termios_p);
int     tcsendbreak(int fd, int duration);
int     tcdrain(int fd);
int     tcflush(int fd, int queue_selector);

speed_t cfgetispeed(const struct termios *termios_p);
speed_t cfgetospeed(const struct termios *termios_p);
int     cfsetispeed(struct termios *termios_p, speed_t speed);
int     cfsetospeed(struct termios *termios_p, speed_t speed);
void    cfmakeraw(struct termios *termios_p);

#endif /* _LIBSYSTEM_TERMIOS_H */
