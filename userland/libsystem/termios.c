/*
 * Kiseki OS - Terminal I/O Implementation
 *
 * tcgetattr/tcsetattr implemented via ioctl syscalls.
 */

#include <termios.h>
#include <errno.h>
#include <syscall.h>

int tcgetattr(int fd, struct termios *termios_p)
{
    long ret = syscall3(SYS_ioctl, (long)fd, (long)TIOCGETA, (long)termios_p);
    if (ret < 0) {
        errno = (int)(-ret);
        return -1;
    }
    return 0;
}

int tcsetattr(int fd, int optional_actions, const struct termios *termios_p)
{
    unsigned long req;
    switch (optional_actions) {
    case TCSANOW:   req = TIOCSETA;  break;
    case TCSADRAIN: req = TIOCSETAW; break;
    case TCSAFLUSH: req = TIOCSETAF; break;
    default:
        errno = EINVAL;
        return -1;
    }

    long ret = syscall3(SYS_ioctl, (long)fd, (long)req, (long)termios_p);
    if (ret < 0) {
        errno = (int)(-ret);
        return -1;
    }
    return 0;
}

int tcsendbreak(int fd, int duration)
{
    (void)fd;
    (void)duration;
    /* Not implemented for now */
    return 0;
}

int tcdrain(int fd)
{
    (void)fd;
    /* Not implemented - assume all output is sent immediately */
    return 0;
}

int tcflush(int fd, int queue_selector)
{
    (void)fd;
    (void)queue_selector;
    /* Not implemented */
    return 0;
}

speed_t cfgetispeed(const struct termios *termios_p)
{
    return termios_p->c_ispeed;
}

speed_t cfgetospeed(const struct termios *termios_p)
{
    return termios_p->c_ospeed;
}

int cfsetispeed(struct termios *termios_p, speed_t speed)
{
    termios_p->c_ispeed = speed;
    return 0;
}

int cfsetospeed(struct termios *termios_p, speed_t speed)
{
    termios_p->c_ospeed = speed;
    return 0;
}

void cfmakeraw(struct termios *termios_p)
{
    termios_p->c_iflag &= ~(IMAXBEL | IXOFF | INPCK | BRKINT |
                             PARMRK | ISTRIP | INLCR | IGNCR |
                             ICRNL | IXON | IGNPAR);
    termios_p->c_iflag |= IGNBRK;
    termios_p->c_oflag &= ~OPOST;
    termios_p->c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL | ICANON |
                             ISIG | IEXTEN | NOFLSH | TOSTOP | PENDIN);
    termios_p->c_cflag &= ~(CSIZE | PARENB);
    termios_p->c_cflag |= CS8 | CREAD;
    termios_p->c_cc[VMIN] = 1;
    termios_p->c_cc[VTIME] = 0;
}
