/*
 * Kiseki OS - /sbin/getty
 *
 * Opens a terminal device, configures it as the controlling terminal,
 * prints the login prompt, reads a username, and execs /bin/login.
 *
 * Proper implementation:
 *   1. Create a new session (setsid)
 *   2. Open the tty device from argv[1] (e.g., /dev/console)
 *   3. Set it as stdin/stdout/stderr via dup2
 *   4. Set it as the controlling terminal (TIOCSCTTY)
 *   5. Display /etc/issue, print login prompt
 *   6. Read username, exec /bin/login
 *
 * Usage: getty <tty-device>
 *
 * Boot chain:
 *   init -> getty -> login -> shell
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/ioctl.h>

/*
 * Get hostname from /etc/hostname (best effort).
 */
static void get_hostname(char *buf, int bufsz)
{
    int fd = open("/etc/hostname", O_RDONLY);
    if (fd >= 0) {
        int n = (int)read(fd, buf, bufsz - 1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            /* Strip trailing newline */
            int len = (int)strlen(buf);
            if (len > 0 && buf[len - 1] == '\n')
                buf[len - 1] = '\0';
            return;
        }
    }
    strcpy(buf, "kiseki");
}

/*
 * setup_terminal - Open the tty device and set up stdin/stdout/stderr.
 *
 * @tty_path: Path to the tty device (e.g., "/dev/console")
 *
 * Returns 0 on success, -1 on failure.
 */
static int setup_terminal(const char *tty_path)
{
    /*
     * Step 1: Create a new session.
     *
     * This detaches us from any previous controlling terminal and
     * makes us the session leader, which is required for TIOCSCTTY.
     */
    setsid();

    /*
     * Step 2: Close inherited file descriptors.
     *
     * These are the console sentinels inherited from init.
     * We'll replace them with proper device-backed fds.
     */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    /*
     * Step 3: Open the tty device.
     *
     * Since we just closed fd 0, the open() will return fd 0 (stdin).
     * We then dup2 it to stdout and stderr.
     */
    int tty_fd = open(tty_path, O_RDWR);
    if (tty_fd < 0) {
        /* Can't print — no stdout. Fatal. */
        _exit(1);
    }

    /* Ensure we got fd 0 (stdin) */
    if (tty_fd != STDIN_FILENO) {
        dup2(tty_fd, STDIN_FILENO);
        close(tty_fd);
    }

    /* Duplicate to stdout and stderr */
    dup2(STDIN_FILENO, STDOUT_FILENO);
    dup2(STDIN_FILENO, STDERR_FILENO);

    /*
     * Step 4: Set this as the controlling terminal.
     */
    ioctl(STDIN_FILENO, TIOCSCTTY, 0);

    /*
     * Step 5: Set default terminal parameters.
     *
     * Ensure canonical mode with echo so the login prompt works
     * properly. This handles the case where a previous session
     * may have left the terminal in raw mode.
     */
    struct termios tio;
    if (tcgetattr(STDIN_FILENO, &tio) == 0) {
        /* Ensure sane defaults */
        tio.c_iflag |= ICRNL | IXON;
        tio.c_oflag |= OPOST | ONLCR;
        tio.c_lflag |= ECHO | ECHOE | ECHOK | ICANON | ISIG;
        tio.c_cflag |= CS8 | CREAD | CLOCAL;
        tcsetattr(STDIN_FILENO, TCSANOW, &tio);
    }

    return 0;
}

int main(int argc, char *argv[])
{
    const char *tty_path = "/dev/console";

    /* Use the tty device specified on the command line, if provided */
    if (argc >= 2 && argv[1] != NULL && argv[1][0] != '\0') {
        tty_path = argv[1];
    }

    /* Set up the terminal device as our stdin/stdout/stderr */
    setup_terminal(tty_path);

    char hostname[256];
    get_hostname(hostname, sizeof(hostname));

    /* Print /etc/issue if it exists (like real getty) */
    {
        int fd = open("/etc/issue", O_RDONLY);
        if (fd >= 0) {
            char ibuf[512];
            int n;
            while ((n = (int)read(fd, ibuf, sizeof(ibuf))) > 0)
                write(STDOUT_FILENO, ibuf, n);
            close(fd);
        }
    }

    /* Login prompt loop */
    for (;;) {
        char username[256];

        printf("%s login: ", hostname);
        fflush(stdout);

        /* The kernel's TTY line discipline handles line editing and echo */
        if (fgets(username, sizeof(username), stdin) == NULL)
            continue;

        /* Strip trailing newline */
        int len = (int)strlen(username);
        if (len > 0 && username[len - 1] == '\n')
            username[len - 1] = '\0';

        /* Skip empty input */
        if (username[0] == '\0')
            continue;

        /* Exec login with the username */
        char *login_argv[] = { "login", username, NULL };
        char *login_envp[] = {
            "PATH=/bin:/sbin:/usr/bin:/usr/sbin",
            "HOME=/root",
            "TERM=vt100",
            NULL
        };

        execve("/bin/login", login_argv, login_envp);

        /* If exec failed, print error and retry */
        printf("getty: cannot exec /bin/login\n");
        break;
    }

    return 1;
}
