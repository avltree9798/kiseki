/*
 * Kiseki OS - POSIX Wrapper Implementation
 *
 * Thin wrappers around raw syscalls. Each sets errno on failure.
 */

#include <unistd.h>
#include <errno.h>
#include <syscall.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>

/* Helper: convert syscall return to libc convention (-1 + errno) */
static inline long _check(long ret)
{
    if (ret < 0) {
        errno = (int)(-ret);
        return -1;
    }
    return ret;
}

/* ============================================================================
 * File I/O
 * ============================================================================ */

ssize_t read(int fd, void *buf, size_t count)
{
    return (ssize_t)_check(syscall3(SYS_read, fd, (long)buf, (long)count));
}

ssize_t write(int fd, const void *buf, size_t count)
{
    return (ssize_t)_check(syscall3(SYS_write, fd, (long)buf, (long)count));
}

int close(int fd)
{
    return (int)_check(syscall1(SYS_close, fd));
}

off_t lseek(int fd, off_t offset, int whence)
{
    return (off_t)_check(syscall3(SYS_lseek, fd, (long)offset, whence));
}

int dup(int oldfd)
{
    return (int)_check(syscall1(SYS_dup, oldfd));
}

int dup2(int oldfd, int newfd)
{
    return (int)_check(syscall2(SYS_dup2, oldfd, newfd));
}

int pipe(int pipefd[2])
{
    return (int)_check(syscall1(SYS_pipe, (long)pipefd));
}

int open(const char *pathname, int flags, ...)
{
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    return (int)_check(syscall3(SYS_open, (long)pathname, flags, (long)mode));
}

int fcntl(int fd, int cmd, ...)
{
    long arg = 0;
    va_list ap;
    va_start(ap, cmd);
    arg = va_arg(ap, long);
    va_end(ap);
    return (int)_check(syscall3(SYS_fcntl, fd, cmd, arg));
}

int creat(const char *pathname, mode_t mode)
{
    return open(pathname, O_WRONLY | O_CREAT | O_TRUNC, mode);
}

/* ============================================================================
 * Process control
 * ============================================================================ */

pid_t fork(void)
{
    return (pid_t)_check(syscall0(SYS_fork));
}

int execve(const char *pathname, char *const argv[], char *const envp[])
{
    return (int)_check(syscall3(SYS_execve, (long)pathname, (long)argv, (long)envp));
}

int execvp(const char *file, char *const argv[])
{
    /* If file contains '/', just call execve directly */
    if (strchr(file, '/'))
        return execve(file, argv, environ);

    /* Search PATH */
    const char *path = NULL;
    if (environ) {
        for (char **ep = environ; *ep; ep++) {
            if ((*ep)[0] == 'P' && (*ep)[1] == 'A' && (*ep)[2] == 'T' &&
                (*ep)[3] == 'H' && (*ep)[4] == '=') {
                path = *ep + 5;
                break;
            }
        }
    }
    if (path == NULL)
        path = "/bin:/usr/bin";

    char buf[PATH_MAX];
    const char *p = path;

    while (*p) {
        const char *end = p;
        while (*end && *end != ':')
            end++;

        size_t dirlen = (size_t)(end - p);
        if (dirlen == 0) {
            buf[0] = '.';
            dirlen = 1;
        } else {
            if (dirlen >= PATH_MAX - 1)
                dirlen = PATH_MAX - 2;
            memcpy(buf, p, dirlen);
        }

        buf[dirlen] = '/';
        size_t filelen = strlen(file);
        if (dirlen + 1 + filelen >= PATH_MAX) {
            p = *end ? end + 1 : end;
            continue;
        }
        memcpy(buf + dirlen + 1, file, filelen);
        buf[dirlen + 1 + filelen] = '\0';

        execve(buf, argv, environ);
        /* If execve returned, it failed. Continue searching unless EACCES. */

        p = *end ? end + 1 : end;
    }

    /* errno is set by the last execve failure */
    return -1;
}

int execv(const char *pathname, char *const argv[])
{
    return execve(pathname, argv, environ);
}

void _exit(int status)
{
    syscall1(SYS_exit, status);
    __builtin_unreachable();
}

/* ============================================================================
 * Process IDs
 * ============================================================================ */

pid_t getpid(void)
{
    return (pid_t)syscall0(SYS_getpid);
}

pid_t getppid(void)
{
    return (pid_t)syscall0(SYS_getppid);
}

uid_t getuid(void)
{
    return (uid_t)syscall0(SYS_getuid);
}

uid_t geteuid(void)
{
    return (uid_t)syscall0(SYS_geteuid);
}

gid_t getgid(void)
{
    return (gid_t)syscall0(SYS_getgid);
}

int setuid(uid_t uid)
{
    return (int)_check(syscall1(SYS_setuid, (long)uid));
}

/* ============================================================================
 * Session and process group
 * ============================================================================ */

pid_t setsid(void)
{
    return (pid_t)_check(syscall0(SYS_setsid));
}

int setpgid(pid_t pid, pid_t pgid)
{
    return (int)_check(syscall2(SYS_setpgid, (long)pid, (long)pgid));
}

pid_t getpgrp(void)
{
    return (pid_t)syscall0(SYS_getpgrp);
}

/*
 * tcgetpgrp/tcsetpgrp - implemented via ioctl on the fd.
 * These use TIOCGPGRP/TIOCSPGRP.
 */
pid_t tcgetpgrp(int fd)
{
    pid_t pgrp;
    long ret = syscall3(SYS_ioctl, fd, 0x40047477 /* TIOCGPGRP */, (long)&pgrp);
    if (ret < 0) {
        errno = (int)(-ret);
        return -1;
    }
    return pgrp;
}

int tcsetpgrp(int fd, pid_t pgrp)
{
    long ret = syscall3(SYS_ioctl, fd, 0x80047476 /* TIOCSPGRP */, (long)&pgrp);
    if (ret < 0) {
        errno = (int)(-ret);
        return -1;
    }
    return 0;
}

/* ============================================================================
 * File operations
 * ============================================================================ */

int access(const char *pathname, int mode)
{
    return (int)_check(syscall2(SYS_access, (long)pathname, mode));
}

int unlink(const char *pathname)
{
    return (int)_check(syscall1(SYS_unlink, (long)pathname));
}

int rmdir(const char *pathname)
{
    return (int)_check(syscall1(SYS_rmdir, (long)pathname));
}

int chdir(const char *path)
{
    return (int)_check(syscall1(SYS_chdir, (long)path));
}

char *getcwd(char *buf, size_t size)
{
    long ret = syscall2(SYS_getcwd, (long)buf, (long)size);
    if (ret < 0) {
        errno = (int)(-ret);
        return NULL;
    }
    return buf;
}

ssize_t readlink(const char *pathname, char *buf, size_t bufsiz)
{
    return (ssize_t)_check(syscall3(SYS_readlink, (long)pathname, (long)buf, (long)bufsiz));
}

int link(const char *oldpath, const char *newpath)
{
    return (int)_check(syscall2(SYS_link, (long)oldpath, (long)newpath));
}

int symlink(const char *target, const char *linkpath)
{
    return (int)_check(syscall2(SYS_symlink, (long)target, (long)linkpath));
}

int isatty(int fd)
{
    /*
     * Check if fd is a terminal by attempting tcgetattr (TIOCGETA ioctl).
     * If it succeeds, fd refers to a terminal.
     */
    char buf[128];  /* Large enough for struct termios */
    long ret = syscall3(SYS_ioctl, fd, 0x40487413 /* TIOCGETA */, (long)buf);
    if (ret < 0) {
        errno = ENOTTY;
        return 0;
    }
    return 1;
}

/* ============================================================================
 * Sleep
 * ============================================================================ */

/* struct timespec for nanosleep */
struct timespec {
    time_t  tv_sec;
    long    tv_nsec;
};

unsigned int sleep(unsigned int seconds)
{
    struct timespec req = { .tv_sec = seconds, .tv_nsec = 0 };
    struct timespec rem = { .tv_sec = 0, .tv_nsec = 0 };

    long ret = syscall2(SYS_nanosleep, (long)&req, (long)&rem);
    if (ret < 0) {
        errno = (int)(-ret);
        return (unsigned int)rem.tv_sec;
    }
    return 0;
}

int usleep(useconds_t usec)
{
    struct timespec req = {
        .tv_sec = usec / 1000000,
        .tv_nsec = (long)(usec % 1000000) * 1000
    };

    long ret = syscall2(SYS_nanosleep, (long)&req, (long)NULL);
    if (ret < 0) {
        errno = (int)(-ret);
        return -1;
    }
    return 0;
}

/* ============================================================================
 * stat wrappers (defined in sys/stat.h, implemented here)
 * ============================================================================ */

int stat(const char *pathname, struct stat *statbuf)
{
    return (int)_check(syscall2(SYS_stat, (long)pathname, (long)statbuf));
}

int fstat(int fd, struct stat *statbuf)
{
    return (int)_check(syscall2(SYS_fstat, fd, (long)statbuf));
}

int lstat(const char *pathname, struct stat *statbuf)
{
    return (int)_check(syscall2(SYS_lstat, (long)pathname, (long)statbuf));
}

int mkdir(const char *pathname, mode_t mode)
{
    return (int)_check(syscall2(SYS_mkdir, (long)pathname, (long)mode));
}

int chmod(const char *pathname, mode_t mode)
{
    return (int)_check(syscall2(SYS_chmod, (long)pathname, (long)mode));
}

mode_t umask(mode_t mask)
{
    return (mode_t)syscall1(SYS_umask, (long)mask);
}

/* ============================================================================
 * wait wrappers (defined in sys/wait.h, implemented here)
 * ============================================================================ */

pid_t wait4(pid_t pid, int *status, int options, void *rusage)
{
    return (pid_t)_check(syscall4(SYS_wait4, (long)pid, (long)status,
                                  (long)options, (long)rusage));
}

pid_t waitpid(pid_t pid, int *status, int options)
{
    return wait4(pid, status, options, NULL);
}

pid_t wait(int *status)
{
    return waitpid(-1, status, 0);
}
