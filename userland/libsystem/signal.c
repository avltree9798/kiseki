/*
 * Kiseki OS - Signal Wrapper Implementation
 */

#include <signal.h>
#include <errno.h>
#include <syscall.h>
#include <unistd.h>

sighandler_t signal(int signum, sighandler_t handler)
{
    struct sigaction sa, old;

    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    if (sigaction(signum, &sa, &old) < 0)
        return SIG_ERR;

    return old.sa_handler;
}

int sigaction(int signum, const struct sigaction *act,
              struct sigaction *oldact)
{
    long ret = syscall3(SYS_sigaction, (long)signum, (long)act, (long)oldact);
    if (ret < 0) {
        errno = (int)(-ret);
        return -1;
    }
    return 0;
}

int kill(pid_t pid, int sig)
{
    long ret = syscall2(SYS_kill, (long)pid, (long)sig);
    if (ret < 0) {
        errno = (int)(-ret);
        return -1;
    }
    return 0;
}

int raise(int sig)
{
    return kill(getpid(), sig);
}

int sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
    long ret = syscall3(SYS_sigprocmask, (long)how, (long)set, (long)oldset);
    if (ret < 0) {
        errno = (int)(-ret);
        return -1;
    }
    return 0;
}
