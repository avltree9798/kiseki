/*
 * Kiseki OS - Signal Handling (Userland)
 *
 * XNU/Darwin-compatible signal numbers and sigaction.
 */

#ifndef _LIBSYSTEM_SIGNAL_H
#define _LIBSYSTEM_SIGNAL_H

#include <types.h>

/* Signal numbers (XNU-compatible, matching kernel/include/bsd/signal.h) */
#define SIGHUP      1
#define SIGINT      2
#define SIGQUIT     3
#define SIGILL      4
#define SIGTRAP     5
#define SIGABRT     6
#define SIGIOT      SIGABRT
#define SIGEMT      7
#define SIGFPE      8
#define SIGKILL     9
#define SIGBUS      10
#define SIGSEGV     11
#define SIGSYS      12
#define SIGPIPE     13
#define SIGALRM     14
#define SIGTERM     15
#define SIGURG      16
#define SIGSTOP     17
#define SIGTSTP     18
#define SIGCONT     19
#define SIGCHLD     20
#define SIGTTIN     21
#define SIGTTOU     22
#define SIGIO       23
#define SIGXCPU     24
#define SIGXFSZ     25
#define SIGVTALRM   26
#define SIGPROF     27
#define SIGWINCH    28
#define SIGINFO     29
#define SIGUSR1     30
#define SIGUSR2     31

#define NSIG        32

/* Signal action flags */
#define SA_ONSTACK      0x0001
#define SA_RESTART      0x0002
#define SA_RESETHAND    0x0004
#define SA_NOCLDSTOP    0x0008
#define SA_NODEFER      0x0010
#define SA_NOCLDWAIT    0x0020
#define SA_SIGINFO      0x0040

/* Signal dispositions */
typedef void (*sighandler_t)(int);

#define SIG_DFL     ((sighandler_t)0)
#define SIG_IGN     ((sighandler_t)1)
#define SIG_ERR     ((sighandler_t)-1)

/* Signal set */
typedef uint32_t sigset_t;

static inline int sigemptyset(sigset_t *set) { *set = 0; return 0; }
static inline int sigfillset(sigset_t *set) { *set = ~(uint32_t)0; return 0; }
static inline int sigaddset(sigset_t *set, int sig) { *set |= (1u << sig); return 0; }
static inline int sigdelset(sigset_t *set, int sig) { *set &= ~(1u << sig); return 0; }
static inline int sigismember(const sigset_t *set, int sig) { return (*set & (1u << sig)) != 0; }

/* sigprocmask how */
#define SIG_BLOCK       1
#define SIG_UNBLOCK     2
#define SIG_SETMASK     3

/* siginfo_t */
typedef struct {
    int     si_signo;
    int     si_errno;
    int     si_code;
    pid_t   si_pid;
    uid_t   si_uid;
    int     si_status;
    void   *si_addr;
} siginfo_t;

#define SI_USER     0x10001
#define SI_QUEUE    0x10002
#define SI_TIMER    0x10003
#define SI_KERNEL   0x10004

/* struct sigaction */
struct sigaction {
    union {
        sighandler_t    sa_handler;
        void          (*sa_sigaction)(int, siginfo_t *, void *);
    };
    sigset_t    sa_mask;
    int         sa_flags;
};

/* Signal functions */
sighandler_t signal(int signum, sighandler_t handler);
int     sigaction(int signum, const struct sigaction *act,
                  struct sigaction *oldact);
int     kill(pid_t pid, int sig);
int     raise(int sig);
int     sigprocmask(int how, const sigset_t *set, sigset_t *oldset);

#endif /* _LIBSYSTEM_SIGNAL_H */
