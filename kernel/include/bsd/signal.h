/*
 * Kiseki OS - Signal Definitions
 *
 * POSIX-compatible signal numbers, sigaction, and mask operations.
 * Matches XNU/Darwin signal numbering.
 *
 * Reference: bsd/sys/signal.h (XNU)
 */

#ifndef _BSD_SIGNAL_H
#define _BSD_SIGNAL_H

#include <kiseki/types.h>

/* ============================================================================
 * Signal Numbers (XNU/POSIX-compatible)
 * ============================================================================ */

#define SIGHUP      1       /* Hangup */
#define SIGINT      2       /* Interrupt */
#define SIGQUIT     3       /* Quit */
#define SIGILL      4       /* Illegal instruction */
#define SIGTRAP     5       /* Trace/breakpoint trap */
#define SIGABRT     6       /* Abort */
#define SIGIOT      SIGABRT /* Compatibility alias */
#define SIGEMT      7       /* EMT instruction */
#define SIGFPE      8       /* Floating point exception */
#define SIGKILL     9       /* Kill (cannot be caught or ignored) */
#define SIGBUS      10      /* Bus error */
#define SIGSEGV     11      /* Segmentation fault */
#define SIGSYS      12      /* Bad system call */
#define SIGPIPE     13      /* Broken pipe */
#define SIGALRM     14      /* Alarm clock */
#define SIGTERM     15      /* Termination */
#define SIGURG      16      /* Urgent I/O condition */
#define SIGSTOP     17      /* Stop (cannot be caught or ignored) */
#define SIGTSTP     18      /* Interactive stop */
#define SIGCONT     19      /* Continue */
#define SIGCHLD     20      /* Child status change */
#define SIGTTIN     21      /* Background read from tty */
#define SIGTTOU     22      /* Background write to tty */
#define SIGIO       23      /* I/O possible */
#define SIGXCPU     24      /* CPU time limit exceeded */
#define SIGXFSZ     25      /* File size limit exceeded */
#define SIGVTALRM   26      /* Virtual time alarm */
#define SIGPROF     27      /* Profiling time alarm */
#define SIGWINCH    28      /* Window size change */
#define SIGINFO     29      /* Information request */
#define SIGUSR1     30      /* User-defined signal 1 */
#define SIGUSR2     31      /* User-defined signal 2 */

#define NSIG        32      /* Number of signals (1-31 valid, 0 unused) */

/* ============================================================================
 * Signal Action Flags
 * ============================================================================ */

#define SA_ONSTACK      0x0001  /* Deliver signal on alternate stack */
#define SA_RESTART      0x0002  /* Restart interrupted syscall */
#define SA_RESETHAND    0x0004  /* Reset handler to SIG_DFL on delivery */
#define SA_NOCLDSTOP    0x0008  /* Don't generate SIGCHLD for stopped children */
#define SA_NODEFER      0x0010  /* Don't block signal during handler */
#define SA_NOCLDWAIT    0x0020  /* Don't create zombies */
#define SA_SIGINFO      0x0040  /* Deliver with siginfo_t */

/* ============================================================================
 * Signal Disposition Constants
 * ============================================================================ */

#define SIG_DFL     ((sig_handler_t)0)      /* Default action */
#define SIG_IGN     ((sig_handler_t)1)      /* Ignore signal */
#define SIG_ERR     ((sig_handler_t)-1)     /* Error return */

/* ============================================================================
 * Signal Mask Operations (for sigprocmask)
 * ============================================================================ */

#define SIG_BLOCK       1   /* Block signals in set */
#define SIG_UNBLOCK     2   /* Unblock signals in set */
#define SIG_SETMASK     3   /* Set mask to provided set */

/* ============================================================================
 * Signal Set
 *
 * Bitmask: bit N represents signal N (bit 0 unused).
 * ============================================================================ */

typedef uint32_t sigset_t;

#define sigemptyset(set)        (*(set) = 0)
#define sigfillset(set)         (*(set) = ~(uint32_t)0)
#define sigaddset(set, sig)     (*(set) |= (1u << (sig)))
#define sigdelset(set, sig)     (*(set) &= ~(1u << (sig)))
#define sigismember(set, sig)   ((*(set) & (1u << (sig))) != 0)

/* ============================================================================
 * Signal Handler Types
 * ============================================================================ */

typedef void (*sig_handler_t)(int);

/*
 * siginfo_t - Signal information (simplified)
 */
typedef struct {
    int             si_signo;   /* Signal number */
    int             si_errno;   /* Error value */
    int             si_code;    /* Signal code (SI_USER, etc.) */
    pid_t           si_pid;     /* Sender's PID */
    uid_t           si_uid;     /* Sender's real UID */
    int             si_status;  /* Exit value or signal */
    void           *si_addr;    /* Faulting address (for SIGSEGV, SIGBUS) */
} siginfo_t;

/* si_code values */
#define SI_USER     0x10001     /* Sent by kill/pthread_kill */
#define SI_QUEUE    0x10002     /* Sent by sigqueue */
#define SI_TIMER    0x10003     /* Timer expiration */
#define SI_KERNEL   0x10004     /* Sent by kernel */

/* ============================================================================
 * struct sigaction
 * ============================================================================ */

struct sigaction {
    union {
        sig_handler_t   sa_handler;     /* Simple handler */
        void            (*sa_sigaction)(int, siginfo_t *, void *); /* SA_SIGINFO handler */
    };
    sigset_t        sa_mask;            /* Signals blocked during handler */
    int             sa_flags;           /* SA_ONSTACK, SA_RESTART, etc. */
};

/* ============================================================================
 * Per-process Signal State
 *
 * Embedded in struct task (to be added in future phase).
 * ============================================================================ */

struct sigacts {
    struct sigaction    actions[NSIG];   /* Per-signal action */
    sigset_t            pending;         /* Pending signal set */
    sigset_t            blocked;         /* Blocked signal mask */
    uint64_t            altstack_sp;     /* Alternate signal stack */
    uint64_t            altstack_size;   /* Alternate stack size */
    bool                altstack_active; /* Currently on alt stack */
};

/* ============================================================================
 * Signal API (kernel-internal)
 * ============================================================================ */

struct task;
struct thread;
struct trap_frame;

/*
 * signal_init - Initialize signal state for a task
 */
void signal_init(struct sigacts *sa);

/*
 * signal_send - Post a signal to a task
 *
 * @target: Target task
 * @sig:    Signal number (1-31)
 *
 * Returns 0 on success, -errno on failure.
 */
int signal_send(struct task *target, int sig);

/*
 * signal_send_pgid - Send a signal to all processes in a process group.
 *
 * @pgid: Process group ID
 * @sig:  Signal number (1-31)
 */
void signal_send_pgid(pid_t pgid, int sig);

/*
 * signal_check - Check for pending deliverable signals
 *
 * Called on return-to-user path. If a signal is pending and not blocked,
 * sets up the user stack frame for the signal handler.
 *
 * @th: Current thread
 * @tf: Current trap frame (for modifying ELR/SP on signal delivery)
 *
 * Returns true if a signal was delivered.
 */
bool signal_check(struct thread *th, struct trap_frame *tf);

/*
 * signal_return - Clean up after a signal handler returns (sigreturn)
 *
 * Restores the original trap frame from the signal trampoline.
 *
 * @tf: Trap frame (points to sigreturn's saved state)
 */
void signal_return(struct trap_frame *tf);

#endif /* _BSD_SIGNAL_H */
