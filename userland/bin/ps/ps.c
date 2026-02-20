/*
 * ps - report process status
 *
 * Kiseki OS coreutils
 *
 * Since Kiseki OS does not have a /proc filesystem, the actual process
 * data source must come from the kernel (e.g., a sysctl-style interface
 * or a dedicated syscall). This implementation provides complete option
 * parsing and output formatting, with a stub data source that the kernel
 * team can fill in.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

static const char *progname = "ps";

/* Process states */
#define PROC_RUNNING    'R'
#define PROC_SLEEPING   'S'
#define PROC_STOPPED    'T'
#define PROC_ZOMBIE     'Z'
#define PROC_IDLE       'I'

/* Maximum processes we can display */
#define MAX_PROCS       1024

/* Process info structure — what we need from the kernel */
struct proc_info {
    pid_t       pid;
    pid_t       ppid;
    uid_t       uid;
    gid_t       gid;
    char        state;
    int         nice;
    long        vsz;            /* Virtual memory size in KB */
    long        rss;            /* Resident set size in KB */
    char        tty[16];        /* TTY name */
    unsigned long utime;        /* User CPU time (ticks) */
    unsigned long stime;        /* System CPU time (ticks) */
    unsigned long starttime;    /* Start time (seconds since epoch) */
    char        comm[256];      /* Command name */
    char        args[1024];     /* Full command line */
};

/* Format mode */
enum format {
    FMT_BASIC,      /* PID TTY TIME CMD */
    FMT_FULL,       /* UID PID PPID C STIME TTY TIME CMD */
    FMT_LONG,       /* F S UID PID PPID C PRI NI ADDR SZ WCHAN TTY TIME CMD */
};

/* Options */
static int opt_all = 0;        /* -e/-A: all processes */
static int opt_pid = -1;       /* -p PID: specific process */
static const char *opt_user = NULL;  /* -u USER */
static enum format opt_fmt = FMT_BASIC;

static void usage(void)
{
    fprintf(stderr, "Usage: %s [-eAfl] [-p PID] [-u USER]\n", progname);
    fprintf(stderr, "Report process status.\n\n");
    fprintf(stderr, "  -e, -A    select all processes\n");
    fprintf(stderr, "  -f        full format listing\n");
    fprintf(stderr, "  -l        long format listing\n");
    fprintf(stderr, "  -p PID    select by process ID\n");
    fprintf(stderr, "  -u USER   select by effective user ID\n");
    fprintf(stderr, "  --help    display this help and exit\n");
}

/*
 * Format CPU time as HH:MM:SS or MM:SS.
 */
static void format_time(unsigned long ticks, char *buf, size_t bufsz)
{
    /* Assume 100 ticks per second */
    unsigned long total_secs = ticks / 100;
    unsigned long hours = total_secs / 3600;
    unsigned long mins = (total_secs % 3600) / 60;
    unsigned long secs = total_secs % 60;

    if (hours > 0)
        snprintf(buf, bufsz, "%lu:%02lu:%02lu", hours, mins, secs);
    else
        snprintf(buf, bufsz, "%02lu:%02lu", mins, secs);
}

/*
 * Format start time.
 * For simplicity, we just format as HH:MM since we don't have
 * a real time-of-day clock interface yet.
 */
static void format_stime(unsigned long starttime, char *buf, size_t bufsz)
{
    unsigned long hours = (starttime / 3600) % 24;
    unsigned long mins = (starttime / 60) % 60;
    snprintf(buf, bufsz, "%02lu:%02lu", hours, mins);
}

/*
 * Kernel process info structure — must match kernel's kinfo_proc_brief.
 * 128 bytes per entry.
 */
struct kinfo_proc_brief {
    int         kp_pid;
    int         kp_ppid;
    unsigned    kp_uid;
    unsigned    kp_gid;
    int         kp_state;       /* 0=unused,1=embryo,2=running,3=sleeping,4=stopped,5=zombie */
    int         kp_pad0;
    unsigned long kp_user_ticks;
    unsigned long kp_sys_ticks;
    unsigned long kp_start_time;
    char        kp_comm[32];
    int         kp_pgrp;
    int         kp_session;
    char        kp_pad1[40];
};

#define SYS_proc_info   336

static inline long raw_syscall2(long num, long a0, long a1)
{
    register long x16 __asm__("x16") = num;
    register long x0  __asm__("x0")  = a0;
    register long x1  __asm__("x1")  = a1;
    register long nzcv;

    __asm__ volatile(
        "svc    #0x80\n\t"
        "mrs    %[nzcv], nzcv"
        : [nzcv] "=r" (nzcv), "+r" (x0)
        : "r" (x16), "r" (x1)
        : "memory", "cc"
    );

    if (nzcv & (1L << 29))
        return -x0;
    return x0;
}

/*
 * Get process list from the kernel via SYS_proc_info.
 */
static int get_proc_list(struct proc_info *procs, int max_procs)
{
    /* Allocate kernel info buffer */
    int kmax = max_procs;
    if (kmax > 256)
        kmax = 256;

    struct kinfo_proc_brief *kbuf = malloc((size_t)kmax * sizeof(*kbuf));
    if (!kbuf)
        return 0;

    long nprocs = raw_syscall2(SYS_proc_info, (long)kbuf, (long)kmax);
    if (nprocs < 0) {
        free(kbuf);
        return 0;
    }

    int count = 0;
    for (long i = 0; i < nprocs && count < max_procs; i++) {
        struct kinfo_proc_brief *kp = &kbuf[i];
        struct proc_info *p = &procs[count];
        memset(p, 0, sizeof(*p));

        p->pid  = kp->kp_pid;
        p->ppid = kp->kp_ppid;
        p->uid  = kp->kp_uid;
        p->gid  = kp->kp_gid;

        switch (kp->kp_state) {
        case 2: p->state = PROC_RUNNING;  break;
        case 3: p->state = PROC_SLEEPING; break;
        case 4: p->state = PROC_STOPPED;  break;
        case 5: p->state = PROC_ZOMBIE;   break;
        case 1: p->state = PROC_IDLE;     break;
        default: p->state = '?';          break;
        }

        p->vsz  = 0;
        p->rss  = 0;
        p->nice = 0;
        strcpy(p->tty, "tty0");
        p->utime     = kp->kp_user_ticks;
        p->stime     = kp->kp_sys_ticks;
        p->starttime = kp->kp_start_time;

        strncpy(p->comm, kp->kp_comm, sizeof(p->comm) - 1);
        strncpy(p->args, kp->kp_comm, sizeof(p->args) - 1);

        count++;
    }

    free(kbuf);
    return count;
}

/*
 * Check if a process matches the selection criteria.
 */
static int proc_matches(const struct proc_info *p)
{
    if (opt_pid >= 0 && p->pid != (pid_t)opt_pid)
        return 0;

    if (opt_user != NULL) {
        /* Compare as UID number (since we don't have getpwnam) */
        char *endp;
        long uid = strtol(opt_user, &endp, 10);
        if (*endp == '\0') {
            if (p->uid != (uid_t)uid)
                return 0;
        }
        /* If opt_user is a name string, we can't resolve it without
         * a passwd database. Skip non-numeric user filters. */
    }

    if (!opt_all && opt_pid < 0 && opt_user == NULL) {
        /* Default: show only processes belonging to this terminal/user */
        if (p->uid != getuid())
            return 0;
    }

    return 1;
}

/*
 * Print the header line for the selected format.
 */
static void print_header(void)
{
    switch (opt_fmt) {
    case FMT_BASIC:
        printf("  PID TTY          TIME CMD\n");
        break;
    case FMT_FULL:
        printf("  UID   PID  PPID  C STIME TTY          TIME CMD\n");
        break;
    case FMT_LONG:
        printf("F S   UID   PID  PPID  C PRI  NI   VSZ   RSS "
               "TTY          TIME CMD\n");
        break;
    }
}

/*
 * Print a single process entry in the selected format.
 */
static void print_proc(const struct proc_info *p)
{
    char timebuf[32];
    char stimebuf[16];

    format_time(p->utime + p->stime, timebuf, sizeof(timebuf));

    switch (opt_fmt) {
    case FMT_BASIC:
        printf("%5d %-8s %8s %s\n",
               p->pid, p->tty, timebuf,
               p->args[0] ? p->args : p->comm);
        break;

    case FMT_FULL:
        format_stime(p->starttime, stimebuf, sizeof(stimebuf));
        printf("%5u %5d %5d  0 %s %-8s %8s %s\n",
               p->uid, p->pid, p->ppid,
               stimebuf, p->tty, timebuf,
               p->args[0] ? p->args : p->comm);
        break;

    case FMT_LONG: {
        int flags = 0;
        int pri = 80;  /* Default priority */
        printf("%1d %c %5u %5d %5d  0 %3d %3d %5ld %5ld %-8s %8s %s\n",
               flags, p->state, p->uid, p->pid, p->ppid,
               pri, p->nice, p->vsz, p->rss,
               p->tty, timebuf,
               p->args[0] ? p->args : p->comm);
        break;
    }
    }
}

int main(int argc, char *argv[])
{
    /* Parse options */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            usage();
            return 0;
        }

        if (argv[i][0] != '-') {
            fprintf(stderr, "%s: unexpected argument '%s'\n", progname,
                    argv[i]);
            usage();
            return 1;
        }

        /* Parse bundled flags */
        const char *p = &argv[i][1];
        while (*p) {
            switch (*p) {
            case 'e':
            case 'A':
                opt_all = 1;
                break;
            case 'f':
                opt_fmt = FMT_FULL;
                break;
            case 'l':
                opt_fmt = FMT_LONG;
                break;
            case 'p':
                /* -p PID */
                if (*(p + 1) != '\0') {
                    /* -pPID form */
                    opt_pid = atoi(p + 1);
                    p += strlen(p) - 1;  /* skip rest */
                } else if (i + 1 < argc) {
                    opt_pid = atoi(argv[++i]);
                } else {
                    fprintf(stderr, "%s: option '-p' requires an argument\n",
                            progname);
                    return 1;
                }
                break;
            case 'u':
                /* -u USER */
                if (*(p + 1) != '\0') {
                    opt_user = p + 1;
                    p += strlen(p) - 1;
                } else if (i + 1 < argc) {
                    opt_user = argv[++i];
                } else {
                    fprintf(stderr, "%s: option '-u' requires an argument\n",
                            progname);
                    return 1;
                }
                break;
            default:
                fprintf(stderr, "%s: invalid option -- '%c'\n", progname, *p);
                usage();
                return 1;
            }
            p++;
        }
    }

    /* Get process list */
    struct proc_info *procs = malloc(MAX_PROCS * sizeof(struct proc_info));
    if (!procs) {
        fprintf(stderr, "%s: out of memory\n", progname);
        return 1;
    }

    int nprocs = get_proc_list(procs, MAX_PROCS);

    /* Print header */
    print_header();

    /* Print matching processes */
    for (int i = 0; i < nprocs; i++) {
        if (proc_matches(&procs[i])) {
            print_proc(&procs[i]);
        }
    }

    free(procs);
    return 0;
}
