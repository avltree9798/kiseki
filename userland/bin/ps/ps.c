/*
 * ps - report process status
 *
 * Kiseki OS coreutils - macOS compatible
 *
 * Supports both BSD-style options (no dash): ps aux
 * and POSIX-style options (with dash): ps -ef
 *
 * BSD options:
 *   a    show processes for all users (with terminal)
 *   u    user-oriented format (USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND)
 *   x    show processes without controlling terminal
 *   
 * POSIX options:
 *   -e   select all processes
 *   -f   full format
 *   -p   select by PID
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

/* Process info structure */
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

/* Format modes */
enum format {
    FMT_DEFAULT,    /* PID TTY TIME CMD */
    FMT_BSD_U,      /* USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND */
    FMT_FULL,       /* UID PID PPID C STIME TTY TIME CMD */
    FMT_LONG,       /* F S UID PID PPID C PRI NI ADDR SZ WCHAN TTY TIME CMD */
};

/* Options */
static int opt_all_users = 0;   /* a: all users */
static int opt_all_procs = 0;   /* x/-e: include processes without tty */
static int opt_pid = -1;        /* -p PID */
static enum format opt_fmt = FMT_DEFAULT;

static void usage(void)
{
    fprintf(stderr, "Usage: %s [aux] [-ef] [-p pid]\n", progname);
    fprintf(stderr, "Report process status.\n\n");
    fprintf(stderr, "BSD options (no dash):\n");
    fprintf(stderr, "  a         show processes for all users\n");
    fprintf(stderr, "  u         user-oriented output format\n");
    fprintf(stderr, "  x         show processes without controlling terminal\n");
    fprintf(stderr, "\nPOSIX options (with dash):\n");
    fprintf(stderr, "  -e, -A    select all processes\n");
    fprintf(stderr, "  -f        full format listing\n");
    fprintf(stderr, "  -p pid    select by process ID\n");
    fprintf(stderr, "  --help    display this help\n");
}

/* Get username from UID (stub - just returns UID as string) */
static const char *get_username(uid_t uid)
{
    static char buf[16];
    if (uid == 0)
        return "root";
    snprintf(buf, sizeof(buf), "%u", uid);
    return buf;
}

/* Format CPU time as HH:MM:SS or MM:SS */
static void format_time(unsigned long ticks, char *buf, size_t bufsz)
{
    unsigned long total_secs = ticks / 100;
    unsigned long hours = total_secs / 3600;
    unsigned long mins = (total_secs % 3600) / 60;
    unsigned long secs = total_secs % 60;

    if (hours > 0)
        snprintf(buf, bufsz, "%lu:%02lu:%02lu", hours, mins, secs);
    else
        snprintf(buf, bufsz, "%lu:%02lu", mins, secs);
}

/* Format start time as HH:MM */
static void format_stime(unsigned long starttime, char *buf, size_t bufsz)
{
    unsigned long hours = (starttime / 3600) % 24;
    unsigned long mins = (starttime / 60) % 60;
    snprintf(buf, bufsz, "%02lu:%02lu", hours, mins);
}

/*
 * Kernel process info structure - must match kernel's kinfo_proc_brief.
 */
struct kinfo_proc_brief {
    int         kp_pid;
    int         kp_ppid;
    unsigned    kp_uid;
    unsigned    kp_gid;
    int         kp_state;
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

/* Get process list from kernel */
static int get_proc_list(struct proc_info *procs, int max_procs)
{
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

        p->vsz  = 4096;  /* Placeholder */
        p->rss  = 1024;  /* Placeholder */
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

/* Check if process matches selection criteria */
static int proc_matches(const struct proc_info *p)
{
    if (opt_pid >= 0 && p->pid != (pid_t)opt_pid)
        return 0;

    /* If neither -e/x nor a specified, show only current user's processes */
    if (!opt_all_procs && !opt_all_users && opt_pid < 0) {
        if (p->uid != getuid())
            return 0;
    }

    return 1;
}

/* Print header */
static void print_header(void)
{
    switch (opt_fmt) {
    case FMT_DEFAULT:
        printf("  PID TTY          TIME CMD\n");
        break;
    case FMT_BSD_U:
        printf("USER       PID  %%CPU %%MEM    VSZ   RSS TTY      STAT  TIME COMMAND\n");
        break;
    case FMT_FULL:
        printf("  UID   PID  PPID  C STIME TTY          TIME CMD\n");
        break;
    case FMT_LONG:
        printf("F S   UID   PID  PPID  C PRI  NI    VSZ   RSS TTY          TIME CMD\n");
        break;
    }
}

/* Print a process entry */
static void print_proc(const struct proc_info *p)
{
    char timebuf[32];
    char stimebuf[16];

    format_time(p->utime + p->stime, timebuf, sizeof(timebuf));

    switch (opt_fmt) {
    case FMT_DEFAULT:
        printf("%5d %-8s %8s %s\n",
               p->pid, p->tty, timebuf,
               p->args[0] ? p->args : p->comm);
        break;

    case FMT_BSD_U:
        /* USER PID %CPU %MEM VSZ RSS TTY STAT TIME COMMAND */
        printf("%-8s %5d   0.0  0.0 %6ld %5ld %-8s %c     %s %s\n",
               get_username(p->uid), p->pid,
               p->vsz, p->rss, p->tty, p->state,
               timebuf, p->args[0] ? p->args : p->comm);
        break;

    case FMT_FULL:
        format_stime(p->starttime, stimebuf, sizeof(stimebuf));
        printf("%5u %5d %5d  0 %s %-8s %8s %s\n",
               p->uid, p->pid, p->ppid,
               stimebuf, p->tty, timebuf,
               p->args[0] ? p->args : p->comm);
        break;

    case FMT_LONG:
        printf("%1d %c %5u %5d %5d  0 %3d %3d %6ld %5ld %-8s %8s %s\n",
               0, p->state, p->uid, p->pid, p->ppid,
               80, p->nice, p->vsz, p->rss,
               p->tty, timebuf,
               p->args[0] ? p->args : p->comm);
        break;
    }
}

/* Parse BSD-style options (no dash) */
static int parse_bsd_opts(const char *opts)
{
    while (*opts) {
        switch (*opts) {
        case 'a':
            opt_all_users = 1;
            break;
        case 'u':
            opt_fmt = FMT_BSD_U;
            break;
        case 'x':
            opt_all_procs = 1;
            break;
        case 'e':
            /* 'e' without dash is BSD style - show environment */
            /* We treat it same as showing all for simplicity */
            opt_all_procs = 1;
            break;
        case 'w':
            /* Wide output - ignore for now */
            break;
        default:
            return -1;
        }
        opts++;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            usage();
            return 0;
        }

        if (argv[i][0] == '-') {
            /* POSIX-style options */
            const char *p = &argv[i][1];
            if (*p == '-') {
                /* Long option */
                fprintf(stderr, "%s: unknown option '%s'\n", progname, argv[i]);
                return 1;
            }
            while (*p) {
                switch (*p) {
                case 'e':
                case 'A':
                    opt_all_procs = 1;
                    opt_all_users = 1;
                    break;
                case 'f':
                    opt_fmt = FMT_FULL;
                    break;
                case 'l':
                    opt_fmt = FMT_LONG;
                    break;
                case 'p':
                    if (*(p + 1)) {
                        opt_pid = atoi(p + 1);
                        goto next_arg;
                    } else if (i + 1 < argc) {
                        opt_pid = atoi(argv[++i]);
                        goto next_arg;
                    } else {
                        fprintf(stderr, "%s: option '-p' requires an argument\n", progname);
                        return 1;
                    }
                    break;
                case 'a':
                    opt_all_users = 1;
                    break;
                case 'u':
                    opt_fmt = FMT_BSD_U;
                    break;
                case 'x':
                    opt_all_procs = 1;
                    break;
                default:
                    fprintf(stderr, "%s: invalid option -- '%c'\n", progname, *p);
                    usage();
                    return 1;
                }
                p++;
            }
        } else {
            /* BSD-style options (no dash) */
            if (parse_bsd_opts(argv[i]) < 0) {
                fprintf(stderr, "%s: invalid option string '%s'\n", progname, argv[i]);
                usage();
                return 1;
            }
        }
        next_arg:;
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
