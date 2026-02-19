/*
 * timeout - run a command with a time limit
 *
 * Runs COMMAND and kills it if it is still running after DURATION seconds.
 *
 * Usage: timeout [-s SIGNAL] DURATION COMMAND [args...]
 *
 *   -s SIGNAL   Signal to send on timeout (default: TERM/15)
 *   DURATION    Timeout in seconds (integer)
 *   COMMAND     Command to execute
 *
 * Exit codes:
 *   124 - Command timed out
 *   125 - timeout itself failed
 *   126 - COMMAND found but not executable
 *   127 - COMMAND not found
 *   Otherwise, the exit status of COMMAND
 *
 * Implementation: fork the command, then the parent polls wait4 in a loop
 * with nanosleep intervals, checking elapsed wall-clock time. If the child
 * hasn't exited before the deadline, send the signal and wait.
 *
 * Kiseki OS coreutils
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/wait.h>

/* gettimeofday struct */
struct kiseki_timeval {
    long tv_sec;
    long tv_usec;
};

static void usage(void)
{
    fprintf(stderr, "Usage: timeout [-s SIGNAL] DURATION COMMAND [args...]\n");
    fprintf(stderr, "Run COMMAND and kill it after DURATION seconds.\n\n");
    fprintf(stderr, "  -s SIGNAL   Signal to send (default: 15/TERM)\n");
    fprintf(stderr, "  DURATION    Timeout in seconds\n");
}

/*
 * Parse a simple positive integer from a string.
 * Returns -1 on error.
 */
static long parse_duration(const char *s)
{
    if (!s || *s == '\0')
        return -1;

    long val = 0;
    const char *p = s;

    while (*p) {
        if (*p < '0' || *p > '9')
            return -1;
        val = val * 10 + (*p - '0');
        p++;
    }
    return val;
}

/*
 * Parse a signal number or name.
 * Supports: numeric, TERM, KILL, HUP, INT, QUIT, ALRM, USR1, USR2
 */
static int parse_signal(const char *s)
{
    if (!s || *s == '\0')
        return -1;

    /* Numeric? */
    if (s[0] >= '0' && s[0] <= '9')
        return (int)parse_duration(s);

    /* Skip optional "SIG" prefix */
    const char *name = s;
    if (name[0] == 'S' && name[1] == 'I' && name[2] == 'G')
        name += 3;

    if (strcmp(name, "TERM") == 0) return SIGTERM;
    if (strcmp(name, "KILL") == 0) return SIGKILL;
    if (strcmp(name, "HUP")  == 0) return SIGHUP;
    if (strcmp(name, "INT")  == 0) return SIGINT;
    if (strcmp(name, "QUIT") == 0) return SIGQUIT;
    if (strcmp(name, "ALRM") == 0) return SIGALRM;
    if (strcmp(name, "USR1") == 0) return SIGUSR1;
    if (strcmp(name, "USR2") == 0) return SIGUSR2;

    return -1;
}

int main(int argc, char *argv[])
{
    int sig = SIGTERM;
    int optind_local = 1;

    if (argc < 3) {
        usage();
        return 125;
    }

    if (strcmp(argv[1], "--help") == 0) {
        usage();
        return 0;
    }

    /* Parse -s SIGNAL option */
    if (optind_local < argc && strcmp(argv[optind_local], "-s") == 0) {
        optind_local++;
        if (optind_local >= argc) {
            fprintf(stderr, "timeout: option -s requires an argument\n");
            return 125;
        }
        sig = parse_signal(argv[optind_local]);
        if (sig < 0) {
            fprintf(stderr, "timeout: invalid signal '%s'\n",
                    argv[optind_local]);
            return 125;
        }
        optind_local++;
    }

    if (optind_local >= argc) {
        fprintf(stderr, "timeout: missing DURATION\n");
        return 125;
    }

    /* Parse duration */
    long duration = parse_duration(argv[optind_local]);
    if (duration < 0) {
        fprintf(stderr, "timeout: invalid duration '%s'\n",
                argv[optind_local]);
        return 125;
    }
    optind_local++;

    if (optind_local >= argc) {
        fprintf(stderr, "timeout: missing COMMAND\n");
        return 125;
    }

    char **cmd_argv = &argv[optind_local];

    /* Fork the child */
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "timeout: fork: %s\n", strerror(errno));
        return 125;
    }

    if (pid == 0) {
        /* Child: exec the command */
        execvp(cmd_argv[0], cmd_argv);
        fprintf(stderr, "timeout: %s: %s\n", cmd_argv[0], strerror(errno));
        _exit(errno == ENOENT ? 127 : 126);
    }

    /* Parent: poll for child exit, checking time limit */
    struct kiseki_timeval start;
    gettimeofday((void *)&start, NULL);

    long deadline = start.tv_sec + duration;
    int timed_out = 0;

    while (1) {
        /* Non-blocking wait */
        int status = 0;
        pid_t w = waitpid(pid, &status, WNOHANG);

        if (w > 0) {
            /* Child exited */
            if (WIFEXITED(status))
                return WEXITSTATUS(status);
            if (WIFSIGNALED(status))
                return 128 + WTERMSIG(status);
            return 1;
        }

        if (w < 0 && errno != EINTR) {
            /* Unexpected error */
            fprintf(stderr, "timeout: waitpid: %s\n", strerror(errno));
            return 125;
        }

        /* Check if deadline passed */
        struct kiseki_timeval now;
        gettimeofday((void *)&now, NULL);

        if (now.tv_sec >= deadline) {
            timed_out = 1;
            break;
        }

        /* Sleep 50ms between polls to avoid busy-wait */
        usleep(50000);
    }

    if (timed_out) {
        /* Kill the child */
        kill(pid, sig);

        /* Wait for it to die (give it a moment) */
        usleep(100000);  /* 100ms grace */

        int status = 0;
        pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == 0) {
            /* Still alive, SIGKILL */
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
        }

        return 124;
    }

    /* Should not reach here */
    return 125;
}
