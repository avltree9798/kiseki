/*
 * time - time a command execution
 *
 * Reports real (wall-clock), user CPU, and system CPU time
 * consumed by a command.
 *
 * Usage: time command [args...]
 *
 * Output (to stderr, matching traditional behaviour):
 *   real    0m1.234s
 *   user    0m0.456s
 *   sys     0m0.012s
 *
 * Kiseki OS coreutils
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/wait.h>

/* gettimeofday struct */
struct kiseki_timeval {
    long tv_sec;
    long tv_usec;
};

/* rusage struct — matches Darwin layout (enough for ru_utime/ru_stime) */
struct kiseki_rusage {
    struct kiseki_timeval ru_utime;    /* user time */
    struct kiseki_timeval ru_stime;    /* system time */
    /* remaining fields we don't care about */
    long ru_padding[14];
};

static void usage(void)
{
    fprintf(stderr, "Usage: time command [arguments...]\n");
    fprintf(stderr, "Time a command execution.\n");
}

/*
 * Print a timeval as Nm.NNNs format to stderr.
 */
static void print_time(const char *label, long sec, long usec)
{
    /* Normalize */
    if (usec < 0) {
        sec -= 1;
        usec += 1000000;
    }
    while (usec >= 1000000) {
        sec += 1;
        usec -= 1000000;
    }
    if (sec < 0) {
        sec = 0;
        usec = 0;
    }

    long minutes = sec / 60;
    long secs = sec % 60;
    long millis = usec / 1000;

    fprintf(stderr, "%s\t%ldm%ld.%03lds\n", label, minutes, secs, millis);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage();
        return 1;
    }

    if (strcmp(argv[1], "--help") == 0) {
        usage();
        return 0;
    }

    /* Record start time */
    struct kiseki_timeval start;
    gettimeofday((void *)&start, NULL);

    /* Fork and exec the command */
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "time: fork: %s\n", strerror(errno));
        return 1;
    }

    if (pid == 0) {
        /* Child: exec the command */
        execvp(argv[1], &argv[1]);
        /* If exec fails */
        fprintf(stderr, "time: %s: %s\n", argv[1], strerror(errno));
        _exit(errno == ENOENT ? 127 : 126);
    }

    /* Parent: wait for child with resource usage */
    int status = 0;
    struct kiseki_rusage ru;
    memset(&ru, 0, sizeof(ru));

    pid_t waited = wait4(pid, &status, 0, (void *)&ru);

    /* Record end time */
    struct kiseki_timeval end;
    gettimeofday((void *)&end, NULL);

    if (waited < 0) {
        fprintf(stderr, "time: wait4: %s\n", strerror(errno));
        return 1;
    }

    /* Compute wall clock (real) time */
    long real_sec = end.tv_sec - start.tv_sec;
    long real_usec = end.tv_usec - start.tv_usec;

    /* Print timing results to stderr */
    fprintf(stderr, "\n");
    print_time("real", real_sec, real_usec);
    print_time("user", ru.ru_utime.tv_sec, ru.ru_utime.tv_usec);
    print_time("sys", ru.ru_stime.tv_sec, ru.ru_stime.tv_usec);

    /* Return the child's exit status */
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    if (WIFSIGNALED(status))
        return 128 + WTERMSIG(status);
    return 1;
}
