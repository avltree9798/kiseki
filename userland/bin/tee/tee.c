/*
 * tee - read from standard input and write to standard output and files
 *
 * Usage: tee [OPTION]... [FILE]...
 *
 * Flags:
 *   -a  Append to the given FILEs, do not overwrite
 *   -i  Ignore the SIGINT signal
 *
 * Copy standard input to each FILE, and also to standard output.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define BUF_SIZE 8192

static void usage(void)
{
    fprintf(stderr, "Usage: tee [-ai] [FILE]...\n");
    exit(1);
}

int main(int argc, char *argv[])
{
    int opt_append = 0;
    int opt_ignore_int = 0;
    int i = 1;
    int ret = 0;

    /* Parse options */
    while (i < argc && argv[i][0] == '-' && argv[i][1] != '\0') {
        if (strcmp(argv[i], "--") == 0) {
            i++;
            break;
        }
        const char *arg = argv[i];
        for (int j = 1; arg[j]; j++) {
            switch (arg[j]) {
            case 'a': opt_append = 1;     break;
            case 'i': opt_ignore_int = 1; break;
            default:
                fprintf(stderr, "tee: unknown option '-%c'\n", arg[j]);
                usage();
            }
        }
        i++;
    }

    if (opt_ignore_int)
        signal(SIGINT, SIG_IGN);

    /* Open output files */
    int nfiles = argc - i;
    int *fds = NULL;

    if (nfiles > 0) {
        fds = malloc((size_t)nfiles * sizeof(int));
        if (!fds) {
            fprintf(stderr, "tee: out of memory\n");
            return 1;
        }

        for (int f = 0; f < nfiles; f++) {
            int flags = O_WRONLY | O_CREAT;
            if (opt_append)
                flags |= O_APPEND;
            else
                flags |= O_TRUNC;

            fds[f] = open(argv[i + f], flags, 0666);
            if (fds[f] < 0) {
                fprintf(stderr, "tee: cannot open '%s': %s\n",
                        argv[i + f], strerror(errno));
                fds[f] = -1;
                ret = 1;
            }
        }
    }

    /* Read from stdin, write to stdout and all files */
    char buf[BUF_SIZE];
    ssize_t n;

    while ((n = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
        /* Write to stdout */
        ssize_t written = 0;
        while (written < n) {
            ssize_t w = write(STDOUT_FILENO, buf + written,
                              (size_t)(n - written));
            if (w < 0) {
                if (errno == EINTR)
                    continue;
                perror("tee: write to stdout");
                ret = 1;
                break;
            }
            written += w;
        }

        /* Write to each file */
        for (int f = 0; f < nfiles; f++) {
            if (fds[f] < 0)
                continue;

            written = 0;
            while (written < n) {
                ssize_t w = write(fds[f], buf + written,
                                  (size_t)(n - written));
                if (w < 0) {
                    if (errno == EINTR)
                        continue;
                    fprintf(stderr, "tee: write to '%s': %s\n",
                            argv[i + f], strerror(errno));
                    close(fds[f]);
                    fds[f] = -1;
                    ret = 1;
                    break;
                }
                written += w;
            }
        }
    }

    if (n < 0 && errno != EINTR) {
        perror("tee: read");
        ret = 1;
    }

    /* Close files */
    for (int f = 0; f < nfiles; f++) {
        if (fds[f] >= 0)
            close(fds[f]);
    }
    free(fds);

    return ret;
}
