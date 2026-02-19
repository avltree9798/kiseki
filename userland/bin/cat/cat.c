/*
 * cat - concatenate files and print on standard output
 *
 * Kiseki OS coreutils
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

static const char *progname = "cat";

static void usage(void)
{
    fprintf(stderr, "Usage: %s [OPTION]... [FILE]...\n", progname);
    fprintf(stderr, "Concatenate FILE(s) to standard output.\n\n");
    fprintf(stderr, "With no FILE, or when FILE is -, read standard input.\n\n");
    fprintf(stderr, "  -n    number all output lines\n");
    fprintf(stderr, "  -b    number non-blank output lines (overrides -n)\n");
    fprintf(stderr, "  -s    suppress repeated empty output lines\n");
    fprintf(stderr, "  -E    display $ at end of each line\n");
    fprintf(stderr, "  --help display this help and exit\n");
}

static int cat_fd(int fd, int opt_n, int opt_b, int opt_s, int opt_E,
                  int *lineno)
{
    char buf[4096];
    /* Line-oriented processing when options require it */
    int need_line_mode = opt_n || opt_b || opt_s || opt_E;

    if (!need_line_mode) {
        /* Fast path: raw copy */
        ssize_t n;
        while ((n = read(fd, buf, sizeof(buf))) > 0) {
            ssize_t written = 0;
            while (written < n) {
                ssize_t w = write(STDOUT_FILENO, buf + written,
                                  (size_t)(n - written));
                if (w < 0) {
                    fprintf(stderr, "%s: write error: %s\n", progname,
                            strerror(errno));
                    return 1;
                }
                written += w;
            }
        }
        if (n < 0) {
            fprintf(stderr, "%s: read error: %s\n", progname,
                    strerror(errno));
            return 1;
        }
        return 0;
    }

    /* Line-oriented path */
    FILE *fp = fdopen(fd, "r");
    if (!fp) {
        fprintf(stderr, "%s: fdopen: %s\n", progname, strerror(errno));
        return 1;
    }

    int prev_blank = 0;
    char line[8192];

    while (fgets(line, (int)sizeof(line), fp) != NULL) {
        size_t len = strlen(line);
        int is_blank = (len == 1 && line[0] == '\n') ||
                       (len == 0);

        /* Squeeze blank lines */
        if (opt_s && is_blank) {
            if (prev_blank)
                continue;
            prev_blank = 1;
        } else {
            prev_blank = 0;
        }

        /* Number lines */
        if (opt_b) {
            if (!is_blank)
                printf("%6d\t", (*lineno)++);
        } else if (opt_n) {
            printf("%6d\t", (*lineno)++);
        }

        /* Print line content */
        if (opt_E) {
            /* Print everything except trailing newline, then $ then newline */
            if (len > 0 && line[len - 1] == '\n') {
                if (len > 1)
                    fwrite(line, 1, len - 1, stdout);
                fputs("$\n", stdout);
            } else {
                fputs(line, stdout);
            }
        } else {
            fputs(line, stdout);
        }
    }

    if (ferror(fp)) {
        fprintf(stderr, "%s: read error: %s\n", progname, strerror(errno));
        /* Don't fclose — it would close the fd we don't own for stdin */
        return 1;
    }

    /* Don't fclose stdin's fd */
    if (fd != STDIN_FILENO)
        fclose(fp);

    return 0;
}

int main(int argc, char *argv[])
{
    int opt_n = 0, opt_b = 0, opt_s = 0, opt_E = 0;
    int first_file = argc; /* index of first non-option argument */

    /* Parse options */
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-' && argv[i][1] != '\0') {
            if (strcmp(argv[i], "--help") == 0) {
                usage();
                return 0;
            }
            if (strcmp(argv[i], "--") == 0) {
                first_file = i + 1;
                break;
            }
            if (strcmp(argv[i], "-") == 0) {
                /* stdin marker, not an option */
                first_file = i;
                break;
            }
            /* Parse bundled flags: -nbsE */
            const char *p = &argv[i][1];
            while (*p) {
                switch (*p) {
                case 'n': opt_n = 1; break;
                case 'b': opt_b = 1; break;
                case 's': opt_s = 1; break;
                case 'E': opt_E = 1; break;
                default:
                    fprintf(stderr, "%s: invalid option -- '%c'\n",
                            progname, *p);
                    usage();
                    return 1;
                }
                p++;
            }
        } else {
            first_file = i;
            break;
        }
    }

    int lineno = 1;
    int ret = 0;

    if (first_file >= argc) {
        /* No files specified: read stdin */
        ret = cat_fd(STDIN_FILENO, opt_n, opt_b, opt_s, opt_E, &lineno);
    } else {
        for (int i = first_file; i < argc; i++) {
            int fd;
            if (strcmp(argv[i], "-") == 0) {
                fd = STDIN_FILENO;
            } else {
                fd = open(argv[i], O_RDONLY);
                if (fd < 0) {
                    fprintf(stderr, "%s: %s: %s\n", progname, argv[i],
                            strerror(errno));
                    ret = 1;
                    continue;
                }
            }
            if (cat_fd(fd, opt_n, opt_b, opt_s, opt_E, &lineno) != 0)
                ret = 1;
            if (fd != STDIN_FILENO)
                close(fd);
        }
    }

    fflush(stdout);
    return ret;
}
