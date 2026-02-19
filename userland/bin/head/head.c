/*
 * head - output the first part of files
 *
 * Usage: head [OPTION]... [FILE]...
 *
 * Flags:
 *   -n NUM  Print the first NUM lines (default 10)
 *   -c NUM  Print the first NUM bytes
 *   -q      Never print headers giving file names
 *   -v      Always print headers giving file names
 *
 * With no FILE, or when FILE is -, read standard input.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static void usage(void)
{
    fprintf(stderr, "Usage: head [OPTION]... [FILE]...\n");
    fprintf(stderr, "  -n NUM  print the first NUM lines (default 10)\n");
    fprintf(stderr, "  -c NUM  print the first NUM bytes\n");
    fprintf(stderr, "  -q      never print headers\n");
    fprintf(stderr, "  -v      always print headers\n");
    exit(1);
}

static int head_lines(FILE *fp, long count)
{
    int c;
    long lines = 0;

    while (lines < count && (c = fgetc(fp)) != EOF) {
        putchar(c);
        if (c == '\n')
            lines++;
    }
    if (ferror(fp))
        return 1;
    return 0;
}

static int head_bytes(FILE *fp, long count)
{
    int c;
    long bytes = 0;

    while (bytes < count && (c = fgetc(fp)) != EOF) {
        putchar(c);
        bytes++;
    }
    if (ferror(fp))
        return 1;
    return 0;
}

int main(int argc, char *argv[])
{
    long count = 10;
    int byte_mode = 0;
    int quiet = 0;
    int verbose = 0;
    int i = 1;
    int ret = 0;

    /* Parse options */
    while (i < argc && argv[i][0] == '-' && argv[i][1] != '\0') {
        if (strcmp(argv[i], "--") == 0) {
            i++;
            break;
        }
        const char *arg = argv[i];
        int j = 1;
        while (arg[j]) {
            switch (arg[j]) {
            case 'n':
                byte_mode = 0;
                /* Number can follow immediately or be next arg */
                if (arg[j + 1]) {
                    count = strtol(&arg[j + 1], NULL, 10);
                    goto next_arg;
                } else if (i + 1 < argc) {
                    i++;
                    count = strtol(argv[i], NULL, 10);
                    goto next_arg;
                } else {
                    fprintf(stderr, "head: option '-n' requires an argument\n");
                    usage();
                }
                break;
            case 'c':
                byte_mode = 1;
                if (arg[j + 1]) {
                    count = strtol(&arg[j + 1], NULL, 10);
                    goto next_arg;
                } else if (i + 1 < argc) {
                    i++;
                    count = strtol(argv[i], NULL, 10);
                    goto next_arg;
                } else {
                    fprintf(stderr, "head: option '-c' requires an argument\n");
                    usage();
                }
                break;
            case 'q':
                quiet = 1;
                verbose = 0;
                break;
            case 'v':
                verbose = 1;
                quiet = 0;
                break;
            default:
                fprintf(stderr, "head: unknown option '-%c'\n", arg[j]);
                usage();
            }
            j++;
        }
next_arg:
        i++;
    }

    if (count < 0) {
        fprintf(stderr, "head: invalid number of %s\n",
                byte_mode ? "bytes" : "lines");
        return 1;
    }

    /* Collect file arguments */
    int nfiles = argc - i;
    char **files = &argv[i];
    if (nfiles == 0) {
        files = NULL;
        nfiles = 0;
    }

    /* Determine whether to print headers */
    int print_headers;
    if (quiet)
        print_headers = 0;
    else if (verbose)
        print_headers = 1;
    else
        print_headers = (nfiles > 1);

    if (nfiles == 0) {
        /* Read from stdin */
        if (print_headers)
            printf("==> standard input <==\n");
        if (byte_mode)
            ret = head_bytes(stdin, count);
        else
            ret = head_lines(stdin, count);
    } else {
        for (int f = 0; f < nfiles; f++) {
            FILE *fp;
            const char *name = files[f];
            int is_stdin = (strcmp(name, "-") == 0);

            if (is_stdin) {
                fp = stdin;
                name = "standard input";
            } else {
                fp = fopen(name, "r");
                if (!fp) {
                    fprintf(stderr, "head: cannot open '%s': %s\n",
                            name, strerror(errno));
                    ret = 1;
                    continue;
                }
            }

            if (print_headers) {
                if (f > 0)
                    putchar('\n');
                printf("==> %s <==\n", name);
            }

            int err;
            if (byte_mode)
                err = head_bytes(fp, count);
            else
                err = head_lines(fp, count);
            if (err)
                ret = 1;

            if (!is_stdin)
                fclose(fp);
        }
    }

    return ret;
}
