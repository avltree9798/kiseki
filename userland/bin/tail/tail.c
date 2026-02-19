/*
 * tail - output the last part of files
 *
 * Usage: tail [OPTION]... [FILE]...
 *
 * Flags:
 *   -n NUM  Output the last NUM lines (default 10)
 *   -c NUM  Output the last NUM bytes
 *   -q      Never print headers giving file names
 *   -v      Always print headers giving file names
 *
 * With no FILE, or when FILE is -, read standard input.
 * Approach: read entire file into memory, then output last N lines/bytes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static void usage(void)
{
    fprintf(stderr, "Usage: tail [OPTION]... [FILE]...\n");
    fprintf(stderr, "  -n NUM  output the last NUM lines (default 10)\n");
    fprintf(stderr, "  -c NUM  output the last NUM bytes\n");
    fprintf(stderr, "  -q      never print headers\n");
    fprintf(stderr, "  -v      always print headers\n");
    exit(1);
}

/* Read entire stream into a malloc'd buffer. Returns buffer, sets *out_len. */
static char *read_all(FILE *fp, size_t *out_len)
{
    size_t cap = 4096;
    size_t len = 0;
    char *buf = malloc(cap);

    if (!buf) {
        fprintf(stderr, "tail: out of memory\n");
        return NULL;
    }

    size_t n;
    while ((n = fread(buf + len, 1, cap - len, fp)) > 0) {
        len += n;
        if (len == cap) {
            cap *= 2;
            char *newbuf = realloc(buf, cap);
            if (!newbuf) {
                fprintf(stderr, "tail: out of memory\n");
                free(buf);
                return NULL;
            }
            buf = newbuf;
        }
    }

    *out_len = len;
    return buf;
}

static int tail_lines(FILE *fp, long count)
{
    size_t len;
    char *buf = read_all(fp, &len);
    if (!buf)
        return 1;

    if (count <= 0 || len == 0) {
        free(buf);
        return 0;
    }

    /* Count newlines backwards from the end to find the start position */
    long newlines = 0;
    size_t pos = len;

    while (pos > 0 && newlines < count) {
        pos--;
        if (buf[pos] == '\n') {
            /* Don't count a trailing newline at the very end */
            if (pos + 1 < len)
                newlines++;
        }
    }

    /* If we found enough newlines, advance past the newline we stopped on */
    if (newlines == count && buf[pos] == '\n')
        pos++;

    fwrite(buf + pos, 1, len - pos, stdout);
    free(buf);
    return 0;
}

static int tail_bytes(FILE *fp, long count)
{
    size_t len;
    char *buf = read_all(fp, &len);
    if (!buf)
        return 1;

    if (count <= 0 || len == 0) {
        free(buf);
        return 0;
    }

    size_t start = 0;
    if ((size_t)count < len)
        start = len - (size_t)count;

    fwrite(buf + start, 1, len - start, stdout);
    free(buf);
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
                if (arg[j + 1]) {
                    count = strtol(&arg[j + 1], NULL, 10);
                    goto next_arg;
                } else if (i + 1 < argc) {
                    i++;
                    count = strtol(argv[i], NULL, 10);
                    goto next_arg;
                } else {
                    fprintf(stderr, "tail: option '-n' requires an argument\n");
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
                    fprintf(stderr, "tail: option '-c' requires an argument\n");
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
                fprintf(stderr, "tail: unknown option '-%c'\n", arg[j]);
                usage();
            }
            j++;
        }
next_arg:
        i++;
    }

    if (count < 0) {
        fprintf(stderr, "tail: invalid number of %s\n",
                byte_mode ? "bytes" : "lines");
        return 1;
    }

    int nfiles = argc - i;
    char **files = &argv[i];

    int print_headers;
    if (quiet)
        print_headers = 0;
    else if (verbose)
        print_headers = 1;
    else
        print_headers = (nfiles > 1);

    if (nfiles == 0) {
        if (print_headers)
            printf("==> standard input <==\n");
        if (byte_mode)
            ret = tail_bytes(stdin, count);
        else
            ret = tail_lines(stdin, count);
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
                    fprintf(stderr, "tail: cannot open '%s': %s\n",
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
                err = tail_bytes(fp, count);
            else
                err = tail_lines(fp, count);
            if (err)
                ret = 1;

            if (!is_stdin)
                fclose(fp);
        }
    }

    return ret;
}
