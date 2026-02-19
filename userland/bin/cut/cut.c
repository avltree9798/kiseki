/*
 * cut - remove sections from each line of files
 *
 * Usage: cut OPTION... [FILE]...
 *
 * Flags:
 *   -b LIST  Select only these bytes
 *   -c LIST  Select only these characters (same as -b for us)
 *   -f LIST  Select only these fields
 *   -d DELIM Use DELIM instead of TAB for field delimiter
 *   -s       Do not print lines not containing delimiters (with -f)
 *
 * LIST is comma-separated, made of: N, N-M, N-, -M  (1-based)
 *
 * With no FILE, or when FILE is -, read standard input.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define MAX_LINE_LEN  8192
#define MAX_POSITIONS 8192

static void usage(void)
{
    fprintf(stderr, "Usage: cut -b LIST | -c LIST | -f LIST [-d DELIM] [-s] [FILE]...\n");
    exit(2);
}

/* Bit array for selected positions (1-based, up to MAX_POSITIONS) */
static unsigned char selected[MAX_POSITIONS / 8 + 1];

static void set_pos(int pos)
{
    if (pos >= 1 && pos <= MAX_POSITIONS)
        selected[(pos - 1) / 8] |= (1 << ((pos - 1) % 8));
}

static int is_set(int pos)
{
    if (pos >= 1 && pos <= MAX_POSITIONS)
        return (selected[(pos - 1) / 8] >> ((pos - 1) % 8)) & 1;
    return 0;
}

/* Parse a LIST specification like "1,3-5,7-,2,-4" */
static int parse_list(const char *list)
{
    const char *p = list;

    memset(selected, 0, sizeof(selected));

    while (*p) {
        int start = 0, end = 0;

        if (*p == '-') {
            /* -M: from 1 to M */
            p++;
            end = 0;
            while (*p >= '0' && *p <= '9') {
                end = end * 10 + (*p - '0');
                p++;
            }
            if (end <= 0) {
                fprintf(stderr, "cut: invalid range in list\n");
                return 1;
            }
            for (int i = 1; i <= end; i++)
                set_pos(i);
        } else if (*p >= '0' && *p <= '9') {
            start = 0;
            while (*p >= '0' && *p <= '9') {
                start = start * 10 + (*p - '0');
                p++;
            }
            if (*p == '-') {
                p++;
                if (*p >= '0' && *p <= '9') {
                    /* N-M */
                    end = 0;
                    while (*p >= '0' && *p <= '9') {
                        end = end * 10 + (*p - '0');
                        p++;
                    }
                    if (end < start) {
                        fprintf(stderr, "cut: invalid decreasing range\n");
                        return 1;
                    }
                    for (int i = start; i <= end; i++)
                        set_pos(i);
                } else {
                    /* N- : from N to MAX */
                    for (int i = start; i <= MAX_POSITIONS; i++)
                        set_pos(i);
                }
            } else {
                /* Just N */
                set_pos(start);
            }
        } else {
            fprintf(stderr, "cut: invalid list character '%c'\n", *p);
            return 1;
        }

        if (*p == ',')
            p++;
        else if (*p && *p != ',') {
            fprintf(stderr, "cut: invalid list\n");
            return 1;
        }
    }

    return 0;
}

static void cut_bytes(FILE *fp)
{
    char line[MAX_LINE_LEN];

    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        int has_nl = (len > 0 && line[len - 1] == '\n');
        if (has_nl)
            line[--len] = '\0';

        for (size_t i = 0; i < len; i++) {
            if (is_set((int)(i + 1)))
                putchar(line[i]);
        }
        putchar('\n');
    }
}

static void cut_fields(FILE *fp, char delim, int suppress)
{
    char line[MAX_LINE_LEN];

    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        int has_nl = (len > 0 && line[len - 1] == '\n');
        if (has_nl)
            line[--len] = '\0';

        /* Check if line contains delimiter */
        if (!strchr(line, delim)) {
            if (!suppress)
                printf("%s\n", line);
            continue;
        }

        /* Split into fields and print selected ones */
        int field = 1;
        int first_output = 1;
        const char *start = line;
        const char *p = line;

        while (1) {
            if (*p == delim || *p == '\0') {
                if (is_set(field)) {
                    if (!first_output)
                        putchar(delim);
                    /* Print field from start to p */
                    fwrite(start, 1, (size_t)(p - start), stdout);
                    first_output = 0;
                }
                field++;
                if (*p == '\0')
                    break;
                start = p + 1;
            }
            p++;
        }
        putchar('\n');
    }
}

int main(int argc, char *argv[])
{
    int mode = 0; /* 0=none, 'b'=bytes, 'c'=chars, 'f'=fields */
    char delim = '\t';
    int suppress = 0;
    const char *list = NULL;
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
            case 'b':
            case 'c':
                mode = arg[j];
                if (arg[j + 1]) {
                    list = &arg[j + 1];
                    goto next_arg;
                } else if (i + 1 < argc) {
                    i++;
                    list = argv[i];
                    goto next_arg;
                } else {
                    fprintf(stderr, "cut: option '-%c' requires an argument\n",
                            arg[j]);
                    usage();
                }
                break;
            case 'f':
                mode = 'f';
                if (arg[j + 1]) {
                    list = &arg[j + 1];
                    goto next_arg;
                } else if (i + 1 < argc) {
                    i++;
                    list = argv[i];
                    goto next_arg;
                } else {
                    fprintf(stderr, "cut: option '-f' requires an argument\n");
                    usage();
                }
                break;
            case 'd':
                if (arg[j + 1]) {
                    delim = arg[j + 1];
                    goto next_arg;
                } else if (i + 1 < argc) {
                    i++;
                    delim = argv[i][0];
                    goto next_arg;
                } else {
                    fprintf(stderr, "cut: option '-d' requires an argument\n");
                    usage();
                }
                break;
            case 's':
                suppress = 1;
                break;
            default:
                fprintf(stderr, "cut: unknown option '-%c'\n", arg[j]);
                usage();
            }
            j++;
        }
next_arg:
        i++;
    }

    if (!mode || !list) {
        fprintf(stderr, "cut: you must specify a list of bytes, characters, or fields\n");
        usage();
    }

    if (parse_list(list))
        return 1;

    int nfiles = argc - i;
    char **files = &argv[i];

    if (nfiles == 0) {
        if (mode == 'f')
            cut_fields(stdin, delim, suppress);
        else
            cut_bytes(stdin);
    } else {
        for (int f = 0; f < nfiles; f++) {
            FILE *fp;
            int is_stdin = (strcmp(files[f], "-") == 0);

            if (is_stdin) {
                fp = stdin;
            } else {
                fp = fopen(files[f], "r");
                if (!fp) {
                    fprintf(stderr, "cut: cannot open '%s': %s\n",
                            files[f], strerror(errno));
                    ret = 1;
                    continue;
                }
            }

            if (mode == 'f')
                cut_fields(fp, delim, suppress);
            else
                cut_bytes(fp);

            if (!is_stdin)
                fclose(fp);
        }
    }

    return ret;
}
