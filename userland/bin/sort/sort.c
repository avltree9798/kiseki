/*
 * sort - sort lines of text files
 *
 * Usage: sort [OPTION]... [FILE]...
 *
 * Flags:
 *   -r       Reverse the result of comparisons
 *   -n       Compare according to string numerical value
 *   -u       Output only unique lines (suppress duplicates)
 *   -f       Fold lower case to upper case characters (ignore case)
 *   -t CHAR  Use CHAR as field separator
 *   -k NUM   Sort by field number NUM (1-based)
 *
 * With no FILE, or when FILE is -, read standard input.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define MAX_LINE_LEN 8192

static int opt_reverse;
static int opt_numeric;
static int opt_fold_case;
static char opt_separator;
static int opt_key_field;  /* 0 means sort whole line, 1-based field */

static void usage(void)
{
    fprintf(stderr, "Usage: sort [-rnuf] [-t CHAR] [-k NUM] [FILE]...\n");
    exit(2);
}

static char to_lower(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c + ('a' - 'A');
    return c;
}

/* Get pointer to the Nth field (1-based) in a line.
 * If separator is 0, fields are whitespace-separated. */
static const char *get_field(const char *line, int field, char sep)
{
    const char *p = line;
    int f = 1;

    if (field <= 1)
        return line;

    while (*p && f < field) {
        if (sep) {
            if (*p == sep)
                f++;
        } else {
            /* Skip non-whitespace */
            while (*p && *p != ' ' && *p != '\t')
                p++;
            /* Skip whitespace */
            while (*p == ' ' || *p == '\t')
                p++;
            f++;
            continue;
        }
        p++;
    }

    return p;
}

static int compare_lines(const void *a, const void *b)
{
    const char *sa = *(const char **)a;
    const char *sb = *(const char **)b;
    int result;

    /* If sorting by a specific field, extract it */
    if (opt_key_field > 0) {
        sa = get_field(sa, opt_key_field, opt_separator);
        sb = get_field(sb, opt_key_field, opt_separator);
    }

    if (opt_numeric) {
        long na = strtol(sa, NULL, 10);
        long nb = strtol(sb, NULL, 10);
        if (na < nb) result = -1;
        else if (na > nb) result = 1;
        else result = 0;
    } else if (opt_fold_case) {
        /* Case-insensitive comparison */
        const char *pa = sa, *pb = sb;
        result = 0;
        while (*pa && *pb) {
            char ca = to_lower(*pa);
            char cb = to_lower(*pb);
            if (ca != cb) {
                result = (ca < cb) ? -1 : 1;
                break;
            }
            pa++;
            pb++;
        }
        if (result == 0) {
            if (*pa) result = 1;
            else if (*pb) result = -1;
        }
    } else {
        result = strcmp(sa, sb);
    }

    return opt_reverse ? -result : result;
}

/* Read all lines from a stream, appending to the dynamic array.
 * Returns 0 on success, 1 on error. */
static int read_lines(FILE *fp, char ***lines, size_t *count, size_t *cap)
{
    char buf[MAX_LINE_LEN];

    while (fgets(buf, sizeof(buf), fp)) {
        /* Remove trailing newline */
        size_t len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n')
            buf[len - 1] = '\0';

        char *line = strdup(buf);
        if (!line) {
            fprintf(stderr, "sort: out of memory\n");
            return 1;
        }

        if (*count >= *cap) {
            *cap = (*cap == 0) ? 256 : *cap * 2;
            char **tmp = realloc(*lines, *cap * sizeof(char *));
            if (!tmp) {
                fprintf(stderr, "sort: out of memory\n");
                free(line);
                return 1;
            }
            *lines = tmp;
        }
        (*lines)[(*count)++] = line;
    }

    if (ferror(fp))
        return 1;
    return 0;
}

int main(int argc, char *argv[])
{
    int opt_unique = 0;
    int i = 1;
    int ret = 0;

    opt_reverse = 0;
    opt_numeric = 0;
    opt_fold_case = 0;
    opt_separator = '\0';
    opt_key_field = 0;

    /* Parse options */
    if (i < argc && strcmp(argv[i], "--help") == 0) {
        printf("Usage: sort [-rnuf] [-t CHAR] [-k NUM] [FILE]...\n");
        return 0;
    }
    while (i < argc && argv[i][0] == '-' && argv[i][1] != '\0') {
        if (strcmp(argv[i], "--") == 0) {
            i++;
            break;
        }
        const char *arg = argv[i];
        int j = 1;
        while (arg[j]) {
            switch (arg[j]) {
            case 'r': opt_reverse = 1;   break;
            case 'n': opt_numeric = 1;   break;
            case 'u': opt_unique = 1;    break;
            case 'f': opt_fold_case = 1; break;
            case 't':
                if (arg[j + 1]) {
                    opt_separator = arg[j + 1];
                    goto next_arg;
                } else if (i + 1 < argc) {
                    i++;
                    opt_separator = argv[i][0];
                    goto next_arg;
                } else {
                    fprintf(stderr, "sort: option '-t' requires an argument\n");
                    usage();
                }
                break;
            case 'k':
                if (arg[j + 1]) {
                    opt_key_field = atoi(&arg[j + 1]);
                    goto next_arg;
                } else if (i + 1 < argc) {
                    i++;
                    opt_key_field = atoi(argv[i]);
                    goto next_arg;
                } else {
                    fprintf(stderr, "sort: option '-k' requires an argument\n");
                    usage();
                }
                break;
            default:
                fprintf(stderr, "sort: unknown option '-%c'\n", arg[j]);
                usage();
            }
            j++;
        }
next_arg:
        i++;
    }

    /* Read lines from all input files (or stdin) */
    char **lines = NULL;
    size_t count = 0, cap = 0;

    int nfiles = argc - i;

    if (nfiles == 0) {
        if (read_lines(stdin, &lines, &count, &cap)) {
            ret = 1;
            goto done;
        }
    } else {
        for (int f = i; f < argc; f++) {
            FILE *fp;
            int is_stdin = (strcmp(argv[f], "-") == 0);

            if (is_stdin) {
                fp = stdin;
            } else {
                fp = fopen(argv[f], "r");
                if (!fp) {
                    fprintf(stderr, "sort: cannot open '%s': %s\n",
                            argv[f], strerror(errno));
                    ret = 1;
                    continue;
                }
            }

            if (read_lines(fp, &lines, &count, &cap))
                ret = 1;

            if (!is_stdin)
                fclose(fp);
        }
    }

    if (count == 0)
        goto done;

    /* Sort */
    qsort(lines, count, sizeof(char *), compare_lines);

    /* Output */
    for (size_t k = 0; k < count; k++) {
        if (opt_unique && k > 0) {
            int dup;
            if (opt_fold_case) {
                const char *pa = lines[k - 1];
                const char *pb = lines[k];
                dup = 1;
                while (*pa && *pb) {
                    if (to_lower(*pa) != to_lower(*pb)) {
                        dup = 0;
                        break;
                    }
                    pa++;
                    pb++;
                }
                if (*pa || *pb)
                    dup = 0;
            } else {
                dup = (strcmp(lines[k - 1], lines[k]) == 0);
            }
            if (dup)
                continue;
        }
        puts(lines[k]);
    }

done:
    for (size_t k = 0; k < count; k++)
        free(lines[k]);
    free(lines);

    return ret;
}
