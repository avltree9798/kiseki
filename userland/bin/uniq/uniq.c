/*
 * uniq - report or omit repeated lines
 *
 * Usage: uniq [OPTION]... [INPUT [OUTPUT]]
 *
 * Flags:
 *   -c       Prefix lines by the number of occurrences
 *   -d       Only print duplicate lines (one for each group)
 *   -u       Only print unique lines
 *   -i       Ignore differences in case when comparing
 *   -f NUM   Avoid comparing the first NUM fields
 *   -s NUM   Avoid comparing the first NUM characters
 *
 * A field is a run of blanks (space/tab) then non-blanks.
 * With no INPUT or when INPUT is -, read standard input.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define MAX_LINE_LEN 8192

static void usage(void)
{
    fprintf(stderr, "Usage: uniq [-cdui] [-f NUM] [-s NUM] [INPUT [OUTPUT]]\n");
    exit(2);
}

static char to_lower(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c + ('a' - 'A');
    return c;
}

/* Skip N fields from the beginning of a string.
 * A field is a run of blanks followed by non-blanks. */
static const char *skip_fields(const char *s, int nfields)
{
    for (int i = 0; i < nfields && *s; i++) {
        /* Skip leading blanks */
        while (*s == ' ' || *s == '\t')
            s++;
        /* Skip non-blanks */
        while (*s && *s != ' ' && *s != '\t')
            s++;
    }
    return s;
}

/* Compare two lines according to options.
 * Returns 0 if equal. */
static int compare_lines(const char *a, const char *b,
                          int skip_f, int skip_c, int ignore_case)
{
    /* Skip fields */
    if (skip_f > 0) {
        a = skip_fields(a, skip_f);
        b = skip_fields(b, skip_f);
    }

    /* Skip characters */
    for (int i = 0; i < skip_c && *a; i++)
        a++;
    for (int i = 0; i < skip_c && *b; i++)
        b++;

    if (ignore_case) {
        while (*a && *b) {
            if (to_lower(*a) != to_lower(*b))
                return 1;
            a++;
            b++;
        }
        return (*a || *b) ? 1 : 0;
    }

    return strcmp(a, b);
}

static void output_line(FILE *out, const char *line, long count,
                        int show_count, int only_dups, int only_unique)
{
    if (only_dups && count < 2)
        return;
    if (only_unique && count > 1)
        return;

    if (show_count)
        fprintf(out, "%7ld %s\n", count, line);
    else
        fprintf(out, "%s\n", line);
}

int main(int argc, char *argv[])
{
    int opt_count = 0;
    int opt_dups = 0;
    int opt_unique = 0;
    int opt_icase = 0;
    int opt_skip_fields = 0;
    int opt_skip_chars = 0;
    int i = 1;

    /* Parse options */
    if (i < argc && strcmp(argv[i], "--help") == 0) {
        printf("Usage: uniq [-cdui] [-f NUM] [-s NUM] [INPUT [OUTPUT]]\n");
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
            case 'c': opt_count = 1;  break;
            case 'd': opt_dups = 1;   break;
            case 'u': opt_unique = 1; break;
            case 'i': opt_icase = 1;  break;
            case 'f':
                if (arg[j + 1]) {
                    opt_skip_fields = atoi(&arg[j + 1]);
                    goto next_arg;
                } else if (i + 1 < argc) {
                    i++;
                    opt_skip_fields = atoi(argv[i]);
                    goto next_arg;
                } else {
                    fprintf(stderr, "uniq: option '-f' requires an argument\n");
                    usage();
                }
                break;
            case 's':
                if (arg[j + 1]) {
                    opt_skip_chars = atoi(&arg[j + 1]);
                    goto next_arg;
                } else if (i + 1 < argc) {
                    i++;
                    opt_skip_chars = atoi(argv[i]);
                    goto next_arg;
                } else {
                    fprintf(stderr, "uniq: option '-s' requires an argument\n");
                    usage();
                }
                break;
            default:
                fprintf(stderr, "uniq: unknown option '-%c'\n", arg[j]);
                usage();
            }
            j++;
        }
next_arg:
        i++;
    }

    /* Input and output files */
    FILE *in = stdin;
    FILE *out = stdout;

    if (i < argc && strcmp(argv[i], "-") != 0) {
        in = fopen(argv[i], "r");
        if (!in) {
            fprintf(stderr, "uniq: cannot open '%s': %s\n",
                    argv[i], strerror(errno));
            return 1;
        }
        i++;
    } else if (i < argc) {
        i++; /* skip the '-' */
    }

    if (i < argc) {
        out = fopen(argv[i], "w");
        if (!out) {
            fprintf(stderr, "uniq: cannot open '%s': %s\n",
                    argv[i], strerror(errno));
            if (in != stdin)
                fclose(in);
            return 1;
        }
    }

    char cur_line[MAX_LINE_LEN];
    char prev_line[MAX_LINE_LEN];
    int have_prev = 0;
    long count = 0;

    while (fgets(cur_line, sizeof(cur_line), in)) {
        /* Remove trailing newline */
        size_t len = strlen(cur_line);
        if (len > 0 && cur_line[len - 1] == '\n')
            cur_line[len - 1] = '\0';

        if (!have_prev) {
            strcpy(prev_line, cur_line);
            count = 1;
            have_prev = 1;
        } else if (compare_lines(prev_line, cur_line,
                                  opt_skip_fields, opt_skip_chars,
                                  opt_icase) == 0) {
            count++;
        } else {
            output_line(out, prev_line, count,
                        opt_count, opt_dups, opt_unique);
            strcpy(prev_line, cur_line);
            count = 1;
        }
    }

    /* Output the last group */
    if (have_prev) {
        output_line(out, prev_line, count,
                    opt_count, opt_dups, opt_unique);
    }

    if (in != stdin)
        fclose(in);
    if (out != stdout)
        fclose(out);

    return 0;
}
