/*
 * wc - word, line, character, and byte count
 *
 * Usage: wc [OPTION]... [FILE]...
 *
 * Flags:
 *   -l  Print the newline count
 *   -w  Print the word count
 *   -c  Print the byte count
 *   -m  Print the character count (same as -c for single-byte locale)
 *
 * Default (no flags): print lines, words, bytes.
 * With multiple files, a totals line is printed.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static void usage(void)
{
    fprintf(stderr, "Usage: wc [-lwcm] [FILE]...\n");
    exit(1);
}

static void print_counts(long lines, long words, long bytes,
                         int show_lines, int show_words, int show_bytes,
                         const char *name)
{
    int first = 1;

    if (show_lines) {
        if (!first) putchar(' ');
        printf("%7ld", lines);
        first = 0;
    }
    if (show_words) {
        if (!first) putchar(' ');
        printf("%7ld", words);
        first = 0;
    }
    if (show_bytes) {
        if (!first) putchar(' ');
        printf("%7ld", bytes);
        first = 0;
    }

    if (name)
        printf(" %s", name);
    putchar('\n');
}

static int wc_file(FILE *fp, long *out_lines, long *out_words, long *out_bytes)
{
    long lines = 0, words = 0, bytes = 0;
    int in_word = 0;
    int c;

    while ((c = fgetc(fp)) != EOF) {
        bytes++;
        if (c == '\n')
            lines++;
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
            c == '\f' || c == '\v') {
            in_word = 0;
        } else {
            if (!in_word) {
                words++;
                in_word = 1;
            }
        }
    }

    if (ferror(fp))
        return 1;

    *out_lines = lines;
    *out_words = words;
    *out_bytes = bytes;
    return 0;
}

int main(int argc, char *argv[])
{
    int show_lines = 0, show_words = 0, show_bytes = 0;
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
            case 'l': show_lines = 1; break;
            case 'w': show_words = 1; break;
            case 'c': show_bytes = 1; break;
            case 'm': show_bytes = 1; break; /* chars == bytes here */
            default:
                fprintf(stderr, "wc: unknown option '-%c'\n", arg[j]);
                usage();
            }
        }
        i++;
    }

    /* Default: show all three */
    if (!show_lines && !show_words && !show_bytes) {
        show_lines = 1;
        show_words = 1;
        show_bytes = 1;
    }

    int nfiles = argc - i;
    char **files = &argv[i];
    long total_lines = 0, total_words = 0, total_bytes = 0;

    if (nfiles == 0) {
        /* Read from stdin */
        long lines, words, bytes;
        if (wc_file(stdin, &lines, &words, &bytes)) {
            perror("wc: read error");
            ret = 1;
        } else {
            print_counts(lines, words, bytes,
                         show_lines, show_words, show_bytes, NULL);
        }
    } else {
        for (int f = 0; f < nfiles; f++) {
            FILE *fp;
            const char *name = files[f];
            int is_stdin = (strcmp(name, "-") == 0);

            if (is_stdin) {
                fp = stdin;
                name = "-";
            } else {
                fp = fopen(name, "r");
                if (!fp) {
                    fprintf(stderr, "wc: cannot open '%s': %s\n",
                            name, strerror(errno));
                    ret = 1;
                    continue;
                }
            }

            long lines, words, bytes;
            if (wc_file(fp, &lines, &words, &bytes)) {
                fprintf(stderr, "wc: read error on '%s'\n", name);
                ret = 1;
            } else {
                print_counts(lines, words, bytes,
                             show_lines, show_words, show_bytes, name);
                total_lines += lines;
                total_words += words;
                total_bytes += bytes;
            }

            if (!is_stdin)
                fclose(fp);
        }

        if (nfiles > 1) {
            print_counts(total_lines, total_words, total_bytes,
                         show_lines, show_words, show_bytes, "total");
        }
    }

    return ret;
}
