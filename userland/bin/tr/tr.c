/*
 * tr - translate or delete characters
 *
 * Usage: tr [OPTION]... SET1 [SET2]
 *
 * Flags:
 *   -d  Delete characters in SET1, do not translate
 *   -s  Squeeze repeated output characters in SET2 to single
 *   -c  Use the complement of SET1
 *
 * SET format:
 *   Literal characters, or ranges like a-z, A-Z, 0-9
 *   Backslash escapes: \n \t \r \\ \a \b \f
 *
 * Reads from stdin, writes to stdout.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(void)
{
    fprintf(stderr, "Usage: tr [-dsc] SET1 [SET2]\n");
    exit(1);
}

/* Expand a set specification into a character array.
 * Returns number of characters in expanded set. */
static int expand_set(const char *spec, unsigned char *out, int maxlen)
{
    int n = 0;
    const unsigned char *p = (const unsigned char *)spec;

    while (*p && n < maxlen) {
        unsigned char c;

        if (*p == '\\' && p[1]) {
            p++;
            switch (*p) {
            case 'n':  c = '\n'; break;
            case 't':  c = '\t'; break;
            case 'r':  c = '\r'; break;
            case 'a':  c = '\a'; break;
            case 'b':  c = '\b'; break;
            case 'f':  c = '\f'; break;
            case '\\': c = '\\'; break;
            default:   c = *p;   break;
            }
            out[n++] = c;
            p++;
        } else if (p[1] == '-' && p[2]) {
            /* Range: e.g., a-z */
            unsigned char start = p[0];
            unsigned char end = p[2];
            if (start <= end) {
                for (unsigned int ch = start; ch <= end && n < maxlen; ch++)
                    out[n++] = (unsigned char)ch;
            } else {
                for (int ch = start; ch >= (int)end && n < maxlen; ch--)
                    out[n++] = (unsigned char)ch;
            }
            p += 3;
        } else {
            out[n++] = *p;
            p++;
        }
    }

    return n;
}

int main(int argc, char *argv[])
{
    int opt_delete = 0;
    int opt_squeeze = 0;
    int opt_complement = 0;
    int i = 1;

    /* Parse options */
    while (i < argc && argv[i][0] == '-' && argv[i][1] != '\0') {
        if (strcmp(argv[i], "--") == 0) {
            i++;
            break;
        }
        const char *arg = argv[i];
        for (int j = 1; arg[j]; j++) {
            switch (arg[j]) {
            case 'd': opt_delete = 1;     break;
            case 's': opt_squeeze = 1;    break;
            case 'c': opt_complement = 1; break;
            default:
                fprintf(stderr, "tr: unknown option '-%c'\n", arg[j]);
                usage();
            }
        }
        i++;
    }

    /* We need at least SET1 */
    if (i >= argc)
        usage();

    const char *set1_spec = argv[i++];
    const char *set2_spec = (i < argc) ? argv[i] : NULL;

    /* Need SET2 if not deleting (unless squeezing with delete) */
    if (!opt_delete && !opt_squeeze && !set2_spec) {
        fprintf(stderr, "tr: missing operand after '%s'\n", set1_spec);
        usage();
    }

    /* Expand sets */
    unsigned char set1[256];
    unsigned char set2[256];
    int set1_len = expand_set(set1_spec, set1, 256);
    int set2_len = 0;
    if (set2_spec)
        set2_len = expand_set(set2_spec, set2, 256);

    /* Build lookup table: is character in SET1? */
    int in_set1[256];
    memset(in_set1, 0, sizeof(in_set1));
    for (int k = 0; k < set1_len; k++)
        in_set1[set1[k]] = 1;

    if (opt_complement) {
        for (int k = 0; k < 256; k++)
            in_set1[k] = !in_set1[k];
    }

    /* Build translation table */
    unsigned char trans[256];
    for (int k = 0; k < 256; k++)
        trans[k] = (unsigned char)k;

    if (!opt_delete && set2_spec) {
        if (opt_complement) {
            /* For complement mode, build the complement set explicitly */
            unsigned char comp_set[256];
            int comp_len = 0;
            for (int k = 0; k < 256; k++) {
                if (in_set1[k])
                    comp_set[comp_len++] = (unsigned char)k;
            }
            /* Map each character in complement set to corresponding set2 char */
            for (int k = 0; k < comp_len; k++) {
                int s2idx = (k < set2_len) ? k : set2_len - 1;
                if (s2idx >= 0)
                    trans[comp_set[k]] = set2[s2idx];
            }
        } else {
            /* Map each character in SET1 to corresponding SET2 character.
             * If SET2 is shorter, last char of SET2 is used for excess. */
            for (int k = 0; k < set1_len; k++) {
                int s2idx = (k < set2_len) ? k : set2_len - 1;
                if (s2idx >= 0)
                    trans[set1[k]] = set2[s2idx];
            }
        }
    }

    /* Build squeeze set: characters to squeeze (from SET2 if translating, SET1 if deleting+squeezing) */
    int squeeze_set[256];
    memset(squeeze_set, 0, sizeof(squeeze_set));
    if (opt_squeeze) {
        if (opt_delete) {
            /* -ds: squeeze characters in SET2 */
            if (set2_spec) {
                for (int k = 0; k < set2_len; k++)
                    squeeze_set[set2[k]] = 1;
            }
        } else if (set2_spec) {
            /* -s: squeeze characters that are in the output set (SET2) */
            for (int k = 0; k < set2_len; k++)
                squeeze_set[set2[k]] = 1;
        } else {
            /* -s without SET2: squeeze chars in SET1 */
            for (int k = 0; k < 256; k++) {
                if (in_set1[k])
                    squeeze_set[k] = 1;
            }
        }
    }

    /* Process input */
    int c;
    int last_out = -1;

    while ((c = fgetc(stdin)) != EOF) {
        unsigned char uc = (unsigned char)c;

        if (opt_delete && in_set1[uc]) {
            /* Delete this character */
            continue;
        }

        unsigned char out;
        if (!opt_delete)
            out = trans[uc];
        else
            out = uc;

        /* Squeeze repeated characters */
        if (opt_squeeze && squeeze_set[out] && out == last_out)
            continue;

        putchar(out);
        last_out = out;
    }

    return 0;
}
