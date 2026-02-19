/*
 * basename - strip directory and suffix from filenames
 *
 * Usage: basename NAME [SUFFIX]
 *        basename -a [-s SUFFIX] NAME...
 *
 * Kiseki OS coreutils
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const char *progname = "basename";

static void usage(void)
{
    fprintf(stderr, "Usage: %s NAME [SUFFIX]\n", progname);
    fprintf(stderr, "  or:  %s -a [-s SUFFIX] NAME...\n", progname);
}

static void do_basename(const char *path, const char *suffix)
{
    /* Handle empty string */
    if (path[0] == '\0') {
        puts("");
        return;
    }

    /* Work on a copy */
    size_t len = strlen(path);

    /* Strip trailing slashes */
    while (len > 1 && path[len - 1] == '/')
        len--;

    /* If entire string is slashes, return "/" */
    if (len == 1 && path[0] == '/') {
        puts("/");
        return;
    }

    /* Find last slash */
    const char *base = path;
    for (size_t i = 0; i < len; i++) {
        if (path[i] == '/' && i + 1 < len)
            base = &path[i + 1];
    }

    size_t baselen = len - (size_t)(base - path);

    /* Strip suffix if provided and it doesn't consume the entire name */
    if (suffix && suffix[0] != '\0') {
        size_t suflen = strlen(suffix);
        if (baselen > suflen &&
            memcmp(base + baselen - suflen, suffix, suflen) == 0) {
            baselen -= suflen;
        }
    }

    fwrite(base, 1, baselen, stdout);
    putchar('\n');
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage();
        return 1;
    }

    int all_mode = 0;
    const char *suffix = NULL;
    int first_arg = 1;

    /* Parse options */
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-' && argv[i][1] != '\0') {
            if (strcmp(argv[i], "--") == 0) {
                first_arg = i + 1;
                break;
            }
            if (strcmp(argv[i], "-a") == 0 ||
                strcmp(argv[i], "--multiple") == 0) {
                all_mode = 1;
                first_arg = i + 1;
            } else if (strcmp(argv[i], "-s") == 0) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "%s: option '-s' requires an argument\n",
                            progname);
                    return 1;
                }
                suffix = argv[++i];
                first_arg = i + 1;
            } else {
                /* Not an option, stop parsing */
                first_arg = i;
                break;
            }
        } else {
            first_arg = i;
            break;
        }
    }

    if (first_arg >= argc) {
        usage();
        return 1;
    }

    if (all_mode) {
        /* -a mode: process each remaining arg */
        for (int i = first_arg; i < argc; i++)
            do_basename(argv[i], suffix);
    } else {
        /* Classic mode: basename NAME [SUFFIX] */
        const char *name = argv[first_arg];
        const char *suf = NULL;

        if (first_arg + 1 < argc)
            suf = argv[first_arg + 1];

        do_basename(name, suf);
    }

    return 0;
}
