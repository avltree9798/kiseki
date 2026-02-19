/*
 * rmdir - remove empty directories
 *
 * Kiseki OS coreutils
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

static const char *progname = "rmdir";

static int opt_parents = 0;
static int opt_verbose = 0;

static void usage(void)
{
    fprintf(stderr, "Usage: %s [OPTION]... DIRECTORY...\n", progname);
    fprintf(stderr, "Remove the DIRECTORY(ies), if they are empty.\n\n");
    fprintf(stderr, "  -p    remove DIRECTORY and its ancestors\n");
    fprintf(stderr, "  -v    output a diagnostic for every directory processed\n");
    fprintf(stderr, "  --help display this help and exit\n");
}

static int do_rmdir(const char *path)
{
    if (rmdir(path) < 0) {
        fprintf(stderr, "%s: failed to remove '%s': %s\n", progname, path,
                strerror(errno));
        return 1;
    }

    if (opt_verbose)
        printf("%s: removing directory, '%s'\n", progname, path);

    return 0;
}

/*
 * Remove directory and its parent components.
 * E.g. "rmdir -p a/b/c" removes c, then a/b, then a.
 */
static int do_rmdir_parents(const char *path)
{
    char *buf = strdup(path);
    if (!buf) {
        fprintf(stderr, "%s: out of memory\n", progname);
        return 1;
    }

    int ret = 0;

    /* Remove the directory itself first */
    if (do_rmdir(buf) != 0) {
        free(buf);
        return 1;
    }

    /* Now remove parent directories one at a time */
    for (;;) {
        /* Strip trailing slashes */
        size_t len = strlen(buf);
        while (len > 1 && buf[len - 1] == '/')
            buf[--len] = '\0';

        /* Find last slash to get parent */
        char *slash = strrchr(buf, '/');
        if (!slash)
            break;

        /* Truncate at the slash to get parent directory */
        *slash = '\0';
        if (buf[0] == '\0')
            break;

        if (do_rmdir(buf) != 0) {
            ret = 1;
            break;
        }
    }

    free(buf);
    return ret;
}

int main(int argc, char *argv[])
{
    int first_arg = argc;

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-' && argv[i][1] != '\0') {
            if (strcmp(argv[i], "--help") == 0) {
                usage();
                return 0;
            }
            if (strcmp(argv[i], "--") == 0) {
                first_arg = i + 1;
                break;
            }
            const char *p = &argv[i][1];
            while (*p) {
                switch (*p) {
                case 'p': opt_parents = 1; break;
                case 'v': opt_verbose = 1; break;
                default:
                    fprintf(stderr, "%s: invalid option -- '%c'\n",
                            progname, *p);
                    usage();
                    return 1;
                }
                p++;
            }
        } else {
            first_arg = i;
            break;
        }
    }

    if (first_arg >= argc) {
        fprintf(stderr, "%s: missing operand\n", progname);
        usage();
        return 1;
    }

    int ret = 0;
    for (int i = first_arg; i < argc; i++) {
        if (opt_parents) {
            if (do_rmdir_parents(argv[i]) != 0)
                ret = 1;
        } else {
            if (do_rmdir(argv[i]) != 0)
                ret = 1;
        }
    }

    return ret;
}
