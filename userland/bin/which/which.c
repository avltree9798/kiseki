/*
 * which - locate a command
 *
 * Usage: which [-a] COMMAND...
 *
 * Searches the PATH environment variable for executable files matching
 * the given command names.
 *
 * Flags:
 *   -a        print all matches, not just the first
 *   --help    display help and exit
 *
 * Exit status:
 *   0  all commands were found
 *   1  one or more commands were not found
 *   2  usage error
 *
 * Kiseki OS coreutils
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

static const char *progname = "which";

/* Default PATH if $PATH is not set */
#define DEFAULT_PATH "/bin:/usr/bin"

static void usage(void)
{
    fprintf(stderr, "Usage: %s [-a] COMMAND...\n", progname);
    fprintf(stderr, "Locate a command in PATH.\n\n");
    fprintf(stderr, "  -a        print all matching executables, "
                    "not just the first\n");
    fprintf(stderr, "  --help    display this help and exit\n");
}

/*
 * Search for `name` in the directories listed in `path_env` (colon-separated).
 * If `all` is set, print every match; otherwise stop after the first.
 * Returns 1 if at least one match was found, 0 otherwise.
 */
static int search_path(const char *name, const char *path_env, int all)
{
    /* If name contains a slash, it's a direct path - just check it */
    if (strchr(name, '/')) {
        if (access(name, X_OK) == 0) {
            puts(name);
            return 1;
        }
        return 0;
    }

    /* Make a mutable copy of PATH */
    size_t plen = strlen(path_env);
    char *path_copy = malloc(plen + 1);
    if (!path_copy) {
        fprintf(stderr, "%s: out of memory\n", progname);
        return 0;
    }
    memcpy(path_copy, path_env, plen + 1);

    int found = 0;
    char fullpath[4096];

    char *saveptr = NULL;
    char *dir = strtok_r(path_copy, ":", &saveptr);

    while (dir) {
        /* Handle empty path component as current directory */
        if (*dir == '\0')
            dir = ".";

        /* Build full path: dir/name */
        size_t dlen = strlen(dir);
        size_t nlen = strlen(name);
        if (dlen + 1 + nlen + 1 > sizeof(fullpath)) {
            dir = strtok_r(NULL, ":", &saveptr);
            continue;
        }

        memcpy(fullpath, dir, dlen);
        fullpath[dlen] = '/';
        memcpy(fullpath + dlen + 1, name, nlen);
        fullpath[dlen + 1 + nlen] = '\0';

        if (access(fullpath, X_OK) == 0) {
            puts(fullpath);
            found = 1;
            if (!all)
                break;
        }

        dir = strtok_r(NULL, ":", &saveptr);
    }

    free(path_copy);
    return found;
}

int main(int argc, char *argv[])
{
    int opt_all = 0;
    int first_cmd = 0; /* index of first command argument */

    /* Parse options */
    int i;
    for (i = 1; i < argc; i++) {
        if (argv[i][0] == '-' && argv[i][1] != '\0') {
            if (strcmp(argv[i], "--help") == 0) {
                usage();
                return 0;
            }
            if (strcmp(argv[i], "--") == 0) {
                i++;
                break;
            }
            /* Parse bundled flags */
            const char *p = &argv[i][1];
            while (*p) {
                switch (*p) {
                case 'a':
                    opt_all = 1;
                    break;
                default:
                    fprintf(stderr, "%s: invalid option -- '%c'\n",
                            progname, *p);
                    usage();
                    return 2;
                }
                p++;
            }
        } else {
            break;
        }
    }
    first_cmd = i;

    if (first_cmd >= argc) {
        fprintf(stderr, "%s: missing command name\n", progname);
        usage();
        return 2;
    }

    /* Get PATH */
    const char *path_env = getenv("PATH");
    if (!path_env || *path_env == '\0')
        path_env = DEFAULT_PATH;

    int ret = 0;

    for (i = first_cmd; i < argc; i++) {
        if (!search_path(argv[i], path_env, opt_all)) {
            fprintf(stderr, "%s: no %s in (%s)\n",
                    progname, argv[i], path_env);
            ret = 1;
        }
    }

    return ret;
}
