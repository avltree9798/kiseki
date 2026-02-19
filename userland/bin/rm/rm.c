/*
 * rm - remove files or directories
 *
 * Kiseki OS coreutils
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>

static const char *progname = "rm";

static int opt_recursive = 0;
static int opt_force     = 0;
static int opt_interact  = 0;
static int opt_verbose   = 0;

static void usage(void)
{
    fprintf(stderr, "Usage: %s [OPTION]... FILE...\n", progname);
    fprintf(stderr, "Remove (unlink) the FILE(s).\n\n");
    fprintf(stderr, "  -r, -R    remove directories and their contents recursively\n");
    fprintf(stderr, "  -f        ignore nonexistent files, never prompt\n");
    fprintf(stderr, "  -i        prompt before every removal\n");
    fprintf(stderr, "  -v        explain what is being done\n");
    fprintf(stderr, "  --help    display this help and exit\n");
}

static int confirm(const char *fmt, const char *path)
{
    fprintf(stderr, "%s: %s '%s'? ", progname, fmt, path);
    fflush(stderr);
    char buf[64];
    if (fgets(buf, (int)sizeof(buf), stdin) == NULL)
        return 0;
    return (buf[0] == 'y' || buf[0] == 'Y');
}

static int do_remove(const char *path)
{
    struct stat st;

    if (lstat(path, &st) < 0) {
        if (opt_force && errno == ENOENT)
            return 0;
        fprintf(stderr, "%s: cannot remove '%s': %s\n", progname, path,
                strerror(errno));
        return 1;
    }

    if (S_ISDIR(st.st_mode)) {
        if (!opt_recursive) {
            fprintf(stderr, "%s: cannot remove '%s': Is a directory\n",
                    progname, path);
            return 1;
        }

        if (opt_interact) {
            if (!confirm("descend into directory", path))
                return 0;
        }

        DIR *dp = opendir(path);
        if (!dp) {
            fprintf(stderr, "%s: cannot open directory '%s': %s\n",
                    progname, path, strerror(errno));
            return 1;
        }

        int ret = 0;
        struct dirent *ent;
        while ((ent = readdir(dp)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 ||
                strcmp(ent->d_name, "..") == 0)
                continue;

            size_t plen = strlen(path);
            size_t nlen = strlen(ent->d_name);
            char *child = malloc(plen + 1 + nlen + 1);
            if (!child) {
                fprintf(stderr, "%s: out of memory\n", progname);
                ret = 1;
                break;
            }
            snprintf(child, plen + 1 + nlen + 1, "%s/%s", path,
                     ent->d_name);

            if (do_remove(child) != 0)
                ret = 1;

            free(child);
        }

        closedir(dp);

        if (opt_interact) {
            if (!confirm("remove directory", path))
                return ret;
        }

        if (rmdir(path) < 0) {
            fprintf(stderr, "%s: cannot remove directory '%s': %s\n",
                    progname, path, strerror(errno));
            ret = 1;
        } else {
            if (opt_verbose)
                printf("removed directory '%s'\n", path);
        }

        return ret;
    }

    /* Regular file, symlink, or other non-directory */
    if (opt_interact) {
        if (!confirm("remove", path))
            return 0;
    }

    if (unlink(path) < 0) {
        if (opt_force && errno == ENOENT)
            return 0;
        fprintf(stderr, "%s: cannot remove '%s': %s\n", progname, path,
                strerror(errno));
        return 1;
    }

    if (opt_verbose)
        printf("removed '%s'\n", path);

    return 0;
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
                case 'r': /* fall through */
                case 'R': opt_recursive = 1; break;
                case 'f': opt_force = 1; opt_interact = 0; break;
                case 'i': opt_interact = 1; opt_force = 0; break;
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

    int nargs = argc - first_arg;
    if (nargs == 0) {
        if (opt_force)
            return 0;
        fprintf(stderr, "%s: missing operand\n", progname);
        usage();
        return 1;
    }

    int ret = 0;
    for (int i = first_arg; i < argc; i++) {
        if (do_remove(argv[i]) != 0)
            ret = 1;
    }

    return ret;
}
