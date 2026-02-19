/*
 * ln - make links between files
 *
 * Kiseki OS coreutils
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>

static const char *progname = "ln";

static int opt_symbolic = 0;
static int opt_force    = 0;
static int opt_verbose  = 0;

static void usage(void)
{
    fprintf(stderr, "Usage: %s [OPTION]... TARGET LINK_NAME\n", progname);
    fprintf(stderr, "   or: %s [OPTION]... TARGET... DIRECTORY\n", progname);
    fprintf(stderr, "\nCreate a link to TARGET with the name LINK_NAME.\n\n");
    fprintf(stderr, "  -s    make symbolic links instead of hard links\n");
    fprintf(stderr, "  -f    remove existing destination files\n");
    fprintf(stderr, "  -v    verbose\n");
    fprintf(stderr, "  --help display this help and exit\n");
}

/*
 * Build dir/basename(target)
 */
static char *path_join(const char *dir, const char *name)
{
    const char *base = strrchr(name, '/');
    base = base ? base + 1 : name;

    size_t dlen = strlen(dir);
    size_t blen = strlen(base);
    char *out = malloc(dlen + 1 + blen + 1);
    if (!out) {
        fprintf(stderr, "%s: out of memory\n", progname);
        return NULL;
    }
    memcpy(out, dir, dlen);
    if (dlen > 0 && dir[dlen - 1] != '/')
        out[dlen++] = '/';
    memcpy(out + dlen, base, blen);
    out[dlen + blen] = '\0';
    return out;
}

static int do_link(const char *target, const char *linkname)
{
    if (opt_force)
        unlink(linkname);

    int ret;
    if (opt_symbolic)
        ret = symlink(target, linkname);
    else
        ret = link(target, linkname);

    if (ret < 0) {
        fprintf(stderr, "%s: failed to create %slink '%s' -> '%s': %s\n",
                progname, opt_symbolic ? "symbolic " : "hard ",
                linkname, target, strerror(errno));
        return 1;
    }

    if (opt_verbose)
        printf("'%s' -> '%s'\n", linkname, target);

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
                case 's': opt_symbolic = 1; break;
                case 'f': opt_force = 1; break;
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
    if (nargs < 1) {
        fprintf(stderr, "%s: missing operand\n", progname);
        usage();
        return 1;
    }

    if (nargs == 1) {
        /*
         * Single argument: create link in current directory with the same
         * basename as target. E.g. "ln -s /usr/bin/foo" creates "./foo".
         */
        const char *target = argv[first_arg];
        const char *base = strrchr(target, '/');
        base = base ? base + 1 : target;
        return do_link(target, base);
    }

    const char *dst = argv[argc - 1];
    int nsources = nargs - 1;

    struct stat dst_st;
    int dst_is_dir = (stat(dst, &dst_st) == 0 && S_ISDIR(dst_st.st_mode));

    if (nsources > 1 && !dst_is_dir) {
        fprintf(stderr, "%s: target '%s' is not a directory\n", progname, dst);
        return 1;
    }

    int ret = 0;
    for (int i = 0; i < nsources; i++) {
        const char *target = argv[first_arg + i];
        if (dst_is_dir) {
            char *linkname = path_join(dst, target);
            if (!linkname) {
                ret = 1;
                continue;
            }
            if (do_link(target, linkname) != 0)
                ret = 1;
            free(linkname);
        } else {
            if (do_link(target, dst) != 0)
                ret = 1;
        }
    }

    return ret;
}
