/*
 * du - estimate file space usage
 *
 * Kiseki OS coreutils
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>

static const char *progname = "du";

static int opt_human    = 0;
static int opt_summary  = 0;
static int opt_all      = 0;
static int opt_kilo     = 0;
static int opt_total    = 0;
static int opt_maxdepth = -1; /* -1 means unlimited */

static void usage(void)
{
    fprintf(stderr, "Usage: %s [OPTION]... [FILE]...\n", progname);
    fprintf(stderr, "Summarize disk usage of the set of FILEs, "
                    "recursively for directories.\n\n");
    fprintf(stderr, "  -h              human-readable sizes (K, M, G)\n");
    fprintf(stderr, "  -s              display only a total for each argument\n");
    fprintf(stderr, "  -a              write counts for all files, not just directories\n");
    fprintf(stderr, "  -k              use 1024-byte blocks (default)\n");
    fprintf(stderr, "  -c              produce a grand total\n");
    fprintf(stderr, "  -d NUM          print total for a directory only if it is NUM\n");
    fprintf(stderr, "                  or fewer levels below the argument\n");
    fprintf(stderr, "  --max-depth=NUM same as -d\n");
    fprintf(stderr, "  --help          display this help and exit\n");
}

/*
 * Format a block count (in 1K blocks) as human-readable.
 */
static void format_size(unsigned long kblocks, char *buf, size_t buflen)
{
    if (!opt_human) {
        snprintf(buf, buflen, "%lu", kblocks);
        return;
    }

    double val = (double)kblocks;
    const char *units[] = {"K", "M", "G", "T", "P"};
    int idx = 0;

    while (val >= 1024.0 && idx < 4) {
        val /= 1024.0;
        idx++;
    }

    if (idx == 0) {
        /* Already in K */
        if (kblocks < 10)
            snprintf(buf, buflen, "%luK", kblocks);
        else
            snprintf(buf, buflen, "%luK", kblocks);
    } else {
        if (val >= 100.0)
            snprintf(buf, buflen, "%lu%s", (unsigned long)(val + 0.5),
                     units[idx]);
        else if (val >= 10.0)
            snprintf(buf, buflen, "%.1f%s", val, units[idx]);
        else
            snprintf(buf, buflen, "%.1f%s", val, units[idx]);
    }
}

static void print_size(unsigned long kblocks, const char *path)
{
    char buf[32];
    format_size(kblocks, buf, sizeof(buf));
    printf("%-8s%s\n", buf, path);
}

/*
 * Build a path by joining dir and name with '/'.
 */
static char *path_join(const char *dir, const char *name)
{
    size_t dlen = strlen(dir);
    size_t nlen = strlen(name);
    char *out = malloc(dlen + 1 + nlen + 1);
    if (!out) {
        fprintf(stderr, "%s: out of memory\n", progname);
        return NULL;
    }
    memcpy(out, dir, dlen);
    if (dlen > 0 && dir[dlen - 1] != '/')
        out[dlen++] = '/';
    memcpy(out + dlen, name, nlen);
    out[dlen + nlen] = '\0';
    return out;
}

/*
 * Recursively compute disk usage.
 *
 * Returns the total size in 1K blocks for the tree rooted at 'path'.
 * depth: current depth (0 = the argument itself).
 */
static unsigned long du_path(const char *path, int depth)
{
    struct stat st;
    if (lstat(path, &st) < 0) {
        fprintf(stderr, "%s: cannot access '%s': %s\n",
                progname, path, strerror(errno));
        return 0;
    }

    /* Size of this entry in 1K blocks: st_blocks is in 512-byte units */
    unsigned long this_size = ((unsigned long)st.st_blocks * 512 + 1023) / 1024;

    if (!S_ISDIR(st.st_mode)) {
        /* Regular file or symlink */
        if (opt_all && !opt_summary) {
            if (opt_maxdepth < 0 || depth <= opt_maxdepth)
                print_size(this_size, path);
        }
        return this_size;
    }

    /* Directory: recurse */
    DIR *dp = opendir(path);
    if (!dp) {
        fprintf(stderr, "%s: cannot read directory '%s': %s\n",
                progname, path, strerror(errno));
        return this_size;
    }

    unsigned long total = this_size;
    struct dirent *ent;

    while ((ent = readdir(dp)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        char *child = path_join(path, ent->d_name);
        if (!child)
            continue;

        total += du_path(child, depth + 1);
        free(child);
    }

    closedir(dp);

    /* Print this directory's total */
    if (opt_summary) {
        /* In summary mode, only print at depth 0 (done by caller) */
    } else if (opt_maxdepth >= 0 && depth > opt_maxdepth) {
        /* Depth exceeded: don't print */
    } else {
        print_size(total, path);
    }

    return total;
}

int main(int argc, char *argv[])
{
    int first_arg = argc;

    /* Parse options */
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
            /* Handle --max-depth=NUM */
            if (strncmp(argv[i], "--max-depth=", 12) == 0) {
                opt_maxdepth = atoi(argv[i] + 12);
                if (opt_maxdepth < 0)
                    opt_maxdepth = 0;
                continue;
            }
            if (strcmp(argv[i], "--max-depth") == 0) {
                if (i + 1 < argc) {
                    opt_maxdepth = atoi(argv[++i]);
                    if (opt_maxdepth < 0)
                        opt_maxdepth = 0;
                } else {
                    fprintf(stderr, "%s: --max-depth requires an argument\n",
                            progname);
                    return 1;
                }
                continue;
            }

            const char *p = &argv[i][1];
            while (*p) {
                switch (*p) {
                case 'h': opt_human = 1; break;
                case 's': opt_summary = 1; break;
                case 'a': opt_all = 1; break;
                case 'k': opt_kilo = 1; break;
                case 'c': opt_total = 1; break;
                case 'd':
                    /* -d NUM: next char or next arg */
                    if (*(p + 1) != '\0') {
                        opt_maxdepth = atoi(p + 1);
                        if (opt_maxdepth < 0)
                            opt_maxdepth = 0;
                        goto next_arg;
                    } else if (i + 1 < argc) {
                        opt_maxdepth = atoi(argv[++i]);
                        if (opt_maxdepth < 0)
                            opt_maxdepth = 0;
                        goto next_arg;
                    } else {
                        fprintf(stderr, "%s: option -d requires an argument\n",
                                progname);
                        return 1;
                    }
                    break;
                default:
                    fprintf(stderr, "%s: invalid option -- '%c'\n",
                            progname, *p);
                    usage();
                    return 1;
                }
                p++;
            }
next_arg:;
        } else {
            first_arg = i;
            break;
        }
    }

    (void)opt_kilo; /* -k is the default behaviour */

    /* Default: current directory */
    const char *default_args[] = {"."};
    const char **args;
    int nargs;

    if (first_arg >= argc) {
        args = default_args;
        nargs = 1;
    } else {
        args = (const char **)&argv[first_arg];
        nargs = argc - first_arg;
    }

    unsigned long grand_total = 0;

    for (int i = 0; i < nargs; i++) {
        unsigned long total = du_path(args[i], 0);

        if (opt_summary)
            print_size(total, args[i]);

        grand_total += total;
    }

    if (opt_total)
        print_size(grand_total, "total");

    return 0;
}
