/*
 * chmod - change file mode bits
 *
 * Kiseki OS coreutils
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>

static const char *progname = "chmod";

static int opt_recursive = 0;
static int opt_verbose   = 0;
static int opt_silent    = 0;

static void usage(void)
{
    fprintf(stderr, "Usage: %s [OPTION]... MODE[,MODE]... FILE...\n", progname);
    fprintf(stderr, "Change the mode of each FILE to MODE.\n\n");
    fprintf(stderr, "  MODE can be octal (e.g. 755) or symbolic (e.g. u+x,go-w)\n");
    fprintf(stderr, "  -R    change files and directories recursively\n");
    fprintf(stderr, "  -v    output a diagnostic for every file processed\n");
    fprintf(stderr, "  -f    suppress most error messages\n");
    fprintf(stderr, "  --help display this help and exit\n");
}

static void mode_str(mode_t m, char *buf)
{
    buf[0] = (m & S_IRUSR) ? 'r' : '-';
    buf[1] = (m & S_IWUSR) ? 'w' : '-';
    buf[2] = (m & S_ISUID) ? ((m & S_IXUSR) ? 's' : 'S')
                            : ((m & S_IXUSR) ? 'x' : '-');
    buf[3] = (m & S_IRGRP) ? 'r' : '-';
    buf[4] = (m & S_IWGRP) ? 'w' : '-';
    buf[5] = (m & S_ISGID) ? ((m & S_IXGRP) ? 's' : 'S')
                            : ((m & S_IXGRP) ? 'x' : '-');
    buf[6] = (m & S_IROTH) ? 'r' : '-';
    buf[7] = (m & S_IWOTH) ? 'w' : '-';
    buf[8] = (m & S_ISVTX) ? ((m & S_IXOTH) ? 't' : 'T')
                            : ((m & S_IXOTH) ? 'x' : '-');
    buf[9] = '\0';
}

/*
 * Parse a single symbolic mode clause: [ugoa...][+-=][rwxst...]
 * Applies the operation to *mode_out based on the current mode.
 * Returns 0 on success, -1 on error.
 */
static int apply_symbolic_clause(const char *clause, mode_t *mode_out,
                                 mode_t current)
{
    const char *p = clause;
    mode_t who_mask = 0;

    /* Parse who: u, g, o, a */
    while (*p == 'u' || *p == 'g' || *p == 'o' || *p == 'a') {
        switch (*p) {
        case 'u': who_mask |= S_IRWXU | S_ISUID; break;
        case 'g': who_mask |= S_IRWXG | S_ISGID; break;
        case 'o': who_mask |= S_IRWXO | S_ISVTX; break;
        case 'a': who_mask |= S_IRWXU | S_IRWXG | S_IRWXO |
                               S_ISUID | S_ISGID | S_ISVTX; break;
        }
        p++;
    }

    /* If no who specified, default to 'a' (but masked by umask for +/=) */
    if (who_mask == 0)
        who_mask = S_IRWXU | S_IRWXG | S_IRWXO | S_ISUID | S_ISGID | S_ISVTX;

    /* May have multiple op+perm groups: u+r-w */
    while (*p == '+' || *p == '-' || *p == '=') {
        char op = *p++;

        /* Parse permission characters */
        mode_t perm_bits = 0;
        while (*p && *p != '+' && *p != '-' && *p != '=' && *p != ',') {
            switch (*p) {
            case 'r':
                perm_bits |= S_IRUSR | S_IRGRP | S_IROTH;
                break;
            case 'w':
                perm_bits |= S_IWUSR | S_IWGRP | S_IWOTH;
                break;
            case 'x':
                perm_bits |= S_IXUSR | S_IXGRP | S_IXOTH;
                break;
            case 's':
                perm_bits |= S_ISUID | S_ISGID;
                break;
            case 't':
                perm_bits |= S_ISVTX;
                break;
            default:
                return -1;
            }
            p++;
        }

        /* Mask perm_bits by who_mask */
        perm_bits &= who_mask;

        switch (op) {
        case '+':
            *mode_out |= perm_bits;
            break;
        case '-':
            *mode_out &= ~perm_bits;
            break;
        case '=':
            /* Clear all bits covered by who_mask, then set perm_bits */
            *mode_out &= ~(who_mask & (S_IRWXU | S_IRWXG | S_IRWXO |
                                        S_ISUID | S_ISGID | S_ISVTX));
            *mode_out |= perm_bits;
            break;
        }
    }

    (void)current;
    return (*p == '\0' || *p == ',') ? 0 : -1;
}

/*
 * Parse a full symbolic mode string (comma-separated clauses).
 * Applies changes to the current mode and returns the new mode.
 * Returns -1 on parse error.
 */
static int parse_symbolic_mode(const char *mode_str_arg, mode_t current,
                               mode_t *result)
{
    *result = current & (S_IRWXU | S_IRWXG | S_IRWXO |
                         S_ISUID | S_ISGID | S_ISVTX);

    /* Work on a copy so we can use strtok_r */
    char *copy = strdup(mode_str_arg);
    if (!copy)
        return -1;

    char *saveptr;
    char *token = strtok_r(copy, ",", &saveptr);
    while (token) {
        if (apply_symbolic_clause(token, result, current) < 0) {
            free(copy);
            return -1;
        }
        token = strtok_r(NULL, ",", &saveptr);
    }

    free(copy);
    return 0;
}

/*
 * Try to parse mode_arg as octal. Returns 1 if it is octal, 0 otherwise.
 */
static int parse_octal_mode(const char *mode_arg, mode_t *result)
{
    const char *p = mode_arg;
    mode_t m = 0;

    if (*p == '\0')
        return 0;

    while (*p) {
        if (*p < '0' || *p > '7')
            return 0;
        m = (m << 3) | (mode_t)(*p - '0');
        p++;
    }

    *result = m;
    return 1;
}

static int do_chmod(const char *path, const char *mode_arg);

static int do_chmod_recursive(const char *path, const char *mode_arg)
{
    DIR *dp = opendir(path);
    if (!dp) {
        if (!opt_silent)
            fprintf(stderr, "%s: cannot open directory '%s': %s\n",
                    progname, path, strerror(errno));
        return 1;
    }

    int ret = 0;
    struct dirent *ent;
    while ((ent = readdir(dp)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        size_t plen = strlen(path);
        size_t nlen = strlen(ent->d_name);
        char *child = malloc(plen + 1 + nlen + 1);
        if (!child) {
            fprintf(stderr, "%s: out of memory\n", progname);
            ret = 1;
            break;
        }
        snprintf(child, plen + 1 + nlen + 1, "%s/%s", path, ent->d_name);

        if (do_chmod(child, mode_arg) != 0)
            ret = 1;

        free(child);
    }

    closedir(dp);
    return ret;
}

static int do_chmod(const char *path, const char *mode_arg)
{
    struct stat st;
    if (lstat(path, &st) < 0) {
        if (!opt_silent)
            fprintf(stderr, "%s: cannot access '%s': %s\n",
                    progname, path, strerror(errno));
        return 1;
    }

    /* Don't follow symlinks */
    if (S_ISLNK(st.st_mode))
        return 0;

    mode_t new_mode;

    if (parse_octal_mode(mode_arg, &new_mode)) {
        /* Octal mode: use directly */
    } else {
        /* Symbolic mode */
        if (parse_symbolic_mode(mode_arg, st.st_mode, &new_mode) < 0) {
            fprintf(stderr, "%s: invalid mode: '%s'\n", progname, mode_arg);
            return 1;
        }
    }

    mode_t old_mode = st.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO |
                                     S_ISUID | S_ISGID | S_ISVTX);

    if (chmod(path, new_mode) < 0) {
        if (!opt_silent)
            fprintf(stderr, "%s: changing permissions of '%s': %s\n",
                    progname, path, strerror(errno));
        return 1;
    }

    if (opt_verbose) {
        char oldbuf[16], newbuf[16];
        mode_str(old_mode, oldbuf);
        mode_str(new_mode, newbuf);
        printf("mode of '%s' changed from %04o (%s) to %04o (%s)\n",
               path, (unsigned)old_mode, oldbuf,
               (unsigned)new_mode, newbuf);
    }

    int ret = 0;

    /* Recurse into directories */
    if (opt_recursive && S_ISDIR(st.st_mode)) {
        if (do_chmod_recursive(path, mode_arg) != 0)
            ret = 1;
    }

    return ret;
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
            const char *p = &argv[i][1];
            while (*p) {
                switch (*p) {
                case 'R': opt_recursive = 1; break;
                case 'v': opt_verbose = 1; break;
                case 'f': opt_silent = 1; break;
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
    if (nargs < 2) {
        fprintf(stderr, "%s: missing operand\n", progname);
        usage();
        return 1;
    }

    const char *mode_arg = argv[first_arg];
    int ret = 0;

    for (int i = first_arg + 1; i < argc; i++) {
        if (do_chmod(argv[i], mode_arg) != 0)
            ret = 1;
    }

    return ret;
}
