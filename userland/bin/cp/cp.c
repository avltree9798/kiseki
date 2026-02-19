/*
 * cp - copy files and directories
 *
 * Kiseki OS coreutils
 */

#include <stdint.h>
#include <sys/types.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>

static const char *progname = "cp";

static int opt_recursive = 0;
static int opt_force     = 0;
static int opt_interact  = 0;
static int opt_verbose   = 0;
static int opt_preserve  = 0;

static void usage(void)
{
    fprintf(stderr, "Usage: %s [OPTION]... SOURCE DEST\n", progname);
    fprintf(stderr, "   or: %s [OPTION]... SOURCE... DIRECTORY\n", progname);
    fprintf(stderr, "\nCopy SOURCE to DEST, or multiple SOURCE(s) to DIRECTORY.\n\n");
    fprintf(stderr, "  -r, -R    copy directories recursively\n");
    fprintf(stderr, "  -f        force: remove destination if needed\n");
    fprintf(stderr, "  -i        prompt before overwrite\n");
    fprintf(stderr, "  -v        verbose\n");
    fprintf(stderr, "  -p        preserve mode and timestamps\n");
    fprintf(stderr, "  --help    display this help and exit\n");
}

/*
 * Ask the user for confirmation. Returns 1 for yes, 0 for no.
 */
static int confirm(const char *fmt, const char *arg)
{
    fprintf(stderr, "%s: %s '%s'? ", progname, fmt, arg);
    fflush(stderr);
    char buf[64];
    if (fgets(buf, (int)sizeof(buf), stdin) == NULL)
        return 0;
    return (buf[0] == 'y' || buf[0] == 'Y');
}

/*
 * Build a destination path: dir/basename(src)
 */
static char *path_join(const char *dir, const char *name)
{
    /* Find basename of name */
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

/*
 * Copy a single regular file from src to dst.
 */
static int copy_file(const char *src, const char *dst, mode_t mode)
{
    int fd_in = open(src, O_RDONLY);
    if (fd_in < 0) {
        fprintf(stderr, "%s: cannot open '%s': %s\n", progname, src,
                strerror(errno));
        return 1;
    }

    /* If destination exists and interactive, ask */
    if (opt_interact && access(dst, F_OK) == 0) {
        if (!confirm("overwrite", dst)) {
            close(fd_in);
            return 0;
        }
    }

    /* If force, try to remove destination first */
    if (opt_force)
        unlink(dst);

    int fd_out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd_out < 0) {
        fprintf(stderr, "%s: cannot create '%s': %s\n", progname, dst,
                strerror(errno));
        close(fd_in);
        return 1;
    }

    char buf[8192];
    ssize_t n;
    int ret = 0;

    while ((n = read(fd_in, buf, sizeof(buf))) > 0) {
        ssize_t written = 0;
        while (written < n) {
            ssize_t w = write(fd_out, buf + written, (size_t)(n - written));
            if (w < 0) {
                fprintf(stderr, "%s: write error on '%s': %s\n", progname,
                        dst, strerror(errno));
                ret = 1;
                goto done;
            }
            written += w;
        }
    }
    if (n < 0) {
        fprintf(stderr, "%s: read error on '%s': %s\n", progname, src,
                strerror(errno));
        ret = 1;
    }

done:
    close(fd_in);

    /* Preserve permissions */
    if (opt_preserve && ret == 0)
        fchmod(fd_out, mode);

    close(fd_out);

    if (opt_verbose && ret == 0)
        printf("'%s' -> '%s'\n", src, dst);

    return ret;
}

/*
 * Recursively copy src to dst.
 */
static int copy_entry(const char *src, const char *dst)
{
    struct stat st;

    if (lstat(src, &st) < 0) {
        fprintf(stderr, "%s: cannot stat '%s': %s\n", progname, src,
                strerror(errno));
        return 1;
    }

    if (S_ISDIR(st.st_mode)) {
        if (!opt_recursive) {
            fprintf(stderr, "%s: -r not specified; omitting directory '%s'\n",
                    progname, src);
            return 1;
        }

        /* Create destination directory */
        mode_t dmode = opt_preserve ? st.st_mode : (st.st_mode | S_IRWXU);
        if (mkdir(dst, dmode) < 0 && errno != EEXIST) {
            fprintf(stderr, "%s: cannot create directory '%s': %s\n",
                    progname, dst, strerror(errno));
            return 1;
        }

        if (opt_verbose)
            printf("'%s' -> '%s'\n", src, dst);

        DIR *dp = opendir(src);
        if (!dp) {
            fprintf(stderr, "%s: cannot open directory '%s': %s\n",
                    progname, src, strerror(errno));
            return 1;
        }

        int ret = 0;
        struct dirent *ent;
        while ((ent = readdir(dp)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 ||
                strcmp(ent->d_name, "..") == 0)
                continue;

            /* Build full source and destination paths */
            size_t slen = strlen(src);
            size_t nlen = strlen(ent->d_name);
            char *child_src = malloc(slen + 1 + nlen + 1);
            char *child_dst = malloc(strlen(dst) + 1 + nlen + 1);
            if (!child_src || !child_dst) {
                fprintf(stderr, "%s: out of memory\n", progname);
                free(child_src);
                free(child_dst);
                ret = 1;
                break;
            }

            snprintf(child_src, slen + 1 + nlen + 1, "%s/%s", src,
                     ent->d_name);
            snprintf(child_dst, strlen(dst) + 1 + nlen + 1, "%s/%s", dst,
                     ent->d_name);

            if (copy_entry(child_src, child_dst) != 0)
                ret = 1;

            free(child_src);
            free(child_dst);
        }

        closedir(dp);

        /* Restore exact permissions after copying children */
        if (opt_preserve)
            chmod(dst, st.st_mode);

        return ret;
    }

    if (S_ISLNK(st.st_mode)) {
        char linkbuf[PATH_MAX];
        ssize_t len = readlink(src, linkbuf, sizeof(linkbuf) - 1);
        if (len < 0) {
            fprintf(stderr, "%s: cannot read symlink '%s': %s\n",
                    progname, src, strerror(errno));
            return 1;
        }
        linkbuf[len] = '\0';

        if (opt_force)
            unlink(dst);

        if (symlink(linkbuf, dst) < 0) {
            fprintf(stderr, "%s: cannot create symlink '%s': %s\n",
                    progname, dst, strerror(errno));
            return 1;
        }
        if (opt_verbose)
            printf("'%s' -> '%s'\n", src, dst);
        return 0;
    }

    if (S_ISREG(st.st_mode)) {
        return copy_file(src, dst, st.st_mode);
    }

    fprintf(stderr, "%s: cannot copy special file '%s'\n", progname, src);
    return 1;
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
                case 'r': /* fall through */
                case 'R': opt_recursive = 1; break;
                case 'f': opt_force = 1; opt_interact = 0; break;
                case 'i': opt_interact = 1; opt_force = 0; break;
                case 'v': opt_verbose = 1; break;
                case 'p': opt_preserve = 1; break;
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

    const char *dst = argv[argc - 1];
    int nsources = nargs - 1;

    struct stat dst_st;
    int dst_is_dir = (stat(dst, &dst_st) == 0 && S_ISDIR(dst_st.st_mode));

    /* Multiple sources require destination to be a directory */
    if (nsources > 1 && !dst_is_dir) {
        fprintf(stderr, "%s: target '%s' is not a directory\n", progname, dst);
        return 1;
    }

    int ret = 0;
    for (int i = 0; i < nsources; i++) {
        const char *src = argv[first_arg + i];
        if (dst_is_dir) {
            char *target = path_join(dst, src);
            if (!target) {
                ret = 1;
                continue;
            }
            if (copy_entry(src, target) != 0)
                ret = 1;
            free(target);
        } else {
            if (copy_entry(src, dst) != 0)
                ret = 1;
        }
    }

    return ret;
}
