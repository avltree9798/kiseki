/*
 * mv - move (rename) files
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

static const char *progname = "mv";

static int opt_force    = 0;
static int opt_interact = 0;
static int opt_verbose  = 0;

static void usage(void)
{
    fprintf(stderr, "Usage: %s [OPTION]... SOURCE DEST\n", progname);
    fprintf(stderr, "   or: %s [OPTION]... SOURCE... DIRECTORY\n", progname);
    fprintf(stderr, "\nRename SOURCE to DEST, or move SOURCE(s) to DIRECTORY.\n\n");
    fprintf(stderr, "  -f    do not prompt before overwriting\n");
    fprintf(stderr, "  -i    prompt before overwrite\n");
    fprintf(stderr, "  -v    verbose\n");
    fprintf(stderr, "  --help display this help and exit\n");
}

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
 * Copy a regular file from src to dst. Used as fallback for cross-device moves.
 */
static int copy_file(const char *src, const char *dst, mode_t mode)
{
    int fd_in = open(src, O_RDONLY);
    if (fd_in < 0) {
        fprintf(stderr, "%s: cannot open '%s': %s\n", progname, src,
                strerror(errno));
        return 1;
    }

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
    close(fd_out);
    return ret;
}

/*
 * Recursively copy directory for cross-device move.
 */
static int copy_recursive(const char *src, const char *dst)
{
    struct stat st;
    if (lstat(src, &st) < 0) {
        fprintf(stderr, "%s: cannot stat '%s': %s\n", progname, src,
                strerror(errno));
        return 1;
    }

    if (S_ISDIR(st.st_mode)) {
        if (mkdir(dst, st.st_mode) < 0 && errno != EEXIST) {
            fprintf(stderr, "%s: cannot create directory '%s': %s\n",
                    progname, dst, strerror(errno));
            return 1;
        }

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

            size_t slen = strlen(src);
            size_t dlen = strlen(dst);
            size_t nlen = strlen(ent->d_name);

            char *csrc = malloc(slen + 1 + nlen + 1);
            char *cdst = malloc(dlen + 1 + nlen + 1);
            if (!csrc || !cdst) {
                fprintf(stderr, "%s: out of memory\n", progname);
                free(csrc);
                free(cdst);
                ret = 1;
                break;
            }

            snprintf(csrc, slen + 1 + nlen + 1, "%s/%s", src, ent->d_name);
            snprintf(cdst, dlen + 1 + nlen + 1, "%s/%s", dst, ent->d_name);

            if (copy_recursive(csrc, cdst) != 0)
                ret = 1;

            free(csrc);
            free(cdst);
        }

        closedir(dp);
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
        unlink(dst);
        if (symlink(linkbuf, dst) < 0) {
            fprintf(stderr, "%s: cannot create symlink '%s': %s\n",
                    progname, dst, strerror(errno));
            return 1;
        }
        return 0;
    }

    if (S_ISREG(st.st_mode))
        return copy_file(src, dst, st.st_mode);

    fprintf(stderr, "%s: cannot move special file '%s'\n", progname, src);
    return 1;
}

/*
 * Recursively remove a directory tree (for cross-device move cleanup).
 */
static int remove_recursive(const char *path)
{
    struct stat st;
    if (lstat(path, &st) < 0)
        return -1;

    if (!S_ISDIR(st.st_mode))
        return unlink(path);

    DIR *dp = opendir(path);
    if (!dp)
        return -1;

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
            ret = -1;
            break;
        }
        snprintf(child, plen + 1 + nlen + 1, "%s/%s", path, ent->d_name);

        if (remove_recursive(child) != 0)
            ret = -1;
        free(child);
    }

    closedir(dp);

    if (rmdir(path) != 0)
        ret = -1;

    return ret;
}

static int do_move(const char *src, const char *dst)
{
    /* Check if destination exists and handle -i/-f */
    if (access(dst, F_OK) == 0) {
        if (opt_interact) {
            if (!confirm("overwrite", dst))
                return 0;
        }
        if (opt_force)
            unlink(dst);
    }

    /* Try rename first (same filesystem) */
    if (rename(src, dst) == 0) {
        if (opt_verbose)
            printf("'%s' -> '%s'\n", src, dst);
        return 0;
    }

    /* If cross-device, fall back to copy + remove */
    if (errno == EXDEV) {
        if (copy_recursive(src, dst) != 0) {
            fprintf(stderr, "%s: cannot copy '%s' to '%s'\n", progname,
                    src, dst);
            return 1;
        }
        if (remove_recursive(src) != 0) {
            fprintf(stderr, "%s: cannot remove '%s': %s\n", progname,
                    src, strerror(errno));
            return 1;
        }
        if (opt_verbose)
            printf("'%s' -> '%s'\n", src, dst);
        return 0;
    }

    fprintf(stderr, "%s: cannot move '%s' to '%s': %s\n", progname,
            src, dst, strerror(errno));
    return 1;
}

/*
 * Build dir/basename(src)
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
    if (nargs < 2) {
        fprintf(stderr, "%s: missing operand\n", progname);
        usage();
        return 1;
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
        const char *src = argv[first_arg + i];
        if (dst_is_dir) {
            char *target = path_join(dst, src);
            if (!target) {
                ret = 1;
                continue;
            }
            if (do_move(src, target) != 0)
                ret = 1;
            free(target);
        } else {
            if (do_move(src, dst) != 0)
                ret = 1;
        }
    }

    return ret;
}
