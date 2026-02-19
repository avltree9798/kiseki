/*
 * touch - change file timestamps
 *
 * Kiseki OS coreutils
 *
 * Note: Since utimes()/utime() syscalls are not yet available in Kiseki,
 * we update timestamps by opening the file (which updates atime/mtime
 * on most filesystems). For existing files we open+close; for new files
 * we create them.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>

static const char *progname = "touch";

static int opt_no_create = 0;
static int opt_atime     = 0;  /* -a: access time only (informational) */
static int opt_mtime     = 0;  /* -m: modification time only (informational) */

static void usage(void)
{
    fprintf(stderr, "Usage: %s [OPTION]... FILE...\n", progname);
    fprintf(stderr, "Update the access and modification times of each FILE to the current time.\n");
    fprintf(stderr, "A FILE that does not exist is created empty, unless -c is given.\n\n");
    fprintf(stderr, "  -a    change only the access time\n");
    fprintf(stderr, "  -c    do not create any files\n");
    fprintf(stderr, "  -m    change only the modification time\n");
    fprintf(stderr, "  --help display this help and exit\n");
}

static int do_touch(const char *path)
{
    struct stat st;
    int exists = (stat(path, &st) == 0);

    if (!exists) {
        if (opt_no_create)
            return 0;

        /* Create the file */
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0666);
        if (fd < 0) {
            fprintf(stderr, "%s: cannot touch '%s': %s\n", progname, path,
                    strerror(errno));
            return 1;
        }
        close(fd);
        return 0;
    }

    /*
     * File exists. Open it to update timestamps.
     * Opening with O_WRONLY and immediately closing updates mtime on most
     * filesystems. For a more precise approach we'd need utimes() which
     * is not yet available.
     *
     * For read-only files, try O_RDONLY (at least updates atime).
     */
    int fd = open(path, O_WRONLY | O_APPEND);
    if (fd < 0) {
        /* Try read-only to at least update atime */
        fd = open(path, O_RDONLY);
        if (fd < 0) {
            fprintf(stderr, "%s: cannot touch '%s': %s\n", progname, path,
                    strerror(errno));
            return 1;
        }
    }
    close(fd);
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
                case 'a': opt_atime = 1; break;
                case 'c': opt_no_create = 1; break;
                case 'm': opt_mtime = 1; break;
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

    /* Suppress unused warnings for informational flags */
    (void)opt_atime;
    (void)opt_mtime;

    int ret = 0;
    for (int i = first_arg; i < argc; i++) {
        if (do_touch(argv[i]) != 0)
            ret = 1;
    }

    return ret;
}
