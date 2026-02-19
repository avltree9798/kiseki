/*
 * umount - unmount filesystems
 *
 * Kiseki OS coreutils
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mount.h>

/*
 * Kiseki umount stubs. Use kiseki_ prefix to avoid conflicting with
 * macOS system symbols (unmount on macOS).
 */
static int kiseki_umount(const char *target)
{
    (void)target;
    errno = ENOSYS;
    return -1;
}

static int kiseki_umount2(const char *target, int flags)
{
    (void)target; (void)flags;
    errno = ENOSYS;
    return -1;
}

/* umount2 flags (Kiseki OS) */
#define KISEKI_MNT_FORCE    1   /* Force unmount */
#define KISEKI_MNT_DETACH   2   /* Lazy unmount */
#define KISEKI_MNT_EXPIRE   4   /* Mark for expiry */

static const char *progname = "umount";

static int opt_force    = 0;
static int opt_lazy     = 0;
static int opt_all      = 0;
static int opt_verbose  = 0;

static void usage(void)
{
    fprintf(stderr, "Usage: %s [OPTION]... MOUNTPOINT|DEVICE...\n", progname);
    fprintf(stderr, "Unmount filesystems.\n\n");
    fprintf(stderr, "  -f    force unmount (in case of unreachable NFS)\n");
    fprintf(stderr, "  -l    lazy unmount (detach now, clean up later)\n");
    fprintf(stderr, "  -a    unmount all filesystems from /etc/mtab\n");
    fprintf(stderr, "  -v    verbose\n");
    fprintf(stderr, "  --help display this help and exit\n");
}

/*
 * Find the mountpoint for a given device by reading /etc/mtab.
 * Returns a strdup'd string, or NULL if not found.
 */
static char *find_mountpoint(const char *device_or_mnt)
{
    FILE *fp = fopen("/etc/mtab", "r");
    if (!fp)
        return NULL;

    char line[1024];
    while (fgets(line, (int)sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n')
            continue;

        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n')
            line[len - 1] = '\0';

        /* Save a copy since strtok modifies the string */
        char saved[1024];
        strncpy(saved, line, sizeof(saved) - 1);
        saved[sizeof(saved) - 1] = '\0';

        char *saveptr;
        char *dev = strtok_r(line, " \t", &saveptr);
        char *mnt = strtok_r(NULL, " \t", &saveptr);

        if (!dev || !mnt)
            continue;

        /* Match on device or mountpoint */
        if (strcmp(dev, device_or_mnt) == 0 ||
            strcmp(mnt, device_or_mnt) == 0) {
            fclose(fp);
            return strdup(mnt);
        }
    }

    fclose(fp);
    return NULL;
}

/*
 * Remove an entry from /etc/mtab for the given mountpoint.
 */
static void remove_mtab_entry(const char *mountpoint)
{
    FILE *fp = fopen("/etc/mtab", "r");
    if (!fp)
        return;

    /* Read all lines */
    char lines[64][1024];
    int nlines = 0;

    while (nlines < 64 && fgets(lines[nlines], 1024, fp))
        nlines++;

    fclose(fp);

    /* Rewrite without the matching entry */
    fp = fopen("/etc/mtab", "w");
    if (!fp)
        return;

    for (int i = 0; i < nlines; i++) {
        char tmp[1024];
        strncpy(tmp, lines[i], sizeof(tmp) - 1);
        tmp[sizeof(tmp) - 1] = '\0';

        char *saveptr;
        char *dev = strtok_r(tmp, " \t", &saveptr);
        char *mnt = strtok_r(NULL, " \t", &saveptr);

        /* Keep lines that don't match */
        if (!dev || !mnt ||
            (strcmp(mnt, mountpoint) != 0 && strcmp(dev, mountpoint) != 0)) {
            fputs(lines[i], fp);
        }
    }

    fclose(fp);
}

static int do_umount(const char *target)
{
    /* Try to resolve device names to mountpoints */
    char *mountpoint = find_mountpoint(target);
    const char *actual_target = mountpoint ? mountpoint : target;

    if (opt_verbose)
        printf("umount: unmounting %s\n", actual_target);

    int ret;
    int flags = 0;

    if (opt_force)
        flags |= KISEKI_MNT_FORCE;
    if (opt_lazy)
        flags |= KISEKI_MNT_DETACH;

    if (flags != 0)
        ret = kiseki_umount2(actual_target, flags);
    else
        ret = kiseki_umount(actual_target);

    if (ret < 0) {
        fprintf(stderr, "%s: %s: %s\n",
                progname, actual_target, strerror(errno));
        free(mountpoint);
        return 1;
    }

    /* Update /etc/mtab */
    remove_mtab_entry(actual_target);

    if (opt_verbose)
        printf("umount: %s unmounted\n", actual_target);

    free(mountpoint);
    return 0;
}

/*
 * Unmount all filesystems listed in /etc/mtab (in reverse order).
 */
static int umount_all(void)
{
    FILE *fp = fopen("/etc/mtab", "r");
    if (!fp) {
        fprintf(stderr, "%s: cannot open /etc/mtab: %s\n",
                progname, strerror(errno));
        return 1;
    }

    /* Read all mountpoints */
    char mountpoints[64][256];
    int count = 0;

    char line[1024];
    while (count < 64 && fgets(line, (int)sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n')
            continue;

        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n')
            line[len - 1] = '\0';

        char *saveptr;
        char *dev = strtok_r(line, " \t", &saveptr);
        char *mnt = strtok_r(NULL, " \t", &saveptr);

        (void)dev;
        if (mnt) {
            strncpy(mountpoints[count], mnt,
                    sizeof(mountpoints[count]) - 1);
            mountpoints[count][sizeof(mountpoints[count]) - 1] = '\0';
            count++;
        }
    }

    fclose(fp);

    /* Unmount in reverse order (leaf mounts first) */
    int ret = 0;
    for (int i = count - 1; i >= 0; i--) {
        /* Skip root filesystem unless forced */
        if (strcmp(mountpoints[i], "/") == 0 && !opt_force)
            continue;

        if (do_umount(mountpoints[i]) != 0)
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
                case 'f': opt_force = 1; break;
                case 'l': opt_lazy = 1; break;
                case 'a': opt_all = 1; break;
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

    if (opt_all)
        return umount_all();

    if (first_arg >= argc) {
        fprintf(stderr, "%s: missing operand\n", progname);
        usage();
        return 1;
    }

    int ret = 0;
    for (int i = first_arg; i < argc; i++) {
        if (do_umount(argv[i]) != 0)
            ret = 1;
    }

    return ret;
}
