/*
 * mount - mount filesystems
 *
 * Kiseki OS coreutils
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mount.h>

/*
 * Kiseki mount syscall wrapper.
 * On Kiseki OS, mount() is not yet a real syscall — this is a stub
 * that returns ENOSYS. The actual mount(2) is done by the kernel
 * at boot time.
 *
 * We use kiseki_mount to avoid conflicting with the macOS mount() symbol.
 */
static int kiseki_mount(const char *source, const char *target,
                        const char *fstype, unsigned long flags,
                        const void *data)
{
    (void)source; (void)target; (void)fstype; (void)flags; (void)data;
    errno = ENOSYS;
    return -1;
}

/* Mount flags (Kiseki OS) */
#define MS_RDONLY       1
#define MS_NOSUID       2
#define MS_NODEV        4
#define MS_NOEXEC       8
#define MS_SYNCHRONOUS  16
#define MS_REMOUNT      32
#define MS_MANDLOCK     64
#define MS_NOATIME      1024
#define MS_NODIRATIME   2048
#define MS_BIND         4096
#define MS_MOVE         8192

static const char *progname = "mount";

static const char *opt_fstype  = NULL;
static const char *opt_options = NULL;
static int         opt_all     = 0;
static int         opt_verbose = 0;

static void usage(void)
{
    fprintf(stderr, "Usage: %s [-t TYPE] [-o OPTIONS] DEVICE MOUNTPOINT\n",
            progname);
    fprintf(stderr, "       %s [-a] [-v]\n", progname);
    fprintf(stderr, "\nMount a filesystem.\n\n");
    fprintf(stderr, "  -t TYPE    filesystem type (e.g. ext4, tmpfs)\n");
    fprintf(stderr, "  -o OPTIONS comma-separated mount options\n");
    fprintf(stderr, "  -a         mount all filesystems in /etc/fstab\n");
    fprintf(stderr, "  -v         verbose\n");
    fprintf(stderr, "  --help     display this help and exit\n\n");
    fprintf(stderr, "With no arguments, display currently mounted filesystems.\n");
}

/*
 * Parse mount options string and return flags + remaining data string.
 * The data string contains options not recognized as standard flags.
 */
static unsigned long parse_options(const char *opts, char *data, size_t datalen)
{
    unsigned long flags = 0;
    data[0] = '\0';

    if (!opts || *opts == '\0')
        return 0;

    char *copy = strdup(opts);
    if (!copy)
        return 0;

    size_t dpos = 0;
    char *saveptr;
    char *tok = strtok_r(copy, ",", &saveptr);

    while (tok) {
        int recognized = 1;

        if (strcmp(tok, "ro") == 0)
            flags |= MS_RDONLY;
        else if (strcmp(tok, "rw") == 0)
            flags &= ~MS_RDONLY;
        else if (strcmp(tok, "nosuid") == 0)
            flags |= MS_NOSUID;
        else if (strcmp(tok, "suid") == 0)
            flags &= ~MS_NOSUID;
        else if (strcmp(tok, "nodev") == 0)
            flags |= MS_NODEV;
        else if (strcmp(tok, "dev") == 0)
            flags &= ~MS_NODEV;
        else if (strcmp(tok, "noexec") == 0)
            flags |= MS_NOEXEC;
        else if (strcmp(tok, "exec") == 0)
            flags &= ~MS_NOEXEC;
        else if (strcmp(tok, "sync") == 0)
            flags |= MS_SYNCHRONOUS;
        else if (strcmp(tok, "async") == 0)
            flags &= ~MS_SYNCHRONOUS;
        else if (strcmp(tok, "remount") == 0)
            flags |= MS_REMOUNT;
        else if (strcmp(tok, "noatime") == 0)
            flags |= MS_NOATIME;
        else if (strcmp(tok, "nodiratime") == 0)
            flags |= MS_NODIRATIME;
        else if (strcmp(tok, "bind") == 0)
            flags |= MS_BIND;
        else if (strcmp(tok, "move") == 0)
            flags |= MS_MOVE;
        else
            recognized = 0;

        /* Unrecognized options go into the data string for the filesystem */
        if (!recognized) {
            if (dpos > 0 && dpos < datalen - 1)
                data[dpos++] = ',';
            size_t tlen = strlen(tok);
            if (dpos + tlen < datalen - 1) {
                memcpy(data + dpos, tok, tlen);
                dpos += tlen;
            }
        }

        tok = strtok_r(NULL, ",", &saveptr);
    }

    data[dpos] = '\0';
    free(copy);
    return flags;
}

/*
 * Display currently mounted filesystems by reading /etc/mtab.
 */
static int show_mounts(void)
{
    FILE *fp = fopen("/etc/mtab", "r");
    if (!fp) {
        fp = fopen("/proc/mounts", "r");
    }
    if (!fp) {
        fprintf(stderr, "%s: cannot open /etc/mtab: %s\n",
                progname, strerror(errno));
        return 1;
    }

    char line[1024];
    while (fgets(line, (int)sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n')
            continue;

        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n')
            line[len - 1] = '\0';

        char *saveptr;
        char *dev = strtok_r(line, " \t", &saveptr);
        char *mnt = strtok_r(NULL, " \t", &saveptr);
        char *type = strtok_r(NULL, " \t", &saveptr);
        char *opts = strtok_r(NULL, " \t", &saveptr);

        if (!dev || !mnt)
            continue;

        printf("%s on %s type %s",
               dev, mnt, type ? type : "unknown");
        if (opts)
            printf(" (%s)", opts);
        printf("\n");
    }

    fclose(fp);
    return 0;
}

/*
 * Mount all filesystems from /etc/fstab.
 */
static int mount_all(void)
{
    FILE *fp = fopen("/etc/fstab", "r");
    if (!fp) {
        fprintf(stderr, "%s: cannot open /etc/fstab: %s\n",
                progname, strerror(errno));
        return 1;
    }

    char line[1024];
    int ret = 0;

    while (fgets(line, (int)sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n')
            continue;

        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n')
            line[len - 1] = '\0';

        char *saveptr;
        char *dev = strtok_r(line, " \t", &saveptr);
        char *mnt = strtok_r(NULL, " \t", &saveptr);
        char *type = strtok_r(NULL, " \t", &saveptr);
        char *opts = strtok_r(NULL, " \t", &saveptr);

        if (!dev || !mnt || !type)
            continue;

        /* Skip entries with "noauto" option */
        if (opts && strstr(opts, "noauto"))
            continue;

        char data[512];
        unsigned long flags = parse_options(opts, data, sizeof(data));

        if (opt_verbose)
            printf("mount: mounting %s on %s (type %s)\n", dev, mnt, type);

        if (kiseki_mount(dev, mnt, type, flags, data[0] ? data : NULL) < 0) {
            fprintf(stderr, "%s: mounting %s on %s failed: %s\n",
                    progname, dev, mnt, strerror(errno));
            ret = 1;
        }
    }

    fclose(fp);
    return ret;
}

/*
 * Append an entry to /etc/mtab.
 */
static void update_mtab(const char *dev, const char *mnt, const char *type,
                        const char *opts)
{
    FILE *fp = fopen("/etc/mtab", "a");
    if (!fp)
        return;
    fprintf(fp, "%s %s %s %s 0 0\n",
            dev, mnt, type ? type : "unknown",
            (opts && *opts) ? opts : "rw");
    fclose(fp);
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
                case 't':
                    /* -t TYPE: type follows immediately or as next arg */
                    if (*(p + 1) != '\0') {
                        opt_fstype = p + 1;
                        goto done_flags;
                    } else if (i + 1 < argc) {
                        opt_fstype = argv[++i];
                        goto done_flags;
                    } else {
                        fprintf(stderr, "%s: option -t requires an argument\n",
                                progname);
                        return 1;
                    }
                    break;
                case 'o':
                    if (*(p + 1) != '\0') {
                        opt_options = p + 1;
                        goto done_flags;
                    } else if (i + 1 < argc) {
                        opt_options = argv[++i];
                        goto done_flags;
                    } else {
                        fprintf(stderr, "%s: option -o requires an argument\n",
                                progname);
                        return 1;
                    }
                    break;
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
done_flags:;
        } else {
            first_arg = i;
            break;
        }
    }

    int nargs = argc - first_arg;

    /* No arguments: show current mounts */
    if (nargs == 0 && !opt_all) {
        return show_mounts();
    }

    /* -a: mount all from /etc/fstab */
    if (opt_all) {
        return mount_all();
    }

    /* Need exactly DEVICE and MOUNTPOINT */
    if (nargs < 2) {
        fprintf(stderr, "%s: missing operand\n", progname);
        usage();
        return 1;
    }

    const char *device = argv[first_arg];
    const char *mountpoint = argv[first_arg + 1];
    const char *fstype = opt_fstype ? opt_fstype : "auto";

    char data[512];
    unsigned long flags = parse_options(opt_options, data, sizeof(data));

    if (opt_verbose)
        printf("mount: mounting %s on %s (type %s)\n",
               device, mountpoint, fstype);

    if (kiseki_mount(device, mountpoint, fstype, flags, data[0] ? data : NULL) < 0) {
        fprintf(stderr, "%s: mount %s on %s failed: %s\n",
                progname, device, mountpoint, strerror(errno));
        return 1;
    }

    /* Update /etc/mtab */
    update_mtab(device, mountpoint, fstype, opt_options);

    if (opt_verbose)
        printf("mount: %s mounted on %s\n", device, mountpoint);

    return 0;
}
