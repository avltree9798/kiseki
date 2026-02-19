/*
 * df - report filesystem disk space usage
 *
 * Kiseki OS coreutils
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mount.h>

static const char *progname = "df";

static int opt_human    = 0;
static int opt_kilo     = 0;
static int opt_inodes   = 0;
static int opt_fstype   = 0;

static void usage(void)
{
    fprintf(stderr, "Usage: %s [OPTION]... [FILE]...\n", progname);
    fprintf(stderr, "Show information about the filesystem on which each FILE resides.\n\n");
    fprintf(stderr, "  -h    human-readable sizes (e.g. 1K, 234M, 2G)\n");
    fprintf(stderr, "  -k    use 1024-byte blocks (default)\n");
    fprintf(stderr, "  -i    show inode information instead of block usage\n");
    fprintf(stderr, "  -T    show filesystem type\n");
    fprintf(stderr, "  --help display this help and exit\n");
}

/*
 * Format a size in bytes as a human-readable string.
 */
static void human_size(unsigned long bytes, char *buf, size_t buflen)
{
    const char *units[] = {"B", "K", "M", "G", "T", "P"};
    int idx = 0;
    double val = (double)bytes;

    while (val >= 1024.0 && idx < 5) {
        val /= 1024.0;
        idx++;
    }

    if (idx == 0)
        snprintf(buf, buflen, "%lu", bytes);
    else if (val >= 100.0)
        snprintf(buf, buflen, "%lu%s", (unsigned long)(val + 0.5), units[idx]);
    else if (val >= 10.0)
        snprintf(buf, buflen, "%.1f%s", val, units[idx]);
    else
        snprintf(buf, buflen, "%.1f%s", val, units[idx]);
}

/*
 * Mount entry from /etc/mtab or /etc/fstab.
 */
struct mount_entry {
    char device[256];
    char mountpoint[256];
    char fstype[64];
};

/*
 * Read mount entries from /etc/mtab (or /etc/fstab as fallback).
 * Returns the number of entries read, or -1 on error.
 */
static int read_mounts(struct mount_entry *entries, int max_entries)
{
    FILE *fp = fopen("/etc/mtab", "r");
    if (!fp)
        fp = fopen("/etc/fstab", "r");
    if (!fp)
        return -1;

    int count = 0;
    char line[1024];
    while (fgets(line, (int)sizeof(line), fp) && count < max_entries) {
        /* Skip comments and blank lines */
        if (line[0] == '#' || line[0] == '\n')
            continue;

        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n')
            line[len - 1] = '\0';

        char *saveptr;
        char *dev = strtok_r(line, " \t", &saveptr);
        char *mnt = strtok_r(NULL, " \t", &saveptr);
        char *type = strtok_r(NULL, " \t", &saveptr);

        if (!dev || !mnt)
            continue;

        strncpy(entries[count].device, dev, sizeof(entries[count].device) - 1);
        entries[count].device[sizeof(entries[count].device) - 1] = '\0';
        strncpy(entries[count].mountpoint, mnt,
                sizeof(entries[count].mountpoint) - 1);
        entries[count].mountpoint[sizeof(entries[count].mountpoint) - 1] = '\0';
        if (type) {
            strncpy(entries[count].fstype, type,
                    sizeof(entries[count].fstype) - 1);
            entries[count].fstype[sizeof(entries[count].fstype) - 1] = '\0';
        } else {
            strcpy(entries[count].fstype, "unknown");
        }
        count++;
    }

    fclose(fp);
    return count;
}

static void print_header(void)
{
    if (opt_inodes) {
        if (opt_fstype)
            printf("%-20s %-8s %10s %10s %10s %5s %s\n",
                   "Filesystem", "Type", "Inodes", "IUsed", "IFree",
                   "IUse%", "Mounted on");
        else
            printf("%-20s %10s %10s %10s %5s %s\n",
                   "Filesystem", "Inodes", "IUsed", "IFree",
                   "IUse%", "Mounted on");
    } else {
        if (opt_fstype)
            printf("%-20s %-8s %10s %10s %10s %5s %s\n",
                   "Filesystem", "Type",
                   opt_human ? "Size" : "1K-blocks",
                   "Used", "Available", "Use%", "Mounted on");
        else
            printf("%-20s %10s %10s %10s %5s %s\n",
                   "Filesystem",
                   opt_human ? "Size" : "1K-blocks",
                   "Used", "Available", "Use%", "Mounted on");
    }
}

static void print_fs_entry(const char *device, const char *mountpoint,
                           const char *fstype)
{
    struct statfs sfs;
    int have_data = 0;

    if (statfs(mountpoint, &sfs) == 0)
        have_data = 1;

    if (opt_inodes) {
        unsigned long total_inodes = have_data ? sfs.f_files : 0;
        unsigned long free_inodes = have_data ? sfs.f_ffree : 0;
        unsigned long used_inodes = total_inodes - free_inodes;
        int pct = 0;
        if (total_inodes > 0)
            pct = (int)((used_inodes * 100 + total_inodes / 2) / total_inodes);

        if (opt_fstype)
            printf("%-20s %-8s %10lu %10lu %10lu %4d%% %s\n",
                   device, fstype, total_inodes, used_inodes,
                   free_inodes, pct, mountpoint);
        else
            printf("%-20s %10lu %10lu %10lu %4d%% %s\n",
                   device, total_inodes, used_inodes,
                   free_inodes, pct, mountpoint);
    } else {
        unsigned long bsize = have_data ? sfs.f_bsize : 4096;
        unsigned long total_blocks = have_data ? sfs.f_blocks : 0;
        unsigned long free_blocks = have_data ? sfs.f_bfree : 0;
        unsigned long avail_blocks = have_data ? sfs.f_bavail : 0;

        unsigned long total_bytes = total_blocks * bsize;
        unsigned long used_bytes = (total_blocks - free_blocks) * bsize;
        unsigned long avail_bytes = avail_blocks * bsize;

        int pct = 0;
        unsigned long used_plus_avail = used_bytes + avail_bytes;
        if (used_plus_avail > 0)
            pct = (int)((used_bytes * 100 + used_plus_avail / 2) /
                         used_plus_avail);

        if (opt_human) {
            char total_str[32], used_str[32], avail_str[32];
            human_size(total_bytes, total_str, sizeof(total_str));
            human_size(used_bytes, used_str, sizeof(used_str));
            human_size(avail_bytes, avail_str, sizeof(avail_str));

            if (opt_fstype)
                printf("%-20s %-8s %10s %10s %10s %4d%% %s\n",
                       device, fstype, total_str, used_str,
                       avail_str, pct, mountpoint);
            else
                printf("%-20s %10s %10s %10s %4d%% %s\n",
                       device, total_str, used_str,
                       avail_str, pct, mountpoint);
        } else {
            /* Display in 1K-blocks */
            unsigned long total_k = total_bytes / 1024;
            unsigned long used_k = used_bytes / 1024;
            unsigned long avail_k = avail_bytes / 1024;

            if (opt_fstype)
                printf("%-20s %-8s %10lu %10lu %10lu %4d%% %s\n",
                       device, fstype, total_k, used_k,
                       avail_k, pct, mountpoint);
            else
                printf("%-20s %10lu %10lu %10lu %4d%% %s\n",
                       device, total_k, used_k,
                       avail_k, pct, mountpoint);
        }
    }
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
                case 'h': opt_human = 1; break;
                case 'k': opt_kilo = 1; break;
                case 'i': opt_inodes = 1; break;
                case 'T': opt_fstype = 1; break;
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

    (void)opt_kilo; /* -k is the default behavior */

    print_header();

    if (first_arg < argc) {
        /* Show info for specific paths */
        for (int i = first_arg; i < argc; i++) {
            /* Use the path itself as both device and mountpoint for lookup */
            print_fs_entry(argv[i], argv[i], "unknown");
        }
    } else {
        /* Read mount table and show all filesystems */
        struct mount_entry entries[64];
        int count = read_mounts(entries, 64);

        if (count <= 0) {
            /* No mount table available; show root filesystem as fallback */
            print_fs_entry("/dev/root", "/", "rootfs");
        } else {
            for (int i = 0; i < count; i++) {
                print_fs_entry(entries[i].device, entries[i].mountpoint,
                               entries[i].fstype);
            }
        }
    }

    return 0;
}
