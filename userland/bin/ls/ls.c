/*
 * Kiseki OS - ls: list directory contents
 *
 * Supports long format, sorting, recursive listing, and various display options.
 */

#include <stdint.h>
#include <sys/types.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

/* ========================================================================
 * Configuration
 * ======================================================================== */

#define MAX_ENTRIES     4096
#define MAX_PATH_LEN    PATH_MAX

/* ========================================================================
 * Flags
 * ======================================================================== */

static int flag_long;           /* -l */
static int flag_all;            /* -a */
static int flag_almost_all;     /* -A */
static int flag_one_per_line;   /* -1 */
static int flag_recursive;      /* -R */
static int flag_reverse;        /* -r */
static int flag_sort_time;      /* -t */
static int flag_sort_size;      /* -S */
static int flag_human_readable; /* -h */
static int flag_directory;      /* -d */
static int flag_classify;       /* -F */
static int flag_inode;          /* -i */
static int flag_numeric_ids;    /* -n */
static int flag_append_slash;   /* -p */

static int had_error;
static int printed_any;         /* For separating recursive sections */

/* ========================================================================
 * Entry structure for sorting
 * ======================================================================== */

typedef struct {
    char        name[NAME_MAX + 1];
    struct stat st;
    int         stat_valid;
} entry_t;

/* ========================================================================
 * Time helpers
 *
 * We need to convert time_t to a human-readable date.
 * Since we have no localtime(), we implement a simple UTC formatter.
 * ======================================================================== */

static const char *month_names[] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

static const int days_in_month[] = {
    31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

static int is_leap_year(int year)
{
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

typedef struct {
    int year;
    int month;  /* 0-11 */
    int day;    /* 1-31 */
    int hour;
    int min;
    int sec;
} simple_tm_t;

static void time_to_tm(time_t t, simple_tm_t *tm)
{
    /* Convert Unix timestamp to broken-down time (UTC) */
    int64_t days = t / 86400;
    int64_t remaining = t % 86400;

    if (remaining < 0) {
        days--;
        remaining += 86400;
    }

    tm->hour = (int)(remaining / 3600);
    remaining %= 3600;
    tm->min = (int)(remaining / 60);
    tm->sec = (int)(remaining % 60);

    /* Days since epoch (1970-01-01) */
    /* Algorithm: count years and months */
    int year = 1970;

    while (days >= 365 + is_leap_year(year)) {
        if (days < 0)
            break;
        days -= 365 + is_leap_year(year);
        year++;
    }

    /* Handle negative days (shouldn't happen for valid timestamps) */
    while (days < 0) {
        year--;
        days += 365 + is_leap_year(year);
    }

    tm->year = year;

    int month = 0;
    int dim;
    while (month < 11) {
        dim = days_in_month[month];
        if (month == 1 && is_leap_year(year))
            dim++;
        if (days < dim)
            break;
        days -= dim;
        month++;
    }

    tm->month = month;
    tm->day = (int)days + 1;
}

/* Get approximate "now" - we don't have a time() syscall easily,
 * but we can use stat on "." as a rough estimate, or just use a
 * fixed threshold. For "6 months old" we use 15768000 seconds. */
static time_t get_now(void)
{
    /* Try to get current time from stat on /dev/null or similar.
     * Fallback: use a large value so we always show HH:MM. */
    struct stat st;
    if (stat("/dev/null", &st) == 0 && st.st_mtime > 0)
        return st.st_mtime;
    /* Another fallback: stat "." */
    if (stat(".", &st) == 0 && st.st_mtime > 0)
        return st.st_mtime;
    return 0;
}

static void format_time(time_t t, char *buf, size_t bufsz)
{
    simple_tm_t tm;
    time_to_tm(t, &tm);

    static time_t now_cache = 0;
    if (now_cache == 0)
        now_cache = get_now();

    int64_t diff = now_cache - t;
    int old = (diff > 15768000 || diff < -15768000); /* ~6 months */

    if (old || now_cache == 0) {
        snprintf(buf, bufsz, "%s %2d  %d",
                 month_names[tm.month], tm.day, tm.year);
    } else {
        snprintf(buf, bufsz, "%s %2d %02d:%02d",
                 month_names[tm.month], tm.day, tm.hour, tm.min);
    }
}

/* ========================================================================
 * Permission string
 * ======================================================================== */

static void format_mode(mode_t mode, char *buf)
{
    /* File type character */
    if (S_ISREG(mode))       buf[0] = '-';
    else if (S_ISDIR(mode))  buf[0] = 'd';
    else if (S_ISLNK(mode))  buf[0] = 'l';
    else if (S_ISCHR(mode))  buf[0] = 'c';
    else if (S_ISBLK(mode))  buf[0] = 'b';
    else if (S_ISFIFO(mode)) buf[0] = 'p';
    else if (S_ISSOCK(mode)) buf[0] = 's';
    else                     buf[0] = '?';

    /* Owner */
    buf[1] = (mode & S_IRUSR) ? 'r' : '-';
    buf[2] = (mode & S_IWUSR) ? 'w' : '-';
    if (mode & S_ISUID)
        buf[3] = (mode & S_IXUSR) ? 's' : 'S';
    else
        buf[3] = (mode & S_IXUSR) ? 'x' : '-';

    /* Group */
    buf[4] = (mode & S_IRGRP) ? 'r' : '-';
    buf[5] = (mode & S_IWGRP) ? 'w' : '-';
    if (mode & S_ISGID)
        buf[6] = (mode & S_IXGRP) ? 's' : 'S';
    else
        buf[6] = (mode & S_IXGRP) ? 'x' : '-';

    /* Other */
    buf[7] = (mode & S_IROTH) ? 'r' : '-';
    buf[8] = (mode & S_IWOTH) ? 'w' : '-';
    if (mode & S_ISVTX)
        buf[9] = (mode & S_IXOTH) ? 't' : 'T';
    else
        buf[9] = (mode & S_IXOTH) ? 'x' : '-';

    buf[10] = '\0';
}

/* ========================================================================
 * Human-readable size
 * ======================================================================== */

static void format_size_human(off_t size, char *buf, size_t bufsz)
{
    if (size < 1024) {
        snprintf(buf, bufsz, "%ld", (long)size);
    } else if (size < 1024L * 1024) {
        long val = (long)((size * 10 + 512) / 1024);
        if (val < 100)
            snprintf(buf, bufsz, "%ld.%ldK", val / 10, val % 10);
        else
            snprintf(buf, bufsz, "%ldK", (long)((size + 512) / 1024));
    } else if (size < 1024L * 1024 * 1024) {
        long val = (long)((size * 10 + 524288) / (1024 * 1024));
        if (val < 100)
            snprintf(buf, bufsz, "%ld.%ldM", val / 10, val % 10);
        else
            snprintf(buf, bufsz, "%ldM", (long)((size + 524288) / (1024 * 1024)));
    } else {
        long val = (long)((size * 10 + 536870912L) / (1024L * 1024 * 1024));
        if (val < 100)
            snprintf(buf, bufsz, "%ld.%ldG", val / 10, val % 10);
        else
            snprintf(buf, bufsz, "%ldG", (long)((size + 536870912L) / (1024L * 1024 * 1024)));
    }
}

/* ========================================================================
 * Type indicator for -F and -p
 * ======================================================================== */

static char type_indicator(mode_t mode)
{
    if (S_ISDIR(mode))  return '/';
    if (flag_classify) {
        if (S_ISLNK(mode))  return '@';
        if (S_ISSOCK(mode)) return '=';
        if (S_ISFIFO(mode)) return '|';
        if (mode & (S_IXUSR | S_IXGRP | S_IXOTH))
            return '*';
    }
    return '\0';
}

/* ========================================================================
 * Comparison functions for qsort
 * ======================================================================== */

static int cmp_name(const void *a, const void *b)
{
    const entry_t *ea = (const entry_t *)a;
    const entry_t *eb = (const entry_t *)b;
    int r = strcmp(ea->name, eb->name);
    return flag_reverse ? -r : r;
}

static int cmp_mtime(const void *a, const void *b)
{
    const entry_t *ea = (const entry_t *)a;
    const entry_t *eb = (const entry_t *)b;
    int r;
    if (ea->st.st_mtime < eb->st.st_mtime) r = 1;      /* Newer first */
    else if (ea->st.st_mtime > eb->st.st_mtime) r = -1;
    else r = strcmp(ea->name, eb->name);                  /* Tie-break */
    return flag_reverse ? -r : r;
}

static int cmp_size(const void *a, const void *b)
{
    const entry_t *ea = (const entry_t *)a;
    const entry_t *eb = (const entry_t *)b;
    int r;
    if (ea->st.st_size < eb->st.st_size) r = 1;         /* Larger first */
    else if (ea->st.st_size > eb->st.st_size) r = -1;
    else r = strcmp(ea->name, eb->name);                  /* Tie-break */
    return flag_reverse ? -r : r;
}

/* ========================================================================
 * Build full path
 * ======================================================================== */

static void build_path(char *buf, size_t bufsz, const char *dir, const char *name)
{
    size_t dlen = strlen(dir);
    if (dlen > 0 && dir[dlen - 1] == '/')
        snprintf(buf, bufsz, "%s%s", dir, name);
    else
        snprintf(buf, bufsz, "%s/%s", dir, name);
}

/* ========================================================================
 * Print entries
 * ======================================================================== */

static void print_entries(entry_t *entries, int count, const char *dirpath)
{
    /* Sort */
    int (*cmpfn)(const void *, const void *) = cmp_name;
    if (flag_sort_time)      cmpfn = cmp_mtime;
    else if (flag_sort_size) cmpfn = cmp_size;
    qsort(entries, count, sizeof(entry_t), cmpfn);

    if (flag_long || flag_numeric_ids) {
        /* Compute column widths for alignment */
        int max_nlink = 0;
        off_t max_size = 0;
        int max_uid = 0;
        int max_gid = 0;
        long total_blocks = 0;

        for (int i = 0; i < count; i++) {
            if (!entries[i].stat_valid)
                continue;
            struct stat *st = &entries[i].st;
            if ((int)st->st_nlink > max_nlink)
                max_nlink = (int)st->st_nlink;
            if (st->st_size > max_size)
                max_size = st->st_size;
            if ((int)st->st_uid > max_uid)
                max_uid = (int)st->st_uid;
            if ((int)st->st_gid > max_gid)
                max_gid = (int)st->st_gid;
            total_blocks += (long)st->st_blocks;
        }

        /* Width calculations */
        int nlink_width = 1;
        { int v = max_nlink; while (v >= 10) { nlink_width++; v /= 10; } }

        int size_width = 1;
        if (flag_human_readable) {
            size_width = 5; /* Enough for "1023M" etc */
        } else {
            off_t v = max_size;
            while (v >= 10) { size_width++; v /= 10; }
        }

        int uid_width = 1;
        { int v = max_uid; while (v >= 10) { uid_width++; v /= 10; } }

        int gid_width = 1;
        { int v = max_gid; while (v >= 10) { gid_width++; v /= 10; } }

        /* Print total blocks (in 1K units, blocks are 512B) */
        printf("total %ld\n", total_blocks / 2);

        for (int i = 0; i < count; i++) {
            if (!entries[i].stat_valid) {
                printf("? %s\n", entries[i].name);
                continue;
            }

            struct stat *st = &entries[i].st;
            char modebuf[12];
            format_mode(st->st_mode, modebuf);

            char timebuf[32];
            format_time(st->st_mtime, timebuf, sizeof(timebuf));

            char sizebuf[32];
            if (flag_human_readable)
                format_size_human(st->st_size, sizebuf, sizeof(sizebuf));
            else
                snprintf(sizebuf, sizeof(sizebuf), "%ld", (long)st->st_size);

            /* Inode prefix */
            if (flag_inode)
                printf("%lu ", (unsigned long)st->st_ino);

            printf("%s %*d %*d %*d %*s %s ",
                   modebuf,
                   nlink_width, (int)st->st_nlink,
                   uid_width, (int)st->st_uid,
                   gid_width, (int)st->st_gid,
                   size_width, sizebuf,
                   timebuf);

            printf("%s", entries[i].name);

            /* Type indicator */
            if (flag_classify || flag_append_slash) {
                char ind = type_indicator(st->st_mode);
                if (ind)
                    putchar(ind);
            }

            /* Symlink target */
            if (S_ISLNK(st->st_mode)) {
                char linkbuf[PATH_MAX];
                char fullpath[PATH_MAX];
                build_path(fullpath, sizeof(fullpath), dirpath, entries[i].name);
                ssize_t llen = readlink(fullpath, linkbuf, sizeof(linkbuf) - 1);
                if (llen > 0) {
                    linkbuf[llen] = '\0';
                    printf(" -> %s", linkbuf);
                }
            }

            putchar('\n');
        }
    } else {
        /* Short format */
        for (int i = 0; i < count; i++) {
            if (flag_inode && entries[i].stat_valid)
                printf("%lu ", (unsigned long)entries[i].st.st_ino);

            printf("%s", entries[i].name);

            if ((flag_classify || flag_append_slash) && entries[i].stat_valid) {
                char ind = type_indicator(entries[i].st.st_mode);
                if (ind)
                    putchar(ind);
            }

            /* In non-long mode, if output is a terminal and -1 not set,
             * we could do column formatting. For simplicity (and since
             * this is freestanding), we always do one-per-line. */
            putchar('\n');
        }
    }
}

/* ========================================================================
 * List a single directory
 * ======================================================================== */

static void list_dir(const char *path, int print_header) __attribute__((unused));

static void list_directory(const char *path, int print_header)
{
    DIR *dp = opendir(path);
    if (!dp) {
        fprintf(stderr, "ls: cannot open '%s': %s\n", path, strerror(errno));
        had_error = 1;
        return;
    }

    if (print_header) {
        if (printed_any)
            putchar('\n');
        printf("%s:\n", path);
    }
    printed_any = 1;

    /* Read all entries */
    entry_t *entries = malloc(MAX_ENTRIES * sizeof(entry_t));
    if (!entries) {
        fprintf(stderr, "ls: out of memory\n");
        closedir(dp);
        had_error = 1;
        return;
    }

    int count = 0;
    struct dirent *ent;

    while ((ent = readdir(dp)) != NULL && count < MAX_ENTRIES) {
        /* Filter hidden files */
        if (ent->d_name[0] == '.') {
            if (!flag_all && !flag_almost_all)
                continue;
            if (flag_almost_all &&
                (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0))
                continue;
        }

        strncpy(entries[count].name, ent->d_name, NAME_MAX);
        entries[count].name[NAME_MAX] = '\0';

        /* Stat the entry */
        char fullpath[MAX_PATH_LEN];
        build_path(fullpath, sizeof(fullpath), path, ent->d_name);

        if (lstat(fullpath, &entries[count].st) < 0) {
            entries[count].stat_valid = 0;
        } else {
            entries[count].stat_valid = 1;
        }

        count++;
    }

    closedir(dp);

    print_entries(entries, count, path);

    /* Recursive: traverse subdirectories */
    if (flag_recursive) {
        /* Sort entries for consistent recursive order */
        qsort(entries, count, sizeof(entry_t), cmp_name);

        for (int i = 0; i < count; i++) {
            if (!entries[i].stat_valid)
                continue;
            if (!S_ISDIR(entries[i].st.st_mode))
                continue;
            if (strcmp(entries[i].name, ".") == 0 ||
                strcmp(entries[i].name, "..") == 0)
                continue;

            char subpath[MAX_PATH_LEN];
            build_path(subpath, sizeof(subpath), path, entries[i].name);
            list_directory(subpath, 1);
        }
    }

    free(entries);
}

/* ========================================================================
 * List a single argument (file or directory)
 * ======================================================================== */

static void list_arg(const char *path, int multi, int print_header)
{
    struct stat st;
    if (lstat(path, &st) < 0) {
        fprintf(stderr, "ls: cannot access '%s': %s\n", path, strerror(errno));
        had_error = 1;
        return;
    }

    if (S_ISDIR(st.st_mode) && !flag_directory) {
        list_directory(path, print_header);
    } else {
        /* Single file */
        entry_t entry;
        strncpy(entry.name, path, NAME_MAX);
        entry.name[NAME_MAX] = '\0';
        entry.st = st;
        entry.stat_valid = 1;

        /* For a single file in long mode, use its parent dir for
         * symlink resolution. We pass "." as the directory. */
        print_entries(&entry, 1, ".");

        printed_any = 1;
    }

    (void)multi;
}

/* ========================================================================
 * Usage
 * ======================================================================== */

static void usage(void)
{
    fprintf(stderr,
        "Usage: ls [OPTIONS] [FILE...]\n"
        "List directory contents.\n\n"
        "Options:\n"
        "  -l       Long listing format\n"
        "  -a       Show all entries (including . and ..)\n"
        "  -A       Show all entries except . and ..\n"
        "  -1       One entry per line\n"
        "  -R       List subdirectories recursively\n"
        "  -r       Reverse sort order\n"
        "  -t       Sort by modification time\n"
        "  -S       Sort by file size\n"
        "  -h       Human-readable sizes (K, M, G)\n"
        "  -d       List directories themselves, not contents\n"
        "  -F       Append type indicator (/ @ * = |)\n"
        "  -i       Print inode number\n"
        "  -n       Numeric uid/gid (with -l)\n"
        "  -p       Append / to directories\n"
    );
}

/* ========================================================================
 * Main
 * ======================================================================== */

int main(int argc, char *argv[])
{
    /* Parse options manually */
    int argi = 1;

    while (argi < argc && argv[argi][0] == '-' && argv[argi][1] != '\0') {
        const char *arg = argv[argi];

        if (strcmp(arg, "--") == 0) {
            argi++;
            break;
        }

        for (int j = 1; arg[j]; j++) {
            switch (arg[j]) {
            case 'l': flag_long = 1; break;
            case 'a': flag_all = 1; break;
            case 'A': flag_almost_all = 1; break;
            case '1': flag_one_per_line = 1; break;
            case 'R': flag_recursive = 1; break;
            case 'r': flag_reverse = 1; break;
            case 't': flag_sort_time = 1; break;
            case 'S': flag_sort_size = 1; break;
            case 'h': flag_human_readable = 1; break;
            case 'd': flag_directory = 1; break;
            case 'F': flag_classify = 1; break;
            case 'i': flag_inode = 1; break;
            case 'n': flag_numeric_ids = 1; flag_long = 1; break;
            case 'p': flag_append_slash = 1; break;
            default:
                fprintf(stderr, "ls: invalid option -- '%c'\n", arg[j]);
                usage();
                exit(2);
            }
        }
        argi++;
    }

    int num_args = argc - argi;

    if (num_args == 0) {
        list_arg(".", 0, flag_recursive);
    } else if (num_args == 1) {
        list_arg(argv[argi], 0, flag_recursive);
    } else {
        /* Multiple arguments: separate files from directories.
         * Print files first, then directories with headers. */

        /* First pass: list non-directory arguments */
        entry_t *file_entries = malloc(num_args * sizeof(entry_t));
        int file_count = 0;
        char **dirs = malloc(num_args * sizeof(char *));
        int dir_count = 0;

        if (!file_entries || !dirs) {
            fprintf(stderr, "ls: out of memory\n");
            exit(2);
        }

        for (int i = argi; i < argc; i++) {
            struct stat st;
            if (lstat(argv[i], &st) < 0) {
                fprintf(stderr, "ls: cannot access '%s': %s\n",
                        argv[i], strerror(errno));
                had_error = 1;
                continue;
            }

            if (S_ISDIR(st.st_mode) && !flag_directory) {
                dirs[dir_count++] = argv[i];
            } else {
                strncpy(file_entries[file_count].name, argv[i], NAME_MAX);
                file_entries[file_count].name[NAME_MAX] = '\0';
                file_entries[file_count].st = st;
                file_entries[file_count].stat_valid = 1;
                file_count++;
            }
        }

        /* Print files */
        if (file_count > 0) {
            print_entries(file_entries, file_count, ".");
            printed_any = 1;
        }

        /* Print directories */
        for (int i = 0; i < dir_count; i++) {
            list_directory(dirs[i], 1);
        }

        free(file_entries);
        free(dirs);
    }

    exit(had_error ? 2 : 0);
}
