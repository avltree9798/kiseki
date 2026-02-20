/*
 * useradd - create a new user (Unix standard interface)
 *
 * Kiseki OS coreutils - Unix/POSIX compatible
 *
 * This is the standard Unix interface for adding users.
 * Options follow the useradd(8) specification.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>

#define LINE_MAX       1024
#define PATH_PASSWD    "/etc/passwd"
#define PATH_SHADOW    "/etc/shadow"
#define PATH_GROUP     "/etc/group"
#define PATH_SKEL      "/etc/skel"
#define DEFAULT_SHELL  "/bin/bash"
#define DEFAULT_HOME   "/Users"    /* macOS style */
#define MIN_SYS_UID    501         /* macOS starts regular users at 501 */
#define MAX_SYS_UID    60000       /* Skip special UIDs like nobody (65534) */

static const char *progname = "useradd";

/* ------------------------------------------------------------------ */
/* Validation helpers                                                 */
/* ------------------------------------------------------------------ */

static int is_alpha(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static int is_alnum(char c)
{
    return is_alpha(c) || (c >= '0' && c <= '9');
}

static int validate_username(const char *name)
{
    if (!name || !*name)
        return 0;
    if (!is_alpha(name[0]) && name[0] != '_')
        return 0;

    size_t len = strlen(name);
    if (len > 32)
        return 0;

    for (size_t i = 1; i < len; i++) {
        char c = name[i];
        if (!is_alnum(c) && c != '_' && c != '-')
            return 0;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* Passwd / group helpers                                             */
/* ------------------------------------------------------------------ */

static int user_exists(const char *username)
{
    FILE *fp = fopen(PATH_PASSWD, "r");
    if (!fp)
        return 0;

    char line[LINE_MAX];
    size_t ulen = strlen(username);
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n')
            continue;
        if (strncmp(line, username, ulen) == 0 && line[ulen] == ':') {
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

static int group_exists(const char *groupname)
{
    FILE *fp = fopen(PATH_GROUP, "r");
    if (!fp)
        return 0;

    char line[LINE_MAX];
    size_t glen = strlen(groupname);
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n')
            continue;
        if (strncmp(line, groupname, glen) == 0 && line[glen] == ':') {
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

static int uid_in_use(int uid)
{
    FILE *fp = fopen(PATH_PASSWD, "r");
    if (!fp)
        return 0;

    char line[LINE_MAX];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n')
            continue;

        char *saveptr = NULL;
        strtok_r(line, ":", &saveptr);
        strtok_r(NULL, ":", &saveptr);
        char *uid_str = strtok_r(NULL, ":", &saveptr);
        if (uid_str && atoi(uid_str) == uid) {
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

static int gid_in_use(int gid)
{
    FILE *fp = fopen(PATH_GROUP, "r");
    if (!fp)
        return 0;

    char line[LINE_MAX];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n')
            continue;

        char *saveptr = NULL;
        strtok_r(line, ":", &saveptr);
        strtok_r(NULL, ":", &saveptr);
        char *gid_str = strtok_r(NULL, ":", &saveptr);
        if (gid_str && atoi(gid_str) == gid) {
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

static int find_next_uid(void)
{
    int next = MIN_SYS_UID;
    FILE *fp = fopen(PATH_PASSWD, "r");
    if (!fp)
        return next;

    char line[LINE_MAX];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n')
            continue;

        char *saveptr = NULL;
        strtok_r(line, ":", &saveptr);
        strtok_r(NULL, ":", &saveptr);
        char *uid_str = strtok_r(NULL, ":", &saveptr);
        if (uid_str) {
            int uid = atoi(uid_str);
            /* Skip special system UIDs like nobody (65534) */
            if (uid >= MIN_SYS_UID && uid < MAX_SYS_UID && uid >= next)
                next = uid + 1;
        }
    }
    fclose(fp);
    return next;
}

static int find_next_gid(void)
{
    int next = MIN_SYS_UID;
    FILE *fp = fopen(PATH_GROUP, "r");
    if (!fp)
        return next;

    char line[LINE_MAX];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n')
            continue;

        char *saveptr = NULL;
        strtok_r(line, ":", &saveptr);
        strtok_r(NULL, ":", &saveptr);
        char *gid_str = strtok_r(NULL, ":", &saveptr);
        if (gid_str) {
            int gid = atoi(gid_str);
            /* Skip special system GIDs like nogroup (65534) */
            if (gid >= MIN_SYS_UID && gid < MAX_SYS_UID && gid >= next)
                next = gid + 1;
        }
    }
    fclose(fp);
    return next;
}

/* ------------------------------------------------------------------ */
/* Group membership management                                        */
/* ------------------------------------------------------------------ */

/*
 * add_user_to_group - Add a user to a single group's member list
 *
 * Reads /etc/group, finds the group, adds the user if not already present,
 * and writes the file back atomically.
 *
 * Returns 0 on success, -1 on error.
 */
static int add_user_to_group(const char *username, const char *groupname)
{
    FILE *fp = fopen(PATH_GROUP, "r");
    if (!fp)
        return -1;

    /* Read entire group file into memory */
    char *lines[256];
    int nlines = 0;
    char buf[LINE_MAX];
    int found_idx = -1;
    size_t ulen = strlen(username);
    size_t glen = strlen(groupname);

    while (fgets(buf, sizeof(buf), fp) && nlines < 256) {
        lines[nlines] = strdup(buf);
        if (!lines[nlines])
            break;

        /* Check if this is the target group */
        if (strncmp(buf, groupname, glen) == 0 && buf[glen] == ':') {
            found_idx = nlines;
        }
        nlines++;
    }
    fclose(fp);

    if (found_idx < 0) {
        /* Group not found */
        for (int i = 0; i < nlines; i++)
            free(lines[i]);
        return -1;
    }

    /* Parse the group line: name:password:gid:members */
    char *line = lines[found_idx];
    size_t len = strlen(line);

    /* Remove trailing newline */
    if (len > 0 && line[len - 1] == '\n')
        line[--len] = '\0';

    /* Find the members field (after 3rd colon) */
    char *p = line;
    int colons = 0;
    char *members_start = NULL;
    while (*p) {
        if (*p == ':') {
            colons++;
            if (colons == 3) {
                members_start = p + 1;
                break;
            }
        }
        p++;
    }

    if (!members_start) {
        for (int i = 0; i < nlines; i++)
            free(lines[i]);
        return -1;
    }

    /* Check if user is already a member */
    char *member = members_start;
    while (*member) {
        /* Find end of this member name */
        char *end = member;
        while (*end && *end != ',')
            end++;

        size_t mlen = (size_t)(end - member);
        if (mlen == ulen && strncmp(member, username, ulen) == 0) {
            /* Already a member */
            for (int i = 0; i < nlines; i++)
                free(lines[i]);
            return 0;
        }

        if (*end == ',')
            member = end + 1;
        else
            break;
    }

    /* Build new line with user added */
    char newline[LINE_MAX];
    if (members_start[0] == '\0') {
        /* No existing members */
        snprintf(newline, sizeof(newline), "%s%s\n", line, username);
    } else {
        /* Append to existing members */
        snprintf(newline, sizeof(newline), "%s,%s\n", line, username);
    }

    free(lines[found_idx]);
    lines[found_idx] = strdup(newline);

    /* Write back to file */
    fp = fopen(PATH_GROUP, "w");
    if (!fp) {
        for (int i = 0; i < nlines; i++)
            free(lines[i]);
        return -1;
    }

    for (int i = 0; i < nlines; i++) {
        fputs(lines[i], fp);
        free(lines[i]);
    }
    fclose(fp);

    return 0;
}

/*
 * add_user_to_groups - Add user to multiple groups (comma-separated)
 *
 * Returns 0 if all groups were successfully updated, -1 if any failed.
 */
static int add_user_to_groups(const char *username, const char *groups)
{
    char buf[512];
    strncpy(buf, groups, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    int ret = 0;
    char *saveptr = NULL;
    char *group = strtok_r(buf, ",", &saveptr);

    while (group) {
        /* Trim leading/trailing whitespace */
        while (*group == ' ' || *group == '\t')
            group++;
        char *end = group + strlen(group) - 1;
        while (end > group && (*end == ' ' || *end == '\t'))
            *end-- = '\0';

        if (*group) {
            if (!group_exists(group)) {
                fprintf(stderr, "%s: group '%s' does not exist\n",
                        progname, group);
                ret = -1;
            } else if (add_user_to_group(username, group) < 0) {
                fprintf(stderr, "%s: failed to add user to group '%s'\n",
                        progname, group);
                ret = -1;
            }
        }

        group = strtok_r(NULL, ",", &saveptr);
    }

    return ret;
}

/* ------------------------------------------------------------------ */
/* File helpers                                                       */
/* ------------------------------------------------------------------ */

static int append_line(const char *path, const char *line)
{
    FILE *fp = fopen(path, "a");
    if (!fp) {
        fprintf(stderr, "%s: cannot open %s: %s\n", progname, path,
                strerror(errno));
        return -1;
    }
    if (fputs(line, fp) == EOF) {
        fprintf(stderr, "%s: write error on %s\n", progname, path);
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

static void ensure_file_exists(const char *path)
{
    struct stat st;
    if (stat(path, &st) < 0) {
        int fd = open(path, O_WRONLY | O_CREAT, 0644);
        if (fd >= 0)
            close(fd);
    }
}

static int copy_file(const char *src, const char *dst, int uid, int gid)
{
    int sfd = open(src, O_RDONLY);
    if (sfd < 0)
        return -1;

    int dfd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dfd < 0) {
        close(sfd);
        return -1;
    }

    char buf[4096];
    ssize_t n;
    while ((n = read(sfd, buf, sizeof(buf))) > 0) {
        write(dfd, buf, (size_t)n);
    }

    close(sfd);
    close(dfd);

    /* Set ownership to the new user */
    chown(dst, uid, gid);
    return 0;
}

static int copy_skel(const char *homedir, int uid, int gid)
{
    struct stat st;
    if (stat(PATH_SKEL, &st) < 0)
        return 0;

    DIR *dir = opendir(PATH_SKEL);
    if (!dir)
        return 0;

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        char src[512], dst[512];
        snprintf(src, sizeof(src), "%s/%s", PATH_SKEL, ent->d_name);
        snprintf(dst, sizeof(dst), "%s/%s", homedir, ent->d_name);

        struct stat es;
        if (stat(src, &es) < 0)
            continue;

        if (S_ISREG(es.st_mode))
            copy_file(src, dst, uid, gid);
    }
    closedir(dir);
    return 0;
}

static int create_home(const char *homedir, int uid, int gid)
{
    if (mkdir(homedir, 0755) < 0) {
        if (errno == EEXIST)
            return 0;
        fprintf(stderr, "%s: cannot create directory '%s': %s\n",
                progname, homedir, strerror(errno));
        return -1;
    }
    /* macOS uses 700 for home directories (private) */
    chmod(homedir, 0700);
    chown(homedir, uid, gid);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Usage                                                              */
/* ------------------------------------------------------------------ */

static void usage(void)
{
    fprintf(stderr, "Usage: %s [options] LOGIN\n", progname);
    fprintf(stderr, "       %s -D [options]\n\n", progname);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -c, --comment COMMENT    GECOS field\n");
    fprintf(stderr, "  -d, --home-dir HOME_DIR  home directory (default: /Users/LOGIN)\n");
    fprintf(stderr, "  -g, --gid GROUP          primary group name or ID\n");
    fprintf(stderr, "  -G, --groups GROUPS      supplementary groups\n");
    fprintf(stderr, "  -m, --create-home        create home directory\n");
    fprintf(stderr, "  -M, --no-create-home     do not create home directory\n");
    fprintf(stderr, "  -s, --shell SHELL        login shell (default: /bin/bash)\n");
    fprintf(stderr, "  -u, --uid UID            user ID\n");
    fprintf(stderr, "  -U, --user-group         create a group with same name as user\n");
    fprintf(stderr, "  -h, --help               display this help\n");
}

/* ------------------------------------------------------------------ */
/* Main                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    int opt_uid = -1;
    int opt_gid = -1;
    const char *opt_home = NULL;
    const char *opt_shell = DEFAULT_SHELL;
    const char *opt_comment = "";
    int opt_create_home = 1;   /* default on (like macOS), -M to disable */
    int opt_user_group = 1;    /* -U default on */
    const char *opt_groups = NULL;
    const char *username = NULL;

    /* Must be root */
    if (getuid() != 0 && geteuid() != 0) {
        fprintf(stderr, "%s: Permission denied.\n", progname);
        return 1;
    }

    /* Parse options (GNU-style: options can appear anywhere) */
    int i;
    for (i = 1; i < argc; i++) {
        if (argv[i][0] != '-') {
            /* Non-option argument = username */
            if (username == NULL) {
                username = argv[i];
            } else {
                fprintf(stderr, "%s: extra operand '%s'\n", progname, argv[i]);
                usage();
                return 1;
            }
            continue;
        }
        if (strcmp(argv[i], "--") == 0) {
            /* Everything after -- is not an option */
            i++;
            if (i < argc && username == NULL)
                username = argv[i];
            break;
        }
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage();
            return 0;
        }
        if (strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--uid") == 0) {
            if (++i >= argc) { fprintf(stderr, "%s: option requires argument -- 'u'\n", progname); return 1; }
            opt_uid = atoi(argv[i]);
        } else if (strcmp(argv[i], "-g") == 0 || strcmp(argv[i], "--gid") == 0) {
            if (++i >= argc) { fprintf(stderr, "%s: option requires argument -- 'g'\n", progname); return 1; }
            opt_gid = atoi(argv[i]);
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--home-dir") == 0) {
            if (++i >= argc) { fprintf(stderr, "%s: option requires argument -- 'd'\n", progname); return 1; }
            opt_home = argv[i];
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--shell") == 0) {
            if (++i >= argc) { fprintf(stderr, "%s: option requires argument -- 's'\n", progname); return 1; }
            opt_shell = argv[i];
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--comment") == 0) {
            if (++i >= argc) { fprintf(stderr, "%s: option requires argument -- 'c'\n", progname); return 1; }
            opt_comment = argv[i];
        } else if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--create-home") == 0) {
            opt_create_home = 1;
        } else if (strcmp(argv[i], "-M") == 0 || strcmp(argv[i], "--no-create-home") == 0) {
            opt_create_home = 0;
        } else if (strcmp(argv[i], "-U") == 0 || strcmp(argv[i], "--user-group") == 0) {
            opt_user_group = 1;
        } else if (strcmp(argv[i], "-G") == 0 || strcmp(argv[i], "--groups") == 0) {
            if (++i >= argc) { fprintf(stderr, "%s: option requires argument -- 'G'\n", progname); return 1; }
            opt_groups = argv[i];
        } else {
            fprintf(stderr, "%s: invalid option -- '%s'\n", progname, argv[i]);
            usage();
            return 1;
        }
    }

    if (username == NULL) {
        fprintf(stderr, "%s: missing username\n", progname);
        usage();
        return 1;
    }

    if (!validate_username(username)) {
        fprintf(stderr, "%s: invalid user name '%s'\n", progname, username);
        return 1;
    }

    if (user_exists(username)) {
        fprintf(stderr, "%s: user '%s' already exists\n", progname, username);
        return 9;  /* Standard exit code for user exists */
    }

    /* Determine UID */
    int uid = (opt_uid >= 0) ? opt_uid : find_next_uid();
    if (opt_uid >= 0 && uid_in_use(uid)) {
        fprintf(stderr, "%s: UID %d already exists\n", progname, uid);
        return 4;
    }

    /* Determine GID */
    int gid;
    int create_group = 0;
    if (opt_gid >= 0) {
        gid = opt_gid;
    } else if (opt_user_group) {
        gid = uid;
        if (gid_in_use(gid))
            gid = find_next_gid();
        create_group = 1;
    } else {
        gid = 20;  /* Default 'staff' group on macOS */
    }

    /* Determine home directory */
    char homedir[512];
    if (opt_home) {
        strncpy(homedir, opt_home, sizeof(homedir) - 1);
        homedir[sizeof(homedir) - 1] = '\0';
    } else {
        snprintf(homedir, sizeof(homedir), "%s/%s", DEFAULT_HOME, username);
    }

    /* Ensure /etc files exist */
    ensure_file_exists(PATH_PASSWD);
    ensure_file_exists(PATH_SHADOW);
    ensure_file_exists(PATH_GROUP);

    /* Create group if needed */
    if (create_group && !group_exists(username)) {
        char group_line[LINE_MAX];
        snprintf(group_line, sizeof(group_line), "%s:x:%d:\n", username, gid);
        append_line(PATH_GROUP, group_line);
    }

    /* Create passwd entry */
    {
        char passwd_line[LINE_MAX];
        snprintf(passwd_line, sizeof(passwd_line),
                 "%s:x:%d:%d:%s:%s:%s\n",
                 username, uid, gid, opt_comment, homedir, opt_shell);
        if (append_line(PATH_PASSWD, passwd_line) < 0)
            return 1;
    }

    /* Create shadow entry */
    {
        char shadow_line[LINE_MAX];
        snprintf(shadow_line, sizeof(shadow_line), "%s:!:0:0:99999:7:::\n", username);
        append_line(PATH_SHADOW, shadow_line);
    }

    /* Create home directory if requested */
    if (opt_create_home) {
        struct stat pst;
        if (stat(DEFAULT_HOME, &pst) < 0)
            mkdir(DEFAULT_HOME, 0755);

        if (create_home(homedir, uid, gid) == 0)
            copy_skel(homedir, uid, gid);
    }

    /* Add user to supplementary groups */
    if (opt_groups) {
        if (add_user_to_groups(username, opt_groups) < 0) {
            fprintf(stderr, "%s: warning: failed to add user to some groups\n",
                    progname);
        }
    }

    return 0;
}
