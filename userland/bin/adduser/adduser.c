/*
 * adduser - add a new user to the system
 *
 * Kiseki OS coreutils
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

static const char *progname = "adduser";

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

/*
 * Validate a username:
 *   - Must start with a letter or underscore
 *   - May contain letters, digits, underscores, hyphens
 *   - Max 32 characters
 */
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

/*
 * Check if a username already exists in /etc/passwd.
 */
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

/*
 * Check if a group name already exists in /etc/group.
 */
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

/*
 * Check if a UID is already in use.
 */
static int uid_in_use(int uid)
{
    FILE *fp = fopen(PATH_PASSWD, "r");
    if (!fp)
        return 0;

    char line[LINE_MAX];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n')
            continue;

        /* Skip to uid field (third field) */
        char *saveptr = NULL;
        strtok_r(line, ":", &saveptr);   /* name */
        strtok_r(NULL, ":", &saveptr);   /* password */
        char *uid_str = strtok_r(NULL, ":", &saveptr);
        if (uid_str && atoi(uid_str) == uid) {
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

/*
 * Check if a GID is already in use.
 */
static int gid_in_use(int gid)
{
    FILE *fp = fopen(PATH_GROUP, "r");
    if (!fp)
        return 0;

    char line[LINE_MAX];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n')
            continue;

        /* Skip to gid field (third field) */
        char *saveptr = NULL;
        strtok_r(line, ":", &saveptr);   /* name */
        strtok_r(NULL, ":", &saveptr);   /* password */
        char *gid_str = strtok_r(NULL, ":", &saveptr);
        if (gid_str && atoi(gid_str) == gid) {
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

/*
 * Find the next available UID >= MIN_SYS_UID.
 */
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
            if (uid >= next)
                next = uid + 1;
        }
    }
    fclose(fp);
    return next;
}

/*
 * Find the next available GID >= MIN_SYS_UID.
 */
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
            if (gid >= next)
                next = gid + 1;
        }
    }
    fclose(fp);
    return next;
}

/* ------------------------------------------------------------------ */
/* File append helpers                                                */
/* ------------------------------------------------------------------ */

/*
 * Append a line to a file.  Returns 0 on success.
 */
static int append_line(const char *path, const char *line)
{
    FILE *fp = fopen(path, "a");
    if (!fp) {
        fprintf(stderr, "%s: cannot open %s: %s\n", progname, path,
                strerror(errno));
        return -1;
    }
    if (fputs(line, fp) == EOF) {
        fprintf(stderr, "%s: write error on %s: %s\n", progname, path,
                strerror(errno));
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

/*
 * Add user to an existing group's member list in /etc/group.
 * Group line format: groupname:x:gid:member1,member2,...
 */
static int add_user_to_group(const char *username, const char *groupname)
{
    FILE *fp = fopen(PATH_GROUP, "r");
    if (!fp) {
        fprintf(stderr, "%s: cannot open %s: %s\n", progname, PATH_GROUP,
                strerror(errno));
        return -1;
    }

    /* Read entire file into memory */
    char *buf = NULL;
    size_t bufsz = 0;
    size_t buflen = 0;
    char line[LINE_MAX];

    while (fgets(line, sizeof(line), fp)) {
        size_t llen = strlen(line);
        /* Ensure space */
        if (buflen + llen + 256 >= bufsz) {
            bufsz = (bufsz == 0) ? 4096 : bufsz * 2;
            char *tmp = realloc(buf, bufsz);
            if (!tmp) {
                free(buf);
                fclose(fp);
                fprintf(stderr, "%s: out of memory\n", progname);
                return -1;
            }
            buf = tmp;
        }

        /* Check if this is the target group line */
        size_t glen = strlen(groupname);
        if (strncmp(line, groupname, glen) == 0 && line[glen] == ':') {
            /* Strip trailing newline for modification */
            if (llen > 0 && line[llen - 1] == '\n')
                line[--llen] = '\0';

            /*
             * Append username to member list.
             * If line ends with ':', just append username.
             * Otherwise append ',username'.
             */
            if (llen > 0 && line[llen - 1] == ':') {
                /* Empty member list */
                strcat(line, username);
            } else {
                /* Check if there are already members */
                /* Count colons to see if we're at members field */
                int colons = 0;
                for (size_t ci = 0; ci < llen; ci++)
                    if (line[ci] == ':')
                        colons++;

                if (colons >= 3 && llen > 0 && line[llen - 1] != ':') {
                    strcat(line, ",");
                    strcat(line, username);
                } else {
                    strcat(line, username);
                }
            }
            strcat(line, "\n");
            llen = strlen(line);
        }

        memcpy(buf + buflen, line, llen);
        buflen += llen;
    }
    fclose(fp);

    if (!buf)
        return -1;

    /* Write back */
    fp = fopen(PATH_GROUP, "w");
    if (!fp) {
        fprintf(stderr, "%s: cannot write %s: %s\n", progname, PATH_GROUP,
                strerror(errno));
        free(buf);
        return -1;
    }
    fwrite(buf, 1, buflen, fp);
    fclose(fp);
    free(buf);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Copy skeleton directory                                            */
/* ------------------------------------------------------------------ */

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
        ssize_t written = 0;
        while (written < n) {
            ssize_t w = write(dfd, buf + written, (size_t)(n - written));
            if (w < 0) {
                close(sfd);
                close(dfd);
                return -1;
            }
            written += w;
        }
    }

    close(sfd);
    close(dfd);

    /* Set ownership — best effort (chown may not be available) */
    (void)uid;
    (void)gid;
    /* chown(dst, uid, gid); — not in our libc yet */

    return 0;
}

static int copy_skel(const char *homedir, int uid, int gid)
{
    struct stat st;
    if (stat(PATH_SKEL, &st) < 0)
        return 0;          /* /etc/skel doesn't exist, that's fine */

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

        /* Only copy regular files (skip subdirectories for simplicity) */
        if (S_ISREG(es.st_mode)) {
            if (copy_file(src, dst, uid, gid) < 0)
                fprintf(stderr, "%s: warning: failed to copy %s\n",
                        progname, src);
        }
    }
    closedir(dir);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Create home directory                                              */
/* ------------------------------------------------------------------ */

static int create_home(const char *homedir, int uid, int gid)
{
    if (mkdir(homedir, 0755) < 0) {
        if (errno == EEXIST) {
            fprintf(stderr, "%s: warning: home directory '%s' "
                    "already exists\n", progname, homedir);
            return 0;
        }
        fprintf(stderr, "%s: cannot create home directory '%s': %s\n",
                progname, homedir, strerror(errno));
        return -1;
    }

    /* Set ownership — best effort */
    (void)uid;
    (void)gid;
    /* chown(homedir, uid, gid); — not in our libc yet */

    /* Set permissions to 0700 */
    chmod(homedir, 0700);

    return 0;
}

/* ------------------------------------------------------------------ */
/* Ensure /etc files exist                                            */
/* ------------------------------------------------------------------ */

static void ensure_file_exists(const char *path)
{
    struct stat st;
    if (stat(path, &st) < 0) {
        int fd = open(path, O_WRONLY | O_CREAT, 0644);
        if (fd >= 0)
            close(fd);
    }
}

/* ------------------------------------------------------------------ */
/* Usage                                                              */
/* ------------------------------------------------------------------ */

static void usage(void)
{
    fprintf(stderr, "Usage: %s [OPTIONS] USERNAME\n", progname);
    fprintf(stderr, "Add a new user to the system.\n\n");
    fprintf(stderr, "  -u UID       specify user ID\n");
    fprintf(stderr, "  -g GID       specify primary group ID\n");
    fprintf(stderr, "  -d HOME      home directory (default: /Users/USERNAME)\n");
    fprintf(stderr, "  -s SHELL     login shell (default: %s)\n",
            DEFAULT_SHELL);
    fprintf(stderr, "  -c COMMENT   GECOS/comment field\n");
    fprintf(stderr, "  -m           create home directory (default)\n");
    fprintf(stderr, "  -M           do NOT create home directory\n");
    fprintf(stderr, "  -G GROUPS    supplementary groups "
            "(comma-separated)\n");
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
    int opt_create_home = 1;        /* -m is default */
    const char *opt_groups = NULL;  /* supplementary groups */
    const char *username = NULL;

    /* Must be root */
    if (getuid() != 0 && geteuid() != 0) {
        fprintf(stderr, "%s: only root may add a user\n", progname);
        return 1;
    }

    /* Parse options */
    int i;
    for (i = 1; i < argc; i++) {
        if (argv[i][0] != '-')
            break;
        if (strcmp(argv[i], "--") == 0) {
            i++;
            break;
        }
        if (strcmp(argv[i], "--help") == 0) {
            usage();
            return 0;
        }
        if (strcmp(argv[i], "-u") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "%s: -u requires an argument\n", progname);
                return 1;
            }
            opt_uid = atoi(argv[i]);
        } else if (strcmp(argv[i], "-g") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "%s: -g requires an argument\n", progname);
                return 1;
            }
            opt_gid = atoi(argv[i]);
        } else if (strcmp(argv[i], "-d") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "%s: -d requires an argument\n", progname);
                return 1;
            }
            opt_home = argv[i];
        } else if (strcmp(argv[i], "-s") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "%s: -s requires an argument\n", progname);
                return 1;
            }
            opt_shell = argv[i];
        } else if (strcmp(argv[i], "-c") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "%s: -c requires an argument\n", progname);
                return 1;
            }
            opt_comment = argv[i];
        } else if (strcmp(argv[i], "-m") == 0) {
            opt_create_home = 1;
        } else if (strcmp(argv[i], "-M") == 0) {
            opt_create_home = 0;
        } else if (strcmp(argv[i], "-G") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "%s: -G requires an argument\n", progname);
                return 1;
            }
            opt_groups = argv[i];
        } else {
            fprintf(stderr, "%s: invalid option '%s'\n", progname, argv[i]);
            usage();
            return 1;
        }
    }

    /* Username is the remaining argument */
    if (i >= argc) {
        fprintf(stderr, "%s: missing username\n", progname);
        usage();
        return 1;
    }
    username = argv[i];

    /* Validate username */
    if (!validate_username(username)) {
        fprintf(stderr, "%s: invalid username '%s'\n", progname, username);
        fprintf(stderr, "Username must start with a letter or underscore, "
                "contain only letters, digits, underscores, or hyphens, "
                "and be at most 32 characters.\n");
        return 1;
    }

    /* Check if user already exists */
    if (user_exists(username)) {
        fprintf(stderr, "%s: user '%s' already exists\n", progname, username);
        return 1;
    }

    /* Determine UID */
    int uid;
    if (opt_uid >= 0) {
        uid = opt_uid;
        if (uid_in_use(uid)) {
            fprintf(stderr, "%s: UID %d is already in use\n", progname, uid);
            return 1;
        }
    } else {
        uid = find_next_uid();
    }

    /* Determine GID */
    int gid;
    int create_group = 0;
    if (opt_gid >= 0) {
        gid = opt_gid;
    } else {
        /*
         * Create a new group with the same name as the user.
         * Use the same ID as the UID unless it's in use.
         */
        gid = uid;
        if (gid_in_use(gid))
            gid = find_next_gid();
        create_group = 1;
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

    /* ---- Create group entry ---- */
    if (create_group && !group_exists(username)) {
        char group_line[LINE_MAX];
        snprintf(group_line, sizeof(group_line), "%s:x:%d:\n",
                 username, gid);
        if (append_line(PATH_GROUP, group_line) < 0) {
            fprintf(stderr, "%s: failed to add group entry\n", progname);
            return 1;
        }
        printf("Adding group '%s' (GID %d) ...\n", username, gid);
    }

    /* ---- Add supplementary groups ---- */
    if (opt_groups) {
        char groups_copy[LINE_MAX];
        strncpy(groups_copy, opt_groups, sizeof(groups_copy) - 1);
        groups_copy[sizeof(groups_copy) - 1] = '\0';

        char *saveptr = NULL;
        char *grp = strtok_r(groups_copy, ",", &saveptr);
        while (grp) {
            /* Trim whitespace */
            while (*grp == ' ')
                grp++;

            if (!group_exists(grp)) {
                fprintf(stderr, "%s: warning: group '%s' does not exist\n",
                        progname, grp);
            } else {
                if (add_user_to_group(username, grp) < 0)
                    fprintf(stderr, "%s: warning: failed to add user "
                            "to group '%s'\n", progname, grp);
                else
                    printf("Adding user '%s' to group '%s' ...\n",
                           username, grp);
            }
            grp = strtok_r(NULL, ",", &saveptr);
        }
    }

    /* ---- Create /etc/passwd entry ---- */
    {
        char passwd_line[LINE_MAX];
        snprintf(passwd_line, sizeof(passwd_line),
                 "%s:x:%d:%d:%s:%s:%s\n",
                 username, uid, gid, opt_comment, homedir, opt_shell);
        if (append_line(PATH_PASSWD, passwd_line) < 0) {
            fprintf(stderr, "%s: failed to add passwd entry\n", progname);
            return 1;
        }
    }

    /* ---- Create /etc/shadow entry ---- */
    {
        /*
         * Shadow format: name:hash:lastchanged:min:max:warn:inactive:expire:
         * We set hash to "!" (locked — user must set password with passwd).
         * Other fields are set to sensible defaults or empty.
         */
        char shadow_line[LINE_MAX];
        snprintf(shadow_line, sizeof(shadow_line),
                 "%s:!:0:0:99999:7:::\n", username);
        if (append_line(PATH_SHADOW, shadow_line) < 0) {
            fprintf(stderr, "%s: failed to add shadow entry\n", progname);
            return 1;
        }
    }

    printf("Adding user '%s' (UID %d, GID %d) ...\n", username, uid, gid);

    /* ---- Create home directory ---- */
    if (opt_create_home) {
        /* Ensure parent directory exists */
        struct stat pst;
        if (stat(DEFAULT_HOME, &pst) < 0)
            mkdir(DEFAULT_HOME, 0755);

        if (create_home(homedir, uid, gid) == 0) {
            printf("Creating home directory '%s' ...\n", homedir);
            /* Copy skeleton files */
            copy_skel(homedir, uid, gid);
        }
    }

    printf("Done.\n");
    return 0;
}
