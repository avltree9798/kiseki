/*
 * id - print real and effective user and group IDs
 *
 * Usage: id [OPTION]... [USER]
 *
 * Flags:
 *   -u    print only the effective user ID
 *   -g    print only the effective group ID
 *   -G    print all group IDs
 *   -n    print name instead of number (with -u, -g, or -G)
 *   -r    print real ID instead of effective (with -u or -g)
 *
 * Kiseki OS coreutils
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

static const char *progname = "id";

/* Maximum number of supplementary groups */
#define MAX_GROUPS 64

/* Parsed passwd entry */
struct passwd_entry {
    char name[256];
    uid_t uid;
    gid_t gid;
    char gecos[256];
    char home[256];
    char shell[256];
};

/* Parsed group entry */
struct group_entry {
    char name[256];
    gid_t gid;
    char members[1024]; /* comma-separated member list */
};

static void usage(void)
{
    fprintf(stderr, "Usage: %s [OPTION]... [USER]\n", progname);
    fprintf(stderr, "Print user and group information.\n\n");
    fprintf(stderr, "  -u    print only the effective user ID\n");
    fprintf(stderr, "  -g    print only the effective group ID\n");
    fprintf(stderr, "  -G    print all group IDs\n");
    fprintf(stderr, "  -n    print name instead of number\n");
    fprintf(stderr, "  -r    print real ID instead of effective\n");
    fprintf(stderr, "  --help display this help and exit\n");
}

/*
 * Parse a single line from /etc/passwd into a passwd_entry.
 * Format: name:x:uid:gid:gecos:home:shell
 * Returns 0 on success, -1 on parse error.
 */
static int parse_passwd_line(const char *line, struct passwd_entry *pw)
{
    char buf[1024];
    size_t len = strlen(line);
    if (len == 0)
        return -1;
    if (len >= sizeof(buf))
        len = sizeof(buf) - 1;
    memcpy(buf, line, len);
    buf[len] = '\0';

    /* Strip trailing newline */
    if (buf[len - 1] == '\n')
        buf[--len] = '\0';

    /* Field 1: name */
    char *p = buf;
    char *colon = strchr(p, ':');
    if (!colon)
        return -1;
    *colon = '\0';
    strncpy(pw->name, p, sizeof(pw->name) - 1);
    pw->name[sizeof(pw->name) - 1] = '\0';

    /* Field 2: password (skip) */
    p = colon + 1;
    colon = strchr(p, ':');
    if (!colon)
        return -1;

    /* Field 3: uid */
    p = colon + 1;
    colon = strchr(p, ':');
    if (!colon)
        return -1;
    *colon = '\0';
    pw->uid = (uid_t)atoi(p);

    /* Field 4: gid */
    p = colon + 1;
    colon = strchr(p, ':');
    if (!colon)
        return -1;
    *colon = '\0';
    pw->gid = (gid_t)atoi(p);

    /* Field 5: gecos */
    p = colon + 1;
    colon = strchr(p, ':');
    if (!colon)
        return -1;
    *colon = '\0';
    strncpy(pw->gecos, p, sizeof(pw->gecos) - 1);
    pw->gecos[sizeof(pw->gecos) - 1] = '\0';

    /* Field 6: home */
    p = colon + 1;
    colon = strchr(p, ':');
    if (!colon)
        return -1;
    *colon = '\0';
    strncpy(pw->home, p, sizeof(pw->home) - 1);
    pw->home[sizeof(pw->home) - 1] = '\0';

    /* Field 7: shell */
    p = colon + 1;
    strncpy(pw->shell, p, sizeof(pw->shell) - 1);
    pw->shell[sizeof(pw->shell) - 1] = '\0';

    return 0;
}

/*
 * Parse a single line from /etc/group into a group_entry.
 * Format: name:x:gid:member1,member2,...
 * Returns 0 on success, -1 on parse error.
 */
static int parse_group_line(const char *line, struct group_entry *gr)
{
    char buf[2048];
    size_t len = strlen(line);
    if (len == 0)
        return -1;
    if (len >= sizeof(buf))
        len = sizeof(buf) - 1;
    memcpy(buf, line, len);
    buf[len] = '\0';

    /* Strip trailing newline */
    if (buf[len - 1] == '\n')
        buf[--len] = '\0';

    /* Field 1: name */
    char *p = buf;
    char *colon = strchr(p, ':');
    if (!colon)
        return -1;
    *colon = '\0';
    strncpy(gr->name, p, sizeof(gr->name) - 1);
    gr->name[sizeof(gr->name) - 1] = '\0';

    /* Field 2: password (skip) */
    p = colon + 1;
    colon = strchr(p, ':');
    if (!colon)
        return -1;

    /* Field 3: gid */
    p = colon + 1;
    colon = strchr(p, ':');
    if (!colon)
        return -1;
    *colon = '\0';
    gr->gid = (gid_t)atoi(p);

    /* Field 4: member list */
    p = colon + 1;
    strncpy(gr->members, p, sizeof(gr->members) - 1);
    gr->members[sizeof(gr->members) - 1] = '\0';

    return 0;
}

/*
 * Look up a user by UID in /etc/passwd.
 * Returns 0 if found, -1 if not found.
 */
static int lookup_uid(uid_t uid, struct passwd_entry *pw)
{
    FILE *fp = fopen("/etc/passwd", "r");
    if (!fp)
        return -1;

    char line[1024];
    while (fgets(line, (int)sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n')
            continue;
        struct passwd_entry tmp;
        if (parse_passwd_line(line, &tmp) == 0 && tmp.uid == uid) {
            *pw = tmp;
            fclose(fp);
            return 0;
        }
    }
    fclose(fp);
    return -1;
}

/*
 * Look up a user by name in /etc/passwd.
 * Returns 0 if found, -1 if not found.
 */
static int lookup_username(const char *name, struct passwd_entry *pw)
{
    FILE *fp = fopen("/etc/passwd", "r");
    if (!fp)
        return -1;

    char line[1024];
    while (fgets(line, (int)sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n')
            continue;
        struct passwd_entry tmp;
        if (parse_passwd_line(line, &tmp) == 0 &&
            strcmp(tmp.name, name) == 0) {
            *pw = tmp;
            fclose(fp);
            return 0;
        }
    }
    fclose(fp);
    return -1;
}

/*
 * Look up a group by GID in /etc/group.
 * Returns 0 if found, -1 if not found.
 */
static int lookup_gid(gid_t gid, struct group_entry *gr)
{
    FILE *fp = fopen("/etc/group", "r");
    if (!fp)
        return -1;

    char line[2048];
    while (fgets(line, (int)sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n')
            continue;
        struct group_entry tmp;
        if (parse_group_line(line, &tmp) == 0 && tmp.gid == gid) {
            *gr = tmp;
            fclose(fp);
            return 0;
        }
    }
    fclose(fp);
    return -1;
}

/*
 * Check if a username is in the comma-separated members string.
 */
static int is_member(const char *members, const char *username)
{
    if (members[0] == '\0')
        return 0;

    /* Work on a copy since strtok_r modifies the string */
    char buf[1024];
    strncpy(buf, members, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *saveptr = NULL;
    char *tok = strtok_r(buf, ",", &saveptr);
    while (tok) {
        /* Trim leading whitespace */
        while (*tok == ' ')
            tok++;
        if (strcmp(tok, username) == 0)
            return 1;
        tok = strtok_r(NULL, ",", &saveptr);
    }
    return 0;
}

/*
 * Get all groups a user belongs to.
 * Fills gids[] and names[] arrays. Returns count of groups found.
 * The primary GID is always included first.
 */
static int get_user_groups(const char *username, gid_t primary_gid,
                           gid_t *gids, char names[][256], int max_groups)
{
    int count = 0;

    /* Always include primary group first */
    gids[count] = primary_gid;
    struct group_entry gr;
    if (lookup_gid(primary_gid, &gr) == 0)
        strncpy(names[count], gr.name, 255);
    else
        snprintf(names[count], 256, "%d", (int)primary_gid);
    names[count][255] = '\0';
    count++;

    /* Scan /etc/group for supplementary memberships */
    FILE *fp = fopen("/etc/group", "r");
    if (!fp)
        return count;

    char line[2048];
    while (fgets(line, (int)sizeof(line), fp) && count < max_groups) {
        if (line[0] == '#' || line[0] == '\n')
            continue;
        struct group_entry tmp;
        if (parse_group_line(line, &tmp) != 0)
            continue;
        /* Skip if it's the primary group (already added) */
        if (tmp.gid == primary_gid)
            continue;
        if (is_member(tmp.members, username)) {
            gids[count] = tmp.gid;
            strncpy(names[count], tmp.name, 255);
            names[count][255] = '\0';
            count++;
        }
    }
    fclose(fp);
    return count;
}

int main(int argc, char *argv[])
{
    int opt_u = 0, opt_g = 0, opt_G = 0, opt_n = 0, opt_r = 0;
    const char *target_user = NULL;

    /* Parse options */
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-' && argv[i][1] != '\0') {
            if (strcmp(argv[i], "--help") == 0) {
                usage();
                return 0;
            }
            if (strcmp(argv[i], "--") == 0) {
                if (i + 1 < argc)
                    target_user = argv[i + 1];
                break;
            }
            /* Parse bundled flags */
            const char *p = &argv[i][1];
            while (*p) {
                switch (*p) {
                case 'u': opt_u = 1; break;
                case 'g': opt_g = 1; break;
                case 'G': opt_G = 1; break;
                case 'n': opt_n = 1; break;
                case 'r': opt_r = 1; break;
                default:
                    fprintf(stderr, "%s: invalid option -- '%c'\n",
                            progname, *p);
                    usage();
                    return 1;
                }
                p++;
            }
        } else {
            target_user = argv[i];
        }
    }

    /* Validate flag combinations */
    if (opt_n && !opt_u && !opt_g && !opt_G) {
        fprintf(stderr, "%s: cannot print only names in default format\n",
                progname);
        return 1;
    }
    if (opt_r && !opt_u && !opt_g) {
        fprintf(stderr,
                "%s: cannot print only real IDs in default format\n",
                progname);
        return 1;
    }

    uid_t uid, euid;
    gid_t gid;
    struct passwd_entry pw;
    int pw_found;

    if (target_user) {
        /* Look up the specified user */
        if (lookup_username(target_user, &pw) != 0) {
            /* Try as numeric UID */
            char *end;
            long val = strtol(target_user, &end, 10);
            if (*end != '\0' || end == target_user) {
                fprintf(stderr, "%s: '%s': no such user\n",
                        progname, target_user);
                return 1;
            }
            if (lookup_uid((uid_t)val, &pw) != 0) {
                fprintf(stderr, "%s: '%s': no such user\n",
                        progname, target_user);
                return 1;
            }
        }
        uid = pw.uid;
        euid = pw.uid;
        gid = pw.gid;
        pw_found = 1;
    } else {
        /* Current process */
        uid = getuid();
        euid = geteuid();
        gid = getgid();
        pw_found = (lookup_uid(euid, &pw) == 0);
        if (!pw_found) {
            /* Try real UID if effective lookup failed */
            pw_found = (lookup_uid(uid, &pw) == 0);
        }
    }

    /* Determine which UID/GID to use */
    uid_t display_uid = opt_r ? uid : euid;
    gid_t display_gid = gid; /* real and effective GID are the same here */

    /* For the target user case, use their passwd entry GID */
    if (target_user) {
        display_uid = pw.uid;
        display_gid = pw.gid;
    }

    /* Look up the display UID's passwd entry if different from what we have */
    struct passwd_entry display_pw;
    int display_pw_found;
    if (pw_found && pw.uid == display_uid) {
        display_pw = pw;
        display_pw_found = 1;
    } else {
        display_pw_found = (lookup_uid(display_uid, &display_pw) == 0);
    }

    /* -u: print user ID only */
    if (opt_u) {
        if (opt_n) {
            if (display_pw_found)
                printf("%s\n", display_pw.name);
            else
                printf("%u\n", (unsigned)display_uid);
        } else {
            printf("%u\n", (unsigned)display_uid);
        }
        return 0;
    }

    /* -g: print group ID only */
    if (opt_g) {
        if (opt_n) {
            struct group_entry gr;
            if (lookup_gid(display_gid, &gr) == 0)
                printf("%s\n", gr.name);
            else
                printf("%u\n", (unsigned)display_gid);
        } else {
            printf("%u\n", (unsigned)display_gid);
        }
        return 0;
    }

    /* -G: print all group IDs */
    if (opt_G) {
        const char *username = display_pw_found ? display_pw.name : "";
        gid_t gids[MAX_GROUPS];
        char gnames[MAX_GROUPS][256];
        int ngroups = get_user_groups(username, display_gid,
                                      gids, gnames, MAX_GROUPS);
        for (int i = 0; i < ngroups; i++) {
            if (i > 0)
                putchar(' ');
            if (opt_n)
                printf("%s", gnames[i]);
            else
                printf("%u", (unsigned)gids[i]);
        }
        putchar('\n');
        return 0;
    }

    /* Default: full output */
    /* uid=N(name) gid=N(name) groups=N(name),... */
    const char *uname_str = display_pw_found ? display_pw.name : NULL;

    /* UID */
    if (uname_str)
        printf("uid=%u(%s)", (unsigned)display_uid, uname_str);
    else
        printf("uid=%u", (unsigned)display_uid);

    /* GID */
    struct group_entry primary_gr;
    if (lookup_gid(display_gid, &primary_gr) == 0)
        printf(" gid=%u(%s)", (unsigned)display_gid, primary_gr.name);
    else
        printf(" gid=%u", (unsigned)display_gid);

    /* If euid != uid, show euid */
    if (!target_user && euid != uid) {
        struct passwd_entry epw;
        if (lookup_uid(euid, &epw) == 0)
            printf(" euid=%u(%s)", (unsigned)euid, epw.name);
        else
            printf(" euid=%u", (unsigned)euid);
    }

    /* Groups */
    const char *username = display_pw_found ? display_pw.name : "";
    gid_t gids[MAX_GROUPS];
    char gnames[MAX_GROUPS][256];
    int ngroups = get_user_groups(username, display_gid,
                                  gids, gnames, MAX_GROUPS);
    printf(" groups=");
    for (int i = 0; i < ngroups; i++) {
        if (i > 0)
            putchar(',');
        printf("%u(%s)", (unsigned)gids[i], gnames[i]);
    }

    putchar('\n');
    return 0;
}
