/*
 * usermod - modify a user account
 *
 * Kiseki OS coreutils - Unix/POSIX compatible
 *
 * Modifies user account information in /etc/passwd and /etc/shadow.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

#define LINE_MAX       1024
#define PATH_PASSWD    "/etc/passwd"
#define PATH_SHADOW    "/etc/shadow"
#define PATH_GROUP     "/etc/group"

static const char *progname = "usermod";

/* ------------------------------------------------------------------ */
/* Helper functions                                                   */
/* ------------------------------------------------------------------ */

static char *read_file(const char *path, size_t *len)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return NULL;

    /* Get file size */
    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return NULL;
    }

    char *buf = malloc((size_t)st.st_size + 1);
    if (!buf) {
        close(fd);
        return NULL;
    }

    ssize_t n = read(fd, buf, (size_t)st.st_size);
    close(fd);

    if (n < 0) {
        free(buf);
        return NULL;
    }

    buf[n] = '\0';
    if (len)
        *len = (size_t)n;
    return buf;
}

static int write_file(const char *path, const char *data, size_t len)
{
    int fd = open(path, O_WRONLY | O_TRUNC | O_CREAT, 0644);
    if (fd < 0)
        return -1;

    ssize_t written = write(fd, data, len);
    close(fd);

    return (written == (ssize_t)len) ? 0 : -1;
}

/*
 * Modify a field in /etc/passwd for a given user.
 * Fields: 0=name, 1=passwd, 2=uid, 3=gid, 4=gecos, 5=home, 6=shell
 */
static int modify_passwd_field(const char *username, int field, const char *newval)
{
    size_t flen;
    char *content = read_file(PATH_PASSWD, &flen);
    if (!content) {
        fprintf(stderr, "%s: cannot read %s\n", progname, PATH_PASSWD);
        return -1;
    }

    char *result = malloc(flen + LINE_MAX);
    if (!result) {
        free(content);
        return -1;
    }

    char *out = result;
    char *line = content;
    int found = 0;
    size_t ulen = strlen(username);

    while (*line) {
        /* Find end of line */
        char *eol = strchr(line, '\n');
        size_t linelen = eol ? (size_t)(eol - line) : strlen(line);

        /* Check if this is our user */
        if (strncmp(line, username, ulen) == 0 && line[ulen] == ':') {
            found = 1;

            /* Parse fields */
            char fields[7][256];
            int nf = 0;
            char *p = line;
            char *end = line + linelen;

            while (p < end && nf < 7) {
                char *colon = memchr(p, ':', (size_t)(end - p));
                size_t fldlen = colon ? (size_t)(colon - p) : (size_t)(end - p);
                if (fldlen >= sizeof(fields[0]))
                    fldlen = sizeof(fields[0]) - 1;
                memcpy(fields[nf], p, fldlen);
                fields[nf][fldlen] = '\0';
                nf++;
                p = colon ? colon + 1 : end;
            }

            /* Update the requested field */
            if (field >= 0 && field < nf && newval) {
                strncpy(fields[field], newval, sizeof(fields[field]) - 1);
                fields[field][sizeof(fields[field]) - 1] = '\0';
            }

            /* Reconstruct line */
            int len = sprintf(out, "%s:%s:%s:%s:%s:%s:%s\n",
                              fields[0], fields[1], fields[2], fields[3],
                              fields[4], fields[5], fields[6]);
            out += len;
        } else {
            /* Copy line unchanged */
            memcpy(out, line, linelen);
            out += linelen;
            *out++ = '\n';
        }

        line = eol ? eol + 1 : line + linelen;
    }

    free(content);

    if (!found) {
        free(result);
        fprintf(stderr, "%s: user '%s' does not exist\n", progname, username);
        return -1;
    }

    if (write_file(PATH_PASSWD, result, (size_t)(out - result)) < 0) {
        free(result);
        fprintf(stderr, "%s: cannot write %s\n", progname, PATH_PASSWD);
        return -1;
    }

    free(result);
    return 0;
}

/*
 * Add user to a group in /etc/group
 * Group line format: groupname:x:gid:user1,user2,user3
 */
static int add_user_to_group(const char *username, const char *groupname)
{
    size_t flen;
    char *content = read_file(PATH_GROUP, &flen);
    if (!content) {
        fprintf(stderr, "%s: cannot read %s\n", progname, PATH_GROUP);
        return -1;
    }

    char *result = malloc(flen + LINE_MAX);
    if (!result) {
        free(content);
        return -1;
    }

    char *out = result;
    char *line = content;
    int found = 0;
    size_t glen = strlen(groupname);

    while (*line) {
        char *eol = strchr(line, '\n');
        size_t linelen = eol ? (size_t)(eol - line) : strlen(line);

        if (strncmp(line, groupname, glen) == 0 && line[glen] == ':') {
            found = 1;

            /* Copy the line to a temp buffer */
            char linecopy[LINE_MAX];
            if (linelen >= sizeof(linecopy))
                linelen = sizeof(linecopy) - 1;
            memcpy(linecopy, line, linelen);
            linecopy[linelen] = '\0';

            /* Check if user is already in the group */
            char *members = strrchr(linecopy, ':');
            if (members) {
                members++; /* Skip the colon */
                /* Check if username already exists in the member list */
                char *p = members;
                int already_member = 0;
                while (*p) {
                    char *comma = strchr(p, ',');
                    size_t mlen = comma ? (size_t)(comma - p) : strlen(p);
                    if (mlen == strlen(username) && strncmp(p, username, mlen) == 0) {
                        already_member = 1;
                        break;
                    }
                    p = comma ? comma + 1 : p + mlen;
                }

                if (already_member) {
                    /* Copy unchanged */
                    memcpy(out, line, linelen);
                    out += linelen;
                    *out++ = '\n';
                } else {
                    /* Add user to the group */
                    if (strlen(members) > 0) {
                        /* Has existing members, append with comma */
                        int len = sprintf(out, "%s,%s\n", linecopy, username);
                        out += len;
                    } else {
                        /* No existing members */
                        int len = sprintf(out, "%s%s\n", linecopy, username);
                        out += len;
                    }
                }
            } else {
                /* Malformed line, copy unchanged */
                memcpy(out, line, linelen);
                out += linelen;
                *out++ = '\n';
            }
        } else {
            /* Copy line unchanged */
            memcpy(out, line, linelen);
            out += linelen;
            *out++ = '\n';
        }

        line = eol ? eol + 1 : line + linelen;
    }

    free(content);

    if (!found) {
        free(result);
        fprintf(stderr, "%s: group '%s' does not exist\n", progname, groupname);
        return -1;
    }

    if (write_file(PATH_GROUP, result, (size_t)(out - result)) < 0) {
        free(result);
        fprintf(stderr, "%s: cannot write %s\n", progname, PATH_GROUP);
        return -1;
    }

    free(result);
    return 0;
}

/*
 * Lock or unlock user account by modifying /etc/shadow
 */
static int lock_unlock_user(const char *username, int lock)
{
    size_t flen;
    char *content = read_file(PATH_SHADOW, &flen);
    if (!content) {
        fprintf(stderr, "%s: cannot read %s\n", progname, PATH_SHADOW);
        return -1;
    }

    char *result = malloc(flen + LINE_MAX);
    if (!result) {
        free(content);
        return -1;
    }

    char *out = result;
    char *line = content;
    int found = 0;
    size_t ulen = strlen(username);

    while (*line) {
        char *eol = strchr(line, '\n');
        size_t linelen = eol ? (size_t)(eol - line) : strlen(line);

        if (strncmp(line, username, ulen) == 0 && line[ulen] == ':') {
            found = 1;

            /* Parse shadow line: name:hash:... */
            char name[64], hash[256], rest[512];
            char linecopy[LINE_MAX];
            memcpy(linecopy, line, linelen);
            linecopy[linelen] = '\0';

            char *p1 = strchr(linecopy, ':');
            if (p1) {
                *p1 = '\0';
                strncpy(name, linecopy, sizeof(name) - 1);
                name[sizeof(name) - 1] = '\0';

                char *p2 = strchr(p1 + 1, ':');
                if (p2) {
                    *p2 = '\0';
                    strncpy(hash, p1 + 1, sizeof(hash) - 1);
                    hash[sizeof(hash) - 1] = '\0';
                    strncpy(rest, p2 + 1, sizeof(rest) - 1);
                    rest[sizeof(rest) - 1] = '\0';
                } else {
                    strncpy(hash, p1 + 1, sizeof(hash) - 1);
                    hash[sizeof(hash) - 1] = '\0';
                    rest[0] = '\0';
                }

                /* Modify hash for lock/unlock */
                if (lock) {
                    if (hash[0] != '!') {
                        char newhash[256];
                        snprintf(newhash, sizeof(newhash), "!%s", hash);
                        strncpy(hash, newhash, sizeof(hash) - 1);
                    }
                } else {
                    if (hash[0] == '!') {
                        memmove(hash, hash + 1, strlen(hash));
                    }
                }

                int len = sprintf(out, "%s:%s:%s\n", name, hash, rest);
                out += len;
            }
        } else {
            memcpy(out, line, linelen);
            out += linelen;
            *out++ = '\n';
        }

        line = eol ? eol + 1 : line + linelen;
    }

    free(content);

    if (!found) {
        free(result);
        fprintf(stderr, "%s: user '%s' does not exist in shadow\n", progname, username);
        return -1;
    }

    if (write_file(PATH_SHADOW, result, (size_t)(out - result)) < 0) {
        free(result);
        fprintf(stderr, "%s: cannot write %s\n", progname, PATH_SHADOW);
        return -1;
    }

    free(result);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Usage                                                              */
/* ------------------------------------------------------------------ */

static void usage(void)
{
    fprintf(stderr, "Usage: %s [options] LOGIN\n\n", progname);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -a, --append             append to groups (use with -G)\n");
    fprintf(stderr, "  -c, --comment COMMENT    new GECOS field\n");
    fprintf(stderr, "  -d, --home HOME_DIR      new home directory\n");
    fprintf(stderr, "  -g, --gid GROUP          new primary group\n");
    fprintf(stderr, "  -G, --groups GROUPS      supplementary groups (comma-separated)\n");
    fprintf(stderr, "  -l, --login NEW_LOGIN    new login name\n");
    fprintf(stderr, "  -s, --shell SHELL        new login shell\n");
    fprintf(stderr, "  -u, --uid UID            new user ID\n");
    fprintf(stderr, "  -L, --lock               lock the user account\n");
    fprintf(stderr, "  -U, --unlock             unlock the user account\n");
    fprintf(stderr, "  -h, --help               display this help\n");
}

/* ------------------------------------------------------------------ */
/* Main                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    const char *opt_comment = NULL;
    const char *opt_home = NULL;
    const char *opt_gid = NULL;
    const char *opt_groups = NULL;
    const char *opt_login = NULL;
    const char *opt_shell = NULL;
    const char *opt_uid = NULL;
    int opt_append = 0;
    int opt_lock = 0;
    int opt_unlock = 0;
    const char *username = NULL;

    /* Must be root */
    if (getuid() != 0 && geteuid() != 0) {
        fprintf(stderr, "%s: Permission denied.\n", progname);
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
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage();
            return 0;
        }
        /* Handle combined options like -aG */
        if (argv[i][0] == '-' && argv[i][1] != '-') {
            const char *p = &argv[i][1];
            while (*p) {
                if (*p == 'a') {
                    opt_append = 1;
                    p++;
                } else if (*p == 'G') {
                    p++;
                    if (*p) {
                        /* -Ggroup */
                        opt_groups = p;
                        break;
                    } else if (i + 1 < argc) {
                        /* -G group */
                        opt_groups = argv[++i];
                        break;
                    } else {
                        fprintf(stderr, "%s: option requires argument -- 'G'\n", progname);
                        return 1;
                    }
                } else if (*p == 'c') {
                    p++;
                    if (*p) { opt_comment = p; break; }
                    else if (++i < argc) { opt_comment = argv[i]; break; }
                    else { fprintf(stderr, "%s: option requires argument -- 'c'\n", progname); return 1; }
                } else if (*p == 'd') {
                    p++;
                    if (*p) { opt_home = p; break; }
                    else if (++i < argc) { opt_home = argv[i]; break; }
                    else { fprintf(stderr, "%s: option requires argument -- 'd'\n", progname); return 1; }
                } else if (*p == 'g') {
                    p++;
                    if (*p) { opt_gid = p; break; }
                    else if (++i < argc) { opt_gid = argv[i]; break; }
                    else { fprintf(stderr, "%s: option requires argument -- 'g'\n", progname); return 1; }
                } else if (*p == 'l') {
                    p++;
                    if (*p) { opt_login = p; break; }
                    else if (++i < argc) { opt_login = argv[i]; break; }
                    else { fprintf(stderr, "%s: option requires argument -- 'l'\n", progname); return 1; }
                } else if (*p == 's') {
                    p++;
                    if (*p) { opt_shell = p; break; }
                    else if (++i < argc) { opt_shell = argv[i]; break; }
                    else { fprintf(stderr, "%s: option requires argument -- 's'\n", progname); return 1; }
                } else if (*p == 'u') {
                    p++;
                    if (*p) { opt_uid = p; break; }
                    else if (++i < argc) { opt_uid = argv[i]; break; }
                    else { fprintf(stderr, "%s: option requires argument -- 'u'\n", progname); return 1; }
                } else if (*p == 'L') {
                    opt_lock = 1;
                    p++;
                } else if (*p == 'U') {
                    opt_unlock = 1;
                    p++;
                } else {
                    fprintf(stderr, "%s: invalid option -- '%c'\n", progname, *p);
                    usage();
                    return 1;
                }
            }
            continue;
        }
        /* Long options */
        if (strcmp(argv[i], "--append") == 0) {
            opt_append = 1;
        } else if (strcmp(argv[i], "--groups") == 0) {
            if (++i >= argc) { fprintf(stderr, "%s: option requires argument -- 'G'\n", progname); return 1; }
            opt_groups = argv[i];
        } else if (strcmp(argv[i], "--comment") == 0) {
            if (++i >= argc) { fprintf(stderr, "%s: option requires argument -- 'c'\n", progname); return 1; }
            opt_comment = argv[i];
        } else if (strcmp(argv[i], "--home") == 0) {
            if (++i >= argc) { fprintf(stderr, "%s: option requires argument -- 'd'\n", progname); return 1; }
            opt_home = argv[i];
        } else if (strcmp(argv[i], "--gid") == 0) {
            if (++i >= argc) { fprintf(stderr, "%s: option requires argument -- 'g'\n", progname); return 1; }
            opt_gid = argv[i];
        } else if (strcmp(argv[i], "--login") == 0) {
            if (++i >= argc) { fprintf(stderr, "%s: option requires argument -- 'l'\n", progname); return 1; }
            opt_login = argv[i];
        } else if (strcmp(argv[i], "--shell") == 0) {
            if (++i >= argc) { fprintf(stderr, "%s: option requires argument -- 's'\n", progname); return 1; }
            opt_shell = argv[i];
        } else if (strcmp(argv[i], "--uid") == 0) {
            if (++i >= argc) { fprintf(stderr, "%s: option requires argument -- 'u'\n", progname); return 1; }
            opt_uid = argv[i];
        } else if (strcmp(argv[i], "--lock") == 0) {
            opt_lock = 1;
        } else if (strcmp(argv[i], "--unlock") == 0) {
            opt_unlock = 1;
        } else {
            fprintf(stderr, "%s: invalid option -- '%s'\n", progname, argv[i]);
            usage();
            return 1;
        }
    }

    if (i >= argc) {
        fprintf(stderr, "%s: missing username\n", progname);
        usage();
        return 1;
    }
    username = argv[i];

    /* Apply modifications */
    int ret = 0;

    if (opt_login)
        ret |= modify_passwd_field(username, 0, opt_login);
    if (opt_uid)
        ret |= modify_passwd_field(username, 2, opt_uid);
    if (opt_gid)
        ret |= modify_passwd_field(username, 3, opt_gid);
    if (opt_comment)
        ret |= modify_passwd_field(username, 4, opt_comment);
    if (opt_home)
        ret |= modify_passwd_field(username, 5, opt_home);
    if (opt_shell)
        ret |= modify_passwd_field(username, 6, opt_shell);

    if (opt_lock)
        ret |= lock_unlock_user(username, 1);
    if (opt_unlock)
        ret |= lock_unlock_user(username, 0);

    /* Handle supplementary groups (-G, with -a for append) */
    if (opt_groups) {
        if (!opt_append) {
            fprintf(stderr, "%s: warning: -G without -a will only add to groups (removing from other groups not implemented)\n", progname);
        }
        /* Parse comma-separated group list */
        char groups_copy[1024];
        strncpy(groups_copy, opt_groups, sizeof(groups_copy) - 1);
        groups_copy[sizeof(groups_copy) - 1] = '\0';

        char *grp = groups_copy;
        while (*grp) {
            char *comma = strchr(grp, ',');
            if (comma)
                *comma = '\0';
            /* Skip empty group names */
            if (*grp) {
                if (add_user_to_group(username, grp) < 0)
                    ret = 1;
            }
            grp = comma ? comma + 1 : grp + strlen(grp);
        }
    }

    return ret ? 1 : 0;
}
