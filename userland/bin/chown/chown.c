/*
 * chown - change file owner and group
 *
 * Kiseki OS coreutils
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

/* chown() is provided by libSystem on Kiseki OS */

static const char *progname = "chown";

static int opt_recursive    = 0;
static int opt_verbose      = 0;
static int opt_silent       = 0;
static int opt_no_deref     = 0; /* -h: don't follow symlinks */

static void usage(void)
{
    fprintf(stderr, "Usage: %s [OPTION]... OWNER[:GROUP] FILE...\n", progname);
    fprintf(stderr, "Change the owner and/or group of each FILE to OWNER and/or GROUP.\n\n");
    fprintf(stderr, "  OWNER          change owner only\n");
    fprintf(stderr, "  OWNER:GROUP    change owner and group\n");
    fprintf(stderr, "  :GROUP         change group only\n\n");
    fprintf(stderr, "  -R    operate on files and directories recursively\n");
    fprintf(stderr, "  -v    output a diagnostic for every file processed\n");
    fprintf(stderr, "  -f    suppress most error messages\n");
    fprintf(stderr, "  -h    affect symbolic links instead of referenced file\n");
    fprintf(stderr, "  --help display this help and exit\n");
}

/*
 * Look up a user name in /etc/passwd and return the uid.
 * Returns 0 on success, -1 on failure.
 */
static int lookup_user(const char *name, uid_t *uid)
{
    FILE *fp = fopen("/etc/passwd", "r");
    if (!fp)
        return -1;

    char line[1024];
    while (fgets(line, (int)sizeof(line), fp)) {
        /* Format: name:password:uid:gid:gecos:home:shell */
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n')
            line[len - 1] = '\0';

        char *saveptr;
        char *field_name = strtok_r(line, ":", &saveptr);
        if (!field_name)
            continue;

        /* Skip password field */
        char *field_pass = strtok_r(NULL, ":", &saveptr);
        if (!field_pass)
            continue;

        char *field_uid = strtok_r(NULL, ":", &saveptr);
        if (!field_uid)
            continue;

        if (strcmp(field_name, name) == 0) {
            *uid = (uid_t)strtoul(field_uid, NULL, 10);
            fclose(fp);
            return 0;
        }
    }

    fclose(fp);
    return -1;
}

/*
 * Look up a group name in /etc/group and return the gid.
 * Returns 0 on success, -1 on failure.
 */
static int lookup_group(const char *name, gid_t *gid)
{
    FILE *fp = fopen("/etc/group", "r");
    if (!fp)
        return -1;

    char line[1024];
    while (fgets(line, (int)sizeof(line), fp)) {
        /* Format: name:password:gid:members */
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n')
            line[len - 1] = '\0';

        char *saveptr;
        char *field_name = strtok_r(line, ":", &saveptr);
        if (!field_name)
            continue;

        char *field_pass = strtok_r(NULL, ":", &saveptr);
        if (!field_pass)
            continue;

        char *field_gid = strtok_r(NULL, ":", &saveptr);
        if (!field_gid)
            continue;

        if (strcmp(field_name, name) == 0) {
            *gid = (gid_t)strtoul(field_gid, NULL, 10);
            fclose(fp);
            return 0;
        }
    }

    fclose(fp);
    return -1;
}

/*
 * Check if a string is entirely numeric.
 */
static int is_numeric(const char *s)
{
    if (!s || *s == '\0')
        return 0;
    while (*s) {
        if (*s < '0' || *s > '9')
            return 0;
        s++;
    }
    return 1;
}

/*
 * Parse the OWNER[:GROUP] spec.
 * Sets *uid and *gid. If a component is not specified, sets it to (uid_t)-1
 * or (gid_t)-1 to indicate "no change".
 * Returns 0 on success, -1 on error.
 */
static int parse_owner_group(const char *spec, uid_t *uid, gid_t *gid)
{
    *uid = (uid_t)-1;
    *gid = (gid_t)-1;

    char *copy = strdup(spec);
    if (!copy)
        return -1;

    /* Find the colon separator */
    char *colon = strchr(copy, ':');

    if (colon) {
        *colon = '\0';
        const char *owner_part = copy;
        const char *group_part = colon + 1;

        /* Parse owner part (may be empty for ":GROUP") */
        if (*owner_part != '\0') {
            if (is_numeric(owner_part)) {
                *uid = (uid_t)strtoul(owner_part, NULL, 10);
            } else {
                if (lookup_user(owner_part, uid) < 0) {
                    fprintf(stderr, "%s: invalid user: '%s'\n",
                            progname, owner_part);
                    free(copy);
                    return -1;
                }
            }
        }

        /* Parse group part (may be empty for "OWNER:") */
        if (*group_part != '\0') {
            if (is_numeric(group_part)) {
                *gid = (gid_t)strtoul(group_part, NULL, 10);
            } else {
                if (lookup_group(group_part, gid) < 0) {
                    fprintf(stderr, "%s: invalid group: '%s'\n",
                            progname, group_part);
                    free(copy);
                    return -1;
                }
            }
        }
    } else {
        /* No colon: owner only */
        if (is_numeric(copy)) {
            *uid = (uid_t)strtoul(copy, NULL, 10);
        } else {
            if (lookup_user(copy, uid) < 0) {
                fprintf(stderr, "%s: invalid user: '%s'\n", progname, copy);
                free(copy);
                return -1;
            }
        }
    }

    free(copy);
    return 0;
}

static int do_chown(const char *path, uid_t uid, gid_t gid);

static int do_chown_recursive(const char *path, uid_t uid, gid_t gid)
{
    DIR *dp = opendir(path);
    if (!dp) {
        if (!opt_silent)
            fprintf(stderr, "%s: cannot open directory '%s': %s\n",
                    progname, path, strerror(errno));
        return 1;
    }

    int ret = 0;
    struct dirent *ent;
    while ((ent = readdir(dp)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        size_t plen = strlen(path);
        size_t nlen = strlen(ent->d_name);
        char *child = malloc(plen + 1 + nlen + 1);
        if (!child) {
            fprintf(stderr, "%s: out of memory\n", progname);
            ret = 1;
            break;
        }
        snprintf(child, plen + 1 + nlen + 1, "%s/%s", path, ent->d_name);

        if (do_chown(child, uid, gid) != 0)
            ret = 1;

        free(child);
    }

    closedir(dp);
    return ret;
}

static int do_chown(const char *path, uid_t uid, gid_t gid)
{
    struct stat st;
    int (*stat_fn)(const char *, struct stat *) = opt_no_deref ? lstat : stat;

    if (stat_fn(path, &st) < 0) {
        if (!opt_silent)
            fprintf(stderr, "%s: cannot access '%s': %s\n",
                    progname, path, strerror(errno));
        return 1;
    }

    /* Resolve "no change" values to current owner/group */
    uid_t new_uid = (uid == (uid_t)-1) ? st.st_uid : uid;
    gid_t new_gid = (gid == (gid_t)-1) ? st.st_gid : gid;

    if (chown(path, new_uid, new_gid) < 0) {
        if (!opt_silent)
            fprintf(stderr, "%s: changing ownership of '%s': %s\n",
                    progname, path, strerror(errno));
        return 1;
    }

    if (opt_verbose) {
        printf("ownership of '%s' changed to %u:%u\n",
               path, (unsigned)new_uid, (unsigned)new_gid);
    }

    /* Recurse into directories */
    if (opt_recursive && S_ISDIR(st.st_mode)) {
        if (do_chown_recursive(path, uid, gid) != 0)
            return 1;
    }

    return 0;
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
                case 'R': opt_recursive = 1; break;
                case 'v': opt_verbose = 1; break;
                case 'f': opt_silent = 1; break;
                case 'h': opt_no_deref = 1; break;
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

    /* Parse owner:group spec */
    uid_t uid;
    gid_t gid;
    if (parse_owner_group(argv[first_arg], &uid, &gid) < 0)
        return 1;

    int ret = 0;
    for (int i = first_arg + 1; i < argc; i++) {
        if (do_chown(argv[i], uid, gid) != 0)
            ret = 1;
    }

    return ret;
}
