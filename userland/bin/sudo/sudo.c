/*
 * sudo - execute a command as another user
 *
 * Kiseki OS coreutils
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <sys/stat.h>

#define LINE_MAX       1024
#define PATH_PASSWD    "/etc/passwd"
#define PATH_SHADOW    "/etc/shadow"
#define PATH_SUDOERS   "/etc/sudoers"
#define DEFAULT_PATH   "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
#define DEFAULT_SHELL  "/bin/sh"

static const char *progname = "sudo";

/* ------------------------------------------------------------------ */
/* Password verification (mirrors login.c)                            */
/* ------------------------------------------------------------------ */

static unsigned long simple_hash(const char *s)
{
    unsigned long h = 5381;
    while (*s)
        h = ((h << 5) + h) ^ (unsigned char)*s++;
    return h;
}

static int verify_password(const char *attempt, const char *stored)
{
    if (stored == NULL || *stored == '\0')
        return 1;
    if (strcmp(stored, "!") == 0 || strcmp(stored, "*") == 0)
        return 0;
    if (strncmp(stored, "plain:", 6) == 0)
        return strcmp(attempt, stored + 6) == 0;
    if (strncmp(stored, "hash:", 5) == 0) {
        unsigned long stored_h = strtoul(stored + 5, NULL, 16);
        return simple_hash(attempt) == stored_h;
    }
    return strcmp(attempt, stored) == 0;
}

/* ------------------------------------------------------------------ */
/* Passwd / shadow helpers                                            */
/* ------------------------------------------------------------------ */

struct passwd_entry {
    char name[256];
    int  uid;
    int  gid;
    char gecos[256];
    char home[256];
    char shell[256];
};

static int parse_passwd_line(char *line, struct passwd_entry *pw)
{
    char *saveptr = NULL;
    char *tok;

    tok = strtok_r(line, ":", &saveptr);
    if (!tok) return -1;
    strncpy(pw->name, tok, sizeof(pw->name) - 1);
    pw->name[sizeof(pw->name) - 1] = '\0';

    tok = strtok_r(NULL, ":", &saveptr);  /* password placeholder */
    if (!tok) return -1;

    tok = strtok_r(NULL, ":", &saveptr);
    if (!tok) return -1;
    pw->uid = atoi(tok);

    tok = strtok_r(NULL, ":", &saveptr);
    if (!tok) return -1;
    pw->gid = atoi(tok);

    tok = strtok_r(NULL, ":", &saveptr);
    if (!tok) return -1;
    strncpy(pw->gecos, tok, sizeof(pw->gecos) - 1);
    pw->gecos[sizeof(pw->gecos) - 1] = '\0';

    tok = strtok_r(NULL, ":", &saveptr);
    if (!tok) return -1;
    strncpy(pw->home, tok, sizeof(pw->home) - 1);
    pw->home[sizeof(pw->home) - 1] = '\0';

    tok = strtok_r(NULL, ":\n", &saveptr);
    if (!tok) return -1;
    strncpy(pw->shell, tok, sizeof(pw->shell) - 1);
    pw->shell[sizeof(pw->shell) - 1] = '\0';

    return 0;
}

static int lookup_passwd(const char *username, struct passwd_entry *pw)
{
    FILE *fp = fopen(PATH_PASSWD, "r");
    if (!fp)
        return -1;

    char line[LINE_MAX];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n')
            continue;
        char copy[LINE_MAX];
        strncpy(copy, line, sizeof(copy) - 1);
        copy[sizeof(copy) - 1] = '\0';

        struct passwd_entry tmp;
        if (parse_passwd_line(copy, &tmp) == 0) {
            if (strcmp(tmp.name, username) == 0) {
                *pw = tmp;
                fclose(fp);
                return 0;
            }
        }
    }
    fclose(fp);
    return -1;
}

static int lookup_passwd_by_uid(int uid, struct passwd_entry *pw)
{
    FILE *fp = fopen(PATH_PASSWD, "r");
    if (!fp)
        return -1;

    char line[LINE_MAX];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n')
            continue;
        char copy[LINE_MAX];
        strncpy(copy, line, sizeof(copy) - 1);
        copy[sizeof(copy) - 1] = '\0';

        struct passwd_entry tmp;
        if (parse_passwd_line(copy, &tmp) == 0) {
            if (tmp.uid == uid) {
                *pw = tmp;
                fclose(fp);
                return 0;
            }
        }
    }
    fclose(fp);
    return -1;
}

static int lookup_shadow(const char *username, char *buf, size_t bufsz)
{
    FILE *fp = fopen(PATH_SHADOW, "r");
    if (!fp)
        return -1;

    char line[LINE_MAX];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n')
            continue;

        size_t ulen = strlen(username);
        if (strncmp(line, username, ulen) != 0 || line[ulen] != ':')
            continue;

        char *hash_start = line + ulen + 1;
        char *colon = strchr(hash_start, ':');
        size_t hash_len;
        if (colon)
            hash_len = (size_t)(colon - hash_start);
        else {
            hash_len = strlen(hash_start);
            if (hash_len > 0 && hash_start[hash_len - 1] == '\n')
                hash_len--;
        }

        if (hash_len >= bufsz)
            hash_len = bufsz - 1;
        memcpy(buf, hash_start, hash_len);
        buf[hash_len] = '\0';
        fclose(fp);
        return 0;
    }
    fclose(fp);
    return -1;
}

/* ------------------------------------------------------------------ */
/* Read password with echo disabled                                   */
/* ------------------------------------------------------------------ */

static int read_password(const char *prompt, char *buf, size_t bufsz)
{
    struct termios old, raw;
    int tty = isatty(STDIN_FILENO);

    if (tty) {
        if (tcgetattr(STDIN_FILENO, &old) < 0) {
            perror("tcgetattr");
            return -1;
        }
        raw = old;
        raw.c_lflag &= ~(ECHO);
        if (tcsetattr(STDIN_FILENO, 0, &raw) < 0) {
            perror("tcsetattr");
            return -1;
        }
    }

    fputs(prompt, stderr);
    fflush(stderr);

    if (fgets(buf, (int)bufsz, stdin) == NULL)
        buf[0] = '\0';

    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n')
        buf[len - 1] = '\0';

    if (tty) {
        tcsetattr(STDIN_FILENO, 0, &old);
        fputc('\n', stderr);
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Check if user is in a given group (by group name)                  */
/* ------------------------------------------------------------------ */

static int user_in_group(const char *username, const char *groupname)
{
    FILE *fp = fopen("/etc/group", "r");
    if (!fp)
        return 0;

    char line[LINE_MAX];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n')
            continue;

        /* Format: groupname:x:gid:member1,member2,... */
        char *saveptr = NULL;
        char *gname = strtok_r(line, ":", &saveptr);
        if (!gname || strcmp(gname, groupname) != 0)
            continue;

        /* Skip password */
        strtok_r(NULL, ":", &saveptr);
        /* Skip gid */
        strtok_r(NULL, ":", &saveptr);
        /* Members list */
        char *members = strtok_r(NULL, ":\n", &saveptr);
        if (!members) {
            fclose(fp);
            return 0;
        }

        /* Check each member */
        char *msave = NULL;
        char *member = strtok_r(members, ",", &msave);
        while (member) {
            /* Trim leading/trailing whitespace */
            while (*member == ' ' || *member == '\t')
                member++;
            char *end = member + strlen(member) - 1;
            while (end > member && (*end == ' ' || *end == '\t' ||
                                    *end == '\n'))
                *end-- = '\0';

            if (strcmp(member, username) == 0) {
                fclose(fp);
                return 1;
            }
            member = strtok_r(NULL, ",", &msave);
        }
        fclose(fp);
        return 0;
    }
    fclose(fp);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Sudoers parsing                                                    */
/*                                                                    */
/* Supported formats:                                                 */
/*   username ALL=(ALL) ALL                                           */
/*   username ALL=(ALL) NOPASSWD: ALL                                 */
/*   %groupname ALL=(ALL) ALL                                         */
/*   %groupname ALL=(ALL) NOPASSWD: ALL                               */
/*   root ALL=(ALL) ALL                                               */
/*                                                                    */
/* Returns:                                                           */
/*    0 = not authorized                                              */
/*    1 = authorized, password required                               */
/*    2 = authorized, no password required                            */
/* ------------------------------------------------------------------ */

static int check_sudoers(const char *username)
{
    FILE *fp = fopen(PATH_SUDOERS, "r");
    if (!fp) {
        /*
         * If /etc/sudoers doesn't exist, allow root to sudo without
         * a file, but deny everyone else.
         */
        struct passwd_entry pw;
        if (lookup_passwd(username, &pw) == 0 && pw.uid == 0)
            return 2;
        return 0;
    }

    char line[LINE_MAX];
    int result = 0;

    while (fgets(line, sizeof(line), fp)) {
        /* Strip comments and blank lines */
        char *hash = strchr(line, '#');
        if (hash)
            *hash = '\0';

        /* Trim leading whitespace */
        char *p = line;
        while (*p == ' ' || *p == '\t')
            p++;

        if (*p == '\0' || *p == '\n')
            continue;

        /* Trim trailing whitespace/newline */
        size_t len = strlen(p);
        while (len > 0 && (p[len - 1] == '\n' || p[len - 1] == ' ' ||
                           p[len - 1] == '\t'))
            p[--len] = '\0';

        if (len == 0)
            continue;

        /*
         * Parse the line.  We expect:
         *   <who> <host>=(<runas>) [NOPASSWD:] <cmds>
         * For simplicity we accept "ALL" for host, runas, and cmds.
         */
        char *saveptr = NULL;
        char *who = strtok_r(p, " \t", &saveptr);
        if (!who)
            continue;

        /* Check if this line matches our user */
        int match = 0;
        if (who[0] == '%') {
            /* Group match */
            if (user_in_group(username, who + 1))
                match = 1;
        } else {
            if (strcmp(who, username) == 0)
                match = 1;
        }

        if (!match)
            continue;

        /* The rest of the line after the who field */
        char *rest = strtok_r(NULL, "", &saveptr);
        if (!rest)
            continue;

        /* Check for NOPASSWD */
        if (strstr(rest, "NOPASSWD")) {
            result = 2;
        } else {
            if (result < 1)
                result = 1;
        }
    }

    fclose(fp);
    return result;
}

/* ------------------------------------------------------------------ */
/* Usage                                                              */
/* ------------------------------------------------------------------ */

static void usage(void)
{
    fprintf(stderr, "Usage: %s [-u USER] [-s] [-i] [-k] [-n] [-v] "
            "COMMAND [ARGS...]\n", progname);
    fprintf(stderr, "Execute a command as another user.\n\n");
    fprintf(stderr, "  -u USER    run command as USER (default: root)\n");
    fprintf(stderr, "  -s         run a shell\n");
    fprintf(stderr, "  -i         simulate a login shell\n");
    fprintf(stderr, "  -k         invalidate cached credentials\n");
    fprintf(stderr, "  -n         non-interactive; fail if password needed\n");
    fprintf(stderr, "  -v         validate/extend credential timeout\n");
}

/* ------------------------------------------------------------------ */
/* Main                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    const char *target_user = "root";
    int opt_shell = 0;
    int opt_login = 0;
    int opt_invalidate = 0;
    int opt_noninteractive = 0;
    int opt_validate = 0;
    int cmd_start = -1;    /* index where command args begin */

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
            target_user = argv[i];
        } else if (strcmp(argv[i], "-s") == 0) {
            opt_shell = 1;
        } else if (strcmp(argv[i], "-i") == 0) {
            opt_login = 1;
        } else if (strcmp(argv[i], "-k") == 0) {
            opt_invalidate = 1;
        } else if (strcmp(argv[i], "-n") == 0) {
            opt_noninteractive = 1;
        } else if (strcmp(argv[i], "-v") == 0) {
            opt_validate = 1;
        } else {
            /* Try bundled short options */
            const char *p = &argv[i][1];
            int valid = 1;
            while (*p && valid) {
                switch (*p) {
                case 's': opt_shell = 1; break;
                case 'i': opt_login = 1; break;
                case 'k': opt_invalidate = 1; break;
                case 'n': opt_noninteractive = 1; break;
                case 'v': opt_validate = 1; break;
                default:
                    fprintf(stderr, "%s: invalid option -- '%c'\n",
                            progname, *p);
                    usage();
                    return 1;
                }
                p++;
            }
        }
    }
    cmd_start = i;

    /* Handle -k: invalidate credentials (no-op since we don't cache) */
    if (opt_invalidate) {
        /* Nothing to invalidate in this implementation */
        if (cmd_start >= argc && !opt_shell && !opt_login && !opt_validate)
            return 0;
    }

    /* Need either a command, -s, -i, or -v */
    if (cmd_start >= argc && !opt_shell && !opt_login && !opt_validate) {
        usage();
        return 1;
    }

    /* Look up caller */
    int caller_uid = getuid();
    struct passwd_entry caller_pw;
    if (lookup_passwd_by_uid(caller_uid, &caller_pw) < 0) {
        fprintf(stderr, "%s: unable to determine caller identity\n",
                progname);
        return 1;
    }

    /* Look up target user */
    struct passwd_entry target_pw;
    if (lookup_passwd(target_user, &target_pw) < 0) {
        fprintf(stderr, "%s: unknown user: %s\n", progname, target_user);
        return 1;
    }

    /* Check sudoers authorization */
    int auth_level = check_sudoers(caller_pw.name);
    if (auth_level == 0) {
        fprintf(stderr,
                "%s: %s is not in the sudoers file. "
                "This incident will be reported.\n",
                progname, caller_pw.name);
        return 1;
    }

    /* Authenticate (caller's password, not target's) */
    if (auth_level == 1 && caller_uid != 0) {
        if (opt_noninteractive) {
            fprintf(stderr, "%s: a password is required\n", progname);
            return 1;
        }

        char shadow_hash[512];
        int have_shadow = lookup_shadow(caller_pw.name, shadow_hash,
                                        sizeof(shadow_hash));
        if (have_shadow < 0)
            shadow_hash[0] = '\0';

        if (shadow_hash[0] != '\0') {
            char prompt[256];
            snprintf(prompt, sizeof(prompt), "[sudo] password for %s: ",
                     caller_pw.name);

            int attempts = 0;
            while (attempts < 3) {
                char password[256];
                if (read_password(prompt, password, sizeof(password)) < 0)
                    return 1;

                if (verify_password(password, shadow_hash)) {
                    memset(password, 0, sizeof(password));
                    break;
                }
                memset(password, 0, sizeof(password));
                fprintf(stderr, "Sorry, try again.\n");
                attempts++;
            }
            if (attempts >= 3) {
                fprintf(stderr,
                        "%s: 3 incorrect password attempts\n", progname);
                return 1;
            }
        }
    }

    /* Handle -v (validate only, no command execution) */
    if (opt_validate) {
        if (cmd_start >= argc && !opt_shell && !opt_login)
            return 0;
    }

    /* Set UID to target */
    if (setuid(target_pw.uid) < 0) {
        fprintf(stderr, "%s: setuid(%d): %s\n", progname, target_pw.uid,
                strerror(errno));
        return 1;
    }

    /* Determine shell for -s/-i */
    const char *shell = target_pw.shell[0] ? target_pw.shell : DEFAULT_SHELL;

    /* Set environment */
    setenv("SUDO_USER", caller_pw.name, 1);
    setenv("SUDO_UID", caller_pw.name, 1);  /* simplified */

    if (opt_login) {
        setenv("HOME", target_pw.home, 1);
        setenv("USER", target_pw.name, 1);
        setenv("LOGNAME", target_pw.name, 1);
        setenv("SHELL", shell, 1);
        setenv("PATH", DEFAULT_PATH, 1);

        if (chdir(target_pw.home) < 0) {
            if (chdir("/") < 0) {
                perror("chdir");
                return 1;
            }
        }
    }

    /* Build correct SUDO_UID */
    {
        char uid_str[32];
        snprintf(uid_str, sizeof(uid_str), "%d", caller_pw.uid);
        setenv("SUDO_UID", uid_str, 1);

        char gid_str[32];
        snprintf(gid_str, sizeof(gid_str), "%d", caller_pw.gid);
        setenv("SUDO_GID", gid_str, 1);
    }

    if (opt_shell || opt_login) {
        /* Run a shell, possibly with -c if there are remaining args */
        const char *shell_base = strrchr(shell, '/');
        shell_base = shell_base ? shell_base + 1 : shell;

        if (cmd_start < argc) {
            /* Concatenate remaining args into a single command string */
            size_t total = 0;
            for (int j = cmd_start; j < argc; j++)
                total += strlen(argv[j]) + 1;

            char *cmd_str = malloc(total + 1);
            if (!cmd_str) {
                fprintf(stderr, "%s: out of memory\n", progname);
                return 1;
            }
            cmd_str[0] = '\0';
            for (int j = cmd_start; j < argc; j++) {
                if (j > cmd_start)
                    strcat(cmd_str, " ");
                strcat(cmd_str, argv[j]);
            }

            char arg0[256];
            if (opt_login)
                snprintf(arg0, sizeof(arg0), "-%s", shell_base);
            else
                snprintf(arg0, sizeof(arg0), "%s", shell_base);

            char *shell_argv[4];
            shell_argv[0] = arg0;
            shell_argv[1] = "-c";
            shell_argv[2] = cmd_str;
            shell_argv[3] = NULL;

            execv(shell, shell_argv);
            fprintf(stderr, "%s: failed to execute %s: %s\n", progname,
                    shell, strerror(errno));
            free(cmd_str);
            return 1;
        } else {
            /* Interactive shell */
            char arg0[256];
            if (opt_login)
                snprintf(arg0, sizeof(arg0), "-%s", shell_base);
            else
                snprintf(arg0, sizeof(arg0), "%s", shell_base);

            char *shell_argv[2];
            shell_argv[0] = arg0;
            shell_argv[1] = NULL;

            execv(shell, shell_argv);
            fprintf(stderr, "%s: failed to execute %s: %s\n", progname,
                    shell, strerror(errno));
            return 1;
        }
    }

    /* Execute the specified command */
    if (cmd_start >= argc) {
        fprintf(stderr, "%s: no command specified\n", progname);
        return 1;
    }

    /* Build argv: command + args */
    int cmd_argc = argc - cmd_start;
    char **cmd_argv = malloc((size_t)(cmd_argc + 1) * sizeof(char *));
    if (!cmd_argv) {
        fprintf(stderr, "%s: out of memory\n", progname);
        return 1;
    }
    for (int j = 0; j < cmd_argc; j++)
        cmd_argv[j] = argv[cmd_start + j];
    cmd_argv[cmd_argc] = NULL;

    execvp(cmd_argv[0], cmd_argv);
    fprintf(stderr, "%s: %s: %s\n", progname, cmd_argv[0], strerror(errno));
    free(cmd_argv);
    return 1;
}
