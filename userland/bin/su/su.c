/*
 * su - switch user
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
#define DEFAULT_PATH   "/usr/local/bin:/usr/bin:/bin"
#define DEFAULT_SHELL  "/bin/sh"

static const char *progname = "su";

/* ------------------------------------------------------------------ */
/* Simple password hash – mirrors login.c                             */
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
/* Usage                                                              */
/* ------------------------------------------------------------------ */

static void usage(void)
{
    fprintf(stderr, "Usage: %s [OPTIONS] [USER]\n", progname);
    fprintf(stderr, "Switch to another user.\n\n");
    fprintf(stderr, "  -, -l, --login   simulate a full login\n");
    fprintf(stderr, "  -c COMMAND       pass COMMAND to the shell with -c\n");
    fprintf(stderr, "  -s SHELL         use SHELL instead of the default\n");
    fprintf(stderr, "  -p               preserve environment\n");
}

/* ------------------------------------------------------------------ */
/* Main                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    int login_shell = 0;
    int preserve_env = 0;
    const char *command = NULL;
    const char *shell_override = NULL;
    const char *target_user = "root";

    /* Parse options */
    int i;
    for (i = 1; i < argc; i++) {
        if (argv[i][0] != '-')
            break;
        if (strcmp(argv[i], "--") == 0) {
            i++;
            break;
        }
        if (strcmp(argv[i], "--login") == 0 || strcmp(argv[i], "-") == 0 ||
            strcmp(argv[i], "-l") == 0) {
            login_shell = 1;
        } else if (strcmp(argv[i], "-c") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "%s: -c requires an argument\n", progname);
                return 1;
            }
            command = argv[i];
        } else if (strcmp(argv[i], "-s") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "%s: -s requires an argument\n", progname);
                return 1;
            }
            shell_override = argv[i];
        } else if (strcmp(argv[i], "-p") == 0) {
            preserve_env = 1;
        } else if (strcmp(argv[i], "--help") == 0) {
            usage();
            return 0;
        } else {
            /* Could be bundled flags like -lp */
            const char *p = &argv[i][1];
            int valid = 1;
            while (*p && valid) {
                switch (*p) {
                case 'l': login_shell = 1; break;
                case 'p': preserve_env = 1; break;
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

    /* Remaining argument = target user */
    if (i < argc)
        target_user = argv[i];

    /* Look up target user */
    struct passwd_entry target_pw;
    if (lookup_passwd(target_user, &target_pw) < 0) {
        fprintf(stderr, "%s: user '%s' does not exist\n", progname,
                target_user);
        return 1;
    }

    /* Authenticate: skip if caller is root */
    int caller_uid = getuid();
    if (caller_uid != 0) {
        char shadow_hash[512];
        int have_shadow = lookup_shadow(target_user, shadow_hash,
                                        sizeof(shadow_hash));
        if (have_shadow < 0)
            shadow_hash[0] = '\0';

        if (shadow_hash[0] != '\0') {
            char password[256];
            if (read_password("Password: ", password, sizeof(password)) < 0)
                return 1;

            if (!verify_password(password, shadow_hash)) {
                memset(password, 0, sizeof(password));
                fprintf(stderr, "%s: Authentication failure\n", progname);
                return 1;
            }
            memset(password, 0, sizeof(password));
        }
    }

    /* Determine shell */
    const char *shell;
    if (shell_override)
        shell = shell_override;
    else if (target_pw.shell[0])
        shell = target_pw.shell;
    else
        shell = DEFAULT_SHELL;

    /* Set UID */
    if (setuid(target_pw.uid) < 0) {
        fprintf(stderr, "%s: setuid(%d): %s\n", progname, target_pw.uid,
                strerror(errno));
        return 1;
    }

    /* Set up environment for login shell */
    if (login_shell && !preserve_env) {
        setenv("HOME", target_pw.home, 1);
        setenv("USER", target_pw.name, 1);
        setenv("LOGNAME", target_pw.name, 1);
        setenv("SHELL", shell, 1);
        setenv("PATH", DEFAULT_PATH, 1);

        if (chdir(target_pw.home) < 0) {
            fprintf(stderr, "%s: warning: cannot chdir to %s: %s\n",
                    progname, target_pw.home, strerror(errno));
            if (chdir("/") < 0) {
                perror("chdir");
                return 1;
            }
        }
    } else if (!preserve_env) {
        /* Even without login, update USER/HOME */
        setenv("HOME", target_pw.home, 1);
        setenv("USER", target_pw.name, 1);
        setenv("LOGNAME", target_pw.name, 1);
        setenv("SHELL", shell, 1);
    }

    /* Build argv for the shell */
    const char *shell_base = strrchr(shell, '/');
    shell_base = shell_base ? shell_base + 1 : shell;

    if (command) {
        /* su -c "command" → shell -c "command" */
        char *shell_argv[4];
        char arg0[256];

        if (login_shell)
            snprintf(arg0, sizeof(arg0), "-%s", shell_base);
        else
            snprintf(arg0, sizeof(arg0), "%s", shell_base);

        shell_argv[0] = arg0;
        shell_argv[1] = "-c";
        shell_argv[2] = (char *)command;
        shell_argv[3] = NULL;

        execv(shell, shell_argv);
    } else {
        /* Interactive shell */
        char *shell_argv[2];
        char arg0[256];

        if (login_shell)
            snprintf(arg0, sizeof(arg0), "-%s", shell_base);
        else
            snprintf(arg0, sizeof(arg0), "%s", shell_base);

        shell_argv[0] = arg0;
        shell_argv[1] = NULL;

        execv(shell, shell_argv);
    }

    /* exec failed */
    fprintf(stderr, "%s: failed to execute %s: %s\n", progname, shell,
            strerror(errno));
    return 1;
}
