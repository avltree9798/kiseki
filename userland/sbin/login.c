/*
 * Kiseki OS - /bin/login
 *
 * Authenticates a user against /etc/passwd and /etc/shadow,
 * sets UID/GID, and execs the user's login shell.
 *
 * Password formats in /etc/shadow:
 *   ""              - no password required
 *   "plain:<text>"  - plaintext comparison
 *   "!" or "*"      - account locked
 *
 * Usage: login [username]
 *
 * Compiled with: clang -o login login.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/ioctl.h>

#define MAX_ATTEMPTS    3
#define LINE_MAX_SZ     1024
#define PATH_PASSWD     "/etc/passwd"
#define PATH_SHADOW     "/etc/shadow"
#define DEFAULT_SHELL   "/bin/bash"
#define DEFAULT_PATH    "/bin:/sbin:/usr/bin:/usr/sbin"

struct passwd_entry {
    char name[256];
    int  uid;
    int  gid;
    char gecos[256];
    char home[256];
    char shell[256];
};

/* ------------------------------------------------------------------ */
/* String helpers                                                      */
/* ------------------------------------------------------------------ */

static void strip_newline(char *s)
{
    int len = (int)strlen(s);
    if (len > 0 && s[len - 1] == '\n')
        s[len - 1] = '\0';
}

/*
 * Read one field from a colon-delimited string.
 * Advances *pp past the colon. Returns pointer to field start.
 */
static char *next_field(char **pp)
{
    if (*pp == NULL)
        return NULL;
    char *start = *pp;
    char *colon = strchr(start, ':');
    if (colon) {
        *colon = '\0';
        *pp = colon + 1;
    } else {
        /* Last field — strip newline */
        strip_newline(start);
        *pp = NULL;
    }
    return start;
}

/* ------------------------------------------------------------------ */
/* Passwd / shadow helpers                                            */
/* ------------------------------------------------------------------ */

static int parse_passwd_line(char *line, struct passwd_entry *pw)
{
    char *p = line;
    char *f;

    /* name */
    f = next_field(&p);
    if (!f) return -1;
    strncpy(pw->name, f, sizeof(pw->name) - 1);

    /* password placeholder (skip) */
    f = next_field(&p);
    if (!f) return -1;

    /* uid */
    f = next_field(&p);
    if (!f) return -1;
    pw->uid = atoi(f);

    /* gid */
    f = next_field(&p);
    if (!f) return -1;
    pw->gid = atoi(f);

    /* gecos */
    f = next_field(&p);
    if (!f) return -1;
    strncpy(pw->gecos, f, sizeof(pw->gecos) - 1);

    /* home */
    f = next_field(&p);
    if (!f) return -1;
    strncpy(pw->home, f, sizeof(pw->home) - 1);

    /* shell */
    f = next_field(&p);
    if (!f) return -1;
    strncpy(pw->shell, f, sizeof(pw->shell) - 1);

    return 0;
}

static int lookup_passwd(const char *username, struct passwd_entry *pw)
{
    FILE *fp = fopen(PATH_PASSWD, "r");
    if (!fp)
        return -1;

    char line[LINE_MAX_SZ];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n')
            continue;
        char copy[LINE_MAX_SZ];
        strncpy(copy, line, sizeof(copy) - 1);
        copy[sizeof(copy) - 1] = '\0';

        struct passwd_entry tmp;
        memset(&tmp, 0, sizeof(tmp));
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

/*
 * Look up password hash in /etc/shadow.
 * Format: name:hash:lastchanged:...
 */
static int lookup_shadow(const char *username, char *buf, int bufsz)
{
    FILE *fp = fopen(PATH_SHADOW, "r");
    if (!fp)
        return -1;

    char line[LINE_MAX_SZ];
    int ulen = (int)strlen(username);

    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n')
            continue;

        /* Match "username:" at start */
        if (strncmp(line, username, ulen) != 0 || line[ulen] != ':')
            continue;

        /* Extract hash field (between first and second colon) */
        char *hash_start = line + ulen + 1;
        char *colon = strchr(hash_start, ':');
        int hash_len;
        if (colon)
            hash_len = (int)(colon - hash_start);
        else {
            hash_len = (int)strlen(hash_start);
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

static int verify_password(const char *attempt, const char *stored)
{
    /* Empty stored = no password required */
    if (stored[0] == '\0')
        return 1;

    /* Locked account */
    if (strcmp(stored, "!") == 0 || strcmp(stored, "*") == 0)
        return 0;

    /* plain:<text> format */
    if (strncmp(stored, "plain:", 6) == 0)
        return strcmp(attempt, stored + 6) == 0;

    /* Direct comparison fallback */
    return strcmp(attempt, stored) == 0;
}

/* ------------------------------------------------------------------ */
/* Password reading (no echo)                                         */
/* ------------------------------------------------------------------ */

/*
 * Read password with echo disabled via termios ioctl.
 * Uses TIOCGETA/TIOCSETA to toggle ECHO flag on the console TTY.
 */
static int read_password(const char *prompt, char *buf, int bufsz)
{
    /* Get current terminal attributes */
    struct termios old_t, new_t;
    int have_termios = 0;

    if (ioctl(0, TIOCGETA, &old_t) == 0) {
        have_termios = 1;
        new_t = old_t;
        new_t.c_lflag &= ~((unsigned long)ECHO);  /* Disable echo */
        ioctl(0, TIOCSETA, &new_t);
    }

    printf("%s", prompt);
    fflush(stdout);

    if (fgets(buf, bufsz, stdin) == NULL) {
        if (have_termios)
            ioctl(0, TIOCSETA, &old_t);  /* Restore echo */
        return -1;
    }

    /* Restore echo */
    if (have_termios)
        ioctl(0, TIOCSETA, &old_t);

    printf("\n");  /* Since echo was off, print newline after password */

    strip_newline(buf);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Hostname                                                           */
/* ------------------------------------------------------------------ */

static void get_hostname(char *buf, int bufsz)
{
    int fd = open("/etc/hostname", O_RDONLY);
    if (fd >= 0) {
        int n = (int)read(fd, buf, bufsz - 1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            strip_newline(buf);
            return;
        }
    }
    strcpy(buf, "kiseki");
}

/* ------------------------------------------------------------------ */
/* Main                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    /* If a username was passed on the command line (from getty), use it */
    const char *preset_user = NULL;
    if (argc >= 2)
        preset_user = argv[1];

    char hostname[256];
    get_hostname(hostname, sizeof(hostname));

    int attempts = 0;
    while (attempts < MAX_ATTEMPTS) {
        char username[256];
        char password[256];
        struct passwd_entry pw;

        /* Get username */
        if (preset_user && attempts == 0) {
            strncpy(username, preset_user, sizeof(username) - 1);
            username[sizeof(username) - 1] = '\0';
        } else {
            printf("%s login: ", hostname);
            fflush(stdout);
            if (fgets(username, sizeof(username), stdin) == NULL)
                return 1;
            strip_newline(username);
            if (username[0] == '\0')
                continue;
        }

        /* Lookup user */
        if (lookup_passwd(username, &pw) < 0) {
            /* Don't reveal whether username exists */
            read_password("Password: ", password, sizeof(password));
            printf("Login incorrect\n");
            attempts++;
            continue;
        }

        /* Get password from shadow */
        char shadow_hash[512];
        if (lookup_shadow(username, shadow_hash, sizeof(shadow_hash)) < 0)
            shadow_hash[0] = '\0';  /* No shadow entry = no password */

        /* Authenticate */
        if (shadow_hash[0] != '\0') {
            if (read_password("Password: ", password, sizeof(password)) < 0)
                return 1;

            if (!verify_password(password, shadow_hash)) {
                memset(password, 0, sizeof(password));
                printf("Login incorrect\n");
                attempts++;
                continue;
            }
        }
        memset(password, 0, sizeof(password));

        /* --- Authentication succeeded --- */

        /* Set UID and GID */
        if (setuid(pw.uid) < 0) {
            printf("login: setuid(%d) failed\n", pw.uid);
            return 1;
        }

        /* Change to home directory */
        if (chdir(pw.home) < 0) {
            chdir("/");
        }

        /* Determine shell */
        const char *shell = pw.shell[0] ? pw.shell : DEFAULT_SHELL;

        /* Build argv: login shell gets "-shellname" as argv[0] */
        const char *shell_base = strrchr(shell, '/');
        shell_base = shell_base ? shell_base + 1 : shell;

        char login_arg[256];
        snprintf(login_arg, sizeof(login_arg), "-%s", shell_base);

        /* Build environment */
        char env_home[280];
        char env_user[280];
        char env_logname[280];
        char env_shell[280];
        snprintf(env_home, sizeof(env_home), "HOME=%s", pw.home);
        snprintf(env_user, sizeof(env_user), "USER=%s", pw.name);
        snprintf(env_logname, sizeof(env_logname), "LOGNAME=%s", pw.name);
        snprintf(env_shell, sizeof(env_shell), "SHELL=%s", shell);

        char *shell_argv[] = { login_arg, NULL };
        char *shell_envp[] = {
            env_home,
            env_user,
            env_logname,
            env_shell,
            "PATH=" DEFAULT_PATH,
            "TERM=vt100",
            NULL
        };

        printf("\nWelcome to %s\n\n", hostname);
        fflush(stdout);

        execve(shell, shell_argv, shell_envp);

        /* exec failed */
        printf("login: failed to execute %s\n", shell);
        return 1;
    }

    printf("login: maximum login attempts exceeded\n");
    return 1;
}
