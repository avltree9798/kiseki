/*
 * login - user login program
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

#define MAX_ATTEMPTS   3
#define FAIL_DELAY     2
#define LINE_MAX       1024
#define PATH_PASSWD    "/etc/passwd"
#define PATH_SHADOW    "/etc/shadow"
#define DEFAULT_PATH   "/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin"
#define DEFAULT_SHELL  "/bin/sh"

static const char *progname = "login";

/* ------------------------------------------------------------------ */
/* Simple hash for password verification.                             */
/*                                                                    */
/* Stored format in /etc/shadow:                                      */
/*   "plain:<cleartext>"  – plaintext comparison                      */
/*   ""  (empty)          – no password required                      */
/*   "!"  or  "*"         – account locked                            */
/* ------------------------------------------------------------------ */

static unsigned long simple_hash(const char *s)
{
    unsigned long h = 5381;
    while (*s)
        h = ((h << 5) + h) ^ (unsigned char)*s++;
    return h;
}

/*
 * Verify a password attempt against the stored hash field.
 * Returns 1 on match, 0 on mismatch.
 */
static int verify_password(const char *attempt, const char *stored)
{
    if (stored == NULL || *stored == '\0')
        return 1;                       /* empty → no password required */

    if (strcmp(stored, "!") == 0 || strcmp(stored, "*") == 0)
        return 0;                       /* locked account */

    /* plain:<text> format */
    if (strncmp(stored, "plain:", 6) == 0)
        return strcmp(attempt, stored + 6) == 0;

    /* hash:<number> format */
    if (strncmp(stored, "hash:", 5) == 0) {
        unsigned long stored_h = strtoul(stored + 5, NULL, 16);
        return simple_hash(attempt) == stored_h;
    }

    /* Fallback: direct comparison */
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

/*
 * get_field - Extract the next colon-separated field from a string.
 * Unlike strtok_r, this handles empty fields correctly.
 */
static int get_field(char **pp, char *buf, size_t bufsz)
{
    if (*pp == NULL || **pp == '\0')
        return -1;

    char *start = *pp;
    char *end = strchr(start, ':');

    if (end == NULL) {
        /* Last field - copy until end of string, strip newline */
        size_t len = strlen(start);
        if (len > 0 && start[len - 1] == '\n')
            len--;
        if (len >= bufsz)
            len = bufsz - 1;
        memcpy(buf, start, len);
        buf[len] = '\0';
        *pp = start + strlen(start);
    } else {
        size_t len = (size_t)(end - start);
        if (len >= bufsz)
            len = bufsz - 1;
        memcpy(buf, start, len);
        buf[len] = '\0';
        *pp = end + 1;
    }
    return 0;
}

/*
 * Parse a line from /etc/passwd into a passwd_entry.
 * Format: name:x:uid:gid:gecos:home:shell
 * Returns 0 on success.
 */
static int parse_passwd_line(char *line, struct passwd_entry *pw)
{
    char *p = line;
    char tmp[256];

    /* name */
    if (get_field(&p, pw->name, sizeof(pw->name)) < 0)
        return -1;

    /* password placeholder (skip) */
    if (get_field(&p, tmp, sizeof(tmp)) < 0)
        return -1;

    /* uid */
    if (get_field(&p, tmp, sizeof(tmp)) < 0)
        return -1;
    pw->uid = atoi(tmp);

    /* gid */
    if (get_field(&p, tmp, sizeof(tmp)) < 0)
        return -1;
    pw->gid = atoi(tmp);

    /* gecos (can be empty) */
    if (get_field(&p, pw->gecos, sizeof(pw->gecos)) < 0)
        return -1;

    /* home */
    if (get_field(&p, pw->home, sizeof(pw->home)) < 0)
        return -1;

    /* shell */
    if (get_field(&p, pw->shell, sizeof(pw->shell)) < 0)
        return -1;

    return 0;
}

/*
 * Look up a user in /etc/passwd by name.
 * Returns 0 on success, -1 if not found.
 */
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

/*
 * Look up a user's password hash in /etc/shadow.
 * Format: name:hash:lastchanged:min:max:warn:inactive:expire:reserved
 * Writes hash into buf (up to bufsz).  Returns 0 on success.
 */
static int lookup_shadow(const char *username, char *buf, size_t bufsz)
{
    FILE *fp = fopen(PATH_SHADOW, "r");
    if (!fp)
        return -1;

    char line[LINE_MAX];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n')
            continue;

        /* Match "username:" at start of line */
        size_t ulen = strlen(username);
        if (strncmp(line, username, ulen) != 0 || line[ulen] != ':')
            continue;

        /* Extract hash field (second field) */
        char *hash_start = line + ulen + 1;
        char *colon = strchr(hash_start, ':');
        size_t hash_len;
        if (colon)
            hash_len = (size_t)(colon - hash_start);
        else {
            hash_len = strlen(hash_start);
            /* strip trailing newline */
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
/* Terminal helpers                                                    */
/* ------------------------------------------------------------------ */

/*
 * Read a line from stdin with echo disabled (for password entry).
 * The trailing newline is stripped.
 */
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

    fputs(prompt, stdout);
    fflush(stdout);

    if (fgets(buf, (int)bufsz, stdin) == NULL)
        buf[0] = '\0';

    /* Strip trailing newline */
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n')
        buf[len - 1] = '\0';

    if (tty) {
        tcsetattr(STDIN_FILENO, 0, &old);
        putchar('\n');
        fflush(stdout);
    }

    return 0;
}

/*
 * Read a visible line (for username entry).
 */
static int read_line(const char *prompt, char *buf, size_t bufsz)
{
    fputs(prompt, stdout);
    fflush(stdout);

    if (fgets(buf, (int)bufsz, stdin) == NULL)
        return -1;

    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n')
        buf[len - 1] = '\0';

    return 0;
}

/* ------------------------------------------------------------------ */
/* Get hostname for the login prompt                                  */
/* ------------------------------------------------------------------ */

static void get_hostname(char *buf, size_t bufsz)
{
    FILE *fp = fopen("/etc/hostname", "r");
    if (fp) {
        if (fgets(buf, (int)bufsz, fp)) {
            size_t len = strlen(buf);
            if (len > 0 && buf[len - 1] == '\n')
                buf[len - 1] = '\0';
            fclose(fp);
            return;
        }
        fclose(fp);
    }
    strncpy(buf, "kiseki", bufsz - 1);
    buf[bufsz - 1] = '\0';
}

/* ------------------------------------------------------------------ */
/* Usage                                                              */
/* ------------------------------------------------------------------ */

static void usage(void)
{
    fprintf(stderr, "Usage: %s [-f USERNAME] [-p] [-h HOSTNAME]\n", progname);
    fprintf(stderr, "Begin a session on the system.\n\n");
    fprintf(stderr, "  -f USERNAME   skip authentication (trusted caller)\n");
    fprintf(stderr, "  -p            preserve environment\n");
    fprintf(stderr, "  -h HOSTNAME   name of remote host for this login\n");
}

/* ------------------------------------------------------------------ */
/* Main                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    const char *force_user = NULL;
    const char *remote_host = NULL;
    int preserve_env = 0;

    /* Parse options (no getopt) */
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
        if (strcmp(argv[i], "-f") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "%s: -f requires an argument\n", progname);
                return 1;
            }
            force_user = argv[i];
        } else if (strcmp(argv[i], "-p") == 0) {
            preserve_env = 1;
        } else if (strcmp(argv[i], "-h") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "%s: -h requires an argument\n", progname);
                return 1;
            }
            remote_host = argv[i];
        } else {
            fprintf(stderr, "%s: invalid option '%s'\n", progname, argv[i]);
            usage();
            return 1;
        }
    }

    /* If there's a trailing positional argument, treat it as the username */
    const char *preset_user = NULL;
    if (i < argc)
        preset_user = argv[i];

    char hostname[256];
    if (remote_host)
        strncpy(hostname, remote_host, sizeof(hostname) - 1);
    else
        get_hostname(hostname, sizeof(hostname));
    hostname[sizeof(hostname) - 1] = '\0';

    /*
     * Main login loop — up to MAX_ATTEMPTS tries.
     */
    int attempts = 0;
    while (attempts < MAX_ATTEMPTS) {
        char username[256];
        char password[256];
        struct passwd_entry pw;

        /* ---- Get username ---- */
        if (force_user) {
            strncpy(username, force_user, sizeof(username) - 1);
            username[sizeof(username) - 1] = '\0';
        } else if (preset_user && attempts == 0) {
            strncpy(username, preset_user, sizeof(username) - 1);
            username[sizeof(username) - 1] = '\0';
        } else {
            char prompt[512];
            snprintf(prompt, sizeof(prompt), "%s login: ", hostname);
            if (read_line(prompt, username, sizeof(username)) < 0)
                return 1;
            if (username[0] == '\0')
                continue;
        }

        /* ---- Lookup user ---- */
        if (lookup_passwd(username, &pw) < 0) {
            /* Don't reveal whether username exists */
            if (!force_user) {
                read_password("Password: ", password, sizeof(password));
            }
            fprintf(stderr, "\nLogin incorrect\n");
            sleep(FAIL_DELAY);
            attempts++;
            continue;
        }

        /* ---- Authenticate ---- */
        if (!force_user) {
            /* Read the shadow entry */
            char shadow_hash[512];
            int have_shadow = lookup_shadow(username, shadow_hash,
                                            sizeof(shadow_hash));

            /* If shadow lookup failed, check if account has no password */
            if (have_shadow < 0)
                shadow_hash[0] = '\0';     /* treat as empty = no password */

            /* If password field is non-empty, prompt */
            if (shadow_hash[0] != '\0') {
                if (read_password("Password: ", password, sizeof(password)) < 0)
                    return 1;

                if (!verify_password(password, shadow_hash)) {
                    /* Clear password from memory */
                    memset(password, 0, sizeof(password));
                    fprintf(stderr, "\nLogin incorrect\n");
                    sleep(FAIL_DELAY);
                    attempts++;
                    continue;
                }
            }

            /* Clear password from memory */
            memset(password, 0, sizeof(password));
        }

        /* ---- Authentication succeeded ---- */

        /* Set UID */
        if (setuid(pw.uid) < 0) {
            fprintf(stderr, "%s: setuid(%d): %s\n", progname, pw.uid,
                    strerror(errno));
            return 1;
        }

        /* Change to home directory */
        if (chdir(pw.home) < 0) {
            fprintf(stderr, "%s: warning: cannot chdir to %s: %s\n",
                    progname, pw.home, strerror(errno));
            /* Fall back to / */
            if (chdir("/") < 0) {
                fprintf(stderr, "%s: cannot chdir to /: %s\n", progname,
                        strerror(errno));
                return 1;
            }
        }

        /* Set up environment */
        if (!preserve_env) {
            /* We can't clearenv() in freestanding, so just set the basics */
            setenv("HOME", pw.home, 1);
            setenv("USER", pw.name, 1);
            setenv("LOGNAME", pw.name, 1);
            setenv("PATH", DEFAULT_PATH, 1);

            const char *shell = pw.shell[0] ? pw.shell : DEFAULT_SHELL;
            setenv("SHELL", shell, 1);

            /* Remove sensitive variables */
            unsetenv("LD_PRELOAD");
            unsetenv("LD_LIBRARY_PATH");
        }

        /* Determine shell to execute */
        const char *shell = pw.shell[0] ? pw.shell : DEFAULT_SHELL;

        /*
         * Build argv for the shell.  Login shells get "-shellname" as
         * argv[0] (the leading dash tells the shell it's a login shell).
         */
        const char *shell_base = strrchr(shell, '/');
        shell_base = shell_base ? shell_base + 1 : shell;

        char login_arg[256];
        snprintf(login_arg, sizeof(login_arg), "-%s", shell_base);

        char *shell_argv[2];
        shell_argv[0] = login_arg;
        shell_argv[1] = NULL;

        /* Display last-login info (best effort) */
        printf("\nWelcome to %s\n\n", hostname);
        fflush(stdout);

        execv(shell, shell_argv);

        /* exec failed */
        fprintf(stderr, "%s: failed to execute %s: %s\n", progname, shell,
                strerror(errno));
        return 1;
    }

    fprintf(stderr, "%s: maximum login attempts exceeded\n", progname);
    return 1;
}
