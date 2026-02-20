/*
 * passwd - change user password
 *
 * Kiseki OS coreutils - Unix/POSIX compatible
 *
 * Usage: passwd [options] [LOGIN]
 *
 * Changes the password for a user account. When called without
 * arguments, changes the password for the current user.
 *
 * Only root can change other users' passwords or use options
 * like -l (lock), -u (unlock), -d (delete password).
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
#define PATH_SHADOW_TMP "/etc/shadow.tmp"

static const char *progname = "passwd";

/* ------------------------------------------------------------------ */
/* Terminal helpers (disable echo for password input)                 */
/* ------------------------------------------------------------------ */

static struct termios orig_termios;
static int termios_saved = 0;

static void disable_echo(void)
{
    struct termios t;
    if (tcgetattr(STDIN_FILENO, &orig_termios) == 0) {
        termios_saved = 1;
        t = orig_termios;
        t.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
        tcsetattr(STDIN_FILENO, TCSANOW, &t);
    }
}

static void restore_echo(void)
{
    if (termios_saved)
        tcsetattr(STDIN_FILENO, TCSANOW, &orig_termios);
}

/* ------------------------------------------------------------------ */
/* Password input                                                     */
/* ------------------------------------------------------------------ */

static int read_password(const char *prompt, char *buf, size_t buflen)
{
    fprintf(stderr, "%s", prompt);
    fflush(stderr);

    disable_echo();

    if (fgets(buf, (int)buflen, stdin) == NULL) {
        restore_echo();
        fprintf(stderr, "\n");
        return -1;
    }

    restore_echo();
    fprintf(stderr, "\n");

    /* Strip newline */
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n')
        buf[len - 1] = '\0';

    return 0;
}

/* ------------------------------------------------------------------ */
/* Simple password hashing (placeholder - real systems use crypt())   */
/*                                                                    */
/* For Kiseki OS, we store passwords in a simple reversible format.   */
/* In production, you'd use crypt() with SHA-512 or bcrypt.           */
/* Format: plain text for now (like early Unix shadow files)          */
/* ------------------------------------------------------------------ */

static void hash_password(const char *plain, char *hash, size_t hashlen)
{
    /* For now, just store the plain password.
     * A real implementation would use crypt(3) with $6$ (SHA-512) */
    strncpy(hash, plain, hashlen - 1);
    hash[hashlen - 1] = '\0';
}

static int verify_password(const char *plain, const char *stored)
{
    /* If stored password is empty or *, it's locked/no password */
    if (!stored || !*stored || strcmp(stored, "*") == 0 ||
        strcmp(stored, "!") == 0 || stored[0] == '!')
        return 0;

    /* Simple comparison for now */
    return strcmp(plain, stored) == 0;
}

/* ------------------------------------------------------------------ */
/* Shadow file helpers                                                */
/* ------------------------------------------------------------------ */

static int user_exists(const char *username)
{
    FILE *fp = fopen(PATH_PASSWD, "r");
    if (!fp)
        return 0;

    char line[LINE_MAX];
    size_t ulen = strlen(username);
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, username, ulen) == 0 && line[ulen] == ':') {
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

static int get_current_password(const char *username, char *buf, size_t buflen)
{
    FILE *fp = fopen(PATH_SHADOW, "r");
    if (!fp) {
        buf[0] = '\0';
        return -1;
    }

    char line[LINE_MAX];
    size_t ulen = strlen(username);

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, username, ulen) == 0 && line[ulen] == ':') {
            /* Extract password field (second field) */
            char *p = line + ulen + 1;
            char *end = strchr(p, ':');
            if (end) {
                size_t plen = (size_t)(end - p);
                if (plen >= buflen)
                    plen = buflen - 1;
                strncpy(buf, p, plen);
                buf[plen] = '\0';
            } else {
                buf[0] = '\0';
            }
            fclose(fp);
            return 0;
        }
    }

    fclose(fp);
    buf[0] = '\0';
    return -1;
}

static int update_shadow_password(const char *username, const char *newhash)
{
    FILE *fp = fopen(PATH_SHADOW, "r");
    if (!fp) {
        fprintf(stderr, "%s: cannot open %s: %s\n", progname, PATH_SHADOW,
                strerror(errno));
        return -1;
    }

    FILE *tmp = fopen(PATH_SHADOW_TMP, "w");
    if (!tmp) {
        fprintf(stderr, "%s: cannot create %s: %s\n", progname, PATH_SHADOW_TMP,
                strerror(errno));
        fclose(fp);
        return -1;
    }

    char line[LINE_MAX];
    size_t ulen = strlen(username);
    int found = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, username, ulen) == 0 && line[ulen] == ':') {
            /* Found the user - replace password field */
            found = 1;

            /* Parse existing fields after password */
            char *p = line + ulen + 1;  /* Skip username: */
            char *colon = strchr(p, ':');
            if (colon) {
                /* Write: username:newhash:rest_of_line */
                fprintf(tmp, "%s:%s%s", username, newhash, colon);
            } else {
                /* Malformed line - write new entry */
                fprintf(tmp, "%s:%s:0:0:99999:7:::\n", username, newhash);
            }
        } else {
            /* Copy line unchanged */
            fputs(line, tmp);
        }
    }

    /* If user wasn't in shadow, add them */
    if (!found) {
        fprintf(tmp, "%s:%s:0:0:99999:7:::\n", username, newhash);
    }

    fclose(fp);
    fclose(tmp);

    /* Replace shadow with tmp */
    if (rename(PATH_SHADOW_TMP, PATH_SHADOW) < 0) {
        fprintf(stderr, "%s: cannot update %s: %s\n", progname, PATH_SHADOW,
                strerror(errno));
        unlink(PATH_SHADOW_TMP);
        return -1;
    }

    /* Restore permissions */
    chmod(PATH_SHADOW, 0600);

    return 0;
}

/* ------------------------------------------------------------------ */
/* Password change logic                                              */
/* ------------------------------------------------------------------ */

static int change_password(const char *username, int is_root)
{
    char current_hash[256];
    char old_pw[256];
    char new_pw[256];
    char confirm_pw[256];
    char new_hash[256];

    /* Get current password hash */
    get_current_password(username, current_hash, sizeof(current_hash));

    /* Non-root users must provide current password */
    if (!is_root && current_hash[0] != '\0' &&
        strcmp(current_hash, "*") != 0 && strcmp(current_hash, "!") != 0) {
        if (read_password("Current password: ", old_pw, sizeof(old_pw)) < 0)
            return 1;

        if (!verify_password(old_pw, current_hash)) {
            fprintf(stderr, "%s: Authentication failure\n", progname);
            return 1;
        }
    }

    /* Read new password */
    if (read_password("New password: ", new_pw, sizeof(new_pw)) < 0)
        return 1;

    if (strlen(new_pw) == 0) {
        fprintf(stderr, "%s: No password supplied\n", progname);
        return 1;
    }

    /* Confirm new password */
    if (read_password("Retype new password: ", confirm_pw, sizeof(confirm_pw)) < 0)
        return 1;

    if (strcmp(new_pw, confirm_pw) != 0) {
        fprintf(stderr, "%s: Sorry, passwords do not match.\n", progname);
        return 1;
    }

    /* Basic password quality checks */
    if (strlen(new_pw) < 4) {
        fprintf(stderr, "%s: Password is too short\n", progname);
        return 1;
    }

    /* Hash the new password */
    hash_password(new_pw, new_hash, sizeof(new_hash));

    /* Update shadow file */
    if (update_shadow_password(username, new_hash) < 0)
        return 1;

    fprintf(stderr, "%s: password updated successfully\n", progname);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Lock/unlock/delete password (root only)                            */
/* ------------------------------------------------------------------ */

static int lock_password(const char *username)
{
    char current[256];
    char locked[260];

    get_current_password(username, current, sizeof(current));

    /* Already locked? */
    if (current[0] == '!') {
        fprintf(stderr, "%s: password is already locked\n", progname);
        return 0;
    }

    snprintf(locked, sizeof(locked), "!%s", current);
    if (update_shadow_password(username, locked) < 0)
        return 1;

    fprintf(stderr, "%s: password locked for %s\n", progname, username);
    return 0;
}

static int unlock_password(const char *username)
{
    char current[256];

    get_current_password(username, current, sizeof(current));

    /* Not locked? */
    if (current[0] != '!') {
        fprintf(stderr, "%s: password is not locked\n", progname);
        return 1;
    }

    /* Remove the '!' prefix */
    if (update_shadow_password(username, current + 1) < 0)
        return 1;

    fprintf(stderr, "%s: password unlocked for %s\n", progname, username);
    return 0;
}

static int delete_password(const char *username)
{
    if (update_shadow_password(username, "") < 0)
        return 1;

    fprintf(stderr, "%s: password deleted for %s\n", progname, username);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Status display                                                     */
/* ------------------------------------------------------------------ */

static int show_status(const char *username)
{
    char current[256];

    if (!user_exists(username)) {
        fprintf(stderr, "%s: user '%s' does not exist\n", progname, username);
        return 1;
    }

    get_current_password(username, current, sizeof(current));

    printf("%s ", username);

    if (current[0] == '\0' || strcmp(current, "*") == 0) {
        printf("NP ");  /* No password */
    } else if (current[0] == '!') {
        printf("L ");   /* Locked */
    } else {
        printf("P ");   /* Password set */
    }

    /* Additional fields would show password age info */
    printf("\n");

    return 0;
}

/* ------------------------------------------------------------------ */
/* Usage                                                              */
/* ------------------------------------------------------------------ */

static void usage(void)
{
    fprintf(stderr, "Usage: %s [options] [LOGIN]\n\n", progname);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -d, --delete      delete the password (make it empty)\n");
    fprintf(stderr, "  -l, --lock        lock the password\n");
    fprintf(stderr, "  -u, --unlock      unlock the password\n");
    fprintf(stderr, "  -S, --status      report password status\n");
    fprintf(stderr, "  -h, --help        display this help\n");
}

/* ------------------------------------------------------------------ */
/* Main                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    int opt_lock = 0;
    int opt_unlock = 0;
    int opt_delete = 0;
    int opt_status = 0;
    const char *username = NULL;

    uid_t uid = getuid();
    uid_t euid = geteuid();
    int is_root = (uid == 0 || euid == 0);

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
        if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--lock") == 0) {
            opt_lock = 1;
        } else if (strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--unlock") == 0) {
            opt_unlock = 1;
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--delete") == 0) {
            opt_delete = 1;
        } else if (strcmp(argv[i], "-S") == 0 || strcmp(argv[i], "--status") == 0) {
            opt_status = 1;
        } else {
            fprintf(stderr, "%s: invalid option -- '%s'\n", progname, argv[i]);
            usage();
            return 1;
        }
    }

    /* Get username (from argument or current user) */
    if (i < argc) {
        username = argv[i];
    } else {
        /* Get current user from environment or passwd file */
        username = getenv("USER");
        if (!username || !*username) {
            /* Try to find username by UID */
            FILE *fp = fopen(PATH_PASSWD, "r");
            if (fp) {
                char line[LINE_MAX];
                static char found_user[64];
                while (fgets(line, sizeof(line), fp)) {
                    char *saveptr = NULL;
                    char *u = strtok_r(line, ":", &saveptr);
                    strtok_r(NULL, ":", &saveptr);  /* skip x */
                    char *uid_str = strtok_r(NULL, ":", &saveptr);
                    if (u && uid_str && atoi(uid_str) == (int)uid) {
                        strncpy(found_user, u, sizeof(found_user) - 1);
                        found_user[sizeof(found_user) - 1] = '\0';
                        username = found_user;
                        break;
                    }
                }
                fclose(fp);
            }
        }
        if (!username || !*username) {
            fprintf(stderr, "%s: Cannot determine your user name.\n", progname);
            return 1;
        }
    }

    /* Check if user exists */
    if (!user_exists(username)) {
        fprintf(stderr, "%s: user '%s' does not exist\n", progname, username);
        return 1;
    }

    /* Root-only operations */
    if ((opt_lock || opt_unlock || opt_delete) && !is_root) {
        fprintf(stderr, "%s: Permission denied.\n", progname);
        return 1;
    }

    /* Non-root users can only change their own password */
    if (!is_root && i < argc) {
        /* User specified a username - check it's their own */
        char *current_user = getenv("USER");
        if (!current_user || strcmp(current_user, username) != 0) {
            fprintf(stderr, "%s: Permission denied.\n", progname);
            return 1;
        }
    }

    /* Execute requested operation */
    if (opt_status) {
        return show_status(username);
    }
    if (opt_lock) {
        return lock_password(username);
    }
    if (opt_unlock) {
        return unlock_password(username);
    }
    if (opt_delete) {
        return delete_password(username);
    }

    /* Default: change password */
    return change_password(username, is_root);
}
