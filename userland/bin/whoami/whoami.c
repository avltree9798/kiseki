/*
 * whoami - print effective user name
 *
 * Usage: whoami [--help]
 *
 * Calls geteuid(), looks up the name in /etc/passwd, and prints it.
 * If the user is not found, prints the numeric UID.
 *
 * Kiseki OS coreutils
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *progname = "whoami";

static void usage(void)
{
    fprintf(stderr, "Usage: %s\n", progname);
    fprintf(stderr, "Print the user name associated with the current "
                    "effective user ID.\n");
}

/*
 * Look up a UID in /etc/passwd and return the username.
 * Returns 0 on success (name written to buf), -1 if not found.
 *
 * /etc/passwd format: name:x:uid:gid:gecos:home:shell
 */
static int uid_to_name(uid_t uid, char *buf, size_t bufsiz)
{
    FILE *fp = fopen("/etc/passwd", "r");
    if (!fp)
        return -1;

    char line[1024];
    while (fgets(line, (int)sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n')
            continue;

        /* Parse name field */
        char *p = line;
        char *colon = strchr(p, ':');
        if (!colon)
            continue;
        *colon = '\0';
        const char *name = p;

        /* Skip password field */
        p = colon + 1;
        colon = strchr(p, ':');
        if (!colon)
            continue;

        /* Parse uid field */
        p = colon + 1;
        colon = strchr(p, ':');
        if (!colon)
            continue;
        *colon = '\0';

        uid_t entry_uid = (uid_t)atoi(p);
        if (entry_uid == uid) {
            strncpy(buf, name, bufsiz - 1);
            buf[bufsiz - 1] = '\0';
            fclose(fp);
            return 0;
        }
    }

    fclose(fp);
    return -1;
}

int main(int argc, char *argv[])
{
    /* Check for --help */
    if (argc > 1) {
        if (strcmp(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
        /* whoami takes no operands */
        fprintf(stderr, "%s: extra operand '%s'\n", progname, argv[1]);
        usage();
        return 1;
    }

    uid_t euid = geteuid();
    char name[256];

    if (uid_to_name(euid, name, sizeof(name)) == 0) {
        puts(name);
    } else {
        /* Fallback: print numeric UID */
        printf("%u\n", (unsigned)euid);
    }

    return 0;
}
