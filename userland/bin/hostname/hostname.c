/*
 * hostname - show or set the system hostname
 *
 * Usage: hostname [-f | -s] [NAME]
 *
 * With no arguments, prints the current hostname (from /etc/hostname).
 * With an argument, sets the hostname (writes to /etc/hostname; requires root).
 *
 * Flags:
 *   -f, --fqdn   print the FQDN (currently just prints the hostname)
 *   -s, --short   print the short hostname (strip after first '.')
 *   --help        display help and exit
 *
 * Kiseki OS coreutils
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

static const char *progname = "hostname";

static void usage(void)
{
    fprintf(stderr, "Usage: %s [-f | -s] [NAME]\n", progname);
    fprintf(stderr, "Show or set the system hostname.\n\n");
    fprintf(stderr, "  -f, --fqdn   display the FQDN\n");
    fprintf(stderr, "  -s, --short  display the short hostname\n");
    fprintf(stderr, "  --help       display this help and exit\n");
}

/*
 * Read hostname from /etc/hostname into buf.
 * Returns 0 on success, -1 on error.
 */
static int read_hostname(char *buf, size_t bufsiz)
{
    FILE *fp = fopen("/etc/hostname", "r");
    if (!fp) {
        fprintf(stderr, "%s: cannot open /etc/hostname: %s\n",
                progname, strerror(errno));
        return -1;
    }

    if (fgets(buf, (int)bufsiz, fp) == NULL) {
        if (ferror(fp)) {
            fprintf(stderr, "%s: error reading /etc/hostname: %s\n",
                    progname, strerror(errno));
            fclose(fp);
            return -1;
        }
        /* Empty file */
        buf[0] = '\0';
    }
    fclose(fp);

    /* Strip trailing whitespace */
    size_t len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r' ||
                       buf[len - 1] == ' '  || buf[len - 1] == '\t'))
        buf[--len] = '\0';

    return 0;
}

/*
 * Write hostname to /etc/hostname.
 * Returns 0 on success, -1 on error.
 */
static int write_hostname(const char *name)
{
    int fd = open("/etc/hostname", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        fprintf(stderr, "%s: cannot open /etc/hostname for writing: %s\n",
                progname, strerror(errno));
        return -1;
    }

    size_t len = strlen(name);
    ssize_t w = write(fd, name, len);
    if (w < 0 || (size_t)w != len) {
        fprintf(stderr, "%s: error writing /etc/hostname: %s\n",
                progname, strerror(errno));
        close(fd);
        return -1;
    }

    /* Write trailing newline */
    w = write(fd, "\n", 1);
    if (w < 0) {
        fprintf(stderr, "%s: error writing /etc/hostname: %s\n",
                progname, strerror(errno));
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

int main(int argc, char *argv[])
{
    int opt_fqdn = 0;
    int opt_short = 0;
    const char *new_hostname = NULL;

    /* Parse options */
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-' && argv[i][1] != '\0') {
            if (strcmp(argv[i], "--help") == 0) {
                usage();
                return 0;
            }
            if (strcmp(argv[i], "--fqdn") == 0 ||
                strcmp(argv[i], "--long") == 0) {
                opt_fqdn = 1;
                continue;
            }
            if (strcmp(argv[i], "--short") == 0) {
                opt_short = 1;
                continue;
            }
            if (strcmp(argv[i], "--") == 0) {
                if (i + 1 < argc)
                    new_hostname = argv[i + 1];
                break;
            }
            /* Parse single-character flags */
            const char *p = &argv[i][1];
            while (*p) {
                switch (*p) {
                case 'f':
                    opt_fqdn = 1;
                    break;
                case 's':
                    opt_short = 1;
                    break;
                default:
                    fprintf(stderr, "%s: invalid option -- '%c'\n",
                            progname, *p);
                    usage();
                    return 1;
                }
                p++;
            }
        } else {
            new_hostname = argv[i];
        }
    }

    /* Setting hostname */
    if (new_hostname) {
        if (opt_fqdn || opt_short) {
            fprintf(stderr, "%s: cannot use -f or -s when setting hostname\n",
                    progname);
            return 1;
        }
        if (strlen(new_hostname) == 0) {
            fprintf(stderr, "%s: hostname cannot be empty\n", progname);
            return 1;
        }
        if (write_hostname(new_hostname) != 0)
            return 1;
        return 0;
    }

    /* Getting hostname */
    char hostname[256];
    if (read_hostname(hostname, sizeof(hostname)) != 0)
        return 1;

    if (hostname[0] == '\0') {
        /* No hostname configured */
        strcpy(hostname, "localhost");
    }

    if (opt_short) {
        /* Truncate at first '.' */
        char *dot = strchr(hostname, '.');
        if (dot)
            *dot = '\0';
    }
    /* opt_fqdn: for now, just print whatever we have (no DNS lookup) */

    puts(hostname);
    return 0;
}
