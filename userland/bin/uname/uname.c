/*
 * uname - print system information
 *
 * Usage: uname [OPTION]...
 *
 * Flags:
 *   -s    kernel name (default if no flags)
 *   -n    network node hostname
 *   -r    kernel release
 *   -v    kernel version
 *   -m    machine hardware name
 *   -a    all of the above
 *
 * Kiseki OS coreutils
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

static const char *progname = "uname";

/* Hardcoded system information */
#define KERNEL_NAME     "Kiseki"
#define KERNEL_RELEASE  "0.1.0"
#define KERNEL_VERSION  "#1 SMP"
#define MACHINE         "aarch64"

static void usage(void)
{
    fprintf(stderr, "Usage: %s [OPTION]...\n", progname);
    fprintf(stderr, "Print certain system information.\n\n");
    fprintf(stderr, "  -s    print the kernel name\n");
    fprintf(stderr, "  -n    print the network node hostname\n");
    fprintf(stderr, "  -r    print the kernel release\n");
    fprintf(stderr, "  -v    print the kernel version\n");
    fprintf(stderr, "  -m    print the machine hardware name\n");
    fprintf(stderr, "  -a    print all information\n");
    fprintf(stderr, "  --help display this help and exit\n");
}

/*
 * Read the hostname from /etc/hostname.
 * Returns the hostname string (statically allocated), or "unknown" on error.
 */
static const char *get_hostname(void)
{
    static char hostname[256];
    FILE *fp = fopen("/etc/hostname", "r");
    if (!fp) {
        strcpy(hostname, "unknown");
        return hostname;
    }

    if (fgets(hostname, (int)sizeof(hostname), fp) == NULL) {
        strcpy(hostname, "unknown");
        fclose(fp);
        return hostname;
    }
    fclose(fp);

    /* Strip trailing newline/whitespace */
    size_t len = strlen(hostname);
    while (len > 0 && (hostname[len - 1] == '\n' ||
                       hostname[len - 1] == '\r' ||
                       hostname[len - 1] == ' '  ||
                       hostname[len - 1] == '\t'))
        hostname[--len] = '\0';

    if (hostname[0] == '\0')
        strcpy(hostname, "unknown");

    return hostname;
}

int main(int argc, char *argv[])
{
    int opt_s = 0, opt_n = 0, opt_r = 0, opt_v = 0, opt_m = 0;

    /* Parse options */
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-' && argv[i][1] != '\0') {
            if (strcmp(argv[i], "--help") == 0) {
                usage();
                return 0;
            }
            if (strcmp(argv[i], "--") == 0)
                break;
            /* Parse bundled flags */
            const char *p = &argv[i][1];
            while (*p) {
                switch (*p) {
                case 's': opt_s = 1; break;
                case 'n': opt_n = 1; break;
                case 'r': opt_r = 1; break;
                case 'v': opt_v = 1; break;
                case 'm': opt_m = 1; break;
                case 'a':
                    opt_s = opt_n = opt_r = opt_v = opt_m = 1;
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
            fprintf(stderr, "%s: extra operand '%s'\n", progname, argv[i]);
            usage();
            return 1;
        }
    }

    /* Default: print kernel name only */
    if (!opt_s && !opt_n && !opt_r && !opt_v && !opt_m)
        opt_s = 1;

    int first = 1;

    if (opt_s) {
        if (!first) putchar(' ');
        fputs(KERNEL_NAME, stdout);
        first = 0;
    }
    if (opt_n) {
        if (!first) putchar(' ');
        fputs(get_hostname(), stdout);
        first = 0;
    }
    if (opt_r) {
        if (!first) putchar(' ');
        fputs(KERNEL_RELEASE, stdout);
        first = 0;
    }
    if (opt_v) {
        if (!first) putchar(' ');
        fputs(KERNEL_VERSION, stdout);
        first = 0;
    }
    if (opt_m) {
        if (!first) putchar(' ');
        fputs(MACHINE, stdout);
        first = 0;
    }

    putchar('\n');
    return 0;
}
