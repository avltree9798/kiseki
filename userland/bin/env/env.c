/*
 * env - run a command in a modified environment
 *
 * Kiseki OS coreutils
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

static const char *progname = "env";

extern char **environ;

static void usage(void)
{
    fprintf(stderr, "Usage: %s [-i] [-u NAME]... [NAME=VALUE]... "
            "[COMMAND [ARG]...]\n", progname);
    fprintf(stderr, "Run COMMAND in a modified environment.\n\n");
    fprintf(stderr, "  -i          start with an empty environment\n");
    fprintf(stderr, "  -u NAME     unset variable NAME\n");
    fprintf(stderr, "  --help      display this help and exit\n");
}

/*
 * Print all environment variables to stdout.
 */
static void print_env(void)
{
    if (environ == NULL)
        return;
    for (char **ep = environ; *ep != NULL; ep++)
        printf("%s\n", *ep);
}

/*
 * Clear the environment by setting environ to an empty list.
 * We allocate a minimal environ with just a NULL terminator.
 */
static void clear_env(void)
{
    /*
     * We cannot simply set environ = NULL because some libc functions
     * may dereference it. Instead, point to an empty list.
     */
    static char *empty_env[] = { NULL };
    environ = empty_env;
}

int main(int argc, char *argv[])
{
    int opt_clear = 0;
    int i;

    /* Parse options */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            usage();
            return 0;
        }

        if (strcmp(argv[i], "--") == 0) {
            i++;
            break;
        }

        if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "-") == 0) {
            opt_clear = 1;
            continue;
        }

        if (strcmp(argv[i], "-u") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "%s: option '-u' requires an argument\n",
                        progname);
                return 125;
            }
            i++;
            /* Defer unset until after potential -i */
            continue;
        }

        if (argv[i][0] == '-' && argv[i][1] == 'u' && argv[i][2] != '\0') {
            /* -uNAME form */
            continue;
        }

        if (argv[i][0] == '-' && argv[i][1] != '\0') {
            fprintf(stderr, "%s: invalid option -- '%s'\n", progname,
                    argv[i]);
            usage();
            return 125;
        }

        /* Not an option — break */
        break;
    }

    /* Apply -i first */
    if (opt_clear)
        clear_env();

    /* Now process -u options (second pass) */
    for (int j = 1; j < i && j < argc; j++) {
        if (strcmp(argv[j], "-u") == 0) {
            if (j + 1 < argc) {
                unsetenv(argv[j + 1]);
                j++;
            }
        } else if (argv[j][0] == '-' && argv[j][1] == 'u' &&
                   argv[j][2] != '\0') {
            unsetenv(&argv[j][2]);
        }
    }

    /* Process NAME=VALUE assignments */
    while (i < argc) {
        /* Check if this argument is a NAME=VALUE pair */
        char *eq = strchr(argv[i], '=');
        if (eq == NULL || eq == argv[i])
            break;  /* Not an assignment, must be the command */

        /* Ensure name doesn't contain invalid chars before '=' */
        int valid = 1;
        for (char *p = argv[i]; p < eq; p++) {
            if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                  (*p >= '0' && *p <= '9') || *p == '_')) {
                valid = 0;
                break;
            }
        }
        if (!valid)
            break;

        /* Split into name and value */
        size_t name_len = (size_t)(eq - argv[i]);
        char *name = malloc(name_len + 1);
        if (!name) {
            fprintf(stderr, "%s: out of memory\n", progname);
            return 125;
        }
        memcpy(name, argv[i], name_len);
        name[name_len] = '\0';

        if (setenv(name, eq + 1, 1) != 0) {
            fprintf(stderr, "%s: setenv '%s': %s\n", progname, name,
                    strerror(errno));
            free(name);
            return 125;
        }
        free(name);
        i++;
    }

    /* If no command, print environment */
    if (i >= argc) {
        print_env();
        return 0;
    }

    /* Execute the command */
    execvp(argv[i], &argv[i]);

    /* If we get here, exec failed */
    fprintf(stderr, "%s: '%s': %s\n", progname, argv[i], strerror(errno));
    return (errno == ENOENT) ? 127 : 126;
}
