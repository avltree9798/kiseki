/*
 * mkdir - make directories
 *
 * Kiseki OS coreutils
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>

static const char *progname = "mkdir";

static int    opt_parents = 0;
static int    opt_verbose = 0;
static mode_t opt_mode    = 0777;
static int    opt_mode_set = 0;

static void usage(void)
{
    fprintf(stderr, "Usage: %s [OPTION]... DIRECTORY...\n", progname);
    fprintf(stderr, "Create the DIRECTORY(ies), if they do not already exist.\n\n");
    fprintf(stderr, "  -p         no error if existing, make parent directories as needed\n");
    fprintf(stderr, "  -m MODE    set file mode (as octal)\n");
    fprintf(stderr, "  -v         print a message for each created directory\n");
    fprintf(stderr, "  --help     display this help and exit\n");
}

/*
 * Parse an octal mode string. Returns -1 on error.
 */
static int parse_mode(const char *s, mode_t *out)
{
    char *end;
    unsigned long val = strtoul(s, &end, 8);
    if (*end != '\0' || val > 07777)
        return -1;
    *out = (mode_t)val;
    return 0;
}

/*
 * Create a single directory, reporting errors.
 */
static int make_one(const char *path, mode_t mode)
{
    if (mkdir(path, mode) < 0) {
        if (errno == EEXIST && opt_parents) {
            /* Check it's actually a directory */
            struct stat st;
            if (stat(path, &st) == 0 && S_ISDIR(st.st_mode))
                return 0;
        }
        fprintf(stderr, "%s: cannot create directory '%s': %s\n",
                progname, path, strerror(errno));
        return 1;
    }
    if (opt_verbose)
        printf("%s: created directory '%s'\n", progname, path);
    return 0;
}

/*
 * Create directory with parent directories as needed (-p).
 */
static int make_parents(const char *path, mode_t mode)
{
    /* Work on a mutable copy */
    char *buf = strdup(path);
    if (!buf) {
        fprintf(stderr, "%s: out of memory\n", progname);
        return 1;
    }

    int ret = 0;
    char *p = buf;

    /* Skip leading slash */
    if (*p == '/')
        p++;

    while (*p) {
        /* Find next slash */
        char *slash = strchr(p, '/');
        if (slash)
            *slash = '\0';

        /* Create intermediate directory with permissive mode */
        struct stat st;
        if (stat(buf, &st) < 0) {
            /*
             * Intermediate directories get 0777 (modified by umask) to
             * ensure we can create children. The final directory gets
             * the requested mode.
             */
            mode_t dir_mode = (slash != NULL) ? (mode_t)0777 : mode;
            if (mkdir(buf, dir_mode) < 0 && errno != EEXIST) {
                fprintf(stderr, "%s: cannot create directory '%s': %s\n",
                        progname, buf, strerror(errno));
                ret = 1;
                goto done;
            }
            if (opt_verbose)
                printf("%s: created directory '%s'\n", progname, buf);
        } else if (!S_ISDIR(st.st_mode)) {
            fprintf(stderr, "%s: '%s' exists but is not a directory\n",
                    progname, buf);
            ret = 1;
            goto done;
        }

        if (slash) {
            *slash = '/';
            p = slash + 1;
        } else {
            break;
        }
    }

done:
    free(buf);
    return ret;
}

int main(int argc, char *argv[])
{
    int first_arg = argc;

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
                case 'p': opt_parents = 1; break;
                case 'v': opt_verbose = 1; break;
                case 'm':
                    opt_mode_set = 1;
                    /* Mode argument: rest of this token or next argv */
                    if (*(p + 1) != '\0') {
                        if (parse_mode(p + 1, &opt_mode) < 0) {
                            fprintf(stderr, "%s: invalid mode '%s'\n",
                                    progname, p + 1);
                            return 1;
                        }
                        goto next_argv;
                    } else if (i + 1 < argc) {
                        i++;
                        if (parse_mode(argv[i], &opt_mode) < 0) {
                            fprintf(stderr, "%s: invalid mode '%s'\n",
                                    progname, argv[i]);
                            return 1;
                        }
                        goto next_argv;
                    } else {
                        fprintf(stderr, "%s: option -m requires an argument\n",
                                progname);
                        return 1;
                    }
                    break;
                default:
                    fprintf(stderr, "%s: invalid option -- '%c'\n",
                            progname, *p);
                    usage();
                    return 1;
                }
                p++;
            }
next_argv:
            ;
        } else {
            first_arg = i;
            break;
        }
    }

    (void)opt_mode_set;

    if (first_arg >= argc) {
        fprintf(stderr, "%s: missing operand\n", progname);
        usage();
        return 1;
    }

    int ret = 0;
    for (int i = first_arg; i < argc; i++) {
        if (opt_parents) {
            if (make_parents(argv[i], opt_mode) != 0)
                ret = 1;
        } else {
            if (make_one(argv[i], opt_mode) != 0)
                ret = 1;
        }
    }

    return ret;
}
