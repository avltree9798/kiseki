/*
 * xargs - build and execute command lines from standard input
 *
 * Kiseki OS coreutils
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>

static const char *progname = "xargs";

/* Limits */
#define ARG_MAX         131072  /* Max total argument length */
#define MAX_ARGS        4096    /* Max number of arguments */
#define INPUT_BUFSZ     65536   /* Input buffer size */

/* Options */
static int opt_max_args = 0;       /* -n: max args per invocation (0=unlimited) */
static char opt_delim = '\n';      /* -d: input delimiter */
static int opt_null = 0;           /* -0: null-delimited input */
static const char *opt_replace = NULL;  /* -I: replace string */
static int opt_trace = 0;          /* -t: trace commands */
static int opt_prompt = 0;         /* -p: prompt before exec */
static int opt_no_run_empty = 0;   /* -r: no run if empty */

static void usage(void)
{
    fprintf(stderr, "Usage: %s [OPTIONS] [COMMAND [INITIAL-ARGS]]\n", progname);
    fprintf(stderr, "Build and execute command lines from standard input.\n\n");
    fprintf(stderr, "  -0        input items are null-terminated\n");
    fprintf(stderr, "  -d DELIM  input delimiter character\n");
    fprintf(stderr, "  -n NUM    max arguments per command line\n");
    fprintf(stderr, "  -I STR    replace STR in command with input item\n");
    fprintf(stderr, "  -t        print command before executing\n");
    fprintf(stderr, "  -p        prompt before each execution\n");
    fprintf(stderr, "  -r        do not run command if input is empty\n");
    fprintf(stderr, "  -P NUM    max parallel processes (ignored, always 1)\n");
    fprintf(stderr, "  --help    display this help and exit\n");
}

/*
 * Execute a command with the given arguments.
 * Returns the exit status, or 255 on exec failure.
 */
static int run_command(char *const *argv)
{
    if (opt_trace || opt_prompt) {
        /* Print the command to stderr */
        for (int i = 0; argv[i] != NULL; i++) {
            if (i > 0)
                fputc(' ', stderr);
            fputs(argv[i], stderr);
        }
        if (opt_prompt) {
            fprintf(stderr, " ?...");
            fflush(stderr);
            /* Read response from /dev/tty */
            char resp[16];
            int tty_fd = open("/dev/tty", O_RDONLY);
            if (tty_fd < 0) {
                /* Can't open tty, skip */
                fputc('\n', stderr);
                return 0;
            }
            ssize_t n = read(tty_fd, resp, sizeof(resp) - 1);
            close(tty_fd);
            if (n <= 0) {
                fputc('\n', stderr);
                return 0;
            }
            resp[n] = '\0';
            if (resp[0] != 'y' && resp[0] != 'Y')
                return 0;
        } else {
            fputc('\n', stderr);
        }
    }

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "%s: fork: %s\n", progname, strerror(errno));
        return 255;
    }

    if (pid == 0) {
        /* Child */
        execvp(argv[0], argv);
        fprintf(stderr, "%s: %s: %s\n", progname, argv[0], strerror(errno));
        _exit((errno == ENOENT) ? 127 : 126);
    }

    /* Parent: wait for child */
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        fprintf(stderr, "%s: waitpid: %s\n", progname, strerror(errno));
        return 255;
    }

    if (WIFEXITED(status))
        return WEXITSTATUS(status);

    return 255;
}

/*
 * Read the next input item from stdin.
 * Handles quoting (single and double quotes) and backslash escaping
 * when not in null-delimited mode.
 *
 * Returns a malloc'd string, or NULL on EOF/error.
 * Sets *eof to 1 when there's no more input.
 */
static char *read_item(int *eof)
{
    char delim = opt_null ? '\0' : opt_delim;
    char *buf = malloc(INPUT_BUFSZ);
    if (!buf)
        return NULL;

    size_t len = 0;
    int c;
    int in_single_quote = 0;
    int in_double_quote = 0;

    if (opt_null || opt_delim != '\n') {
        /*
         * Simple delimiter-based reading: read until we see the delimiter
         * or EOF. No quote processing.
         */
        while ((c = fgetc(stdin)) != EOF) {
            if ((char)c == delim)
                break;
            if (len + 1 < INPUT_BUFSZ)
                buf[len++] = (char)c;
        }
        if (c == EOF && len == 0) {
            free(buf);
            *eof = 1;
            return NULL;
        }
        buf[len] = '\0';
        return buf;
    }

    /*
     * Default (newline/whitespace delimited) mode with quote handling.
     * Items are separated by whitespace. Quoted strings preserve spaces.
     */

    /* Skip leading whitespace */
    while ((c = fgetc(stdin)) != EOF) {
        if (c != ' ' && c != '\t' && c != '\n')
            break;
    }
    if (c == EOF) {
        free(buf);
        *eof = 1;
        return NULL;
    }

    /* Process characters */
    while (c != EOF) {
        if (!in_single_quote && !in_double_quote) {
            if (c == ' ' || c == '\t' || c == '\n')
                break;  /* End of item */
            if (c == '\\') {
                /* Escape next character */
                c = fgetc(stdin);
                if (c == EOF)
                    break;
                if (len + 1 < INPUT_BUFSZ)
                    buf[len++] = (char)c;
            } else if (c == '\'') {
                in_single_quote = 1;
            } else if (c == '"') {
                in_double_quote = 1;
            } else {
                if (len + 1 < INPUT_BUFSZ)
                    buf[len++] = (char)c;
            }
        } else if (in_single_quote) {
            if (c == '\'')
                in_single_quote = 0;
            else if (len + 1 < INPUT_BUFSZ)
                buf[len++] = (char)c;
        } else if (in_double_quote) {
            if (c == '"') {
                in_double_quote = 0;
            } else if (c == '\\') {
                c = fgetc(stdin);
                if (c == EOF)
                    break;
                if (len + 1 < INPUT_BUFSZ)
                    buf[len++] = (char)c;
            } else {
                if (len + 1 < INPUT_BUFSZ)
                    buf[len++] = (char)c;
            }
        }
        c = fgetc(stdin);
    }

    if (len == 0 && c == EOF) {
        free(buf);
        *eof = 1;
        return NULL;
    }

    buf[len] = '\0';
    return buf;
}

/*
 * Execute command with -I replacement mode.
 * For each input item, replace all occurrences of opt_replace in the
 * template args with the input item, then execute.
 */
static int run_replace_mode(int cmd_argc, char **cmd_argv)
{
    int ret = 0;
    int input_eof = 0;

    while (!input_eof) {
        char *item = read_item(&input_eof);
        if (item == NULL)
            break;

        /* Build argument list with replacements */
        char **new_argv = malloc((size_t)(cmd_argc + 1) * sizeof(char *));
        if (!new_argv) {
            fprintf(stderr, "%s: out of memory\n", progname);
            free(item);
            return 1;
        }

        for (int i = 0; i < cmd_argc; i++) {
            /* Check if this arg contains the replace string */
            char *pos = strstr(cmd_argv[i], opt_replace);
            if (pos == NULL) {
                new_argv[i] = strdup(cmd_argv[i]);
            } else {
                /* Replace all occurrences */
                size_t rlen = strlen(opt_replace);
                size_t ilen = strlen(item);
                size_t alen = strlen(cmd_argv[i]);
                /* Count occurrences for sizing */
                int count = 0;
                const char *scan = cmd_argv[i];
                while ((scan = strstr(scan, opt_replace)) != NULL) {
                    count++;
                    scan += rlen;
                }
                size_t newlen = alen + (size_t)count * (ilen - rlen);
                char *newarg = malloc(newlen + 1);
                if (!newarg) {
                    fprintf(stderr, "%s: out of memory\n", progname);
                    for (int j = 0; j < i; j++)
                        free(new_argv[j]);
                    free(new_argv);
                    free(item);
                    return 1;
                }

                char *dst = newarg;
                const char *src = cmd_argv[i];
                while ((pos = strstr(src, opt_replace)) != NULL) {
                    size_t prefix_len = (size_t)(pos - src);
                    memcpy(dst, src, prefix_len);
                    dst += prefix_len;
                    memcpy(dst, item, ilen);
                    dst += ilen;
                    src = pos + rlen;
                }
                strcpy(dst, src);
                new_argv[i] = newarg;
            }

            if (new_argv[i] == NULL) {
                fprintf(stderr, "%s: out of memory\n", progname);
                for (int j = 0; j < i; j++)
                    free(new_argv[j]);
                free(new_argv);
                free(item);
                return 1;
            }
        }
        new_argv[cmd_argc] = NULL;

        int r = run_command(new_argv);
        if (r == 255)
            ret = 1;
        else if (r != 0)
            ret = 123;

        for (int i = 0; i < cmd_argc; i++)
            free(new_argv[i]);
        free(new_argv);
        free(item);
    }

    return ret;
}

int main(int argc, char *argv[])
{
    int cmd_start = -1;  /* Index of first command argument */

    /* Parse options */
    int i;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            usage();
            return 0;
        }

        if (strcmp(argv[i], "--") == 0) {
            i++;
            break;
        }

        if (argv[i][0] != '-')
            break;

        if (strcmp(argv[i], "-0") == 0) {
            opt_null = 1;
            continue;
        }

        if (strcmp(argv[i], "-t") == 0) {
            opt_trace = 1;
            continue;
        }

        if (strcmp(argv[i], "-p") == 0) {
            opt_prompt = 1;
            opt_trace = 1;  /* -p implies -t */
            continue;
        }

        if (strcmp(argv[i], "-r") == 0) {
            opt_no_run_empty = 1;
            continue;
        }

        if (strcmp(argv[i], "-n") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "%s: option '-n' requires an argument\n",
                        progname);
                return 1;
            }
            opt_max_args = atoi(argv[++i]);
            if (opt_max_args <= 0) {
                fprintf(stderr, "%s: invalid number for -n: '%s'\n",
                        progname, argv[i]);
                return 1;
            }
            continue;
        }

        if (strcmp(argv[i], "-d") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "%s: option '-d' requires an argument\n",
                        progname);
                return 1;
            }
            i++;
            if (strcmp(argv[i], "\\n") == 0) {
                opt_delim = '\n';
            } else if (strcmp(argv[i], "\\t") == 0) {
                opt_delim = '\t';
            } else if (strcmp(argv[i], "\\0") == 0) {
                opt_delim = '\0';
                opt_null = 1;
            } else if (argv[i][0] != '\0') {
                opt_delim = argv[i][0];
            }
            continue;
        }

        if (strcmp(argv[i], "-I") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "%s: option '-I' requires an argument\n",
                        progname);
                return 1;
            }
            opt_replace = argv[++i];
            if (opt_max_args == 0)
                opt_max_args = 1;  /* -I implies -n 1 */
            continue;
        }

        if (strcmp(argv[i], "-P") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "%s: option '-P' requires an argument\n",
                        progname);
                return 1;
            }
            i++;  /* Accept but ignore (always 1) */
            continue;
        }

        fprintf(stderr, "%s: invalid option '%s'\n", progname, argv[i]);
        usage();
        return 1;
    }

    cmd_start = i;

    /* Default command is /bin/echo */
    char *default_cmd[] = { "echo", NULL };
    char **cmd_argv;
    int cmd_argc;

    if (cmd_start >= argc) {
        cmd_argv = default_cmd;
        cmd_argc = 1;
    } else {
        cmd_argv = &argv[cmd_start];
        cmd_argc = argc - cmd_start;
    }

    /* Replace mode: handle separately */
    if (opt_replace != NULL)
        return run_replace_mode(cmd_argc, cmd_argv);

    /*
     * Normal mode: collect items and batch into command invocations.
     */
    char **exec_argv = malloc((size_t)(cmd_argc + MAX_ARGS + 1) * sizeof(char *));
    if (!exec_argv) {
        fprintf(stderr, "%s: out of memory\n", progname);
        return 1;
    }

    /* Items collected from stdin */
    char **items = malloc(MAX_ARGS * sizeof(char *));
    if (!items) {
        fprintf(stderr, "%s: out of memory\n", progname);
        free(exec_argv);
        return 1;
    }

    int ret = 0;
    int input_eof = 0;
    int total_items = 0;

    while (!input_eof) {
        /* Collect items up to max_args */
        int n_items = 0;
        size_t total_len = 0;

        /* Add base command length */
        for (int j = 0; j < cmd_argc; j++)
            total_len += strlen(cmd_argv[j]) + 1;

        while (!input_eof) {
            if (opt_max_args > 0 && n_items >= opt_max_args)
                break;

            char *item = read_item(&input_eof);
            if (item == NULL)
                break;

            size_t item_len = strlen(item) + 1;
            if (total_len + item_len > ARG_MAX && n_items > 0) {
                /* Would exceed limit, save for next batch */
                /* Push back — we can't really push back, so we just
                 * include it if it's the first item */
                /* Actually, just include this and break */
                items[n_items++] = item;
                total_items++;
                break;
            }

            items[n_items++] = item;
            total_items++;
            total_len += item_len;
        }

        if (n_items == 0)
            break;

        /* Build exec_argv: [command] [initial-args] [items...] NULL */
        int idx = 0;
        for (int j = 0; j < cmd_argc; j++)
            exec_argv[idx++] = cmd_argv[j];
        for (int j = 0; j < n_items; j++)
            exec_argv[idx++] = items[j];
        exec_argv[idx] = NULL;

        int r = run_command(exec_argv);
        if (r == 255) {
            ret = 1;
            /* Fatal error, stop */
            for (int j = 0; j < n_items; j++)
                free(items[j]);
            break;
        } else if (r != 0) {
            ret = 123;
        }

        /* Free items */
        for (int j = 0; j < n_items; j++)
            free(items[j]);
    }

    /* If -r and no items were read, don't run */
    if (opt_no_run_empty && total_items == 0) {
        free(exec_argv);
        free(items);
        return 0;
    }

    /* If no items were read and -r was not set, run command with no extra args */
    if (total_items == 0 && !opt_no_run_empty) {
        /* Build exec_argv with just the command */
        int idx = 0;
        for (int j = 0; j < cmd_argc; j++)
            exec_argv[idx++] = cmd_argv[j];
        exec_argv[idx] = NULL;
        ret = run_command(exec_argv);
    }

    free(exec_argv);
    free(items);
    return ret;
}
