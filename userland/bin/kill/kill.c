/*
 * kill - send signals to processes
 *
 * Kiseki OS coreutils
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

static const char *progname = "kill";

/* Signal name-to-number mapping table */
static const struct {
    const char *name;
    int         num;
} signal_table[] = {
    { "HUP",    SIGHUP    },
    { "INT",    SIGINT    },
    { "QUIT",   SIGQUIT   },
    { "ILL",    SIGILL    },
    { "TRAP",   SIGTRAP   },
    { "ABRT",   SIGABRT   },
    { "IOT",    SIGABRT   },
    { "EMT",    SIGEMT    },
    { "FPE",    SIGFPE    },
    { "KILL",   SIGKILL   },
    { "BUS",    SIGBUS    },
    { "SEGV",   SIGSEGV   },
    { "SYS",    SIGSYS    },
    { "PIPE",   SIGPIPE   },
    { "ALRM",   SIGALRM   },
    { "TERM",   SIGTERM   },
    { "URG",    SIGURG    },
    { "STOP",   SIGSTOP   },
    { "TSTP",   SIGTSTP   },
    { "CONT",   SIGCONT   },
    { "CHLD",   SIGCHLD   },
    { "TTIN",   SIGTTIN   },
    { "TTOU",   SIGTTOU   },
    { "IO",     SIGIO     },
    { "XCPU",   SIGXCPU   },
    { "XFSZ",   SIGXFSZ   },
    { "VTALRM", SIGVTALRM },
    { "PROF",   SIGPROF   },
    { "WINCH",  SIGWINCH  },
    { "INFO",   SIGINFO   },
    { "USR1",   SIGUSR1   },
    { "USR2",   SIGUSR2   },
    { NULL,     0         }
};

static void usage(void)
{
    fprintf(stderr, "Usage: %s [-s SIGNAL | -SIGNAL] PID...\n", progname);
    fprintf(stderr, "       %s -l [SIGNAL]\n", progname);
    fprintf(stderr, "\nSend a signal to processes.\n");
    fprintf(stderr, "Default signal is TERM (15).\n");
}

/*
 * Convert a signal name (without SIG prefix) to its number.
 * Returns -1 if not found.
 */
static int signal_name_to_num(const char *name)
{
    for (int i = 0; signal_table[i].name != NULL; i++) {
        if (strcmp(signal_table[i].name, name) == 0)
            return signal_table[i].num;
    }
    return -1;
}

/*
 * Convert a signal name that may optionally have a "SIG" prefix.
 */
static int parse_signal_name(const char *name)
{
    /* Strip optional SIG prefix */
    if (strncmp(name, "SIG", 3) == 0)
        name += 3;
    return signal_name_to_num(name);
}

/*
 * Convert a signal number to its name.
 * Returns NULL if not found.
 */
static const char *signal_num_to_name(int num)
{
    for (int i = 0; signal_table[i].name != NULL; i++) {
        if (signal_table[i].num == num)
            return signal_table[i].name;
    }
    return NULL;
}

/*
 * List all signals.
 */
static void list_signals(void)
{
    int col = 0;
    for (int sig = 1; sig < NSIG; sig++) {
        const char *name = signal_num_to_name(sig);
        if (name != NULL) {
            printf("%2d) SIG%-8s", sig, name);
            col++;
            if (col % 4 == 0)
                putchar('\n');
        }
    }
    if (col % 4 != 0)
        putchar('\n');
}

/*
 * Given a signal number or exit status, print the signal name.
 */
static int list_signal(const char *arg)
{
    char *endp;
    long val = strtol(arg, &endp, 10);

    if (*endp != '\0' || endp == arg) {
        /* It's a name — convert to number */
        int num = parse_signal_name(arg);
        if (num < 0) {
            fprintf(stderr, "%s: unknown signal '%s'\n", progname, arg);
            return 1;
        }
        printf("%d\n", num);
    } else {
        /* It's a number — convert to name */
        /* If > 128, treat as exit status (signal = val - 128) */
        if (val > 128)
            val -= 128;
        if (val < 1 || val >= NSIG) {
            fprintf(stderr, "%s: unknown signal %ld\n", progname, val);
            return 1;
        }
        const char *name = signal_num_to_name((int)val);
        if (name != NULL)
            printf("%s\n", name);
        else
            printf("%ld\n", val);
    }
    return 0;
}

/*
 * Parse a signal specification: number or name.
 * Returns signal number or -1 on error.
 */
static int parse_signal(const char *spec)
{
    /* Try as a number first */
    char *endp;
    long val = strtol(spec, &endp, 10);
    if (*endp == '\0' && endp != spec) {
        if (val < 1 || val >= NSIG) {
            fprintf(stderr, "%s: invalid signal number %ld\n",
                    progname, val);
            return -1;
        }
        return (int)val;
    }

    /* Try as a name */
    int num = parse_signal_name(spec);
    if (num < 0) {
        fprintf(stderr, "%s: unknown signal '%s'\n", progname, spec);
        return -1;
    }
    return num;
}

int main(int argc, char *argv[])
{
    int signum = SIGTERM;
    int list_mode = 0;
    int first_pid = 1;

    if (argc < 2) {
        usage();
        return 1;
    }

    /* Parse options */
    int i = 1;
    while (i < argc) {
        if (strcmp(argv[i], "--help") == 0) {
            usage();
            return 0;
        }

        if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "-L") == 0) {
            list_mode = 1;
            i++;
            break;
        }

        if (strcmp(argv[i], "-s") == 0) {
            /* -s SIGNAL */
            if (i + 1 >= argc) {
                fprintf(stderr, "%s: option '-s' requires an argument\n",
                        progname);
                return 1;
            }
            signum = parse_signal(argv[i + 1]);
            if (signum < 0)
                return 1;
            i += 2;
            first_pid = i;
            continue;
        }

        if (argv[i][0] == '-' && argv[i][1] != '\0') {
            const char *spec = &argv[i][1];

            /*
             * Check if this is a signal specification or a negative PID.
             * If it's all digits, it could be -9 (signal) or we need context.
             * Convention: if it's before any PID args, treat as signal.
             * If the first char is a digit and the rest are digits, it's
             * a signal number. If it starts with a letter, it's a signal name.
             */
            if (spec[0] >= '0' && spec[0] <= '9') {
                /* Looks like -NUMBER (signal specification) */
                signum = parse_signal(spec);
                if (signum < 0)
                    return 1;
                i++;
                first_pid = i;
                continue;
            }

            if ((spec[0] >= 'A' && spec[0] <= 'Z') ||
                (spec[0] >= 'a' && spec[0] <= 'z')) {
                /* Signal name like -TERM, -HUP, etc. */
                signum = parse_signal(spec);
                if (signum < 0)
                    return 1;
                i++;
                first_pid = i;
                continue;
            }

            /* Not a known option, fall through to PID parsing */
            break;
        }

        /* Not an option */
        break;
    }

    first_pid = i;

    if (list_mode) {
        if (first_pid >= argc) {
            /* No argument to -l: list all signals */
            list_signals();
            return 0;
        }
        /* List specific signals */
        int ret = 0;
        for (int j = first_pid; j < argc; j++) {
            if (list_signal(argv[j]) != 0)
                ret = 1;
        }
        return ret;
    }

    /* Must have at least one PID */
    if (first_pid >= argc) {
        fprintf(stderr, "%s: no process ID specified\n", progname);
        usage();
        return 1;
    }

    /* Send signal to each PID */
    int ret = 0;
    for (int j = first_pid; j < argc; j++) {
        char *endp;
        long pid_val = strtol(argv[j], &endp, 10);
        if (*endp != '\0' || endp == argv[j]) {
            fprintf(stderr, "%s: invalid PID '%s'\n", progname, argv[j]);
            ret = 1;
            continue;
        }

        if (kill((pid_t)pid_val, signum) < 0) {
            fprintf(stderr, "%s: (%d) - No such process\n",
                    progname, (int)pid_val);
            ret = 1;
        }
    }

    return ret;
}
