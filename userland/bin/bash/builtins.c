/*
 * Kiseki OS - Shell Builtins
 *
 * All built-in shell commands.
 */

#include "shell.h"
#include "parser.h"
#include "expand.h"
#include <termios.h>

/* ---------- Forward declarations ---------- */

int  shell_execute(shell_state_t *state, ast_node_t *node);
int  exec_function_call(shell_state_t *state, const char *name,
                        int argc, char **argv);
int  var_parse_assignment(const char *str, char **name_out, char **value_out);
void hash_clear(void);
void hash_print(void);
void hash_remove(const char *name);
char *find_in_path(const char *name, const char *path_env);
int  is_builtin(const char *name);

/* Forward declarations for readline/history */
void history_add(const char *line);

/* ---------- Builtin function type ---------- */

typedef int (*builtin_fn_t)(shell_state_t *state, int argc, char **argv);

/* ---------- builtin_colon : do nothing, return 0 ---------- */

static int builtin_colon(shell_state_t *state, int argc, char **argv)
{
    (void)state; (void)argc; (void)argv;
    return 0;
}

/* ---------- builtin_true / builtin_false ---------- */

static int builtin_true(shell_state_t *state, int argc, char **argv)
{
    (void)state; (void)argc; (void)argv;
    return 0;
}

static int builtin_false(shell_state_t *state, int argc, char **argv)
{
    (void)state; (void)argc; (void)argv;
    return 1;
}

/* ---------- builtin_exit ---------- */

static int builtin_exit(shell_state_t *state, int argc, char **argv)
{
    int code = state->last_exit_status;
    if (argc > 1)
        code = atoi(argv[1]) & 0xff;
    if (state->opts.interactive)
        fprintf(stderr, "exit\n");
    state->running = 0;
    state->last_exit_status = code;
    return code;
}

/* ---------- builtin_cd ---------- */

static int builtin_cd(shell_state_t *state, int argc, char **argv)
{
    const char *target = NULL;

    if (argc < 2 || strcmp(argv[1], "~") == 0) {
        target = shell_get_var(state, "HOME");
        if (!target || !target[0]) {
            fprintf(stderr, "bash: cd: HOME not set\n");
            return 1;
        }
    } else if (strcmp(argv[1], "-") == 0) {
        target = shell_get_var(state, "OLDPWD");
        if (!target || !target[0]) {
            fprintf(stderr, "bash: cd: OLDPWD not set\n");
            return 1;
        }
        printf("%s\n", target);
    } else {
        target = argv[1];
    }

    /* Handle tilde prefix */
    char expanded[PATH_MAX];
    if (target[0] == '~') {
        const char *home = shell_get_var(state, "HOME");
        if (home) {
            snprintf(expanded, sizeof(expanded), "%s%s", home, target + 1);
            target = expanded;
        }
    }

    char oldpwd[PATH_MAX];
    getcwd(oldpwd, sizeof(oldpwd));

    if (chdir(target) < 0) {
        fprintf(stderr, "bash: cd: %s: %s\n", target, strerror(errno));
        return 1;
    }

    shell_set_var(state, "OLDPWD", oldpwd);

    char newpwd[PATH_MAX];
    if (getcwd(newpwd, sizeof(newpwd)))
        shell_set_var(state, "PWD", newpwd);

    return 0;
}

/* ---------- builtin_pwd ---------- */

static int builtin_pwd(shell_state_t *state, int argc, char **argv)
{
    int physical = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-P") == 0) physical = 1;
        else if (strcmp(argv[i], "-L") == 0) physical = 0;
    }

    if (physical) {
        char buf[PATH_MAX];
        if (getcwd(buf, sizeof(buf))) {
            printf("%s\n", buf);
            return 0;
        }
        fprintf(stderr, "bash: pwd: error retrieving current directory\n");
        return 1;
    }

    /* Logical: use $PWD */
    const char *pwd = shell_get_var(state, "PWD");
    if (pwd && pwd[0]) {
        printf("%s\n", pwd);
        return 0;
    }

    char buf[PATH_MAX];
    if (getcwd(buf, sizeof(buf))) {
        printf("%s\n", buf);
        return 0;
    }
    return 1;
}

/* ---------- builtin_echo ---------- */

static int builtin_echo(shell_state_t *state, int argc, char **argv)
{
    (void)state;
    int newline = 1;
    int escapes = 0;    /* -e enables, -E disables (default off) */
    int i = 1;

    /* Parse options */
    while (i < argc) {
        if (strcmp(argv[i], "-n") == 0) {
            newline = 0;
            i++;
        } else if (strcmp(argv[i], "-e") == 0) {
            escapes = 1;
            i++;
        } else if (strcmp(argv[i], "-E") == 0) {
            escapes = 0;
            i++;
        } else if (strcmp(argv[i], "-ne") == 0 || strcmp(argv[i], "-en") == 0) {
            newline = 0;
            escapes = 1;
            i++;
        } else if (strcmp(argv[i], "-nE") == 0 || strcmp(argv[i], "-En") == 0) {
            newline = 0;
            escapes = 0;
            i++;
        } else {
            break;
        }
    }

    for (int j = i; j < argc; j++) {
        if (j > i) fputc(' ', stdout);

        if (escapes) {
            const char *s = argv[j];
            while (*s) {
                if (*s == '\\' && s[1]) {
                    switch (s[1]) {
                    case 'n':  fputc('\n', stdout); s += 2; break;
                    case 't':  fputc('\t', stdout); s += 2; break;
                    case '\\': fputc('\\', stdout); s += 2; break;
                    case 'a':  fputc('\a', stdout); s += 2; break;
                    case 'b':  fputc('\b', stdout); s += 2; break;
                    case 'r':  fputc('\r', stdout); s += 2; break;
                    case 'f':  fputc('\f', stdout); s += 2; break;
                    case 'v':  fputc('\v', stdout); s += 2; break;
                    case 'c':  goto done;  /* Stop output */
                    case '0': {
                        /* Octal: \0NNN */
                        int val = 0;
                        s += 2;
                        for (int k = 0; k < 3 && *s >= '0' && *s <= '7'; k++)
                            val = val * 8 + (*s++ - '0');
                        fputc(val, stdout);
                        break;
                    }
                    case 'x': {
                        /* Hex: \xHH */
                        int val = 0;
                        s += 2;
                        for (int k = 0; k < 2; k++) {
                            if (*s >= '0' && *s <= '9')
                                val = val * 16 + (*s++ - '0');
                            else if (*s >= 'a' && *s <= 'f')
                                val = val * 16 + (*s++ - 'a' + 10);
                            else if (*s >= 'A' && *s <= 'F')
                                val = val * 16 + (*s++ - 'A' + 10);
                            else
                                break;
                        }
                        fputc(val, stdout);
                        break;
                    }
                    default:
                        fputc('\\', stdout);
                        fputc(s[1], stdout);
                        s += 2;
                        break;
                    }
                } else {
                    fputc(*s++, stdout);
                }
            }
        } else {
            fputs(argv[j], stdout);
        }
    }
done:
    if (newline) fputc('\n', stdout);
    fflush(stdout);
    return 0;
}

/* ---------- builtin_printf ---------- */

static int builtin_printf(shell_state_t *state, int argc, char **argv)
{
    (void)state;
    if (argc < 2) {
        fprintf(stderr, "printf: usage: printf format [arguments]\n");
        return 1;
    }

    const char *fmt = argv[1];
    int argi = 2;

    while (*fmt) {
        if (*fmt == '\\') {
            fmt++;
            switch (*fmt) {
            case 'n': fputc('\n', stdout); break;
            case 't': fputc('\t', stdout); break;
            case '\\': fputc('\\', stdout); break;
            case 'a': fputc('\a', stdout); break;
            case 'b': fputc('\b', stdout); break;
            case 'r': fputc('\r', stdout); break;
            case 'f': fputc('\f', stdout); break;
            case 'v': fputc('\v', stdout); break;
            case '0': {
                int val = 0;
                fmt++;
                for (int k = 0; k < 3 && *fmt >= '0' && *fmt <= '7'; k++)
                    val = val * 8 + (*fmt++ - '0');
                fputc(val, stdout);
                continue;
            }
            case '\0': fputc('\\', stdout); continue;
            default: fputc('\\', stdout); fputc(*fmt, stdout); break;
            }
            if (*fmt) fmt++;
        } else if (*fmt == '%') {
            fmt++;
            if (*fmt == '%') {
                fputc('%', stdout);
                fmt++;
                continue;
            }

            /* Parse flags */
            char spec[64];
            int si = 0;
            spec[si++] = '%';

            /* Flags: -, +, space, 0, # */
            while (*fmt == '-' || *fmt == '+' || *fmt == ' ' ||
                   *fmt == '0' || *fmt == '#') {
                if (si < 60) spec[si++] = *fmt;
                fmt++;
            }
            /* Width */
            while (*fmt >= '0' && *fmt <= '9') {
                if (si < 60) spec[si++] = *fmt;
                fmt++;
            }
            /* Precision */
            if (*fmt == '.') {
                if (si < 60) spec[si++] = *fmt;
                fmt++;
                while (*fmt >= '0' && *fmt <= '9') {
                    if (si < 60) spec[si++] = *fmt;
                    fmt++;
                }
            }

            const char *arg = (argi < argc) ? argv[argi++] : "";

            switch (*fmt) {
            case 'd': case 'i': {
                spec[si++] = 'l';
                spec[si++] = 'd';
                spec[si] = '\0';
                long val = strtol(arg, NULL, 0);
                printf(spec, val);
                break;
            }
            case 'u': {
                spec[si++] = 'l';
                spec[si++] = 'u';
                spec[si] = '\0';
                unsigned long val = strtoul(arg, NULL, 0);
                printf(spec, val);
                break;
            }
            case 'o': {
                spec[si++] = 'l';
                spec[si++] = 'o';
                spec[si] = '\0';
                unsigned long val = strtoul(arg, NULL, 0);
                printf(spec, val);
                break;
            }
            case 'x': {
                spec[si++] = 'l';
                spec[si++] = 'x';
                spec[si] = '\0';
                unsigned long val = strtoul(arg, NULL, 0);
                printf(spec, val);
                break;
            }
            case 'X': {
                spec[si++] = 'l';
                spec[si++] = 'X';
                spec[si] = '\0';
                unsigned long val = strtoul(arg, NULL, 0);
                printf(spec, val);
                break;
            }
            case 's': {
                spec[si++] = 's';
                spec[si] = '\0';
                printf(spec, arg);
                break;
            }
            case 'c': {
                fputc(arg[0] ? arg[0] : '\0', stdout);
                break;
            }
            case 'b': {
                /* %b: interpret escape sequences in the argument */
                const char *s = arg;
                while (*s) {
                    if (*s == '\\' && s[1]) {
                        switch (s[1]) {
                        case 'n': fputc('\n', stdout); s += 2; break;
                        case 't': fputc('\t', stdout); s += 2; break;
                        case '\\': fputc('\\', stdout); s += 2; break;
                        case 'a': fputc('\a', stdout); s += 2; break;
                        case 'b': fputc('\b', stdout); s += 2; break;
                        default: fputc(*s++, stdout); break;
                        }
                    } else {
                        fputc(*s++, stdout);
                    }
                }
                break;
            }
            default:
                if (*fmt) {
                    spec[si++] = *fmt;
                    spec[si] = '\0';
                    printf("%s", spec);
                }
                break;
            }
            if (*fmt) fmt++;
        } else {
            fputc(*fmt++, stdout);
        }
    }

    fflush(stdout);
    return 0;
}

/* ---------- builtin_export ---------- */

static int builtin_export(shell_state_t *state, int argc, char **argv)
{
    int unexport = 0;
    int start = 1;

    if (argc > 1 && strcmp(argv[1], "-n") == 0) {
        unexport = 1;
        start = 2;
    }

    /* No args: list all exported variables */
    if (start >= argc) {
        for (int i = 0; i < state->nvars; i++) {
            if (state->vars[i].name && state->vars[i].exported) {
                printf("declare -x %s", state->vars[i].name);
                if (state->vars[i].value)
                    printf("=\"%s\"", state->vars[i].value);
                printf("\n");
            }
        }
        return 0;
    }

    for (int i = start; i < argc; i++) {
        char *eq = strchr(argv[i], '=');
        if (eq) {
            /* export NAME=VALUE
             * argv[i] has already been expanded by exec_command()'s
             * expand_words(), so do NOT expand again — just parse and set. */
            char *name = NULL, *value = NULL;
            if (var_parse_assignment(argv[i], &name, &value) == 0) {
                shell_set_var(state, name, value);
                if (!unexport)
                    shell_export_var(state, name);
                free(name);
                free(value);
            }
        } else {
            if (unexport) {
                /* Unexport: just clear export flag */
                for (int j = 0; j < state->nvars; j++) {
                    if (state->vars[j].name &&
                        strcmp(state->vars[j].name, argv[i]) == 0) {
                        state->vars[j].exported = 0;
                        break;
                    }
                }
            } else {
                shell_export_var(state, argv[i]);
            }
        }
    }
    return 0;
}

/* ---------- builtin_unset ---------- */

static int builtin_unset(shell_state_t *state, int argc, char **argv)
{
    int func_mode = 0;
    int start = 1;

    if (argc > 1 && strcmp(argv[1], "-f") == 0) {
        func_mode = 1;
        start = 2;
    } else if (argc > 1 && strcmp(argv[1], "-v") == 0) {
        start = 2;
    }

    for (int i = start; i < argc; i++) {
        if (func_mode)
            shell_unset_func(state, argv[i]);
        else
            shell_unset_var(state, argv[i]);
    }
    return 0;
}

/* ---------- builtin_set ---------- */

static int builtin_set(shell_state_t *state, int argc, char **argv)
{
    if (argc < 2) {
        /* Print all variables */
        for (int i = 0; i < state->nvars; i++) {
            if (state->vars[i].name)
                printf("%s=%s\n", state->vars[i].name,
                       state->vars[i].value ? state->vars[i].value : "");
        }
        return 0;
    }

    int i = 1;
    while (i < argc) {
        const char *arg = argv[i];
        if (arg[0] == '-' && arg[1] == '-' && arg[2] == '\0') {
            /* set -- args: set positional params */
            i++;
            /* Free old positional params */
            if (state->positional) {
                for (int j = 0; j < state->positional_count; j++)
                    free(state->positional[j]);
                free(state->positional);
            }
            int npos = argc - i;
            if (npos > 0) {
                state->positional = malloc(sizeof(char *) * npos);
                for (int j = 0; j < npos; j++)
                    state->positional[j] = strdup(argv[i + j]);
            } else {
                state->positional = NULL;
            }
            state->positional_count = npos;
            return 0;
        }

        if ((arg[0] == '-' || arg[0] == '+') && arg[1]) {
            int enable = (arg[0] == '-');

            if (arg[1] == 'o' && arg[2] == '\0') {
                /* -o option_name / +o option_name */
                i++;
                if (i >= argc) {
                    /* List options */
                    printf("%-20s %s\n", "errexit", state->opts.errexit ? "on" : "off");
                    printf("%-20s %s\n", "nounset", state->opts.nounset ? "on" : "off");
                    printf("%-20s %s\n", "xtrace", state->opts.xtrace ? "on" : "off");
                    printf("%-20s %s\n", "verbose", state->opts.verbose ? "on" : "off");
                    printf("%-20s %s\n", "noglob", state->opts.noglob ? "on" : "off");
                    printf("%-20s %s\n", "noclobber", state->opts.noclobber ? "on" : "off");
                    printf("%-20s %s\n", "allexport", state->opts.allexport ? "on" : "off");
                    printf("%-20s %s\n", "notify", state->opts.notify ? "on" : "off");
                    printf("%-20s %s\n", "noexec", state->opts.noexec ? "on" : "off");
                    printf("%-20s %s\n", "pipefail", state->opts.pipefail ? "on" : "off");
                    return 0;
                }
                const char *opt = argv[i];
                if (strcmp(opt, "errexit") == 0) state->opts.errexit = enable;
                else if (strcmp(opt, "nounset") == 0) state->opts.nounset = enable;
                else if (strcmp(opt, "xtrace") == 0) state->opts.xtrace = enable;
                else if (strcmp(opt, "verbose") == 0) state->opts.verbose = enable;
                else if (strcmp(opt, "noglob") == 0) state->opts.noglob = enable;
                else if (strcmp(opt, "noclobber") == 0) state->opts.noclobber = enable;
                else if (strcmp(opt, "allexport") == 0) state->opts.allexport = enable;
                else if (strcmp(opt, "notify") == 0) state->opts.notify = enable;
                else if (strcmp(opt, "noexec") == 0) state->opts.noexec = enable;
                else if (strcmp(opt, "pipefail") == 0) state->opts.pipefail = enable;
                else {
                    fprintf(stderr, "bash: set: %s: invalid option name\n", opt);
                    return 1;
                }
                i++;
                continue;
            }

            /* Short options: -e, -u, -x, etc. */
            for (int j = 1; arg[j]; j++) {
                switch (arg[j]) {
                case 'e': state->opts.errexit = enable; break;
                case 'u': state->opts.nounset = enable; break;
                case 'x': state->opts.xtrace = enable; break;
                case 'v': state->opts.verbose = enable; break;
                case 'f': state->opts.noglob = enable; break;
                case 'C': state->opts.noclobber = enable; break;
                case 'a': state->opts.allexport = enable; break;
                case 'b': state->opts.notify = enable; break;
                case 'n': state->opts.noexec = enable; break;
                default:
                    fprintf(stderr, "bash: set: -%c: invalid option\n", arg[j]);
                    return 1;
                }
            }
            i++;
        } else {
            /* set word word word... = set positional params */
            if (state->positional) {
                for (int j = 0; j < state->positional_count; j++)
                    free(state->positional[j]);
                free(state->positional);
            }
            int npos = argc - i;
            state->positional = malloc(sizeof(char *) * npos);
            for (int j = 0; j < npos; j++)
                state->positional[j] = strdup(argv[i + j]);
            state->positional_count = npos;
            return 0;
        }
    }
    return 0;
}

/* ---------- builtin_shift ---------- */

static int builtin_shift(shell_state_t *state, int argc, char **argv)
{
    int n = 1;
    if (argc > 1)
        n = atoi(argv[1]);
    if (n < 0) n = 0;
    if (n > state->positional_count)
        n = state->positional_count;

    /* Free shifted params */
    for (int i = 0; i < n; i++)
        free(state->positional[i]);

    /* Move remaining */
    int remaining = state->positional_count - n;
    for (int i = 0; i < remaining; i++)
        state->positional[i] = state->positional[i + n];

    state->positional_count = remaining;
    return 0;
}

/* ---------- builtin_source (.) ---------- */

static int builtin_source(shell_state_t *state, int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "bash: source: filename argument required\n");
        return 2;
    }

    const char *filename = argv[1];

    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "bash: %s: No such file or directory\n", filename);
        return 1;
    }

    /* Read the entire file into a buffer so multi-line constructs work */
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (size <= 0) {
        fclose(fp);
        return 0;
    }

    char *buf = malloc((size_t)size + 1);
    if (!buf) {
        fclose(fp);
        return 1;
    }

    size_t nread = fread(buf, 1, (size_t)size, fp);
    buf[nread] = '\0';
    fclose(fp);

    /* Save and set positional params if provided */
    char **old_pos = NULL;
    int old_count = 0;
    if (argc > 2) {
        old_pos = state->positional;
        old_count = state->positional_count;
        state->positional_count = argc - 2;
        state->positional = malloc(sizeof(char *) * state->positional_count);
        for (int i = 0; i < state->positional_count; i++)
            state->positional[i] = strdup(argv[i + 2]);
    }

    /* Parse and execute the entire file */
    int status = 0;
    ast_node_t *ast = parse_input(buf);
    if (ast) {
        status = shell_execute(state, ast);
        ast_free(ast);
    }

    free(buf);

    /* Restore positional params */
    if (old_pos || (argc > 2)) {
        if (state->positional) {
            for (int i = 0; i < state->positional_count; i++)
                free(state->positional[i]);
            free(state->positional);
        }
        state->positional = old_pos;
        state->positional_count = old_count;
    }

    return status;
}

/* ---------- builtin_eval ---------- */

static int builtin_eval(shell_state_t *state, int argc, char **argv)
{
    if (argc < 2) return 0;

    /* Concatenate all arguments with spaces */
    size_t total = 0;
    for (int i = 1; i < argc; i++)
        total += strlen(argv[i]) + 1;

    char *cmd = malloc(total + 1);
    if (!cmd) return 1;
    cmd[0] = '\0';

    for (int i = 1; i < argc; i++) {
        if (i > 1) strcat(cmd, " ");
        strcat(cmd, argv[i]);
    }

    ast_node_t *ast = parse_input(cmd);
    int status = 0;
    if (ast) {
        status = shell_execute(state, ast);
        ast_free(ast);
    }

    free(cmd);
    return status;
}

/* ---------- builtin_exec ---------- */

static int builtin_exec(shell_state_t *state, int argc, char **argv)
{
    if (argc < 2) return 0;

    /* Find the command */
    const char *path_env = shell_get_var(state, "PATH");
    char *fullpath = find_in_path(argv[1], path_env);
    if (!fullpath) {
        fprintf(stderr, "bash: exec: %s: not found\n", argv[1]);
        return 127;
    }

    char **envp = shell_build_envp(state);

    /* Build argv */
    char **exec_argv = malloc(sizeof(char *) * argc);
    for (int i = 1; i < argc; i++)
        exec_argv[i - 1] = argv[i];
    exec_argv[argc - 1] = NULL;

    execve(fullpath, exec_argv, envp);

    /* If we get here, execve failed */
    fprintf(stderr, "bash: exec: %s: %s\n", fullpath, strerror(errno));
    free(exec_argv);
    shell_free_envp(envp);
    free(fullpath);
    return 126;
}

/* ---------- builtin_read ---------- */

static int builtin_read(shell_state_t *state, int argc, char **argv)
{
    const char *prompt = NULL;
    int raw = 0;
    int silent = 0;
    int nchars = -1;
    int start = 1;

    /* Parse options */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-r") == 0) {
            raw = 1;
            start = i + 1;
        } else if (strcmp(argv[i], "-s") == 0) {
            silent = 1;
            start = i + 1;
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            prompt = argv[i + 1];
            i++;
            start = i + 1;
        } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            nchars = atoi(argv[i + 1]);
            i++;
            start = i + 1;
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            /* Timeout: not fully implemented, skip */
            i++;
            start = i + 1;
        } else if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
            /* Array: simplified - just read into the named variable */
            i++;
            start = i + 1;
        } else if (argv[i][0] != '-') {
            start = i;
            break;
        }
    }

    if (prompt && isatty(STDIN_FILENO))
        fprintf(stderr, "%s", prompt);

    /* Set up silent mode */
    struct termios old_term, new_term;
    int term_set = 0;
    if (silent && isatty(STDIN_FILENO)) {
        tcgetattr(STDIN_FILENO, &old_term);
        new_term = old_term;
        new_term.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSADRAIN, &new_term);
        term_set = 1;
    }

    char buf[MAX_LINE];
    int pos = 0;
    int cont = 1;

    while (cont && pos < (int)sizeof(buf) - 1) {
        if (nchars >= 0 && pos >= nchars) break;

        char c;
        ssize_t n = read(STDIN_FILENO, &c, 1);
        if (n <= 0) {
            /* EOF */
            if (pos == 0) {
                if (term_set)
                    tcsetattr(STDIN_FILENO, TCSADRAIN, &old_term);
                return 1;
            }
            break;
        }

        if (c == '\n') break;

        if (!raw && c == '\\') {
            /* Read next char */
            n = read(STDIN_FILENO, &c, 1);
            if (n <= 0) break;
            if (c == '\n') continue; /* Line continuation */
            buf[pos++] = c;
        } else {
            buf[pos++] = c;
        }
    }
    buf[pos] = '\0';

    if (term_set) {
        tcsetattr(STDIN_FILENO, TCSADRAIN, &old_term);
        if (silent) fputc('\n', stderr);
    }

    /* Split on IFS and assign to variables */
    const char *ifs = shell_get_var(state, "IFS");
    if (!ifs) ifs = " \t\n";

    int nvars = argc - start;
    if (nvars <= 0) {
        /* Default: assign to REPLY */
        shell_set_var(state, "REPLY", buf);
        return 0;
    }

    char *line = buf;
    for (int i = 0; i < nvars; i++) {
        /* Skip leading IFS chars */
        while (*line && strchr(ifs, *line))
            line++;

        if (i == nvars - 1) {
            /* Last variable gets the rest */
            /* Trim trailing IFS */
            size_t len = strlen(line);
            while (len > 0 && strchr(ifs, line[len - 1]))
                len--;
            char *val = malloc(len + 1);
            memcpy(val, line, len);
            val[len] = '\0';
            shell_set_var(state, argv[start + i], val);
            free(val);
        } else {
            /* Find end of this word */
            char *end = line;
            while (*end && !strchr(ifs, *end))
                end++;
            size_t wlen = (size_t)(end - line);
            char *val = malloc(wlen + 1);
            memcpy(val, line, wlen);
            val[wlen] = '\0';
            shell_set_var(state, argv[start + i], val);
            free(val);
            line = end;
        }
    }

    return 0;
}

/* ---------- builtin_test (aka [) ---------- */

static int test_file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static int test_file_regular(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static int test_file_directory(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static int test_file_readable(const char *path)
{
    return access(path, R_OK) == 0;
}

static int test_file_writable(const char *path)
{
    return access(path, W_OK) == 0;
}

static int test_file_executable(const char *path)
{
    return access(path, X_OK) == 0;
}

static int test_file_size(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && st.st_size > 0;
}

static int test_file_symlink(const char *path)
{
    struct stat st;
    return lstat(path, &st) == 0 && S_ISLNK(st.st_mode);
}

static int test_expr(int argc, char **argv, int *pos);

static int test_primary(int argc, char **argv, int *pos)
{
    if (*pos >= argc) return 1; /* false */

    const char *arg = argv[*pos];

    /* Parenthesized expression */
    if (strcmp(arg, "(") == 0) {
        (*pos)++;
        int result = test_expr(argc, argv, pos);
        if (*pos < argc && strcmp(argv[*pos], ")") == 0)
            (*pos)++;
        return result;
    }

    /* Unary operators */
    if (arg[0] == '-' && arg[1] && !arg[2]) {
        if (*pos + 1 >= argc) return 1;
        const char *operand = argv[*pos + 1];
        *pos += 2;

        switch (arg[1]) {
        case 'e': return test_file_exists(operand) ? 0 : 1;
        case 'f': return test_file_regular(operand) ? 0 : 1;
        case 'd': return test_file_directory(operand) ? 0 : 1;
        case 'r': return test_file_readable(operand) ? 0 : 1;
        case 'w': return test_file_writable(operand) ? 0 : 1;
        case 'x': return test_file_executable(operand) ? 0 : 1;
        case 's': return test_file_size(operand) ? 0 : 1;
        case 'L': case 'h': return test_file_symlink(operand) ? 0 : 1;
        case 'z': return (strlen(operand) == 0) ? 0 : 1;
        case 'n': return (strlen(operand) > 0) ? 0 : 1;
        case 't': {
            int fd_num = atoi(operand);
            return isatty(fd_num) ? 0 : 1;
        }
        default:
            /* Unknown unary, treat as string test */
            *pos -= 2;
            break;
        }
    }

    /* Unary ! */
    if (strcmp(arg, "!") == 0) {
        (*pos)++;
        return test_primary(argc, argv, pos) ? 0 : 1;
    }

    /* Binary operators: check if next arg is an operator */
    if (*pos + 2 <= argc) {
        const char *operand1 = argv[*pos];

        if (*pos + 1 < argc) {
            const char *op = argv[*pos + 1];
            if (*pos + 2 < argc) {
                const char *operand2 = argv[*pos + 2];

                /* String comparison */
                if (strcmp(op, "=") == 0 || strcmp(op, "==") == 0) {
                    *pos += 3;
                    return (strcmp(operand1, operand2) == 0) ? 0 : 1;
                }
                if (strcmp(op, "!=") == 0) {
                    *pos += 3;
                    return (strcmp(operand1, operand2) != 0) ? 0 : 1;
                }

                /* Integer comparison */
                if (strcmp(op, "-eq") == 0) {
                    *pos += 3;
                    return (atoi(operand1) == atoi(operand2)) ? 0 : 1;
                }
                if (strcmp(op, "-ne") == 0) {
                    *pos += 3;
                    return (atoi(operand1) != atoi(operand2)) ? 0 : 1;
                }
                if (strcmp(op, "-lt") == 0) {
                    *pos += 3;
                    return (atoi(operand1) < atoi(operand2)) ? 0 : 1;
                }
                if (strcmp(op, "-le") == 0) {
                    *pos += 3;
                    return (atoi(operand1) <= atoi(operand2)) ? 0 : 1;
                }
                if (strcmp(op, "-gt") == 0) {
                    *pos += 3;
                    return (atoi(operand1) > atoi(operand2)) ? 0 : 1;
                }
                if (strcmp(op, "-ge") == 0) {
                    *pos += 3;
                    return (atoi(operand1) >= atoi(operand2)) ? 0 : 1;
                }

                /* File comparison */
                if (strcmp(op, "-nt") == 0) {
                    struct stat s1, s2;
                    *pos += 3;
                    if (stat(operand1, &s1) != 0) return 1;
                    if (stat(operand2, &s2) != 0) return 1;
                    return (s1.st_mtime > s2.st_mtime) ? 0 : 1;
                }
                if (strcmp(op, "-ot") == 0) {
                    struct stat s1, s2;
                    *pos += 3;
                    if (stat(operand1, &s1) != 0) return 1;
                    if (stat(operand2, &s2) != 0) return 1;
                    return (s1.st_mtime < s2.st_mtime) ? 0 : 1;
                }
            }
        }
    }

    /* Single string: true if non-empty */
    (*pos)++;
    return (arg[0] != '\0') ? 0 : 1;
}

static int test_expr(int argc, char **argv, int *pos)
{
    int result = test_primary(argc, argv, pos);

    while (*pos < argc) {
        if (strcmp(argv[*pos], "-a") == 0) {
            (*pos)++;
            int right = test_primary(argc, argv, pos);
            result = (result == 0 && right == 0) ? 0 : 1;
        } else if (strcmp(argv[*pos], "-o") == 0) {
            (*pos)++;
            int right = test_primary(argc, argv, pos);
            result = (result == 0 || right == 0) ? 0 : 1;
        } else {
            break;
        }
    }
    return result;
}

static int builtin_test(shell_state_t *state, int argc, char **argv)
{
    (void)state;

    /* Handle [ ... ] form: strip trailing ] */
    int test_argc = argc;
    if (strcmp(argv[0], "[") == 0) {
        if (argc < 2 || strcmp(argv[argc - 1], "]") != 0) {
            fprintf(stderr, "bash: [: missing `]'\n");
            return 2;
        }
        test_argc = argc - 1;
    }

    if (test_argc <= 1) return 1; /* No args = false */

    int pos = 1;
    int result = test_expr(test_argc, argv, &pos);
    return result;
}

/* ---------- builtin_type ---------- */

static int builtin_type(shell_state_t *state, int argc, char **argv)
{
    if (argc < 2) return 0;
    int status = 0;

    for (int i = 1; i < argc; i++) {
        const char *name = argv[i];

        /* Check alias */
        const char *alias = shell_get_alias(state, name);
        if (alias) {
            printf("%s is aliased to `%s'\n", name, alias);
            continue;
        }

        /* Check builtin */
        if (is_builtin(name)) {
            printf("%s is a shell builtin\n", name);
            continue;
        }

        /* Check function */
        shell_func_t *func = shell_get_func(state, name);
        if (func) {
            printf("%s is a function\n", name);
            continue;
        }

        /* Check PATH */
        const char *path_env = shell_get_var(state, "PATH");
        char *path = find_in_path(name, path_env);
        if (path) {
            printf("%s is %s\n", name, path);
            free(path);
            continue;
        }

        fprintf(stderr, "bash: type: %s: not found\n", name);
        status = 1;
    }
    return status;
}

/* ---------- builtin_alias ---------- */

static int builtin_alias(shell_state_t *state, int argc, char **argv)
{
    if (argc < 2) {
        /* List all aliases */
        for (int i = 0; i < state->naliases; i++) {
            if (state->aliases[i].name)
                printf("alias %s='%s'\n", state->aliases[i].name,
                       state->aliases[i].value);
        }
        return 0;
    }

    int status = 0;
    for (int i = 1; i < argc; i++) {
        char *eq = strchr(argv[i], '=');
        if (eq) {
            /* Define alias */
            size_t nlen = (size_t)(eq - argv[i]);
            char *name = malloc(nlen + 1);
            memcpy(name, argv[i], nlen);
            name[nlen] = '\0';
            shell_set_alias(state, name, eq + 1);
            free(name);
        } else {
            /* Print alias */
            const char *val = shell_get_alias(state, argv[i]);
            if (val)
                printf("alias %s='%s'\n", argv[i], val);
            else {
                fprintf(stderr, "bash: alias: %s: not found\n", argv[i]);
                status = 1;
            }
        }
    }
    return status;
}

/* ---------- builtin_unalias ---------- */

static int builtin_unalias(shell_state_t *state, int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "bash: unalias: usage: unalias [-a] name ...\n");
        return 1;
    }

    if (strcmp(argv[1], "-a") == 0) {
        /* Remove all */
        for (int i = 0; i < state->naliases; i++) {
            free(state->aliases[i].name);
            free(state->aliases[i].value);
            state->aliases[i].name = NULL;
            state->aliases[i].value = NULL;
        }
        state->naliases = 0;
        return 0;
    }

    for (int i = 1; i < argc; i++)
        shell_unset_alias(state, argv[i]);
    return 0;
}

/* ---------- builtin_hash ---------- */

static int builtin_hash(shell_state_t *state, int argc, char **argv)
{
    (void)state;
    if (argc < 2) {
        hash_print();
        return 0;
    }

    if (strcmp(argv[1], "-r") == 0) {
        hash_clear();
        return 0;
    }

    if (strcmp(argv[1], "-d") == 0 && argc > 2) {
        hash_remove(argv[2]);
        return 0;
    }

    /* Hash specific commands */
    const char *path_env = shell_get_var(state, "PATH");
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') continue;
        char *path = find_in_path(argv[i], path_env);
        if (path) {
            /* hash_insert is in execute.c, we have the extern */
            free(path);
        } else {
            fprintf(stderr, "bash: hash: %s: not found\n", argv[i]);
        }
    }
    return 0;
}

/* ---------- builtin_trap ---------- */

/* Trap table: signal -> command string */
static char *trap_commands[NSIG];

static void trap_handler(int sig)
{
    if (sig >= 0 && sig < NSIG && trap_commands[sig]) {
        ast_node_t *ast = parse_input(trap_commands[sig]);
        if (ast && g_shell) {
            shell_execute(g_shell, ast);
            ast_free(ast);
        }
    }
}

static int builtin_trap(shell_state_t *state, int argc, char **argv)
{
    (void)state;

    if (argc < 2) {
        /* List traps */
        for (int i = 0; i < NSIG; i++) {
            if (trap_commands[i])
                printf("trap -- '%s' %d\n", trap_commands[i], i);
        }
        return 0;
    }

    if (argc == 2) {
        /* trap '' or trap - */
        if (strcmp(argv[1], "-") == 0) {
            /* Reset all traps */
            for (int i = 0; i < NSIG; i++) {
                if (trap_commands[i]) {
                    free(trap_commands[i]);
                    trap_commands[i] = NULL;
                    signal(i, SIG_DFL);
                }
            }
            return 0;
        }
    }

    /* trap 'command' SIG ... */
    const char *cmd = argv[1];
    for (int i = 2; i < argc; i++) {
        int sig = -1;

        /* Parse signal name or number */
        if (argv[i][0] >= '0' && argv[i][0] <= '9') {
            sig = atoi(argv[i]);
        } else {
            /* Signal names */
            const char *name = argv[i];
            if (strncmp(name, "SIG", 3) == 0) name += 3;

            if (strcmp(name, "HUP") == 0) sig = SIGHUP;
            else if (strcmp(name, "INT") == 0) sig = SIGINT;
            else if (strcmp(name, "QUIT") == 0) sig = SIGQUIT;
            else if (strcmp(name, "TERM") == 0) sig = SIGTERM;
            else if (strcmp(name, "CHLD") == 0) sig = SIGCHLD;
            else if (strcmp(name, "CONT") == 0) sig = SIGCONT;
            else if (strcmp(name, "STOP") == 0) sig = SIGTSTP;
            else if (strcmp(name, "TSTP") == 0) sig = SIGTSTP;
            else if (strcmp(name, "TTIN") == 0) sig = SIGTTIN;
            else if (strcmp(name, "TTOU") == 0) sig = SIGTTOU;
            else if (strcmp(name, "PIPE") == 0) sig = SIGPIPE;
            else if (strcmp(name, "ALRM") == 0) sig = SIGALRM;
            else if (strcmp(name, "USR1") == 0) sig = SIGUSR1;
            else if (strcmp(name, "USR2") == 0) sig = SIGUSR2;
            else if (strcmp(name, "EXIT") == 0) sig = 0;
            else {
                fprintf(stderr, "bash: trap: %s: invalid signal\n", argv[i]);
                return 1;
            }
        }

        if (sig < 0 || sig >= NSIG) {
            fprintf(stderr, "bash: trap: %d: invalid signal\n", sig);
            return 1;
        }

        free(trap_commands[sig]);

        if (cmd[0] == '\0' || strcmp(cmd, "-") == 0) {
            /* Reset to default */
            trap_commands[sig] = NULL;
            if (sig > 0) signal(sig, SIG_DFL);
        } else if (cmd[0] == '\0') {
            /* Ignore */
            trap_commands[sig] = strdup("");
            if (sig > 0) signal(sig, SIG_IGN);
        } else {
            trap_commands[sig] = strdup(cmd);
            if (sig > 0) signal(sig, trap_handler);
        }
    }
    return 0;
}

/* ---------- builtin_return ---------- */

static int builtin_return(shell_state_t *state, int argc, char **argv)
{
    if (!state->in_function) {
        fprintf(stderr, "bash: return: can only `return' from a function\n");
        return 1;
    }

    state->do_return = 1;
    state->return_value = (argc > 1) ? atoi(argv[1]) : state->last_exit_status;
    return state->return_value;
}

/* ---------- builtin_break ---------- */

static int builtin_break(shell_state_t *state, int argc, char **argv)
{
    if (state->loop_depth == 0) {
        fprintf(stderr, "bash: break: only meaningful in a loop\n");
        return 0;
    }

    int n = 1;
    if (argc > 1) n = atoi(argv[1]);
    if (n < 1) n = 1;

    state->do_break = 1;
    state->break_count = n;
    return 0;
}

/* ---------- builtin_continue ---------- */

static int builtin_continue(shell_state_t *state, int argc, char **argv)
{
    if (state->loop_depth == 0) {
        fprintf(stderr, "bash: continue: only meaningful in a loop\n");
        return 0;
    }

    int n = 1;
    if (argc > 1) n = atoi(argv[1]);
    if (n < 1) n = 1;

    state->do_continue = 1;
    state->continue_count = n;
    return 0;
}

/* ---------- builtin_local ---------- */

static int builtin_local(shell_state_t *state, int argc, char **argv)
{
    if (!state->in_function) {
        fprintf(stderr, "bash: local: can only be used in a function\n");
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        char *name = NULL, *value = NULL;
        if (var_parse_assignment(argv[i], &name, &value) == 0) {
            /* Already expanded by exec_command() — just set directly */
            shell_set_var(state, name, value);
            free(name);
            free(value);
        } else {
            /* Just declare without value */
            const char *existing = shell_get_var(state, argv[i]);
            if (!existing)
                shell_set_var(state, argv[i], "");
        }
    }
    return 0;
}

/* ---------- builtin_declare ---------- */

static int builtin_declare(shell_state_t *state, int argc, char **argv)
{
    int flag_export = 0;
    int flag_readonly = 0;
    int flag_integer = 0;
    (void)flag_integer;

    int i = 1;
    while (i < argc && argv[i][0] == '-') {
        for (int j = 1; argv[i][j]; j++) {
            switch (argv[i][j]) {
            case 'x': flag_export = 1; break;
            case 'r': flag_readonly = 1; break;
            case 'i': flag_integer = 1; break;
            case 'a': /* array - simplified */ break;
            default:
                fprintf(stderr, "bash: declare: -%c: invalid option\n",
                        argv[i][j]);
                return 1;
            }
        }
        i++;
    }

    if (i >= argc) {
        /* No args: list all variables with attributes */
        for (int j = 0; j < state->nvars; j++) {
            if (!state->vars[j].name) continue;
            printf("declare ");
            if (state->vars[j].exported) printf("-x ");
            if (state->vars[j].readonly) printf("-r ");
            printf("%s", state->vars[j].name);
            if (state->vars[j].value)
                printf("=\"%s\"", state->vars[j].value);
            printf("\n");
        }
        return 0;
    }

    for (; i < argc; i++) {
        char *name = NULL, *value = NULL;
        if (var_parse_assignment(argv[i], &name, &value) == 0) {
            /* Already expanded by exec_command() — just set directly */
            shell_set_var(state, name, value);
        } else {
            name = strdup(argv[i]);
            if (!shell_get_var(state, name))
                shell_set_var(state, name, "");
        }

        if (flag_export && name)
            shell_export_var(state, name);
        if (flag_readonly && name)
            shell_set_readonly(state, name);

        free(name);
        free(value);
    }
    return 0;
}

/* ---------- builtin_readonly ---------- */

static int builtin_readonly(shell_state_t *state, int argc, char **argv)
{
    if (argc < 2) {
        /* List readonly variables */
        for (int i = 0; i < state->nvars; i++) {
            if (state->vars[i].name && state->vars[i].readonly) {
                printf("declare -r %s", state->vars[i].name);
                if (state->vars[i].value)
                    printf("=\"%s\"", state->vars[i].value);
                printf("\n");
            }
        }
        return 0;
    }

    for (int i = 1; i < argc; i++) {
        char *name = NULL, *value = NULL;
        if (var_parse_assignment(argv[i], &name, &value) == 0) {
            /* Already expanded by exec_command() — just set directly */
            shell_set_var(state, name, value);
            shell_set_readonly(state, name);
            free(name);
            free(value);
        } else {
            shell_set_readonly(state, argv[i]);
        }
    }
    return 0;
}

/* ---------- builtin_let ---------- */

static int builtin_let(shell_state_t *state, int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "bash: let: expression expected\n");
        return 1;
    }

    long result = 0;
    for (int i = 1; i < argc; i++) {
        int err = 0;
        result = arith_eval(argv[i], state, &err);
        if (err) {
            fprintf(stderr, "bash: let: %s: expression error\n", argv[i]);
            return 1;
        }
    }
    return result == 0 ? 1 : 0; /* let returns 1 if last expr is 0 */
}

/* ---------- builtin_getopts ---------- */

static int builtin_getopts(shell_state_t *state, int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "bash: getopts: usage: getopts optstring name\n");
        return 1;
    }

    const char *optstring = argv[1];
    const char *varname = argv[2];

    const char *optind_str = shell_get_var(state, "OPTIND");
    int optind = optind_str ? atoi(optind_str) : 1;

    /* Get the argument to parse (from positional params) */
    char **args = state->positional;
    int nargs = state->positional_count;

    if (argc > 3) {
        /* Extra args override positional params */
        args = argv + 3;
        nargs = argc - 3;
    }

    if (optind < 1 || optind > nargs) {
        shell_set_var(state, varname, "?");
        return 1;
    }

    const char *current = args[optind - 1];
    if (!current || current[0] != '-' || current[1] == '\0' ||
        strcmp(current, "--") == 0) {
        shell_set_var(state, varname, "?");
        return 1;
    }

    /* Find the option character */
    char opt_char = current[1]; /* Simplified: single char options */
    const char *found = strchr(optstring, opt_char);

    char buf[4];
    if (!found) {
        /* Unknown option */
        buf[0] = '?';
        buf[1] = '\0';
        shell_set_var(state, varname, buf);
        shell_set_var(state, "OPTARG", "");
        fprintf(stderr, "bash: getopts: illegal option -- %c\n", opt_char);
    } else {
        buf[0] = opt_char;
        buf[1] = '\0';
        shell_set_var(state, varname, buf);

        /* Check if option requires argument */
        if (found[1] == ':') {
            if (current[2]) {
                /* Argument is rest of current word */
                shell_set_var(state, "OPTARG", current + 2);
            } else if (optind < nargs) {
                /* Argument is next word */
                optind++;
                shell_set_var(state, "OPTARG", args[optind - 1]);
            } else {
                fprintf(stderr, "bash: getopts: option requires argument -- %c\n",
                        opt_char);
                buf[0] = '?';
                shell_set_var(state, varname, buf);
            }
        }
    }

    optind++;
    snprintf(buf, sizeof(buf), "%d", optind);
    shell_set_var(state, "OPTIND", buf);
    return 0;
}

/* ---------- builtin_umask ---------- */

static int builtin_umask(shell_state_t *state, int argc, char **argv)
{
    (void)state;

    if (argc < 2) {
        mode_t mask = umask(0);
        umask(mask);
        printf("%04o\n", (unsigned int)mask);
        return 0;
    }

    /* Parse octal */
    mode_t newmask = (mode_t)strtol(argv[1], NULL, 8);
    umask(newmask);
    return 0;
}

/* ---------- builtin_wait ---------- */

static int builtin_wait(shell_state_t *state, int argc, char **argv)
{
    if (argc < 2) {
        /* Wait for all background jobs */
        int status = 0;
        for (int i = 0; i < MAX_JOBS; i++) {
            if (state->jobs[i].pgid > 0 &&
                state->jobs[i].status == JOB_RUNNING) {
                int wstatus;
                waitpid(state->jobs[i].pgid, &wstatus, 0);
                if (WIFEXITED(wstatus))
                    status = WEXITSTATUS(wstatus);
                state->jobs[i].status = JOB_DONE;
            }
        }
        return status;
    }

    /* Wait for specific pid */
    pid_t pid = (pid_t)atoi(argv[1]);
    int wstatus;
    pid_t wp = waitpid(pid, &wstatus, 0);
    if (wp < 0) {
        fprintf(stderr, "bash: wait: pid %d is not a child of this shell\n",
                (int)pid);
        return 127;
    }

    if (WIFEXITED(wstatus))
        return WEXITSTATUS(wstatus);
    if (WIFSIGNALED(wstatus))
        return 128 + WTERMSIG(wstatus);
    return 0;
}

/* ---------- builtin_kill ---------- */

static int builtin_kill(shell_state_t *state, int argc, char **argv)
{
    (void)state;
    int sig = SIGTERM;
    int start = 1;

    if (argc < 2) {
        fprintf(stderr, "bash: kill: usage: kill [-s sigspec | -n signum | -sigspec] pid ...\n");
        return 1;
    }

    /* Parse signal */
    if (argv[1][0] == '-') {
        const char *sigstr = argv[1] + 1;

        if (strcmp(sigstr, "l") == 0 || strcmp(sigstr, "L") == 0) {
            /* List signals */
            printf(" 1) SIGHUP\t 2) SIGINT\t 3) SIGQUIT\t 4) SIGILL\n");
            printf(" 5) SIGTRAP\t 6) SIGABRT\t 7) SIGEMT\t 8) SIGFPE\n");
            printf(" 9) SIGKILL\t10) SIGBUS\t11) SIGSEGV\t12) SIGSYS\n");
            printf("13) SIGPIPE\t14) SIGALRM\t15) SIGTERM\t16) SIGURG\n");
            printf("17) SIGSTOP\t18) SIGTSTP\t19) SIGCONT\t20) SIGCHLD\n");
            printf("21) SIGTTIN\t22) SIGTTOU\t23) SIGIO\t24) SIGXCPU\n");
            printf("25) SIGXFSZ\t26) SIGVTALRM\t27) SIGPROF\t28) SIGWINCH\n");
            printf("29) SIGINFO\t30) SIGUSR1\t31) SIGUSR2\n");
            return 0;
        }

        if (strcmp(sigstr, "s") == 0 && argc > 2) {
            sigstr = argv[2];
            start = 3;
        } else if (strcmp(sigstr, "n") == 0 && argc > 2) {
            sig = atoi(argv[2]);
            start = 3;
            goto do_kill;
        } else {
            start = 2;
        }

        /* Parse signal name or number */
        if (sigstr[0] >= '0' && sigstr[0] <= '9') {
            sig = atoi(sigstr);
        } else {
            const char *name = sigstr;
            if (strncmp(name, "SIG", 3) == 0) name += 3;

            if (strcmp(name, "HUP") == 0) sig = SIGHUP;
            else if (strcmp(name, "INT") == 0) sig = SIGINT;
            else if (strcmp(name, "QUIT") == 0) sig = SIGQUIT;
            else if (strcmp(name, "KILL") == 0) sig = SIGKILL;
            else if (strcmp(name, "TERM") == 0) sig = SIGTERM;
            else if (strcmp(name, "STOP") == 0) sig = SIGTSTP;
            else if (strcmp(name, "TSTP") == 0) sig = SIGTSTP;
            else if (strcmp(name, "CONT") == 0) sig = SIGCONT;
            else if (strcmp(name, "CHLD") == 0) sig = SIGCHLD;
            else if (strcmp(name, "USR1") == 0) sig = SIGUSR1;
            else if (strcmp(name, "USR2") == 0) sig = SIGUSR2;
            else if (strcmp(name, "PIPE") == 0) sig = SIGPIPE;
            else if (strcmp(name, "ALRM") == 0) sig = SIGALRM;
            else {
                fprintf(stderr, "bash: kill: %s: invalid signal\n", sigstr);
                return 1;
            }
        }
    }

do_kill:
    for (int i = start; i < argc; i++) {
        /* Handle %job_id */
        if (argv[i][0] == '%') {
            int job_id = atoi(argv[i] + 1);
            int found = 0;
            for (int j = 0; j < MAX_JOBS; j++) {
                if (state->jobs[j].id == job_id && state->jobs[j].pgid > 0) {
                    kill(-state->jobs[j].pgid, sig);
                    found = 1;
                    break;
                }
            }
            if (!found)
                fprintf(stderr, "bash: kill: %%%d: no such job\n", job_id);
        } else {
            pid_t pid = (pid_t)atoi(argv[i]);
            if (kill(pid, sig) < 0) {
                fprintf(stderr, "bash: kill: (%d) - %s\n", (int)pid,
                        strerror(errno));
            }
        }
    }
    return 0;
}

/* ---------- builtin_jobs ---------- */

static int builtin_jobs(shell_state_t *state, int argc, char **argv)
{
    int show_pids = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0) show_pids = 1;
    }

    for (int i = 0; i < MAX_JOBS; i++) {
        if (state->jobs[i].pgid == 0) continue;

        const char *status_str = "Running";
        switch (state->jobs[i].status) {
        case JOB_RUNNING:    status_str = "Running"; break;
        case JOB_STOPPED:    status_str = "Stopped"; break;
        case JOB_DONE:       status_str = "Done"; break;
        case JOB_TERMINATED: status_str = "Terminated"; break;
        }

        if (show_pids)
            printf("[%d] %d %-12s %s\n", state->jobs[i].id,
                   (int)state->jobs[i].pgid, status_str,
                   state->jobs[i].command ? state->jobs[i].command : "");
        else
            printf("[%d] %-12s %s\n", state->jobs[i].id, status_str,
                   state->jobs[i].command ? state->jobs[i].command : "");
    }
    return 0;
}

/* ---------- builtin_fg ---------- */

static int builtin_fg(shell_state_t *state, int argc, char **argv)
{
    int job_id = -1;

    if (argc > 1) {
        const char *arg = argv[1];
        if (arg[0] == '%') arg++;
        job_id = atoi(arg);
    }

    /* Find the job */
    int idx = -1;
    if (job_id >= 0) {
        for (int i = 0; i < MAX_JOBS; i++) {
            if (state->jobs[i].id == job_id && state->jobs[i].pgid > 0) {
                idx = i;
                break;
            }
        }
    } else {
        /* Find most recent background/stopped job */
        int max_id = -1;
        for (int i = 0; i < MAX_JOBS; i++) {
            if (state->jobs[i].pgid > 0 &&
                (state->jobs[i].status == JOB_RUNNING ||
                 state->jobs[i].status == JOB_STOPPED) &&
                state->jobs[i].id > max_id) {
                max_id = state->jobs[i].id;
                idx = i;
            }
        }
    }

    if (idx < 0) {
        fprintf(stderr, "bash: fg: no current job\n");
        return 1;
    }

    job_t *job = &state->jobs[idx];
    printf("%s\n", job->command ? job->command : "");

    /* Give terminal to job */
    if (state->terminal_fd >= 0)
        tcsetpgrp(state->terminal_fd, job->pgid);

    /* Send SIGCONT */
    kill(-job->pgid, SIGCONT);
    job->status = JOB_RUNNING;
    job->foreground = 1;

    /* Wait for job */
    int wstatus;
    pid_t wpid;
    do {
        wpid = waitpid(-job->pgid, &wstatus, WUNTRACED);
    } while (wpid < 0 && errno == EINTR);

    /* Restore terminal */
    if (state->terminal_fd >= 0)
        tcsetpgrp(state->terminal_fd, state->shell_pgid);

    if (WIFEXITED(wstatus)) {
        int status = WEXITSTATUS(wstatus);
        job->status = JOB_DONE;
        state->last_exit_status = status;
        return status;
    }
    if (WIFSTOPPED(wstatus)) {
        job->status = JOB_STOPPED;
        fprintf(stderr, "\n[%d]+ Stopped\t%s\n", job->id,
                job->command ? job->command : "");
        return 128 + WSTOPSIG(wstatus);
    }
    if (WIFSIGNALED(wstatus)) {
        job->status = JOB_TERMINATED;
        return 128 + WTERMSIG(wstatus);
    }

    return 0;
}

/* ---------- builtin_bg ---------- */

static int builtin_bg(shell_state_t *state, int argc, char **argv)
{
    int job_id = -1;

    if (argc > 1) {
        const char *arg = argv[1];
        if (arg[0] == '%') arg++;
        job_id = atoi(arg);
    }

    int idx = -1;
    if (job_id >= 0) {
        for (int i = 0; i < MAX_JOBS; i++) {
            if (state->jobs[i].id == job_id && state->jobs[i].pgid > 0) {
                idx = i;
                break;
            }
        }
    } else {
        /* Find most recent stopped job */
        int max_id = -1;
        for (int i = 0; i < MAX_JOBS; i++) {
            if (state->jobs[i].pgid > 0 &&
                state->jobs[i].status == JOB_STOPPED &&
                state->jobs[i].id > max_id) {
                max_id = state->jobs[i].id;
                idx = i;
            }
        }
    }

    if (idx < 0) {
        fprintf(stderr, "bash: bg: no current job\n");
        return 1;
    }

    job_t *job = &state->jobs[idx];
    printf("[%d]+ %s &\n", job->id, job->command ? job->command : "");

    kill(-job->pgid, SIGCONT);
    job->status = JOB_RUNNING;
    job->foreground = 0;
    return 0;
}

/* ---------- builtin_enable ---------- */

/* Simplified: just list builtins */
static char *disabled_builtins[64];
static int  n_disabled = 0;

static int builtin_enable(shell_state_t *state, int argc, char **argv)
{
    (void)state;

    if (argc < 2) {
        /* List all enabled builtins */
        printf("enable .\nenable :\nenable [\nenable alias\nenable bg\n");
        printf("enable break\nenable cd\nenable continue\nenable declare\n");
        printf("enable echo\nenable enable\nenable eval\nenable exec\n");
        printf("enable exit\nenable export\nenable false\nenable fg\n");
        printf("enable getopts\nenable hash\nenable jobs\nenable kill\n");
        printf("enable let\nenable local\nenable printf\nenable pwd\n");
        printf("enable read\nenable readonly\nenable return\nenable set\n");
        printf("enable shift\nenable source\nenable test\nenable trap\n");
        printf("enable true\nenable type\nenable umask\nenable unalias\n");
        printf("enable unset\nenable wait\n");
        return 0;
    }

    int disable = 0;
    int start = 1;
    if (strcmp(argv[1], "-n") == 0) {
        disable = 1;
        start = 2;
    }

    for (int i = start; i < argc; i++) {
        if (disable) {
            if (n_disabled < 64)
                disabled_builtins[n_disabled++] = strdup(argv[i]);
        } else {
            /* Re-enable */
            for (int j = 0; j < n_disabled; j++) {
                if (disabled_builtins[j] &&
                    strcmp(disabled_builtins[j], argv[i]) == 0) {
                    free(disabled_builtins[j]);
                    disabled_builtins[j] = disabled_builtins[--n_disabled];
                    break;
                }
            }
        }
    }
    return 0;
}

/* ---------- Builtin dispatch table ---------- */

typedef struct {
    const char   *name;
    builtin_fn_t  fn;
} builtin_entry_t;

static const builtin_entry_t builtin_table[] = {
    { ":",          builtin_colon },
    { ".",          builtin_source },
    { "[",          builtin_test },
    { "alias",      builtin_alias },
    { "bg",         builtin_bg },
    { "break",      builtin_break },
    { "cd",         builtin_cd },
    { "continue",   builtin_continue },
    { "declare",    builtin_declare },
    { "echo",       builtin_echo },
    { "enable",     builtin_enable },
    { "eval",       builtin_eval },
    { "exec",       builtin_exec },
    { "exit",       builtin_exit },
    { "export",     builtin_export },
    { "false",      builtin_false },
    { "fg",         builtin_fg },
    { "getopts",    builtin_getopts },
    { "hash",       builtin_hash },
    { "jobs",       builtin_jobs },
    { "kill",       builtin_kill },
    { "let",        builtin_let },
    { "local",      builtin_local },
    { "printf",     builtin_printf },
    { "pwd",        builtin_pwd },
    { "read",       builtin_read },
    { "readonly",   builtin_readonly },
    { "return",     builtin_return },
    { "set",        builtin_set },
    { "shift",      builtin_shift },
    { "source",     builtin_source },
    { "test",       builtin_test },
    { "trap",       builtin_trap },
    { "true",       builtin_true },
    { "type",       builtin_type },
    { "umask",      builtin_umask },
    { "unalias",    builtin_unalias },
    { "unset",      builtin_unset },
    { "wait",       builtin_wait },
    { NULL, NULL }
};

/* ---------- Public API ---------- */

int is_builtin(const char *name)
{
    if (!name) return 0;

    /* Check if disabled */
    for (int i = 0; i < n_disabled; i++) {
        if (disabled_builtins[i] && strcmp(disabled_builtins[i], name) == 0)
            return 0;
    }

    for (int i = 0; builtin_table[i].name; i++) {
        if (strcmp(builtin_table[i].name, name) == 0)
            return 1;
    }
    return 0;
}

builtin_fn_t get_builtin(const char *name)
{
    if (!name) return NULL;

    for (int i = 0; builtin_table[i].name; i++) {
        if (strcmp(builtin_table[i].name, name) == 0)
            return builtin_table[i].fn;
    }
    return NULL;
}
