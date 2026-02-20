/*
 * Kiseki OS - Bash-compatible Shell
 *
 * Main entry point: option parsing, startup file sourcing,
 * and the interactive read-eval-print loop.
 */

#include "shell.h"
#include "parser.h"
#include "expand.h"

/* ---------- Global shell state ---------- */

shell_state_t *g_shell = NULL;

/* ---------- Forward declarations ---------- */

/* variables.c */
void    var_init(shell_state_t *state);

/* execute.c */
int     shell_execute(shell_state_t *state, ast_node_t *node);

/* jobs.c */
void    job_init(shell_state_t *state);
void    job_notify(shell_state_t *state);

/* history.c */
void        history_add(const char *line);
void        history_load(const char *filename);
void        history_save(const char *filename);
char       *history_expand(const char *line);

/* readline.c */
char   *read_line(shell_state_t *state, const char *prompt);

/* builtins.c */
int     is_builtin(const char *name);

/* ---------- Source a file if it exists ---------- */

static void source_file(shell_state_t *state, const char *path)
{
    if (access(path, R_OK) != 0)
        return;

    FILE *fp = fopen(path, "r");
    if (!fp) return;

    /* Read the entire file into a buffer so multi-line constructs
     * (if/then/fi, for/do/done, etc.) are parsed correctly. */
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (size <= 0) {
        fclose(fp);
        return;
    }

    char *buf = malloc((size_t)size + 1);
    if (!buf) {
        fclose(fp);
        return;
    }

    size_t nread = fread(buf, 1, (size_t)size, fp);
    buf[nread] = '\0';
    fclose(fp);

    /* Parse and execute the entire file as one script */
    ast_node_t *ast = parse_input(buf);
    if (ast) {
        shell_execute(state, ast);
        ast_free(ast);
    }

    free(buf);
}

/* ---------- Execute a command string (-c) ---------- */

static int exec_string(shell_state_t *state, const char *cmd)
{
    ast_node_t *ast = parse_input(cmd);
    if (!ast) return 1;

    int status = shell_execute(state, ast);
    ast_free(ast);
    return status;
}

/* ---------- Execute a script file ---------- */

static int exec_script(shell_state_t *state, const char *filename)
{
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "bash: %s: No such file or directory\n", filename);
        return 127;
    }

    /* Read the entire file into a buffer */
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

    /* Skip shebang line if present */
    char *script = buf;
    if (nread >= 2 && script[0] == '#' && script[1] == '!') {
        /* Skip to end of first line */
        while (*script && *script != '\n')
            script++;
        if (*script == '\n')
            script++;
    }

    /* Parse and execute the entire script */
    int status = 0;
    ast_node_t *ast = parse_input(script);
    if (ast) {
        status = shell_execute(state, ast);
        ast_free(ast);
    }

    free(buf);
    return status;
}

/* ---------- Handle alias expansion ---------- */

static char *expand_aliases(shell_state_t *state, const char *line)
{
    /* Simple alias expansion: check if first word is an alias */
    if (!line || !line[0]) return strdup(line ? line : "");

    /* Skip leading whitespace */
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (!*p) return strdup(line);

    /* Extract first word */
    const char *word_start = p;
    while (*p && *p != ' ' && *p != '\t' && *p != ';' && *p != '|' &&
           *p != '&' && *p != '(' && *p != ')' && *p != '<' && *p != '>')
        p++;

    size_t wlen = (size_t)(p - word_start);
    char word[256];
    if (wlen >= sizeof(word)) return strdup(line);
    memcpy(word, word_start, wlen);
    word[wlen] = '\0';

    const char *alias_val = shell_get_alias(state, word);
    if (!alias_val) return strdup(line);

    /* Replace first word with alias value */
    size_t prefix_len = (size_t)(word_start - line);
    size_t alias_len = strlen(alias_val);
    size_t rest_len = strlen(p);
    size_t total = prefix_len + alias_len + rest_len + 1;

    char *result = malloc(total);
    if (!result) return strdup(line);

    if (prefix_len > 0) memcpy(result, line, prefix_len);
    memcpy(result + prefix_len, alias_val, alias_len);
    memcpy(result + prefix_len + alias_len, p, rest_len);
    result[prefix_len + alias_len + rest_len] = '\0';

    return result;
}

/* ---------- Expand PS1/PS2 prompt escapes ---------- */

/*
 * Process bash prompt escape sequences in PS1/PS2.
 * Supported: \u (user), \h (hostname), \H (full hostname),
 *            \w (cwd), \W (basename of cwd), \$ (# if root, $ otherwise),
 *            \n (newline), \r (CR), \a (bell), \e (ESC),
 *            \[ (begin non-printing), \] (end non-printing),
 *            \\ (literal backslash), \0NNN (octal), \d (date),
 *            \t (24h HH:MM:SS), \T (12h HH:MM:SS), \@ (12h am/pm),
 *            \! (history number), \# (command number), \j (jobs),
 *            \s (shell name), \v (version), \V (version+patch)
 */
static char *expand_prompt(shell_state_t *state, const char *ps)
{
    if (!ps) return strdup("$ ");

    /* Allocate generous output buffer */
    size_t cap = strlen(ps) * 4 + 256;
    char *out = malloc(cap);
    if (!out) return strdup(ps);
    size_t olen = 0;

#define PROMPT_PUSH(c) do { \
    if (olen + 1 < cap) out[olen++] = (c); \
} while(0)
#define PROMPT_APPEND(s) do { \
    const char *_s = (s); \
    while (*_s && olen + 1 < cap) out[olen++] = *_s++; \
} while(0)

    for (size_t i = 0; ps[i]; i++) {
        if (ps[i] == '\\' && ps[i + 1]) {
            i++;
            switch (ps[i]) {
            case 'u': {
                const char *user = shell_get_var(state, "USER");
                if (!user) user = "user";
                PROMPT_APPEND(user);
                break;
            }
            case 'h': case 'H': {
                char hostname[64];
                const char *hn = shell_get_var(state, "HOSTNAME");
                if (!hn) {
                    /* Try gethostname — may not be available, fallback */
                    hostname[0] = '\0';
                    gethostname(hostname, sizeof(hostname));
                    if (hostname[0] == '\0')
                        strcpy(hostname, "kiseki");
                    hn = hostname;
                }
                if (ps[i] == 'h') {
                    /* Short hostname: up to first '.' */
                    const char *dot = strchr(hn, '.');
                    if (dot) {
                        size_t n = (size_t)(dot - hn);
                        for (size_t j = 0; j < n && olen + 1 < cap; j++)
                            out[olen++] = hn[j];
                    } else {
                        PROMPT_APPEND(hn);
                    }
                } else {
                    PROMPT_APPEND(hn);
                }
                break;
            }
            case 'w': case 'W': {
                char cwd[PATH_MAX];
                if (!getcwd(cwd, sizeof(cwd)))
                    strcpy(cwd, "?");
                if (ps[i] == 'w') {
                    /* Replace $HOME prefix with ~ */
                    const char *home = shell_get_var(state, "HOME");
                    if (home && home[0] && strncmp(cwd, home, strlen(home)) == 0) {
                        PROMPT_PUSH('~');
                        PROMPT_APPEND(cwd + strlen(home));
                    } else {
                        PROMPT_APPEND(cwd);
                    }
                } else {
                    /* Just the basename */
                    const char *base = strrchr(cwd, '/');
                    if (base && base[1])
                        PROMPT_APPEND(base + 1);
                    else
                        PROMPT_APPEND(cwd);
                }
                break;
            }
            case '$':
                /* # if uid==0 (root), $ otherwise */
                PROMPT_PUSH(getuid() == 0 ? '#' : '$');
                break;
            case 'n':
                PROMPT_PUSH('\n');
                break;
            case 'r':
                PROMPT_PUSH('\r');
                break;
            case 'a':
                PROMPT_PUSH('\007');
                break;
            case 'e':
                PROMPT_PUSH('\033');
                break;
            case '\\':
                PROMPT_PUSH('\\');
                break;
            case '[':
                /* Begin non-printing sequence — terminal ignores these bytes
                 * for cursor positioning. We just skip the markers. */
                break;
            case ']':
                break;
            case 's': {
                /* Shell name (basename of $0) */
                const char *s = state->argv0 ? state->argv0 : "bash";
                const char *base = strrchr(s, '/');
                PROMPT_APPEND(base ? base + 1 : s);
                break;
            }
            case 'j': {
                /* Number of jobs */
                char buf[16];
                snprintf(buf, sizeof(buf), "%d", state->njobs);
                PROMPT_APPEND(buf);
                break;
            }
            case '!': case '#': {
                /* History/command number — just use line_number */
                char buf[16];
                snprintf(buf, sizeof(buf), "%d", state->line_number);
                PROMPT_APPEND(buf);
                break;
            }
            case '0': case '1': case '2': case '3':
            case '4': case '5': case '6': case '7': {
                /* Octal character: \0NNN */
                int val = ps[i] - '0';
                for (int k = 0; k < 2 && ps[i + 1] >= '0' && ps[i + 1] <= '7'; k++) {
                    i++;
                    val = val * 8 + (ps[i] - '0');
                }
                PROMPT_PUSH((char)val);
                break;
            }
            default:
                /* Unknown escape — output as-is */
                PROMPT_PUSH('\\');
                PROMPT_PUSH(ps[i]);
                break;
            }
        } else {
            PROMPT_PUSH(ps[i]);
        }
    }

    out[olen] = '\0';

#undef PROMPT_PUSH
#undef PROMPT_APPEND

    return out;
}

/* ---------- Interactive SIGINT handler ---------- */

static volatile int got_sigint = 0;

static void interactive_sigint_handler(int sig)
{
    (void)sig;
    got_sigint = 1;
    /* The readline will handle this */
}

/* ---------- Interactive loop ---------- */

static int interactive_loop(shell_state_t *state)
{
    int status = 0;

    while (state->running) {
        /* Notify about completed background jobs */
        job_notify(state);

        /* Get prompt and expand escape sequences */
        const char *ps1_raw = shell_get_var(state, "PS1");
        if (!ps1_raw) ps1_raw = "\\$ ";
        char *ps1 = expand_prompt(state, ps1_raw);

        /* Read a line */
        got_sigint = 0;
        char *line = read_line(state, ps1);
        free(ps1);

        if (!line) {
            /* EOF (Ctrl-D) */
            if (state->opts.interactive)
                fprintf(stderr, "\nexit\n");
            break;
        }

        if (line[0] == '\0')
            continue;

        /* History expansion */
        char *expanded = history_expand(line);
        if (!expanded) continue; /* Error in expansion */

        /* Add to history */
        history_add(expanded);

        /* Handle line continuation (trailing backslash) */
        char full_line[MAX_LINE * 4];
        strncpy(full_line, expanded, sizeof(full_line) - 1);
        full_line[sizeof(full_line) - 1] = '\0';
        free(expanded);

        while (strlen(full_line) > 0 &&
               full_line[strlen(full_line) - 1] == '\\') {
            full_line[strlen(full_line) - 1] = '\0';

            const char *ps2_raw = shell_get_var(state, "PS2");
            if (!ps2_raw) ps2_raw = "> ";
            char *ps2 = expand_prompt(state, ps2_raw);

            char *cont = read_line(state, ps2);
            free(ps2);
            if (!cont) break;

            size_t cur_len = strlen(full_line);
            size_t cont_len = strlen(cont);
            if (cur_len + cont_len < sizeof(full_line) - 1) {
                memcpy(full_line + cur_len, cont, cont_len);
                full_line[cur_len + cont_len] = '\0';
            }
        }

        /* Expand aliases */
        char *aliased = expand_aliases(state, full_line);

        /* Verbose mode */
        if (state->opts.verbose)
            fprintf(stderr, "%s\n", aliased);

        /* Parse and execute */
        state->line_number++;
        ast_node_t *ast = parse_input(aliased);
        free(aliased);

        if (ast) {
            if (!state->opts.noexec)
                status = shell_execute(state, ast);
            ast_free(ast);
        }

        /* Check errexit */
        if (state->opts.errexit && status != 0 && state->running) {
            /* In interactive mode, don't exit on errexit */
            if (!state->opts.interactive) {
                state->running = 0;
            }
        }
    }

    return status;
}

/* ---------- Shell init ---------- */

shell_state_t *shell_init(int argc, char **argv)
{
    (void)argc;

    shell_state_t *state = calloc(1, sizeof(shell_state_t));
    if (!state) {
        fprintf(stderr, "bash: failed to allocate shell state\n");
        _exit(2);
    }

    state->running = 1;
    state->shell_pid = getpid();
    state->terminal_fd = -1;
    state->next_job_id = 1;

    /* Set $0 */
    state->argv0 = strdup(argv ? argv[0] : "bash");

    return state;
}

/* ---------- Shell cleanup ---------- */

void shell_cleanup(shell_state_t *state)
{
    if (!state) return;

    /* Free variables */
    for (int i = 0; i < state->nvars; i++) {
        free(state->vars[i].name);
        free(state->vars[i].value);
    }

    /* Free functions */
    for (int i = 0; i < state->nfuncs; i++)
        free(state->funcs[i].name);

    /* Free aliases */
    for (int i = 0; i < state->naliases; i++) {
        free(state->aliases[i].name);
        free(state->aliases[i].value);
    }

    /* Free jobs */
    for (int i = 0; i < MAX_JOBS; i++) {
        if (state->jobs[i].pgid > 0) {
            free(state->jobs[i].pids);
            free(state->jobs[i].statuses);
            free(state->jobs[i].command);
        }
    }

    /* Free positional params */
    if (state->positional) {
        for (int i = 0; i < state->positional_count; i++)
            free(state->positional[i]);
        free(state->positional);
    }

    free(state->argv0);
    free(state);
}

/* ---------- Usage ---------- */

static void print_usage(void)
{
    fprintf(stderr,
            "Usage: bash [options] [file [arguments]]\n"
            "  -c string    Execute commands from string\n"
            "  -i           Force interactive mode\n"
            "  -l, --login  Make this a login shell\n"
            "  -s           Read commands from standard input\n"
            "  -x           Print commands before execution\n"
            "  -e           Exit on error\n"
            "  -v, --verbose Print input lines as they are read\n"
            "  --norc       Don't read ~/.bashrc\n"
            "  --noprofile  Don't read profile files\n"
            );
}

/* ---------- MAIN ---------- */

int main(int argc, char **argv, char **envp)
{
    (void)envp;

    /* Initialize shell state */
    shell_state_t *state = shell_init(argc, argv);
    g_shell = state;

    /* Parse command-line options */
    const char *cmd_string = NULL;
    const char *script_file = NULL;
    int force_interactive = 0;
    int from_stdin = 0;
    int norc = 0;
    int noprofile = 0;
    int script_arg_start = 0;

    int i = 1;
    while (i < argc) {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            cmd_string = argv[i + 1];
            i += 2;
            /* Remaining args are positional params */
            if (i < argc) {
                state->argv0 = strdup(argv[i]);
                i++;
            }
            break;
        } else if (strcmp(argv[i], "-i") == 0) {
            force_interactive = 1;
            i++;
        } else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--login") == 0) {
            state->opts.login = 1;
            i++;
        } else if (strcmp(argv[i], "-s") == 0) {
            from_stdin = 1;
            i++;
        } else if (strcmp(argv[i], "-x") == 0) {
            state->opts.xtrace = 1;
            i++;
        } else if (strcmp(argv[i], "-e") == 0) {
            state->opts.errexit = 1;
            i++;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            state->opts.verbose = 1;
            i++;
        } else if (strcmp(argv[i], "--norc") == 0) {
            norc = 1;
            i++;
        } else if (strcmp(argv[i], "--noprofile") == 0) {
            noprofile = 1;
            i++;
        } else if (strcmp(argv[i], "--help") == 0) {
            print_usage();
            shell_cleanup(state);
            return 0;
        } else if (argv[i][0] == '-' && argv[i][1] == '-' && argv[i][2] == '\0') {
            /* -- end of options */
            i++;
            break;
        } else if (argv[i][0] == '-') {
            /* Combined short options: -ex, -eux, etc. */
            for (int j = 1; argv[i][j]; j++) {
                switch (argv[i][j]) {
                case 'e': state->opts.errexit = 1; break;
                case 'u': state->opts.nounset = 1; break;
                case 'x': state->opts.xtrace = 1; break;
                case 'v': state->opts.verbose = 1; break;
                case 'f': state->opts.noglob = 1; break;
                case 'a': state->opts.allexport = 1; break;
                case 'b': state->opts.notify = 1; break;
                case 'n': state->opts.noexec = 1; break;
                default:
                    fprintf(stderr, "bash: -%c: invalid option\n", argv[i][j]);
                    break;
                }
            }
            i++;
        } else {
            /* Script file */
            script_file = argv[i];
            script_arg_start = i + 1;
            break;
        }
    }

    /* Set positional params from remaining args */
    int pos_start = script_file ? script_arg_start : i;
    if (pos_start < argc) {
        state->positional_count = argc - pos_start;
        state->positional = malloc(sizeof(char *) * state->positional_count);
        for (int j = 0; j < state->positional_count; j++)
            state->positional[j] = strdup(argv[pos_start + j]);
    }

    /* Initialize default variables first */
    var_init(state);

    /* Import environment variables (overrides defaults) */
    shell_import_environ(state);

    /* Determine if interactive */
    if (force_interactive)
        state->opts.interactive = 1;
    else if (!cmd_string && !script_file && isatty(STDIN_FILENO))
        state->opts.interactive = 1;

    /* Check if login shell (argv[0] starts with -) */
    if (argv[0] && argv[0][0] == '-')
        state->opts.login = 1;

    /* Initialize job control */
    job_init(state);

    /* Set up signals for interactive shell */
    if (state->opts.interactive) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sigemptyset(&sa.sa_mask);

        /* Ignore job control signals in the shell itself */
        sa.sa_handler = SIG_IGN;
        sigaction(SIGTSTP, &sa, NULL);
        sigaction(SIGTTIN, &sa, NULL);
        sigaction(SIGTTOU, &sa, NULL);

        /* Handle SIGINT gracefully */
        sa.sa_handler = interactive_sigint_handler;
        sa.sa_flags = 0; /* Don't restart, so read() returns */
        sigaction(SIGINT, &sa, NULL);

        /* Ignore SIGQUIT */
        sa.sa_handler = SIG_IGN;
        sigaction(SIGQUIT, &sa, NULL);

        /* Ignore SIGPIPE */
        sa.sa_handler = SIG_IGN;
        sigaction(SIGPIPE, &sa, NULL);
    }

    /* Source startup files */
    if (state->opts.login && !noprofile) {
        source_file(state, "/etc/profile");

        /* Try in order: .bash_profile, .bash_login, .profile */
        const char *home = shell_get_var(state, "HOME");
        if (home) {
            char path[PATH_MAX];

            snprintf(path, sizeof(path), "%s/.bash_profile", home);
            if (access(path, R_OK) == 0) {
                source_file(state, path);
            } else {
                snprintf(path, sizeof(path), "%s/.bash_login", home);
                if (access(path, R_OK) == 0) {
                    source_file(state, path);
                } else {
                    snprintf(path, sizeof(path), "%s/.profile", home);
                    source_file(state, path);
                }
            }
        }
    }

    if (state->opts.interactive && !norc) {
        const char *home = shell_get_var(state, "HOME");
        if (home) {
            char path[PATH_MAX];
            snprintf(path, sizeof(path), "%s/.bashrc", home);
            source_file(state, path);
        }
    }

    /* Load command history */
    if (state->opts.interactive) {
        const char *home = shell_get_var(state, "HOME");
        if (home) {
            char histfile[PATH_MAX];
            snprintf(histfile, sizeof(histfile), "%s/.bash_history", home);
            history_load(histfile);
        }
    }

    /* Execute based on mode */
    int exit_status = 0;

    if (cmd_string) {
        /* -c: execute command string */
        exit_status = exec_string(state, cmd_string);
    } else if (script_file) {
        /* Script file */
        free(state->argv0);
        state->argv0 = strdup(script_file);
        exit_status = exec_script(state, script_file);
    } else if (from_stdin || !state->opts.interactive) {
        /* Read all of stdin into a buffer, then parse as a complete script.
         * This handles multi-line constructs properly. */
        size_t buf_cap = 4096;
        size_t buf_len = 0;
        char *buf = malloc(buf_cap);
        if (buf) {
            char chunk[1024];
            size_t n;
            while ((n = fread(chunk, 1, sizeof(chunk), stdin)) > 0) {
                if (buf_len + n >= buf_cap) {
                    buf_cap = (buf_len + n) * 2;
                    buf = realloc(buf, buf_cap);
                    if (!buf) break;
                }
                memcpy(buf + buf_len, chunk, n);
                buf_len += n;
            }
            if (buf) {
                buf[buf_len] = '\0';
                ast_node_t *ast = parse_input(buf);
                if (ast) {
                    exit_status = shell_execute(state, ast);
                    ast_free(ast);
                }
                free(buf);
            }
        }
    } else {
        /* Interactive loop */
        exit_status = interactive_loop(state);
    }

    /* Save history */
    if (state->opts.interactive) {
        const char *home = shell_get_var(state, "HOME");
        if (home) {
            char histfile[PATH_MAX];
            snprintf(histfile, sizeof(histfile), "%s/.bash_history", home);
            history_save(histfile);
        }
    }

    /* Final exit status */
    exit_status = state->last_exit_status;

    /* Cleanup */
    shell_cleanup(state);
    g_shell = NULL;

    return exit_status;
}
