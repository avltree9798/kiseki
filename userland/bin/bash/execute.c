/*
 * Kiseki OS - Shell AST Executor
 *
 * Walks the AST produced by the parser and executes commands.
 * Handles pipelines, redirections, builtins, functions, and compound commands.
 */

#include "shell.h"
#include "parser.h"
#include "expand.h"
#include <sys/time.h>

/* ---------- Forward declarations (variables.c) ---------- */

int var_parse_assignment(const char *str, char **name_out, char **value_out);

/* ---------- Forward declarations (builtins.c) ---------- */

typedef int (*builtin_fn_t)(shell_state_t *state, int argc, char **argv);
int         is_builtin(const char *name);
builtin_fn_t get_builtin(const char *name);

/* ---------- Forward declarations (this file) ---------- */

static int exec_node(shell_state_t *state, ast_node_t *node);
static int exec_command(shell_state_t *state, ast_node_t *node);
static int exec_pipeline(shell_state_t *state, ast_node_t *node);
static int exec_if(shell_state_t *state, ast_node_t *node);
static int exec_for(shell_state_t *state, ast_node_t *node);
static int exec_while(shell_state_t *state, ast_node_t *node, int until);
static int exec_case(shell_state_t *state, ast_node_t *node);
static int exec_subshell(shell_state_t *state, ast_node_t *node);
static int exec_brace_group(shell_state_t *state, ast_node_t *node);
static int exec_function_def(shell_state_t *state, ast_node_t *node);
int exec_function_call(shell_state_t *state, const char *name,
                       int argc, char **argv);

/* ---------- Redirect save/restore ---------- */

#define MAX_SAVED_FDS 32

typedef struct {
    int original_fd;    /* The fd we overwrote */
    int saved_copy;     /* dup'd copy, or -1 if was closed */
} saved_fd_t;

typedef struct {
    saved_fd_t fds[MAX_SAVED_FDS];
    int        count;
} redir_state_t;

static redir_state_t *setup_redirects(redirect_t *redirects, shell_state_t *state)
{
    if (!redirects) return NULL;

    redir_state_t *rs = malloc(sizeof(redir_state_t));
    if (!rs) return NULL;
    rs->count = 0;

    for (redirect_t *r = redirects; r; r = r->next) {
        int src_fd = r->fd;
        int target_fd = -1;
        char *expanded = NULL;

        /* Expand the target filename/fd */
        if (r->target) {
            expanded = expand_word_nosplit(r->target, state);
            if (!expanded) expanded = strdup(r->target);
        }

        switch (r->type) {
        case REDIR_INPUT:
            if (src_fd < 0) src_fd = STDIN_FILENO;
            target_fd = open(expanded, O_RDONLY, 0);
            if (target_fd < 0) {
                fprintf(stderr, "bash: %s: No such file or directory\n",
                        expanded);
                free(expanded);
                goto fail;
            }
            break;

        case REDIR_OUTPUT:
            if (src_fd < 0) src_fd = STDOUT_FILENO;
            target_fd = open(expanded, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (target_fd < 0) {
                fprintf(stderr, "bash: %s: Cannot create file\n", expanded);
                free(expanded);
                goto fail;
            }
            break;

        case REDIR_APPEND:
            if (src_fd < 0) src_fd = STDOUT_FILENO;
            target_fd = open(expanded, O_WRONLY | O_CREAT | O_APPEND, 0644);
            if (target_fd < 0) {
                fprintf(stderr, "bash: %s: Cannot open for append\n", expanded);
                free(expanded);
                goto fail;
            }
            break;

        case REDIR_CLOBBER:
            if (src_fd < 0) src_fd = STDOUT_FILENO;
            target_fd = open(expanded, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (target_fd < 0) {
                fprintf(stderr, "bash: %s: Cannot create file\n", expanded);
                free(expanded);
                goto fail;
            }
            break;

        case REDIR_RDWR:
            if (src_fd < 0) src_fd = STDIN_FILENO;
            target_fd = open(expanded, O_RDWR | O_CREAT, 0644);
            if (target_fd < 0) {
                fprintf(stderr, "bash: %s: Cannot open\n", expanded);
                free(expanded);
                goto fail;
            }
            break;

        case REDIR_HEREDOC:
            if (src_fd < 0) src_fd = STDIN_FILENO;
            {
                /* Create a pipe, write heredoc content, use read end */
                int pipefd[2];
                if (pipe(pipefd) < 0) {
                    free(expanded);
                    goto fail;
                }
                const char *content = expanded ? expanded : "";
                size_t clen = strlen(content);
                write(pipefd[1], content, clen);
                close(pipefd[1]);
                target_fd = pipefd[0];
            }
            break;

        case REDIR_DUP_INPUT:
            if (src_fd < 0) src_fd = STDIN_FILENO;
            if (expanded && strcmp(expanded, "-") == 0) {
                /* Save and close */
                if (rs->count < MAX_SAVED_FDS) {
                    int saved = dup(src_fd);
                    rs->fds[rs->count].original_fd = src_fd;
                    rs->fds[rs->count].saved_copy = saved;
                    rs->count++;
                }
                close(src_fd);
                free(expanded);
                continue;
            }
            target_fd = expanded ? atoi(expanded) : -1;
            if (target_fd < 0) {
                fprintf(stderr, "bash: %s: Bad file descriptor\n",
                        expanded ? expanded : "");
                free(expanded);
                goto fail;
            }
            /* dup2 the target to src_fd */
            if (rs->count < MAX_SAVED_FDS) {
                int saved = dup(src_fd);
                rs->fds[rs->count].original_fd = src_fd;
                rs->fds[rs->count].saved_copy = saved;
                rs->count++;
            }
            dup2(target_fd, src_fd);
            free(expanded);
            continue;

        case REDIR_DUP_OUTPUT:
            if (src_fd < 0) src_fd = STDOUT_FILENO;
            if (expanded && strcmp(expanded, "-") == 0) {
                if (rs->count < MAX_SAVED_FDS) {
                    int saved = dup(src_fd);
                    rs->fds[rs->count].original_fd = src_fd;
                    rs->fds[rs->count].saved_copy = saved;
                    rs->count++;
                }
                close(src_fd);
                free(expanded);
                continue;
            }
            target_fd = expanded ? atoi(expanded) : -1;
            if (target_fd < 0) {
                fprintf(stderr, "bash: %s: Bad file descriptor\n",
                        expanded ? expanded : "");
                free(expanded);
                goto fail;
            }
            if (rs->count < MAX_SAVED_FDS) {
                int saved = dup(src_fd);
                rs->fds[rs->count].original_fd = src_fd;
                rs->fds[rs->count].saved_copy = saved;
                rs->count++;
            }
            dup2(target_fd, src_fd);
            free(expanded);
            continue;
        }

        free(expanded);

        if (target_fd < 0) continue;

        /* Save original fd */
        if (rs->count < MAX_SAVED_FDS) {
            int saved = dup(src_fd);
            rs->fds[rs->count].original_fd = src_fd;
            rs->fds[rs->count].saved_copy = saved;
            rs->count++;
        }

        dup2(target_fd, src_fd);
        close(target_fd);
    }

    return rs;

fail:
    /* Restore what we've done so far */
    for (int i = rs->count - 1; i >= 0; i--) {
        if (rs->fds[i].saved_copy >= 0) {
            dup2(rs->fds[i].saved_copy, rs->fds[i].original_fd);
            close(rs->fds[i].saved_copy);
        }
    }
    free(rs);
    return (redir_state_t *)-1; /* Error sentinel */
}

static void restore_redirects(redir_state_t *rs)
{
    if (!rs || rs == (redir_state_t *)-1) return;

    for (int i = rs->count - 1; i >= 0; i--) {
        if (rs->fds[i].saved_copy >= 0) {
            dup2(rs->fds[i].saved_copy, rs->fds[i].original_fd);
            close(rs->fds[i].saved_copy);
        } else {
            close(rs->fds[i].original_fd);
        }
    }
    free(rs);
}

/* ---------- PATH search ---------- */

char *find_in_path(const char *name, const char *path_env)
{
    if (!name || !name[0]) return NULL;

    /* If name contains a slash, use it directly */
    if (strchr(name, '/')) {
        if (access(name, X_OK) == 0)
            return strdup(name);
        return NULL;
    }

    if (!path_env || !path_env[0]) return NULL;

    char pathbuf[PATH_MAX];
    char *path_copy = strdup(path_env);
    if (!path_copy) return NULL;

    char *saveptr = NULL;
    char *dir = strtok_r(path_copy, ":", &saveptr);

    while (dir) {
        size_t dlen = strlen(dir);
        size_t nlen = strlen(name);

        if (dlen + 1 + nlen + 1 > sizeof(pathbuf)) {
            dir = strtok_r(NULL, ":", &saveptr);
            continue;
        }

        memcpy(pathbuf, dir, dlen);
        pathbuf[dlen] = '/';
        memcpy(pathbuf + dlen + 1, name, nlen);
        pathbuf[dlen + 1 + nlen] = '\0';

        if (access(pathbuf, X_OK) == 0) {
            free(path_copy);
            return strdup(pathbuf);
        }

        dir = strtok_r(NULL, ":", &saveptr);
    }

    free(path_copy);
    return NULL;
}

/* ---------- Command hash table (simplified) ---------- */

#define HASH_SIZE 64

typedef struct hash_entry {
    char *name;
    char *path;
    int   hits;
    struct hash_entry *next;
} hash_entry_t;

static hash_entry_t *hash_table[HASH_SIZE];

static unsigned int hash_str(const char *s)
{
    unsigned int h = 0;
    while (*s) {
        h = h * 31 + (unsigned char)*s;
        s++;
    }
    return h % HASH_SIZE;
}

static char *hash_lookup(const char *name)
{
    unsigned int h = hash_str(name);
    for (hash_entry_t *e = hash_table[h]; e; e = e->next) {
        if (strcmp(e->name, name) == 0) {
            e->hits++;
            return e->path;
        }
    }
    return NULL;
}

static void hash_insert(const char *name, const char *path)
{
    unsigned int h = hash_str(name);

    /* Check if already exists */
    for (hash_entry_t *e = hash_table[h]; e; e = e->next) {
        if (strcmp(e->name, name) == 0) {
            free(e->path);
            e->path = strdup(path);
            return;
        }
    }

    hash_entry_t *e = malloc(sizeof(hash_entry_t));
    if (!e) return;
    e->name = strdup(name);
    e->path = strdup(path);
    e->hits = 0;
    e->next = hash_table[h];
    hash_table[h] = e;
}

void hash_remove(const char *name)
{
    unsigned int h = hash_str(name);
    hash_entry_t **pp = &hash_table[h];
    while (*pp) {
        if (strcmp((*pp)->name, name) == 0) {
            hash_entry_t *tmp = *pp;
            *pp = tmp->next;
            free(tmp->name);
            free(tmp->path);
            free(tmp);
            return;
        }
        pp = &(*pp)->next;
    }
}

void hash_clear(void)
{
    for (int i = 0; i < HASH_SIZE; i++) {
        hash_entry_t *e = hash_table[i];
        while (e) {
            hash_entry_t *next = e->next;
            free(e->name);
            free(e->path);
            free(e);
            e = next;
        }
        hash_table[i] = NULL;
    }
}

void hash_print(void)
{
    printf("hits\tcommand\n");
    for (int i = 0; i < HASH_SIZE; i++) {
        for (hash_entry_t *e = hash_table[i]; e; e = e->next) {
            printf("  %d\t%s\n", e->hits, e->path);
        }
    }
}

/* ---------- Apply pre-command assignments ---------- */

static char **save_assignments(shell_state_t *state, char **assignments,
                               int nassignments, int *nsaved)
{
    /* For temporary assignments (VAR=val cmd), save old values */
    char **saved = NULL;
    *nsaved = 0;

    if (nassignments <= 0) return NULL;

    saved = malloc(sizeof(char *) * nassignments * 2);
    if (!saved) return NULL;

    for (int i = 0; i < nassignments; i++) {
        char *name = NULL, *value = NULL;
        if (var_parse_assignment(assignments[i], &name, &value) == 0) {
            const char *old = shell_get_var(state, name);
            saved[(*nsaved) * 2] = strdup(name);
            saved[(*nsaved) * 2 + 1] = old ? strdup(old) : NULL;
            (*nsaved)++;

            /* Expand assignment value */
            char *expanded = expand_word_nosplit(value, state);
            shell_set_var(state, name, expanded ? expanded : value);
            free(expanded);
            free(name);
            free(value);
        }
    }
    return saved;
}

static void restore_assignments(shell_state_t *state, char **saved, int nsaved)
{
    if (!saved) return;
    for (int i = 0; i < nsaved; i++) {
        char *name = saved[i * 2];
        char *old_val = saved[i * 2 + 1];
        if (old_val) {
            shell_set_var(state, name, old_val);
            free(old_val);
        } else {
            shell_unset_var(state, name);
        }
        free(name);
    }
    free(saved);
}

/* ---------- Execute command node ---------- */

static int exec_command(shell_state_t *state, ast_node_t *node)
{
    if (!node || node->type != NODE_COMMAND) return 1;

    int nwords = node->data.command.nwords;
    char **words = node->data.command.words;
    int nassign = node->data.command.nassignments;
    char **assignments = node->data.command.assignments;
    redirect_t *redirects = node->data.command.redirects;

    /* No command words — just assignments and/or redirects */
    if (nwords == 0) {
        /* Apply assignments to the shell environment permanently */
        for (int i = 0; i < nassign; i++) {
            char *name = NULL, *value = NULL;
            if (var_parse_assignment(assignments[i], &name, &value) == 0) {
                char *expanded = expand_word_nosplit(value, state);
                shell_set_var(state, name, expanded ? expanded : value);
                shell_export_var(state, name);
                free(expanded);
                free(name);
                free(value);
            }
        }
        /* Handle redirects (e.g., bare "> file") */
        redir_state_t *rs = setup_redirects(redirects, state);
        if (rs == (redir_state_t *)-1)
            return 1;
        restore_redirects(rs);
        return 0;
    }

    /* Expand all words */
    word_list_t *expanded = expand_words(words, nwords, state);
    if (!expanded || expanded->count == 0) {
        /* After expansion, nothing left — just do assignments */
        for (int i = 0; i < nassign; i++) {
            char *name = NULL, *value = NULL;
            if (var_parse_assignment(assignments[i], &name, &value) == 0) {
                char *exp = expand_word_nosplit(value, state);
                shell_set_var(state, name, exp ? exp : value);
                free(exp);
                free(name);
                free(value);
            }
        }
        if (expanded) word_list_free(expanded);
        return 0;
    }

    char *cmd_name = expanded->words[0];
    int argc = expanded->count;
    char **argv = expanded->words;

    /* Trace mode */
    if (state->opts.xtrace) {
        fprintf(stderr, "+ ");
        for (int i = 0; i < argc; i++) {
            if (i) fprintf(stderr, " ");
            fprintf(stderr, "%s", argv[i]);
        }
        fprintf(stderr, "\n");
    }

    int status = 0;

    /* Check for builtin */
    if (is_builtin(cmd_name)) {
        /* Temporary assignments for builtin */
        int nsaved = 0;
        char **saved = save_assignments(state, assignments, nassign, &nsaved);

        /* Set up redirects */
        redir_state_t *rs = setup_redirects(redirects, state);
        if (rs == (redir_state_t *)-1) {
            restore_assignments(state, saved, nsaved);
            word_list_free(expanded);
            return 1;
        }

        builtin_fn_t fn = get_builtin(cmd_name);
        status = fn(state, argc, argv);

        restore_redirects(rs);
        restore_assignments(state, saved, nsaved);
        state->last_exit_status = status;
        word_list_free(expanded);
        return status;
    }

    /* Check for shell function */
    shell_func_t *func = shell_get_func(state, cmd_name);
    if (func) {
        int nsaved = 0;
        char **saved = save_assignments(state, assignments, nassign, &nsaved);

        redir_state_t *rs = setup_redirects(redirects, state);
        if (rs == (redir_state_t *)-1) {
            restore_assignments(state, saved, nsaved);
            word_list_free(expanded);
            return 1;
        }

        status = exec_function_call(state, cmd_name, argc, argv);

        restore_redirects(rs);
        restore_assignments(state, saved, nsaved);
        state->last_exit_status = status;
        word_list_free(expanded);
        return status;
    }

    /* External command: find in PATH */
    char *fullpath = NULL;

    /* Check hash table first */
    char *hashed = hash_lookup(cmd_name);
    if (hashed && access(hashed, X_OK) == 0) {
        fullpath = strdup(hashed);
    } else {
        const char *path_env = shell_get_var(state, "PATH");
        fullpath = find_in_path(cmd_name, path_env);
        if (fullpath && !strchr(cmd_name, '/'))
            hash_insert(cmd_name, fullpath);
    }

    if (!fullpath) {
        fprintf(stderr, "bash: %s: command not found\n", cmd_name);
        state->last_exit_status = 127;
        word_list_free(expanded);
        return 127;
    }

    /* Build envp with assignments applied */
    /* Temporarily apply assignments for child environment */
    int nsaved = 0;
    char **saved = save_assignments(state, assignments, nassign, &nsaved);

    char **envp = shell_build_envp(state);

    /* Fork and exec */
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "bash: fork: %s\n", strerror(errno));
        restore_assignments(state, saved, nsaved);
        shell_free_envp(envp);
        free(fullpath);
        word_list_free(expanded);
        state->last_exit_status = 1;
        return 1;
    }

    if (pid == 0) {
        /* Child process */

        /* Reset signal handlers */
        signal(SIGINT, SIG_DFL);
        signal(SIGQUIT, SIG_DFL);
        signal(SIGTSTP, SIG_DFL);
        signal(SIGTTIN, SIG_DFL);
        signal(SIGTTOU, SIG_DFL);
        signal(SIGCHLD, SIG_DFL);

        /* Set up process group for job control */
        if (state->opts.interactive) {
            pid_t child_pid = getpid();
            setpgid(child_pid, child_pid);
            if (state->terminal_fd >= 0)
                tcsetpgrp(state->terminal_fd, child_pid);
        }

        /* Set up redirects in child */
        redir_state_t *rs = setup_redirects(redirects, state);
        if (rs == (redir_state_t *)-1)
            _exit(1);

        /* Build argv array for execve */
        char **exec_argv = malloc(sizeof(char *) * (argc + 1));
        if (!exec_argv) _exit(127);
        for (int i = 0; i < argc; i++)
            exec_argv[i] = argv[i];
        exec_argv[argc] = NULL;

        execve(fullpath, exec_argv, envp);

        /* If execve fails with ENOEXEC, try running as a shell script */
        if (errno == ENOEXEC) {
            /* Re-exec as: /bin/bash <script> [args...] */
            int nargs = argc + 2; /* "bash" + fullpath + original args[1..] + NULL */
            char **script_argv = malloc(sizeof(char *) * nargs);
            if (script_argv) {
                script_argv[0] = "/bin/bash";
                script_argv[1] = fullpath;
                for (int si = 1; si < argc; si++)
                    script_argv[si + 1] = argv[si];
                script_argv[argc + 1] = NULL;
                execve("/bin/bash", script_argv, envp);
            }
        }

        /* If we get here, execve failed entirely */
        fprintf(stderr, "bash: %s: %s\n", fullpath, strerror(errno));
        _exit(127);
    }

    /* Parent process */
    restore_assignments(state, saved, nsaved);

    /* Set child's process group */
    if (state->opts.interactive) {
        setpgid(pid, pid);
        if (state->terminal_fd >= 0)
            tcsetpgrp(state->terminal_fd, pid);
    }

    /* Wait for child */
    int wstatus;
    pid_t wpid;
    do {
        wpid = waitpid(pid, &wstatus, WUNTRACED);
    } while (wpid < 0 && errno == EINTR);

    /* Restore shell to foreground */
    if (state->opts.interactive && state->terminal_fd >= 0)
        tcsetpgrp(state->terminal_fd, state->shell_pgid);

    if (WIFEXITED(wstatus))
        status = WEXITSTATUS(wstatus);
    else if (WIFSIGNALED(wstatus))
        status = 128 + WTERMSIG(wstatus);
    else if (WIFSTOPPED(wstatus))
        status = 128 + WSTOPSIG(wstatus);

    shell_free_envp(envp);
    free(fullpath);
    word_list_free(expanded);
    state->last_exit_status = status;
    return status;
}

/* ---------- Execute pipeline ---------- */

/*
 * print_time_line - format a timeval as Nm.NNNs for 'time' keyword output
 */
static void print_time_line(const char *label, long sec, long usec)
{
    if (usec < 0) { sec -= 1; usec += 1000000; }
    while (usec >= 1000000) { sec += 1; usec -= 1000000; }
    if (sec < 0) { sec = 0; usec = 0; }
    fprintf(stderr, "%s\t%ldm%ld.%03lds\n", label, sec / 60, sec % 60, usec / 1000);
}

static int exec_pipeline(shell_state_t *state, ast_node_t *node)
{
    if (!node || node->type != NODE_PIPELINE) return 1;

    int ncmds = node->data.pipeline.ncommands;
    ast_node_t **commands = node->data.pipeline.commands;
    int timed = node->data.pipeline.timed;

    /* Record start time if this is a timed pipeline */
    struct timeval t_start = {0, 0};
    if (timed)
        gettimeofday(&t_start, NULL);

    if (ncmds == 1) {
        int status = exec_node(state, commands[0]);
        if (node->data.pipeline.bang)
            status = status ? 0 : 1;
        if (timed) {
            struct timeval t_end = {0, 0};
            gettimeofday(&t_end, NULL);
            fprintf(stderr, "\n");
            print_time_line("real", t_end.tv_sec - t_start.tv_sec,
                            t_end.tv_usec - t_start.tv_usec);
            print_time_line("user", 0, 0);
            print_time_line("sys", 0, 0);
        }
        state->last_exit_status = status;
        return status;
    }

    /* Create pipes */
    int (*pipes)[2] = malloc(sizeof(int[2]) * (ncmds - 1));
    if (!pipes) return 1;

    for (int i = 0; i < ncmds - 1; i++) {
        if (pipe(pipes[i]) < 0) {
            fprintf(stderr, "bash: pipe: %s\n", strerror(errno));
            /* Clean up already created pipes */
            for (int j = 0; j < i; j++) {
                close(pipes[j][0]);
                close(pipes[j][1]);
            }
            free(pipes);
            return 1;
        }
    }

    pid_t *pids = malloc(sizeof(pid_t) * ncmds);
    if (!pids) {
        for (int i = 0; i < ncmds - 1; i++) {
            close(pipes[i][0]);
            close(pipes[i][1]);
        }
        free(pipes);
        return 1;
    }

    pid_t pgid = 0;

    for (int i = 0; i < ncmds; i++) {
        pid_t pid = fork();
        if (pid < 0) {
            fprintf(stderr, "bash: fork: %s\n", strerror(errno));
            pids[i] = -1;
            continue;
        }

        if (pid == 0) {
            /* Child */
            signal(SIGINT, SIG_DFL);
            signal(SIGQUIT, SIG_DFL);
            signal(SIGTSTP, SIG_DFL);
            signal(SIGTTIN, SIG_DFL);
            signal(SIGTTOU, SIG_DFL);

            /* Set process group */
            if (state->opts.interactive) {
                if (i == 0)
                    setpgid(0, 0);
                else
                    setpgid(0, pids[0] > 0 ? pids[0] : getpid());
            }

            /* Wire up pipes */
            if (i > 0) {
                dup2(pipes[i - 1][0], STDIN_FILENO);
            }
            if (i < ncmds - 1) {
                dup2(pipes[i][1], STDOUT_FILENO);
            }

            /* Close all pipe fds */
            for (int j = 0; j < ncmds - 1; j++) {
                close(pipes[j][0]);
                close(pipes[j][1]);
            }

            int status = exec_node(state, commands[i]);
            _exit(status);
        }

        /* Parent */
        pids[i] = pid;

        if (i == 0) {
            pgid = pid;
            if (state->opts.interactive)
                setpgid(pid, pid);
        } else {
            if (state->opts.interactive)
                setpgid(pid, pgid);
        }
    }

    /* Close all pipe fds in parent */
    for (int i = 0; i < ncmds - 1; i++) {
        close(pipes[i][0]);
        close(pipes[i][1]);
    }

    /* Give terminal to pipeline's process group */
    if (state->opts.interactive && state->terminal_fd >= 0 && pgid > 0)
        tcsetpgrp(state->terminal_fd, pgid);

    /* Wait for all children */
    int last_status = 0;
    int pipefail_status = 0;

    for (int i = 0; i < ncmds; i++) {
        if (pids[i] <= 0) continue;

        int wstatus;
        pid_t wpid;
        do {
            wpid = waitpid(pids[i], &wstatus, 0);
        } while (wpid < 0 && errno == EINTR);

        int s = 0;
        if (WIFEXITED(wstatus))
            s = WEXITSTATUS(wstatus);
        else if (WIFSIGNALED(wstatus))
            s = 128 + WTERMSIG(wstatus);

        if (i == ncmds - 1)
            last_status = s;
        if (s != 0)
            pipefail_status = s;
    }

    /* Restore shell to foreground */
    if (state->opts.interactive && state->terminal_fd >= 0)
        tcsetpgrp(state->terminal_fd, state->shell_pgid);

    free(pids);
    free(pipes);

    int status = state->opts.pipefail ? pipefail_status : last_status;
    if (node->data.pipeline.bang)
        status = status ? 0 : 1;

    if (timed) {
        struct timeval t_end = {0, 0};
        gettimeofday(&t_end, NULL);
        fprintf(stderr, "\n");
        print_time_line("real", t_end.tv_sec - t_start.tv_sec,
                        t_end.tv_usec - t_start.tv_usec);
        print_time_line("user", 0, 0);
        print_time_line("sys", 0, 0);
    }

    state->last_exit_status = status;
    return status;
}

/* ---------- Execute if ---------- */

static int exec_if(shell_state_t *state, ast_node_t *node)
{
    if (!node || node->type != NODE_IF) return 1;

    redir_state_t *rs = setup_redirects(node->data.if_clause.redirects, state);
    if (rs == (redir_state_t *)-1) return 1;

    exec_node(state, node->data.if_clause.condition);

    int status;
    if (state->last_exit_status == 0) {
        status = exec_node(state, node->data.if_clause.then_body);
    } else if (node->data.if_clause.else_body) {
        status = exec_node(state, node->data.if_clause.else_body);
    } else {
        status = 0;
    }

    restore_redirects(rs);
    state->last_exit_status = status;
    return status;
}

/* ---------- Execute for ---------- */

static int exec_for(shell_state_t *state, ast_node_t *node)
{
    if (!node || node->type != NODE_FOR) return 1;

    redir_state_t *rs = setup_redirects(node->data.for_clause.redirects, state);
    if (rs == (redir_state_t *)-1) return 1;

    const char *varname = node->data.for_clause.varname;
    word_list_t *words = NULL;

    if (node->data.for_clause.words && node->data.for_clause.nwords > 0) {
        words = expand_words(node->data.for_clause.words,
                             node->data.for_clause.nwords, state);
    } else {
        /* Default: iterate over positional parameters */
        words = word_list_new();
        if (words) {
            for (int i = 0; i < state->positional_count; i++) {
                if (state->positional[i])
                    word_list_add(words, state->positional[i]);
            }
        }
    }

    int status = 0;
    state->loop_depth++;

    if (words) {
        for (int i = 0; i < words->count; i++) {
            if (state->do_break) {
                state->break_count--;
                if (state->break_count <= 0) {
                    state->do_break = 0;
                    state->break_count = 0;
                }
                break;
            }
            if (state->do_continue) {
                state->continue_count--;
                if (state->continue_count <= 0) {
                    state->do_continue = 0;
                    state->continue_count = 0;
                    /* Continue to next iteration */
                } else {
                    break; /* Propagate continue to outer loop */
                }
            }

            shell_set_var(state, varname, words->words[i]);
            status = exec_node(state, node->data.for_clause.body);

            if (state->do_return) break;
        }
        word_list_free(words);
    }

    state->loop_depth--;
    restore_redirects(rs);
    state->last_exit_status = status;
    return status;
}

/* ---------- Execute while/until ---------- */

static int exec_while(shell_state_t *state, ast_node_t *node, int until)
{
    if (!node) return 1;

    redir_state_t *rs = setup_redirects(node->data.loop.redirects, state);
    if (rs == (redir_state_t *)-1) return 1;

    int status = 0;
    state->loop_depth++;

    for (;;) {
        if (state->do_break) {
            state->break_count--;
            if (state->break_count <= 0) {
                state->do_break = 0;
                state->break_count = 0;
            }
            break;
        }

        exec_node(state, node->data.loop.condition);
        int cond = state->last_exit_status;

        /* while: continue if cond==0; until: continue if cond!=0 */
        if (until ? (cond == 0) : (cond != 0))
            break;

        if (state->do_continue) {
            state->continue_count--;
            if (state->continue_count <= 0) {
                state->do_continue = 0;
                state->continue_count = 0;
            } else {
                break;
            }
            continue;
        }

        status = exec_node(state, node->data.loop.body);

        if (state->do_return) break;

        if (state->do_continue) {
            state->continue_count--;
            if (state->continue_count <= 0) {
                state->do_continue = 0;
                state->continue_count = 0;
            } else {
                break;
            }
        }
    }

    state->loop_depth--;
    restore_redirects(rs);
    state->last_exit_status = status;
    return status;
}

/* ---------- Execute case ---------- */

static int exec_case(shell_state_t *state, ast_node_t *node)
{
    if (!node || node->type != NODE_CASE) return 1;

    redir_state_t *rs = setup_redirects(node->data.case_clause.redirects, state);
    if (rs == (redir_state_t *)-1) return 1;

    /* Expand the case word */
    char *word = expand_word_nosplit(node->data.case_clause.word, state);
    if (!word) word = strdup(node->data.case_clause.word);

    int status = 0;
    int matched = 0;

    for (case_item_t *item = node->data.case_clause.items; item; item = item->next) {
        if (matched) break;

        for (int i = 0; i < item->npatterns; i++) {
            /* Expand the pattern */
            char *pat = expand_word_nosplit(item->patterns[i], state);
            if (!pat) pat = strdup(item->patterns[i]);

            if (glob_match(pat, word)) {
                free(pat);
                matched = 1;
                if (item->body)
                    status = exec_node(state, item->body);
                break;
            }
            free(pat);
        }
    }

    free(word);
    restore_redirects(rs);
    state->last_exit_status = status;
    return status;
}

/* ---------- Execute function call ---------- */

int exec_function_call(shell_state_t *state, const char *name,
                       int argc, char **argv)
{
    shell_func_t *func = shell_get_func(state, name);
    if (!func || !func->body) return 127;

    /* Save positional params */
    char **old_positional = state->positional;
    int old_count = state->positional_count;
    char *old_argv0 = state->argv0;
    int old_in_function = state->in_function;

    /* Set new positional params from argv[1..] */
    state->positional_count = argc - 1;
    if (state->positional_count > 0) {
        state->positional = malloc(sizeof(char *) * state->positional_count);
        for (int i = 0; i < state->positional_count; i++)
            state->positional[i] = strdup(argv[i + 1]);
    } else {
        state->positional = NULL;
    }
    state->argv0 = strdup(argv[0]);
    state->in_function = 1;
    state->do_return = 0;

    int status = exec_node(state, func->body);

    if (state->do_return) {
        status = state->return_value;
        state->do_return = 0;
    }

    /* Restore positional params */
    if (state->positional) {
        for (int i = 0; i < state->positional_count; i++)
            free(state->positional[i]);
        free(state->positional);
    }
    free(state->argv0);
    state->positional = old_positional;
    state->positional_count = old_count;
    state->argv0 = old_argv0;
    state->in_function = old_in_function;

    state->last_exit_status = status;
    return status;
}

/* ---------- Execute subshell ---------- */

static int exec_subshell(shell_state_t *state, ast_node_t *node)
{
    if (!node || node->type != NODE_SUBSHELL) return 1;

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "bash: fork: %s\n", strerror(errno));
        return 1;
    }

    if (pid == 0) {
        /* Child: reset signals */
        signal(SIGINT, SIG_DFL);
        signal(SIGQUIT, SIG_DFL);
        signal(SIGTSTP, SIG_DFL);

        state->subshell_level++;

        redir_state_t *rs = setup_redirects(node->data.subshell.redirects, state);
        if (rs == (redir_state_t *)-1)
            _exit(1);

        int status = exec_node(state, node->data.subshell.body);
        _exit(status);
    }

    int wstatus;
    pid_t wpid;
    do {
        wpid = waitpid(pid, &wstatus, 0);
    } while (wpid < 0 && errno == EINTR);

    int status = 0;
    if (WIFEXITED(wstatus))
        status = WEXITSTATUS(wstatus);
    else if (WIFSIGNALED(wstatus))
        status = 128 + WTERMSIG(wstatus);

    state->last_exit_status = status;
    return status;
}

/* ---------- Execute brace group ---------- */

static int exec_brace_group(shell_state_t *state, ast_node_t *node)
{
    if (!node || node->type != NODE_BRACE_GROUP) return 1;

    redir_state_t *rs = setup_redirects(node->data.brace_group.redirects, state);
    if (rs == (redir_state_t *)-1) return 1;

    int status = exec_node(state, node->data.brace_group.body);

    restore_redirects(rs);
    state->last_exit_status = status;
    return status;
}

/* ---------- Execute function definition ---------- */

static int exec_function_def(shell_state_t *state, ast_node_t *node)
{
    if (!node || node->type != NODE_FUNCTION) return 1;

    shell_set_func(state, node->data.function.name, node->data.function.body);
    return 0;
}

/* ---------- Execute AND (&&) ---------- */

static int exec_and(shell_state_t *state, ast_node_t *node)
{
    int status = exec_node(state, node->data.binary.left);
    if (status == 0)
        status = exec_node(state, node->data.binary.right);
    state->last_exit_status = status;
    return status;
}

/* ---------- Execute OR (||) ---------- */

static int exec_or(shell_state_t *state, ast_node_t *node)
{
    int status = exec_node(state, node->data.binary.left);
    if (status != 0)
        status = exec_node(state, node->data.binary.right);
    state->last_exit_status = status;
    return status;
}

/* ---------- Execute SEMI (;) ---------- */

static int exec_semi(shell_state_t *state, ast_node_t *node)
{
    exec_node(state, node->data.binary.left);
    int status = exec_node(state, node->data.binary.right);
    state->last_exit_status = status;
    return status;
}

/* ---------- Execute BG (&) ---------- */

static int exec_bg(shell_state_t *state, ast_node_t *node)
{
    if (!node || node->type != NODE_BG) return 1;

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "bash: fork: %s\n", strerror(errno));
        return 1;
    }

    if (pid == 0) {
        /* Child: reset signals, run in background */
        signal(SIGINT, SIG_IGN);
        signal(SIGQUIT, SIG_IGN);
        signal(SIGTSTP, SIG_IGN);

        if (state->opts.interactive) {
            setpgid(0, 0);
        }

        int status = exec_node(state, node->data.bg.child);
        _exit(status);
    }

    /* Parent */
    if (state->opts.interactive)
        setpgid(pid, pid);

    state->last_bg_pid = pid;

    /* Add to job table */
    /* Find a free slot */
    int job_id = -1;
    for (int i = 0; i < MAX_JOBS; i++) {
        if (state->jobs[i].pgid == 0) {
            job_id = i;
            break;
        }
    }
    if (job_id >= 0) {
        state->jobs[job_id].id = state->next_job_id++;
        state->jobs[job_id].pgid = pid;
        state->jobs[job_id].pids = malloc(sizeof(pid_t));
        state->jobs[job_id].pids[0] = pid;
        state->jobs[job_id].npids = 1;
        state->jobs[job_id].statuses = calloc(1, sizeof(int));
        state->jobs[job_id].status = JOB_RUNNING;
        state->jobs[job_id].command = strdup("(background)");
        state->jobs[job_id].foreground = 0;
        state->jobs[job_id].notified = 0;
        state->njobs++;

        if (state->opts.interactive) {
            fprintf(stderr, "[%d] %d\n", state->jobs[job_id].id,
                    (int)pid);
        }
    }

    state->last_exit_status = 0;
    return 0;
}

/* ---------- Execute BANG (!) ---------- */

static int exec_bang(shell_state_t *state, ast_node_t *node)
{
    if (!node || node->type != NODE_BANG) return 1;

    int status = exec_node(state, node->data.bang.child);
    status = status ? 0 : 1;
    state->last_exit_status = status;
    return status;
}

/* ---------- Main dispatch ---------- */

static int exec_node(shell_state_t *state, ast_node_t *node)
{
    if (!node) return 0;

    /* Check for break/continue/return propagation */
    if (state->do_break || state->do_continue || state->do_return)
        return state->last_exit_status;

    int status = 0;

    switch (node->type) {
    case NODE_COMMAND:
        status = exec_command(state, node);
        break;
    case NODE_PIPELINE:
        status = exec_pipeline(state, node);
        break;
    case NODE_AND:
        status = exec_and(state, node);
        break;
    case NODE_OR:
        status = exec_or(state, node);
        break;
    case NODE_SEMI:
        status = exec_semi(state, node);
        break;
    case NODE_BG:
        status = exec_bg(state, node);
        break;
    case NODE_SUBSHELL:
        status = exec_subshell(state, node);
        break;
    case NODE_IF:
        status = exec_if(state, node);
        break;
    case NODE_FOR:
        status = exec_for(state, node);
        break;
    case NODE_WHILE:
        status = exec_while(state, node, 0);
        break;
    case NODE_UNTIL:
        status = exec_while(state, node, 1);
        break;
    case NODE_CASE:
        status = exec_case(state, node);
        break;
    case NODE_FUNCTION:
        status = exec_function_def(state, node);
        break;
    case NODE_BRACE_GROUP:
        status = exec_brace_group(state, node);
        break;
    case NODE_BANG:
        status = exec_bang(state, node);
        break;
    }

    /* errexit: exit if command fails */
    if (state->opts.errexit && status != 0) {
        /* Don't exit for conditions of if/while/until, or part of && / || */
        /* Simplified: just set and let main loop handle it */
    }

    return status;
}

/* ---------- Public API ---------- */

int shell_execute(shell_state_t *state, ast_node_t *node)
{
    return exec_node(state, node);
}
