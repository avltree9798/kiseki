/*
 * Kiseki OS - Bash-compatible Shell
 *
 * Master header: shell state, limits, and forward declarations.
 */

#ifndef _SHELL_H
#define _SHELL_H

#include <stdint.h>
#include <sys/types.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

/* ---------- Limits ---------- */

#define MAX_LINE        4096    /* Maximum input line length */
#define MAX_ARGS        256     /* Maximum arguments to a command */
#define MAX_VARS        512     /* Maximum shell variables */
#define MAX_FUNCS       64      /* Maximum shell functions */
#define MAX_ALIASES     128     /* Maximum alias definitions */
#define MAX_JOBS        32      /* Maximum tracked jobs */
#define MAX_POSITIONAL  256     /* Maximum positional parameters ($1...) */
#define MAX_PATH_SEARCH 64      /* Maximum PATH directories to search */

/* ---------- Forward declarations (AST) ---------- */

typedef struct ast_node     ast_node_t;
typedef struct redirect     redirect_t;
typedef struct token        token_t;
typedef struct lexer        lexer_t;

/* ---------- Shell variable ---------- */

typedef struct shell_var {
    char   *name;               /* Variable name */
    char   *value;              /* Variable value (always stored as string) */
    int     exported;           /* Marked for export to child processes */
    int     readonly;           /* Read-only flag */
} shell_var_t;

/* ---------- Shell function ---------- */

typedef struct shell_func {
    char       *name;           /* Function name */
    ast_node_t *body;           /* AST body (NODE_BRACE_GROUP usually) */
} shell_func_t;

/* ---------- Shell alias ---------- */

typedef struct shell_alias {
    char   *name;               /* Alias name */
    char   *value;              /* Replacement text */
} shell_alias_t;

/* ---------- Job control ---------- */

typedef enum {
    JOB_RUNNING,
    JOB_STOPPED,
    JOB_DONE,
    JOB_TERMINATED
} job_status_t;

typedef struct job {
    int             id;         /* Job number (%1, %2, ...) */
    pid_t           pgid;       /* Process group ID */
    pid_t          *pids;       /* Array of PIDs in this job */
    int             npids;      /* Number of PIDs */
    int            *statuses;   /* Exit statuses per PID */
    job_status_t    status;     /* Overall job status */
    char           *command;    /* Command string (for display) */
    int             foreground; /* Was launched in foreground */
    int             notified;   /* User has been notified of completion */
} job_t;

/* ---------- Shell option flags ---------- */

typedef struct shell_opts {
    int     interactive;        /* -i: interactive shell */
    int     login;              /* -l: login shell */
    int     hashbang;           /* Running from #! script */
    int     verbose;            /* -v: print input lines as read */
    int     xtrace;             /* -x: print commands before execution */
    int     errexit;            /* -e: exit on error */
    int     nounset;            /* -u: treat unset variables as error */
    int     noglob;             /* -f: disable pathname expansion */
    int     noclobber;          /* -C: don't overwrite with > */
    int     allexport;          /* -a: auto-export variables */
    int     notify;             /* -b: notify of bg job completion */
    int     noexec;             /* -n: read commands but don't execute */
    int     pipefail;           /* pipefail: pipeline exit = last nonzero */
} shell_opts_t;

/* ---------- Shell state ---------- */

typedef struct shell_state {
    /* Variable table */
    shell_var_t     vars[MAX_VARS];
    int             nvars;

    /* Function table */
    shell_func_t    funcs[MAX_FUNCS];
    int             nfuncs;

    /* Alias table */
    shell_alias_t   aliases[MAX_ALIASES];
    int             naliases;

    /* Job list */
    job_t           jobs[MAX_JOBS];
    int             njobs;
    int             next_job_id;

    /* Special parameters */
    int             last_exit_status;   /* $? */
    pid_t           shell_pid;          /* $$ */
    pid_t           last_bg_pid;        /* $! */

    /* Positional parameters */
    char           *argv0;              /* $0 */
    char          **positional;         /* $1, $2, ... */
    int             positional_count;   /* $# */

    /* Shell options (determines $-) */
    shell_opts_t    opts;

    /* Working state */
    int             line_number;        /* $LINENO */
    int             running;            /* Main loop flag */
    int             in_function;        /* Currently executing a function */
    int             loop_depth;         /* Nesting level for break/continue */
    int             break_count;        /* break N */
    int             continue_count;     /* continue N */
    int             do_break;           /* break requested */
    int             do_continue;        /* continue requested */
    int             do_return;          /* return from function */
    int             return_value;       /* return value */
    int             subshell_level;     /* Nesting depth of subshells */

    /* Terminal info (for job control) */
    int             terminal_fd;        /* Controlling terminal fd */
    pid_t           shell_pgid;         /* Shell's process group */
} shell_state_t;

/* ---------- Global shell state ---------- */

extern shell_state_t *g_shell;

/* ---------- Shell lifecycle ---------- */

shell_state_t  *shell_init(int argc, char **argv);
void            shell_cleanup(shell_state_t *state);

/* ---------- Variable operations ---------- */

const char     *shell_get_var(shell_state_t *state, const char *name);
int             shell_set_var(shell_state_t *state, const char *name,
                              const char *value);
int             shell_unset_var(shell_state_t *state, const char *name);
int             shell_export_var(shell_state_t *state, const char *name);
int             shell_set_readonly(shell_state_t *state, const char *name);
char          **shell_build_envp(shell_state_t *state);
void            shell_free_envp(char **envp);
void            shell_import_environ(shell_state_t *state);

/* ---------- Function operations ---------- */

shell_func_t   *shell_get_func(shell_state_t *state, const char *name);
int             shell_set_func(shell_state_t *state, const char *name,
                               ast_node_t *body);
int             shell_unset_func(shell_state_t *state, const char *name);

/* ---------- Alias operations ---------- */

const char     *shell_get_alias(shell_state_t *state, const char *name);
int             shell_set_alias(shell_state_t *state, const char *name,
                                const char *value);
int             shell_unset_alias(shell_state_t *state, const char *name);

/* ---------- Special parameter helpers ---------- */

/* Build the $- flags string (e.g. "himBH") */
void            shell_build_flags_string(shell_state_t *state, char *buf,
                                         size_t bufsz);

/* Get a special variable by name ($?, $$, etc.) - returns static buffer */
const char     *shell_get_special(shell_state_t *state, const char *name);

/* ---------- Lexer (lexer.h) ---------- */

lexer_t        *lexer_init(const char *input);
token_t        *lexer_next_token(lexer_t *lex);
token_t        *lexer_peek(lexer_t *lex);
void            token_free(token_t *tok);
void            lexer_free(lexer_t *lex);

/* ---------- Parser (parser.h) ---------- */

ast_node_t     *parse_input(const char *input);
void            ast_free(ast_node_t *node);

/* ---------- Expansion (expand.h) ---------- */

typedef struct word_list {
    char          **words;
    int             count;
    int             capacity;
} word_list_t;

word_list_t    *expand_word(const char *word, shell_state_t *state);
word_list_t    *expand_words(char **words, int nwords, shell_state_t *state);
word_list_t    *expand_pattern(const char *pattern);
long            arith_eval(const char *expr, shell_state_t *state, int *err);
void            word_list_free(word_list_t *wl);
word_list_t    *word_list_new(void);
void            word_list_add(word_list_t *wl, const char *word);

#endif /* _SHELL_H */
