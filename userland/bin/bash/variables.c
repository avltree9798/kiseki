/*
 * Kiseki OS - Shell Variable / Environment System
 *
 * Manages shell variables, special parameters, and environment export.
 */

#include "shell.h"

/* ---------- Internal helpers ---------- */

static shell_var_t *var_find(shell_state_t *state, const char *name)
{
    for (int i = 0; i < state->nvars; i++) {
        if (state->vars[i].name && strcmp(state->vars[i].name, name) == 0)
            return &state->vars[i];
    }
    return NULL;
}

static shell_var_t *var_alloc(shell_state_t *state)
{
    /* Try to find an empty slot first */
    for (int i = 0; i < state->nvars; i++) {
        if (state->vars[i].name == NULL)
            return &state->vars[i];
    }
    if (state->nvars >= MAX_VARS)
        return NULL;
    return &state->vars[state->nvars++];
}

/* ---------- Internal: set a default variable ---------- */

static void set_default(shell_state_t *state, const char *name,
                        const char *value, int exported)
{
    shell_var_t *v = var_find(state, name);
    if (!v) {
        v = var_alloc(state);
        if (!v) return;
        v->name = strdup(name);
        v->readonly = 0;
    }
    free(v->value);
    v->value = strdup(value);
    v->exported = exported;
}

/* ---------- Public API: var_init ---------- */

void var_init(shell_state_t *state)
{
    char buf[64];
    char cwd[PATH_MAX];

    set_default(state, "PATH", "/bin:/usr/bin", 1);
    set_default(state, "HOME", "/root", 1);
    set_default(state, "PS1", "\\u@\\h:\\w\\$ ", 0);
    set_default(state, "PS2", "> ", 0);
    set_default(state, "IFS", " \t\n", 0);
    set_default(state, "BASH_VERSION", "5.2.0", 0);
    set_default(state, "SHELL", "/bin/bash", 1);

    if (getcwd(cwd, sizeof(cwd)))
        set_default(state, "PWD", cwd, 1);
    else
        set_default(state, "PWD", "/", 1);

    set_default(state, "USER", "root", 1);

    snprintf(buf, sizeof(buf), "%d", (int)getuid());
    set_default(state, "UID", buf, 0);

    set_default(state, "HOSTNAME", "kiseki", 1);

    snprintf(buf, sizeof(buf), "%d", (int)getpid());
    set_default(state, "BASHPID", buf, 0);

    set_default(state, "OPTIND", "1", 0);
    set_default(state, "OPTERR", "1", 0);

    /* LINENO will be dynamically generated in var_get */
    set_default(state, "LINENO", "0", 0);

    /* SHLVL */
    const char *shlvl = shell_get_var(state, "SHLVL");
    int lvl = shlvl ? atoi(shlvl) + 1 : 1;
    snprintf(buf, sizeof(buf), "%d", lvl);
    set_default(state, "SHLVL", buf, 1);

    /* RANDOM seed */
    srand((unsigned int)getpid());
}

/* ---------- Import environment ---------- */

void shell_import_environ(shell_state_t *state)
{
    extern char **environ;
    if (!environ) return;

    for (int i = 0; environ[i]; i++) {
        char *eq = strchr(environ[i], '=');
        if (!eq) continue;

        size_t nlen = (size_t)(eq - environ[i]);
        char *name = malloc(nlen + 1);
        if (!name) continue;
        memcpy(name, environ[i], nlen);
        name[nlen] = '\0';

        shell_var_t *v = var_find(state, name);
        if (!v) {
            v = var_alloc(state);
            if (!v) { free(name); continue; }
            v->name = name;
            v->readonly = 0;
        } else {
            free(name);
        }
        free(v->value);
        v->value = strdup(eq + 1);
        v->exported = 1;
    }
}

/* ---------- Special parameter handling ---------- */

static char special_buf[64];

const char *shell_get_special(shell_state_t *state, const char *name)
{
    if (!name || !name[0]) return NULL;

    /* Single-character specials */
    if (name[1] == '\0') {
        switch (name[0]) {
        case '?':
            snprintf(special_buf, sizeof(special_buf), "%d",
                     state->last_exit_status);
            return special_buf;
        case '$':
            snprintf(special_buf, sizeof(special_buf), "%d",
                     (int)state->shell_pid);
            return special_buf;
        case '!':
            if (state->last_bg_pid > 0) {
                snprintf(special_buf, sizeof(special_buf), "%d",
                         (int)state->last_bg_pid);
                return special_buf;
            }
            return "";
        case '#':
            snprintf(special_buf, sizeof(special_buf), "%d",
                     state->positional_count);
            return special_buf;
        case '0':
            return state->argv0 ? state->argv0 : "bash";
        case '-': {
            char flags[32];
            shell_build_flags_string(state, flags, sizeof(flags));
            /* Copy into static buffer */
            strncpy(special_buf, flags, sizeof(special_buf) - 1);
            special_buf[sizeof(special_buf) - 1] = '\0';
            return special_buf;
        }
        case '_':
            return "";  /* Last argument of previous command - simplified */
        default:
            /* Positional parameters $1..$9 as single-char */
            if (name[0] >= '1' && name[0] <= '9') {
                int idx = name[0] - '0';
                if (idx <= state->positional_count && state->positional)
                    return state->positional[idx - 1];
                return NULL;
            }
            break;
        }
    }

    /* Multi-digit positional: $10, $11, ... */
    {
        int all_digit = 1;
        for (int i = 0; name[i]; i++) {
            if (name[i] < '0' || name[i] > '9') { all_digit = 0; break; }
        }
        if (all_digit && name[0]) {
            int idx = atoi(name);
            if (idx >= 1 && idx <= state->positional_count && state->positional)
                return state->positional[idx - 1];
            return NULL;
        }
    }

    /* $@ and $* handled in expand.c; we provide fallback here */
    if (strcmp(name, "@") == 0 || strcmp(name, "*") == 0) {
        /* Join all positional params */
        special_buf[0] = '\0';
        size_t off = 0;
        for (int i = 0; i < state->positional_count && state->positional; i++) {
            if (i > 0 && off < sizeof(special_buf) - 1)
                special_buf[off++] = ' ';
            size_t plen = strlen(state->positional[i]);
            if (off + plen < sizeof(special_buf) - 1) {
                memcpy(special_buf + off, state->positional[i], plen);
                off += plen;
            }
        }
        special_buf[off] = '\0';
        return special_buf;
    }

    /* RANDOM */
    if (strcmp(name, "RANDOM") == 0) {
        snprintf(special_buf, sizeof(special_buf), "%d", rand() & 0x7fff);
        return special_buf;
    }

    /* LINENO */
    if (strcmp(name, "LINENO") == 0) {
        snprintf(special_buf, sizeof(special_buf), "%d", state->line_number);
        return special_buf;
    }

    /* SECONDS - not tracked, return 0 */
    if (strcmp(name, "SECONDS") == 0) {
        return "0";
    }

    return NULL;
}

/* ---------- Build $- flags string ---------- */

void shell_build_flags_string(shell_state_t *state, char *buf, size_t bufsz)
{
    size_t i = 0;
    if (state->opts.errexit   && i < bufsz - 1) buf[i++] = 'e';
    if (state->opts.nounset   && i < bufsz - 1) buf[i++] = 'u';
    if (state->opts.xtrace    && i < bufsz - 1) buf[i++] = 'x';
    if (state->opts.verbose   && i < bufsz - 1) buf[i++] = 'v';
    if (state->opts.noglob    && i < bufsz - 1) buf[i++] = 'f';
    if (state->opts.noclobber && i < bufsz - 1) buf[i++] = 'C';
    if (state->opts.allexport && i < bufsz - 1) buf[i++] = 'a';
    if (state->opts.notify    && i < bufsz - 1) buf[i++] = 'b';
    if (state->opts.noexec    && i < bufsz - 1) buf[i++] = 'n';
    if (state->opts.interactive && i < bufsz - 1) buf[i++] = 'i';
    if (state->opts.hashbang  && i < bufsz - 1) buf[i++] = 's';
    buf[i] = '\0';
}

/* ---------- Public API: shell_get_var ---------- */

const char *shell_get_var(shell_state_t *state, const char *name)
{
    if (!name) return NULL;

    /* Check specials first */
    const char *sp = shell_get_special(state, name);
    if (sp) return sp;

    /* Regular variable lookup */
    shell_var_t *v = var_find(state, name);
    if (v) return v->value;

    return NULL;
}

/* ---------- Public API: shell_set_var ---------- */

int shell_set_var(shell_state_t *state, const char *name, const char *value)
{
    if (!name || !name[0]) return -1;

    shell_var_t *v = var_find(state, name);
    if (v) {
        if (v->readonly) {
            fprintf(stderr, "bash: %s: readonly variable\n", name);
            return -1;
        }
        free(v->value);
        v->value = value ? strdup(value) : strdup("");
        if (state->opts.allexport)
            v->exported = 1;
        return 0;
    }

    /* Create new variable */
    v = var_alloc(state);
    if (!v) {
        fprintf(stderr, "bash: too many variables\n");
        return -1;
    }
    v->name = strdup(name);
    v->value = value ? strdup(value) : strdup("");
    v->exported = state->opts.allexport ? 1 : 0;
    v->readonly = 0;
    return 0;
}

/* ---------- Public API: shell_unset_var ---------- */

int shell_unset_var(shell_state_t *state, const char *name)
{
    for (int i = 0; i < state->nvars; i++) {
        if (state->vars[i].name && strcmp(state->vars[i].name, name) == 0) {
            if (state->vars[i].readonly) {
                fprintf(stderr, "bash: unset: %s: cannot unset: readonly variable\n",
                        name);
                return -1;
            }
            free(state->vars[i].name);
            free(state->vars[i].value);
            state->vars[i].name = NULL;
            state->vars[i].value = NULL;
            state->vars[i].exported = 0;
            state->vars[i].readonly = 0;
            return 0;
        }
    }
    return 0; /* Not found is not an error */
}

/* ---------- Public API: shell_export_var ---------- */

int shell_export_var(shell_state_t *state, const char *name)
{
    shell_var_t *v = var_find(state, name);
    if (v) {
        v->exported = 1;
        return 0;
    }
    /* Create empty exported variable */
    v = var_alloc(state);
    if (!v) return -1;
    v->name = strdup(name);
    v->value = strdup("");
    v->exported = 1;
    v->readonly = 0;
    return 0;
}

/* ---------- Public API: shell_set_readonly ---------- */

int shell_set_readonly(shell_state_t *state, const char *name)
{
    shell_var_t *v = var_find(state, name);
    if (v) {
        v->readonly = 1;
        return 0;
    }
    /* Create empty readonly variable */
    v = var_alloc(state);
    if (!v) return -1;
    v->name = strdup(name);
    v->value = strdup("");
    v->exported = 0;
    v->readonly = 1;
    return 0;
}

/* ---------- Public API: shell_build_envp ---------- */

char **shell_build_envp(shell_state_t *state)
{
    /* Count exported vars */
    int count = 0;
    for (int i = 0; i < state->nvars; i++) {
        if (state->vars[i].name && state->vars[i].exported)
            count++;
    }

    char **envp = malloc(sizeof(char *) * (count + 1));
    if (!envp) return NULL;

    int idx = 0;
    for (int i = 0; i < state->nvars; i++) {
        if (!state->vars[i].name || !state->vars[i].exported)
            continue;
        const char *n = state->vars[i].name;
        const char *val = state->vars[i].value ? state->vars[i].value : "";
        size_t nlen = strlen(n);
        size_t vlen = strlen(val);
        char *entry = malloc(nlen + 1 + vlen + 1);
        if (!entry) continue;
        memcpy(entry, n, nlen);
        entry[nlen] = '=';
        memcpy(entry + nlen + 1, val, vlen);
        entry[nlen + 1 + vlen] = '\0';
        envp[idx++] = entry;
    }
    envp[idx] = NULL;
    return envp;
}

/* ---------- Public API: shell_free_envp ---------- */

void shell_free_envp(char **envp)
{
    if (!envp) return;
    for (int i = 0; envp[i]; i++)
        free(envp[i]);
    free(envp);
}

/* ---------- Function operations ---------- */

shell_func_t *shell_get_func(shell_state_t *state, const char *name)
{
    for (int i = 0; i < state->nfuncs; i++) {
        if (state->funcs[i].name && strcmp(state->funcs[i].name, name) == 0)
            return &state->funcs[i];
    }
    return NULL;
}

int shell_set_func(shell_state_t *state, const char *name, ast_node_t *body)
{
    /* Update existing */
    for (int i = 0; i < state->nfuncs; i++) {
        if (state->funcs[i].name && strcmp(state->funcs[i].name, name) == 0) {
            /* Don't free old body - AST might be shared; caller manages */
            state->funcs[i].body = body;
            return 0;
        }
    }
    if (state->nfuncs >= MAX_FUNCS) {
        fprintf(stderr, "bash: too many functions\n");
        return -1;
    }
    state->funcs[state->nfuncs].name = strdup(name);
    state->funcs[state->nfuncs].body = body;
    state->nfuncs++;
    return 0;
}

int shell_unset_func(shell_state_t *state, const char *name)
{
    for (int i = 0; i < state->nfuncs; i++) {
        if (state->funcs[i].name && strcmp(state->funcs[i].name, name) == 0) {
            free(state->funcs[i].name);
            state->funcs[i].name = NULL;
            state->funcs[i].body = NULL;
            return 0;
        }
    }
    return 0;
}

/* ---------- Alias operations ---------- */

const char *shell_get_alias(shell_state_t *state, const char *name)
{
    for (int i = 0; i < state->naliases; i++) {
        if (state->aliases[i].name &&
            strcmp(state->aliases[i].name, name) == 0)
            return state->aliases[i].value;
    }
    return NULL;
}

int shell_set_alias(shell_state_t *state, const char *name, const char *value)
{
    /* Update existing */
    for (int i = 0; i < state->naliases; i++) {
        if (state->aliases[i].name &&
            strcmp(state->aliases[i].name, name) == 0) {
            free(state->aliases[i].value);
            state->aliases[i].value = strdup(value);
            return 0;
        }
    }
    if (state->naliases >= MAX_ALIASES) {
        fprintf(stderr, "bash: too many aliases\n");
        return -1;
    }
    state->aliases[state->naliases].name = strdup(name);
    state->aliases[state->naliases].value = strdup(value);
    state->naliases++;
    return 0;
}

int shell_unset_alias(shell_state_t *state, const char *name)
{
    for (int i = 0; i < state->naliases; i++) {
        if (state->aliases[i].name &&
            strcmp(state->aliases[i].name, name) == 0) {
            free(state->aliases[i].name);
            free(state->aliases[i].value);
            state->aliases[i].name = NULL;
            state->aliases[i].value = NULL;
            return 0;
        }
    }
    return 0;
}

/* ---------- Parse assignment string ---------- */

int var_parse_assignment(const char *str, char **name_out, char **value_out)
{
    if (!str) return -1;

    const char *eq = strchr(str, '=');
    if (!eq || eq == str) return -1;

    /* Validate name: must start with alpha/_, then alnum/_ */
    for (const char *p = str; p < eq; p++) {
        char c = *p;
        if (p == str) {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'))
                return -1;
        } else {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '_'))
                return -1;
        }
    }

    size_t nlen = (size_t)(eq - str);
    *name_out = malloc(nlen + 1);
    if (!*name_out) return -1;
    memcpy(*name_out, str, nlen);
    (*name_out)[nlen] = '\0';

    *value_out = strdup(eq + 1);
    return 0;
}
