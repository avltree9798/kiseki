/*
 * Kiseki OS - Shell Word Expansion Implementation
 *
 * Full bash expansion pipeline:
 *   1. Brace expansion
 *   2. Tilde expansion
 *   3. Parameter expansion (including ${...} operators)
 *   4. Command substitution ($() and ``)
 *   5. Arithmetic expansion ($(()))
 *   6. Word splitting (IFS)
 *   7. Filename globbing
 *   8. Quote removal
 */

#include "expand.h"

/* ---------- Dynamic string buffer ---------- */

typedef struct {
    char   *data;
    size_t  len;
    size_t  cap;
} strbuf_t;

static void sb_init(strbuf_t *sb)
{
    sb->cap = 64;
    sb->data = malloc(sb->cap);
    sb->len = 0;
    if (sb->data)
        sb->data[0] = '\0';
}

static void sb_push(strbuf_t *sb, char c)
{
    if (sb->len + 1 >= sb->cap) {
        sb->cap *= 2;
        sb->data = realloc(sb->data, sb->cap);
    }
    sb->data[sb->len++] = c;
    sb->data[sb->len] = '\0';
}

static void sb_append(strbuf_t *sb, const char *s)
{
    if (!s) return;
    while (*s)
        sb_push(sb, *s++);
}

static void sb_append_n(strbuf_t *sb, const char *s, size_t n)
{
    for (size_t i = 0; i < n && s[i]; i++)
        sb_push(sb, s[i]);
}

static char *sb_detach(strbuf_t *sb)
{
    char *r = sb->data;
    sb->data = NULL;
    sb->len = sb->cap = 0;
    return r;
}

static void sb_free(strbuf_t *sb)
{
    free(sb->data);
    sb->data = NULL;
    sb->len = sb->cap = 0;
}

/* ---------- Word list operations ---------- */

word_list_t *word_list_new(void)
{
    word_list_t *wl = malloc(sizeof(word_list_t));
    if (!wl) return NULL;
    wl->capacity = 8;
    wl->words = malloc(sizeof(char *) * wl->capacity);
    wl->count = 0;
    return wl;
}

void word_list_add(word_list_t *wl, const char *word)
{
    if (!wl) return;
    if (wl->count >= wl->capacity) {
        wl->capacity *= 2;
        wl->words = realloc(wl->words, sizeof(char *) * wl->capacity);
    }
    wl->words[wl->count++] = strdup(word);
}

void word_list_add_list(word_list_t *dst, word_list_t *src)
{
    if (!dst || !src) return;
    for (int i = 0; i < src->count; i++)
        word_list_add(dst, src->words[i]);
}

void word_list_free(word_list_t *wl)
{
    if (!wl) return;
    for (int i = 0; i < wl->count; i++)
        free(wl->words[i]);
    free(wl->words);
    free(wl);
}

/* ---------- Helper: is_digit, is_alpha ---------- */

static int ch_is_digit(char c)
{
    return c >= '0' && c <= '9';
}

static int ch_is_alpha(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

static int ch_is_alnum(char c)
{
    return ch_is_alpha(c) || ch_is_digit(c);
}

/* ---------- 1. Brace expansion ---------- */

/*
 * Handles {a,b,c} and {1..10} and {a..z} forms.
 * Nested braces are not handled (bash does, but this is sufficient).
 */

static int find_matching_brace(const char *s, size_t start)
{
    int depth = 0;
    for (size_t i = start; s[i]; i++) {
        if (s[i] == '\\' && s[i + 1]) {
            i++;
            continue;
        }
        if (s[i] == '{') depth++;
        else if (s[i] == '}') {
            depth--;
            if (depth == 0)
                return (int)i;
        }
    }
    return -1;
}

/* Find unquoted comma at brace level 0 within braces content */
static int find_comma(const char *s, size_t start, size_t end)
{
    int depth = 0;
    for (size_t i = start; i < end; i++) {
        if (s[i] == '\\' && i + 1 < end) { i++; continue; }
        if (s[i] == '{') depth++;
        else if (s[i] == '}') depth--;
        else if (s[i] == ',' && depth == 0)
            return (int)i;
    }
    return -1;
}

/* Try to parse {start..end[..step]} sequence */
static word_list_t *try_seq_expansion(const char *prefix, const char *inner,
                                       const char *suffix)
{
    /* Look for ".." in inner */
    const char *dots = strstr(inner, "..");
    if (!dots)
        return NULL;

    const char *start_str = inner;
    size_t start_len = dots - inner;
    const char *rest = dots + 2;

    /* Look for optional second ".." for step */
    const char *dots2 = strstr(rest, "..");
    const char *end_str = rest;
    size_t end_len;
    long step = 0;
    int has_step = 0;

    if (dots2) {
        end_len = dots2 - rest;
        has_step = 1;
        step = strtol(dots2 + 2, NULL, 10);
    } else {
        end_len = strlen(rest);
    }

    /* Check if char range (single char start and end) */
    if (start_len == 1 && end_len == 1 &&
        ((start_str[0] >= 'a' && start_str[0] <= 'z') ||
         (start_str[0] >= 'A' && start_str[0] <= 'Z')) &&
        ((end_str[0] >= 'a' && end_str[0] <= 'z') ||
         (end_str[0] >= 'A' && end_str[0] <= 'Z'))) {
        /* Character sequence */
        char s = start_str[0];
        char e = end_str[0];
        int inc = (s <= e) ? 1 : -1;
        if (has_step && step != 0)
            inc = (step > 0) ? (int)step * inc : (int)(-step) * inc;
        if (inc == 0) inc = 1;

        word_list_t *wl = word_list_new();
        char buf[MAX_LINE];
        for (char c = s; (inc > 0) ? (c <= e) : (c >= e); c += inc) {
            snprintf(buf, sizeof(buf), "%s%c%s", prefix, c, suffix);
            word_list_add(wl, buf);
            if ((inc > 0 && c + inc < c) || (inc < 0 && c + inc > c))
                break; /* overflow guard */
        }
        return wl;
    }

    /* Numeric sequence */
    char start_buf[64], end_buf[64];
    memcpy(start_buf, start_str, start_len);
    start_buf[start_len] = '\0';
    memcpy(end_buf, end_str, end_len);
    end_buf[end_len] = '\0';

    char *ep1, *ep2;
    long sn = strtol(start_buf, &ep1, 10);
    long en = strtol(end_buf, &ep2, 10);
    if (*ep1 != '\0' || *ep2 != '\0')
        return NULL;

    long inc = (sn <= en) ? 1 : -1;
    if (has_step && step != 0)
        inc = (step > 0) ? step : -step;
    if (sn > en && inc > 0)
        inc = -inc;

    /* Detect zero-padding: if start or end has leading zeros */
    int pad = 0;
    if ((start_len > 1 && start_buf[0] == '0') ||
        (end_len > 1 && end_buf[0] == '0')) {
        int sl = (int)start_len;
        int el = (int)end_len;
        pad = sl > el ? sl : el;
    }

    word_list_t *wl = word_list_new();
    char buf[MAX_LINE];
    char num[64];

    for (long i = sn; (inc > 0) ? (i <= en) : (i >= en); i += inc) {
        if (pad > 0) {
            /* Zero-padded */
            char fmt[16];
            snprintf(fmt, sizeof(fmt), "%%0%dld", pad);
            snprintf(num, sizeof(num), fmt, i);
        } else {
            snprintf(num, sizeof(num), "%ld", i);
        }
        snprintf(buf, sizeof(buf), "%s%s%s", prefix, num, suffix);
        word_list_add(wl, buf);

        if (inc == 0) break;
    }
    return wl;
}

word_list_t *expand_braces(const char *word)
{
    word_list_t *result = word_list_new();

    /* Find first unquoted '{' */
    int brace_start = -1;
    for (int i = 0; word[i]; i++) {
        if (word[i] == '\\' && word[i + 1]) { i++; continue; }
        if (word[i] == '\'' || word[i] == '"') {
            char q = word[i++];
            while (word[i] && word[i] != q) {
                if (word[i] == '\\' && q == '"' && word[i + 1])
                    i++;
                i++;
            }
            continue;
        }
        if (word[i] == '{') {
            brace_start = i;
            break;
        }
    }

    if (brace_start < 0) {
        word_list_add(result, word);
        return result;
    }

    int brace_end = find_matching_brace(word, brace_start);
    if (brace_end < 0) {
        word_list_add(result, word);
        return result;
    }

    /* Extract prefix, inner content, suffix */
    char *prefix = strndup(word, brace_start);
    char *inner = strndup(word + brace_start + 1, brace_end - brace_start - 1);
    const char *suffix = word + brace_end + 1;

    /* Try sequence expansion first */
    word_list_t *seq = try_seq_expansion(prefix, inner, suffix);
    if (seq) {
        /* Recursively expand braces in each result */
        for (int i = 0; i < seq->count; i++) {
            word_list_t *sub = expand_braces(seq->words[i]);
            word_list_add_list(result, sub);
            word_list_free(sub);
        }
        word_list_free(seq);
        free(prefix);
        free(inner);
        return result;
    }

    /* Comma-separated expansion */
    int has_comma = (find_comma(inner, 0, strlen(inner)) >= 0);
    if (!has_comma) {
        /* No comma and no sequence - no expansion */
        word_list_add(result, word);
        free(prefix);
        free(inner);
        return result;
    }

    /* Split on commas at depth 0 */
    size_t inner_len = strlen(inner);
    size_t pos = 0;
    while (pos <= inner_len) {
        int comma = find_comma(inner, pos, inner_len);
        size_t end = (comma >= 0) ? (size_t)comma : inner_len;

        char *part = strndup(inner + pos, end - pos);
        char *expanded = malloc(strlen(prefix) + strlen(part) +
                                strlen(suffix) + 1);
        strcpy(expanded, prefix);
        strcat(expanded, part);
        strcat(expanded, suffix);

        /* Recursively expand braces */
        word_list_t *sub = expand_braces(expanded);
        word_list_add_list(result, sub);
        word_list_free(sub);

        free(part);
        free(expanded);

        if (comma < 0) break;
        pos = end + 1;
    }

    free(prefix);
    free(inner);
    return result;
}

/* ---------- 2. Tilde expansion ---------- */

char *expand_tilde(const char *word, shell_state_t *state)
{
    if (!word || word[0] != '~')
        return strdup(word);

    /* Find end of tilde prefix (up to first / or end) */
    size_t i = 1;
    while (word[i] && word[i] != '/')
        i++;

    if (i == 1) {
        /* Plain ~ -> $HOME */
        const char *home = shell_get_var(state, "HOME");
        if (!home) home = getenv("HOME");
        if (!home) return strdup(word);

        strbuf_t sb;
        sb_init(&sb);
        sb_append(&sb, home);
        sb_append(&sb, word + 1);
        return sb_detach(&sb);
    }

    /* ~user -> look up user's home dir. On Kiseki we don't have
     * getpwnam yet, so just leave it unexpanded. */
    return strdup(word);
}

/* ---------- 3. Parameter expansion ---------- */

/*
 * Handles: $VAR, ${VAR}, ${#VAR}, ${VAR:-default}, ${VAR:=default},
 *          ${VAR:?error}, ${VAR:+alt}, ${VAR#pattern}, ${VAR##pattern},
 *          ${VAR%pattern}, ${VAR%%pattern}, ${VAR/pattern/replace},
 *          ${VAR//pattern/replace}
 * Also: $?, $$, $!, $0-$9, $@, $*, $#, $-
 */

/* Get a variable value. Handles special parameters. */
static const char *get_var_value(shell_state_t *state, const char *name)
{
    if (!name || !*name)
        return NULL;

    /* Single-char special parameters */
    if (name[1] == '\0') {
        switch (name[0]) {
        case '?':
        case '$':
        case '!':
        case '#':
        case '-':
        case '@':
        case '*':
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
            return shell_get_special(state, name);
        }
    }

    /* Named special variables */
    if (strcmp(name, "PPID") == 0 || strcmp(name, "PWD") == 0 ||
        strcmp(name, "OLDPWD") == 0 || strcmp(name, "RANDOM") == 0 ||
        strcmp(name, "LINENO") == 0 || strcmp(name, "SECONDS") == 0 ||
        strcmp(name, "BASH_VERSION") == 0) {
        return shell_get_special(state, name);
    }

    /* Regular variable */
    const char *val = shell_get_var(state, name);
    if (val)
        return val;

    /* Try environment */
    return getenv(name);
}

/* Simple pattern match for # % operators (fnmatch-like) */
static int simple_pattern_match(const char *pattern, const char *string)
{
    return glob_match(pattern, string);
}

/*
 * Parse and expand a ${...} parameter expansion.
 * 'expr' points to the content between ${ and }, NOT including the braces.
 */
static char *expand_param_braced(const char *expr, shell_state_t *state)
{
    if (!expr || !*expr)
        return strdup("");

    /* ${#VAR} - string length */
    if (expr[0] == '#' && expr[1] != '\0') {
        const char *val = get_var_value(state, expr + 1);
        char buf[32];
        snprintf(buf, sizeof(buf), "%ld", val ? (long)strlen(val) : 0L);
        return strdup(buf);
    }

    /* Find the variable name and the operator */
    size_t name_len = 0;
    if (ch_is_alpha(expr[0]) || expr[0] == '_') {
        while (ch_is_alnum(expr[name_len]) || expr[name_len] == '_')
            name_len++;
    } else if (ch_is_digit(expr[0])) {
        name_len = 1;
    } else if (expr[0] == '?' || expr[0] == '$' || expr[0] == '!' ||
               expr[0] == '#' || expr[0] == '-' || expr[0] == '@' ||
               expr[0] == '*') {
        name_len = 1;
    }

    if (name_len == 0)
        return strdup("");

    char *name = strndup(expr, name_len);
    const char *op = expr + name_len;

    /* If no operator, just return the value */
    if (!*op) {
        const char *val = get_var_value(state, name);
        free(name);
        return strdup(val ? val : "");
    }

    const char *val = get_var_value(state, name);

    /* Operators */
    if (op[0] == ':' || op[0] == '-' || op[0] == '=' ||
        op[0] == '?' || op[0] == '+') {
        int colon = (op[0] == ':');
        char op_char = colon ? op[1] : op[0];
        const char *arg = colon ? op + 2 : op + 1;

        int is_unset = (val == NULL);
        int is_null = (val != NULL && val[0] == '\0');
        int use_default = colon ? (is_unset || is_null) : is_unset;

        switch (op_char) {
        case '-':   /* ${VAR:-default} */
            free(name);
            if (use_default)
                return strdup(arg);
            return strdup(val ? val : "");

        case '=':   /* ${VAR:=default} */
            if (use_default) {
                char *expanded_arg = strdup(arg);
                shell_set_var(state, name, expanded_arg);
                free(name);
                return expanded_arg;
            }
            free(name);
            return strdup(val ? val : "");

        case '?':   /* ${VAR:?error} */
            if (use_default) {
                if (arg && *arg)
                    fprintf(stderr, "bash: %s: %s\n", name, arg);
                else
                    fprintf(stderr, "bash: %s: parameter null or not set\n",
                            name);
                free(name);
                return strdup("");
            }
            free(name);
            return strdup(val ? val : "");

        case '+':   /* ${VAR:+alt} */
            free(name);
            if (!use_default)
                return strdup(arg);
            return strdup("");
        }
    }

    /* ${VAR#pattern} / ${VAR##pattern} - prefix removal */
    if (op[0] == '#') {
        int greedy = (op[1] == '#');
        const char *pattern = greedy ? op + 2 : op + 1;

        if (!val || !*val) {
            free(name);
            return strdup("");
        }

        size_t vlen = strlen(val);
        if (greedy) {
            /* Remove longest prefix */
            for (size_t i = vlen; i > 0; i--) {
                char *prefix = strndup(val, i);
                if (simple_pattern_match(pattern, prefix)) {
                    free(prefix);
                    free(name);
                    return strdup(val + i);
                }
                free(prefix);
            }
        } else {
            /* Remove shortest prefix */
            for (size_t i = 0; i <= vlen; i++) {
                char *prefix = strndup(val, i);
                if (simple_pattern_match(pattern, prefix)) {
                    free(prefix);
                    free(name);
                    return strdup(val + i);
                }
                free(prefix);
            }
        }

        free(name);
        return strdup(val);
    }

    /* ${VAR%pattern} / ${VAR%%pattern} - suffix removal */
    if (op[0] == '%') {
        int greedy = (op[1] == '%');
        const char *pattern = greedy ? op + 2 : op + 1;

        if (!val || !*val) {
            free(name);
            return strdup("");
        }

        size_t vlen = strlen(val);
        if (greedy) {
            /* Remove longest suffix */
            for (size_t i = 0; i < vlen; i++) {
                if (simple_pattern_match(pattern, val + i)) {
                    free(name);
                    return strndup(val, i);
                }
            }
        } else {
            /* Remove shortest suffix */
            for (size_t i = vlen; i > 0; i--) {
                if (simple_pattern_match(pattern, val + i)) {
                    free(name);
                    return strndup(val, i);
                }
            }
        }

        free(name);
        return strdup(val);
    }

    /* ${VAR/pattern/replace} / ${VAR//pattern/replace} */
    if (op[0] == '/') {
        int global = (op[1] == '/');
        const char *pat_start = global ? op + 2 : op + 1;

        /* Find the replacement string (separated by /) */
        const char *slash = strchr(pat_start, '/');
        char *pattern;
        const char *replace;

        if (slash) {
            pattern = strndup(pat_start, slash - pat_start);
            replace = slash + 1;
        } else {
            pattern = strdup(pat_start);
            replace = "";
        }

        if (!val || !*val) {
            free(pattern);
            free(name);
            return strdup("");
        }

        strbuf_t result;
        sb_init(&result);
        size_t vlen = strlen(val);

        for (size_t i = 0; i < vlen; ) {
            /* Try to match pattern starting at position i */
            int matched = 0;
            for (size_t end = i + 1; end <= vlen; end++) {
                char *sub = strndup(val + i, end - i);
                if (simple_pattern_match(pattern, sub)) {
                    sb_append(&result, replace);
                    i = end;
                    matched = 1;
                    free(sub);
                    break;
                }
                free(sub);
            }
            if (!matched) {
                sb_push(&result, val[i]);
                i++;
            } else if (!global) {
                /* Only replace first occurrence */
                sb_append(&result, val + i);
                break;
            }
        }

        free(pattern);
        free(name);
        return sb_detach(&result);
    }

    /* Unrecognized operator - just return value */
    free(name);
    return strdup(val ? val : "");
}

/*
 * Expand all parameter references in a string.
 * Handles: $VAR, ${...}, $?, $$, $!, $0-$9, $@, $*, $#, $-
 * Does NOT handle $() or $(()) - those are handled separately.
 */
char *expand_parameters(const char *word, shell_state_t *state)
{
    if (!word)
        return strdup("");

    strbuf_t sb;
    sb_init(&sb);
    size_t i = 0;
    size_t len = strlen(word);

    while (i < len) {
        char c = word[i];

        /* Single-quoted regions: no expansion, preserve quotes for later stages.
         * Quotes must survive through split_on_ifs() (which skips quoted regions)
         * and get removed in remove_quotes(). */
        if (c == '\'') {
            sb_push(&sb, c); /* preserve opening quote */
            i++;
            while (i < len && word[i] != '\'') {
                sb_push(&sb, word[i]);
                i++;
            }
            if (i < len) {
                sb_push(&sb, '\''); /* preserve closing quote */
                i++;
            }
            continue;
        }

        /* Double-quoted regions: expand $ but preserve quoting markers */
        if (c == '"') {
            /* Pass through - quote removal happens later */
            sb_push(&sb, c);
            i++;
            continue;
        }

        /* Backslash */
        if (c == '\\' && i + 1 < len) {
            sb_push(&sb, c);
            sb_push(&sb, word[i + 1]);
            i += 2;
            continue;
        }

        /* Dollar sign */
        if (c == '$' && i + 1 < len) {
            char next = word[i + 1];

            /* $(( arithmetic )) */
            if (next == '(' && i + 2 < len && word[i + 2] == '(') {
                /* Find matching )) */
                int depth = 1;
                size_t j = i + 3;
                while (j < len && depth > 0) {
                    if (word[j] == '(' && j + 1 < len && word[j + 1] == '(') {
                        depth++;
                        j += 2;
                        continue;
                    }
                    if (word[j] == ')' && j + 1 < len && word[j + 1] == ')') {
                        depth--;
                        if (depth == 0) break;
                        j += 2;
                        continue;
                    }
                    j++;
                }
                char *expr = strndup(word + i + 3, j - i - 3);
                char *result = expand_arithmetic(expr, state);
                sb_append(&sb, result);
                free(expr);
                free(result);
                i = j + 2; /* skip )) */
                continue;
            }

            /* $( command substitution ) */
            if (next == '(') {
                int depth = 1;
                size_t j = i + 2;
                while (j < len && depth > 0) {
                    if (word[j] == '(') depth++;
                    else if (word[j] == ')') depth--;
                    if (depth > 0) j++;
                }
                char *cmd = strndup(word + i + 2, j - i - 2);
                char *result = expand_command_subst(cmd, state);
                sb_append(&sb, result);
                free(cmd);
                free(result);
                i = j + 1; /* skip ) */
                continue;
            }

            /* ${...} */
            if (next == '{') {
                int depth = 1;
                size_t j = i + 2;
                while (j < len && depth > 0) {
                    if (word[j] == '{') depth++;
                    else if (word[j] == '}') depth--;
                    if (depth > 0) j++;
                }
                char *expr = strndup(word + i + 2, j - i - 2);
                char *result = expand_param_braced(expr, state);
                sb_append(&sb, result);
                free(expr);
                free(result);
                i = j + 1; /* skip } */
                continue;
            }

            /* $VAR (alphanumeric name) */
            if (ch_is_alpha(next) || next == '_') {
                size_t j = i + 1;
                while (j < len && (ch_is_alnum(word[j]) || word[j] == '_'))
                    j++;
                char *vname = strndup(word + i + 1, j - i - 1);
                const char *val = get_var_value(state, vname);
                if (val) sb_append(&sb, val);
                free(vname);
                i = j;
                continue;
            }

            /* Single-char specials: $?, $$, $!, $#, $-, $@, $*, $0-$9 */
            if (next == '?' || next == '$' || next == '!' || next == '#' ||
                next == '-' || next == '@' || next == '*' ||
                (next >= '0' && next <= '9')) {
                char name[2] = { next, '\0' };
                const char *val = get_var_value(state, name);
                if (val) sb_append(&sb, val);
                i += 2;
                continue;
            }

            /* Bare $ - just output it */
            sb_push(&sb, '$');
            i++;
            continue;
        }

        /* Backtick command substitution */
        if (c == '`') {
            size_t j = i + 1;
            while (j < len && word[j] != '`') {
                if (word[j] == '\\' && j + 1 < len)
                    j++;
                j++;
            }
            char *cmd = strndup(word + i + 1, j - i - 1);
            char *result = expand_command_subst(cmd, state);
            sb_append(&sb, result);
            free(cmd);
            free(result);
            i = j + 1; /* skip closing ` */
            continue;
        }

        /* Regular character */
        sb_push(&sb, c);
        i++;
    }

    return sb_detach(&sb);
}

/* ---------- 4. Command substitution ---------- */

char *expand_command_subst(const char *cmd, shell_state_t *state)
{
    if (!cmd || !*cmd)
        return strdup("");

    (void)state;

    int pipefd[2];
    if (pipe(pipefd) < 0)
        return strdup("");

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return strdup("");
    }

    if (pid == 0) {
        /* Child: redirect stdout to pipe, exec shell to run cmd */
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);

        /* Re-exec the shell with -c to run the command.
         * We use /bin/bash if available, otherwise try execvp("bash",...) */
        char *argv[4];
        argv[0] = "bash";
        argv[1] = "-c";
        argv[2] = (char *)cmd;
        argv[3] = NULL;
        execvp("bash", argv);
        _exit(127);
    }

    /* Parent: read output from pipe */
    close(pipefd[1]);

    strbuf_t sb;
    sb_init(&sb);
    char buf[1024];
    ssize_t n;
    while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) {
        sb_append_n(&sb, buf, n);
    }
    close(pipefd[0]);

    int status;
    waitpid(pid, &status, 0);
    if (state && WIFEXITED(status))
        state->last_exit_status = WEXITSTATUS(status);

    /* Remove trailing newlines (bash behavior) */
    while (sb.len > 0 && sb.data[sb.len - 1] == '\n') {
        sb.data[--sb.len] = '\0';
    }

    return sb_detach(&sb);
}

/* ---------- 5. Arithmetic expansion ---------- */

/*
 * Recursive descent arithmetic evaluator.
 *
 * Grammar (C-like precedence):
 *   expr       -> ternary
 *   ternary    -> or_expr ('?' expr ':' ternary)?
 *   or_expr    -> and_expr ('||' and_expr)*
 *   and_expr   -> bitor_expr ('&&' bitor_expr)*
 *   bitor_expr -> xor_expr ('|' xor_expr)*
 *   xor_expr   -> bitand_expr ('^' bitand_expr)*
 *   bitand_expr-> eq_expr ('&' eq_expr)*
 *   eq_expr    -> rel_expr (('=='|'!=') rel_expr)*
 *   rel_expr   -> shift_expr (('<'|'>'|'<='|'>=') shift_expr)*
 *   shift_expr -> add_expr (('<<'|'>>') add_expr)*
 *   add_expr   -> mul_expr (('+'|'-') mul_expr)*
 *   mul_expr   -> unary_expr (('*'|'/'|'%') unary_expr)*
 *   unary_expr -> ('+' | '-' | '!' | '~') unary_expr | primary
 *   primary    -> NUMBER | VARIABLE | '(' expr ')'
 */

typedef struct {
    const char     *str;
    size_t          pos;
    size_t          len;
    shell_state_t  *state;
    int             error;
} arith_ctx_t;

static void arith_skip_ws(arith_ctx_t *ctx)
{
    while (ctx->pos < ctx->len &&
           (ctx->str[ctx->pos] == ' ' || ctx->str[ctx->pos] == '\t'))
        ctx->pos++;
}

static char arith_peek(arith_ctx_t *ctx)
{
    arith_skip_ws(ctx);
    if (ctx->pos >= ctx->len)
        return '\0';
    return ctx->str[ctx->pos];
}

static char arith_peek_at(arith_ctx_t *ctx, size_t offset)
{
    arith_skip_ws(ctx);
    if (ctx->pos + offset >= ctx->len)
        return '\0';
    return ctx->str[ctx->pos + offset];
}

static long arith_parse_expr(arith_ctx_t *ctx);

static long arith_parse_primary(arith_ctx_t *ctx)
{
    arith_skip_ws(ctx);

    if (ctx->pos >= ctx->len) {
        ctx->error = 1;
        return 0;
    }

    char c = ctx->str[ctx->pos];

    /* Parenthesized expression */
    if (c == '(') {
        ctx->pos++;
        long val = arith_parse_expr(ctx);
        arith_skip_ws(ctx);
        if (ctx->pos < ctx->len && ctx->str[ctx->pos] == ')')
            ctx->pos++;
        else
            ctx->error = 1;
        return val;
    }

    /* Hex number */
    if (c == '0' && ctx->pos + 1 < ctx->len &&
        (ctx->str[ctx->pos + 1] == 'x' || ctx->str[ctx->pos + 1] == 'X')) {
        ctx->pos += 2;
        long val = 0;
        while (ctx->pos < ctx->len) {
            c = ctx->str[ctx->pos];
            if (ch_is_digit(c))
                val = val * 16 + (c - '0');
            else if (c >= 'a' && c <= 'f')
                val = val * 16 + (c - 'a' + 10);
            else if (c >= 'A' && c <= 'F')
                val = val * 16 + (c - 'A' + 10);
            else
                break;
            ctx->pos++;
        }
        return val;
    }

    /* Octal number (leading 0) */
    if (c == '0' && ctx->pos + 1 < ctx->len &&
        ctx->str[ctx->pos + 1] >= '0' && ctx->str[ctx->pos + 1] <= '7') {
        long val = 0;
        while (ctx->pos < ctx->len && ctx->str[ctx->pos] >= '0' &&
               ctx->str[ctx->pos] <= '7') {
            val = val * 8 + (ctx->str[ctx->pos] - '0');
            ctx->pos++;
        }
        return val;
    }

    /* Decimal number */
    if (ch_is_digit(c)) {
        long val = 0;
        while (ctx->pos < ctx->len && ch_is_digit(ctx->str[ctx->pos])) {
            val = val * 10 + (ctx->str[ctx->pos] - '0');
            ctx->pos++;
        }
        return val;
    }

    /* Variable reference (with optional $ prefix) */
    if (c == '$')
        ctx->pos++;

    if (ch_is_alpha(ctx->str[ctx->pos]) || ctx->str[ctx->pos] == '_') {
        size_t start = ctx->pos;
        while (ctx->pos < ctx->len &&
               (ch_is_alnum(ctx->str[ctx->pos]) || ctx->str[ctx->pos] == '_'))
            ctx->pos++;
        char *vname = strndup(ctx->str + start, ctx->pos - start);
        const char *val = get_var_value(ctx->state, vname);
        free(vname);
        if (val && *val)
            return strtol(val, NULL, 0);
        return 0;
    }

    ctx->error = 1;
    return 0;
}

static long arith_parse_unary(arith_ctx_t *ctx)
{
    arith_skip_ws(ctx);
    char c = arith_peek(ctx);

    if (c == '+') {
        ctx->pos++;
        return arith_parse_unary(ctx);
    }
    if (c == '-') {
        ctx->pos++;
        return -arith_parse_unary(ctx);
    }
    if (c == '!') {
        ctx->pos++;
        return !arith_parse_unary(ctx);
    }
    if (c == '~') {
        ctx->pos++;
        return ~arith_parse_unary(ctx);
    }
    /* Pre-increment/decrement: not supported yet */
    return arith_parse_primary(ctx);
}

static long arith_parse_mul(arith_ctx_t *ctx)
{
    long left = arith_parse_unary(ctx);
    while (!ctx->error) {
        char c = arith_peek(ctx);
        if (c == '*') { ctx->pos++; left *= arith_parse_unary(ctx); }
        else if (c == '/' && arith_peek_at(ctx, 0) != '/') {
            /* Make sure it's not // (which would be caught above) */
            ctx->pos++;
            long right = arith_parse_unary(ctx);
            if (right == 0) { ctx->error = 1; return 0; }
            left /= right;
        }
        else if (c == '%') {
            ctx->pos++;
            long right = arith_parse_unary(ctx);
            if (right == 0) { ctx->error = 1; return 0; }
            left %= right;
        }
        else break;
    }
    return left;
}

static long arith_parse_add(arith_ctx_t *ctx)
{
    long left = arith_parse_mul(ctx);
    while (!ctx->error) {
        char c = arith_peek(ctx);
        if (c == '+') { ctx->pos++; left += arith_parse_mul(ctx); }
        else if (c == '-') { ctx->pos++; left -= arith_parse_mul(ctx); }
        else break;
    }
    return left;
}

static long arith_parse_shift(arith_ctx_t *ctx)
{
    long left = arith_parse_add(ctx);
    while (!ctx->error) {
        arith_skip_ws(ctx);
        if (ctx->pos + 1 < ctx->len &&
            ctx->str[ctx->pos] == '<' && ctx->str[ctx->pos + 1] == '<') {
            ctx->pos += 2;
            left <<= arith_parse_add(ctx);
        } else if (ctx->pos + 1 < ctx->len &&
                   ctx->str[ctx->pos] == '>' && ctx->str[ctx->pos + 1] == '>') {
            ctx->pos += 2;
            left >>= arith_parse_add(ctx);
        } else break;
    }
    return left;
}

static long arith_parse_rel(arith_ctx_t *ctx)
{
    long left = arith_parse_shift(ctx);
    while (!ctx->error) {
        arith_skip_ws(ctx);
        if (ctx->pos + 1 < ctx->len &&
            ctx->str[ctx->pos] == '<' && ctx->str[ctx->pos + 1] == '=') {
            ctx->pos += 2;
            left = left <= arith_parse_shift(ctx);
        } else if (ctx->pos + 1 < ctx->len &&
                   ctx->str[ctx->pos] == '>' && ctx->str[ctx->pos + 1] == '=') {
            ctx->pos += 2;
            left = left >= arith_parse_shift(ctx);
        } else if (ctx->str[ctx->pos] == '<' &&
                   (ctx->pos + 1 >= ctx->len || ctx->str[ctx->pos + 1] != '<')) {
            ctx->pos++;
            left = left < arith_parse_shift(ctx);
        } else if (ctx->str[ctx->pos] == '>' &&
                   (ctx->pos + 1 >= ctx->len || ctx->str[ctx->pos + 1] != '>')) {
            ctx->pos++;
            left = left > arith_parse_shift(ctx);
        } else break;
    }
    return left;
}

static long arith_parse_eq(arith_ctx_t *ctx)
{
    long left = arith_parse_rel(ctx);
    while (!ctx->error) {
        arith_skip_ws(ctx);
        if (ctx->pos + 1 < ctx->len &&
            ctx->str[ctx->pos] == '=' && ctx->str[ctx->pos + 1] == '=') {
            ctx->pos += 2;
            left = left == arith_parse_rel(ctx);
        } else if (ctx->pos + 1 < ctx->len &&
                   ctx->str[ctx->pos] == '!' && ctx->str[ctx->pos + 1] == '=') {
            ctx->pos += 2;
            left = left != arith_parse_rel(ctx);
        } else break;
    }
    return left;
}

static long arith_parse_bitand(arith_ctx_t *ctx)
{
    long left = arith_parse_eq(ctx);
    while (!ctx->error) {
        arith_skip_ws(ctx);
        if (ctx->str[ctx->pos] == '&' &&
            (ctx->pos + 1 >= ctx->len || ctx->str[ctx->pos + 1] != '&')) {
            ctx->pos++;
            left &= arith_parse_eq(ctx);
        } else break;
    }
    return left;
}

static long arith_parse_xor(arith_ctx_t *ctx)
{
    long left = arith_parse_bitand(ctx);
    while (!ctx->error) {
        if (arith_peek(ctx) == '^') {
            ctx->pos++;
            left ^= arith_parse_bitand(ctx);
        } else break;
    }
    return left;
}

static long arith_parse_bitor(arith_ctx_t *ctx)
{
    long left = arith_parse_xor(ctx);
    while (!ctx->error) {
        arith_skip_ws(ctx);
        if (ctx->str[ctx->pos] == '|' &&
            (ctx->pos + 1 >= ctx->len || ctx->str[ctx->pos + 1] != '|')) {
            ctx->pos++;
            left |= arith_parse_xor(ctx);
        } else break;
    }
    return left;
}

static long arith_parse_and(arith_ctx_t *ctx)
{
    long left = arith_parse_bitor(ctx);
    while (!ctx->error) {
        arith_skip_ws(ctx);
        if (ctx->pos + 1 < ctx->len &&
            ctx->str[ctx->pos] == '&' && ctx->str[ctx->pos + 1] == '&') {
            ctx->pos += 2;
            long right = arith_parse_bitor(ctx);
            left = left && right;
        } else break;
    }
    return left;
}

static long arith_parse_or(arith_ctx_t *ctx)
{
    long left = arith_parse_and(ctx);
    while (!ctx->error) {
        arith_skip_ws(ctx);
        if (ctx->pos + 1 < ctx->len &&
            ctx->str[ctx->pos] == '|' && ctx->str[ctx->pos + 1] == '|') {
            ctx->pos += 2;
            long right = arith_parse_and(ctx);
            left = left || right;
        } else break;
    }
    return left;
}

static long arith_parse_ternary(arith_ctx_t *ctx)
{
    long cond = arith_parse_or(ctx);
    arith_skip_ws(ctx);
    if (ctx->pos < ctx->len && ctx->str[ctx->pos] == '?') {
        ctx->pos++;
        long then_val = arith_parse_expr(ctx);
        arith_skip_ws(ctx);
        if (ctx->pos < ctx->len && ctx->str[ctx->pos] == ':')
            ctx->pos++;
        else
            ctx->error = 1;
        long else_val = arith_parse_ternary(ctx);
        return cond ? then_val : else_val;
    }
    return cond;
}

static long arith_parse_expr(arith_ctx_t *ctx)
{
    return arith_parse_ternary(ctx);
}

long arith_eval(const char *expr, shell_state_t *state, int *err)
{
    if (!expr || !*expr) {
        if (err) *err = 0;
        return 0;
    }

    arith_ctx_t ctx;
    ctx.str = expr;
    ctx.pos = 0;
    ctx.len = strlen(expr);
    ctx.state = state;
    ctx.error = 0;

    long result = arith_parse_expr(&ctx);

    if (err) *err = ctx.error;
    return result;
}

char *expand_arithmetic(const char *expr, shell_state_t *state)
{
    int err = 0;
    /* First expand variables within the expression */
    char *expanded = expand_parameters(expr, state);
    long result = arith_eval(expanded, state, &err);
    free(expanded);

    if (err) {
        fprintf(stderr, "bash: arithmetic syntax error: %s\n", expr);
        return strdup("0");
    }

    char buf[32];
    snprintf(buf, sizeof(buf), "%ld", result);
    return strdup(buf);
}

/* ---------- 6. Word splitting ---------- */

word_list_t *split_on_ifs(const char *word, shell_state_t *state)
{
    word_list_t *wl = word_list_new();
    if (!word || !*word)
        return wl;

    const char *ifs = shell_get_var(state, "IFS");
    if (!ifs)
        ifs = " \t\n"; /* default IFS */

    /* If IFS is empty, no splitting occurs */
    if (!*ifs) {
        word_list_add(wl, word);
        return wl;
    }

    /* Classify IFS characters: whitespace vs non-whitespace */
    int ifs_ws[256];
    int ifs_nws[256];
    memset(ifs_ws, 0, sizeof(ifs_ws));
    memset(ifs_nws, 0, sizeof(ifs_nws));

    for (const char *p = ifs; *p; p++) {
        unsigned char uc = (unsigned char)*p;
        if (*p == ' ' || *p == '\t' || *p == '\n')
            ifs_ws[uc] = 1;
        else
            ifs_nws[uc] = 1;
    }

    size_t len = strlen(word);
    size_t i = 0;

    /* Skip leading IFS whitespace */
    while (i < len && ifs_ws[(unsigned char)word[i]])
        i++;

    strbuf_t current;
    sb_init(&current);
    int in_word = 0;

    while (i < len) {
        unsigned char c = (unsigned char)word[i];

        /* Skip single-quoted regions — no splitting inside quotes */
        if (c == '\'') {
            sb_push(&current, word[i]);
            i++;
            while (i < len && word[i] != '\'') {
                sb_push(&current, word[i]);
                i++;
            }
            if (i < len) {
                sb_push(&current, word[i]); /* closing quote */
                i++;
            }
            in_word = 1;
            continue;
        }

        /* Skip double-quoted regions — no splitting inside quotes */
        if (c == '"') {
            sb_push(&current, word[i]);
            i++;
            while (i < len && word[i] != '"') {
                if (word[i] == '\\' && i + 1 < len) {
                    sb_push(&current, word[i]);
                    i++;
                    sb_push(&current, word[i]);
                    i++;
                    continue;
                }
                sb_push(&current, word[i]);
                i++;
            }
            if (i < len) {
                sb_push(&current, word[i]); /* closing quote */
                i++;
            }
            in_word = 1;
            continue;
        }

        /* Backslash escapes — don't split on the escaped char */
        if (c == '\\' && i + 1 < len) {
            sb_push(&current, word[i]);
            sb_push(&current, word[i + 1]);
            i += 2;
            in_word = 1;
            continue;
        }

        if (ifs_nws[c]) {
            /* Non-whitespace IFS delimiter */
            if (in_word || current.len > 0) {
                word_list_add(wl, current.data);
                current.len = 0;
                current.data[0] = '\0';
            } else {
                /* Empty field */
                word_list_add(wl, "");
            }
            i++;
            /* Skip IFS whitespace after delimiter */
            while (i < len && ifs_ws[(unsigned char)word[i]])
                i++;
            in_word = 0;
            continue;
        }

        if (ifs_ws[c]) {
            /* IFS whitespace: terminates current field */
            if (in_word) {
                word_list_add(wl, current.data);
                current.len = 0;
                current.data[0] = '\0';
                in_word = 0;
            }
            while (i < len && ifs_ws[(unsigned char)word[i]])
                i++;
            continue;
        }

        /* Regular character */
        sb_push(&current, word[i]);
        in_word = 1;
        i++;
    }

    /* Remaining word */
    if (in_word || current.len > 0) {
        word_list_add(wl, current.data);
    }

    sb_free(&current);
    return wl;
}

/* ---------- 7. Filename globbing ---------- */

/* Pattern matching: supports *, ?, [...], [!...], [a-z] */
int glob_match(const char *pattern, const char *string)
{
    const char *p = pattern;
    const char *s = string;

    while (*p) {
        if (*p == '*') {
            /* Skip consecutive stars */
            while (*p == '*') p++;
            if (!*p) return 1; /* trailing * matches everything */

            /* Try matching rest of pattern at each position */
            while (*s) {
                if (glob_match(p, s))
                    return 1;
                s++;
            }
            return glob_match(p, s);
        }

        if (*p == '?') {
            if (!*s) return 0;
            p++;
            s++;
            continue;
        }

        if (*p == '[') {
            if (!*s) return 0;
            p++;
            int negate = 0;
            if (*p == '!' || *p == '^') {
                negate = 1;
                p++;
            }

            int matched = 0;
            int first = 1;
            char prev = 0;

            while (*p && *p != ']') {
                if (*p == '-' && !first && p[1] && p[1] != ']') {
                    p++;
                    if ((unsigned char)*s >= (unsigned char)prev &&
                        (unsigned char)*s <= (unsigned char)*p)
                        matched = 1;
                    prev = *p;
                    p++;
                } else {
                    if (*p == *s)
                        matched = 1;
                    prev = *p;
                    p++;
                }
                first = 0;
            }

            if (*p == ']') p++;
            if (negate) matched = !matched;
            if (!matched) return 0;
            s++;
            continue;
        }

        /* Literal match */
        if (*p == '\\' && p[1]) {
            p++;
        }
        if (*p != *s) return 0;
        p++;
        s++;
    }

    return *s == '\0';
}

/* Check if a word contains unquoted glob characters */
static int has_glob_chars(const char *word)
{
    int in_sq = 0, in_dq = 0;
    for (size_t i = 0; word[i]; i++) {
        if (word[i] == '\\' && word[i + 1]) { i++; continue; }
        if (word[i] == '\'' && !in_dq) { in_sq = !in_sq; continue; }
        if (word[i] == '"' && !in_sq) { in_dq = !in_dq; continue; }
        if (!in_sq && !in_dq) {
            if (word[i] == '*' || word[i] == '?')
                return 1;
            /* Only treat '[' as glob if there's a matching ']' */
            if (word[i] == '[') {
                const char *p = &word[i + 1];
                while (*p && *p != ']') p++;
                if (*p == ']')
                    return 1;
            }
        }
    }
    return 0;
}

word_list_t *expand_pattern(const char *pattern)
{
    word_list_t *wl = word_list_new();

    if (!pattern || !*pattern || !has_glob_chars(pattern)) {
        if (pattern)
            word_list_add(wl, pattern);
        return wl;
    }

    /* Remove quotes for the actual matching */
    char *clean = remove_quotes(pattern);

    /* Determine directory to scan:
     * If pattern contains '/', split into dir + name components.
     * For simplicity, we only glob the last component. */
    const char *slash = strrchr(clean, '/');
    char *dir;
    const char *name_pat;

    if (slash) {
        dir = strndup(clean, slash - clean + 1);
        name_pat = slash + 1;
    } else {
        dir = strdup(".");
        name_pat = clean;
    }

    DIR *dp = opendir(dir);
    if (!dp) {
        /* No matches - return the pattern literally */
        word_list_add(wl, pattern);
        free(dir);
        free(clean);
        return wl;
    }

    struct dirent *ent;
    int matched = 0;

    while ((ent = readdir(dp)) != NULL) {
        /* Skip hidden files unless pattern starts with . */
        if (ent->d_name[0] == '.' && name_pat[0] != '.')
            continue;

        if (glob_match(name_pat, ent->d_name)) {
            strbuf_t path;
            sb_init(&path);
            if (slash) {
                sb_append(&path, dir);
                sb_append(&path, ent->d_name);
            } else {
                sb_append(&path, ent->d_name);
            }
            word_list_add(wl, path.data);
            sb_free(&path);
            matched++;
        }
    }
    closedir(dp);

    /* If no matches, return the pattern literally (bash default) */
    if (!matched)
        word_list_add(wl, pattern);

    /* Sort the results (simple insertion sort) */
    if (wl->count > 1) {
        for (int i = 1; i < wl->count; i++) {
            char *key = wl->words[i];
            int j = i - 1;
            while (j >= 0 && strcmp(wl->words[j], key) > 0) {
                wl->words[j + 1] = wl->words[j];
                j--;
            }
            wl->words[j + 1] = key;
        }
    }

    free(dir);
    free(clean);
    return wl;
}

/* ---------- 8. Quote removal ---------- */

char *remove_quotes(const char *word)
{
    if (!word)
        return strdup("");

    strbuf_t sb;
    sb_init(&sb);
    size_t i = 0;
    size_t len = strlen(word);

    while (i < len) {
        char c = word[i];

        /* Single quotes: remove quotes, pass content literally */
        if (c == '\'') {
            i++;
            while (i < len && word[i] != '\'') {
                sb_push(&sb, word[i]);
                i++;
            }
            if (i < len) i++; /* skip closing ' */
            continue;
        }

        /* Double quotes: remove quotes, process backslash escapes */
        if (c == '"') {
            i++;
            while (i < len && word[i] != '"') {
                if (word[i] == '\\' && i + 1 < len) {
                    char next = word[i + 1];
                    if (next == '$' || next == '`' || next == '"' ||
                        next == '\\' || next == '\n') {
                        sb_push(&sb, next);
                        i += 2;
                        continue;
                    }
                }
                sb_push(&sb, word[i]);
                i++;
            }
            if (i < len) i++; /* skip closing " */
            continue;
        }

        /* Backslash outside quotes */
        if (c == '\\' && i + 1 < len) {
            sb_push(&sb, word[i + 1]);
            i += 2;
            continue;
        }

        sb_push(&sb, c);
        i++;
    }

    return sb_detach(&sb);
}

/* ---------- Main expansion pipeline ---------- */

/*
 * Expand a single word through the full bash expansion pipeline.
 * Returns a word_list because expansion can produce multiple words.
 */
word_list_t *expand_word(const char *word, shell_state_t *state)
{
    if (!word)
        return word_list_new();

    /* 1. Brace expansion */
    word_list_t *after_brace = expand_braces(word);

    word_list_t *result = word_list_new();

    for (int i = 0; i < after_brace->count; i++) {
        const char *w = after_brace->words[i];

        /* 2. Tilde expansion */
        char *after_tilde = expand_tilde(w, state);

        /* 3. Parameter expansion (also handles 4. command subst and 5. arith) */
        char *after_params = expand_parameters(after_tilde, state);
        free(after_tilde);

        /* 6. Word splitting */
        word_list_t *after_split = split_on_ifs(after_params, state);
        free(after_params);

        /* 7. Filename globbing + 8. Quote removal */
        for (int j = 0; j < after_split->count; j++) {
            if (has_glob_chars(after_split->words[j]) &&
                !(state && state->opts.noglob)) {
                word_list_t *globbed = expand_pattern(after_split->words[j]);
                /* Quote removal on each glob result */
                for (int k = 0; k < globbed->count; k++) {
                    char *clean = remove_quotes(globbed->words[k]);
                    word_list_add(result, clean);
                    free(clean);
                }
                word_list_free(globbed);
            } else {
                /* 8. Quote removal */
                char *clean = remove_quotes(after_split->words[j]);
                word_list_add(result, clean);
                free(clean);
            }
        }
        word_list_free(after_split);
    }

    word_list_free(after_brace);
    return result;
}

/*
 * Expand an array of words. Each word goes through full expansion.
 */
word_list_t *expand_words(char **words, int nwords, shell_state_t *state)
{
    word_list_t *result = word_list_new();
    for (int i = 0; i < nwords; i++) {
        word_list_t *expanded = expand_word(words[i], state);
        word_list_add_list(result, expanded);
        word_list_free(expanded);
    }
    return result;
}

/*
 * Expand a word without word splitting or globbing.
 * Used for: variable assignments, here-document bodies, etc.
 */
char *expand_word_nosplit(const char *word, shell_state_t *state)
{
    if (!word)
        return strdup("");

    char *after_tilde = expand_tilde(word, state);
    char *after_params = expand_parameters(after_tilde, state);
    free(after_tilde);
    char *clean = remove_quotes(after_params);
    free(after_params);
    return clean;
}

/*
 * Expand assignment value (right side of VAR=value).
 * Performs tilde expansion, parameter expansion, command substitution,
 * arithmetic expansion, and quote removal. NO word splitting or globbing.
 */
char *expand_assignment_value(const char *value, shell_state_t *state)
{
    return expand_word_nosplit(value, state);
}
