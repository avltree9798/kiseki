/*
 * Kiseki OS - Shell Command History
 *
 * Circular buffer for command history, with persistence,
 * navigation, and history expansion (!, !!, !N, ^old^new).
 */

#include "shell.h"

/* ---------- History buffer ---------- */

#define HISTORY_MAX 1000

static char *history_entries[HISTORY_MAX];
static int   history_count = 0;      /* Total entries ever added */
static int   history_size = 0;       /* Current number of valid entries */
static int   history_start = 0;      /* Start index in circular buffer */

/* ---------- history_add ---------- */

void history_add(const char *line)
{
    if (!line || !line[0]) return;

    /* Don't add duplicates of the last entry */
    if (history_size > 0) {
        int last_idx = (history_start + history_size - 1) % HISTORY_MAX;
        if (history_entries[last_idx] &&
            strcmp(history_entries[last_idx], line) == 0)
            return;
    }

    if (history_size < HISTORY_MAX) {
        /* Buffer not yet full */
        int idx = (history_start + history_size) % HISTORY_MAX;
        history_entries[idx] = strdup(line);
        history_size++;
    } else {
        /* Buffer full: overwrite oldest */
        free(history_entries[history_start]);
        history_entries[history_start] = strdup(line);
        history_start = (history_start + 1) % HISTORY_MAX;
    }
    history_count++;
}

/* ---------- history_get ---------- */

const char *history_get(int index)
{
    /* index is 1-based history number */
    /* Convert to our internal representation */
    int base = history_count - history_size + 1;

    if (index < base || index > history_count)
        return NULL;

    int offset = index - base;
    int real_idx = (history_start + offset) % HISTORY_MAX;
    return history_entries[real_idx];
}

/* ---------- history_get_offset ---------- */

/* Get by offset from end: 0 = last, 1 = second to last, etc. */
const char *history_get_offset(int offset)
{
    if (offset < 0 || offset >= history_size)
        return NULL;

    int idx = (history_start + history_size - 1 - offset) % HISTORY_MAX;
    return history_entries[idx];
}

/* ---------- history_get_count ---------- */

int history_get_count(void)
{
    return history_count;
}

/* ---------- history_get_size ---------- */

int history_get_size(void)
{
    return history_size;
}

/* ---------- history_search ---------- */

const char *history_search(const char *prefix)
{
    if (!prefix || !prefix[0]) return NULL;

    size_t plen = strlen(prefix);

    /* Search backward from most recent */
    for (int i = history_size - 1; i >= 0; i--) {
        int idx = (history_start + i) % HISTORY_MAX;
        if (history_entries[idx] &&
            strncmp(history_entries[idx], prefix, plen) == 0)
            return history_entries[idx];
    }
    return NULL;
}

/* ---------- history_search_containing ---------- */

const char *history_search_containing(const char *substr)
{
    if (!substr || !substr[0]) return NULL;

    for (int i = history_size - 1; i >= 0; i--) {
        int idx = (history_start + i) % HISTORY_MAX;
        if (history_entries[idx] && strstr(history_entries[idx], substr))
            return history_entries[idx];
    }
    return NULL;
}

/* ---------- history_load ---------- */

void history_load(const char *filename)
{
    if (!filename) return;

    FILE *fp = fopen(filename, "r");
    if (!fp) return;

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), fp)) {
        /* Strip trailing newline */
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n')
            line[len - 1] = '\0';
        if (line[0] != '\0')
            history_add(line);
    }

    fclose(fp);
}

/* ---------- history_save ---------- */

void history_save(const char *filename)
{
    if (!filename) return;

    FILE *fp = fopen(filename, "w");
    if (!fp) return;

    for (int i = 0; i < history_size; i++) {
        int idx = (history_start + i) % HISTORY_MAX;
        if (history_entries[idx])
            fprintf(fp, "%s\n", history_entries[idx]);
    }

    fclose(fp);
}

/* ---------- history_expand ---------- */

/*
 * Handle history expansion:
 *   !!           -> last command
 *   !N           -> command number N
 *   !-N          -> N-th previous command
 *   !prefix      -> most recent command starting with prefix
 *   !?string?    -> most recent command containing string
 *   !$           -> last argument of previous command
 *   ^old^new     -> quick substitution on previous command
 *   !:N          -> N-th word of previous command
 *
 * Returns: new allocated string with expansions, or NULL on error.
 *          If no expansion needed, returns a copy of the input.
 */
char *history_expand(const char *line)
{
    if (!line) return NULL;

    /* Quick check: any history references? */
    int has_bang = 0;
    int has_caret = (line[0] == '^');
    for (const char *p = line; *p; p++) {
        if (*p == '!' && p[1] != ' ' && p[1] != '\t' && p[1] != '\0' &&
            p[1] != '=') {
            has_bang = 1;
            break;
        }
    }

    if (!has_bang && !has_caret)
        return strdup(line);

    /* Handle ^old^new^ quick substitution */
    if (has_caret && line[0] == '^') {
        const char *old_start = line + 1;
        const char *old_end = strchr(old_start, '^');
        if (!old_end) return strdup(line);

        size_t old_len = (size_t)(old_end - old_start);
        char *old_str = malloc(old_len + 1);
        memcpy(old_str, old_start, old_len);
        old_str[old_len] = '\0';

        const char *new_start = old_end + 1;
        const char *new_end = strchr(new_start, '^');
        size_t new_len = new_end ? (size_t)(new_end - new_start) : strlen(new_start);
        char *new_str = malloc(new_len + 1);
        memcpy(new_str, new_start, new_len);
        new_str[new_len] = '\0';

        /* Get previous command */
        const char *prev = history_get_offset(0);
        if (!prev) {
            free(old_str);
            free(new_str);
            fprintf(stderr, "bash: !: event not found\n");
            return NULL;
        }

        /* Find and replace */
        const char *pos = strstr(prev, old_str);
        if (!pos) {
            fprintf(stderr, "bash: ^%s^%s: substitution failed\n",
                    old_str, new_str);
            free(old_str);
            free(new_str);
            return NULL;
        }

        size_t prev_len = strlen(prev);
        size_t result_len = prev_len - old_len + new_len;
        char *result = malloc(result_len + 1);
        size_t prefix_len = (size_t)(pos - prev);
        memcpy(result, prev, prefix_len);
        memcpy(result + prefix_len, new_str, new_len);
        memcpy(result + prefix_len + new_len,
               pos + old_len,
               prev_len - prefix_len - old_len);
        result[result_len] = '\0';

        free(old_str);
        free(new_str);

        /* Print expanded command */
        printf("%s\n", result);
        return result;
    }

    /* Process ! expansions */
    size_t cap = strlen(line) * 2 + 64;
    char *result = malloc(cap);
    size_t rlen = 0;
    const char *p = line;
    int in_single_quote = 0;

    while (*p) {
        /* Track single quotes (no expansion inside single quotes) */
        if (*p == '\'') {
            in_single_quote = !in_single_quote;
            if (rlen + 1 >= cap) { cap *= 2; result = realloc(result, cap); }
            result[rlen++] = *p++;
            continue;
        }

        if (in_single_quote || *p != '!') {
            if (rlen + 1 >= cap) { cap *= 2; result = realloc(result, cap); }
            result[rlen++] = *p++;
            continue;
        }

        /* We have a ! */
        p++; /* Skip ! */

        const char *expanded = NULL;

        if (*p == '!') {
            /* !! -> last command */
            expanded = history_get_offset(0);
            if (!expanded) {
                fprintf(stderr, "bash: !!: event not found\n");
                free(result);
                return NULL;
            }
            p++;
        } else if (*p == '$') {
            /* !$ -> last argument of previous command */
            const char *prev = history_get_offset(0);
            if (!prev) {
                fprintf(stderr, "bash: !$: event not found\n");
                free(result);
                return NULL;
            }
            /* Find last word */
            const char *last_word = prev;
            const char *q = prev;
            while (*q) {
                while (*q == ' ' || *q == '\t') q++;
                if (*q) {
                    last_word = q;
                    while (*q && *q != ' ' && *q != '\t') q++;
                }
            }
            /* Copy last word only */
            size_t wlen = (size_t)(q - last_word);
            while (rlen + wlen >= cap) { cap *= 2; result = realloc(result, cap); }
            memcpy(result + rlen, last_word, wlen);
            rlen += wlen;
            p++;
            continue;
        } else if (*p == '-' || (*p >= '0' && *p <= '9')) {
            /* !N or !-N */
            int neg = 0;
            if (*p == '-') { neg = 1; p++; }
            int num = 0;
            while (*p >= '0' && *p <= '9')
                num = num * 10 + (*p++ - '0');

            if (neg) {
                expanded = history_get_offset(num - 1);
            } else {
                expanded = history_get(num);
            }

            if (!expanded) {
                fprintf(stderr, "bash: !%s%d: event not found\n",
                        neg ? "-" : "", num);
                free(result);
                return NULL;
            }
        } else if (*p == '?') {
            /* !?string? */
            p++;
            const char *end = strchr(p, '?');
            size_t slen = end ? (size_t)(end - p) : strlen(p);
            char *search = malloc(slen + 1);
            memcpy(search, p, slen);
            search[slen] = '\0';
            expanded = history_search_containing(search);
            free(search);
            if (!expanded) {
                fprintf(stderr, "bash: !?: event not found\n");
                free(result);
                return NULL;
            }
            p += slen;
            if (*p == '?') p++;
        } else if (*p == ':') {
            /* !:N - word N of previous command */
            p++;
            int word_num = 0;
            while (*p >= '0' && *p <= '9')
                word_num = word_num * 10 + (*p++ - '0');

            const char *prev = history_get_offset(0);
            if (!prev) {
                fprintf(stderr, "bash: !: event not found\n");
                free(result);
                return NULL;
            }

            /* Find word N */
            const char *q = prev;
            int widx = 0;
            while (*q) {
                while (*q == ' ' || *q == '\t') q++;
                if (*q == '\0') break;
                const char *wstart = q;
                while (*q && *q != ' ' && *q != '\t') q++;
                if (widx == word_num) {
                    size_t wlen = (size_t)(q - wstart);
                    while (rlen + wlen >= cap) { cap *= 2; result = realloc(result, cap); }
                    memcpy(result + rlen, wstart, wlen);
                    rlen += wlen;
                    expanded = NULL; /* Already handled */
                    break;
                }
                widx++;
            }
            continue;
        } else if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                   *p == '_') {
            /* !prefix */
            const char *start = p;
            while ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                   (*p >= '0' && *p <= '9') || *p == '_' || *p == '-' ||
                   *p == '.' || *p == '/')
                p++;

            size_t plen = (size_t)(p - start);
            char *prefix = malloc(plen + 1);
            memcpy(prefix, start, plen);
            prefix[plen] = '\0';

            expanded = history_search(prefix);
            free(prefix);

            if (!expanded) {
                fprintf(stderr, "bash: !%.*s: event not found\n",
                        (int)plen, start);
                free(result);
                return NULL;
            }
        } else {
            /* Lone ! followed by space/etc - literal ! */
            if (rlen + 1 >= cap) { cap *= 2; result = realloc(result, cap); }
            result[rlen++] = '!';
            continue;
        }

        if (expanded) {
            size_t elen = strlen(expanded);
            while (rlen + elen >= cap) { cap *= 2; result = realloc(result, cap); }
            memcpy(result + rlen, expanded, elen);
            rlen += elen;
        }
    }

    result[rlen] = '\0';

    /* If expansion changed the line, print it */
    if (strcmp(result, line) != 0)
        printf("%s\n", result);

    return result;
}

/* ---------- history_clear ---------- */

void history_clear(void)
{
    for (int i = 0; i < history_size; i++) {
        int idx = (history_start + i) % HISTORY_MAX;
        free(history_entries[idx]);
        history_entries[idx] = NULL;
    }
    history_count = 0;
    history_size = 0;
    history_start = 0;
}
