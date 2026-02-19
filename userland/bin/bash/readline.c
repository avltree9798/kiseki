/*
 * Kiseki OS - Shell Line Editor
 *
 * Raw-mode terminal line editing with cursor movement, history
 * navigation, tab completion, and kill/yank.
 */

#include "shell.h"
#include <termios.h>

/* ---------- Forward declarations (history.c) ---------- */

void        history_add(const char *line);
const char *history_get_offset(int offset);
int         history_get_count(void);
int         history_get_size(void);
const char *history_search(const char *prefix);

/* ---------- Forward declarations (execute.c / builtins.c) ---------- */

int  is_builtin(const char *name);
char *find_in_path(const char *name, const char *path_env);

/* ---------- Line editor state ---------- */

typedef struct {
    char    buf[MAX_LINE];      /* Edit buffer */
    int     len;                /* Current length */
    int     pos;                /* Cursor position */
    int     hist_idx;           /* History navigation index (-1 = current) */
    char    saved_line[MAX_LINE]; /* Saved current line when browsing history */
    char    kill_buf[MAX_LINE]; /* Kill ring (for Ctrl-Y) */
    int     kill_len;
} line_state_t;

/* ---------- Terminal raw mode ---------- */

static struct termios orig_termios;
static int raw_mode = 0;

static int enable_raw_mode(int fd)
{
    if (!isatty(fd)) return -1;
    if (tcgetattr(fd, &orig_termios) < 0) return -1;

    struct termios raw = orig_termios;

    /* Input modes: no break, no CR to NL, no parity check, no strip, no flow */
    raw.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);

    /* Output modes: disable post processing */
    raw.c_oflag &= ~(OPOST);

    /* Control modes: 8-bit chars */
    raw.c_cflag |= CS8;

    /* Local modes: no echo, no canonical, no extended, no signal */
    raw.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);

    /* Control chars: return with 1 char, no timeout */
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;

    if (tcsetattr(fd, TCSADRAIN, &raw) < 0) return -1;
    raw_mode = 1;
    return 0;
}

static void disable_raw_mode(int fd)
{
    if (raw_mode) {
        tcsetattr(fd, TCSADRAIN, &orig_termios);
        raw_mode = 0;
    }
}

/* ---------- Terminal output helpers ---------- */

static void term_write(const char *s, int n)
{
    write(STDOUT_FILENO, s, (size_t)n);
}

static void term_puts(const char *s)
{
    write(STDOUT_FILENO, s, strlen(s));
}

static void term_putchar(char c)
{
    write(STDOUT_FILENO, &c, 1);
}

/* Move cursor to column (0-based from prompt end) */
static void term_move_cursor(int prompt_len, int col)
{
    /* Use carriage return then move right */
    char buf[32];
    int n = snprintf(buf, sizeof(buf), "\r\033[%dC", prompt_len + col);
    term_write(buf, n);
}

/* Clear from cursor to end of line */
static void term_clear_eol(void)
{
    term_puts("\033[K");
}

/* Clear entire screen */
static void term_clear_screen(void)
{
    term_puts("\033[H\033[2J");
}

/* ---------- Prompt expansion ---------- */

static int expand_prompt(shell_state_t *state, const char *prompt,
                         char *buf, size_t bufsz)
{
    size_t out = 0;
    const char *p = prompt;

    while (*p && out < bufsz - 1) {
        if (*p == '\\' && p[1]) {
            p++;
            switch (*p) {
            case 'u': {
                const char *user = shell_get_var(state, "USER");
                if (!user) user = "user";
                size_t ulen = strlen(user);
                if (out + ulen < bufsz) { memcpy(buf + out, user, ulen); out += ulen; }
                break;
            }
            case 'h': case 'H': {
                const char *host = shell_get_var(state, "HOSTNAME");
                if (!host) host = "kiseki";
                if (*p == 'h') {
                    /* Short hostname (up to first dot) */
                    const char *dot = strchr(host, '.');
                    size_t hlen = dot ? (size_t)(dot - host) : strlen(host);
                    if (out + hlen < bufsz) { memcpy(buf + out, host, hlen); out += hlen; }
                } else {
                    size_t hlen = strlen(host);
                    if (out + hlen < bufsz) { memcpy(buf + out, host, hlen); out += hlen; }
                }
                break;
            }
            case 'w': case 'W': {
                const char *pwd = shell_get_var(state, "PWD");
                if (!pwd) pwd = "/";
                const char *home = shell_get_var(state, "HOME");

                char display[PATH_MAX];
                if (home && strncmp(pwd, home, strlen(home)) == 0) {
                    snprintf(display, sizeof(display), "~%s", pwd + strlen(home));
                } else {
                    strncpy(display, pwd, sizeof(display) - 1);
                    display[sizeof(display) - 1] = '\0';
                }

                if (*p == 'W') {
                    /* Basename only */
                    const char *base = strrchr(display, '/');
                    if (base && base[1])
                        base++;
                    else if (!base)
                        base = display;
                    else if (base == display && display[0] == '/' && display[1] == '\0')
                        base = display;
                    size_t blen = strlen(base);
                    if (out + blen < bufsz) { memcpy(buf + out, base, blen); out += blen; }
                } else {
                    size_t dlen = strlen(display);
                    if (out + dlen < bufsz) { memcpy(buf + out, display, dlen); out += dlen; }
                }
                break;
            }
            case '$':
                buf[out++] = (getuid() == 0) ? '#' : '$';
                break;
            case 'n':
                buf[out++] = '\n';
                break;
            case 'r':
                buf[out++] = '\r';
                break;
            case 't': {
                /* Time HH:MM:SS - simplified */
                const char *t = "00:00:00";
                size_t tlen = strlen(t);
                if (out + tlen < bufsz) { memcpy(buf + out, t, tlen); out += tlen; }
                break;
            }
            case 'd': {
                /* Date - simplified */
                const char *d = "Mon Jan 01";
                size_t dlen = strlen(d);
                if (out + dlen < bufsz) { memcpy(buf + out, d, dlen); out += dlen; }
                break;
            }
            case '!': {
                /* History number */
                char num[16];
                int n = snprintf(num, sizeof(num), "%d", history_get_count() + 1);
                if (out + (size_t)n < bufsz) { memcpy(buf + out, num, n); out += n; }
                break;
            }
            case '#': {
                /* Command number */
                char num[16];
                int n = snprintf(num, sizeof(num), "%d", state->line_number);
                if (out + (size_t)n < bufsz) { memcpy(buf + out, num, n); out += n; }
                break;
            }
            case '[':
                /* Begin non-printing chars - skip for length calculation */
                break;
            case ']':
                /* End non-printing chars */
                break;
            case '\\':
                buf[out++] = '\\';
                break;
            case 'a':
                buf[out++] = '\a';
                break;
            case 'e':
                buf[out++] = '\033';
                break;
            default:
                buf[out++] = '\\';
                if (out < bufsz - 1) buf[out++] = *p;
                break;
            }
            p++;
        } else {
            buf[out++] = *p++;
        }
    }
    buf[out] = '\0';
    return (int)out;
}

/* Calculate visible length of prompt (excluding escape sequences) */
static int prompt_visible_len(const char *prompt)
{
    int len = 0;
    int in_escape = 0;

    for (const char *p = prompt; *p; p++) {
        if (*p == '\033') {
            in_escape = 1;
            continue;
        }
        if (in_escape) {
            if ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z'))
                in_escape = 0;
            continue;
        }
        if (*p != '\r' && *p != '\n')
            len++;
    }
    return len;
}

/* ---------- Refresh display ---------- */

static void refresh_line(const char *prompt, int prompt_len, line_state_t *ls)
{
    /* Move to start of line */
    term_puts("\r");

    /* Write prompt */
    term_puts(prompt);

    /* Write buffer */
    term_write(ls->buf, ls->len);

    /* Clear rest of line */
    term_clear_eol();

    /* Move cursor to correct position */
    term_move_cursor(prompt_len, ls->pos);
}

/* ---------- Tab completion ---------- */

static void complete_word(shell_state_t *state, line_state_t *ls,
                          const char *prompt, int prompt_len)
{
    /* Find the start of the current word */
    int word_start = ls->pos;
    while (word_start > 0 && ls->buf[word_start - 1] != ' ' &&
           ls->buf[word_start - 1] != '\t')
        word_start--;

    size_t wlen = (size_t)(ls->pos - word_start);
    if (wlen == 0) return;

    char prefix[PATH_MAX];
    if (wlen >= sizeof(prefix)) return;
    memcpy(prefix, ls->buf + word_start, wlen);
    prefix[wlen] = '\0';

    /* Determine if we're completing a command (first word) or filename */
    int is_first_word = 1;
    for (int i = 0; i < word_start; i++) {
        if (ls->buf[i] != ' ' && ls->buf[i] != '\t') {
            is_first_word = 0;
            break;
        }
    }

    /* Check for variable completion */
    if (prefix[0] == '$') {
        const char *var_prefix = prefix + 1;
        size_t vplen = strlen(var_prefix);
        char *match = NULL;
        int nmatches = 0;

        for (int i = 0; i < state->nvars; i++) {
            if (!state->vars[i].name) continue;
            if (strncmp(state->vars[i].name, var_prefix, vplen) == 0) {
                nmatches++;
                if (!match)
                    match = state->vars[i].name;
            }
        }

        if (nmatches == 1) {
            /* Complete the variable */
            const char *suffix = match + vplen;
            size_t slen = strlen(suffix);

            /* Make room */
            if (ls->len + (int)slen >= MAX_LINE - 1) return;
            memmove(ls->buf + ls->pos + slen, ls->buf + ls->pos,
                    (size_t)(ls->len - ls->pos));
            memcpy(ls->buf + ls->pos, suffix, slen);
            ls->pos += (int)slen;
            ls->len += (int)slen;
            ls->buf[ls->len] = '\0';
            refresh_line(prompt, prompt_len, ls);
        }
        return;
    }

    /* Collect matches */
    char *matches[256];
    int nmatches = 0;

    /* If completing commands (first word), search builtins and PATH */
    if (is_first_word) {
        /* Search builtins */
        /* Check common builtin names */
        static const char *builtins[] = {
            ":", ".", "[", "alias", "bg", "break", "cd", "continue",
            "declare", "echo", "enable", "eval", "exec", "exit", "export",
            "false", "fg", "getopts", "hash", "jobs", "kill", "let",
            "local", "printf", "pwd", "read", "readonly", "return", "set",
            "shift", "source", "test", "trap", "true", "type", "umask",
            "unalias", "unset", "wait", NULL
        };

        for (int i = 0; builtins[i] && nmatches < 255; i++) {
            if (strncmp(builtins[i], prefix, wlen) == 0)
                matches[nmatches++] = strdup(builtins[i]);
        }

        /* Search PATH for executables */
        const char *path_env = shell_get_var(state, "PATH");
        if (path_env) {
            char *path_copy = strdup(path_env);
            char *saveptr = NULL;
            char *dir = strtok_r(path_copy, ":", &saveptr);

            while (dir && nmatches < 255) {
                DIR *d = opendir(dir);
                if (d) {
                    struct dirent *ent;
                    while ((ent = readdir(d)) && nmatches < 255) {
                        if (strncmp(ent->d_name, prefix, wlen) == 0) {
                            /* Check it's not a duplicate */
                            int dup = 0;
                            for (int j = 0; j < nmatches; j++) {
                                if (strcmp(matches[j], ent->d_name) == 0) {
                                    dup = 1;
                                    break;
                                }
                            }
                            if (!dup)
                                matches[nmatches++] = strdup(ent->d_name);
                        }
                    }
                    closedir(d);
                }
                dir = strtok_r(NULL, ":", &saveptr);
            }
            free(path_copy);
        }
    }

    /* Always try filename completion */
    if (nmatches == 0 || !is_first_word) {
        /* Determine directory and file prefix */
        char dirpath[PATH_MAX];
        const char *file_prefix = prefix;
        const char *last_slash = strrchr(prefix, '/');

        if (last_slash) {
            size_t dlen = (size_t)(last_slash - prefix) + 1;
            if (dlen >= sizeof(dirpath)) dlen = sizeof(dirpath) - 1;
            memcpy(dirpath, prefix, dlen);
            dirpath[dlen] = '\0';
            file_prefix = last_slash + 1;
        } else {
            strcpy(dirpath, ".");
        }

        size_t fplen = strlen(file_prefix);
        DIR *d = opendir(dirpath);
        if (d) {
            struct dirent *ent;
            while ((ent = readdir(d)) && nmatches < 255) {
                if (ent->d_name[0] == '.' && file_prefix[0] != '.')
                    continue;
                if (strncmp(ent->d_name, file_prefix, fplen) == 0) {
                    char fullmatch[PATH_MAX];
                    if (last_slash) {
                        size_t dlen = (size_t)(last_slash - prefix) + 1;
                        memcpy(fullmatch, prefix, dlen);
                        strcpy(fullmatch + dlen, ent->d_name);
                    } else {
                        strcpy(fullmatch, ent->d_name);
                    }

                    /* Add trailing / for directories */
                    char fullpath[PATH_MAX];
                    snprintf(fullpath, sizeof(fullpath), "%s/%s",
                             dirpath, ent->d_name);
                    struct stat st;
                    if (stat(fullpath, &st) == 0 && S_ISDIR(st.st_mode)) {
                        strcat(fullmatch, "/");
                    }

                    matches[nmatches++] = strdup(fullmatch);
                }
            }
            closedir(d);
        }
    }

    if (nmatches == 0) {
        /* Beep */
        term_putchar('\a');
        return;
    }

    if (nmatches == 1) {
        /* Single match: complete it */
        const char *completion = matches[0];
        size_t comp_len = strlen(completion);
        size_t to_add = comp_len - wlen;

        if (ls->len + (int)to_add >= MAX_LINE - 1) {
            for (int i = 0; i < nmatches; i++) free(matches[i]);
            return;
        }

        /* Insert the completion */
        memmove(ls->buf + ls->pos + to_add, ls->buf + ls->pos,
                (size_t)(ls->len - ls->pos));
        memcpy(ls->buf + ls->pos, completion + wlen, to_add);
        ls->pos += (int)to_add;
        ls->len += (int)to_add;
        ls->buf[ls->len] = '\0';

        /* Add space if not ending with / */
        if (completion[comp_len - 1] != '/' && ls->len < MAX_LINE - 1) {
            memmove(ls->buf + ls->pos + 1, ls->buf + ls->pos,
                    (size_t)(ls->len - ls->pos));
            ls->buf[ls->pos] = ' ';
            ls->pos++;
            ls->len++;
            ls->buf[ls->len] = '\0';
        }

        refresh_line(prompt, prompt_len, ls);
    } else {
        /* Multiple matches: find common prefix */
        size_t common = strlen(matches[0]);
        for (int i = 1; i < nmatches; i++) {
            size_t j;
            for (j = 0; j < common && matches[0][j] == matches[i][j]; j++)
                ;
            common = j;
        }

        if (common > wlen) {
            /* Complete to common prefix */
            size_t to_add = common - wlen;
            if (ls->len + (int)to_add < MAX_LINE - 1) {
                memmove(ls->buf + ls->pos + to_add, ls->buf + ls->pos,
                        (size_t)(ls->len - ls->pos));
                memcpy(ls->buf + ls->pos, matches[0] + wlen, to_add);
                ls->pos += (int)to_add;
                ls->len += (int)to_add;
                ls->buf[ls->len] = '\0';
                refresh_line(prompt, prompt_len, ls);
            }
        } else {
            /* Show all matches */
            term_puts("\r\n");
            for (int i = 0; i < nmatches; i++) {
                term_puts(matches[i]);
                term_puts("  ");
            }
            term_puts("\r\n");
            refresh_line(prompt, prompt_len, ls);
        }
    }

    for (int i = 0; i < nmatches; i++)
        free(matches[i]);
}

/* ---------- Read a single character (handle escape sequences) ---------- */

/* Returns: positive char, or negative for special keys */
#define KEY_UP      -1
#define KEY_DOWN    -2
#define KEY_RIGHT   -3
#define KEY_LEFT    -4
#define KEY_HOME    -5
#define KEY_END     -6
#define KEY_DELETE  -7

static int read_key(int fd)
{
    char c;
    ssize_t n = read(fd, &c, 1);
    if (n <= 0) return -100; /* EOF/error */

    if (c != '\033') return (unsigned char)c;

    /* Escape sequence */
    char seq[4];
    n = read(fd, &seq[0], 1);
    if (n <= 0) return '\033';

    if (seq[0] == '[') {
        n = read(fd, &seq[1], 1);
        if (n <= 0) return '\033';

        if (seq[1] >= '0' && seq[1] <= '9') {
            n = read(fd, &seq[2], 1);
            if (n <= 0) return '\033';
            if (seq[2] == '~') {
                switch (seq[1]) {
                case '1': return KEY_HOME;
                case '3': return KEY_DELETE;
                case '4': return KEY_END;
                case '7': return KEY_HOME;
                case '8': return KEY_END;
                }
            }
        } else {
            switch (seq[1]) {
            case 'A': return KEY_UP;
            case 'B': return KEY_DOWN;
            case 'C': return KEY_RIGHT;
            case 'D': return KEY_LEFT;
            case 'H': return KEY_HOME;
            case 'F': return KEY_END;
            }
        }
    } else if (seq[0] == 'O') {
        n = read(fd, &seq[1], 1);
        if (n <= 0) return '\033';
        switch (seq[1]) {
        case 'H': return KEY_HOME;
        case 'F': return KEY_END;
        }
    }

    return '\033';
}

/* ---------- Main line reading function ---------- */

char *read_line(shell_state_t *state, const char *raw_prompt)
{
    if (!isatty(STDIN_FILENO)) {
        /* Non-interactive: just read a line */
        static char buf[MAX_LINE];
        if (fgets(buf, sizeof(buf), stdin) == NULL)
            return NULL;
        size_t len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n')
            buf[len - 1] = '\0';
        return buf;
    }

    /* Expand the prompt string */
    char prompt[512];
    expand_prompt(state, raw_prompt, prompt, sizeof(prompt));
    int prompt_len = prompt_visible_len(prompt);

    /* Enter raw mode */
    if (enable_raw_mode(STDIN_FILENO) < 0) {
        /* Fallback to cooked mode */
        term_puts(prompt);
        static char buf[MAX_LINE];
        if (fgets(buf, sizeof(buf), stdin) == NULL)
            return NULL;
        size_t len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n')
            buf[len - 1] = '\0';
        return buf;
    }

    line_state_t ls;
    memset(&ls, 0, sizeof(ls));
    ls.hist_idx = -1;
    ls.saved_line[0] = '\0';

    /* Display prompt */
    term_puts(prompt);

    /* Static result buffer */
    static char result[MAX_LINE];

    for (;;) {
        int key = read_key(STDIN_FILENO);

        if (key == -100) {
            /* EOF */
            disable_raw_mode(STDIN_FILENO);
            return NULL;
        }

        switch (key) {
        case '\r':
        case '\n':
            /* Accept line */
            disable_raw_mode(STDIN_FILENO);
            term_puts("\r\n");
            ls.buf[ls.len] = '\0';
            memcpy(result, ls.buf, ls.len + 1);
            return result;

        case 4: /* Ctrl-D */
            if (ls.len == 0) {
                /* EOF on empty line */
                disable_raw_mode(STDIN_FILENO);
                return NULL;
            }
            /* Delete char under cursor */
            if (ls.pos < ls.len) {
                memmove(ls.buf + ls.pos, ls.buf + ls.pos + 1,
                        (size_t)(ls.len - ls.pos - 1));
                ls.len--;
                ls.buf[ls.len] = '\0';
                refresh_line(prompt, prompt_len, &ls);
            }
            break;

        case 3: /* Ctrl-C */
            /* Discard current line */
            disable_raw_mode(STDIN_FILENO);
            term_puts("^C\r\n");
            result[0] = '\0';
            return result;

        case 12: /* Ctrl-L: clear screen */
            term_clear_screen();
            refresh_line(prompt, prompt_len, &ls);
            break;

        case 127: /* Backspace */
        case 8:   /* Ctrl-H */
            if (ls.pos > 0) {
                memmove(ls.buf + ls.pos - 1, ls.buf + ls.pos,
                        (size_t)(ls.len - ls.pos));
                ls.pos--;
                ls.len--;
                ls.buf[ls.len] = '\0';
                refresh_line(prompt, prompt_len, &ls);
            }
            break;

        case '\t': /* Tab completion */
            complete_word(state, &ls, prompt, prompt_len);
            break;

        case 1: /* Ctrl-A: Home */
            ls.pos = 0;
            refresh_line(prompt, prompt_len, &ls);
            break;

        case 5: /* Ctrl-E: End */
            ls.pos = ls.len;
            refresh_line(prompt, prompt_len, &ls);
            break;

        case 11: /* Ctrl-K: Kill to end of line */
            if (ls.pos < ls.len) {
                int kill_len = ls.len - ls.pos;
                memcpy(ls.kill_buf, ls.buf + ls.pos, kill_len);
                ls.kill_buf[kill_len] = '\0';
                ls.kill_len = kill_len;
                ls.len = ls.pos;
                ls.buf[ls.len] = '\0';
                refresh_line(prompt, prompt_len, &ls);
            }
            break;

        case 21: /* Ctrl-U: Kill to beginning of line */
            if (ls.pos > 0) {
                memcpy(ls.kill_buf, ls.buf, ls.pos);
                ls.kill_buf[ls.pos] = '\0';
                ls.kill_len = ls.pos;
                memmove(ls.buf, ls.buf + ls.pos, (size_t)(ls.len - ls.pos));
                ls.len -= ls.pos;
                ls.pos = 0;
                ls.buf[ls.len] = '\0';
                refresh_line(prompt, prompt_len, &ls);
            }
            break;

        case 23: /* Ctrl-W: Kill word backward */
            if (ls.pos > 0) {
                int old_pos = ls.pos;
                /* Skip spaces */
                while (ls.pos > 0 && ls.buf[ls.pos - 1] == ' ')
                    ls.pos--;
                /* Skip word */
                while (ls.pos > 0 && ls.buf[ls.pos - 1] != ' ')
                    ls.pos--;

                int kill_len = old_pos - ls.pos;
                memcpy(ls.kill_buf, ls.buf + ls.pos, kill_len);
                ls.kill_buf[kill_len] = '\0';
                ls.kill_len = kill_len;

                memmove(ls.buf + ls.pos, ls.buf + old_pos,
                        (size_t)(ls.len - old_pos));
                ls.len -= kill_len;
                ls.buf[ls.len] = '\0';
                refresh_line(prompt, prompt_len, &ls);
            }
            break;

        case 25: /* Ctrl-Y: Yank (paste from kill buffer) */
            if (ls.kill_len > 0 && ls.len + ls.kill_len < MAX_LINE - 1) {
                memmove(ls.buf + ls.pos + ls.kill_len, ls.buf + ls.pos,
                        (size_t)(ls.len - ls.pos));
                memcpy(ls.buf + ls.pos, ls.kill_buf, ls.kill_len);
                ls.pos += ls.kill_len;
                ls.len += ls.kill_len;
                ls.buf[ls.len] = '\0';
                refresh_line(prompt, prompt_len, &ls);
            }
            break;

        case 20: /* Ctrl-T: Transpose chars */
            if (ls.pos > 0 && ls.pos < ls.len) {
                char tmp = ls.buf[ls.pos - 1];
                ls.buf[ls.pos - 1] = ls.buf[ls.pos];
                ls.buf[ls.pos] = tmp;
                if (ls.pos < ls.len) ls.pos++;
                refresh_line(prompt, prompt_len, &ls);
            }
            break;

        case 2: /* Ctrl-B: Left */
            if (ls.pos > 0) {
                ls.pos--;
                refresh_line(prompt, prompt_len, &ls);
            }
            break;

        case 6: /* Ctrl-F: Right */
            if (ls.pos < ls.len) {
                ls.pos++;
                refresh_line(prompt, prompt_len, &ls);
            }
            break;

        case 14: /* Ctrl-N: Down (next history) */
            goto handle_down;

        case 16: /* Ctrl-P: Up (previous history) */
            goto handle_up;

        case KEY_UP:
handle_up:
            {
                /* Save current line if at bottom */
                if (ls.hist_idx < 0)
                    memcpy(ls.saved_line, ls.buf, ls.len + 1);

                int new_idx = ls.hist_idx + 1;
                const char *entry = history_get_offset(new_idx);
                if (entry) {
                    ls.hist_idx = new_idx;
                    strncpy(ls.buf, entry, MAX_LINE - 1);
                    ls.buf[MAX_LINE - 1] = '\0';
                    ls.len = (int)strlen(ls.buf);
                    ls.pos = ls.len;
                    refresh_line(prompt, prompt_len, &ls);
                }
            }
            break;

        case KEY_DOWN:
handle_down:
            {
                if (ls.hist_idx > 0) {
                    ls.hist_idx--;
                    const char *entry = history_get_offset(ls.hist_idx);
                    if (entry) {
                        strncpy(ls.buf, entry, MAX_LINE - 1);
                        ls.buf[MAX_LINE - 1] = '\0';
                        ls.len = (int)strlen(ls.buf);
                        ls.pos = ls.len;
                    }
                } else if (ls.hist_idx == 0) {
                    ls.hist_idx = -1;
                    memcpy(ls.buf, ls.saved_line, MAX_LINE);
                    ls.len = (int)strlen(ls.buf);
                    ls.pos = ls.len;
                }
                refresh_line(prompt, prompt_len, &ls);
            }
            break;

        case KEY_LEFT:
            if (ls.pos > 0) {
                ls.pos--;
                refresh_line(prompt, prompt_len, &ls);
            }
            break;

        case KEY_RIGHT:
            if (ls.pos < ls.len) {
                ls.pos++;
                refresh_line(prompt, prompt_len, &ls);
            }
            break;

        case KEY_HOME:
            ls.pos = 0;
            refresh_line(prompt, prompt_len, &ls);
            break;

        case KEY_END:
            ls.pos = ls.len;
            refresh_line(prompt, prompt_len, &ls);
            break;

        case KEY_DELETE:
            if (ls.pos < ls.len) {
                memmove(ls.buf + ls.pos, ls.buf + ls.pos + 1,
                        (size_t)(ls.len - ls.pos - 1));
                ls.len--;
                ls.buf[ls.len] = '\0';
                refresh_line(prompt, prompt_len, &ls);
            }
            break;

        default:
            /* Regular character */
            if (key >= 32 && key < 127 && ls.len < MAX_LINE - 1) {
                /* Insert at cursor */
                if (ls.pos < ls.len) {
                    memmove(ls.buf + ls.pos + 1, ls.buf + ls.pos,
                            (size_t)(ls.len - ls.pos));
                }
                ls.buf[ls.pos] = (char)key;
                ls.pos++;
                ls.len++;
                ls.buf[ls.len] = '\0';
                refresh_line(prompt, prompt_len, &ls);
            }
            break;
        }
    }
}
