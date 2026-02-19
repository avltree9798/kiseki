/*
 * Kiseki OS - Shell Lexer Implementation
 *
 * Tokenizes bash input into a stream of tokens.
 * Handles: single/double quoting, backslash escaping, $() command substitution,
 * ${} parameter expansion, backtick substitution, here-documents, comments,
 * tilde expansion markers, and all bash operators.
 */

#include "lexer.h"

/* ---------- Helpers ---------- */

static int is_blank(char c)
{
    return c == ' ' || c == '\t';
}

static int is_operator_start(char c)
{
    return c == '|' || c == '&' || c == ';' || c == '<' || c == '>' ||
           c == '(' || c == ')' || c == '{' || c == '}' || c == '!';
}

static int is_metachar(char c)
{
    return is_blank(c) || c == '\n' || is_operator_start(c);
}

static int is_name_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}

static int is_digit(char c)
{
    return c >= '0' && c <= '9';
}

/* ---------- Dynamic string buffer ---------- */

typedef struct {
    char   *data;
    size_t  len;
    size_t  cap;
} strbuf_t;

static void strbuf_init(strbuf_t *sb)
{
    sb->cap = 64;
    sb->data = malloc(sb->cap);
    sb->len = 0;
    if (sb->data)
        sb->data[0] = '\0';
}

static void strbuf_push(strbuf_t *sb, char c)
{
    if (sb->len + 1 >= sb->cap) {
        sb->cap *= 2;
        sb->data = realloc(sb->data, sb->cap);
    }
    sb->data[sb->len++] = c;
    sb->data[sb->len] = '\0';
}

static void strbuf_append(strbuf_t *sb, const char *s, size_t n)
{
    while (n--) {
        strbuf_push(sb, *s++);
    }
}

static char *strbuf_detach(strbuf_t *sb)
{
    char *result = sb->data;
    sb->data = NULL;
    sb->len = 0;
    sb->cap = 0;
    return result;
}

static void strbuf_free(strbuf_t *sb)
{
    free(sb->data);
    sb->data = NULL;
    sb->len = 0;
    sb->cap = 0;
}

/* ---------- Lexer character access ---------- */

static char lex_peek_char(lexer_t *lex)
{
    if (lex->pos >= lex->len)
        return '\0';
    return lex->input[lex->pos];
}

static char lex_peek_ahead(lexer_t *lex, size_t offset)
{
    if (lex->pos + offset >= lex->len)
        return '\0';
    return lex->input[lex->pos + offset];
}

static char lex_advance(lexer_t *lex)
{
    if (lex->pos >= lex->len)
        return '\0';
    char c = lex->input[lex->pos++];
    if (c == '\n')
        lex->line++;
    return c;
}

/* ---------- Token allocation ---------- */

static token_t *token_new(token_type_t type, const char *value, int line)
{
    token_t *tok = malloc(sizeof(token_t));
    if (!tok)
        return NULL;
    tok->type = type;
    tok->value = value ? strdup(value) : NULL;
    tok->line = line;
    tok->quoted = 0;
    return tok;
}

/* ---------- Reserved word lookup ---------- */

typedef struct {
    const char     *word;
    token_type_t    type;
} reserved_word_t;

static const reserved_word_t reserved_words[] = {
    { "if",       TOK_IF       },
    { "then",     TOK_THEN     },
    { "else",     TOK_ELSE     },
    { "elif",     TOK_ELIF     },
    { "fi",       TOK_FI       },
    { "do",       TOK_DO       },
    { "done",     TOK_DONE     },
    { "case",     TOK_CASE     },
    { "esac",     TOK_ESAC     },
    { "while",    TOK_WHILE    },
    { "until",    TOK_UNTIL    },
    { "for",      TOK_FOR      },
    { "in",       TOK_IN       },
    { "function", TOK_FUNCTION },
    { "select",   TOK_SELECT   },
    { "time",     TOK_TIME     },
    { "{",        TOK_LBRACE   },
    { "}",        TOK_RBRACE   },
    { "!",        TOK_BANG     },
    { NULL,       TOK_EOF      }
};

static token_type_t lookup_reserved(const char *word)
{
    for (int i = 0; reserved_words[i].word != NULL; i++) {
        if (strcmp(word, reserved_words[i].word) == 0)
            return reserved_words[i].type;
    }
    return TOK_WORD;
}

/* ---------- Skip blanks and comments ---------- */

static void skip_blanks(lexer_t *lex)
{
    while (lex->pos < lex->len && is_blank(lex->input[lex->pos]))
        lex->pos++;
}

static void skip_comment(lexer_t *lex)
{
    if (lex->pos < lex->len && lex->input[lex->pos] == '#') {
        while (lex->pos < lex->len && lex->input[lex->pos] != '\n')
            lex->pos++;
    }
}

/* ---------- Read here-document bodies ---------- */

/*
 * After encountering a newline, if there are pending here-documents,
 * we read their bodies from the input.
 */
static void read_heredoc_bodies(lexer_t *lex)
{
    for (int i = 0; i < lex->nheredocs; i++) {
        heredoc_pending_t *hd = &lex->heredocs[i];
        strbuf_t body;
        strbuf_init(&body);

        size_t delim_len = strlen(hd->delimiter);

        while (lex->pos < lex->len) {
            /* Find start of current line */
            size_t line_start = lex->pos;
            const char *line_ptr = &lex->input[lex->pos];

            /* For <<-, skip leading tabs */
            size_t skip = 0;
            if (hd->strip_tabs) {
                while (line_start + skip < lex->len &&
                       lex->input[line_start + skip] == '\t')
                    skip++;
            }

            /* Check if this line matches the delimiter */
            const char *check = &lex->input[line_start + skip];
            size_t remaining = lex->len - (line_start + skip);

            int match = 0;
            if (remaining >= delim_len) {
                if (memcmp(check, hd->delimiter, delim_len) == 0) {
                    /* Must be followed by newline or end of input */
                    if (line_start + skip + delim_len >= lex->len ||
                        lex->input[line_start + skip + delim_len] == '\n') {
                        match = 1;
                    }
                }
            }

            if (match) {
                /* Consume the delimiter line */
                lex->pos = line_start + skip + delim_len;
                if (lex->pos < lex->len && lex->input[lex->pos] == '\n') {
                    lex->pos++;
                    lex->line++;
                }
                break;
            }

            /* Not the delimiter - append this line to body */
            while (lex->pos < lex->len && lex->input[lex->pos] != '\n') {
                strbuf_push(&body, lex->input[lex->pos]);
                lex->pos++;
            }
            if (lex->pos < lex->len && lex->input[lex->pos] == '\n') {
                strbuf_push(&body, '\n');
                lex->pos++;
                lex->line++;
            }
        }

        /* Attach body text to the target token */
        if (hd->target_token) {
            free(hd->target_token->value);
            hd->target_token->value = strbuf_detach(&body);
            hd->target_token->quoted = hd->quoted;
        } else {
            strbuf_free(&body);
        }

        free(hd->delimiter);
    }
    lex->nheredocs = 0;
    lex->heredoc_needs_body = 0;
}

/* ---------- Scan a word token ---------- */

/*
 * Scan balanced content: tracks nested parens, braces, $() etc.
 * Used for scanning $(command) and ${parameter} content.
 */
static void scan_dollar_paren(lexer_t *lex, strbuf_t *sb)
{
    /* We are positioned after "$(" - scan until matching ")" */
    strbuf_append(sb, "$(", 2);
    int depth = 1;
    while (lex->pos < lex->len && depth > 0) {
        char c = lex->input[lex->pos];
        if (c == '(')
            depth++;
        else if (c == ')')
            depth--;
        if (depth > 0 || c == ')') {
            strbuf_push(sb, c);
            if (c == '\n')
                lex->line++;
            lex->pos++;
        }
    }
}

static void scan_dollar_brace(lexer_t *lex, strbuf_t *sb)
{
    /* We are positioned after "${" - scan until matching "}" */
    strbuf_append(sb, "${", 2);
    int depth = 1;
    while (lex->pos < lex->len && depth > 0) {
        char c = lex->input[lex->pos];
        if (c == '{')
            depth++;
        else if (c == '}')
            depth--;
        if (depth > 0 || c == '}') {
            strbuf_push(sb, c);
            if (c == '\n')
                lex->line++;
            lex->pos++;
        }
    }
}

static void scan_arith(lexer_t *lex, strbuf_t *sb)
{
    /* We are positioned after "$((" - scan until matching "))" */
    strbuf_append(sb, "$((", 3);
    int depth = 1;
    while (lex->pos < lex->len && depth > 0) {
        char c = lex->input[lex->pos];
        if (c == '(' && lex_peek_ahead(lex, 1) == '(') {
            depth++;
            strbuf_push(sb, c);
            lex->pos++;
            c = lex->input[lex->pos];
            strbuf_push(sb, c);
            lex->pos++;
            continue;
        }
        if (c == ')' && lex->pos + 1 < lex->len &&
            lex->input[lex->pos + 1] == ')') {
            depth--;
            strbuf_push(sb, ')');
            lex->pos++;
            strbuf_push(sb, ')');
            lex->pos++;
            continue;
        }
        strbuf_push(sb, c);
        if (c == '\n')
            lex->line++;
        lex->pos++;
    }
}

static void scan_backtick(lexer_t *lex, strbuf_t *sb)
{
    /* We are positioned after the opening backtick */
    strbuf_push(sb, '`');
    while (lex->pos < lex->len) {
        char c = lex->input[lex->pos];
        if (c == '`') {
            strbuf_push(sb, '`');
            lex->pos++;
            return;
        }
        if (c == '\\') {
            strbuf_push(sb, c);
            lex->pos++;
            if (lex->pos < lex->len) {
                strbuf_push(sb, lex->input[lex->pos]);
                lex->pos++;
            }
            continue;
        }
        strbuf_push(sb, c);
        if (c == '\n')
            lex->line++;
        lex->pos++;
    }
}

/*
 * scan_word - scan a word token (handles all quoting and expansion syntax).
 * Returns a token with the raw text preserved (expansion happens later).
 */
static token_t *scan_word(lexer_t *lex)
{
    strbuf_t sb;
    strbuf_init(&sb);
    int start_line = lex->line;
    int any_quoted = 0;
    int is_assignment = 0;
    int saw_equals = 0;

    while (lex->pos < lex->len) {
        char c = lex->input[lex->pos];

        /* Unquoted metacharacters end the word */
        if (is_metachar(c) || c == '\n')
            break;

        /* Handle comments: # at start of word (only if word is empty) */
        if (c == '#' && sb.len == 0) {
            break;
        }

        /* Backslash escaping (outside quotes) */
        if (c == '\\') {
            strbuf_push(&sb, c);
            lex->pos++;
            if (lex->pos < lex->len) {
                c = lex->input[lex->pos];
                strbuf_push(&sb, c);
                if (c == '\n')
                    lex->line++;
                lex->pos++;
            }
            continue;
        }

        /* Single quoting */
        if (c == '\'') {
            /*
             * Quoting in the NAME part of an assignment (before '=')
             * prevents assignment recognition. Quoting in the VALUE
             * part (after '=') is fine — TEST='foo' is still an assignment.
             */
            if (!saw_equals)
                any_quoted = 1;
            strbuf_push(&sb, c);
            lex->pos++;
            while (lex->pos < lex->len && lex->input[lex->pos] != '\'') {
                strbuf_push(&sb, lex->input[lex->pos]);
                if (lex->input[lex->pos] == '\n')
                    lex->line++;
                lex->pos++;
            }
            if (lex->pos < lex->len) {
                strbuf_push(&sb, '\'');
                lex->pos++;
            }
            continue;
        }

        /* Double quoting */
        if (c == '"') {
            if (!saw_equals)
                any_quoted = 1;
            strbuf_push(&sb, c);
            lex->pos++;
            while (lex->pos < lex->len && lex->input[lex->pos] != '"') {
                char dc = lex->input[lex->pos];

                /* Backslash inside double quotes: only special for $`"\ \n */
                if (dc == '\\' && lex->pos + 1 < lex->len) {
                    char next = lex->input[lex->pos + 1];
                    if (next == '$' || next == '`' || next == '"' ||
                        next == '\\' || next == '\n') {
                        strbuf_push(&sb, dc);
                        lex->pos++;
                        strbuf_push(&sb, lex->input[lex->pos]);
                        if (lex->input[lex->pos] == '\n')
                            lex->line++;
                        lex->pos++;
                        continue;
                    }
                }

                /* $(...) inside double quotes */
                if (dc == '$' && lex->pos + 1 < lex->len) {
                    char next = lex->input[lex->pos + 1];
                    if (next == '(' && lex->pos + 2 < lex->len &&
                        lex->input[lex->pos + 2] == '(') {
                        /* $(( arithmetic )) */
                        lex->pos += 3;
                        scan_arith(lex, &sb);
                        continue;
                    }
                    if (next == '(') {
                        lex->pos += 2;
                        scan_dollar_paren(lex, &sb);
                        continue;
                    }
                    if (next == '{') {
                        lex->pos += 2;
                        scan_dollar_brace(lex, &sb);
                        continue;
                    }
                }

                /* Backtick inside double quotes */
                if (dc == '`') {
                    lex->pos++;
                    scan_backtick(lex, &sb);
                    continue;
                }

                strbuf_push(&sb, dc);
                if (dc == '\n')
                    lex->line++;
                lex->pos++;
            }
            if (lex->pos < lex->len) {
                strbuf_push(&sb, '"');
                lex->pos++;
            }
            continue;
        }

        /* Dollar expansions (outside quotes) */
        if (c == '$' && lex->pos + 1 < lex->len) {
            char next = lex->input[lex->pos + 1];
            if (next == '(' && lex->pos + 2 < lex->len &&
                lex->input[lex->pos + 2] == '(') {
                lex->pos += 3;
                scan_arith(lex, &sb);
                continue;
            }
            if (next == '(') {
                lex->pos += 2;
                scan_dollar_paren(lex, &sb);
                continue;
            }
            if (next == '{') {
                lex->pos += 2;
                scan_dollar_brace(lex, &sb);
                continue;
            }
        }

        /* Backtick outside quotes */
        if (c == '`') {
            lex->pos++;
            scan_backtick(lex, &sb);
            continue;
        }

        /* Track whether this looks like an assignment (name=value) */
        if (c == '=' && !saw_equals && sb.len > 0) {
            /* Check if everything before = is a valid variable name */
            int valid = 1;
            for (size_t i = 0; i < sb.len; i++) {
                char ch = sb.data[i];
                if (i == 0 && is_digit(ch)) { valid = 0; break; }
                if (!is_name_char(ch)) { valid = 0; break; }
            }
            if (valid) {
                is_assignment = 1;
            }
            saw_equals = 1;
        }

        /* Regular character */
        strbuf_push(&sb, c);
        lex->pos++;
    }

    if (sb.len == 0) {
        strbuf_free(&sb);
        return NULL;
    }

    char *word = strbuf_detach(&sb);
    token_type_t type;

    if (is_assignment && !any_quoted) {
        type = TOK_ASSIGNMENT_WORD;
    } else if (!any_quoted) {
        type = lookup_reserved(word);
    } else {
        type = TOK_WORD;
    }

    token_t *tok = token_new(type, word, start_line);
    tok->quoted = any_quoted;
    free(word);
    return tok;
}

/* ---------- Scan operator token ---------- */

static token_t *scan_operator(lexer_t *lex)
{
    int start_line = lex->line;
    char c = lex->input[lex->pos];

    switch (c) {
    case '(':
        lex->pos++;
        return token_new(TOK_LPAREN, "(", start_line);

    case ')':
        lex->pos++;
        return token_new(TOK_RPAREN, ")", start_line);

    case '|':
        lex->pos++;
        if (lex->pos < lex->len && lex->input[lex->pos] == '|') {
            lex->pos++;
            return token_new(TOK_OR_IF, "||", start_line);
        }
        return token_new(TOK_PIPE, "|", start_line);

    case '&':
        lex->pos++;
        if (lex->pos < lex->len && lex->input[lex->pos] == '&') {
            lex->pos++;
            return token_new(TOK_AND_IF, "&&", start_line);
        }
        return token_new(TOK_AMP, "&", start_line);

    case ';':
        lex->pos++;
        if (lex->pos < lex->len && lex->input[lex->pos] == ';') {
            lex->pos++;
            return token_new(TOK_DSEMI, ";;", start_line);
        }
        return token_new(TOK_SEMI, ";", start_line);

    case '<':
        lex->pos++;
        if (lex->pos < lex->len) {
            char next = lex->input[lex->pos];
            if (next == '<') {
                lex->pos++;
                if (lex->pos < lex->len && lex->input[lex->pos] == '-') {
                    lex->pos++;
                    return token_new(TOK_DLESSDASH, "<<-", start_line);
                }
                return token_new(TOK_DLESS, "<<", start_line);
            }
            if (next == '&') {
                lex->pos++;
                return token_new(TOK_LESSAND, "<&", start_line);
            }
            if (next == '>') {
                lex->pos++;
                return token_new(TOK_LESSGREAT, "<>", start_line);
            }
        }
        return token_new(TOK_LESS, "<", start_line);

    case '>':
        lex->pos++;
        if (lex->pos < lex->len) {
            char next = lex->input[lex->pos];
            if (next == '>') {
                lex->pos++;
                return token_new(TOK_DGREAT, ">>", start_line);
            }
            if (next == '&') {
                lex->pos++;
                return token_new(TOK_GREATAND, ">&", start_line);
            }
            if (next == '|') {
                lex->pos++;
                return token_new(TOK_CLOBBER, ">|", start_line);
            }
        }
        return token_new(TOK_GREAT, ">", start_line);

    default:
        break;
    }

    /* Should not reach here */
    lex->pos++;
    return token_new(TOK_ERROR, "unexpected character", start_line);
}

/* ---------- Scan IO_NUMBER ---------- */

/*
 * Check if we have an IO_NUMBER: one or more digits followed immediately
 * by < or >. Must be called before scan_word.
 */
static token_t *try_scan_io_number(lexer_t *lex)
{
    /* Save position for backtracking */
    size_t saved_pos = lex->pos;
    int start_line = lex->line;

    /* Scan digits */
    size_t num_start = lex->pos;
    while (lex->pos < lex->len && is_digit(lex->input[lex->pos]))
        lex->pos++;

    if (lex->pos == num_start) {
        lex->pos = saved_pos;
        return NULL;
    }

    /* Must be followed by < or > */
    if (lex->pos < lex->len &&
        (lex->input[lex->pos] == '<' || lex->input[lex->pos] == '>')) {
        size_t num_len = lex->pos - num_start;
        char *num_str = malloc(num_len + 1);
        memcpy(num_str, &lex->input[num_start], num_len);
        num_str[num_len] = '\0';
        token_t *tok = token_new(TOK_IO_NUMBER, num_str, start_line);
        free(num_str);
        return tok;
    }

    /* Not an IO_NUMBER - backtrack */
    lex->pos = saved_pos;
    return NULL;
}

/* ---------- Handle heredoc delimiter after << or <<- ---------- */

static void register_heredoc(lexer_t *lex, token_t *redir_tok)
{
    /* Skip blanks after << / <<- */
    skip_blanks(lex);

    if (lex->nheredocs >= MAX_HEREDOCS)
        return;

    /* Read the delimiter word */
    strbuf_t sb;
    strbuf_init(&sb);
    int quoted = 0;

    while (lex->pos < lex->len) {
        char c = lex->input[lex->pos];
        if (is_blank(c) || c == '\n' || c == ';' || c == '&' ||
            c == '|' || c == ')' || c == '#')
            break;

        if (c == '\\') {
            quoted = 1;
            lex->pos++;
            if (lex->pos < lex->len) {
                strbuf_push(&sb, lex->input[lex->pos]);
                lex->pos++;
            }
            continue;
        }

        if (c == '\'' || c == '"') {
            quoted = 1;
            char quote = c;
            lex->pos++;
            while (lex->pos < lex->len && lex->input[lex->pos] != quote) {
                strbuf_push(&sb, lex->input[lex->pos]);
                lex->pos++;
            }
            if (lex->pos < lex->len)
                lex->pos++;  /* skip closing quote */
            continue;
        }

        strbuf_push(&sb, c);
        lex->pos++;
    }

    /* Create a placeholder token for the heredoc body */
    token_t *body_tok = token_new(TOK_WORD, "", redir_tok->line);

    heredoc_pending_t *hd = &lex->heredocs[lex->nheredocs++];
    hd->delimiter = strbuf_detach(&sb);
    hd->strip_tabs = (redir_tok->type == TOK_DLESSDASH);
    hd->quoted = quoted;
    hd->target_token = body_tok;

    /* Store the body token pointer in the redirect token's value for the
     * parser to retrieve. We encode it as a special marker. The parser
     * will use the heredoc_pending to get the actual body. We replace
     * the redir token's value with the delimiter so the parser knows. */
    free(redir_tok->value);
    redir_tok->value = strdup(hd->delimiter);

    /* Stash the body token - caller (the parser) will find it via the
     * lexer's heredoc tracking. For now, we mark that we need to read
     * the body at the next newline. */
    lex->heredoc_needs_body = 1;

    (void)body_tok;  /* Will be accessed via heredocs array */
}

/* ---------- Main token scanning ---------- */

token_t *lexer_next_token(lexer_t *lex)
{
    if (!lex)
        return NULL;

    /* Return peeked token if available */
    if (lex->peeked) {
        token_t *tok = lex->peeked;
        lex->peeked = lex->peeked2;  /* promote peeked2 to peeked */
        lex->peeked2 = NULL;
        return tok;
    }

retry:
    /* Skip blanks */
    skip_blanks(lex);

    /* Skip comments */
    if (lex->pos < lex->len && lex->input[lex->pos] == '#') {
        skip_comment(lex);
        goto retry;
    }

    /* End of input */
    if (lex->pos >= lex->len)
        return token_new(TOK_EOF, NULL, lex->line);

    char c = lex->input[lex->pos];

    /* Newline */
    if (c == '\n') {
        int line = lex->line;
        lex->pos++;
        lex->line++;

        /* If there are pending here-documents, read their bodies now */
        if (lex->heredoc_needs_body) {
            read_heredoc_bodies(lex);
        }

        return token_new(TOK_NEWLINE, "\n", line);
    }

    /* Operators: check for IO_NUMBER first (digit(s) before < or >) */
    if (is_digit(c)) {
        token_t *io_tok = try_scan_io_number(lex);
        if (io_tok)
            return io_tok;
        /* Fall through to word scanning */
    }

    /* Operators */
    if (is_operator_start(c)) {
        /*
         * '{' and '}' are reserved words in bash, not operators.
         * '!' is also a reserved word. However, they are recognized
         * as operators at the character level and then the parser
         * interprets them. We handle '{', '}', '!' in scan_word
         * via reserved word lookup, unless they appear as operator chars.
         *
         * Special case: '{' and '}' as standalone tokens
         */
        if (c == '{' || c == '}') {
            /* Check if it's a standalone brace (word delimiter follows) */
            char next = lex_peek_ahead(lex, 1);
            if (next == '\0' || is_blank(next) || next == '\n' ||
                next == ';' || next == '&' || next == '|' ||
                next == ')' || next == '#') {
                int line = lex->line;
                lex->pos++;
                if (c == '{')
                    return token_new(TOK_LBRACE, "{", line);
                else
                    return token_new(TOK_RBRACE, "}", line);
            }
            /* Otherwise treat as start of a word */
            goto scan_word_label;
        }

        if (c == '!') {
            /* '!' is a reserved word when it's a standalone token */
            char next = lex_peek_ahead(lex, 1);
            if (next == '\0' || is_blank(next) || next == '\n') {
                int line = lex->line;
                lex->pos++;
                return token_new(TOK_BANG, "!", line);
            }
            /* Otherwise part of a word (e.g., $!) */
            goto scan_word_label;
        }

        token_t *op_tok = scan_operator(lex);

        /* If this is a heredoc operator, register the pending heredoc */
        if (op_tok && (op_tok->type == TOK_DLESS ||
                       op_tok->type == TOK_DLESSDASH)) {
            register_heredoc(lex, op_tok);
        }

        return op_tok;
    }

scan_word_label:
    /* Word token */
    {
        token_t *word_tok = scan_word(lex);
        if (word_tok)
            return word_tok;
    }

    /* If scan_word returned NULL and we're not at end, something is wrong */
    if (lex->pos < lex->len) {
        int line = lex->line;
        lex->pos++;
        return token_new(TOK_ERROR, "unexpected character", line);
    }

    return token_new(TOK_EOF, NULL, lex->line);
}

/* ---------- Peek ---------- */

token_t *lexer_peek(lexer_t *lex)
{
    if (!lex)
        return NULL;
    if (!lex->peeked) {
        lex->peeked = lexer_next_token(lex);
    }
    return lex->peeked;
}

/* ---------- Init / Free ---------- */

lexer_t *lexer_init(const char *input)
{
    if (!input)
        return NULL;

    lexer_t *lex = malloc(sizeof(lexer_t));
    if (!lex)
        return NULL;

    lex->input = input;
    lex->pos = 0;
    lex->len = strlen(input);
    lex->line = 1;
    lex->peeked = NULL;
    lex->peeked2 = NULL;
    lex->nheredocs = 0;
    lex->heredoc_needs_body = 0;

    return lex;
}

void token_free(token_t *tok)
{
    if (!tok)
        return;
    free(tok->value);
    free(tok);
}

void lexer_free(lexer_t *lex)
{
    if (!lex)
        return;
    if (lex->peeked)
        token_free(lex->peeked);
    if (lex->peeked2)
        token_free(lex->peeked2);
    /* Free any remaining heredoc delimiters */
    for (int i = 0; i < lex->nheredocs; i++) {
        free(lex->heredocs[i].delimiter);
        if (lex->heredocs[i].target_token)
            token_free(lex->heredocs[i].target_token);
    }
    free(lex);
}

/* ---------- Debug: token type names ---------- */

const char *token_type_name(token_type_t type)
{
    switch (type) {
    case TOK_WORD:            return "WORD";
    case TOK_ASSIGNMENT_WORD: return "ASSIGNMENT_WORD";
    case TOK_IO_NUMBER:       return "IO_NUMBER";
    case TOK_NEWLINE:         return "NEWLINE";
    case TOK_AND_IF:          return "AND_IF";
    case TOK_OR_IF:           return "OR_IF";
    case TOK_DSEMI:           return "DSEMI";
    case TOK_PIPE:            return "PIPE";
    case TOK_AMP:             return "AMP";
    case TOK_SEMI:            return "SEMI";
    case TOK_LESS:            return "LESS";
    case TOK_GREAT:           return "GREAT";
    case TOK_DLESS:           return "DLESS";
    case TOK_DGREAT:          return "DGREAT";
    case TOK_LESSAND:         return "LESSAND";
    case TOK_GREATAND:        return "GREATAND";
    case TOK_DLESSDASH:       return "DLESSDASH";
    case TOK_CLOBBER:         return "CLOBBER";
    case TOK_LESSGREAT:       return "LESSGREAT";
    case TOK_LPAREN:          return "LPAREN";
    case TOK_RPAREN:          return "RPAREN";
    case TOK_LBRACE:          return "LBRACE";
    case TOK_RBRACE:          return "RBRACE";
    case TOK_BANG:             return "BANG";
    case TOK_IF:              return "IF";
    case TOK_THEN:            return "THEN";
    case TOK_ELSE:            return "ELSE";
    case TOK_ELIF:            return "ELIF";
    case TOK_FI:              return "FI";
    case TOK_DO:              return "DO";
    case TOK_DONE:            return "DONE";
    case TOK_CASE:            return "CASE";
    case TOK_ESAC:            return "ESAC";
    case TOK_WHILE:           return "WHILE";
    case TOK_UNTIL:           return "UNTIL";
    case TOK_FOR:             return "FOR";
    case TOK_IN:              return "IN";
    case TOK_FUNCTION:        return "FUNCTION";
    case TOK_SELECT:          return "SELECT";
    case TOK_TIME:            return "TIME";
    case TOK_EOF:             return "EOF";
    case TOK_ERROR:           return "ERROR";
    default:                  return "UNKNOWN";
    }
}
