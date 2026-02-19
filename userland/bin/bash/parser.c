/*
 * Kiseki OS - Shell Parser Implementation
 *
 * Recursive descent parser following bash grammar:
 *
 *   program         -> linebreak complete_commands linebreak
 *   complete_commands -> complete_command (newline_list complete_command)*
 *   complete_command -> and_or (separator_op and_or)* [separator_op]
 *   and_or          -> pipeline (('&&'|'||') linebreak pipeline)*
 *   pipeline        -> ['!'] pipe_sequence
 *   pipe_sequence   -> command ('|' linebreak command)*
 *   command         -> simple_command
 *                    | compound_command redirect_list?
 *                    | function_def
 *   compound_command-> brace_group | subshell | if_clause
 *                    | for_clause | while_clause | until_clause | case_clause
 *   simple_command  -> cmd_prefix cmd_word cmd_suffix?
 *                    | cmd_prefix
 *                    | cmd_name cmd_suffix?
 *   redirect_list   -> io_redirect+
 */

#include "parser.h"

/* ---------- Parser state ---------- */

typedef struct parser {
    lexer_t    *lex;
    token_t    *current;    /* Current token (consumed) */
    int         error;      /* Error flag */
    char        error_msg[256];
} parser_t;

/* ---------- Forward declarations ---------- */

static ast_node_t *parse_compound_list(parser_t *p);
static ast_node_t *parse_and_or(parser_t *p);
static ast_node_t *parse_pipeline(parser_t *p);
static ast_node_t *parse_command(parser_t *p);
static ast_node_t *parse_simple_command(parser_t *p);
static ast_node_t *parse_compound_command(parser_t *p);
static ast_node_t *parse_brace_group(parser_t *p);
static ast_node_t *parse_subshell(parser_t *p);
static ast_node_t *parse_if_clause(parser_t *p);
static ast_node_t *parse_for_clause(parser_t *p);
static ast_node_t *parse_while_clause(parser_t *p);
static ast_node_t *parse_until_clause(parser_t *p);
static ast_node_t *parse_case_clause(parser_t *p);
static ast_node_t *parse_function_def(parser_t *p, char *name);
static redirect_t *parse_io_redirect(parser_t *p);
static redirect_t *parse_redirect_list(parser_t *p);

/* ---------- Helper: token management ---------- */

static token_t *peek(parser_t *p)
{
    return lexer_peek(p->lex);
}

static token_type_t peek_type(parser_t *p)
{
    token_t *t = peek(p);
    return t ? t->type : TOK_EOF;
}

static token_t *advance(parser_t *p)
{
    if (p->current)
        token_free(p->current);
    p->current = lexer_next_token(p->lex);
    return p->current;
}

/*
 * Consume the current peeked token and return a copy.
 * After this, the next peek/advance will get the following token.
 */
static token_t *eat(parser_t *p)
{
    token_t *tok = lexer_next_token(p->lex);
    return tok;
}

static int accept(parser_t *p, token_type_t type)
{
    if (peek_type(p) == type) {
        token_t *tok = eat(p);
        token_free(tok);
        return 1;
    }
    return 0;
}

static int expect(parser_t *p, token_type_t type)
{
    if (peek_type(p) == type) {
        token_t *tok = eat(p);
        token_free(tok);
        return 1;
    }
    p->error = 1;
    snprintf(p->error_msg, sizeof(p->error_msg),
             "expected %s, got %s",
             token_type_name(type), token_type_name(peek_type(p)));
    return 0;
}

/* Eat a word token and return its value (caller must free) */
static char *eat_word_value(parser_t *p)
{
    token_t *tok = eat(p);
    if (!tok)
        return NULL;
    char *val = tok->value ? strdup(tok->value) : NULL;
    token_free(tok);
    return val;
}

static void parse_error(parser_t *p, const char *msg)
{
    if (!p->error) {
        p->error = 1;
        snprintf(p->error_msg, sizeof(p->error_msg), "%s", msg);
    }
}

/* ---------- Skip newlines ---------- */

static void skip_newlines(parser_t *p)
{
    while (peek_type(p) == TOK_NEWLINE) {
        token_t *tok = eat(p);
        token_free(tok);
    }
}

/* ---------- AST node constructors ---------- */

static ast_node_t *node_new(node_type_t type, int line)
{
    ast_node_t *node = calloc(1, sizeof(ast_node_t));
    if (!node)
        return NULL;
    node->type = type;
    node->line = line;
    return node;
}

/* ---------- Redirect helpers ---------- */

static redirect_t *redirect_new(redir_type_t type, int fd, const char *target)
{
    redirect_t *r = calloc(1, sizeof(redirect_t));
    if (!r)
        return NULL;
    r->type = type;
    r->fd = fd;
    r->target = target ? strdup(target) : NULL;
    r->next = NULL;
    r->heredoc_quoted = 0;
    return r;
}

static void redirect_append(redirect_t **list, redirect_t *redir)
{
    if (!*list) {
        *list = redir;
        return;
    }
    redirect_t *tail = *list;
    while (tail->next)
        tail = tail->next;
    tail->next = redir;
}

/* ---------- Check if current token starts a redirect ---------- */

static int is_redirect_token(token_type_t t)
{
    return t == TOK_LESS || t == TOK_GREAT || t == TOK_DLESS ||
           t == TOK_DGREAT || t == TOK_LESSAND || t == TOK_GREATAND ||
           t == TOK_DLESSDASH || t == TOK_CLOBBER || t == TOK_LESSGREAT ||
           t == TOK_IO_NUMBER;
}

/* ---------- Check if token is a word (or can appear as a word) ---------- */

static int is_word_token(token_type_t t)
{
    return t == TOK_WORD || t == TOK_ASSIGNMENT_WORD;
}

/* ---------- Check if token starts a compound command ---------- */

static int is_compound_start(token_type_t t)
{
    return t == TOK_LBRACE || t == TOK_LPAREN || t == TOK_IF ||
           t == TOK_FOR || t == TOK_WHILE || t == TOK_UNTIL ||
           t == TOK_CASE || t == TOK_FUNCTION || t == TOK_SELECT;
}

/* ---------- Dynamic array helpers for words ---------- */

typedef struct {
    char  **items;
    int     count;
    int     cap;
} str_array_t;

static void str_array_init(str_array_t *a)
{
    a->cap = 8;
    a->items = malloc(sizeof(char *) * a->cap);
    a->count = 0;
}

static void str_array_push(str_array_t *a, char *s)
{
    if (a->count >= a->cap) {
        a->cap *= 2;
        a->items = realloc(a->items, sizeof(char *) * a->cap);
    }
    a->items[a->count++] = s;
}

static void str_array_free_shallow(str_array_t *a)
{
    free(a->items);
    a->items = NULL;
    a->count = 0;
}

/* ---------- Dynamic array for AST nodes ---------- */

typedef struct {
    ast_node_t **items;
    int          count;
    int          cap;
} node_array_t;

static void node_array_init(node_array_t *a)
{
    a->cap = 4;
    a->items = malloc(sizeof(ast_node_t *) * a->cap);
    a->count = 0;
}

static void node_array_push(node_array_t *a, ast_node_t *node)
{
    if (a->count >= a->cap) {
        a->cap *= 2;
        a->items = realloc(a->items, sizeof(ast_node_t *) * a->cap);
    }
    a->items[a->count++] = node;
}

static void node_array_free_shallow(node_array_t *a)
{
    free(a->items);
    a->items = NULL;
    a->count = 0;
}

/* ---------- Parse IO redirect ---------- */

/*
 * io_redirect -> IO_NUMBER? io_op filename
 * io_op       -> '<' | '>' | '>>' | '<<' | '<<-' | '<&' | '>&' | '>|' | '<>'
 */
static redirect_t *parse_io_redirect(parser_t *p)
{
    int fd = -1;

    /* Optional IO_NUMBER */
    if (peek_type(p) == TOK_IO_NUMBER) {
        token_t *num_tok = eat(p);
        fd = atoi(num_tok->value);
        token_free(num_tok);
    }

    token_type_t op = peek_type(p);
    if (!is_redirect_token(op) || op == TOK_IO_NUMBER)
        return NULL;

    token_t *op_tok = eat(p);
    redir_type_t rtype;
    int default_fd;

    switch (op) {
    case TOK_LESS:
        rtype = REDIR_INPUT;
        default_fd = 0;
        break;
    case TOK_GREAT:
        rtype = REDIR_OUTPUT;
        default_fd = 1;
        break;
    case TOK_DGREAT:
        rtype = REDIR_APPEND;
        default_fd = 1;
        break;
    case TOK_DLESS:
    case TOK_DLESSDASH:
        rtype = REDIR_HEREDOC;
        default_fd = 0;
        break;
    case TOK_LESSAND:
        rtype = REDIR_DUP_INPUT;
        default_fd = 0;
        break;
    case TOK_GREATAND:
        rtype = REDIR_DUP_OUTPUT;
        default_fd = 1;
        break;
    case TOK_CLOBBER:
        rtype = REDIR_CLOBBER;
        default_fd = 1;
        break;
    case TOK_LESSGREAT:
        rtype = REDIR_RDWR;
        default_fd = 0;
        break;
    default:
        token_free(op_tok);
        return NULL;
    }

    if (fd == -1)
        fd = default_fd;

    /* For heredocs, the target (delimiter) was already stored in op_tok->value
     * by the lexer. The actual body will be in the lexer's heredoc tracking.
     * For now, create the redirect with the delimiter/body. */
    char *target = NULL;
    if (rtype == REDIR_HEREDOC) {
        /* The lexer has already consumed the delimiter and queued the heredoc.
         * op_tok->value contains the delimiter name. The heredoc body
         * will be available after the next newline is processed.
         * We store the delimiter as the target for now; the executor will
         * handle heredoc body retrieval from the lexer's heredoc list. */
        target = op_tok->value ? strdup(op_tok->value) : strdup("");

        /* Check if there's a pending heredoc body token in the lexer */
        for (int i = 0; i < p->lex->nheredocs; i++) {
            if (p->lex->heredocs[i].target_token &&
                p->lex->heredocs[i].target_token->value) {
                /* If body has been filled (after newline processing) */
                if (strlen(p->lex->heredocs[i].target_token->value) > 0) {
                    free(target);
                    target = strdup(p->lex->heredocs[i].target_token->value);
                }
            }
        }
    } else {
        /* Read the target word */
        if (!is_word_token(peek_type(p))) {
            parse_error(p, "expected filename after redirect operator");
            token_free(op_tok);
            return NULL;
        }
        target = eat_word_value(p);
    }

    redirect_t *redir = redirect_new(rtype, fd, target);
    free(target);
    token_free(op_tok);
    return redir;
}

/* Parse a list of redirects appended after a compound command */
static redirect_t *parse_redirect_list(parser_t *p)
{
    redirect_t *list = NULL;
    while (is_redirect_token(peek_type(p))) {
        redirect_t *r = parse_io_redirect(p);
        if (r)
            redirect_append(&list, r);
        else
            break;
    }
    return list;
}

/* ---------- Parse simple command ---------- */

/*
 * simple_command -> (assignment_word | io_redirect)* [word (word | io_redirect)*]
 */
static ast_node_t *parse_simple_command(parser_t *p)
{
    int line = peek(p) ? peek(p)->line : 0;
    str_array_t words;
    str_array_t assignments;
    redirect_t *redirects = NULL;

    str_array_init(&words);
    str_array_init(&assignments);

    /* Phase 1: prefix assignments and redirects */
    while (!p->error) {
        if (peek_type(p) == TOK_ASSIGNMENT_WORD) {
            token_t *tok = eat(p);
            str_array_push(&assignments, strdup(tok->value));
            token_free(tok);
            continue;
        }
        if (is_redirect_token(peek_type(p))) {
            redirect_t *r = parse_io_redirect(p);
            if (r)
                redirect_append(&redirects, r);
            continue;
        }
        break;
    }

    /* Phase 2: command word(s) and suffix redirects */
    while (!p->error) {
        if (is_word_token(peek_type(p))) {
            token_t *tok = eat(p);
            str_array_push(&words, strdup(tok->value));
            token_free(tok);
            continue;
        }
        if (is_redirect_token(peek_type(p))) {
            redirect_t *r = parse_io_redirect(p);
            if (r)
                redirect_append(&redirects, r);
            continue;
        }
        break;
    }

    /* Must have at least one word or assignment */
    if (words.count == 0 && assignments.count == 0 && redirects == NULL) {
        str_array_free_shallow(&words);
        str_array_free_shallow(&assignments);
        return NULL;
    }

    ast_node_t *node = node_new(NODE_COMMAND, line);
    node->data.command.words = words.items;
    node->data.command.nwords = words.count;
    node->data.command.assignments = assignments.items;
    node->data.command.nassignments = assignments.count;
    node->data.command.redirects = redirects;
    return node;
}

/* ---------- Parse compound commands ---------- */

/* brace_group -> '{' compound_list '}' */
static ast_node_t *parse_brace_group(parser_t *p)
{
    int line = peek(p) ? peek(p)->line : 0;
    if (!expect(p, TOK_LBRACE))
        return NULL;

    skip_newlines(p);
    ast_node_t *body = parse_compound_list(p);
    skip_newlines(p);

    if (!expect(p, TOK_RBRACE)) {
        ast_free(body);
        return NULL;
    }

    ast_node_t *node = node_new(NODE_BRACE_GROUP, line);
    node->data.brace_group.body = body;
    node->data.brace_group.redirects = parse_redirect_list(p);
    return node;
}

/* subshell -> '(' compound_list ')' */
static ast_node_t *parse_subshell(parser_t *p)
{
    int line = peek(p) ? peek(p)->line : 0;
    if (!expect(p, TOK_LPAREN))
        return NULL;

    skip_newlines(p);
    ast_node_t *body = parse_compound_list(p);
    skip_newlines(p);

    if (!expect(p, TOK_RPAREN)) {
        ast_free(body);
        return NULL;
    }

    ast_node_t *node = node_new(NODE_SUBSHELL, line);
    node->data.subshell.body = body;
    node->data.subshell.redirects = parse_redirect_list(p);
    return node;
}

/* if_clause -> 'if' compound_list 'then' compound_list
 *              ('elif' compound_list 'then' compound_list)*
 *              ['else' compound_list]
 *              'fi' */
static ast_node_t *parse_if_clause(parser_t *p)
{
    int line = peek(p) ? peek(p)->line : 0;
    if (!expect(p, TOK_IF))
        return NULL;

    skip_newlines(p);
    ast_node_t *condition = parse_compound_list(p);
    skip_newlines(p);

    if (!expect(p, TOK_THEN)) {
        ast_free(condition);
        return NULL;
    }

    skip_newlines(p);
    ast_node_t *then_body = parse_compound_list(p);
    skip_newlines(p);

    ast_node_t *else_body = NULL;
    if (peek_type(p) == TOK_ELIF) {
        /* Recursively parse elif as nested if */
        else_body = parse_if_clause(p);
    } else if (accept(p, TOK_ELSE)) {
        skip_newlines(p);
        else_body = parse_compound_list(p);
        skip_newlines(p);
        if (!expect(p, TOK_FI)) {
            ast_free(condition);
            ast_free(then_body);
            ast_free(else_body);
            return NULL;
        }
    } else {
        if (!expect(p, TOK_FI)) {
            ast_free(condition);
            ast_free(then_body);
            return NULL;
        }
    }

    ast_node_t *node = node_new(NODE_IF, line);
    node->data.if_clause.condition = condition;
    node->data.if_clause.then_body = then_body;
    node->data.if_clause.else_body = else_body;
    node->data.if_clause.redirects = parse_redirect_list(p);
    return node;
}

/* for_clause -> 'for' name [linebreak] ['in' word* (';'|newline)] linebreak
 *               'do' compound_list 'done' */
static ast_node_t *parse_for_clause(parser_t *p)
{
    int line = peek(p) ? peek(p)->line : 0;
    if (!expect(p, TOK_FOR))
        return NULL;

    /* Variable name */
    if (!is_word_token(peek_type(p))) {
        parse_error(p, "expected variable name after 'for'");
        return NULL;
    }
    char *varname = eat_word_value(p);

    skip_newlines(p);

    /* Optional 'in' word-list */
    str_array_t wordlist;
    str_array_init(&wordlist);
    int has_in = 0;

    if (peek_type(p) == TOK_IN) {
        has_in = 1;
        token_t *tok = eat(p);
        token_free(tok);

        while (is_word_token(peek_type(p))) {
            token_t *w = eat(p);
            str_array_push(&wordlist, strdup(w->value));
            token_free(w);
        }

        /* Consume ';' or newline after word list */
        if (peek_type(p) == TOK_SEMI || peek_type(p) == TOK_NEWLINE) {
            token_t *sep = eat(p);
            token_free(sep);
        }
    } else {
        /* No 'in' - consume optional ';' */
        if (peek_type(p) == TOK_SEMI) {
            token_t *sep = eat(p);
            token_free(sep);
        }
    }

    skip_newlines(p);

    if (!expect(p, TOK_DO)) {
        free(varname);
        for (int i = 0; i < wordlist.count; i++)
            free(wordlist.items[i]);
        str_array_free_shallow(&wordlist);
        return NULL;
    }

    skip_newlines(p);
    ast_node_t *body = parse_compound_list(p);
    skip_newlines(p);

    if (!expect(p, TOK_DONE)) {
        free(varname);
        for (int i = 0; i < wordlist.count; i++)
            free(wordlist.items[i]);
        str_array_free_shallow(&wordlist);
        ast_free(body);
        return NULL;
    }

    ast_node_t *node = node_new(NODE_FOR, line);
    node->data.for_clause.varname = varname;
    if (has_in) {
        node->data.for_clause.words = wordlist.items;
        node->data.for_clause.nwords = wordlist.count;
    } else {
        node->data.for_clause.words = NULL;
        node->data.for_clause.nwords = 0;
        str_array_free_shallow(&wordlist);
    }
    node->data.for_clause.body = body;
    node->data.for_clause.redirects = parse_redirect_list(p);
    return node;
}

/* while_clause -> 'while' compound_list 'do' compound_list 'done' */
static ast_node_t *parse_while_clause(parser_t *p)
{
    int line = peek(p) ? peek(p)->line : 0;
    if (!expect(p, TOK_WHILE))
        return NULL;

    skip_newlines(p);
    ast_node_t *condition = parse_compound_list(p);
    skip_newlines(p);

    if (!expect(p, TOK_DO)) {
        ast_free(condition);
        return NULL;
    }

    skip_newlines(p);
    ast_node_t *body = parse_compound_list(p);
    skip_newlines(p);

    if (!expect(p, TOK_DONE)) {
        ast_free(condition);
        ast_free(body);
        return NULL;
    }

    ast_node_t *node = node_new(NODE_WHILE, line);
    node->data.loop.condition = condition;
    node->data.loop.body = body;
    node->data.loop.redirects = parse_redirect_list(p);
    return node;
}

/* until_clause -> 'until' compound_list 'do' compound_list 'done' */
static ast_node_t *parse_until_clause(parser_t *p)
{
    int line = peek(p) ? peek(p)->line : 0;
    if (!expect(p, TOK_UNTIL))
        return NULL;

    skip_newlines(p);
    ast_node_t *condition = parse_compound_list(p);
    skip_newlines(p);

    if (!expect(p, TOK_DO)) {
        ast_free(condition);
        return NULL;
    }

    skip_newlines(p);
    ast_node_t *body = parse_compound_list(p);
    skip_newlines(p);

    if (!expect(p, TOK_DONE)) {
        ast_free(condition);
        ast_free(body);
        return NULL;
    }

    ast_node_t *node = node_new(NODE_UNTIL, line);
    node->data.loop.condition = condition;
    node->data.loop.body = body;
    node->data.loop.redirects = parse_redirect_list(p);
    return node;
}

/* case_clause -> 'case' word linebreak 'in' linebreak
 *                (case_item)* 'esac'
 * case_item   -> ['('] pattern ('|' pattern)* ')' linebreak
 *                compound_list? ';;' linebreak */
static ast_node_t *parse_case_clause(parser_t *p)
{
    int line = peek(p) ? peek(p)->line : 0;
    if (!expect(p, TOK_CASE))
        return NULL;

    if (!is_word_token(peek_type(p))) {
        parse_error(p, "expected word after 'case'");
        return NULL;
    }
    char *word = eat_word_value(p);

    skip_newlines(p);
    if (!expect(p, TOK_IN)) {
        free(word);
        return NULL;
    }
    skip_newlines(p);

    /* Parse case items */
    case_item_t *items_head = NULL;
    case_item_t *items_tail = NULL;

    while (peek_type(p) != TOK_ESAC && peek_type(p) != TOK_EOF && !p->error) {
        /* Optional leading '(' */
        accept(p, TOK_LPAREN);

        /* Parse patterns: pattern ('|' pattern)* */
        str_array_t patterns;
        str_array_init(&patterns);

        if (is_word_token(peek_type(p))) {
            str_array_push(&patterns, eat_word_value(p));
        } else {
            parse_error(p, "expected pattern in case item");
            str_array_free_shallow(&patterns);
            break;
        }

        while (peek_type(p) == TOK_PIPE) {
            token_t *tok = eat(p);
            token_free(tok);
            if (is_word_token(peek_type(p))) {
                str_array_push(&patterns, eat_word_value(p));
            } else {
                parse_error(p, "expected pattern after '|'");
                break;
            }
        }

        if (!expect(p, TOK_RPAREN)) {
            for (int i = 0; i < patterns.count; i++)
                free(patterns.items[i]);
            str_array_free_shallow(&patterns);
            break;
        }

        skip_newlines(p);

        /* Parse body (optional: can be empty before ;;) */
        ast_node_t *body = NULL;
        if (peek_type(p) != TOK_DSEMI && peek_type(p) != TOK_ESAC) {
            body = parse_compound_list(p);
        }

        skip_newlines(p);

        /* Expect ';;' (or esac terminates) */
        if (peek_type(p) == TOK_DSEMI) {
            token_t *tok = eat(p);
            token_free(tok);
        }

        skip_newlines(p);

        /* Create case_item */
        case_item_t *item = calloc(1, sizeof(case_item_t));
        item->patterns = patterns.items;
        item->npatterns = patterns.count;
        item->body = body;
        item->next = NULL;

        if (!items_head) {
            items_head = item;
            items_tail = item;
        } else {
            items_tail->next = item;
            items_tail = item;
        }
    }

    if (!expect(p, TOK_ESAC)) {
        free(word);
        case_item_free(items_head);
        return NULL;
    }

    ast_node_t *node = node_new(NODE_CASE, line);
    node->data.case_clause.word = word;
    node->data.case_clause.items = items_head;
    node->data.case_clause.redirects = parse_redirect_list(p);
    return node;
}

/* function_def -> 'function' name ['()'] compound_command
 *              |  name '()' compound_command */
static ast_node_t *parse_function_def(parser_t *p, char *name)
{
    int line = peek(p) ? peek(p)->line : 0;

    skip_newlines(p);

    /* Parse the function body (must be a compound command) */
    ast_node_t *body = parse_compound_command(p);
    if (!body) {
        parse_error(p, "expected function body");
        free(name);
        return NULL;
    }

    ast_node_t *node = node_new(NODE_FUNCTION, line);
    node->data.function.name = name;
    node->data.function.body = body;
    node->data.function.redirects = parse_redirect_list(p);
    return node;
}

/* ---------- Parse compound command ---------- */

static ast_node_t *parse_compound_command(parser_t *p)
{
    switch (peek_type(p)) {
    case TOK_LBRACE:    return parse_brace_group(p);
    case TOK_LPAREN:    return parse_subshell(p);
    case TOK_IF:        return parse_if_clause(p);
    case TOK_FOR:       return parse_for_clause(p);
    case TOK_WHILE:     return parse_while_clause(p);
    case TOK_UNTIL:     return parse_until_clause(p);
    case TOK_CASE:      return parse_case_clause(p);
    default:            return NULL;
    }
}

/* ---------- Parse command ---------- */

/*
 * command -> function_def | compound_command redirect_list? | simple_command
 *
 * Detecting function_def: either 'function name ...' or 'name()...'
 */
static ast_node_t *parse_command(parser_t *p)
{
    if (p->error)
        return NULL;

    /* 'function' keyword */
    if (peek_type(p) == TOK_FUNCTION) {
        token_t *tok = eat(p);
        token_free(tok);

        if (!is_word_token(peek_type(p))) {
            parse_error(p, "expected function name");
            return NULL;
        }
        char *name = eat_word_value(p);

        /* Optional '()' */
        if (peek_type(p) == TOK_LPAREN) {
            token_t *lp = eat(p);
            token_free(lp);
            if (!expect(p, TOK_RPAREN)) {
                free(name);
                return NULL;
            }
        }

        return parse_function_def(p, name);
    }

    /* Check for 'name()' function definition.
     *
     * We need two-token lookahead: WORD followed by '('.
     * Strategy: eat the first token, then peek at the next.  If not a
     * function def we must push BOTH tokens back.  Our lexer only has
     * single pushback (peeked), so we save the second token aside,
     * put the first token back as peeked, then re-insert the second
     * token by scanning it from the lexer again — but that doesn't
     * work because the lexer has advanced.
     *
     * Correct approach: eat the first, peek the second.  If we need
     * to push back, free the current peeked, set peeked = first,
     * then rewind the lexer position to before the second token was
     * scanned.  But we can't rewind the lexer easily.
     *
     * Simplest correct approach: eat the first, save the peeked second
     * token, then set peeked = first.  We store the saved second token
     * in a local and manually re-insert it as peeked after first is
     * consumed by parse_simple_command. But that's fragile.
     *
     * Best approach: eat both, push both back in correct order using a
     * two-slot pushback. We'll add a second pushback slot to the lexer.
     */
    if (is_word_token(peek_type(p))) {
        token_t *first = eat(p);

        if (peek_type(p) == TOK_LPAREN) {
            /* Save first token info */
            char *name = strdup(first->value);
            token_free(first);

            token_t *lp = eat(p);
            token_free(lp);

            if (peek_type(p) == TOK_RPAREN) {
                /* It's a function definition: name() { ... } */
                token_t *rp = eat(p);
                token_free(rp);
                return parse_function_def(p, name);
            } else {
                /* Not a function - this was name( something */
                parse_error(p, "expected ')' after '(' in function definition");
                free(name);
                return NULL;
            }
        }

        /* Not a function def — push first token back.
         * peek_type() above set p->lex->peeked to the second token.
         * We need to push first back BEFORE the peeked token.
         * Save the peeked (second) token, set first as peeked,
         * then store second in a new pushback slot (peeked2). */
        token_t *second = p->lex->peeked;  /* may be non-NULL from peek */
        p->lex->peeked = first;             /* first goes back first */
        p->lex->peeked2 = second;           /* second goes after first */
    }

    /* Compound commands */
    if (is_compound_start(peek_type(p))) {
        return parse_compound_command(p);
    }

    /* Simple command */
    return parse_simple_command(p);
}

/* ---------- Parse pipeline ---------- */

/*
 * pipeline -> ['time' ['-p']] ['!'] command ('|' linebreak command)*
 *
 * The 'time' reserved word is a pipeline prefix in bash.
 * It times the entire pipeline and reports real/user/sys to stderr.
 */
static ast_node_t *parse_pipeline(parser_t *p)
{
    if (p->error)
        return NULL;

    int line = peek(p) ? peek(p)->line : 0;
    int timed = 0;
    int bang = 0;

    /* Check for leading 'time' keyword */
    if (peek_type(p) == TOK_TIME) {
        timed = 1;
        token_t *tok = eat(p);
        token_free(tok);
        /* Skip optional '-p' (POSIX output format — we ignore it) */
        if (peek_type(p) == TOK_WORD) {
            token_t *peeked = peek(p);
            if (peeked && peeked->value && strcmp(peeked->value, "-p") == 0) {
                token_t *opt = eat(p);
                token_free(opt);
            }
        }
    }

    /* Check for leading '!' */
    if (peek_type(p) == TOK_BANG) {
        bang = 1;
        token_t *tok = eat(p);
        token_free(tok);
    }

    ast_node_t *first = parse_command(p);

    /* 'time' with no command: just report zero times */
    if (!first && timed) {
        first = node_new(NODE_COMMAND, line);
        first->data.command.words = NULL;
        first->data.command.nwords = 0;
        first->data.command.assignments = NULL;
        first->data.command.nassignments = 0;
        first->data.command.redirects = NULL;
    }

    if (!first)
        return NULL;

    /* Check for pipe */
    if (peek_type(p) != TOK_PIPE) {
        /* Single command */
        if (bang) {
            ast_node_t *bnode = node_new(NODE_BANG, line);
            bnode->data.bang.child = first;
            if (!timed)
                return bnode;
            /* Wrap bang in a timed single-command pipeline */
            node_array_t cmds;
            node_array_init(&cmds);
            node_array_push(&cmds, bnode);
            ast_node_t *node = node_new(NODE_PIPELINE, line);
            node->data.pipeline.commands = cmds.items;
            node->data.pipeline.ncommands = cmds.count;
            node->data.pipeline.bang = 0;
            node->data.pipeline.timed = 1;
            return node;
        }
        if (timed) {
            /* Wrap single command in a timed pipeline */
            node_array_t cmds;
            node_array_init(&cmds);
            node_array_push(&cmds, first);
            ast_node_t *node = node_new(NODE_PIPELINE, line);
            node->data.pipeline.commands = cmds.items;
            node->data.pipeline.ncommands = cmds.count;
            node->data.pipeline.bang = 0;
            node->data.pipeline.timed = 1;
            return node;
        }
        return first;
    }

    /* Build pipeline */
    node_array_t cmds;
    node_array_init(&cmds);
    node_array_push(&cmds, first);

    while (peek_type(p) == TOK_PIPE) {
        token_t *tok = eat(p);
        token_free(tok);
        skip_newlines(p);

        ast_node_t *cmd = parse_command(p);
        if (!cmd) {
            parse_error(p, "expected command after '|'");
            break;
        }
        node_array_push(&cmds, cmd);
    }

    ast_node_t *node = node_new(NODE_PIPELINE, line);
    node->data.pipeline.commands = cmds.items;
    node->data.pipeline.ncommands = cmds.count;
    node->data.pipeline.bang = bang;
    node->data.pipeline.timed = timed;
    return node;
}

/* ---------- Parse and_or ---------- */

/*
 * and_or -> pipeline (('&&' | '||') linebreak pipeline)*
 */
static ast_node_t *parse_and_or(parser_t *p)
{
    if (p->error)
        return NULL;

    ast_node_t *left = parse_pipeline(p);
    if (!left)
        return NULL;

    while (peek_type(p) == TOK_AND_IF || peek_type(p) == TOK_OR_IF) {
        token_t *op = eat(p);
        node_type_t ntype = (op->type == TOK_AND_IF) ? NODE_AND : NODE_OR;
        int line = op->line;
        token_free(op);

        skip_newlines(p);

        ast_node_t *right = parse_pipeline(p);
        if (!right) {
            parse_error(p, "expected command after '&&' or '||'");
            ast_free(left);
            return NULL;
        }

        ast_node_t *node = node_new(ntype, line);
        node->data.binary.left = left;
        node->data.binary.right = right;
        left = node;
    }

    return left;
}

/* ---------- Parse compound list ---------- */

/*
 * compound_list -> linebreak and_or ((';' | '&' | newline) linebreak and_or)*
 *                  [';' | '&' | newline]
 *
 * This is the top-level list inside braces, subshells, if bodies, etc.
 */
static ast_node_t *parse_compound_list(parser_t *p)
{
    if (p->error)
        return NULL;

    skip_newlines(p);

    ast_node_t *left = parse_and_or(p);
    if (!left)
        return NULL;

    while (!p->error) {
        token_type_t sep = peek_type(p);

        if (sep == TOK_SEMI || sep == TOK_NEWLINE) {
            token_t *tok = eat(p);
            token_free(tok);
            skip_newlines(p);

            /* Check if what follows is an end-of-construct token */
            token_type_t next = peek_type(p);
            if (next == TOK_EOF || next == TOK_RBRACE || next == TOK_RPAREN ||
                next == TOK_FI || next == TOK_DONE || next == TOK_ESAC ||
                next == TOK_THEN || next == TOK_ELSE || next == TOK_ELIF ||
                next == TOK_DO || next == TOK_DSEMI)
                break;

            ast_node_t *right = parse_and_or(p);
            if (!right)
                break;

            ast_node_t *node = node_new(NODE_SEMI, left->line);
            node->data.binary.left = left;
            node->data.binary.right = right;
            left = node;
            continue;
        }

        if (sep == TOK_AMP) {
            token_t *tok = eat(p);
            int line = tok->line;
            token_free(tok);

            /* Wrap the left side as background */
            ast_node_t *bg = node_new(NODE_BG, line);
            bg->data.bg.child = left;

            skip_newlines(p);

            /* Check if more follows */
            token_type_t next = peek_type(p);
            if (next == TOK_EOF || next == TOK_RBRACE || next == TOK_RPAREN ||
                next == TOK_FI || next == TOK_DONE || next == TOK_ESAC ||
                next == TOK_THEN || next == TOK_ELSE || next == TOK_ELIF ||
                next == TOK_DO || next == TOK_DSEMI) {
                left = bg;
                break;
            }

            ast_node_t *right = parse_and_or(p);
            if (!right) {
                left = bg;
                break;
            }

            ast_node_t *node = node_new(NODE_SEMI, line);
            node->data.binary.left = bg;
            node->data.binary.right = right;
            left = node;
            continue;
        }

        break;
    }

    return left;
}

/* ---------- Parse complete input ---------- */

ast_node_t *parse_input(const char *input)
{
    if (!input || !*input)
        return NULL;

    parser_t p;
    memset(&p, 0, sizeof(p));
    p.lex = lexer_init(input);
    if (!p.lex)
        return NULL;

    skip_newlines(&p);

    ast_node_t *result = NULL;
    if (peek_type(&p) != TOK_EOF) {
        result = parse_compound_list(&p);
    }

    if (p.error) {
        fprintf(stderr, "bash: syntax error: %s\n", p.error_msg);
        ast_free(result);
        result = NULL;
    }

    if (p.current)
        token_free(p.current);
    lexer_free(p.lex);
    return result;
}

/* ---------- AST cleanup ---------- */

void redirect_free(redirect_t *redir)
{
    while (redir) {
        redirect_t *next = redir->next;
        free(redir->target);
        free(redir);
        redir = next;
    }
}

void case_item_free(case_item_t *item)
{
    while (item) {
        case_item_t *next = item->next;
        for (int i = 0; i < item->npatterns; i++)
            free(item->patterns[i]);
        free(item->patterns);
        ast_free(item->body);
        free(item);
        item = next;
    }
}

void ast_free(ast_node_t *node)
{
    if (!node)
        return;

    switch (node->type) {
    case NODE_COMMAND:
        for (int i = 0; i < node->data.command.nwords; i++)
            free(node->data.command.words[i]);
        free(node->data.command.words);
        for (int i = 0; i < node->data.command.nassignments; i++)
            free(node->data.command.assignments[i]);
        free(node->data.command.assignments);
        redirect_free(node->data.command.redirects);
        break;

    case NODE_PIPELINE:
        for (int i = 0; i < node->data.pipeline.ncommands; i++)
            ast_free(node->data.pipeline.commands[i]);
        free(node->data.pipeline.commands);
        break;

    case NODE_AND:
    case NODE_OR:
    case NODE_SEMI:
        ast_free(node->data.binary.left);
        ast_free(node->data.binary.right);
        break;

    case NODE_BG:
        ast_free(node->data.bg.child);
        break;

    case NODE_SUBSHELL:
        ast_free(node->data.subshell.body);
        redirect_free(node->data.subshell.redirects);
        break;

    case NODE_IF:
        ast_free(node->data.if_clause.condition);
        ast_free(node->data.if_clause.then_body);
        ast_free(node->data.if_clause.else_body);
        redirect_free(node->data.if_clause.redirects);
        break;

    case NODE_FOR:
        free(node->data.for_clause.varname);
        for (int i = 0; i < node->data.for_clause.nwords; i++)
            free(node->data.for_clause.words[i]);
        free(node->data.for_clause.words);
        ast_free(node->data.for_clause.body);
        redirect_free(node->data.for_clause.redirects);
        break;

    case NODE_WHILE:
    case NODE_UNTIL:
        ast_free(node->data.loop.condition);
        ast_free(node->data.loop.body);
        redirect_free(node->data.loop.redirects);
        break;

    case NODE_CASE:
        free(node->data.case_clause.word);
        case_item_free(node->data.case_clause.items);
        redirect_free(node->data.case_clause.redirects);
        break;

    case NODE_FUNCTION:
        free(node->data.function.name);
        ast_free(node->data.function.body);
        redirect_free(node->data.function.redirects);
        break;

    case NODE_BRACE_GROUP:
        ast_free(node->data.brace_group.body);
        redirect_free(node->data.brace_group.redirects);
        break;

    case NODE_BANG:
        ast_free(node->data.bang.child);
        break;
    }

    free(node);
}

/* ---------- Debug: print AST ---------- */

static void print_indent(int indent)
{
    for (int i = 0; i < indent; i++)
        fprintf(stderr, "  ");
}

void ast_print(ast_node_t *node, int indent)
{
    if (!node) {
        print_indent(indent);
        fprintf(stderr, "(null)\n");
        return;
    }

    print_indent(indent);

    switch (node->type) {
    case NODE_COMMAND:
        fprintf(stderr, "COMMAND:");
        if (node->data.command.nassignments > 0) {
            fprintf(stderr, " assigns=[");
            for (int i = 0; i < node->data.command.nassignments; i++) {
                if (i > 0) fprintf(stderr, ", ");
                fprintf(stderr, "%s", node->data.command.assignments[i]);
            }
            fprintf(stderr, "]");
        }
        if (node->data.command.nwords > 0) {
            fprintf(stderr, " words=[");
            for (int i = 0; i < node->data.command.nwords; i++) {
                if (i > 0) fprintf(stderr, ", ");
                fprintf(stderr, "%s", node->data.command.words[i]);
            }
            fprintf(stderr, "]");
        }
        fprintf(stderr, "\n");
        break;

    case NODE_PIPELINE:
        fprintf(stderr, "PIPELINE%s%s (%d cmds):\n",
                node->data.pipeline.timed ? " [time]" : "",
                node->data.pipeline.bang ? " [!]" : "",
                node->data.pipeline.ncommands);
        for (int i = 0; i < node->data.pipeline.ncommands; i++)
            ast_print(node->data.pipeline.commands[i], indent + 1);
        break;

    case NODE_AND:
        fprintf(stderr, "AND:\n");
        ast_print(node->data.binary.left, indent + 1);
        ast_print(node->data.binary.right, indent + 1);
        break;

    case NODE_OR:
        fprintf(stderr, "OR:\n");
        ast_print(node->data.binary.left, indent + 1);
        ast_print(node->data.binary.right, indent + 1);
        break;

    case NODE_SEMI:
        fprintf(stderr, "SEMI:\n");
        ast_print(node->data.binary.left, indent + 1);
        ast_print(node->data.binary.right, indent + 1);
        break;

    case NODE_BG:
        fprintf(stderr, "BG:\n");
        ast_print(node->data.bg.child, indent + 1);
        break;

    case NODE_SUBSHELL:
        fprintf(stderr, "SUBSHELL:\n");
        ast_print(node->data.subshell.body, indent + 1);
        break;

    case NODE_IF:
        fprintf(stderr, "IF:\n");
        print_indent(indent + 1);
        fprintf(stderr, "condition:\n");
        ast_print(node->data.if_clause.condition, indent + 2);
        print_indent(indent + 1);
        fprintf(stderr, "then:\n");
        ast_print(node->data.if_clause.then_body, indent + 2);
        if (node->data.if_clause.else_body) {
            print_indent(indent + 1);
            fprintf(stderr, "else:\n");
            ast_print(node->data.if_clause.else_body, indent + 2);
        }
        break;

    case NODE_FOR:
        fprintf(stderr, "FOR %s in", node->data.for_clause.varname);
        for (int i = 0; i < node->data.for_clause.nwords; i++)
            fprintf(stderr, " %s", node->data.for_clause.words[i]);
        fprintf(stderr, ":\n");
        ast_print(node->data.for_clause.body, indent + 1);
        break;

    case NODE_WHILE:
        fprintf(stderr, "WHILE:\n");
        print_indent(indent + 1);
        fprintf(stderr, "condition:\n");
        ast_print(node->data.loop.condition, indent + 2);
        print_indent(indent + 1);
        fprintf(stderr, "body:\n");
        ast_print(node->data.loop.body, indent + 2);
        break;

    case NODE_UNTIL:
        fprintf(stderr, "UNTIL:\n");
        print_indent(indent + 1);
        fprintf(stderr, "condition:\n");
        ast_print(node->data.loop.condition, indent + 2);
        print_indent(indent + 1);
        fprintf(stderr, "body:\n");
        ast_print(node->data.loop.body, indent + 2);
        break;

    case NODE_CASE:
        fprintf(stderr, "CASE %s:\n", node->data.case_clause.word);
        for (case_item_t *ci = node->data.case_clause.items; ci; ci = ci->next) {
            print_indent(indent + 1);
            fprintf(stderr, "patterns: ");
            for (int i = 0; i < ci->npatterns; i++) {
                if (i > 0) fprintf(stderr, " | ");
                fprintf(stderr, "%s", ci->patterns[i]);
            }
            fprintf(stderr, ")\n");
            ast_print(ci->body, indent + 2);
        }
        break;

    case NODE_FUNCTION:
        fprintf(stderr, "FUNCTION %s:\n", node->data.function.name);
        ast_print(node->data.function.body, indent + 1);
        break;

    case NODE_BRACE_GROUP:
        fprintf(stderr, "BRACE_GROUP:\n");
        ast_print(node->data.brace_group.body, indent + 1);
        break;

    case NODE_BANG:
        fprintf(stderr, "BANG:\n");
        ast_print(node->data.bang.child, indent + 1);
        break;
    }
}
