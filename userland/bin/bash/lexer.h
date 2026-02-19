/*
 * Kiseki OS - Shell Lexer
 *
 * Tokenizer for bash-compatible shell syntax.
 * Handles quoting, escaping, here-docs, comments, and all bash operators.
 */

#ifndef _LEXER_H
#define _LEXER_H

#include "shell.h"

/* ---------- Token types ---------- */

typedef enum {
    /* Literals and identifiers */
    TOK_WORD,               /* A regular word */
    TOK_ASSIGNMENT_WORD,    /* name=value */
    TOK_IO_NUMBER,          /* Numeric fd before redirect (e.g., 2>) */
    TOK_NEWLINE,            /* \n */

    /* Operators */
    TOK_AND_IF,             /* && */
    TOK_OR_IF,              /* || */
    TOK_DSEMI,              /* ;; */
    TOK_PIPE,               /* | */
    TOK_AMP,                /* & */
    TOK_SEMI,               /* ; */

    /* Redirections */
    TOK_LESS,               /* < */
    TOK_GREAT,              /* > */
    TOK_DLESS,              /* << */
    TOK_DGREAT,             /* >> */
    TOK_LESSAND,            /* <& */
    TOK_GREATAND,           /* >& */
    TOK_DLESSDASH,          /* <<- */
    TOK_CLOBBER,            /* >| */
    TOK_LESSGREAT,          /* <> */

    /* Grouping */
    TOK_LPAREN,             /* ( */
    TOK_RPAREN,             /* ) */
    TOK_LBRACE,             /* { */
    TOK_RBRACE,             /* } */

    /* Reserved words */
    TOK_BANG,               /* ! */
    TOK_IF,
    TOK_THEN,
    TOK_ELSE,
    TOK_ELIF,
    TOK_FI,
    TOK_DO,
    TOK_DONE,
    TOK_CASE,
    TOK_ESAC,
    TOK_WHILE,
    TOK_UNTIL,
    TOK_FOR,
    TOK_IN,
    TOK_FUNCTION,
    TOK_SELECT,
    TOK_TIME,

    /* End of input */
    TOK_EOF,

    /* Error */
    TOK_ERROR
} token_type_t;

/* ---------- Token ---------- */

struct token {
    token_type_t    type;
    char           *value;      /* Token text (heap-allocated) */
    int             line;       /* Line number where token starts */
    int             quoted;     /* Was any part of this token quoted? */
};

/* ---------- Here-document tracking ---------- */

#define MAX_HEREDOCS    16

typedef struct heredoc_pending {
    char   *delimiter;          /* End marker (e.g., "EOF") */
    int     strip_tabs;         /* <<- : strip leading tabs */
    int     quoted;             /* Delimiter was quoted (no expansion) */
    token_t *target_token;      /* Token to fill with heredoc content */
} heredoc_pending_t;

/* ---------- Lexer state ---------- */

struct lexer {
    const char     *input;      /* Full input string */
    size_t          pos;        /* Current scan position */
    size_t          len;        /* Total input length */
    int             line;       /* Current line number */

    /* Peeked tokens (two-slot lookahead for function-def detection) */
    token_t        *peeked;
    token_t        *peeked2;    /* Second pushback slot */

    /* Here-document queue */
    heredoc_pending_t   heredocs[MAX_HEREDOCS];
    int                 nheredocs;
    int                 heredoc_needs_body;  /* Need to read body at next \n */
};

/* ---------- Public API ---------- */

lexer_t    *lexer_init(const char *input);
token_t    *lexer_next_token(lexer_t *lex);
token_t    *lexer_peek(lexer_t *lex);
void        token_free(token_t *tok);
void        lexer_free(lexer_t *lex);

/* Utility: human-readable token type name (for debugging) */
const char *token_type_name(token_type_t type);

#endif /* _LEXER_H */
