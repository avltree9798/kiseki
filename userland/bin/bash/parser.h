/*
 * Kiseki OS - Shell Parser
 *
 * Recursive descent parser for bash syntax.
 * Produces an abstract syntax tree (AST) from token stream.
 */

#ifndef _PARSER_H
#define _PARSER_H

#include "lexer.h"

/* ---------- AST node types ---------- */

typedef enum {
    NODE_COMMAND,       /* Simple command: words + assignments + redirects */
    NODE_PIPELINE,      /* cmd1 | cmd2 | cmd3 */
    NODE_AND,           /* cmd1 && cmd2 */
    NODE_OR,            /* cmd1 || cmd2 */
    NODE_SEMI,          /* cmd1 ; cmd2 (sequential) */
    NODE_BG,            /* cmd & (background) */
    NODE_SUBSHELL,      /* ( cmd ) */
    NODE_IF,            /* if/then/elif/else/fi */
    NODE_FOR,           /* for var in words; do body; done */
    NODE_WHILE,         /* while cond; do body; done */
    NODE_UNTIL,         /* until cond; do body; done */
    NODE_CASE,          /* case word in pattern) body;; esac */
    NODE_FUNCTION,      /* name() { body } */
    NODE_BRACE_GROUP,   /* { body } */
    NODE_BANG           /* ! pipeline (negate exit status) */
} node_type_t;

/* ---------- Redirect types ---------- */

typedef enum {
    REDIR_INPUT,        /* < file */
    REDIR_OUTPUT,       /* > file */
    REDIR_APPEND,       /* >> file */
    REDIR_HEREDOC,      /* << delim */
    REDIR_DUP_INPUT,    /* <& fd */
    REDIR_DUP_OUTPUT,   /* >& fd */
    REDIR_CLOBBER,      /* >| file */
    REDIR_RDWR          /* <> file */
} redir_type_t;

/* ---------- Redirect ---------- */

struct redirect {
    redir_type_t    type;
    int             fd;         /* Source fd (-1 for default) */
    char           *target;     /* Filename, fd number, or heredoc content */
    int             heredoc_quoted; /* Heredoc: was delimiter quoted? */
    redirect_t     *next;       /* Linked list */
};

/* ---------- Case pattern item ---------- */

typedef struct case_item {
    char              **patterns;       /* Array of patterns */
    int                 npatterns;
    ast_node_t         *body;           /* Commands for this case */
    struct case_item   *next;
} case_item_t;

/* ---------- AST node ---------- */

struct ast_node {
    node_type_t     type;

    union {
        /* NODE_COMMAND */
        struct {
            char          **words;          /* Command words (argv) */
            int             nwords;
            char          **assignments;    /* VAR=value pairs */
            int             nassignments;
            redirect_t     *redirects;      /* Redirect list */
        } command;

        /* NODE_PIPELINE */
        struct {
            ast_node_t    **commands;       /* Array of commands */
            int             ncommands;
            int             bang;           /* Preceded by ! */
            int             timed;         /* Preceded by 'time' keyword */
        } pipeline;

        /* NODE_AND, NODE_OR, NODE_SEMI */
        struct {
            ast_node_t     *left;
            ast_node_t     *right;
        } binary;

        /* NODE_BG */
        struct {
            ast_node_t     *child;
        } bg;

        /* NODE_SUBSHELL */
        struct {
            ast_node_t     *body;
            redirect_t     *redirects;
        } subshell;

        /* NODE_IF */
        struct {
            ast_node_t     *condition;      /* Test commands */
            ast_node_t     *then_body;      /* Then clause */
            ast_node_t     *else_body;      /* Else/elif clause (or NULL) */
            redirect_t     *redirects;
        } if_clause;

        /* NODE_FOR */
        struct {
            char           *varname;        /* Iterator variable */
            char          **words;          /* Word list (NULL = $@) */
            int             nwords;
            ast_node_t     *body;
            redirect_t     *redirects;
        } for_clause;

        /* NODE_WHILE, NODE_UNTIL */
        struct {
            ast_node_t     *condition;
            ast_node_t     *body;
            redirect_t     *redirects;
        } loop;

        /* NODE_CASE */
        struct {
            char           *word;           /* Word to match */
            case_item_t    *items;          /* Linked list of case items */
            redirect_t     *redirects;
        } case_clause;

        /* NODE_FUNCTION */
        struct {
            char           *name;
            ast_node_t     *body;
            redirect_t     *redirects;
        } function;

        /* NODE_BRACE_GROUP */
        struct {
            ast_node_t     *body;
            redirect_t     *redirects;
        } brace_group;

        /* NODE_BANG */
        struct {
            ast_node_t     *child;
        } bang;
    } data;

    int line;   /* Source line number */
};

/* ---------- Public API ---------- */

ast_node_t     *parse_input(const char *input);
void            ast_free(ast_node_t *node);

/* Helpers for redirect and case_item freeing */
void            redirect_free(redirect_t *redir);
void            case_item_free(case_item_t *item);

/* Debug: print AST (for development) */
void            ast_print(ast_node_t *node, int indent);

#endif /* _PARSER_H */
