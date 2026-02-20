/*
 * Kiseki OS - awk: Pattern-directed scanning and processing language
 *
 * A basic but functional AWK implementation with:
 * - Lexer, recursive-descent parser, AST, tree-walk evaluator
 * - Field splitting, built-in variables, associative arrays
 * - Regex matching (built-in engine)
 * - Control flow: if/else, while, for, for-in, do-while
 * - Built-in functions: print, printf, length, substr, index, split,
 *   sub, gsub, tolower, toupper, sprintf, int
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

/* =========================================================================
 * Regex engine (minimal, shared pattern)
 * ========================================================================= */

#define RE_MAX_NODES 256

enum re_type {
    RE_LITERAL, RE_DOT, RE_STAR, RE_PLUS, RE_QUEST,
    RE_ANCHOR_BOL, RE_ANCHOR_EOL,
    RE_CLASS, RE_NCLASS, RE_END
};

struct re_node {
    enum re_type type;
    char ch;
    char cls[32]; /* 256-bit bitmap */
};

static void cls_set(char cls[32], unsigned char c) { cls[c / 8] |= (1 << (c % 8)); }
static int  cls_get(const char cls[32], unsigned char c) { return (cls[c / 8] >> (c % 8)) & 1; }

static int re_compile(const char *pat, struct re_node *nodes, int max)
{
    int n = 0;
    int i = 0;
    while (pat[i] && n < max - 1) {
        if (pat[i] == '^') {
            nodes[n++].type = RE_ANCHOR_BOL;
            i++;
        } else if (pat[i] == '$' && pat[i+1] == '\0') {
            nodes[n++].type = RE_ANCHOR_EOL;
            i++;
        } else if (pat[i] == '.') {
            nodes[n].type = RE_DOT;
            nodes[n].ch = 0;
            n++; i++;
        } else if (pat[i] == '[') {
            int neg = 0;
            i++;
            if (pat[i] == '^') { neg = 1; i++; }
            struct re_node *nd = &nodes[n];
            nd->type = neg ? RE_NCLASS : RE_CLASS;
            memset(nd->cls, 0, 32);
            int first = 1;
            while (pat[i] && (first || pat[i] != ']')) {
                first = 0;
                if (pat[i+1] == '-' && pat[i+2] && pat[i+2] != ']') {
                    for (unsigned char c = (unsigned char)pat[i]; c <= (unsigned char)pat[i+2]; c++)
                        cls_set(nd->cls, c);
                    i += 3;
                } else if (pat[i] == '\\' && pat[i+1]) {
                    i++;
                    cls_set(nd->cls, (unsigned char)pat[i]);
                    i++;
                } else {
                    cls_set(nd->cls, (unsigned char)pat[i]);
                    i++;
                }
            }
            if (pat[i] == ']') i++;
            n++;
        } else if (pat[i] == '\\' && pat[i+1]) {
            i++;
            nodes[n].type = RE_LITERAL;
            nodes[n].ch = pat[i];
            n++; i++;
        } else {
            nodes[n].type = RE_LITERAL;
            nodes[n].ch = pat[i];
            n++; i++;
        }
        /* Check for quantifiers */
        if (pat[i] == '*' || pat[i] == '+' || pat[i] == '?') {
            struct re_node base = nodes[n-1];
            nodes[n-1] = base;
            struct re_node q;
            q.ch = 0;
            memset(q.cls, 0, 32);
            if (pat[i] == '*') q.type = RE_STAR;
            else if (pat[i] == '+') q.type = RE_PLUS;
            else q.type = RE_QUEST;
            q.ch = 0;
            /* encode: base is at n-1, quantifier wraps it */
            /* Simple approach: replace node with quantified version */
            /* We'll handle in matching instead */
            /* Store quantifier type in a separate slot */
            nodes[n] = q;
            n++; i++;
        }
    }
    nodes[n].type = RE_END;
    return n;
}

static int re_match_here(struct re_node *nodes, int pos, const char *text, int ti);

static int re_match_single(struct re_node *nd, char c)
{
    if (!c) return 0;
    switch (nd->type) {
    case RE_LITERAL: return nd->ch == c;
    case RE_DOT: return c != '\n';
    case RE_CLASS: return cls_get(nd->cls, (unsigned char)c);
    case RE_NCLASS: return !cls_get(nd->cls, (unsigned char)c) && c != '\n';
    default: return 0;
    }
}

static int re_match_here(struct re_node *nodes, int pos, const char *text, int ti)
{
    if (nodes[pos].type == RE_END) return ti;
    if (nodes[pos].type == RE_ANCHOR_EOL)
        return (text[ti] == '\0' || text[ti] == '\n') ? ti : -1;
    if (nodes[pos].type == RE_ANCHOR_BOL)
        return re_match_here(nodes, pos+1, text, ti);

    /* Check if next node is a quantifier */
    if (pos + 1 < RE_MAX_NODES &&
        (nodes[pos+1].type == RE_STAR || nodes[pos+1].type == RE_PLUS ||
         nodes[pos+1].type == RE_QUEST)) {
        struct re_node *base = &nodes[pos];
        enum re_type qt = nodes[pos+1].type;
        int next = pos + 2;
        int min_rep = (qt == RE_PLUS) ? 1 : 0;
        int max_rep = (qt == RE_QUEST) ? 1 : 10000;

        /* Count max matches */
        int count = 0;
        while (count < max_rep && text[ti + count] && re_match_single(base, text[ti + count]))
            count++;

        /* Try greedy: from max down to min */
        for (int c = count; c >= min_rep; c--) {
            int r = re_match_here(nodes, next, text, ti + c);
            if (r >= 0) return r;
        }
        return -1;
    }

    /* Single match */
    if (re_match_single(&nodes[pos], text[ti]))
        return re_match_here(nodes, pos+1, text, ti+1);
    return -1;
}

static int re_search(struct re_node *nodes, const char *text, int *match_start, int *match_end)
{
    int anchored = (nodes[0].type == RE_ANCHOR_BOL);
    int len = (int)strlen(text);
    for (int i = 0; i <= len; i++) {
        int r = re_match_here(nodes, 0, text, i);
        if (r >= 0) {
            if (match_start) *match_start = i;
            if (match_end) *match_end = r;
            return 1;
        }
        if (anchored) break;
    }
    return 0;
}

/* =========================================================================
 * AWK value system
 * ========================================================================= */

#define VAL_STRING  1
#define VAL_NUMBER  2

typedef struct awk_val {
    int     type;
    char   *sval;
    double  nval;
} awk_val;

static awk_val val_num(double n)
{
    awk_val v;
    v.type = VAL_NUMBER;
    v.nval = n;
    v.sval = NULL;
    return v;
}

static awk_val val_str(const char *s)
{
    awk_val v;
    v.type = VAL_STRING;
    v.sval = strdup(s ? s : "");
    v.nval = 0;
    return v;
}

static void val_free(awk_val *v)
{
    if (v->sval) { free(v->sval); v->sval = NULL; }
}

/* Convert to number */
static double val_to_num(awk_val *v)
{
    if (v->type == VAL_NUMBER) return v->nval;
    if (v->sval) {
        char *end;
        double d = (double)strtol(v->sval, &end, 10);
        /* Check for decimal */
        if (*end == '.') {
            double frac = 0.0, div = 10.0;
            end++;
            while (*end >= '0' && *end <= '9') {
                frac += (*end - '0') / div;
                div *= 10.0;
                end++;
            }
            d += (d < 0) ? -frac : frac;
        }
        return d;
    }
    return 0.0;
}

/* Convert to string */
static const char *val_to_str(awk_val *v, char *buf, int bufsz)
{
    if (v->type == VAL_STRING && v->sval) return v->sval;
    /* Format number */
    long l = (long)v->nval;
    if ((double)l == v->nval) {
        snprintf(buf, bufsz, "%ld", l);
    } else {
        snprintf(buf, bufsz, "%.6g", v->nval);
    }
    return buf;
}

static int val_is_true(awk_val *v)
{
    if (v->type == VAL_NUMBER) return v->nval != 0.0;
    if (v->sval) return v->sval[0] != '\0';
    return 0;
}

/* Simple double printing without libc %f */
static void double_to_str(double d, char *buf, int bufsz)
{
    long l = (long)d;
    if ((double)l == d) {
        snprintf(buf, bufsz, "%ld", l);
    } else {
        /* Manual: integer part + fractional */
        int neg = 0;
        if (d < 0) { neg = 1; d = -d; }
        long ip = (long)d;
        double fp = d - (double)ip;
        /* 6 decimal places */
        long frac = (long)(fp * 1000000.0 + 0.5);
        if (neg) snprintf(buf, bufsz, "-%ld.%06ld", ip, frac);
        else snprintf(buf, bufsz, "%ld.%06ld", ip, frac);
        /* Strip trailing zeros */
        int len = (int)strlen(buf);
        while (len > 1 && buf[len-1] == '0' && buf[len-2] != '.') {
            buf[--len] = '\0';
        }
    }
}

/* =========================================================================
 * Variable / symbol table (associative arrays)
 * ========================================================================= */

#define MAX_VARS 1024
#define MAX_ARRAY_SIZE 4096

typedef struct awk_array_entry {
    char    *key;
    awk_val  val;
    struct awk_array_entry *next;
} awk_array_entry;

typedef struct awk_array {
    awk_array_entry *buckets[256];
    int count;
} awk_array;

typedef struct awk_var {
    char       *name;
    awk_val     val;
    awk_array  *array;  /* non-NULL if this is an array */
} awk_var;

static awk_var g_vars[MAX_VARS];
static int g_nvars = 0;

static unsigned hash_str(const char *s)
{
    unsigned h = 5381;
    while (*s) h = h * 33 + (unsigned char)*s++;
    return h;
}

static awk_var *var_lookup(const char *name)
{
    for (int i = 0; i < g_nvars; i++) {
        if (strcmp(g_vars[i].name, name) == 0)
            return &g_vars[i];
    }
    return NULL;
}

static awk_var *var_get(const char *name)
{
    awk_var *v = var_lookup(name);
    if (v) return v;
    if (g_nvars >= MAX_VARS) {
        fprintf(stderr, "awk: too many variables\n");
        exit(2);
    }
    v = &g_vars[g_nvars++];
    v->name = strdup(name);
    v->val = val_str("");
    v->array = NULL;
    return v;
}

static void var_set(const char *name, awk_val val)
{
    awk_var *v = var_get(name);
    val_free(&v->val);
    v->val = val;
}

static void var_set_num(const char *name, double n)
{
    var_set(name, val_num(n));
}

static void var_set_str(const char *name, const char *s)
{
    var_set(name, val_str(s));
}

/* Array operations */
static awk_array *array_ensure(awk_var *v)
{
    if (!v->array) {
        v->array = calloc(1, sizeof(awk_array));
    }
    return v->array;
}

static awk_val *array_get(awk_array *a, const char *key)
{
    unsigned h = hash_str(key) % 256;
    awk_array_entry *e = a->buckets[h];
    while (e) {
        if (strcmp(e->key, key) == 0) return &e->val;
        e = e->next;
    }
    /* Create new entry */
    e = calloc(1, sizeof(awk_array_entry));
    e->key = strdup(key);
    e->val = val_str("");
    e->next = a->buckets[h];
    a->buckets[h] = e;
    a->count++;
    return &e->val;
}

static int array_has(awk_array *a, const char *key)
{
    if (!a) return 0;
    unsigned h = hash_str(key) % 256;
    awk_array_entry *e = a->buckets[h];
    while (e) {
        if (strcmp(e->key, key) == 0) return 1;
        e = e->next;
    }
    return 0;
}

static void array_delete(awk_array *a, const char *key)
{
    if (!a) return;
    unsigned h = hash_str(key) % 256;
    awk_array_entry **pp = &a->buckets[h];
    while (*pp) {
        if (strcmp((*pp)->key, key) == 0) {
            awk_array_entry *e = *pp;
            *pp = e->next;
            free(e->key);
            val_free(&e->val);
            free(e);
            a->count--;
            return;
        }
        pp = &(*pp)->next;
    }
}

/* =========================================================================
 * Field handling
 * ========================================================================= */

#define MAX_FIELDS 1024

static char  g_line[65536];     /* Current input line ($0) */
static char *g_fields[MAX_FIELDS];
static int   g_nfields = 0;
static char  g_fs[64] = " ";   /* Field separator */

/* =========================================================================
 * Output Redirection Table
 *
 * Tracks open output files and pipes for print/printf > file, >> file, | cmd.
 * Entries are reused by filename/command match (awk keeps them open until END).
 * ========================================================================= */

#define AWK_MAX_OUTPUTS 16

struct awk_output {
    char    name[256];  /* filename or command string */
    FILE   *fp;
    int     mode;       /* '>' = write, 'A' = append, '|' = pipe */
};

static struct awk_output g_outputs[AWK_MAX_OUTPUTS];
static int g_noutputs = 0;

static FILE *awk_get_output(const char *name, int mode)
{
    /* Search existing entries */
    for (int i = 0; i < g_noutputs; i++) {
        if (g_outputs[i].mode == mode && strcmp(g_outputs[i].name, name) == 0)
            return g_outputs[i].fp;
    }

    /* Open new entry */
    if (g_noutputs >= AWK_MAX_OUTPUTS) {
        fprintf(stderr, "awk: too many open output files\n");
        return stdout;
    }

    FILE *fp = NULL;
    if (mode == '>') {
        fp = fopen(name, "w");
    } else if (mode == 'A') {
        fp = fopen(name, "a");
    } else if (mode == '|') {
        fp = popen(name, "w");
    }

    if (fp == NULL) {
        fprintf(stderr, "awk: cannot open '%s': %s\n", name, strerror(errno));
        return stdout;
    }

    struct awk_output *o = &g_outputs[g_noutputs++];
    strncpy(o->name, name, sizeof(o->name) - 1);
    o->name[sizeof(o->name) - 1] = '\0';
    o->fp = fp;
    o->mode = mode;

    return fp;
}

static void awk_close_outputs(void)
{
    for (int i = 0; i < g_noutputs; i++) {
        if (g_outputs[i].fp) {
            if (g_outputs[i].mode == '|')
                pclose(g_outputs[i].fp);
            else
                fclose(g_outputs[i].fp);
            g_outputs[i].fp = NULL;
        }
    }
    g_noutputs = 0;
}

static void split_fields(void)
{
    static char field_buf[65536];
    strcpy(field_buf, g_line);
    g_nfields = 0;

    if (strcmp(g_fs, " ") == 0) {
        /* Default: split on runs of whitespace, skip leading */
        char *p = field_buf;
        while (*p == ' ' || *p == '\t' || *p == '\n') p++;
        while (*p && g_nfields < MAX_FIELDS - 1) {
            g_fields[g_nfields++] = p;
            while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
            if (*p) { *p++ = '\0'; }
            while (*p == ' ' || *p == '\t' || *p == '\n') p++;
        }
    } else if (g_fs[0] && !g_fs[1]) {
        /* Single-char separator */
        char sep = g_fs[0];
        char *p = field_buf;
        while (g_nfields < MAX_FIELDS - 1) {
            g_fields[g_nfields++] = p;
            char *next = strchr(p, sep);
            if (!next) break;
            *next = '\0';
            p = next + 1;
        }
    } else {
        /* Treat FS as regex — simplified: just use first char */
        char *p = field_buf;
        g_fields[g_nfields++] = p;
        /* For simplicity, split on the whole FS string */
        int fslen = (int)strlen(g_fs);
        while (*p && g_nfields < MAX_FIELDS - 1) {
            char *found = strstr(p, g_fs);
            if (!found) break;
            *found = '\0';
            p = found + fslen;
            g_fields[g_nfields++] = p;
        }
    }
}

static const char *get_field(int n)
{
    if (n == 0) return g_line;
    if (n >= 1 && n <= g_nfields) return g_fields[n-1];
    return "";
}

static void rebuild_record(void)
{
    /* Reconstruct $0 from fields using OFS */
    awk_var *ofs_var = var_lookup("OFS");
    const char *ofs = (ofs_var && ofs_var->val.sval) ? ofs_var->val.sval : " ";
    g_line[0] = '\0';
    for (int i = 0; i < g_nfields; i++) {
        if (i > 0) strcat(g_line, ofs);
        strcat(g_line, g_fields[i]);
    }
}

/* =========================================================================
 * AST node types
 * ========================================================================= */

enum node_type {
    N_NUMBER, N_STRING, N_REGEX,
    N_FIELDREF,     /* $expr */
    N_VAR,          /* variable reference */
    N_ARRAY_REF,    /* array[subscript] */
    N_ASSIGN,       /* var = expr */
    N_ADD_ASSIGN, N_SUB_ASSIGN, N_MUL_ASSIGN, N_DIV_ASSIGN, N_MOD_ASSIGN,
    N_BINOP,        /* +, -, *, /, %, ^, <, >, <=, >=, ==, !=, ~, !~ */
    N_UNARY_MINUS,
    N_NOT,          /* ! */
    N_AND,          /* && */
    N_OR,           /* || */
    N_CONCAT,       /* string concatenation (juxtaposition) */
    N_MATCH,        /* ~ */
    N_NOTMATCH,     /* !~ */
    N_TERNARY,      /* cond ? a : b */
    N_INCR, N_DECR, /* ++, -- (prefix) */
    N_POST_INCR, N_POST_DECR,
    N_IN,           /* (key) in array */
    N_GETLINE,
    N_CALL,         /* built-in function call */
    N_PRINT,
    N_PRINTF,
    N_IF,
    N_WHILE,
    N_DO_WHILE,
    N_FOR,
    N_FOR_IN,
    N_BREAK,
    N_CONTINUE,
    N_NEXT,
    N_EXIT,
    N_RETURN,
    N_DELETE,
    N_BLOCK,        /* { stmt; stmt; ... } */
    N_RULE,         /* pattern { action } */
    N_PROGRAM,      /* list of rules */
    N_NOP
};

#define OP_ADD  '+'
#define OP_SUB  '-'
#define OP_MUL  '*'
#define OP_DIV  '/'
#define OP_MOD  '%'
#define OP_POW  '^'
#define OP_LT   '<'
#define OP_GT   '>'
#define OP_LE   256
#define OP_GE   257
#define OP_EQ   258
#define OP_NE   259

typedef struct node {
    enum node_type type;
    int         op;         /* for N_BINOP: operator */
    double      num;        /* for N_NUMBER */
    char       *str;        /* for N_STRING, N_REGEX, N_VAR, N_CALL */
    struct node *left;      /* first child / condition */
    struct node *right;     /* second child */
    struct node *extra;     /* third child (e.g., else branch, for increment) */
    struct node *extra2;    /* fourth (for-init) */
    struct node **args;     /* function arguments / print args */
    int          nargs;
    struct node *next;      /* sibling in block/program */
} node;

static node *alloc_node(enum node_type type)
{
    node *n = calloc(1, sizeof(node));
    n->type = type;
    return n;
}

/* =========================================================================
 * Lexer
 * ========================================================================= */

enum tok_type {
    T_EOF = 0, T_NL, T_SEMI,
    T_LBRACE, T_RBRACE, T_LPAREN, T_RPAREN, T_LBRACKET, T_RBRACKET,
    T_COMMA, T_DOLLAR,
    T_ASSIGN, T_ADD_ASSIGN, T_SUB_ASSIGN, T_MUL_ASSIGN, T_DIV_ASSIGN, T_MOD_ASSIGN,
    T_PLUS, T_MINUS, T_STAR, T_SLASH, T_PERCENT, T_CARET,
    T_LT, T_GT, T_LE, T_GE, T_EQ, T_NE,
    T_AND, T_OR, T_NOT,
    T_MATCH, T_NOTMATCH,   /* ~ !~ */
    T_INCR, T_DECR,        /* ++ -- */
    T_APPEND,               /* >> */
    T_PIPE,                 /* | */
    T_QUESTION, T_COLON,
    T_NUMBER, T_STRING, T_REGEX,
    T_NAME,
    /* Keywords */
    T_BEGIN, T_END, T_IF, T_ELSE, T_WHILE, T_FOR, T_DO,
    T_BREAK, T_CONTINUE, T_NEXT, T_EXIT, T_RETURN,
    T_DELETE, T_IN, T_GETLINE,
    T_PRINT, T_PRINTF, T_FUNCTION,
};

static const char *g_src;
static int g_pos;
static enum tok_type g_tok;
static char g_tok_str[4096];
static double g_tok_num;

static int is_alpha(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'; }
static int is_digit(char c) { return c >= '0' && c <= '9'; }
static int is_alnum(char c) { return is_alpha(c) || is_digit(c); }
static int is_space(char c) { return c == ' ' || c == '\t' || c == '\r'; }

static void skip_ws(void)
{
    while (g_src[g_pos]) {
        if (is_space(g_src[g_pos])) {
            g_pos++;
        } else if (g_src[g_pos] == '\\' && g_src[g_pos+1] == '\n') {
            g_pos += 2;  /* line continuation */
        } else if (g_src[g_pos] == '#') {
            while (g_src[g_pos] && g_src[g_pos] != '\n') g_pos++;
        } else {
            break;
        }
    }
}

/* Whether the last token could precede a regex (i.e., / is division if
   after a value-producing token, regex otherwise) */
static int g_last_was_value = 0;

static void next_token(void)
{
    skip_ws();
    char c = g_src[g_pos];

    if (!c) { g_tok = T_EOF; return; }

    if (c == '\n') { g_pos++; g_tok = T_NL; g_last_was_value = 0; return; }
    if (c == ';') { g_pos++; g_tok = T_SEMI; g_last_was_value = 0; return; }
    if (c == '{') { g_pos++; g_tok = T_LBRACE; g_last_was_value = 0; return; }
    if (c == '}') { g_pos++; g_tok = T_RBRACE; g_last_was_value = 0; return; }
    if (c == '(') { g_pos++; g_tok = T_LPAREN; g_last_was_value = 0; return; }
    if (c == ')') { g_pos++; g_tok = T_RPAREN; g_last_was_value = 1; return; }
    if (c == '[') { g_pos++; g_tok = T_LBRACKET; g_last_was_value = 0; return; }
    if (c == ']') { g_pos++; g_tok = T_RBRACKET; g_last_was_value = 1; return; }
    if (c == ',') { g_pos++; g_tok = T_COMMA; g_last_was_value = 0; return; }
    if (c == '$') { g_pos++; g_tok = T_DOLLAR; g_last_was_value = 0; return; }
    if (c == '?') { g_pos++; g_tok = T_QUESTION; g_last_was_value = 0; return; }
    if (c == ':') { g_pos++; g_tok = T_COLON; g_last_was_value = 0; return; }
    if (c == '|') {
        if (g_src[g_pos+1] == '|') { g_pos += 2; g_tok = T_OR; }
        else { g_pos++; g_tok = T_PIPE; }
        g_last_was_value = 0; return;
    }
    if (c == '^') { g_pos++; g_tok = T_CARET; g_last_was_value = 0; return; }
    if (c == '%') {
        if (g_src[g_pos+1] == '=') { g_pos += 2; g_tok = T_MOD_ASSIGN; }
        else { g_pos++; g_tok = T_PERCENT; }
        g_last_was_value = 0; return;
    }
    if (c == '~') { g_pos++; g_tok = T_MATCH; g_last_was_value = 0; return; }
    if (c == '+') {
        if (g_src[g_pos+1] == '+') { g_pos += 2; g_tok = T_INCR; g_last_was_value = 1; return; }
        if (g_src[g_pos+1] == '=') { g_pos += 2; g_tok = T_ADD_ASSIGN; g_last_was_value = 0; return; }
        g_pos++; g_tok = T_PLUS; g_last_was_value = 0; return;
    }
    if (c == '-') {
        if (g_src[g_pos+1] == '-') { g_pos += 2; g_tok = T_DECR; g_last_was_value = 1; return; }
        if (g_src[g_pos+1] == '=') { g_pos += 2; g_tok = T_SUB_ASSIGN; g_last_was_value = 0; return; }
        g_pos++; g_tok = T_MINUS; g_last_was_value = 0; return;
    }
    if (c == '*') {
        if (g_src[g_pos+1] == '=') { g_pos += 2; g_tok = T_MUL_ASSIGN; g_last_was_value = 0; return; }
        g_pos++; g_tok = T_STAR; g_last_was_value = 0; return;
    }
    if (c == '/') {
        if (!g_last_was_value) {
            /* It's a regex */
            g_pos++;
            int len = 0;
            while (g_src[g_pos] && g_src[g_pos] != '/' && g_src[g_pos] != '\n') {
                if (g_src[g_pos] == '\\' && g_src[g_pos+1]) {
                    g_tok_str[len++] = g_src[g_pos++];
                    g_tok_str[len++] = g_src[g_pos++];
                } else {
                    g_tok_str[len++] = g_src[g_pos++];
                }
            }
            if (g_src[g_pos] == '/') g_pos++;
            g_tok_str[len] = '\0';
            g_tok = T_REGEX;
            g_last_was_value = 1;
            return;
        }
        if (g_src[g_pos+1] == '=') { g_pos += 2; g_tok = T_DIV_ASSIGN; g_last_was_value = 0; return; }
        g_pos++; g_tok = T_SLASH; g_last_was_value = 0; return;
    }
    if (c == '<') {
        if (g_src[g_pos+1] == '=') { g_pos += 2; g_tok = T_LE; }
        else { g_pos++; g_tok = T_LT; }
        g_last_was_value = 0; return;
    }
    if (c == '>') {
        if (g_src[g_pos+1] == '=') { g_pos += 2; g_tok = T_GE; }
        else if (g_src[g_pos+1] == '>') { g_pos += 2; g_tok = T_APPEND; }
        else { g_pos++; g_tok = T_GT; }
        g_last_was_value = 0; return;
    }
    if (c == '=') {
        if (g_src[g_pos+1] == '=') { g_pos += 2; g_tok = T_EQ; g_last_was_value = 0; }
        else { g_pos++; g_tok = T_ASSIGN; g_last_was_value = 0; }
        return;
    }
    if (c == '!') {
        if (g_src[g_pos+1] == '=') { g_pos += 2; g_tok = T_NE; g_last_was_value = 0; return; }
        if (g_src[g_pos+1] == '~') { g_pos += 2; g_tok = T_NOTMATCH; g_last_was_value = 0; return; }
        g_pos++; g_tok = T_NOT; g_last_was_value = 0; return;
    }
    if (c == '&') {
        if (g_src[g_pos+1] == '&') { g_pos += 2; g_tok = T_AND; g_last_was_value = 0; return; }
        /* stray & — treat as error or literal */
        g_pos++; g_tok = T_EOF; return;
    }

    /* Number */
    if (is_digit(c) || (c == '.' && is_digit(g_src[g_pos+1]))) {
        int start = g_pos;
        if (c == '0' && (g_src[g_pos+1] == 'x' || g_src[g_pos+1] == 'X')) {
            g_pos += 2;
            while (is_digit(g_src[g_pos]) ||
                   (g_src[g_pos] >= 'a' && g_src[g_pos] <= 'f') ||
                   (g_src[g_pos] >= 'A' && g_src[g_pos] <= 'F'))
                g_pos++;
        } else {
            while (is_digit(g_src[g_pos])) g_pos++;
            if (g_src[g_pos] == '.') {
                g_pos++;
                while (is_digit(g_src[g_pos])) g_pos++;
            }
            if (g_src[g_pos] == 'e' || g_src[g_pos] == 'E') {
                g_pos++;
                if (g_src[g_pos] == '+' || g_src[g_pos] == '-') g_pos++;
                while (is_digit(g_src[g_pos])) g_pos++;
            }
        }
        int len = g_pos - start;
        memcpy(g_tok_str, g_src + start, len);
        g_tok_str[len] = '\0';
        g_tok_num = (double)strtol(g_tok_str, NULL, 0);
        /* Handle decimal */
        char *dot = strchr(g_tok_str, '.');
        if (dot) {
            char *end;
            long ip = strtol(g_tok_str, &end, 10);
            double d = (double)ip;
            if (*end == '.') {
                end++;
                double frac = 0.0, div = 10.0;
                while (*end >= '0' && *end <= '9') {
                    frac += (*end - '0') / div;
                    div *= 10.0;
                    end++;
                }
                g_tok_num = d + ((d < 0) ? -frac : frac);
            }
        }
        g_tok = T_NUMBER;
        g_last_was_value = 1;
        return;
    }

    /* String literal */
    if (c == '"') {
        g_pos++;
        int len = 0;
        while (g_src[g_pos] && g_src[g_pos] != '"') {
            if (g_src[g_pos] == '\\') {
                g_pos++;
                switch (g_src[g_pos]) {
                case 'n': g_tok_str[len++] = '\n'; break;
                case 't': g_tok_str[len++] = '\t'; break;
                case 'r': g_tok_str[len++] = '\r'; break;
                case '\\': g_tok_str[len++] = '\\'; break;
                case '"': g_tok_str[len++] = '"'; break;
                case '/': g_tok_str[len++] = '/'; break;
                case 'a': g_tok_str[len++] = '\a'; break;
                case 'b': g_tok_str[len++] = '\b'; break;
                default: g_tok_str[len++] = '\\'; g_tok_str[len++] = g_src[g_pos]; break;
                }
                g_pos++;
            } else {
                g_tok_str[len++] = g_src[g_pos++];
            }
        }
        if (g_src[g_pos] == '"') g_pos++;
        g_tok_str[len] = '\0';
        g_tok = T_STRING;
        g_last_was_value = 1;
        return;
    }

    /* Identifier / keyword */
    if (is_alpha(c)) {
        int len = 0;
        while (is_alnum(g_src[g_pos]))
            g_tok_str[len++] = g_src[g_pos++];
        g_tok_str[len] = '\0';

        /* Check keywords */
        if (strcmp(g_tok_str, "BEGIN") == 0) { g_tok = T_BEGIN; g_last_was_value = 0; return; }
        if (strcmp(g_tok_str, "END") == 0) { g_tok = T_END; g_last_was_value = 0; return; }
        if (strcmp(g_tok_str, "if") == 0) { g_tok = T_IF; g_last_was_value = 0; return; }
        if (strcmp(g_tok_str, "else") == 0) { g_tok = T_ELSE; g_last_was_value = 0; return; }
        if (strcmp(g_tok_str, "while") == 0) { g_tok = T_WHILE; g_last_was_value = 0; return; }
        if (strcmp(g_tok_str, "for") == 0) { g_tok = T_FOR; g_last_was_value = 0; return; }
        if (strcmp(g_tok_str, "do") == 0) { g_tok = T_DO; g_last_was_value = 0; return; }
        if (strcmp(g_tok_str, "break") == 0) { g_tok = T_BREAK; g_last_was_value = 0; return; }
        if (strcmp(g_tok_str, "continue") == 0) { g_tok = T_CONTINUE; g_last_was_value = 0; return; }
        if (strcmp(g_tok_str, "next") == 0) { g_tok = T_NEXT; g_last_was_value = 0; return; }
        if (strcmp(g_tok_str, "exit") == 0) { g_tok = T_EXIT; g_last_was_value = 0; return; }
        if (strcmp(g_tok_str, "return") == 0) { g_tok = T_RETURN; g_last_was_value = 0; return; }
        if (strcmp(g_tok_str, "delete") == 0) { g_tok = T_DELETE; g_last_was_value = 0; return; }
        if (strcmp(g_tok_str, "in") == 0) { g_tok = T_IN; g_last_was_value = 0; return; }
        if (strcmp(g_tok_str, "getline") == 0) { g_tok = T_GETLINE; g_last_was_value = 1; return; }
        if (strcmp(g_tok_str, "print") == 0) { g_tok = T_PRINT; g_last_was_value = 0; return; }
        if (strcmp(g_tok_str, "printf") == 0) { g_tok = T_PRINTF; g_last_was_value = 0; return; }
        if (strcmp(g_tok_str, "function") == 0) { g_tok = T_FUNCTION; g_last_was_value = 0; return; }

        g_tok = T_NAME;
        g_last_was_value = 1;
        return;
    }

    /* Unknown character */
    fprintf(stderr, "awk: unexpected character '%c'\n", c);
    g_pos++;
    next_token();
}

static void skip_newlines(void)
{
    while (g_tok == T_NL || g_tok == T_SEMI)
        next_token();
}

static void expect(enum tok_type t)
{
    if (g_tok != t) {
        fprintf(stderr, "awk: syntax error: expected token %d, got %d\n", t, g_tok);
        exit(2);
    }
    next_token();
}

/* =========================================================================
 * Parser — recursive descent
 * ========================================================================= */

static node *parse_expr(void);
static node *parse_assign(void);
static node *parse_stmt(void);
static node *parse_block(void);

static node *parse_primary(void)
{
    node *n;
    if (g_tok == T_NUMBER) {
        n = alloc_node(N_NUMBER);
        n->num = g_tok_num;
        next_token();
        return n;
    }
    if (g_tok == T_STRING) {
        n = alloc_node(N_STRING);
        n->str = strdup(g_tok_str);
        next_token();
        return n;
    }
    if (g_tok == T_REGEX) {
        n = alloc_node(N_REGEX);
        n->str = strdup(g_tok_str);
        next_token();
        return n;
    }
    if (g_tok == T_DOLLAR) {
        next_token();
        n = alloc_node(N_FIELDREF);
        n->left = parse_primary();
        return n;
    }
    if (g_tok == T_LPAREN) {
        next_token();
        n = parse_expr();
        if (g_tok == T_RPAREN) next_token();
        return n;
    }
    if (g_tok == T_NOT) {
        next_token();
        n = alloc_node(N_NOT);
        n->left = parse_primary();
        return n;
    }
    if (g_tok == T_MINUS) {
        next_token();
        n = alloc_node(N_UNARY_MINUS);
        n->left = parse_primary();
        return n;
    }
    if (g_tok == T_INCR) {
        next_token();
        n = alloc_node(N_INCR);
        n->left = parse_primary();
        return n;
    }
    if (g_tok == T_DECR) {
        next_token();
        n = alloc_node(N_DECR);
        n->left = parse_primary();
        return n;
    }
    if (g_tok == T_GETLINE) {
        next_token();
        n = alloc_node(N_GETLINE);
        /* Optional variable */
        if (g_tok == T_NAME) {
            n->str = strdup(g_tok_str);
            next_token();
        }
        return n;
    }
    if (g_tok == T_NAME) {
        char name[256];
        strcpy(name, g_tok_str);
        next_token();

        /* Check for function call */
        if (g_tok == T_LPAREN) {
            next_token();
            n = alloc_node(N_CALL);
            n->str = strdup(name);
            /* Parse arguments */
            int cap = 8;
            n->args = malloc(cap * sizeof(node *));
            n->nargs = 0;
            if (g_tok != T_RPAREN) {
                n->args[n->nargs++] = parse_expr();
                while (g_tok == T_COMMA) {
                    next_token();
                    if (n->nargs >= cap) {
                        cap *= 2;
                        n->args = realloc(n->args, cap * sizeof(node *));
                    }
                    n->args[n->nargs++] = parse_expr();
                }
            }
            if (g_tok == T_RPAREN) next_token();
            return n;
        }

        /* Check for array subscript */
        if (g_tok == T_LBRACKET) {
            next_token();
            n = alloc_node(N_ARRAY_REF);
            n->str = strdup(name);
            n->left = parse_expr();
            /* Handle multi-dimensional: a[i,j] becomes a[i SUBSEP j] */
            while (g_tok == T_COMMA) {
                next_token();
                node *concat = alloc_node(N_CONCAT);
                node *subsep_str = alloc_node(N_STRING);
                subsep_str->str = strdup("\034"); /* SUBSEP */
                node *c1 = alloc_node(N_CONCAT);
                c1->left = n->left;
                c1->right = subsep_str;
                concat->left = c1;
                concat->right = parse_expr();
                n->left = concat;
            }
            if (g_tok == T_RBRACKET) next_token();
            return n;
        }

        n = alloc_node(N_VAR);
        n->str = strdup(name);
        return n;
    }

    /* Fallback */
    n = alloc_node(N_NUMBER);
    n->num = 0;
    return n;
}

static node *parse_postfix(void)
{
    node *n = parse_primary();
    if (g_tok == T_INCR) {
        next_token();
        node *p = alloc_node(N_POST_INCR);
        p->left = n;
        return p;
    }
    if (g_tok == T_DECR) {
        next_token();
        node *p = alloc_node(N_POST_DECR);
        p->left = n;
        return p;
    }
    return n;
}

static node *parse_power(void)
{
    node *left = parse_postfix();
    if (g_tok == T_CARET) {
        next_token();
        node *n = alloc_node(N_BINOP);
        n->op = OP_POW;
        n->left = left;
        n->right = parse_power(); /* right-associative */
        return n;
    }
    return left;
}

static node *parse_mul(void)
{
    node *left = parse_power();
    while (g_tok == T_STAR || g_tok == T_SLASH || g_tok == T_PERCENT) {
        int op = (g_tok == T_STAR) ? OP_MUL : (g_tok == T_SLASH) ? OP_DIV : OP_MOD;
        next_token();
        node *n = alloc_node(N_BINOP);
        n->op = op;
        n->left = left;
        n->right = parse_power();
        left = n;
    }
    return left;
}

static node *parse_add(void)
{
    node *left = parse_mul();
    while (g_tok == T_PLUS || g_tok == T_MINUS) {
        int op = (g_tok == T_PLUS) ? OP_ADD : OP_SUB;
        next_token();
        node *n = alloc_node(N_BINOP);
        n->op = op;
        n->left = left;
        n->right = parse_mul();
        left = n;
    }
    return left;
}

/* String concatenation: two values next to each other without an operator */
static node *parse_concat(void)
{
    node *left = parse_add();
    /* Concatenation: if next token starts an expression and is not
       an operator, it's concatenation */
    while (g_tok == T_DOLLAR || g_tok == T_NAME || g_tok == T_NUMBER ||
           g_tok == T_STRING || g_tok == T_LPAREN || g_tok == T_NOT ||
           g_tok == T_INCR || g_tok == T_DECR) {
        /* But not if we're at a statement boundary */
        node *n = alloc_node(N_CONCAT);
        n->left = left;
        n->right = parse_add();
        left = n;
    }
    return left;
}

static node *parse_comparison(void)
{
    node *left = parse_concat();
    if (g_tok == T_LT || g_tok == T_GT || g_tok == T_LE || g_tok == T_GE ||
        g_tok == T_EQ || g_tok == T_NE) {
        int op;
        switch (g_tok) {
        case T_LT: op = OP_LT; break;
        case T_GT: op = OP_GT; break;
        case T_LE: op = OP_LE; break;
        case T_GE: op = OP_GE; break;
        case T_EQ: op = OP_EQ; break;
        case T_NE: op = OP_NE; break;
        default: op = OP_EQ; break;
        }
        next_token();
        node *n = alloc_node(N_BINOP);
        n->op = op;
        n->left = left;
        n->right = parse_concat();
        left = n;
    }
    return left;
}

static node *parse_match(void)
{
    node *left = parse_comparison();
    if (g_tok == T_MATCH) {
        next_token();
        node *n = alloc_node(N_MATCH);
        n->left = left;
        n->right = parse_primary();
        return n;
    }
    if (g_tok == T_NOTMATCH) {
        next_token();
        node *n = alloc_node(N_NOTMATCH);
        n->left = left;
        n->right = parse_primary();
        return n;
    }
    /* Check for `in` */
    if (g_tok == T_IN) {
        next_token();
        node *n = alloc_node(N_IN);
        n->left = left;
        n->right = alloc_node(N_VAR);
        if (g_tok == T_NAME) {
            n->right->str = strdup(g_tok_str);
            next_token();
        }
        return n;
    }
    return left;
}

static node *parse_and(void)
{
    node *left = parse_match();
    while (g_tok == T_AND) {
        next_token();
        node *n = alloc_node(N_AND);
        n->left = left;
        n->right = parse_match();
        left = n;
    }
    return left;
}

static node *parse_or(void)
{
    node *left = parse_and();
    while (g_tok == T_OR) {
        next_token();
        node *n = alloc_node(N_OR);
        n->left = left;
        n->right = parse_and();
        left = n;
    }
    return left;
}

static node *parse_ternary(void)
{
    node *cond = parse_or();
    if (g_tok == T_QUESTION) {
        next_token();
        node *n = alloc_node(N_TERNARY);
        n->left = cond;
        n->right = parse_expr();
        expect(T_COLON);
        n->extra = parse_expr();
        return n;
    }
    return cond;
}

static node *parse_assign(void)
{
    node *left = parse_ternary();
    if (g_tok == T_ASSIGN || g_tok == T_ADD_ASSIGN || g_tok == T_SUB_ASSIGN ||
        g_tok == T_MUL_ASSIGN || g_tok == T_DIV_ASSIGN || g_tok == T_MOD_ASSIGN) {
        enum node_type nt;
        switch (g_tok) {
        case T_ASSIGN: nt = N_ASSIGN; break;
        case T_ADD_ASSIGN: nt = N_ADD_ASSIGN; break;
        case T_SUB_ASSIGN: nt = N_SUB_ASSIGN; break;
        case T_MUL_ASSIGN: nt = N_MUL_ASSIGN; break;
        case T_DIV_ASSIGN: nt = N_DIV_ASSIGN; break;
        case T_MOD_ASSIGN: nt = N_MOD_ASSIGN; break;
        default: nt = N_ASSIGN; break;
        }
        next_token();
        node *n = alloc_node(nt);
        n->left = left;
        n->right = parse_assign(); /* right-associative */
        return n;
    }
    return left;
}

static node *parse_expr(void)
{
    return parse_assign();
}

/* Parse a print argument list (expressions separated by commas) */
static void parse_print_args(node *n)
{
    int cap = 8;
    n->args = malloc(cap * sizeof(node *));
    n->nargs = 0;

    /* Check for empty arg list */
    if (g_tok == T_SEMI || g_tok == T_NL || g_tok == T_RBRACE ||
        g_tok == T_PIPE || g_tok == T_GT || g_tok == T_APPEND ||
        g_tok == T_EOF)
        return;

    n->args[n->nargs++] = parse_expr();
    while (g_tok == T_COMMA) {
        next_token();
        if (n->nargs >= cap) {
            cap *= 2;
            n->args = realloc(n->args, cap * sizeof(node *));
        }
        n->args[n->nargs++] = parse_expr();
    }
}

static node *parse_simple_stmt(void)
{
    node *n;

    if (g_tok == T_PRINT) {
        next_token();
        n = alloc_node(N_PRINT);
        parse_print_args(n);
        /* Handle > file, >> file, | cmd redirection */
        if (g_tok == T_GT) {
            n->op = '>';
            next_token();
            n->extra = parse_expr();
        } else if (g_tok == T_APPEND) {
            n->op = 'A';   /* >> (append) */
            next_token();
            n->extra = parse_expr();
        } else if (g_tok == T_PIPE) {
            n->op = '|';
            next_token();
            n->extra = parse_expr();
        }
        return n;
    }
    if (g_tok == T_PRINTF) {
        next_token();
        n = alloc_node(N_PRINTF);
        parse_print_args(n);
        /* Handle > file, >> file, | cmd redirection */
        if (g_tok == T_GT) {
            n->op = '>';
            next_token();
            n->extra = parse_expr();
        } else if (g_tok == T_APPEND) {
            n->op = 'A';
            next_token();
            n->extra = parse_expr();
        } else if (g_tok == T_PIPE) {
            n->op = '|';
            next_token();
            n->extra = parse_expr();
        }
        return n;
    }
    if (g_tok == T_DELETE) {
        next_token();
        n = alloc_node(N_DELETE);
        if (g_tok == T_NAME) {
            n->str = strdup(g_tok_str);
            next_token();
            if (g_tok == T_LBRACKET) {
                next_token();
                n->left = parse_expr();
                if (g_tok == T_RBRACKET) next_token();
            }
        }
        return n;
    }
    if (g_tok == T_NEXT) { next_token(); return alloc_node(N_NEXT); }
    if (g_tok == T_BREAK) { next_token(); return alloc_node(N_BREAK); }
    if (g_tok == T_CONTINUE) { next_token(); return alloc_node(N_CONTINUE); }
    if (g_tok == T_EXIT) {
        next_token();
        n = alloc_node(N_EXIT);
        if (g_tok != T_SEMI && g_tok != T_NL && g_tok != T_RBRACE && g_tok != T_EOF)
            n->left = parse_expr();
        return n;
    }

    /* Expression statement */
    return parse_expr();
}

static node *parse_stmt(void)
{
    skip_newlines();

    if (g_tok == T_LBRACE)
        return parse_block();

    if (g_tok == T_IF) {
        next_token();
        node *n = alloc_node(N_IF);
        expect(T_LPAREN);
        n->left = parse_expr();
        expect(T_RPAREN);
        skip_newlines();
        n->right = parse_stmt();
        skip_newlines();
        if (g_tok == T_ELSE) {
            next_token();
            skip_newlines();
            n->extra = parse_stmt();
        }
        return n;
    }
    if (g_tok == T_WHILE) {
        next_token();
        node *n = alloc_node(N_WHILE);
        expect(T_LPAREN);
        n->left = parse_expr();
        expect(T_RPAREN);
        skip_newlines();
        n->right = parse_stmt();
        return n;
    }
    if (g_tok == T_DO) {
        next_token();
        skip_newlines();
        node *n = alloc_node(N_DO_WHILE);
        n->right = parse_stmt();
        skip_newlines();
        if (g_tok == T_WHILE) next_token();
        expect(T_LPAREN);
        n->left = parse_expr();
        expect(T_RPAREN);
        return n;
    }
    if (g_tok == T_FOR) {
        next_token();
        expect(T_LPAREN);
        /* Check for for-in: for (var in array) */
        /* Peek ahead: if NAME IN NAME, it's for-in */
        int saved_pos = g_pos;
        enum tok_type saved_tok = g_tok;
        char saved_str[256];
        strcpy(saved_str, g_tok_str);
        double saved_num = g_tok_num;
        int saved_val = g_last_was_value;

        if (g_tok == T_NAME || g_tok == T_LPAREN) {
            /* Try to parse for-in */
            char varname[256] = "";
            int is_for_in = 0;

            if (g_tok == T_LPAREN) {
                /* (var in array) */
                next_token();
                if (g_tok == T_NAME) {
                    strcpy(varname, g_tok_str);
                    next_token();
                    if (g_tok == T_IN) is_for_in = 1;
                }
            } else {
                strcpy(varname, g_tok_str);
                next_token();
                if (g_tok == T_IN) is_for_in = 1;
            }

            if (is_for_in) {
                /* for (var in array) */
                next_token(); /* skip IN */
                node *n = alloc_node(N_FOR_IN);
                n->str = strdup(varname);
                if (g_tok == T_NAME) {
                    n->left = alloc_node(N_VAR);
                    n->left->str = strdup(g_tok_str);
                    next_token();
                }
                if (g_tok == T_RPAREN) next_token();
                skip_newlines();
                n->right = parse_stmt();
                return n;
            }

            /* Not for-in, restore state */
            g_pos = saved_pos;
            g_tok = saved_tok;
            strcpy(g_tok_str, saved_str);
            g_tok_num = saved_num;
            g_last_was_value = saved_val;
        }

        /* C-style for */
        node *n = alloc_node(N_FOR);
        if (g_tok != T_SEMI) n->extra2 = parse_simple_stmt();
        expect(T_SEMI);
        if (g_tok != T_SEMI) n->left = parse_expr();
        expect(T_SEMI);
        if (g_tok != T_RPAREN) n->extra = parse_simple_stmt();
        expect(T_RPAREN);
        skip_newlines();
        n->right = parse_stmt();
        return n;
    }

    node *n = parse_simple_stmt();
    /* consume optional separator */
    if (g_tok == T_SEMI || g_tok == T_NL)
        next_token();
    return n;
}

static node *parse_block(void)
{
    expect(T_LBRACE);
    node *n = alloc_node(N_BLOCK);
    node *tail = NULL;
    skip_newlines();
    while (g_tok != T_RBRACE && g_tok != T_EOF) {
        node *s = parse_stmt();
        if (!tail) { n->left = s; tail = s; }
        else { tail->next = s; tail = s; }
        skip_newlines();
    }
    if (g_tok == T_RBRACE) next_token();
    return n;
}

static node *parse_pattern(void)
{
    if (g_tok == T_REGEX) {
        node *n = alloc_node(N_REGEX);
        n->str = strdup(g_tok_str);
        next_token();
        return n;
    }
    return parse_expr();
}

static node *parse_program(void)
{
    node *prog = alloc_node(N_PROGRAM);
    node *tail = NULL;

    skip_newlines();
    while (g_tok != T_EOF) {
        node *rule = alloc_node(N_RULE);

        if (g_tok == T_BEGIN) {
            next_token();
            skip_newlines();
            rule->str = strdup("BEGIN");
            rule->right = parse_block();
        } else if (g_tok == T_END) {
            next_token();
            skip_newlines();
            rule->str = strdup("END");
            rule->right = parse_block();
        } else if (g_tok == T_FUNCTION) {
            /* Skip user-defined functions for now — simplified */
            next_token();
            if (g_tok == T_NAME) next_token();
            if (g_tok == T_LPAREN) {
                while (g_tok != T_RPAREN && g_tok != T_EOF) next_token();
                if (g_tok == T_RPAREN) next_token();
            }
            skip_newlines();
            if (g_tok == T_LBRACE)
                rule->right = parse_block();
            rule->str = strdup("FUNC");
        } else if (g_tok == T_LBRACE) {
            /* No pattern — match all */
            rule->left = NULL;
            rule->right = parse_block();
        } else {
            /* Pattern */
            rule->left = parse_pattern();
            skip_newlines();
            if (g_tok == T_COMMA) {
                /* Range pattern: pat1, pat2 */
                next_token();
                skip_newlines();
                rule->extra = parse_pattern();
            }
            skip_newlines();
            if (g_tok == T_LBRACE) {
                rule->right = parse_block();
            } else {
                /* Pattern only — default action is { print } */
                node *p = alloc_node(N_PRINT);
                p->args = NULL;
                p->nargs = 0;
                rule->right = p;
            }
        }

        if (!tail) { prog->left = rule; tail = rule; }
        else { tail->next = rule; tail = rule; }
        skip_newlines();
    }
    return prog;
}

/* =========================================================================
 * Evaluator
 * ========================================================================= */

#define EVAL_NORMAL     0
#define EVAL_BREAK      1
#define EVAL_CONTINUE   2
#define EVAL_NEXT       3
#define EVAL_EXIT       4
#define EVAL_RETURN     5

static int g_exit_code = 0;
static int g_eval_state = EVAL_NORMAL;

static awk_val eval(node *n);

static void set_lvalue(node *n, awk_val val)
{
    if (n->type == N_VAR) {
        var_set(n->str, val);
    } else if (n->type == N_FIELDREF) {
        awk_val idx_v = eval(n->left);
        int idx = (int)val_to_num(&idx_v);
        val_free(&idx_v);
        char buf[256];
        const char *s = val_to_str(&val, buf, sizeof(buf));
        if (idx == 0) {
            strncpy(g_line, s, sizeof(g_line) - 1);
            g_line[sizeof(g_line) - 1] = '\0';
            split_fields();
        } else if (idx >= 1 && idx <= MAX_FIELDS) {
            /* Extend fields if needed */
            while (g_nfields < idx) {
                g_fields[g_nfields] = "";
                g_nfields++;
            }
            g_fields[idx - 1] = strdup(s);
            rebuild_record();
        }
    } else if (n->type == N_ARRAY_REF) {
        awk_var *v = var_get(n->str);
        awk_array *a = array_ensure(v);
        awk_val key_v = eval(n->left);
        char kbuf[256];
        const char *key = val_to_str(&key_v, kbuf, sizeof(kbuf));
        awk_val *slot = array_get(a, key);
        val_free(slot);
        *slot = val;
        val_free(&key_v);
    }
}

static awk_val get_lvalue(node *n)
{
    if (n->type == N_VAR) {
        awk_var *v = var_get(n->str);
        if (v->val.sval)
            return val_str(v->val.sval);
        return val_num(v->val.nval);
    } else if (n->type == N_FIELDREF) {
        awk_val idx_v = eval(n->left);
        int idx = (int)val_to_num(&idx_v);
        val_free(&idx_v);
        return val_str(get_field(idx));
    } else if (n->type == N_ARRAY_REF) {
        awk_var *v = var_get(n->str);
        awk_array *a = array_ensure(v);
        awk_val key_v = eval(n->left);
        char kbuf[256];
        const char *key = val_to_str(&key_v, kbuf, sizeof(kbuf));
        awk_val *slot = array_get(a, key);
        val_free(&key_v);
        if (slot->sval) return val_str(slot->sval);
        return val_num(slot->nval);
    }
    return val_num(0);
}

/* Simple power function */
static double awk_pow(double base, double exp)
{
    if (exp == 0) return 1.0;
    if (exp < 0) return 1.0 / awk_pow(base, -exp);
    int e = (int)exp;
    double r = 1.0;
    for (int i = 0; i < e; i++) r *= base;
    return r;
}

/* Case conversion */
static char to_lower(char c)
{
    return (c >= 'A' && c <= 'Z') ? c + 32 : c;
}

static char to_upper(char c)
{
    return (c >= 'a' && c <= 'z') ? c - 32 : c;
}

static awk_val eval_call(node *n)
{
    const char *fn = n->str;
    awk_val args[16];
    int nargs = n->nargs;
    if (nargs > 16) nargs = 16;
    for (int i = 0; i < nargs; i++)
        args[i] = eval(n->args[i]);

    awk_val result = val_num(0);

    if (strcmp(fn, "length") == 0) {
        if (nargs == 0)
            result = val_num((double)strlen(g_line));
        else {
            char buf[256];
            const char *s = val_to_str(&args[0], buf, sizeof(buf));
            result = val_num((double)strlen(s));
        }
    } else if (strcmp(fn, "substr") == 0) {
        char buf[256];
        const char *s = val_to_str(&args[0], buf, sizeof(buf));
        int pos = (nargs >= 2) ? (int)val_to_num(&args[1]) : 1;
        int len = (nargs >= 3) ? (int)val_to_num(&args[2]) : (int)strlen(s);
        if (pos < 1) pos = 1;
        pos--; /* 1-based to 0-based */
        int slen = (int)strlen(s);
        if (pos >= slen) { result = val_str(""); }
        else {
            if (pos + len > slen) len = slen - pos;
            char tmp[65536];
            memcpy(tmp, s + pos, len);
            tmp[len] = '\0';
            result = val_str(tmp);
        }
    } else if (strcmp(fn, "index") == 0) {
        char buf1[256], buf2[256];
        const char *s = val_to_str(&args[0], buf1, sizeof(buf1));
        const char *t = val_to_str(&args[1], buf2, sizeof(buf2));
        char *p = strstr(s, t);
        result = val_num(p ? (double)(p - s + 1) : 0.0);
    } else if (strcmp(fn, "split") == 0) {
        /* split(str, array [, fs]) */
        char buf[65536];
        const char *s = val_to_str(&args[0], buf, sizeof(buf));
        char *str_copy = strdup(s);

        /* Get array variable name from the AST node */
        const char *arr_name = "ARGV"; /* default */
        if (n->nargs >= 2 && n->args[1]->type == N_VAR)
            arr_name = n->args[1]->str;
        else if (n->nargs >= 2 && n->args[1]->type == N_ARRAY_REF)
            arr_name = n->args[1]->str;

        awk_var *av = var_get(arr_name);
        if (!av->array) av->array = calloc(1, sizeof(awk_array));
        /* Clear array */
        for (int b = 0; b < 256; b++) {
            awk_array_entry *e = av->array->buckets[b];
            while (e) {
                awk_array_entry *nxt = e->next;
                free(e->key);
                val_free(&e->val);
                free(e);
                e = nxt;
            }
            av->array->buckets[b] = NULL;
        }
        av->array->count = 0;

        const char *sep = (nargs >= 3) ? val_to_str(&args[2], buf, sizeof(buf)) : g_fs;
        int count = 0;
        if (strcmp(sep, " ") == 0) {
            char *p = str_copy;
            while (*p == ' ' || *p == '\t' || *p == '\n') p++;
            while (*p) {
                char *start = p;
                while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
                char save = *p;
                if (*p) *p = '\0';
                count++;
                char key[32];
                snprintf(key, sizeof(key), "%d", count);
                *array_get(av->array, key) = val_str(start);
                if (save) p++;
                while (*p == ' ' || *p == '\t' || *p == '\n') p++;
            }
        } else {
            char *p = str_copy;
            while (*p) {
                char *next = strstr(p, sep);
                if (next) *next = '\0';
                count++;
                char key[32];
                snprintf(key, sizeof(key), "%d", count);
                *array_get(av->array, key) = val_str(p);
                if (!next) break;
                p = next + strlen(sep);
            }
        }
        free(str_copy);
        result = val_num((double)count);
    } else if (strcmp(fn, "sub") == 0 || strcmp(fn, "gsub") == 0) {
        /* sub/gsub(regex, replacement [, target]) */
        int global = (strcmp(fn, "gsub") == 0);
        char rbuf[256];
        const char *pat_str = val_to_str(&args[0], rbuf, sizeof(rbuf));
        char repbuf[256];
        const char *rep = val_to_str(&args[1], repbuf, sizeof(repbuf));

        /* Get target string */
        char *target;
        int target_is_field0 = 1;
        if (nargs >= 3 && n->args[2]->type == N_VAR) {
            awk_var *tv = var_get(n->args[2]->str);
            char tbuf[256];
            target = strdup(val_to_str(&tv->val, tbuf, sizeof(tbuf)));
            target_is_field0 = 0;
        } else {
            target = strdup(g_line);
        }

        struct re_node re[RE_MAX_NODES];
        re_compile(pat_str, re, RE_MAX_NODES);

        char out[65536];
        int oi = 0, si = 0, count = 0;
        int tlen = (int)strlen(target);

        while (si <= tlen) {
            int ms, me;
            if (re_search(re, target + si, &ms, &me) && me > ms) {
                /* Copy before match */
                memcpy(out + oi, target + si, ms);
                oi += ms;
                /* Copy replacement (& = whole match) */
                for (int r = 0; rep[r]; r++) {
                    if (rep[r] == '&') {
                        memcpy(out + oi, target + si + ms, me - ms);
                        oi += me - ms;
                    } else if (rep[r] == '\\' && rep[r+1]) {
                        out[oi++] = rep[++r];
                    } else {
                        out[oi++] = rep[r];
                    }
                }
                si += (me > 0) ? me : 1;
                count++;
                if (!global) {
                    /* Copy rest */
                    strcpy(out + oi, target + si);
                    oi += (int)strlen(target + si);
                    break;
                }
            } else {
                /* Copy rest */
                strcpy(out + oi, target + si);
                oi += (int)strlen(target + si);
                break;
            }
        }
        out[oi] = '\0';

        if (target_is_field0) {
            strncpy(g_line, out, sizeof(g_line) - 1);
            g_line[sizeof(g_line) - 1] = '\0';
            split_fields();
        } else if (nargs >= 3 && n->args[2]->type == N_VAR) {
            var_set_str(n->args[2]->str, out);
        }

        free(target);
        result = val_num((double)count);
    } else if (strcmp(fn, "sprintf") == 0) {
        /* Basic sprintf */
        if (nargs >= 1) {
            char buf[256];
            const char *fmt = val_to_str(&args[0], buf, sizeof(buf));
            char out[65536];
            int oi = 0;
            int ai = 1;
            for (int fi = 0; fmt[fi] && oi < 65000; fi++) {
                if (fmt[fi] == '%' && fmt[fi+1]) {
                    fi++;
                    /* Skip flags/width/precision */
                    while (fmt[fi] == '-' || fmt[fi] == '+' || fmt[fi] == ' ' ||
                           fmt[fi] == '0' || fmt[fi] == '#') fi++;
                    while (fmt[fi] >= '0' && fmt[fi] <= '9') fi++;
                    if (fmt[fi] == '.') { fi++; while (fmt[fi] >= '0' && fmt[fi] <= '9') fi++; }

                    if (fmt[fi] == 'd' || fmt[fi] == 'i') {
                        long v = (ai < nargs) ? (long)val_to_num(&args[ai++]) : 0;
                        oi += snprintf(out + oi, sizeof(out) - oi, "%ld", v);
                    } else if (fmt[fi] == 's') {
                        char ab[256];
                        const char *s = (ai < nargs) ? val_to_str(&args[ai++], ab, sizeof(ab)) : "";
                        oi += snprintf(out + oi, sizeof(out) - oi, "%s", s);
                    } else if (fmt[fi] == 'c') {
                        int ch = (ai < nargs) ? (int)val_to_num(&args[ai++]) : 0;
                        out[oi++] = (char)ch;
                    } else if (fmt[fi] == 'x' || fmt[fi] == 'X') {
                        unsigned long v = (ai < nargs) ? (unsigned long)val_to_num(&args[ai++]) : 0;
                        oi += snprintf(out + oi, sizeof(out) - oi,
                                      fmt[fi] == 'x' ? "%lx" : "%lX", v);
                    } else if (fmt[fi] == 'o') {
                        unsigned long v = (ai < nargs) ? (unsigned long)val_to_num(&args[ai++]) : 0;
                        oi += snprintf(out + oi, sizeof(out) - oi, "%lo", v);
                    } else if (fmt[fi] == 'f' || fmt[fi] == 'g' || fmt[fi] == 'e') {
                        double v = (ai < nargs) ? val_to_num(&args[ai++]) : 0.0;
                        char nb[64];
                        double_to_str(v, nb, sizeof(nb));
                        oi += snprintf(out + oi, sizeof(out) - oi, "%s", nb);
                    } else if (fmt[fi] == '%') {
                        out[oi++] = '%';
                    }
                } else {
                    out[oi++] = fmt[fi];
                }
            }
            out[oi] = '\0';
            result = val_str(out);
        }
    } else if (strcmp(fn, "tolower") == 0) {
        char buf[256];
        const char *s = (nargs >= 1) ? val_to_str(&args[0], buf, sizeof(buf)) : "";
        char *r = strdup(s);
        for (int i = 0; r[i]; i++) r[i] = to_lower(r[i]);
        result = val_str(r);
        free(r);
    } else if (strcmp(fn, "toupper") == 0) {
        char buf[256];
        const char *s = (nargs >= 1) ? val_to_str(&args[0], buf, sizeof(buf)) : "";
        char *r = strdup(s);
        for (int i = 0; r[i]; i++) r[i] = to_upper(r[i]);
        result = val_str(r);
        free(r);
    } else if (strcmp(fn, "int") == 0) {
        double d = (nargs >= 1) ? val_to_num(&args[0]) : 0.0;
        result = val_num((double)(long)d);
    } else if (strcmp(fn, "sin") == 0 || strcmp(fn, "cos") == 0 ||
               strcmp(fn, "log") == 0 || strcmp(fn, "exp") == 0 ||
               strcmp(fn, "sqrt") == 0) {
        /* Stubs for math functions — just return 0 */
        result = val_num(0.0);
    } else if (strcmp(fn, "rand") == 0) {
        /* Simple LCG */
        static unsigned long rseed = 12345;
        rseed = rseed * 1103515245 + 12345;
        result = val_num((double)(rseed & 0x7fffffff) / 2147483647.0);
    } else if (strcmp(fn, "srand") == 0) {
        /* Accept but ignore */
        result = val_num(0);
    } else if (strcmp(fn, "system") == 0) {
        /* Can't really do system() in freestanding, stub */
        result = val_num(0);
    } else if (strcmp(fn, "match") == 0) {
        char buf1[256], buf2[256];
        const char *s = val_to_str(&args[0], buf1, sizeof(buf1));
        const char *pat = val_to_str(&args[1], buf2, sizeof(buf2));
        struct re_node re[RE_MAX_NODES];
        re_compile(pat, re, RE_MAX_NODES);
        int ms, me;
        if (re_search(re, s, &ms, &me)) {
            var_set_num("RSTART", (double)(ms + 1));
            var_set_num("RLENGTH", (double)(me - ms));
            result = val_num((double)(ms + 1));
        } else {
            var_set_num("RSTART", 0);
            var_set_num("RLENGTH", -1);
            result = val_num(0);
        }
    } else {
        fprintf(stderr, "awk: unknown function '%s'\n", fn);
    }

    for (int i = 0; i < nargs; i++)
        val_free(&args[i]);

    return result;
}

static void do_print(node *n, FILE *out)
{
    awk_var *ofs_var = var_lookup("OFS");
    awk_var *ors_var = var_lookup("ORS");
    const char *ofs = (ofs_var && ofs_var->val.sval) ? ofs_var->val.sval : " ";
    const char *ors = (ors_var && ors_var->val.sval) ? ors_var->val.sval : "\n";

    if (n->nargs == 0) {
        fputs(g_line, out);
    } else {
        for (int i = 0; i < n->nargs; i++) {
            if (i > 0) fputs(ofs, out);
            awk_val v = eval(n->args[i]);
            char buf[256];
            fputs(val_to_str(&v, buf, sizeof(buf)), out);
            val_free(&v);
        }
    }
    fputs(ors, out);
}

static void do_printf(node *n, FILE *out)
{
    if (n->nargs < 1) return;
    awk_val fmt_v = eval(n->args[0]);
    char fmtbuf[256];
    const char *fmt = val_to_str(&fmt_v, fmtbuf, sizeof(fmtbuf));
    int ai = 1;

    for (int fi = 0; fmt[fi]; fi++) {
        if (fmt[fi] == '\\') {
            fi++;
            switch (fmt[fi]) {
            case 'n': fputc('\n', out); break;
            case 't': fputc('\t', out); break;
            case 'r': fputc('\r', out); break;
            case '\\': fputc('\\', out); break;
            case '"': fputc('"', out); break;
            default: fputc('\\', out); fputc(fmt[fi], out); break;
            }
            continue;
        }
        if (fmt[fi] != '%') { fputc(fmt[fi], out); continue; }
        fi++;
        if (fmt[fi] == '%') { fputc('%', out); continue; }

        /* Collect format spec */
        char spec[64];
        int si = 0;
        spec[si++] = '%';
        while (fmt[fi] == '-' || fmt[fi] == '+' || fmt[fi] == ' ' ||
               fmt[fi] == '0' || fmt[fi] == '#') spec[si++] = fmt[fi++];
        if (fmt[fi] == '*') {
            awk_val wv = (ai < n->nargs) ? eval(n->args[ai++]) : val_num(0);
            int w = (int)val_to_num(&wv);
            val_free(&wv);
            si += snprintf(spec + si, sizeof(spec) - si, "%d", w);
            fi++;
        } else {
            while (fmt[fi] >= '0' && fmt[fi] <= '9') spec[si++] = fmt[fi++];
        }
        if (fmt[fi] == '.') {
            spec[si++] = fmt[fi++];
            if (fmt[fi] == '*') {
                awk_val pv = (ai < n->nargs) ? eval(n->args[ai++]) : val_num(0);
                int p = (int)val_to_num(&pv);
                val_free(&pv);
                si += snprintf(spec + si, sizeof(spec) - si, "%d", p);
                fi++;
            } else {
                while (fmt[fi] >= '0' && fmt[fi] <= '9') spec[si++] = fmt[fi++];
            }
        }
        spec[si++] = fmt[fi];
        spec[si] = '\0';

        awk_val av = (ai < n->nargs) ? eval(n->args[ai++]) : val_str("");

        switch (fmt[fi]) {
        case 'd': case 'i': {
            long v = (long)val_to_num(&av);
            /* Replace trailing d/i with ld */
            spec[si-1] = 'l';
            spec[si] = 'd';
            spec[si+1] = '\0';
            fprintf(out, spec, v);
            break;
        }
        case 'o': case 'x': case 'X': case 'u': {
            unsigned long v = (unsigned long)val_to_num(&av);
            spec[si-1] = 'l';
            spec[si] = fmt[fi];
            spec[si+1] = '\0';
            fprintf(out, spec, v);
            break;
        }
        case 'c': {
            char buf[256];
            const char *s = val_to_str(&av, buf, sizeof(buf));
            fputc(s[0], out);
            break;
        }
        case 's': {
            char buf[65536];
            const char *s = val_to_str(&av, buf, sizeof(buf));
            fprintf(out, spec, s);
            break;
        }
        case 'f': case 'g': case 'e': {
            double d = val_to_num(&av);
            char nb[64];
            double_to_str(d, nb, sizeof(nb));
            fputs(nb, out);
            break;
        }
        default:
            fputc(fmt[fi], out);
            break;
        }
        val_free(&av);
    }
    val_free(&fmt_v);
}

static awk_val eval(node *n)
{
    if (!n) return val_num(0);

    switch (n->type) {
    case N_NUMBER:
        return val_num(n->num);

    case N_STRING:
        return val_str(n->str);

    case N_REGEX: {
        /* Match against $0 */
        struct re_node re[RE_MAX_NODES];
        re_compile(n->str, re, RE_MAX_NODES);
        return val_num(re_search(re, g_line, NULL, NULL) ? 1.0 : 0.0);
    }

    case N_VAR:
        return get_lvalue(n);

    case N_FIELDREF:
        return get_lvalue(n);

    case N_ARRAY_REF:
        return get_lvalue(n);

    case N_ASSIGN: {
        awk_val v = eval(n->right);
        set_lvalue(n->left, v);
        if (v.sval) return val_str(v.sval);
        return val_num(v.nval);
    }

    case N_ADD_ASSIGN: case N_SUB_ASSIGN: case N_MUL_ASSIGN:
    case N_DIV_ASSIGN: case N_MOD_ASSIGN: {
        awk_val lv = get_lvalue(n->left);
        awk_val rv = eval(n->right);
        double l = val_to_num(&lv);
        double r = val_to_num(&rv);
        double res;
        switch (n->type) {
        case N_ADD_ASSIGN: res = l + r; break;
        case N_SUB_ASSIGN: res = l - r; break;
        case N_MUL_ASSIGN: res = l * r; break;
        case N_DIV_ASSIGN: res = (r != 0) ? l / r : 0; break;
        case N_MOD_ASSIGN: res = (r != 0) ? (double)((long)l % (long)r) : 0; break;
        default: res = 0; break;
        }
        val_free(&lv);
        val_free(&rv);
        awk_val result = val_num(res);
        set_lvalue(n->left, result);
        return val_num(res);
    }

    case N_BINOP: {
        awk_val lv = eval(n->left);
        awk_val rv = eval(n->right);
        double res;

        if (n->op == OP_LT || n->op == OP_GT || n->op == OP_LE ||
            n->op == OP_GE || n->op == OP_EQ || n->op == OP_NE) {
            /* String comparison if both are strings, numeric otherwise */
            int use_string = (lv.type == VAL_STRING && rv.type == VAL_STRING);
            if (use_string) {
                char lb[256], rb2[256];
                const char *ls = val_to_str(&lv, lb, sizeof(lb));
                const char *rs = val_to_str(&rv, rb2, sizeof(rb2));
                int cmp = strcmp(ls, rs);
                switch (n->op) {
                case OP_LT: res = cmp < 0; break;
                case OP_GT: res = cmp > 0; break;
                case OP_LE: res = cmp <= 0; break;
                case OP_GE: res = cmp >= 0; break;
                case OP_EQ: res = cmp == 0; break;
                case OP_NE: res = cmp != 0; break;
                default: res = 0; break;
                }
            } else {
                double l = val_to_num(&lv);
                double r = val_to_num(&rv);
                switch (n->op) {
                case OP_LT: res = l < r; break;
                case OP_GT: res = l > r; break;
                case OP_LE: res = l <= r; break;
                case OP_GE: res = l >= r; break;
                case OP_EQ: res = l == r; break;
                case OP_NE: res = l != r; break;
                default: res = 0; break;
                }
            }
        } else {
            double l = val_to_num(&lv);
            double r = val_to_num(&rv);
            switch (n->op) {
            case OP_ADD: res = l + r; break;
            case OP_SUB: res = l - r; break;
            case OP_MUL: res = l * r; break;
            case OP_DIV: res = (r != 0) ? l / r : 0; break;
            case OP_MOD: res = (r != 0) ? (double)((long)l % (long)r) : 0; break;
            case OP_POW: res = awk_pow(l, r); break;
            default: res = 0; break;
            }
        }
        val_free(&lv);
        val_free(&rv);
        return val_num(res);
    }

    case N_UNARY_MINUS: {
        awk_val v = eval(n->left);
        double d = -val_to_num(&v);
        val_free(&v);
        return val_num(d);
    }

    case N_NOT: {
        awk_val v = eval(n->left);
        int t = val_is_true(&v);
        val_free(&v);
        return val_num(t ? 0.0 : 1.0);
    }

    case N_AND: {
        awk_val lv = eval(n->left);
        if (!val_is_true(&lv)) { val_free(&lv); return val_num(0); }
        val_free(&lv);
        awk_val rv = eval(n->right);
        int t = val_is_true(&rv);
        val_free(&rv);
        return val_num(t ? 1.0 : 0.0);
    }

    case N_OR: {
        awk_val lv = eval(n->left);
        if (val_is_true(&lv)) { val_free(&lv); return val_num(1); }
        val_free(&lv);
        awk_val rv = eval(n->right);
        int t = val_is_true(&rv);
        val_free(&rv);
        return val_num(t ? 1.0 : 0.0);
    }

    case N_CONCAT: {
        awk_val lv = eval(n->left);
        awk_val rv = eval(n->right);
        char lb[256], rb2[256];
        const char *ls = val_to_str(&lv, lb, sizeof(lb));
        const char *rs = val_to_str(&rv, rb2, sizeof(rb2));
        char *cat = malloc(strlen(ls) + strlen(rs) + 1);
        strcpy(cat, ls);
        strcat(cat, rs);
        awk_val result = val_str(cat);
        free(cat);
        val_free(&lv);
        val_free(&rv);
        return result;
    }

    case N_MATCH: case N_NOTMATCH: {
        awk_val sv = eval(n->left);
        char buf[256];
        const char *s = val_to_str(&sv, buf, sizeof(buf));
        awk_val pv = eval(n->right);
        char pbuf[256];
        const char *pat = val_to_str(&pv, pbuf, sizeof(pbuf));
        struct re_node re[RE_MAX_NODES];
        re_compile(pat, re, RE_MAX_NODES);
        int matched = re_search(re, s, NULL, NULL);
        val_free(&sv);
        val_free(&pv);
        if (n->type == N_NOTMATCH) matched = !matched;
        return val_num(matched ? 1.0 : 0.0);
    }

    case N_TERNARY: {
        awk_val cv = eval(n->left);
        int t = val_is_true(&cv);
        val_free(&cv);
        return eval(t ? n->right : n->extra);
    }

    case N_INCR: case N_DECR: {
        awk_val v = get_lvalue(n->left);
        double d = val_to_num(&v);
        val_free(&v);
        d += (n->type == N_INCR) ? 1 : -1;
        awk_val nv = val_num(d);
        set_lvalue(n->left, nv);
        return val_num(d);
    }

    case N_POST_INCR: case N_POST_DECR: {
        awk_val v = get_lvalue(n->left);
        double d = val_to_num(&v);
        val_free(&v);
        double new_d = d + ((n->type == N_POST_INCR) ? 1 : -1);
        set_lvalue(n->left, val_num(new_d));
        return val_num(d); /* return old value */
    }

    case N_IN: {
        awk_val kv = eval(n->left);
        char kbuf[256];
        const char *key = val_to_str(&kv, kbuf, sizeof(kbuf));
        const char *arr_name = n->right->str;
        awk_var *av = var_lookup(arr_name);
        int found = (av && av->array) ? array_has(av->array, key) : 0;
        val_free(&kv);
        return val_num(found ? 1.0 : 0.0);
    }

    case N_GETLINE: {
        if (fgets(g_line, sizeof(g_line), stdin)) {
            /* Strip newline */
            int len = (int)strlen(g_line);
            if (len > 0 && g_line[len-1] == '\n') g_line[--len] = '\0';
            split_fields();
            awk_var *nr = var_get("NR");
            nr->val.nval += 1;
            nr->val.type = VAL_NUMBER;
            var_set_num("NF", (double)g_nfields);
            if (n->str)
                var_set_str(n->str, g_line);
            return val_num(1);
        }
        return val_num(0);
    }

    case N_CALL:
        return eval_call(n);

    case N_PRINT: {
        FILE *out = stdout;
        if (n->op && n->extra) {
            awk_val rv = eval(n->extra);
            char rbuf[256];
            const char *rname = val_to_str(&rv, rbuf, sizeof(rbuf));
            out = awk_get_output(rname, n->op);
            val_free(&rv);
        }
        do_print(n, out);
        fflush(out);
        return val_num(0);
    }

    case N_PRINTF: {
        FILE *out = stdout;
        if (n->op && n->extra) {
            awk_val rv = eval(n->extra);
            char rbuf[256];
            const char *rname = val_to_str(&rv, rbuf, sizeof(rbuf));
            out = awk_get_output(rname, n->op);
            val_free(&rv);
        }
        do_printf(n, out);
        fflush(out);
        return val_num(0);
    }

    case N_IF: {
        awk_val cv = eval(n->left);
        int t = val_is_true(&cv);
        val_free(&cv);
        if (t) {
            return eval(n->right);
        } else if (n->extra) {
            return eval(n->extra);
        }
        return val_num(0);
    }

    case N_WHILE: {
        while (g_eval_state == EVAL_NORMAL) {
            awk_val cv = eval(n->left);
            int t = val_is_true(&cv);
            val_free(&cv);
            if (!t) break;
            awk_val bv = eval(n->right);
            val_free(&bv);
            if (g_eval_state == EVAL_BREAK) { g_eval_state = EVAL_NORMAL; break; }
            if (g_eval_state == EVAL_CONTINUE) { g_eval_state = EVAL_NORMAL; continue; }
            if (g_eval_state == EVAL_NEXT || g_eval_state == EVAL_EXIT) break;
        }
        return val_num(0);
    }

    case N_DO_WHILE: {
        do {
            awk_val bv = eval(n->right);
            val_free(&bv);
            if (g_eval_state == EVAL_BREAK) { g_eval_state = EVAL_NORMAL; break; }
            if (g_eval_state == EVAL_CONTINUE) g_eval_state = EVAL_NORMAL;
            if (g_eval_state == EVAL_NEXT || g_eval_state == EVAL_EXIT) break;
            awk_val cv = eval(n->left);
            int t = val_is_true(&cv);
            val_free(&cv);
            if (!t) break;
        } while (g_eval_state == EVAL_NORMAL);
        return val_num(0);
    }

    case N_FOR: {
        /* init */
        if (n->extra2) { awk_val v = eval(n->extra2); val_free(&v); }
        while (g_eval_state == EVAL_NORMAL) {
            /* condition */
            if (n->left) {
                awk_val cv = eval(n->left);
                int t = val_is_true(&cv);
                val_free(&cv);
                if (!t) break;
            }
            /* body */
            awk_val bv = eval(n->right);
            val_free(&bv);
            if (g_eval_state == EVAL_BREAK) { g_eval_state = EVAL_NORMAL; break; }
            if (g_eval_state == EVAL_CONTINUE) g_eval_state = EVAL_NORMAL;
            if (g_eval_state == EVAL_NEXT || g_eval_state == EVAL_EXIT) break;
            /* increment */
            if (n->extra) { awk_val iv = eval(n->extra); val_free(&iv); }
        }
        return val_num(0);
    }

    case N_FOR_IN: {
        const char *var_name = n->str;
        const char *arr_name = n->left ? n->left->str : "";
        awk_var *av = var_lookup(arr_name);
        if (av && av->array) {
            for (int b = 0; b < 256 && g_eval_state == EVAL_NORMAL; b++) {
                awk_array_entry *e = av->array->buckets[b];
                while (e && g_eval_state == EVAL_NORMAL) {
                    var_set_str(var_name, e->key);
                    awk_val bv = eval(n->right);
                    val_free(&bv);
                    if (g_eval_state == EVAL_BREAK) { g_eval_state = EVAL_NORMAL; goto forin_done; }
                    if (g_eval_state == EVAL_CONTINUE) g_eval_state = EVAL_NORMAL;
                    if (g_eval_state == EVAL_NEXT || g_eval_state == EVAL_EXIT) goto forin_done;
                    e = e->next;
                }
            }
        }
forin_done:
        return val_num(0);
    }

    case N_BREAK:
        g_eval_state = EVAL_BREAK;
        return val_num(0);

    case N_CONTINUE:
        g_eval_state = EVAL_CONTINUE;
        return val_num(0);

    case N_NEXT:
        g_eval_state = EVAL_NEXT;
        return val_num(0);

    case N_EXIT:
        if (n->left) {
            awk_val v = eval(n->left);
            g_exit_code = (int)val_to_num(&v);
            val_free(&v);
        }
        g_eval_state = EVAL_EXIT;
        return val_num(0);

    case N_DELETE: {
        awk_var *v = var_lookup(n->str);
        if (v && v->array && n->left) {
            awk_val kv = eval(n->left);
            char kbuf[256];
            const char *key = val_to_str(&kv, kbuf, sizeof(kbuf));
            array_delete(v->array, key);
            val_free(&kv);
        }
        return val_num(0);
    }

    case N_BLOCK: {
        node *s = n->left;
        awk_val last = val_num(0);
        while (s && g_eval_state == EVAL_NORMAL) {
            val_free(&last);
            last = eval(s);
            s = s->next;
        }
        return last;
    }

    case N_NOP:
        return val_num(0);

    default:
        return val_num(0);
    }
}

/* =========================================================================
 * Main program execution
 * ========================================================================= */

static int eval_pattern(node *pat)
{
    if (!pat) return 1; /* no pattern = match all */
    awk_val v = eval(pat);
    int t = val_is_true(&v);
    val_free(&v);
    return t;
}

/* Range pattern state — one per rule */
#define MAX_RULES 256
static int g_range_active[MAX_RULES];

static void run_rules(node *prog, int is_begin, int is_end)
{
    int rule_idx = 0;
    node *rule = prog->left;
    while (rule && g_eval_state != EVAL_EXIT) {
        if (rule->str && strcmp(rule->str, "BEGIN") == 0) {
            if (is_begin && rule->right) {
                awk_val v = eval(rule->right);
                val_free(&v);
            }
        } else if (rule->str && strcmp(rule->str, "END") == 0) {
            if (is_end && rule->right) {
                awk_val v = eval(rule->right);
                val_free(&v);
            }
        } else if (rule->str && strcmp(rule->str, "FUNC") == 0) {
            /* Skip function definitions during execution */
        } else if (!is_begin && !is_end) {
            int match = 0;
            if (rule->extra) {
                /* Range pattern: pat1, pat2 */
                if (!g_range_active[rule_idx]) {
                    if (eval_pattern(rule->left)) {
                        g_range_active[rule_idx] = 1;
                        match = 1;
                    }
                } else {
                    match = 1;
                    if (eval_pattern(rule->extra))
                        g_range_active[rule_idx] = 0;
                }
            } else {
                match = eval_pattern(rule->left);
            }
            if (match && rule->right) {
                g_eval_state = EVAL_NORMAL;
                awk_val v = eval(rule->right);
                val_free(&v);
                if (g_eval_state == EVAL_NEXT) {
                    g_eval_state = EVAL_NORMAL;
                    break; /* skip remaining rules for this line */
                }
            }
        }
        rule = rule->next;
        rule_idx++;
    }
}

static void process_file(FILE *fp, const char *filename, node *prog)
{
    var_set_str("FILENAME", filename);
    awk_var *fnr_var = var_get("FNR");
    fnr_var->val.type = VAL_NUMBER;
    fnr_var->val.nval = 0;

    /* Get RS */
    awk_var *rs_var = var_lookup("RS");
    char rs = (rs_var && rs_var->val.sval && rs_var->val.sval[0]) ? rs_var->val.sval[0] : '\n';

    while (fgets(g_line, sizeof(g_line), fp) && g_eval_state != EVAL_EXIT) {
        /* Strip record separator */
        int len = (int)strlen(g_line);
        if (len > 0 && g_line[len-1] == rs) g_line[--len] = '\0';
        if (len > 0 && g_line[len-1] == '\r') g_line[--len] = '\0';

        /* Update FS from variable */
        awk_var *fs_var = var_lookup("FS");
        if (fs_var && fs_var->val.sval) {
            strncpy(g_fs, fs_var->val.sval, sizeof(g_fs) - 1);
            g_fs[sizeof(g_fs) - 1] = '\0';
        }

        split_fields();

        /* Update built-in vars */
        awk_var *nr_var = var_get("NR");
        nr_var->val.type = VAL_NUMBER;
        nr_var->val.nval += 1;
        fnr_var->val.nval += 1;
        var_set_num("NF", (double)g_nfields);

        run_rules(prog, 0, 0);
    }
}

static void usage(void)
{
    fprintf(stderr, "usage: awk [-F fs] [-v var=val] [-f progfile] ['program'] [file ...]\n");
    exit(2);
}

int main(int argc, char *argv[])
{
    const char *program_text = NULL;
    char *prog_file = NULL;
    int argi = 1;

    /* Initialize built-in variables */
    var_set_str("FS", " ");
    var_set_str("RS", "\n");
    var_set_str("OFS", " ");
    var_set_str("ORS", "\n");
    var_set_str("SUBSEP", "\034");
    var_set_num("NR", 0);
    var_set_num("NF", 0);
    var_set_num("FNR", 0);
    var_set_str("FILENAME", "");
    var_set_num("RSTART", 0);
    var_set_num("RLENGTH", 0);
    strcpy(g_fs, " ");

    /* Parse options */
    while (argi < argc && argv[argi][0] == '-' && argv[argi][1]) {
        if (strcmp(argv[argi], "--") == 0) { argi++; break; }
        if (strcmp(argv[argi], "--help") == 0) {
            printf("usage: awk [-F fs] [-v var=val] [-f progfile] ['program'] [file ...]\n");
            return 0;
        }

        const char *opt = argv[argi];
        if (opt[1] == 'F') {
            const char *fs;
            if (opt[2]) fs = opt + 2;
            else if (argi + 1 < argc) fs = argv[++argi];
            else usage();
            var_set_str("FS", fs);
            strncpy(g_fs, fs, sizeof(g_fs) - 1);
            g_fs[sizeof(g_fs) - 1] = '\0';
        } else if (opt[1] == 'v') {
            const char *assign = NULL;
            if (opt[2]) assign = opt + 2;
            else if (argi + 1 < argc) assign = argv[++argi];
            else usage();
            if (!assign) usage();  /* safety check */
            char name[256], value[4096];
            const char *eq = strchr(assign, '=');
            if (!eq) usage();
            int nlen = (int)(eq - assign);
            if (nlen >= (int)sizeof(name)) nlen = sizeof(name) - 1;
            memcpy(name, assign, nlen);
            name[nlen] = '\0';
            strcpy(value, eq + 1);
            var_set_str(name, value);
        } else if (opt[1] == 'f') {
            if (opt[2]) prog_file = (char *)(opt + 2);
            else if (argi + 1 < argc) prog_file = argv[++argi];
            else usage();
        } else {
            fprintf(stderr, "awk: unknown option '%s'\n", opt);
            usage();
        }
        argi++;
    }

    /* Get program text */
    char *prog_buf = NULL;
    if (prog_file) {
        FILE *f = fopen(prog_file, "r");
        if (!f) {
            fprintf(stderr, "awk: can't open program file '%s': %s\n",
                    prog_file, strerror(errno));
            return 2;
        }
        size_t cap = 4096, len = 0;
        prog_buf = malloc(cap);
        int ch;
        while ((ch = fgetc(f)) != EOF) {
            if (len + 1 >= cap) {
                cap *= 2;
                prog_buf = realloc(prog_buf, cap);
            }
            prog_buf[len++] = (char)ch;
        }
        prog_buf[len] = '\0';
        fclose(f);
        program_text = prog_buf;
    } else if (argi < argc) {
        program_text = argv[argi++];
    } else {
        usage();
    }

    /* Parse the AWK program */
    g_src = program_text;
    g_pos = 0;
    g_last_was_value = 0;
    next_token();
    node *prog = parse_program();

    memset(g_range_active, 0, sizeof(g_range_active));

    /* Run BEGIN blocks */
    g_eval_state = EVAL_NORMAL;
    run_rules(prog, 1, 0);

    /* Process input files */
    if (g_eval_state != EVAL_EXIT) {
        if (argi >= argc) {
            /* Read from stdin */
            process_file(stdin, "(stdin)", prog);
        } else {
            while (argi < argc && g_eval_state != EVAL_EXIT) {
                const char *fname = argv[argi++];
                if (strcmp(fname, "-") == 0) {
                    process_file(stdin, "(stdin)", prog);
                } else {
                    FILE *f = fopen(fname, "r");
                    if (!f) {
                        fprintf(stderr, "awk: can't open '%s': %s\n",
                                fname, strerror(errno));
                        g_exit_code = 2;
                        continue;
                    }
                    process_file(f, fname, prog);
                    fclose(f);
                }
            }
        }
    }

    /* Run END blocks */
    g_eval_state = EVAL_NORMAL;
    run_rules(prog, 0, 1);

    /* Close all redirected output files/pipes */
    awk_close_outputs();

    if (prog_buf) free(prog_buf);
    return g_exit_code;
}
