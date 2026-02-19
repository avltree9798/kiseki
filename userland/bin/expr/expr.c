/*
 * expr - evaluate expressions
 *
 * Usage: expr EXPRESSION
 *
 * Each token is a separate command-line argument.
 * Operator precedence (lowest to highest):
 *   |  (or)
 *   &  (and)
 *   = != < <= > >=  (comparison)
 *   + -  (addition/subtraction)
 *   * / %  (multiplication/division/modulo)
 *   match, substr, index, length, ( )  (primary)
 *
 * Exit status: 0 if expression is non-null and non-zero,
 *              1 if null or zero, 2 on error.
 *
 * Kiseki OS coreutils
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static const char *progname = "expr";
static int pos;
static int nargs;
static char **args;

/*
 * Value: either a string or integer.  We always store the string form;
 * we try to interpret as integer only when needed.
 */
typedef struct {
    char *str;
} Value;

static void expr_error(const char *msg)
{
    fprintf(stderr, "%s: %s\n", progname, msg);
    exit(2);
}

static void syntax_error(void)
{
    expr_error("syntax error");
}

static const char *peek(void)
{
    if (pos >= nargs)
        return NULL;
    return args[pos];
}

static const char *advance(void)
{
    if (pos >= nargs)
        syntax_error();
    return args[pos++];
}

static int match(const char *s)
{
    const char *p = peek();
    if (p && strcmp(p, s) == 0) {
        pos++;
        return 1;
    }
    return 0;
}

static Value make_str(const char *s)
{
    Value v;
    v.str = strdup(s);
    if (!v.str)
        expr_error("out of memory");
    return v;
}

static Value make_int(long n)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "%ld", n);
    return make_str(buf);
}

static void free_val(Value *v)
{
    free(v->str);
    v->str = NULL;
}

/*
 * Try to parse a value as an integer. Returns 1 on success.
 */
static int to_int(const Value *v, long *out)
{
    const char *s = v->str;
    if (s[0] == '\0')
        return 0;

    char *end;
    errno = 0;
    long n = strtol(s, &end, 10);
    if (errno != 0 || *end != '\0')
        return 0;
    *out = n;
    return 1;
}

/*
 * Is a value "null" (empty string or "0")?
 */
static int is_null(const Value *v)
{
    if (v->str[0] == '\0')
        return 1;
    long n;
    if (to_int(v, &n) && n == 0)
        return 1;
    return 0;
}

/* Forward declarations for recursive descent parser */
static Value eval_or(void);
static Value eval_and(void);
static Value eval_compare(void);
static Value eval_add(void);
static Value eval_mul(void);
static Value eval_primary(void);

/*
 * Simple pattern matching for 'match' and ':' operators.
 * Supports: . (any char), * (zero or more of preceding), ^ (start),
 * and literal characters. Match is always anchored at start.
 * Returns the length of the match, or the first captured group.
 */
static int simple_match(const char *str, const char *pat, char *group,
                        size_t groupsz)
{
    /* We implement a basic regex matcher anchored at start of string.
     * Supports: . * \char and literal chars.
     * Parentheses \( \) for grouping (but we simplify to just capture
     * the whole match if no groups). */

    const char *s = str;
    const char *p = pat;
    const char *grp_start = NULL;
    const char *grp_end = NULL;

    /* Track positions for backtracking on * */
    while (*p) {
        /* Check for \( and \) */
        if (p[0] == '\\' && p[1] == '(') {
            grp_start = s;
            p += 2;
            continue;
        }
        if (p[0] == '\\' && p[1] == ')') {
            grp_end = s;
            p += 2;
            continue;
        }

        /* Get current pattern character */
        char pc;
        int is_dot = 0;
        if (p[0] == '\\' && p[1]) {
            pc = p[1];
            p += 2;
        } else if (p[0] == '.') {
            is_dot = 1;
            pc = '.';
            p++;
        } else {
            pc = *p;
            p++;
        }

        /* Check for * (zero or more) */
        if (*p == '*') {
            p++;
            /* Greedy match: try as many as possible, then backtrack */
            const char *saved_s = s;
            while (*s && (is_dot || *s == pc))
                s++;
            /* Try matching rest of pattern from each position */
            while (s >= saved_s) {
                /* Save state and try recursive match of remainder */
                /* Simple approach: since our regex is basic, we just
                 * greedily consume and return the longest match if
                 * there's no more pattern. */
                if (*p == '\0') {
                    /* No more pattern; match succeeded */
                    goto done;
                }
                /* Check if next pattern char matches */
                if (p[0] == '\\' && p[1] == '(') {
                    /* Group start - continue outer loop */
                    goto done_star;
                }
                if (p[0] == '\\' && p[1] == ')') {
                    goto done_star;
                }
                /* Try simple next-char check for non-star patterns */
                {
                    char nc;
                    int nd = 0;
                    const char *np = p;
                    if (np[0] == '\\' && np[1] && np[1] != '(' && np[1] != ')') {
                        nc = np[1];
                    } else if (np[0] == '.') {
                        nd = 1;
                        nc = '.';
                    } else {
                        nc = np[0];
                    }
                    if (*s && (nd || *s == nc)) {
                        goto done_star;
                    }
                }
                s--;
            }
            /* Could not match; fail */
            goto fail;
done_star:
            continue;
        }

        /* Normal single character match */
        if (*s == '\0')
            goto fail;
        if (is_dot || *s == pc) {
            s++;
        } else {
            goto fail;
        }
    }

done:
    if (grp_start != NULL) {
        if (grp_end == NULL)
            grp_end = s;
        size_t glen = (size_t)(grp_end - grp_start);
        if (glen >= groupsz)
            glen = groupsz - 1;
        memcpy(group, grp_start, glen);
        group[glen] = '\0';
        return -1; /* Signal: use group string instead of count */
    }

    if (group) {
        group[0] = '\0';
    }
    return (int)(s - str);

fail:
    if (group)
        group[0] = '\0';
    return 0;
}

/*
 * expr  →  or_expr
 */
static Value eval_expr(void)
{
    return eval_or();
}

/*
 * or_expr  →  and_expr ( '|' and_expr )*
 */
static Value eval_or(void)
{
    Value left = eval_and();

    while (peek() && strcmp(peek(), "|") == 0) {
        pos++;
        Value right = eval_and();
        if (!is_null(&left)) {
            free_val(&right);
        } else {
            free_val(&left);
            left = right;
        }
    }

    return left;
}

/*
 * and_expr  →  compare_expr ( '&' compare_expr )*
 */
static Value eval_and(void)
{
    Value left = eval_compare();

    while (peek() && strcmp(peek(), "&") == 0) {
        pos++;
        Value right = eval_compare();
        if (!is_null(&left) && !is_null(&right)) {
            free_val(&right);
        } else {
            free_val(&left);
            free_val(&right);
            left = make_str("0");
        }
    }

    return left;
}

/*
 * compare_expr  →  add_expr ( ('=' | '!=' | '<' | '<=' | '>' | '>=') add_expr )*
 */
static Value eval_compare(void)
{
    Value left = eval_add();

    while (peek() &&
           (strcmp(peek(), "=") == 0 ||
            strcmp(peek(), "!=") == 0 ||
            strcmp(peek(), "<") == 0 ||
            strcmp(peek(), "<=") == 0 ||
            strcmp(peek(), ">") == 0 ||
            strcmp(peek(), ">=") == 0)) {
        const char *op = advance();
        Value right = eval_add();

        int result;
        long ln, rn;

        /* If both are integers, compare numerically */
        if (to_int(&left, &ln) && to_int(&right, &rn)) {
            if (strcmp(op, "=") == 0)       result = (ln == rn);
            else if (strcmp(op, "!=") == 0) result = (ln != rn);
            else if (strcmp(op, "<") == 0)  result = (ln < rn);
            else if (strcmp(op, "<=") == 0) result = (ln <= rn);
            else if (strcmp(op, ">") == 0)  result = (ln > rn);
            else                            result = (ln >= rn);
        } else {
            int cmp = strcmp(left.str, right.str);
            if (strcmp(op, "=") == 0)       result = (cmp == 0);
            else if (strcmp(op, "!=") == 0) result = (cmp != 0);
            else if (strcmp(op, "<") == 0)  result = (cmp < 0);
            else if (strcmp(op, "<=") == 0) result = (cmp <= 0);
            else if (strcmp(op, ">") == 0)  result = (cmp > 0);
            else                            result = (cmp >= 0);
        }

        free_val(&left);
        free_val(&right);
        left = make_int(result ? 1 : 0);
    }

    return left;
}

/*
 * add_expr  →  mul_expr ( ('+' | '-') mul_expr )*
 */
static Value eval_add(void)
{
    Value left = eval_mul();

    while (peek() &&
           (strcmp(peek(), "+") == 0 || strcmp(peek(), "-") == 0)) {
        const char *op = advance();
        Value right = eval_mul();

        long ln, rn;
        if (!to_int(&left, &ln)) {
            fprintf(stderr, "%s: non-integer argument '%s'\n",
                    progname, left.str);
            exit(2);
        }
        if (!to_int(&right, &rn)) {
            fprintf(stderr, "%s: non-integer argument '%s'\n",
                    progname, right.str);
            exit(2);
        }

        long result;
        if (strcmp(op, "+") == 0)
            result = ln + rn;
        else
            result = ln - rn;

        free_val(&left);
        free_val(&right);
        left = make_int(result);
    }

    return left;
}

/*
 * mul_expr  →  primary ( ('*' | '/' | '%') primary )*
 */
static Value eval_mul(void)
{
    Value left = eval_primary();

    while (peek() &&
           (strcmp(peek(), "*") == 0 ||
            strcmp(peek(), "/") == 0 ||
            strcmp(peek(), "%") == 0)) {
        const char *op = advance();
        Value right = eval_primary();

        long ln, rn;
        if (!to_int(&left, &ln)) {
            fprintf(stderr, "%s: non-integer argument '%s'\n",
                    progname, left.str);
            exit(2);
        }
        if (!to_int(&right, &rn)) {
            fprintf(stderr, "%s: non-integer argument '%s'\n",
                    progname, right.str);
            exit(2);
        }

        long result;
        if (strcmp(op, "*") == 0) {
            result = ln * rn;
        } else {
            if (rn == 0) {
                expr_error("division by zero");
            }
            if (strcmp(op, "/") == 0)
                result = ln / rn;
            else
                result = ln % rn;
        }

        free_val(&left);
        free_val(&right);
        left = make_int(result);
    }

    return left;
}

/*
 * primary  →  '(' expr ')'
 *           | 'match' STRING REGEX
 *           | 'substr' STRING POS LENGTH
 *           | 'index' STRING CHARS
 *           | 'length' STRING
 *           | STRING ':' REGEX
 *           | STRING
 */
static Value eval_primary(void)
{
    const char *tok = peek();

    if (tok == NULL)
        syntax_error();

    /* Parenthesized expression */
    if (strcmp(tok, "(") == 0) {
        pos++;
        Value v = eval_expr();
        if (!match(")"))
            expr_error("missing ')'");
        return v;
    }

    /* Keyword operators */
    if (strcmp(tok, "match") == 0) {
        pos++;
        const char *str = advance();
        const char *pat = advance();
        char group[256];
        int n = simple_match(str, pat, group, sizeof(group));
        if (n == -1) {
            /* Group captured */
            return make_str(group);
        }
        return make_int(n);
    }

    if (strcmp(tok, "substr") == 0) {
        pos++;
        const char *str = advance();
        const char *spos = advance();
        const char *slen = advance();

        long p = strtol(spos, NULL, 10);
        long l = strtol(slen, NULL, 10);
        size_t slen_str = strlen(str);

        if (p <= 0 || l <= 0 || (size_t)p > slen_str)
            return make_str("");

        size_t start = (size_t)(p - 1); /* 1-indexed */
        size_t maxlen = slen_str - start;
        if ((size_t)l > maxlen)
            l = (long)maxlen;

        char *buf = malloc((size_t)l + 1);
        if (!buf)
            expr_error("out of memory");
        memcpy(buf, str + start, (size_t)l);
        buf[l] = '\0';
        Value v;
        v.str = buf;
        return v;
    }

    if (strcmp(tok, "index") == 0) {
        pos++;
        const char *str = advance();
        const char *chars = advance();

        /* Find first occurrence of any char in 'chars' within 'str' */
        for (size_t i = 0; str[i]; i++) {
            if (strchr(chars, str[i]) != NULL)
                return make_int((long)(i + 1)); /* 1-indexed */
        }
        return make_int(0);
    }

    if (strcmp(tok, "length") == 0) {
        pos++;
        const char *str = advance();
        return make_int((long)strlen(str));
    }

    /* Regular value, possibly followed by ':' (match operator) */
    const char *val = advance();

    if (peek() && strcmp(peek(), ":") == 0) {
        pos++;
        const char *pat = advance();
        char group[256];
        int n = simple_match(val, pat, group, sizeof(group));
        if (n == -1)
            return make_str(group);
        return make_int(n);
    }

    return make_str(val);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s EXPRESSION\n", progname);
        return 2;
    }

    args = argv + 1;
    nargs = argc - 1;
    pos = 0;

    Value result = eval_expr();

    /* Check all arguments were consumed */
    if (pos < nargs) {
        fprintf(stderr, "%s: syntax error: unexpected '%s'\n",
                progname, args[pos]);
        return 2;
    }

    /* Print result */
    puts(result.str);

    /* Exit status: 0 if non-null/non-zero, 1 if null/zero */
    int status = is_null(&result) ? 1 : 0;
    free_val(&result);
    return status;
}
