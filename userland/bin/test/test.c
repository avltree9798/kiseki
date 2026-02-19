/*
 * test - evaluate conditional expression
 *
 * Usage: test EXPRESSION
 *    or: [ EXPRESSION ]
 *
 * Exit status: 0 if EXPRESSION is true, 1 if false, 2 on error.
 *
 * Implements a recursive descent parser over argv.
 *
 * Grammar (lowest to highest precedence):
 *   expr     → or_expr
 *   or_expr  → and_expr ( '-o' and_expr )*
 *   and_expr → not_expr ( '-a' not_expr )*
 *   not_expr → '!' not_expr | primary
 *   primary  → '(' expr ')' | unary_test | binary_test | STRING
 *
 * Kiseki OS coreutils
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

static const char *progname = "test";
static int pos;
static int nargs;
static char **args;

static void test_error(const char *msg)
{
    fprintf(stderr, "%s: %s\n", progname, msg);
    exit(2);
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
        test_error("unexpected end of expression");
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

/* Forward declarations */
static int eval_expr(void);
static int eval_or(void);
static int eval_and(void);
static int eval_not(void);
static int eval_primary(void);

/*
 * Check if a string looks like a unary file/string test operator.
 */
static int is_unary_op(const char *s)
{
    if (s[0] != '-' || s[1] == '\0' || s[2] != '\0')
        return 0;
    return strchr("bcdefghkLnprsStuwxz", s[1]) != NULL;
}

/*
 * Check if a string is a binary operator.
 */
static int is_binary_op(const char *s)
{
    return strcmp(s, "=") == 0 ||
           strcmp(s, "!=") == 0 ||
           strcmp(s, "<") == 0 ||
           strcmp(s, ">") == 0 ||
           strcmp(s, "-eq") == 0 ||
           strcmp(s, "-ne") == 0 ||
           strcmp(s, "-lt") == 0 ||
           strcmp(s, "-le") == 0 ||
           strcmp(s, "-gt") == 0 ||
           strcmp(s, "-ge") == 0 ||
           strcmp(s, "-nt") == 0 ||
           strcmp(s, "-ot") == 0 ||
           strcmp(s, "-ef") == 0;
}

/*
 * Evaluate a unary file/string test.
 */
static int eval_unary(const char *op, const char *arg)
{
    struct stat st;

    switch (op[1]) {
    /* File tests */
    case 'e': return stat(arg, &st) == 0;
    case 'f': return stat(arg, &st) == 0 && S_ISREG(st.st_mode);
    case 'd': return stat(arg, &st) == 0 && S_ISDIR(st.st_mode);
    case 'b': return stat(arg, &st) == 0 && S_ISBLK(st.st_mode);
    case 'c': return stat(arg, &st) == 0 && S_ISCHR(st.st_mode);
    case 'p': return stat(arg, &st) == 0 && S_ISFIFO(st.st_mode);
    case 'S': return stat(arg, &st) == 0 && S_ISSOCK(st.st_mode);
    case 'L': /* fall through */
    case 'h': return lstat(arg, &st) == 0 && S_ISLNK(st.st_mode);
    case 's': return stat(arg, &st) == 0 && st.st_size > 0;
    case 'r': return access(arg, R_OK) == 0;
    case 'w': return access(arg, W_OK) == 0;
    case 'x': return access(arg, X_OK) == 0;
    case 'u': return stat(arg, &st) == 0 && (st.st_mode & S_ISUID);
    case 'g': return stat(arg, &st) == 0 && (st.st_mode & S_ISGID);
    case 'k': return stat(arg, &st) == 0 && (st.st_mode & S_ISVTX);
    case 't': {
        /* -t FD: true if FD is open and is a terminal */
        char *end;
        long fd = strtol(arg, &end, 10);
        if (*end != '\0')
            return 0;
        return isatty((int)fd);
    }

    /* String tests */
    case 'z': return arg[0] == '\0';
    case 'n': return arg[0] != '\0';

    default:
        fprintf(stderr, "%s: unknown unary operator '%s'\n", progname, op);
        exit(2);
    }
    return 0;
}

/*
 * Evaluate a binary test.
 */
static int eval_binary(const char *left, const char *op, const char *right)
{
    /* String comparisons */
    if (strcmp(op, "=") == 0)
        return strcmp(left, right) == 0;
    if (strcmp(op, "!=") == 0)
        return strcmp(left, right) != 0;
    if (strcmp(op, "<") == 0)
        return strcmp(left, right) < 0;
    if (strcmp(op, ">") == 0)
        return strcmp(left, right) > 0;

    /* Numeric comparisons */
    if (strcmp(op, "-eq") == 0 || strcmp(op, "-ne") == 0 ||
        strcmp(op, "-lt") == 0 || strcmp(op, "-le") == 0 ||
        strcmp(op, "-gt") == 0 || strcmp(op, "-ge") == 0) {
        char *end1, *end2;
        long l = strtol(left, &end1, 10);
        long r = strtol(right, &end2, 10);
        if (*end1 != '\0') {
            fprintf(stderr, "%s: integer expression expected: '%s'\n",
                    progname, left);
            exit(2);
        }
        if (*end2 != '\0') {
            fprintf(stderr, "%s: integer expression expected: '%s'\n",
                    progname, right);
            exit(2);
        }

        if (strcmp(op, "-eq") == 0) return l == r;
        if (strcmp(op, "-ne") == 0) return l != r;
        if (strcmp(op, "-lt") == 0) return l < r;
        if (strcmp(op, "-le") == 0) return l <= r;
        if (strcmp(op, "-gt") == 0) return l > r;
        if (strcmp(op, "-ge") == 0) return l >= r;
    }

    /* File comparisons */
    if (strcmp(op, "-nt") == 0 || strcmp(op, "-ot") == 0 ||
        strcmp(op, "-ef") == 0) {
        struct stat st1, st2;
        if (stat(left, &st1) != 0)
            return 0;
        if (stat(right, &st2) != 0)
            return 0;
        if (strcmp(op, "-nt") == 0)
            return st1.st_mtime > st2.st_mtime;
        if (strcmp(op, "-ot") == 0)
            return st1.st_mtime < st2.st_mtime;
        if (strcmp(op, "-ef") == 0)
            return st1.st_dev == st2.st_dev && st1.st_ino == st2.st_ino;
    }

    fprintf(stderr, "%s: unknown binary operator '%s'\n", progname, op);
    exit(2);
    return 0;
}

/*
 * Recursive descent parser.
 */
static int eval_expr(void)
{
    return eval_or();
}

static int eval_or(void)
{
    int result = eval_and();
    while (peek() && strcmp(peek(), "-o") == 0) {
        pos++;
        int right = eval_and();
        result = result || right;
    }
    return result;
}

static int eval_and(void)
{
    int result = eval_not();
    while (peek() && strcmp(peek(), "-a") == 0) {
        pos++;
        int right = eval_not();
        result = result && right;
    }
    return result;
}

static int eval_not(void)
{
    if (peek() && strcmp(peek(), "!") == 0) {
        pos++;
        return !eval_not();
    }
    return eval_primary();
}

static int eval_primary(void)
{
    const char *tok = peek();

    if (tok == NULL) {
        /* Empty expression is false */
        return 0;
    }

    /* Parenthesized expression */
    if (strcmp(tok, "(") == 0) {
        pos++;
        int result = eval_expr();
        if (!match(")"))
            test_error("missing ')'");
        return result;
    }

    /* Unary operator: -X ARG */
    if (is_unary_op(tok) && pos + 1 < nargs) {
        /*
         * Need to be careful: this could be a string that looks like
         * a unary op used in a binary test. Peek ahead.
         */
        if (pos + 2 < nargs && is_binary_op(args[pos + 1])) {
            /* It's a binary expression: tok is left operand */
            goto binary_check;
        }
        pos++;
        const char *arg = advance();
        return eval_unary(tok, arg);
    }

binary_check:
    /*
     * Binary operator: LEFT OP RIGHT
     * Look ahead to see if the next token is a binary operator.
     */
    if (pos + 2 < nargs && is_binary_op(args[pos + 1])) {
        const char *left = advance();
        const char *op = advance();
        const char *right = advance();
        return eval_binary(left, op, right);
    }

    /* Single string: true if non-empty */
    {
        const char *s = advance();
        return s[0] != '\0';
    }
}

int main(int argc, char *argv[])
{
    /* Determine program name */
    const char *name = argv[0];
    if (name) {
        const char *slash = strrchr(name, '/');
        if (slash)
            name = slash + 1;
        progname = name;
    }

    /* If invoked as '[', the last argument must be ']' */
    if (strcmp(progname, "[") == 0) {
        if (argc < 2 || strcmp(argv[argc - 1], "]") != 0) {
            fprintf(stderr, "%s: missing ']'\n", progname);
            return 2;
        }
        argc--; /* exclude the trailing ']' */
    }

    /* Set up parser state (skip argv[0]) */
    args = argv + 1;
    nargs = argc - 1;
    pos = 0;

    /* No arguments → false */
    if (nargs == 0)
        return 1;

    int result = eval_expr();

    /* Make sure all arguments were consumed */
    if (pos < nargs) {
        fprintf(stderr, "%s: unexpected argument '%s'\n", progname, args[pos]);
        return 2;
    }

    return result ? 0 : 1;
}
