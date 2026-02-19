/*
 * find - search for files in a directory hierarchy
 *
 * Kiseki OS coreutils
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>

static const char *progname = "find";

/* ------------------------------------------------------------------ */
/* Expression tree                                                     */
/* ------------------------------------------------------------------ */

enum expr_type {
    EXPR_NAME,          /* -name PATTERN */
    EXPR_TYPE,          /* -type T */
    EXPR_SIZE,          /* -size [+/-]N[c|k|M] */
    EXPR_NEWER,         /* -newer FILE */
    EXPR_EMPTY,         /* -empty */
    EXPR_PERM,          /* -perm MODE */
    EXPR_PRINT,         /* -print */
    EXPR_DELETE,        /* -delete */
    EXPR_EXEC,          /* -exec CMD {} \; */
    EXPR_AND,           /* -a / -and */
    EXPR_OR,            /* -o / -or */
    EXPR_NOT,           /* ! / -not */
};

struct expr {
    enum expr_type type;
    struct expr *left;      /* For AND/OR */
    struct expr *right;     /* For AND/OR */
    struct expr *child;     /* For NOT */
    union {
        /* EXPR_NAME */
        const char *pattern;
        /* EXPR_TYPE */
        char filetype;      /* 'f', 'd', 'l', 'b', 'c', 'p' */
        /* EXPR_SIZE */
        struct {
            long long size;
            char size_cmp;      /* '+', '-', or '=' (exact) */
            char size_unit;     /* 'b' (512-byte), 'c', 'k', 'M' */
        } size;
        /* EXPR_NEWER */
        time_t newer_mtime;
        /* EXPR_PERM */
        mode_t perm;
        /* EXPR_EXEC */
        struct {
            char **argv;
            int argc;
        } exec;
    } u;
};

/* Options (not part of expression tree) */
static int opt_maxdepth = -1;   /* -1 = unlimited */
static int opt_mindepth = 0;

/* Did the expression contain any action (-print, -exec, -delete)? */
static int has_action = 0;

/* ------------------------------------------------------------------ */
/* Glob pattern matcher                                                */
/* ------------------------------------------------------------------ */

/*
 * Match a string against a shell glob pattern.
 * Supports *, ?, and [...] character classes.
 */
static int glob_match(const char *pattern, const char *string)
{
    while (*pattern && *string) {
        if (*pattern == '*') {
            pattern++;
            /* Skip consecutive stars */
            while (*pattern == '*')
                pattern++;
            if (*pattern == '\0')
                return 1;
            /* Try matching rest of pattern at every position */
            while (*string) {
                if (glob_match(pattern, string))
                    return 1;
                string++;
            }
            return glob_match(pattern, string);
        }

        if (*pattern == '?') {
            pattern++;
            string++;
            continue;
        }

        if (*pattern == '[') {
            pattern++;
            int negate = 0;
            if (*pattern == '!' || *pattern == '^') {
                negate = 1;
                pattern++;
            }

            int matched = 0;
            char prev = 0;
            while (*pattern && *pattern != ']') {
                if (*pattern == '-' && prev != 0 && *(pattern + 1) != ']' &&
                    *(pattern + 1) != '\0') {
                    /* Range: prev-next */
                    pattern++;
                    if (*string >= prev && *string <= *pattern)
                        matched = 1;
                    prev = *pattern;
                    pattern++;
                } else {
                    if (*pattern == *string)
                        matched = 1;
                    prev = *pattern;
                    pattern++;
                }
            }
            if (*pattern == ']')
                pattern++;

            if (negate)
                matched = !matched;
            if (!matched)
                return 0;
            string++;
            continue;
        }

        /* Literal character */
        if (*pattern == '\\' && *(pattern + 1) != '\0')
            pattern++;  /* Escaped character */

        if (*pattern != *string)
            return 0;
        pattern++;
        string++;
    }

    /* Consume trailing stars */
    while (*pattern == '*')
        pattern++;

    return (*pattern == '\0' && *string == '\0');
}

/* ------------------------------------------------------------------ */
/* Expression allocator                                                */
/* ------------------------------------------------------------------ */

static struct expr *expr_alloc(enum expr_type type)
{
    struct expr *e = calloc(1, sizeof(struct expr));
    if (!e) {
        fprintf(stderr, "%s: out of memory\n", progname);
        exit(1);
    }
    e->type = type;
    return e;
}

static void expr_free(struct expr *e)
{
    if (!e)
        return;
    expr_free(e->left);
    expr_free(e->right);
    expr_free(e->child);
    if (e->type == EXPR_EXEC) {
        free(e->u.exec.argv);
    }
    free(e);
}

/* ------------------------------------------------------------------ */
/* Expression parser                                                   */
/* ------------------------------------------------------------------ */

/*
 * Recursive descent parser for find expressions:
 *
 *   expr     := or_expr
 *   or_expr  := and_expr ( ( '-o' | '-or' ) and_expr )*
 *   and_expr := not_expr ( ( '-a' | '-and' | implicit ) not_expr )*
 *   not_expr := ( '!' | '-not' ) not_expr | primary
 *   primary  := '(' expr ')' | predicate
 */

static int parse_idx;
static int parse_argc;
static char **parse_argv;

static struct expr *parse_or(void);

static struct expr *parse_primary(void)
{
    if (parse_idx >= parse_argc)
        return NULL;

    const char *arg = parse_argv[parse_idx];

    /* Parenthesized expression */
    if (strcmp(arg, "(") == 0) {
        parse_idx++;
        struct expr *e = parse_or();
        if (parse_idx >= parse_argc || strcmp(parse_argv[parse_idx], ")") != 0) {
            fprintf(stderr, "%s: missing ')'\n", progname);
            exit(1);
        }
        parse_idx++;
        return e;
    }

    /* -name PATTERN */
    if (strcmp(arg, "-name") == 0) {
        if (parse_idx + 1 >= parse_argc) {
            fprintf(stderr, "%s: -name requires an argument\n", progname);
            exit(1);
        }
        parse_idx++;
        struct expr *e = expr_alloc(EXPR_NAME);
        e->u.pattern = parse_argv[parse_idx++];
        return e;
    }

    /* -type TYPE */
    if (strcmp(arg, "-type") == 0) {
        if (parse_idx + 1 >= parse_argc) {
            fprintf(stderr, "%s: -type requires an argument\n", progname);
            exit(1);
        }
        parse_idx++;
        char t = parse_argv[parse_idx][0];
        if (t != 'f' && t != 'd' && t != 'l' && t != 'b' &&
            t != 'c' && t != 'p') {
            fprintf(stderr, "%s: unknown type '%c'\n", progname, t);
            exit(1);
        }
        struct expr *e = expr_alloc(EXPR_TYPE);
        e->u.filetype = t;
        parse_idx++;
        return e;
    }

    /* -size [+/-]N[c|k|M] */
    if (strcmp(arg, "-size") == 0) {
        if (parse_idx + 1 >= parse_argc) {
            fprintf(stderr, "%s: -size requires an argument\n", progname);
            exit(1);
        }
        parse_idx++;
        const char *s = parse_argv[parse_idx++];
        struct expr *e = expr_alloc(EXPR_SIZE);
        e->u.size.size_cmp = '=';
        e->u.size.size_unit = 'b';  /* Default: 512-byte blocks */

        if (*s == '+') {
            e->u.size.size_cmp = '+';
            s++;
        } else if (*s == '-') {
            e->u.size.size_cmp = '-';
            s++;
        }

        char *endp;
        e->u.size.size = strtol(s, &endp, 10);

        if (*endp == 'c') {
            e->u.size.size_unit = 'c';
            endp++;
        } else if (*endp == 'k') {
            e->u.size.size_unit = 'k';
            endp++;
        } else if (*endp == 'M') {
            e->u.size.size_unit = 'M';
            endp++;
        }

        return e;
    }

    /* -newer FILE */
    if (strcmp(arg, "-newer") == 0) {
        if (parse_idx + 1 >= parse_argc) {
            fprintf(stderr, "%s: -newer requires an argument\n", progname);
            exit(1);
        }
        parse_idx++;
        struct stat st;
        if (stat(parse_argv[parse_idx], &st) < 0) {
            fprintf(stderr, "%s: cannot stat '%s': %s\n", progname,
                    parse_argv[parse_idx], strerror(errno));
            exit(1);
        }
        struct expr *e = expr_alloc(EXPR_NEWER);
        e->u.newer_mtime = st.st_mtime;
        parse_idx++;
        return e;
    }

    /* -empty */
    if (strcmp(arg, "-empty") == 0) {
        parse_idx++;
        return expr_alloc(EXPR_EMPTY);
    }

    /* -perm MODE */
    if (strcmp(arg, "-perm") == 0) {
        if (parse_idx + 1 >= parse_argc) {
            fprintf(stderr, "%s: -perm requires an argument\n", progname);
            exit(1);
        }
        parse_idx++;
        struct expr *e = expr_alloc(EXPR_PERM);
        e->u.perm = (mode_t)strtoul(parse_argv[parse_idx++], NULL, 8);
        return e;
    }

    /* -print */
    if (strcmp(arg, "-print") == 0) {
        parse_idx++;
        has_action = 1;
        return expr_alloc(EXPR_PRINT);
    }

    /* -delete */
    if (strcmp(arg, "-delete") == 0) {
        parse_idx++;
        has_action = 1;
        return expr_alloc(EXPR_DELETE);
    }

    /* -exec CMD {} \; */
    if (strcmp(arg, "-exec") == 0) {
        parse_idx++;
        int start = parse_idx;
        /* Find the terminating ';' */
        while (parse_idx < parse_argc &&
               strcmp(parse_argv[parse_idx], ";") != 0)
            parse_idx++;

        if (parse_idx >= parse_argc) {
            fprintf(stderr, "%s: -exec missing ';'\n", progname);
            exit(1);
        }

        int exec_argc = parse_idx - start;
        if (exec_argc == 0) {
            fprintf(stderr, "%s: -exec requires a command\n", progname);
            exit(1);
        }

        struct expr *e = expr_alloc(EXPR_EXEC);
        /* +1 for NULL terminator */
        e->u.exec.argv = malloc((size_t)(exec_argc + 1) * sizeof(char *));
        if (!e->u.exec.argv) {
            fprintf(stderr, "%s: out of memory\n", progname);
            exit(1);
        }
        for (int i = 0; i < exec_argc; i++)
            e->u.exec.argv[i] = parse_argv[start + i];
        e->u.exec.argv[exec_argc] = NULL;
        e->u.exec.argc = exec_argc;

        parse_idx++;  /* Skip ';' */
        has_action = 1;
        return e;
    }

    /* -maxdepth N / -mindepth N (handled as global options here) */
    if (strcmp(arg, "-maxdepth") == 0) {
        if (parse_idx + 1 >= parse_argc) {
            fprintf(stderr, "%s: -maxdepth requires an argument\n", progname);
            exit(1);
        }
        parse_idx++;
        opt_maxdepth = atoi(parse_argv[parse_idx++]);
        /* Consume the option and try to parse the next primary */
        return parse_primary();
    }

    if (strcmp(arg, "-mindepth") == 0) {
        if (parse_idx + 1 >= parse_argc) {
            fprintf(stderr, "%s: -mindepth requires an argument\n", progname);
            exit(1);
        }
        parse_idx++;
        opt_mindepth = atoi(parse_argv[parse_idx++]);
        return parse_primary();
    }

    fprintf(stderr, "%s: unknown predicate '%s'\n", progname, arg);
    exit(1);
    return NULL;
}

static struct expr *parse_not(void)
{
    if (parse_idx >= parse_argc)
        return NULL;

    const char *arg = parse_argv[parse_idx];

    if (strcmp(arg, "!") == 0 || strcmp(arg, "-not") == 0) {
        parse_idx++;
        struct expr *e = expr_alloc(EXPR_NOT);
        e->child = parse_not();
        if (!e->child) {
            fprintf(stderr, "%s: expected expression after '%s'\n",
                    progname, arg);
            exit(1);
        }
        return e;
    }

    return parse_primary();
}

static struct expr *parse_and(void)
{
    struct expr *left = parse_not();
    if (!left)
        return NULL;

    while (parse_idx < parse_argc) {
        const char *arg = parse_argv[parse_idx];

        /* Explicit AND */
        if (strcmp(arg, "-a") == 0 || strcmp(arg, "-and") == 0) {
            parse_idx++;
            struct expr *right = parse_not();
            if (!right) {
                fprintf(stderr, "%s: expected expression after '%s'\n",
                        progname, arg);
                exit(1);
            }
            struct expr *and_node = expr_alloc(EXPR_AND);
            and_node->left = left;
            and_node->right = right;
            left = and_node;
            continue;
        }

        /* Implicit AND: next token is not an OR or close-paren */
        if (strcmp(arg, "-o") == 0 || strcmp(arg, "-or") == 0 ||
            strcmp(arg, ")") == 0)
            break;

        /* Must be another primary — implicit AND */
        struct expr *right = parse_not();
        if (!right)
            break;
        struct expr *and_node = expr_alloc(EXPR_AND);
        and_node->left = left;
        and_node->right = right;
        left = and_node;
    }

    return left;
}

static struct expr *parse_or(void)
{
    struct expr *left = parse_and();
    if (!left)
        return NULL;

    while (parse_idx < parse_argc) {
        const char *arg = parse_argv[parse_idx];

        if (strcmp(arg, "-o") != 0 && strcmp(arg, "-or") != 0)
            break;

        parse_idx++;
        struct expr *right = parse_and();
        if (!right) {
            fprintf(stderr, "%s: expected expression after '%s'\n",
                    progname, arg);
            exit(1);
        }
        struct expr *or_node = expr_alloc(EXPR_OR);
        or_node->left = left;
        or_node->right = right;
        left = or_node;
    }

    return left;
}

/* ------------------------------------------------------------------ */
/* Expression evaluator                                                */
/* ------------------------------------------------------------------ */

/*
 * Evaluate an expression against a file.
 * Returns 1 if true, 0 if false.
 */
static int eval_expr(const struct expr *e, const char *path,
                     const char *name, const struct stat *st)
{
    if (!e)
        return 1;

    switch (e->type) {
    case EXPR_NAME:
        return glob_match(e->u.pattern, name);

    case EXPR_TYPE:
        switch (e->u.filetype) {
        case 'f': return S_ISREG(st->st_mode);
        case 'd': return S_ISDIR(st->st_mode);
        case 'l': return S_ISLNK(st->st_mode);
        case 'b': return S_ISBLK(st->st_mode);
        case 'c': return S_ISCHR(st->st_mode);
        case 'p': return S_ISFIFO(st->st_mode);
        default:  return 0;
        }

    case EXPR_SIZE: {
        long long file_size;
        switch (e->u.size.size_unit) {
        case 'c':
            file_size = (long long)st->st_size;
            break;
        case 'k':
            file_size = ((long long)st->st_size + 1023) / 1024;
            break;
        case 'M':
            file_size = ((long long)st->st_size + 1048575) / 1048576;
            break;
        default: /* 'b': 512-byte blocks */
            file_size = ((long long)st->st_size + 511) / 512;
            break;
        }

        switch (e->u.size.size_cmp) {
        case '+': return file_size > e->u.size.size;
        case '-': return file_size < e->u.size.size;
        default:  return file_size == e->u.size.size;
        }
    }

    case EXPR_NEWER:
        return st->st_mtime > e->u.newer_mtime;

    case EXPR_EMPTY:
        if (S_ISREG(st->st_mode))
            return st->st_size == 0;
        if (S_ISDIR(st->st_mode)) {
            DIR *d = opendir(path);
            if (!d)
                return 0;
            struct dirent *ent;
            int empty = 1;
            while ((ent = readdir(d)) != NULL) {
                if (strcmp(ent->d_name, ".") == 0 ||
                    strcmp(ent->d_name, "..") == 0)
                    continue;
                empty = 0;
                break;
            }
            closedir(d);
            return empty;
        }
        return 0;

    case EXPR_PERM:
        return (st->st_mode & 07777) == e->u.perm;

    case EXPR_PRINT:
        printf("%s\n", path);
        return 1;

    case EXPR_DELETE:
        if (S_ISDIR(st->st_mode)) {
            if (rmdir(path) < 0) {
                fprintf(stderr, "%s: cannot delete '%s': %s\n", progname,
                        path, strerror(errno));
                return 0;
            }
        } else {
            if (unlink(path) < 0) {
                fprintf(stderr, "%s: cannot delete '%s': %s\n", progname,
                        path, strerror(errno));
                return 0;
            }
        }
        return 1;

    case EXPR_EXEC: {
        /* Build argv with {} replaced by path */
        char **argv = malloc((size_t)(e->u.exec.argc + 1) * sizeof(char *));
        if (!argv)
            return 0;
        for (int i = 0; i < e->u.exec.argc; i++) {
            if (strcmp(e->u.exec.argv[i], "{}") == 0)
                argv[i] = (char *)path;
            else
                argv[i] = e->u.exec.argv[i];
        }
        argv[e->u.exec.argc] = NULL;

        pid_t pid = fork();
        if (pid < 0) {
            fprintf(stderr, "%s: fork: %s\n", progname, strerror(errno));
            free(argv);
            return 0;
        }
        if (pid == 0) {
            execvp(argv[0], argv);
            fprintf(stderr, "%s: exec '%s': %s\n", progname, argv[0],
                    strerror(errno));
            _exit(1);
        }
        int status;
        waitpid(pid, &status, 0);
        free(argv);
        return WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }

    case EXPR_AND:
        if (!eval_expr(e->left, path, name, st))
            return 0;
        return eval_expr(e->right, path, name, st);

    case EXPR_OR:
        if (eval_expr(e->left, path, name, st))
            return 1;
        return eval_expr(e->right, path, name, st);

    case EXPR_NOT:
        return !eval_expr(e->child, path, name, st);
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Directory traversal                                                 */
/* ------------------------------------------------------------------ */

static int walk(const char *path, const struct expr *expr, int depth);

/*
 * Build a child path from parent and entry name.
 * Returns a malloc'd string.
 */
static char *build_path(const char *parent, const char *name)
{
    size_t plen = strlen(parent);
    size_t nlen = strlen(name);

    /* Remove trailing slash from parent */
    while (plen > 1 && parent[plen - 1] == '/')
        plen--;

    char *buf = malloc(plen + 1 + nlen + 1);
    if (!buf) {
        fprintf(stderr, "%s: out of memory\n", progname);
        return NULL;
    }

    memcpy(buf, parent, plen);
    buf[plen] = '/';
    memcpy(buf + plen + 1, name, nlen);
    buf[plen + 1 + nlen] = '\0';
    return buf;
}

/*
 * Get the basename of a path.
 */
static const char *path_basename(const char *path)
{
    const char *last = strrchr(path, '/');
    return last ? last + 1 : path;
}

/*
 * Process a single file/directory entry.
 */
static int process_entry(const char *path, const struct expr *expr, int depth)
{
    struct stat st;

    /* Use lstat to not follow symlinks */
    if (lstat(path, &st) < 0) {
        fprintf(stderr, "%s: '%s': %s\n", progname, path, strerror(errno));
        return 1;
    }

    int ret = 0;

    /* Evaluate expression if within mindepth */
    if (depth >= opt_mindepth) {
        int result = eval_expr(expr, path, path_basename(path), &st);
        /* If no explicit action and result is true, default to print */
        if (!has_action && result)
            printf("%s\n", path);
    }

    /* Recurse into directories */
    if (S_ISDIR(st.st_mode)) {
        if (opt_maxdepth >= 0 && depth >= opt_maxdepth)
            return ret;
        ret = walk(path, expr, depth + 1);
    }

    return ret;
}

/*
 * Walk a directory, processing each entry.
 */
static int walk(const char *dirpath, const struct expr *expr, int depth)
{
    DIR *d = opendir(dirpath);
    if (!d) {
        fprintf(stderr, "%s: '%s': %s\n", progname, dirpath,
                strerror(errno));
        return 1;
    }

    int ret = 0;
    struct dirent *ent;

    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        char *child = build_path(dirpath, ent->d_name);
        if (!child) {
            ret = 1;
            break;
        }

        if (process_entry(child, expr, depth) != 0)
            ret = 1;

        free(child);
    }

    closedir(d);
    return ret;
}

/* ------------------------------------------------------------------ */
/* Usage                                                               */
/* ------------------------------------------------------------------ */

static void usage(void)
{
    fprintf(stderr, "Usage: %s [PATH...] [EXPRESSION]\n\n", progname);
    fprintf(stderr, "Search for files in a directory hierarchy.\n\n");
    fprintf(stderr, "Predicates:\n");
    fprintf(stderr, "  -name PATTERN   match filename against glob pattern\n");
    fprintf(stderr, "  -type TYPE      match file type (f,d,l,b,c,p)\n");
    fprintf(stderr, "  -size [+/-]N[c|k|M]  match file size\n");
    fprintf(stderr, "  -newer FILE     newer than FILE's modification time\n");
    fprintf(stderr, "  -empty          empty files or directories\n");
    fprintf(stderr, "  -perm MODE      exact permission match (octal)\n");
    fprintf(stderr, "  -maxdepth N     descend at most N levels\n");
    fprintf(stderr, "  -mindepth N     do not apply tests above depth N\n\n");
    fprintf(stderr, "Actions:\n");
    fprintf(stderr, "  -print          print pathname (default)\n");
    fprintf(stderr, "  -exec CMD {} ;  execute command for each file\n");
    fprintf(stderr, "  -delete         delete matched files\n\n");
    fprintf(stderr, "Operators:\n");
    fprintf(stderr, "  -and / -a       logical AND (default)\n");
    fprintf(stderr, "  -or  / -o       logical OR\n");
    fprintf(stderr, "  -not / !        logical NOT\n");
    fprintf(stderr, "  ( expr )        grouping\n");
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    if (argc >= 2 && strcmp(argv[1], "--help") == 0) {
        usage();
        return 0;
    }

    /*
     * Separate starting paths from expressions.
     * Paths are arguments before the first expression keyword.
     * Expression keywords start with '-', '!', or '('.
     */
    char *paths[256];
    int npaths = 0;
    int expr_start = 1;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (a[0] == '-' || a[0] == '!' || a[0] == '(') {
            expr_start = i;
            break;
        }
        if (npaths < 256)
            paths[npaths++] = argv[i];
        expr_start = i + 1;
    }

    /* Default path is "." */
    if (npaths == 0) {
        paths[0] = ".";
        npaths = 1;
    }

    /* Parse expression */
    parse_argv = argv;
    parse_argc = argc;
    parse_idx = expr_start;

    struct expr *expr = NULL;
    if (parse_idx < parse_argc) {
        expr = parse_or();
        if (parse_idx < parse_argc) {
            fprintf(stderr, "%s: unexpected '%s'\n", progname,
                    parse_argv[parse_idx]);
            return 1;
        }
    }

    /* Process each starting path */
    int ret = 0;
    for (int i = 0; i < npaths; i++) {
        if (process_entry(paths[i], expr, 0) != 0)
            ret = 1;
    }

    expr_free(expr);
    fflush(stdout);
    return ret;
}
