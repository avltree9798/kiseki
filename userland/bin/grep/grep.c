/*
 * Kiseki OS - grep: search for patterns in files
 *
 * Implements a basic regex engine and standard grep flags.
 * Exit status: 0 if match found, 1 if not, 2 on error.
 */

#include <stdint.h>
#include <sys/types.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>

/* ========================================================================
 * Configuration
 * ======================================================================== */

#define MAX_LINE    8192
#define MAX_REGEX   512

/* ========================================================================
 * Regex engine
 * ======================================================================== */

/* Regex node types */
enum {
    RE_LITERAL,     /* Match a literal character */
    RE_DOT,         /* Match any character */
    RE_STAR,        /* Zero or more of previous */
    RE_PLUS,        /* One or more of previous */
    RE_QUEST,       /* Zero or one of previous */
    RE_ANCHOR_BOL,  /* ^ beginning of line */
    RE_ANCHOR_EOL,  /* $ end of line */
    RE_CLASS,       /* Character class [abc] */
    RE_NCLASS,      /* Negated character class [^abc] */
};

/* Character class: bitmap of 256 bits (32 bytes) */
typedef struct {
    uint8_t bits[32];
} charset_t;

static void charset_set(charset_t *cs, int c)
{
    cs->bits[(uint8_t)c >> 3] |= (1 << ((uint8_t)c & 7));
}

static int charset_test(const charset_t *cs, int c)
{
    return (cs->bits[(uint8_t)c >> 3] >> ((uint8_t)c & 7)) & 1;
}

/* Regex node */
typedef struct {
    int     type;
    int     ch;             /* For RE_LITERAL */
    charset_t cset;         /* For RE_CLASS / RE_NCLASS */
} re_node_t;

/* Compiled regex */
typedef struct {
    re_node_t   nodes[MAX_REGEX];
    int         len;
    int         anchored_start; /* Pattern starts with ^ */
} regex_t;

/* Flags */
static int flag_ignore_case;
static int flag_invert;
static int flag_count;
static int flag_list_files;
static int flag_line_numbers;
static int flag_no_filename;
static int flag_recursive;
static int flag_quiet;
static int flag_whole_word;
static int flag_fixed_string;
static int flag_explicit_pattern; /* -e was used */

static int num_files;       /* Number of file arguments */
static int match_found;     /* Global: any match found? */
static int had_error;       /* Global: any error? */

static char *pattern_str;   /* The pattern string */
static regex_t compiled_re; /* Compiled regex */

/* ========================================================================
 * Character helpers
 * ======================================================================== */

static int to_lower(int c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A' + 'a';
    return c;
}

static int is_alnum(int c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}

/* ========================================================================
 * Regex compiler
 * ======================================================================== */

static int re_compile(regex_t *re, const char *pat)
{
    re->len = 0;
    re->anchored_start = 0;

    const char *p = pat;

    while (*p) {
        if (re->len >= MAX_REGEX - 1) {
            fprintf(stderr, "grep: regex too complex\n");
            return -1;
        }

        re_node_t *node = &re->nodes[re->len];
        memset(node, 0, sizeof(*node));

        switch (*p) {
        case '^':
            if (p == pat) {
                node->type = RE_ANCHOR_BOL;
                re->anchored_start = 1;
            } else {
                node->type = RE_LITERAL;
                node->ch = '^';
            }
            p++;
            re->len++;
            break;

        case '$':
            if (*(p + 1) == '\0') {
                node->type = RE_ANCHOR_EOL;
            } else {
                node->type = RE_LITERAL;
                node->ch = '$';
            }
            p++;
            re->len++;
            break;

        case '.':
            node->type = RE_DOT;
            p++;
            re->len++;
            break;

        case '\\':
            p++;
            if (*p == '\0') {
                fprintf(stderr, "grep: trailing backslash\n");
                return -1;
            }
            node->type = RE_LITERAL;
            node->ch = *p;
            p++;
            re->len++;
            break;

        case '[': {
            p++; /* skip '[' */
            int negated = 0;
            if (*p == '^') {
                negated = 1;
                p++;
            }
            memset(&node->cset, 0, sizeof(node->cset));
            /* Handle ] as first char in class */
            if (*p == ']') {
                charset_set(&node->cset, ']');
                p++;
            }
            while (*p && *p != ']') {
                if (*(p + 1) == '-' && *(p + 2) && *(p + 2) != ']') {
                    /* Range a-z */
                    int lo = (uint8_t)*p;
                    int hi = (uint8_t)*(p + 2);
                    if (lo > hi) {
                        int tmp = lo;
                        lo = hi;
                        hi = tmp;
                    }
                    for (int c = lo; c <= hi; c++) {
                        charset_set(&node->cset, c);
                        if (flag_ignore_case) {
                            if (c >= 'a' && c <= 'z')
                                charset_set(&node->cset, c - 32);
                            else if (c >= 'A' && c <= 'Z')
                                charset_set(&node->cset, c + 32);
                        }
                    }
                    p += 3;
                } else if (*p == '\\' && *(p + 1)) {
                    p++;
                    charset_set(&node->cset, (uint8_t)*p);
                    p++;
                } else {
                    charset_set(&node->cset, (uint8_t)*p);
                    if (flag_ignore_case) {
                        int c = (uint8_t)*p;
                        if (c >= 'a' && c <= 'z')
                            charset_set(&node->cset, c - 32);
                        else if (c >= 'A' && c <= 'Z')
                            charset_set(&node->cset, c + 32);
                    }
                    p++;
                }
            }
            if (*p == ']')
                p++;
            node->type = negated ? RE_NCLASS : RE_CLASS;
            re->len++;
            break;
        }

        case '*':
        case '+':
        case '?':
            /* Quantifier: modify previous node */
            if (re->len == 0) {
                /* Treat as literal at start */
                node->type = RE_LITERAL;
                node->ch = *p;
                p++;
                re->len++;
            } else {
                int qtype;
                if (*p == '*') qtype = RE_STAR;
                else if (*p == '+') qtype = RE_PLUS;
                else qtype = RE_QUEST;

                /* Insert quantifier node after the previous one */
                /* We shift the previous node into a quantifier wrapper
                 * by using a simple scheme: the quantifier node stores
                 * the index of what it quantifies (always len-1).
                 * Actually, simpler: just mark with type. The match
                 * engine handles it by looking at nodes[i-1]. */
                node->type = qtype;
                p++;
                re->len++;
            }
            break;

        default:
            node->type = RE_LITERAL;
            node->ch = *p;
            p++;
            re->len++;
            break;
        }
    }

    return 0;
}

/* ========================================================================
 * Regex matcher (backtracking NFA)
 * ======================================================================== */

/* Match a single node against character c at position in the string.
 * Returns 1 if the node matches the character. */
static int node_match_char(const re_node_t *node, int c)
{
    switch (node->type) {
    case RE_LITERAL:
        if (flag_ignore_case)
            return to_lower(node->ch) == to_lower(c);
        return node->ch == c;
    case RE_DOT:
        return c != '\0'; /* Dot matches everything except NUL */
    case RE_CLASS:
        if (flag_ignore_case) {
            return charset_test(&node->cset, (uint8_t)c) ||
                   charset_test(&node->cset, (uint8_t)to_lower(c)) ||
                   charset_test(&node->cset, (uint8_t)(c >= 'a' && c <= 'z' ? c - 32 : c));
        }
        return charset_test(&node->cset, (uint8_t)c);
    case RE_NCLASS:
        if (c == '\0')
            return 0;
        if (flag_ignore_case) {
            return !(charset_test(&node->cset, (uint8_t)c) ||
                     charset_test(&node->cset, (uint8_t)to_lower(c)) ||
                     charset_test(&node->cset, (uint8_t)(c >= 'a' && c <= 'z' ? c - 32 : c)));
        }
        return !charset_test(&node->cset, (uint8_t)c);
    default:
        return 0;
    }
}

/* Recursive match: try to match regex nodes[ni..] against string s.
 * Returns pointer past last matched char, or NULL on failure. */
static const char *re_match_here(const regex_t *re, int ni, const char *s)
{
    while (ni < re->len) {
        const re_node_t *node = &re->nodes[ni];

        /* Check if next node is a quantifier */
        if (ni + 1 < re->len) {
            int next_type = re->nodes[ni + 1].type;

            if (next_type == RE_STAR) {
                /* Greedy match: try as many as possible, then backtrack */
                const char *sp = s;
                int count = 0;

                /* Count max matches */
                while (*sp && node_match_char(node, *sp)) {
                    sp++;
                    count++;
                }

                /* Try from max down to 0 */
                for (int i = count; i >= 0; i--) {
                    const char *result = re_match_here(re, ni + 2, s + i);
                    if (result)
                        return result;
                }
                return NULL;
            }

            if (next_type == RE_PLUS) {
                /* One or more: must match at least once */
                const char *sp = s;
                int count = 0;

                while (*sp && node_match_char(node, *sp)) {
                    sp++;
                    count++;
                }

                if (count == 0)
                    return NULL;

                for (int i = count; i >= 1; i--) {
                    const char *result = re_match_here(re, ni + 2, s + i);
                    if (result)
                        return result;
                }
                return NULL;
            }

            if (next_type == RE_QUEST) {
                /* Zero or one: try with one first, then zero */
                if (*s && node_match_char(node, *s)) {
                    const char *result = re_match_here(re, ni + 2, s + 1);
                    if (result)
                        return result;
                }
                return re_match_here(re, ni + 2, s);
            }
        }

        /* Not followed by quantifier */
        if (node->type == RE_ANCHOR_BOL) {
            /* Already handled by caller; skip */
            ni++;
            continue;
        }

        if (node->type == RE_ANCHOR_EOL) {
            if (*s == '\0')
                return s;
            return NULL;
        }

        if (node->type == RE_STAR || node->type == RE_PLUS ||
            node->type == RE_QUEST) {
            /* Orphan quantifier (shouldn't happen with valid regex) */
            ni++;
            continue;
        }

        /* Simple character match */
        if (*s == '\0')
            return NULL;

        if (!node_match_char(node, *s))
            return NULL;

        s++;
        ni++;
    }

    return s; /* All nodes matched */
}

/* Try to match the regex against string s.
 * Returns 1 if the string matches. */
static int re_match(const regex_t *re, const char *s)
{
    if (re->len == 0)
        return 1; /* Empty regex matches everything */

    int start_ni = 0;

    /* If anchored at start, only try at position 0 */
    if (re->anchored_start) {
        start_ni = 1; /* Skip the BOL node */
        return re_match_here(re, start_ni, s) != NULL;
    }

    /* Try matching at every position */
    const char *p = s;
    do {
        if (re_match_here(re, start_ni, p) != NULL)
            return 1;
    } while (*p++ != '\0');

    return 0;
}

/* ========================================================================
 * Fixed string matching
 * ======================================================================== */

static int fixed_match(const char *text, const char *pat)
{
    size_t plen = strlen(pat);

    if (plen == 0)
        return 1;

    if (flag_ignore_case) {
        size_t tlen = strlen(text);
        if (plen > tlen)
            return 0;
        for (size_t i = 0; i <= tlen - plen; i++) {
            size_t j;
            for (j = 0; j < plen; j++) {
                if (to_lower((uint8_t)text[i + j]) != to_lower((uint8_t)pat[j]))
                    break;
            }
            if (j == plen)
                return 1;
        }
        return 0;
    } else {
        return strstr(text, pat) != NULL;
    }
}

/* ========================================================================
 * Whole-word matching wrapper
 * ======================================================================== */

static int match_line(const char *line)
{
    if (flag_fixed_string) {
        if (!flag_whole_word)
            return fixed_match(line, pattern_str);

        /* Whole word: find each occurrence of pattern and check boundaries */
        size_t plen = strlen(pattern_str);
        const char *p = line;
        while (*p) {
            const char *found;
            if (flag_ignore_case) {
                /* Manual search */
                found = NULL;
                size_t tlen = strlen(p);
                if (plen <= tlen) {
                    for (size_t i = 0; i <= tlen - plen; i++) {
                        size_t j;
                        for (j = 0; j < plen; j++) {
                            if (to_lower((uint8_t)p[i + j]) != to_lower((uint8_t)pattern_str[j]))
                                break;
                        }
                        if (j == plen) {
                            found = p + i;
                            break;
                        }
                    }
                }
            } else {
                found = strstr(p, pattern_str);
            }

            if (!found)
                return 0;

            /* Check word boundaries */
            int at_start = (found == line) || !is_alnum((uint8_t)*(found - 1));
            int at_end = !is_alnum((uint8_t)*(found + plen));
            if (at_start && at_end)
                return 1;

            p = found + 1;
        }
        return 0;
    }

    /* Regex match */
    if (!flag_whole_word)
        return re_match(&compiled_re, line);

    /* Whole word with regex: try at each word boundary */
    const char *p = line;
    do {
        int at_start = (p == line) || !is_alnum((uint8_t)*(p - 1));
        if (at_start) {
            const char *end = re_match_here(&compiled_re,
                compiled_re.anchored_start ? 1 : 0, p);
            if (end) {
                int at_end = !is_alnum((uint8_t)*end);
                if (at_end)
                    return 1;
            }
        }
    } while (*p++ != '\0');

    return 0;
}

/* ========================================================================
 * Strip trailing newline
 * ======================================================================== */

static void chomp(char *line)
{
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
        line[--len] = '\0';
}

/* ========================================================================
 * Process a single file/stream
 * ======================================================================== */

static void grep_file(FILE *fp, const char *filename)
{
    char line[MAX_LINE];
    int lineno = 0;
    int count = 0;
    int show_filename = (!flag_no_filename && num_files > 1) ||
                        (!flag_no_filename && flag_recursive);

    while (fgets(line, sizeof(line), fp) != NULL) {
        lineno++;
        chomp(line);

        int matched = match_line(line);

        if (flag_invert)
            matched = !matched;

        if (matched) {
            match_found = 1;
            count++;

            if (flag_quiet)
                return;

            if (flag_list_files) {
                printf("%s\n", filename ? filename : "(standard input)");
                return;
            }

            if (!flag_count) {
                if (show_filename && filename)
                    printf("%s:", filename);
                if (flag_line_numbers)
                    printf("%d:", lineno);
                printf("%s\n", line);
            }
        }
    }

    if (flag_count) {
        if (show_filename && filename)
            printf("%s:", filename);
        printf("%d\n", count);
    }
}

/* ========================================================================
 * Recursive directory processing
 * ======================================================================== */

static void grep_path(const char *path);

static void grep_dir(const char *dirpath)
{
    DIR *dp = opendir(dirpath);
    if (!dp) {
        fprintf(stderr, "grep: %s: %s\n", dirpath, strerror(errno));
        had_error = 1;
        return;
    }

    struct dirent *ent;
    while ((ent = readdir(dp)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        char fullpath[PATH_MAX];
        size_t dlen = strlen(dirpath);
        size_t nlen = strlen(ent->d_name);

        if (dlen + 1 + nlen + 1 > PATH_MAX)
            continue;

        strcpy(fullpath, dirpath);
        if (dlen > 0 && dirpath[dlen - 1] != '/') {
            fullpath[dlen] = '/';
            fullpath[dlen + 1] = '\0';
        }
        strcat(fullpath, ent->d_name);

        grep_path(fullpath);
    }

    closedir(dp);
}

static void grep_path(const char *path)
{
    struct stat st;
    if (lstat(path, &st) < 0) {
        fprintf(stderr, "grep: %s: %s\n", path, strerror(errno));
        had_error = 1;
        return;
    }

    if (S_ISDIR(st.st_mode)) {
        if (flag_recursive) {
            grep_dir(path);
        } else {
            fprintf(stderr, "grep: %s: Is a directory\n", path);
            had_error = 1;
        }
        return;
    }

    if (!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode))
        return;

    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "grep: %s: %s\n", path, strerror(errno));
        had_error = 1;
        return;
    }

    grep_file(fp, path);
    fclose(fp);
}

/* ========================================================================
 * Usage
 * ======================================================================== */

static void usage(void)
{
    fprintf(stderr,
        "Usage: grep [OPTIONS] PATTERN [FILE...]\n"
        "Search for PATTERN in each FILE or standard input.\n\n"
        "Options:\n"
        "  -i       Ignore case distinctions\n"
        "  -v       Invert match (select non-matching lines)\n"
        "  -c       Print count of matching lines\n"
        "  -l       Print only filenames with matches\n"
        "  -n       Print line numbers\n"
        "  -h       Suppress filename prefix\n"
        "  -r, -R   Recursively search directories\n"
        "  -e PAT   Use PAT as pattern\n"
        "  -q       Quiet mode (exit status only)\n"
        "  -w       Match whole words only\n"
        "  -F       Fixed string match (no regex)\n"
    );
}

/* ========================================================================
 * Main
 * ======================================================================== */

int main(int argc, char *argv[])
{
    /* Parse options manually (no getopt) */
    int argi = 1;
    pattern_str = NULL;

    if (argi < argc && strcmp(argv[argi], "--help") == 0) {
        printf(
            "Usage: grep [OPTIONS] PATTERN [FILE...]\n"
            "Search for PATTERN in each FILE or standard input.\n\n"
            "Options:\n"
            "  -i       Ignore case distinctions\n"
            "  -v       Invert match (select non-matching lines)\n"
            "  -c       Print count of matching lines\n"
            "  -l       Print only filenames with matches\n"
            "  -n       Print line numbers\n"
            "  -h       Suppress filename prefix\n"
            "  -r, -R   Recursively search directories\n"
            "  -e PAT   Use PAT as pattern\n"
            "  -q       Quiet mode (exit status only)\n"
            "  -w       Match whole words only\n"
            "  -F       Fixed string match (no regex)\n"
            "  --help   Display this help and exit\n"
        );
        exit(0);
    }

    while (argi < argc && argv[argi][0] == '-' && argv[argi][1] != '\0') {
        const char *arg = argv[argi];

        /* Handle "--" */
        if (strcmp(arg, "--") == 0) {
            argi++;
            break;
        }

        /* Walk through option characters */
        for (int j = 1; arg[j]; j++) {
            switch (arg[j]) {
            case 'i': flag_ignore_case = 1; break;
            case 'v': flag_invert = 1; break;
            case 'c': flag_count = 1; break;
            case 'l': flag_list_files = 1; break;
            case 'n': flag_line_numbers = 1; break;
            case 'h': flag_no_filename = 1; break;
            case 'r': /* fall through */
            case 'R': flag_recursive = 1; break;
            case 'q': flag_quiet = 1; break;
            case 'w': flag_whole_word = 1; break;
            case 'F': flag_fixed_string = 1; break;
            case 'e':
                flag_explicit_pattern = 1;
                /* Pattern follows: rest of this arg or next arg */
                if (arg[j + 1]) {
                    pattern_str = strdup(&arg[j + 1]);
                } else if (argi + 1 < argc) {
                    argi++;
                    pattern_str = strdup(argv[argi]);
                } else {
                    fprintf(stderr, "grep: option -e requires an argument\n");
                    exit(2);
                }
                goto next_arg; /* Done with this arg string */
            default:
                fprintf(stderr, "grep: invalid option -- '%c'\n", arg[j]);
                usage();
                exit(2);
            }
        }
next_arg:
        argi++;
    }

    /* Get pattern */
    if (!pattern_str) {
        if (argi >= argc) {
            fprintf(stderr, "grep: missing pattern\n");
            usage();
            exit(2);
        }
        pattern_str = strdup(argv[argi]);
        argi++;
    }

    /* Compile regex if not fixed string mode */
    if (!flag_fixed_string) {
        if (re_compile(&compiled_re, pattern_str) < 0)
            exit(2);
    }

    /* Remaining args are files */
    num_files = argc - argi;

    if (num_files == 0) {
        /* Read from stdin */
        grep_file(stdin, NULL);
    } else {
        for (int i = argi; i < argc; i++) {
            if (strcmp(argv[i], "-") == 0)
                grep_file(stdin, "(standard input)");
            else
                grep_path(argv[i]);
        }
    }

    free(pattern_str);

    if (had_error)
        exit(2);
    exit(match_found ? 0 : 1);
}
