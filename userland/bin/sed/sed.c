/*
 * sed - stream editor
 *
 * Kiseki OS coreutils
 *
 * Implements: s, d, p, q, a, i, c, y, =, n, w commands
 * Addresses: line number, $, /regex/, addr1,addr2 ranges
 * Flags: -n, -e, -i, -f
 * Built-in basic regex engine (., *, +, ?, ^, $, [...], \, grouping)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

static const char *progname = "sed";

/* ========================================================================
 * Regex Engine
 * ======================================================================== */

#define RE_MAX_GROUPS   10
#define RE_MAX_CODE     4096
#define RE_MAX_CLASSES  32

/* Compiled regex opcodes */
enum {
    RE_LITERAL,     /* match exact char */
    RE_DOT,         /* match any char (except newline) */
    RE_CLASS,       /* character class [...]  */
    RE_NCLASS,      /* negated class [^...] */
    RE_BOL,         /* ^ */
    RE_EOL,         /* $ */
    RE_STAR,        /* greedy * */
    RE_PLUS,        /* greedy + */
    RE_QUEST,       /* ? */
    RE_STAR_LAZY,   /* *? */
    RE_PLUS_LAZY,   /* +? */
    RE_QUEST_LAZY,  /* ?? */
    RE_SAVE_START,  /* start of group capture */
    RE_SAVE_END,    /* end of group capture */
    RE_JMP,         /* unconditional jump (offset) */
    RE_SPLIT,       /* split: try both paths */
    RE_MATCH,       /* successful match */
};

typedef struct {
    unsigned char code[RE_MAX_CODE];
    int codelen;
    /* Character class storage */
    unsigned char classes[RE_MAX_CLASSES][32]; /* 256-bit bitmap */
    int nclasses;
    int ngroups;
    int flags;  /* RE_FLAG_* */
} regex_t;

#define RE_FLAG_ICASE  1

typedef struct {
    const char *start;
    const char *end;
} re_group_t;

typedef struct {
    re_group_t groups[RE_MAX_GROUPS];
    int ngroups;
} re_match_t;

static int re_tolower(int c)
{
    if (c >= 'A' && c <= 'Z')
        return c + ('a' - 'A');
    return c;
}

static int re_toupper(int c)
{
    if (c >= 'a' && c <= 'z')
        return c - ('a' - 'A');
    return c;
}

static void class_set(unsigned char *bitmap, int c)
{
    bitmap[c / 8] |= (unsigned char)(1 << (c % 8));
}

static int class_test(const unsigned char *bitmap, int c)
{
    return (bitmap[c / 8] >> (c % 8)) & 1;
}

static void emit(regex_t *re, int byte)
{
    if (re->codelen < RE_MAX_CODE)
        re->code[re->codelen++] = (unsigned char)byte;
}

static void emit2(regex_t *re, int b1, int b2)
{
    emit(re, b1);
    emit(re, b2);
}

/* Parse a character class [...] and store in the class bitmap array.
 * Returns pointer past the closing ']'. */
static const char *parse_class(const char *p, regex_t *re, int *cls_idx)
{
    if (re->nclasses >= RE_MAX_CLASSES)
        return p;

    *cls_idx = re->nclasses;
    unsigned char *bm = re->classes[re->nclasses++];
    memset(bm, 0, 32);

    int negate = 0;
    if (*p == '^') {
        negate = 1;
        p++;
    }

    /* First char (or after ^) can be ] literally */
    int first = 1;
    while (*p && (*p != ']' || first)) {
        first = 0;
        int c = (unsigned char)*p;

        if (p[1] == '-' && p[2] && p[2] != ']') {
            /* Range a-z */
            int lo = c;
            int hi = (unsigned char)p[2];
            if (lo > hi) { int t = lo; lo = hi; hi = t; }
            for (int i = lo; i <= hi; i++)
                class_set(bm, i);
            p += 3;
        } else if (*p == '\\' && p[1]) {
            p++;
            class_set(bm, (unsigned char)*p);
            p++;
        } else {
            class_set(bm, c);
            p++;
        }
    }

    if (negate) {
        for (int i = 0; i < 32; i++)
            bm[i] = ~bm[i];
        /* Don't match NUL */
        bm[0] &= ~1;
    }

    if (*p == ']')
        p++;

    return p;
}

/* Compile regex pattern to bytecode. Returns 0 on success. */
static int re_compile(regex_t *re, const char *pattern, int flags)
{
    memset(re, 0, sizeof(*re));
    re->flags = flags;

    const char *p = pattern;
    int group_stack[RE_MAX_GROUPS];
    int group_depth = 0;
    int group_count = 0;

    /* We compile atoms and handle quantifiers inline. */
    while (*p) {
        int atom_start = re->codelen;

        switch (*p) {
        case '^':
            emit(re, RE_BOL);
            p++;
            break;

        case '$':
            emit(re, RE_EOL);
            p++;
            break;

        case '.':
            emit(re, RE_DOT);
            p++;
            break;

        case '[': {
            p++; /* skip [ */
            int cls_idx;
            p = parse_class(p, re, &cls_idx);
            /* Check if negated was stored */
            /* We used nclass bit in the bitmap itself */
            emit2(re, RE_CLASS, cls_idx);
            break;
        }

        case '\\':
            p++;
            if (*p == '(' ) {
                /* Group start */
                if (group_count < RE_MAX_GROUPS) {
                    emit2(re, RE_SAVE_START, group_count);
                    group_stack[group_depth++] = group_count;
                    group_count++;
                }
                p++;
                continue;
            } else if (*p == ')') {
                /* Group end */
                if (group_depth > 0) {
                    group_depth--;
                    emit2(re, RE_SAVE_END, group_stack[group_depth]);
                }
                p++;
                continue;
            } else if (*p >= '1' && *p <= '9') {
                /* Backreference in pattern - we just match the literal
                 * for simplicity in the regex engine; full backrefs
                 * in replacement handled separately */
                emit2(re, RE_LITERAL, (unsigned char)*p);
                p++;
                break;
            } else if (*p == 'n') {
                emit2(re, RE_LITERAL, '\n');
                p++;
                break;
            } else if (*p == 't') {
                emit2(re, RE_LITERAL, '\t');
                p++;
                break;
            } else if (*p) {
                emit2(re, RE_LITERAL, (unsigned char)*p);
                p++;
                break;
            }
            break;

        case '*':
        case '+':
        case '?':
            /* Quantifier without atom - treat as literal */
            emit2(re, RE_LITERAL, (unsigned char)*p);
            p++;
            break;

        default:
            emit2(re, RE_LITERAL, (unsigned char)*p);
            p++;
            break;
        }

        /* Check for quantifier after atom */
        if (*p == '*' || *p == '+' || *p == '?') {
            int atom_len = re->codelen - atom_start;
            unsigned char atom[RE_MAX_CODE];
            memcpy(atom, re->code + atom_start, (size_t)atom_len);
            re->codelen = atom_start;

            if (*p == '*') {
                /* SPLIT -> atom -> JMP back */
                int split_pos = re->codelen;
                emit(re, RE_SPLIT);
                emit(re, 0); /* placeholder: offset to after JMP */
                emit(re, 0);
                int body_start = re->codelen;
                for (int i = 0; i < atom_len; i++)
                    emit(re, atom[i]);
                emit(re, RE_JMP);
                /* jump back to split */
                int jmp_target = split_pos - (re->codelen + 2);
                emit(re, (jmp_target >> 8) & 0xFF);
                emit(re, jmp_target & 0xFF);
                /* patch split to skip to here */
                int skip = re->codelen - body_start;
                re->code[split_pos + 1] = (unsigned char)((skip >> 8) & 0xFF);
                re->code[split_pos + 2] = (unsigned char)(skip & 0xFF);
            } else if (*p == '+') {
                /* atom -> SPLIT back */
                for (int i = 0; i < atom_len; i++)
                    emit(re, atom[i]);
                emit(re, RE_SPLIT);
                /* offset = negative to go back to atom */
                int back = atom_start - (re->codelen + 2);
                emit(re, (back >> 8) & 0xFF);
                emit(re, back & 0xFF);
            } else { /* ? */
                /* SPLIT -> atom */
                emit(re, RE_SPLIT);
                emit(re, 0);
                emit(re, 0);
                int body_start = re->codelen;
                for (int i = 0; i < atom_len; i++)
                    emit(re, atom[i]);
                int skip = re->codelen - body_start;
                re->code[body_start - 2] = (unsigned char)((skip >> 8) & 0xFF);
                re->code[body_start - 1] = (unsigned char)(skip & 0xFF);
            }
            p++;
        }
    }

    emit(re, RE_MATCH);
    re->ngroups = group_count;
    return 0;
}

/* Recursive match at a given position in the bytecode and input */
static int re_exec_inner(const regex_t *re, int pc, const char *sp,
                         const char *input_start, const char *input_end,
                         re_group_t *groups, int depth)
{
    if (depth > 1000)
        return 0;

    while (pc < re->codelen) {
        int op = re->code[pc];

        switch (op) {
        case RE_MATCH:
            return 1;

        case RE_LITERAL: {
            int expected = re->code[pc + 1];
            if (sp >= input_end)
                return 0;
            int actual = (unsigned char)*sp;
            if (re->flags & RE_FLAG_ICASE) {
                if (re_tolower(actual) != re_tolower(expected))
                    return 0;
            } else {
                if (actual != expected)
                    return 0;
            }
            sp++;
            pc += 2;
            break;
        }

        case RE_DOT:
            if (sp >= input_end || *sp == '\n')
                return 0;
            sp++;
            pc++;
            break;

        case RE_CLASS:
        case RE_NCLASS: {
            if (sp >= input_end)
                return 0;
            int cls_idx = re->code[pc + 1];
            int c = (unsigned char)*sp;
            if (re->flags & RE_FLAG_ICASE) {
                /* Test both cases */
                int cl = re_tolower(c);
                int cu = re_toupper(c);
                int match = class_test(re->classes[cls_idx], cl) ||
                            class_test(re->classes[cls_idx], cu);
                if (!match)
                    return 0;
            } else {
                if (!class_test(re->classes[cls_idx], c))
                    return 0;
            }
            sp++;
            pc += 2;
            break;
        }

        case RE_BOL:
            if (sp != input_start && (sp == input_end || sp[-1] != '\n'))
                return 0;
            pc++;
            break;

        case RE_EOL:
            if (sp < input_end && *sp != '\n' && *sp != '\0')
                return 0;
            pc++;
            break;

        case RE_SPLIT: {
            int offset = (signed char)re->code[pc + 1];
            offset = (offset << 8) | (re->code[pc + 2] & 0xFF);
            /* Try primary path first (pc + 3), then alternate (pc + 3 + offset) */
            re_group_t saved[RE_MAX_GROUPS];
            memcpy(saved, groups, sizeof(saved));
            if (re_exec_inner(re, pc + 3, sp, input_start, input_end,
                              groups, depth + 1))
                return 1;
            memcpy(groups, saved, sizeof(saved));
            if (re_exec_inner(re, pc + 3 + offset, sp, input_start,
                              input_end, groups, depth + 1))
                return 1;
            return 0;
        }

        case RE_JMP: {
            int offset = (signed char)re->code[pc + 1];
            offset = (offset << 8) | (re->code[pc + 2] & 0xFF);
            pc = pc + 3 + offset;
            break;
        }

        case RE_SAVE_START: {
            int grp = re->code[pc + 1];
            const char *old = groups[grp].start;
            groups[grp].start = sp;
            if (re_exec_inner(re, pc + 2, sp, input_start, input_end,
                              groups, depth + 1))
                return 1;
            groups[grp].start = old;
            return 0;
        }

        case RE_SAVE_END: {
            int grp = re->code[pc + 1];
            const char *old = groups[grp].end;
            groups[grp].end = sp;
            if (re_exec_inner(re, pc + 2, sp, input_start, input_end,
                              groups, depth + 1))
                return 1;
            groups[grp].end = old;
            return 0;
        }

        default:
            return 0;
        }
    }
    return 0;
}

/* Execute regex against string. Returns 1 on match, fills match info. */
static int __attribute__((unused)) re_exec(const regex_t *re, const char *str, re_match_t *match)
{
    int len = (int)strlen(str);
    const char *end = str + len;
    re_group_t groups[RE_MAX_GROUPS];
    memset(groups, 0, sizeof(groups));

    /* Check if pattern is anchored at start */
    int anchored = (re->codelen > 0 && re->code[0] == RE_BOL);

    for (const char *sp = str; sp <= end; sp++) {
        memset(groups, 0, sizeof(groups));
        groups[0].start = sp;

        if (re_exec_inner(re, 0, sp, str, end, groups, 0)) {
            groups[0].end = sp; /* Will be set by traversal */
            /* Find end of match - walk the bytecode result */
            /* Actually, we need to find where sp ended up. Let's use a
             * different approach: track sp through the match. */
            /* Re-run saving the final sp by using groups[0] as full match */
            /* For the full match, we wrap: SAVE_START 0, <pattern>, SAVE_END 0 */
            /* Actually let's just search for the end by trying longest match */

            /* Find match end: try each position from end of string backward */
            for (const char *ep = end; ep >= sp; ep--) {
                memset(groups, 0, sizeof(groups));
                groups[0].start = sp;
                groups[0].end = ep;
                /* We need to properly track the end position */
                if (re_exec_inner(re, 0, sp, str, end, groups, 0)) {
                    /* Find actual end - the maximum sp reached */
                    if (match) {
                        match->ngroups = re->ngroups + 1;
                        match->groups[0].start = sp;
                        match->groups[0].end = ep;
                        for (int i = 1; i < RE_MAX_GROUPS; i++)
                            match->groups[i] = groups[i];
                    }
                    return 1;
                }
            }

            /* Fallback: zero-length match at sp */
            if (match) {
                match->ngroups = re->ngroups + 1;
                match->groups[0].start = sp;
                match->groups[0].end = sp;
                for (int i = 1; i < RE_MAX_GROUPS; i++)
                    match->groups[i] = groups[i];
            }
            return 1;
        }

        if (anchored)
            break;
    }
    return 0;
}

/* Execute regex, but start searching from a given offset. Fills match. */
__attribute__((unused))
static int re_exec_from(const regex_t *re, const char *str, const char *from,
                        re_match_t *match)
{
    const char *end = str + strlen(str);
    re_group_t groups[RE_MAX_GROUPS];

    int anchored = (re->codelen > 0 && re->code[0] == RE_BOL);

    for (const char *sp = from; sp <= end; sp++) {
        memset(groups, 0, sizeof(groups));

        if (re_exec_inner(re, 0, sp, str, end, groups, 0)) {
            /* Find longest match from sp */
            for (const char *ep = end; ep >= sp; ep--) {
                memset(groups, 0, sizeof(groups));
                if (re_exec_inner(re, 0, sp, str, end, groups, 0)) {
                    /* Check this actually matches up to ep */
                    /* We need to verify that the match consumes up to ep */
                    /* Simplification: accept first successful match end */
                    if (match) {
                        match->ngroups = re->ngroups + 1;
                        match->groups[0].start = sp;
                        match->groups[0].end = ep;
                        for (int i = 1; i < RE_MAX_GROUPS; i++)
                            match->groups[i] = groups[i];
                    }
                    return 1;
                }
            }
            /* Zero length match */
            if (match) {
                match->ngroups = re->ngroups + 1;
                match->groups[0].start = sp;
                match->groups[0].end = sp;
                for (int i = 1; i < RE_MAX_GROUPS; i++)
                    match->groups[i] = groups[i];
            }
            return 1;
        }

        if (anchored)
            break;
    }
    return 0;
}

/* Better approach: a simple NFA-based match that tracks the final position.
 * Let's replace the above with a cleaner recursive matcher. */

/* Simple recursive regex match. Returns pointer past match, or NULL. */
static const char *re_match_here(const regex_t *re, int pc, const char *sp,
                                 const char *start, const char *end,
                                 re_group_t *groups, int depth);

static const char *re_match_here(const regex_t *re, int pc, const char *sp,
                                 const char *start, const char *end,
                                 re_group_t *groups, int depth)
{
    if (depth > 2000)
        return NULL;

    while (pc < re->codelen) {
        int op = re->code[pc];

        switch (op) {
        case RE_MATCH:
            return sp;

        case RE_LITERAL: {
            if (sp >= end)
                return NULL;
            int expected = re->code[pc + 1];
            int actual = (unsigned char)*sp;
            if (re->flags & RE_FLAG_ICASE) {
                if (re_tolower(actual) != re_tolower(expected))
                    return NULL;
            } else {
                if (actual != expected)
                    return NULL;
            }
            sp++;
            pc += 2;
            break;
        }

        case RE_DOT:
            if (sp >= end || *sp == '\n')
                return NULL;
            sp++;
            pc++;
            break;

        case RE_CLASS: {
            if (sp >= end)
                return NULL;
            int cls_idx = re->code[pc + 1];
            int c = (unsigned char)*sp;
            if (re->flags & RE_FLAG_ICASE) {
                if (!class_test(re->classes[cls_idx], re_tolower(c)) &&
                    !class_test(re->classes[cls_idx], re_toupper(c)))
                    return NULL;
            } else {
                if (!class_test(re->classes[cls_idx], c))
                    return NULL;
            }
            sp++;
            pc += 2;
            break;
        }

        case RE_BOL:
            if (sp != start && (sp <= start || sp[-1] != '\n'))
                return NULL;
            pc++;
            break;

        case RE_EOL:
            if (sp < end && *sp != '\n' && *sp != '\0')
                return NULL;
            pc++;
            break;

        case RE_SPLIT: {
            int offset = (signed char)re->code[pc + 1];
            offset = (offset << 8) | (re->code[pc + 2] & 0xFF);
            /* Try primary first, then alternate */
            re_group_t saved[RE_MAX_GROUPS];
            memcpy(saved, groups, sizeof(saved));
            const char *r = re_match_here(re, pc + 3, sp, start, end,
                                          groups, depth + 1);
            if (r)
                return r;
            memcpy(groups, saved, sizeof(saved));
            return re_match_here(re, pc + 3 + offset, sp, start, end,
                                 groups, depth + 1);
        }

        case RE_JMP: {
            int offset = (signed char)re->code[pc + 1];
            offset = (offset << 8) | (re->code[pc + 2] & 0xFF);
            pc = pc + 3 + offset;
            break;
        }

        case RE_SAVE_START: {
            int grp = re->code[pc + 1];
            const char *old = groups[grp].start;
            groups[grp].start = sp;
            const char *r = re_match_here(re, pc + 2, sp, start, end,
                                          groups, depth + 1);
            if (r)
                return r;
            groups[grp].start = old;
            return NULL;
        }

        case RE_SAVE_END: {
            int grp = re->code[pc + 1];
            const char *old = groups[grp].end;
            groups[grp].end = sp;
            const char *r = re_match_here(re, pc + 2, sp, start, end,
                                          groups, depth + 1);
            if (r)
                return r;
            groups[grp].end = old;
            return NULL;
        }

        default:
            return NULL;
        }
    }
    return NULL;
}

/* Search for regex in string. Returns 1 on match, sets match_start/end. */
static int regex_search(const regex_t *re, const char *str,
                        const char **match_start, const char **match_end,
                        re_group_t *groups)
{
    int len = (int)strlen(str);
    const char *end = str + len;
    int anchored = (re->codelen > 0 && re->code[0] == RE_BOL);
    re_group_t local_groups[RE_MAX_GROUPS];

    for (const char *sp = str; sp <= end; sp++) {
        memset(local_groups, 0, sizeof(local_groups));
        const char *ep = re_match_here(re, 0, sp, str, end, local_groups, 0);
        if (ep) {
            if (match_start)
                *match_start = sp;
            if (match_end)
                *match_end = ep;
            if (groups)
                memcpy(groups, local_groups, sizeof(local_groups));
            return 1;
        }
        if (anchored)
            break;
    }
    return 0;
}

/* Search from a specific starting position */
static int regex_search_from(const regex_t *re, const char *str,
                             const char *from,
                             const char **match_start, const char **match_end,
                             re_group_t *groups)
{
    int len = (int)strlen(str);
    const char *end = str + len;
    int anchored = (re->codelen > 0 && re->code[0] == RE_BOL);
    re_group_t local_groups[RE_MAX_GROUPS];

    for (const char *sp = from; sp <= end; sp++) {
        memset(local_groups, 0, sizeof(local_groups));
        const char *ep = re_match_here(re, 0, sp, str, end, local_groups, 0);
        if (ep) {
            if (match_start)
                *match_start = sp;
            if (match_end)
                *match_end = ep;
            if (groups)
                memcpy(groups, local_groups, sizeof(local_groups));
            return 1;
        }
        if (anchored)
            break;
    }
    return 0;
}

/* Test if regex matches the string (anywhere) */
static int regex_matches(const regex_t *re, const char *str)
{
    return regex_search(re, str, NULL, NULL, NULL);
}


/* ========================================================================
 * Sed Data Structures
 * ======================================================================== */

#define MAX_COMMANDS    1024
#define MAX_SCRIPTS     64
#define LINE_SIZE       65536
#define MAX_WFILES      16

/* Address types */
enum {
    ADDR_NONE,
    ADDR_LINE,
    ADDR_LAST,       /* $ */
    ADDR_REGEX,
};

typedef struct {
    int type;
    int line;
    regex_t regex;
} sed_addr_t;

/* Command types */
enum {
    CMD_SUB,        /* s */
    CMD_DELETE,     /* d */
    CMD_PRINT,     /* p */
    CMD_QUIT,      /* q */
    CMD_APPEND,    /* a */
    CMD_INSERT,    /* i */
    CMD_CHANGE,    /* c */
    CMD_XLATE,     /* y */
    CMD_LINENUM,   /* = */
    CMD_NEXT,      /* n */
    CMD_WRITE,     /* w */
    CMD_NOOP,
};

/* Substitution data */
typedef struct {
    regex_t regex;
    char *replacement;
    int global;         /* g flag */
    int print;          /* p flag */
    int nth;            /* Nth occurrence (0 = not set) */
    int icase;          /* i flag */
    char *wfile;        /* w file */
} sub_data_t;

/* Transliterate data */
typedef struct {
    char src[256];
    char dst[256];
    int len;
} xlate_data_t;

typedef struct {
    int type;
    sed_addr_t addr1;
    sed_addr_t addr2;
    int has_addr2;
    int in_range;       /* for range tracking */

    union {
        sub_data_t sub;
        xlate_data_t xlate;
        char *text;         /* for a, i, c, w */
    } u;
    int negated;            /* ! modifier */
} sed_cmd_t;

static sed_cmd_t commands[MAX_COMMANDS];
static int ncmds = 0;

/* Write files cache */
typedef struct {
    char *name;
    FILE *fp;
} wfile_entry_t;

static wfile_entry_t wfiles[MAX_WFILES];
static int nwfiles = 0;

/* Options */
static int opt_n = 0;          /* suppress default output */
static int opt_inplace = 0;    /* in-place edit */

/* Scripts from -e and -f */
static char *scripts[MAX_SCRIPTS];
static int nscripts = 0;

/* ========================================================================
 * Parsing Helpers
 * ======================================================================== */

static void usage(void)
{
    fprintf(stderr, "Usage: %s [-n] [-e script] [-i] [-f file] [script] [file...]\n",
            progname);
    exit(2);
}

/* Get the delimiter character from a s or y command and find the end.
 * Handles backslash escaping of the delimiter. */
static const char *find_delim(const char *p, char delim)
{
    while (*p) {
        if (*p == '\\' && p[1]) {
            p += 2;
            continue;
        }
        if (*p == delim)
            return p;
        p++;
    }
    return p;
}

/* Unescape a replacement string (handle \n, \t, \\, \<delim>) */
static char *unescape_replacement(const char *s, int len, char delim)
{
    char *out = malloc((size_t)(len + 1));
    if (!out)
        return NULL;
    int j = 0;
    for (int i = 0; i < len; i++) {
        if (s[i] == '\\' && i + 1 < len) {
            char next = s[i + 1];
            if (next == 'n') {
                out[j++] = '\n';
                i++;
            } else if (next == 't') {
                out[j++] = '\t';
                i++;
            } else if (next == delim) {
                out[j++] = delim;
                i++;
            } else if (next == '\\') {
                out[j++] = '\\';
                i++;
            } else if (next == '&') {
                out[j++] = '\\';
                out[j++] = '&';
                i++;
            } else if (next >= '1' && next <= '9') {
                out[j++] = '\\';
                out[j++] = next;
                i++;
            } else {
                out[j++] = s[i];
            }
        } else {
            out[j++] = s[i];
        }
    }
    out[j] = '\0';
    return out;
}

/* Unescape text for a\, i\, c\ commands */
static char *unescape_text(const char *s)
{
    int len = (int)strlen(s);
    char *out = malloc((size_t)(len + 1));
    if (!out)
        return NULL;
    int j = 0;
    for (int i = 0; i < len; i++) {
        if (s[i] == '\\' && i + 1 < len) {
            if (s[i + 1] == 'n') {
                out[j++] = '\n';
                i++;
            } else if (s[i + 1] == 't') {
                out[j++] = '\t';
                i++;
            } else if (s[i + 1] == '\\') {
                out[j++] = '\\';
                i++;
            } else {
                out[j++] = s[i + 1];
                i++;
            }
        } else {
            out[j++] = s[i];
        }
    }
    out[j] = '\0';
    return out;
}

/* Parse an address from the script. Returns pointer past address. */
static const char *parse_address(const char *p, sed_addr_t *addr)
{
    addr->type = ADDR_NONE;

    while (*p == ' ' || *p == '\t')
        p++;

    if (*p >= '0' && *p <= '9') {
        addr->type = ADDR_LINE;
        addr->line = 0;
        while (*p >= '0' && *p <= '9') {
            addr->line = addr->line * 10 + (*p - '0');
            p++;
        }
    } else if (*p == '$') {
        addr->type = ADDR_LAST;
        p++;
    } else if (*p == '/' || *p == '\\') {
        char delim;
        if (*p == '\\') {
            p++;
            delim = *p;
            if (!delim)
                return p;
            p++;
        } else {
            delim = '/';
            p++;
        }

        /* Read pattern up to closing delimiter */
        const char *pat_start = p;
        const char *pat_end = find_delim(p, delim);
        int pat_len = (int)(pat_end - pat_start);
        char *pat = malloc((size_t)(pat_len + 1));
        memcpy(pat, pat_start, (size_t)pat_len);
        pat[pat_len] = '\0';

        addr->type = ADDR_REGEX;
        re_compile(&addr->regex, pat, 0);
        free(pat);

        if (*pat_end == delim)
            p = pat_end + 1;
        else
            p = pat_end;
    }

    return p;
}

/* Skip whitespace */
static const char *skip_ws(const char *p)
{
    while (*p == ' ' || *p == '\t')
        p++;
    return p;
}

/* Parse a single sed command. Returns pointer past command, or NULL on error. */
static const char *parse_command(const char *p)
{
    if (ncmds >= MAX_COMMANDS) {
        fprintf(stderr, "%s: too many commands\n", progname);
        return NULL;
    }

    p = skip_ws(p);

    /* Skip empty lines and comments */
    if (*p == '\0' || *p == '\n' || *p == '#')
        return NULL;

    sed_cmd_t *cmd = &commands[ncmds];
    memset(cmd, 0, sizeof(*cmd));

    /* Parse first address */
    p = parse_address(p, &cmd->addr1);
    p = skip_ws(p);

    /* Check for range */
    if (*p == ',') {
        p++;
        cmd->has_addr2 = 1;
        p = parse_address(p, &cmd->addr2);
        p = skip_ws(p);
    }

    /* Check for negation */
    if (*p == '!') {
        cmd->negated = 1;
        p++;
        p = skip_ws(p);
    }

    /* Parse command character */
    char c = *p;
    p++;

    switch (c) {
    case 's': {
        /* s/PATTERN/REPLACEMENT/FLAGS */
        char delim = *p;
        if (!delim) {
            fprintf(stderr, "%s: unterminated s command\n", progname);
            return NULL;
        }
        p++;

        /* Pattern */
        const char *pat_start = p;
        const char *pat_end = find_delim(p, delim);
        int pat_len = (int)(pat_end - pat_start);
        char *pat = malloc((size_t)(pat_len + 1));
        memcpy(pat, pat_start, (size_t)pat_len);
        pat[pat_len] = '\0';
        p = pat_end;
        if (*p == delim)
            p++;

        /* Replacement */
        const char *rep_start = p;
        const char *rep_end = find_delim(p, delim);
        int rep_len = (int)(rep_end - rep_start);
        char *rep = unescape_replacement(rep_start, rep_len, delim);
        p = rep_end;
        if (*p == delim)
            p++;

        /* Flags */
        cmd->type = CMD_SUB;
        cmd->u.sub.global = 0;
        cmd->u.sub.print = 0;
        cmd->u.sub.nth = 0;
        cmd->u.sub.icase = 0;
        cmd->u.sub.wfile = NULL;

        int regex_flags = 0;

        while (*p && *p != ';' && *p != '\n') {
            if (*p == 'g') {
                cmd->u.sub.global = 1;
                p++;
            } else if (*p == 'p') {
                cmd->u.sub.print = 1;
                p++;
            } else if (*p == 'i' || *p == 'I') {
                cmd->u.sub.icase = 1;
                regex_flags |= RE_FLAG_ICASE;
                p++;
            } else if (*p >= '1' && *p <= '9') {
                cmd->u.sub.nth = 0;
                while (*p >= '0' && *p <= '9') {
                    cmd->u.sub.nth = cmd->u.sub.nth * 10 + (*p - '0');
                    p++;
                }
            } else if (*p == 'w') {
                p++;
                p = skip_ws(p);
                const char *fname_start = p;
                while (*p && *p != ';' && *p != '\n')
                    p++;
                int fname_len = (int)(p - fname_start);
                /* Trim trailing whitespace */
                while (fname_len > 0 &&
                       (fname_start[fname_len-1] == ' ' ||
                        fname_start[fname_len-1] == '\t'))
                    fname_len--;
                cmd->u.sub.wfile = malloc((size_t)(fname_len + 1));
                memcpy(cmd->u.sub.wfile, fname_start, (size_t)fname_len);
                cmd->u.sub.wfile[fname_len] = '\0';
            } else {
                p++;
            }
        }

        re_compile(&cmd->u.sub.regex, pat, regex_flags);
        cmd->u.sub.replacement = rep;
        free(pat);
        ncmds++;
        break;
    }

    case 'y': {
        /* y/SRC/DST/ */
        char delim = *p;
        if (!delim)
            return NULL;
        p++;

        const char *src_start = p;
        const char *src_end = find_delim(p, delim);
        int src_len = (int)(src_end - src_start);
        p = src_end;
        if (*p == delim)
            p++;

        const char *dst_start = p;
        const char *dst_end = find_delim(p, delim);
        int dst_len = (int)(dst_end - dst_start);
        p = dst_end;
        if (*p == delim)
            p++;

        if (src_len != dst_len) {
            fprintf(stderr, "%s: y command strings must be same length\n",
                    progname);
            return NULL;
        }

        cmd->type = CMD_XLATE;
        cmd->u.xlate.len = src_len;
        memcpy(cmd->u.xlate.src, src_start, (size_t)src_len);
        cmd->u.xlate.src[src_len] = '\0';
        memcpy(cmd->u.xlate.dst, dst_start, (size_t)dst_len);
        cmd->u.xlate.dst[dst_len] = '\0';
        ncmds++;
        break;
    }

    case 'd':
        cmd->type = CMD_DELETE;
        ncmds++;
        break;

    case 'p':
        cmd->type = CMD_PRINT;
        ncmds++;
        break;

    case 'q':
        cmd->type = CMD_QUIT;
        ncmds++;
        break;

    case '=':
        cmd->type = CMD_LINENUM;
        ncmds++;
        break;

    case 'n':
        cmd->type = CMD_NEXT;
        ncmds++;
        break;

    case 'a': {
        /* a\ or a followed by text */
        if (*p == '\\')
            p++;
        p = skip_ws(p);
        /* Rest of line is the text */
        const char *text_start = p;
        while (*p && *p != '\n')
            p++;
        int text_len = (int)(p - text_start);
        cmd->type = CMD_APPEND;
        cmd->u.text = unescape_text(text_start);
        (void)text_len;
        ncmds++;
        break;
    }

    case 'i': {
        if (*p == '\\')
            p++;
        p = skip_ws(p);
        const char *text_start = p;
        while (*p && *p != '\n')
            p++;
        cmd->type = CMD_INSERT;
        cmd->u.text = unescape_text(text_start);
        ncmds++;
        break;
    }

    case 'c': {
        if (*p == '\\')
            p++;
        p = skip_ws(p);
        const char *text_start = p;
        while (*p && *p != '\n')
            p++;
        cmd->type = CMD_CHANGE;
        cmd->u.text = unescape_text(text_start);
        ncmds++;
        break;
    }

    case 'w': {
        p = skip_ws(p);
        const char *fname_start = p;
        while (*p && *p != ';' && *p != '\n')
            p++;
        int fname_len = (int)(p - fname_start);
        while (fname_len > 0 &&
               (fname_start[fname_len-1] == ' ' ||
                fname_start[fname_len-1] == '\t'))
            fname_len--;
        cmd->type = CMD_WRITE;
        cmd->u.text = malloc((size_t)(fname_len + 1));
        memcpy(cmd->u.text, fname_start, (size_t)fname_len);
        cmd->u.text[fname_len] = '\0';
        ncmds++;
        break;
    }

    default:
        /* Unknown command, skip */
        break;
    }

    return p;
}

/* Parse a complete script string into commands */
static void parse_script(const char *script)
{
    const char *p = script;
    while (*p) {
        /* Skip whitespace and separators */
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == ';')
            p++;
        if (*p == '\0')
            break;
        if (*p == '#') {
            /* Skip comment to end of line */
            while (*p && *p != '\n')
                p++;
            continue;
        }

        const char *next = parse_command(p);
        if (!next || next == p) {
            /* Skip to next separator */
            while (*p && *p != ';' && *p != '\n')
                p++;
        } else {
            p = next;
        }
    }
}

/* ========================================================================
 * Address Matching
 * ======================================================================== */

static int addr_matches(const sed_addr_t *addr, const char *line,
                        int lineno, int is_last)
{
    switch (addr->type) {
    case ADDR_NONE:
        return 1;
    case ADDR_LINE:
        return (lineno == addr->line);
    case ADDR_LAST:
        return is_last;
    case ADDR_REGEX:
        return regex_matches(&addr->regex, line);
    }
    return 0;
}

static int cmd_applies(sed_cmd_t *cmd, const char *line, int lineno,
                       int is_last)
{
    int result;

    if (cmd->addr1.type == ADDR_NONE && !cmd->has_addr2) {
        /* No address: applies to all lines */
        result = 1;
    } else if (!cmd->has_addr2) {
        /* Single address */
        result = addr_matches(&cmd->addr1, line, lineno, is_last);
    } else {
        /* Range address */
        if (cmd->in_range) {
            result = 1;
            if (addr_matches(&cmd->addr2, line, lineno, is_last))
                cmd->in_range = 0;
        } else {
            if (addr_matches(&cmd->addr1, line, lineno, is_last)) {
                cmd->in_range = 1;
                result = 1;
            } else {
                result = 0;
            }
        }
    }

    if (cmd->negated)
        result = !result;

    return result;
}

/* ========================================================================
 * Write File Management
 * ======================================================================== */

static FILE *get_wfile(const char *name)
{
    for (int i = 0; i < nwfiles; i++) {
        if (strcmp(wfiles[i].name, name) == 0)
            return wfiles[i].fp;
    }

    if (nwfiles >= MAX_WFILES) {
        fprintf(stderr, "%s: too many w files\n", progname);
        return NULL;
    }

    FILE *fp = fopen(name, "w");
    if (!fp) {
        fprintf(stderr, "%s: %s: %s\n", progname, name, strerror(errno));
        return NULL;
    }

    wfiles[nwfiles].name = strdup(name);
    wfiles[nwfiles].fp = fp;
    nwfiles++;
    return fp;
}

static void close_wfiles(void)
{
    for (int i = 0; i < nwfiles; i++) {
        fclose(wfiles[i].fp);
        free(wfiles[i].name);
    }
    nwfiles = 0;
}

/* ========================================================================
 * Substitution
 * ======================================================================== */

/* Apply replacement, expanding & and \1-\9 */
static int do_replacement(char *out, int outsize, const char *repl,
                          const char *match_start, const char *match_end,
                          re_group_t *groups)
{
    int j = 0;
    for (const char *r = repl; *r && j < outsize - 1; r++) {
        if (*r == '&') {
            /* Whole match */
            int mlen = (int)(match_end - match_start);
            if (j + mlen < outsize) {
                memcpy(out + j, match_start, (size_t)mlen);
                j += mlen;
            }
        } else if (*r == '\\' && r[1] >= '1' && r[1] <= '9') {
            int grp = r[1] - '0';
            r++;
            if (groups[grp].start && groups[grp].end) {
                int glen = (int)(groups[grp].end - groups[grp].start);
                if (j + glen < outsize) {
                    memcpy(out + j, groups[grp].start, (size_t)glen);
                    j += glen;
                }
            }
        } else {
            out[j++] = *r;
        }
    }
    out[j] = '\0';
    return j;
}

/* Perform substitution on a line. Returns 1 if substitution was made. */
static int do_sub(sed_cmd_t *cmd, char *line, int linesize)
{
    sub_data_t *sub = &cmd->u.sub;
    char result[LINE_SIZE];
    int rpos = 0;
    const char *p = line;
    int count = 0;
    int did_sub = 0;
    int target = sub->nth ? sub->nth : (sub->global ? 0 : 1);

    while (*p) {
        const char *ms, *me;
        re_group_t groups[RE_MAX_GROUPS];
        memset(groups, 0, sizeof(groups));

        if (regex_search_from(&sub->regex, line, p, &ms, &me, groups)) {
            /* Copy everything before match */
            int pre_len = (int)(ms - p);
            if (rpos + pre_len < LINE_SIZE) {
                memcpy(result + rpos, p, (size_t)pre_len);
                rpos += pre_len;
            }

            count++;

            if (target == 0 || count == target) {
                /* Do replacement */
                char rep_buf[LINE_SIZE];
                int rep_len = do_replacement(rep_buf, LINE_SIZE,
                                             sub->replacement,
                                             ms, me, groups);
                if (rpos + rep_len < LINE_SIZE) {
                    memcpy(result + rpos, rep_buf, (size_t)rep_len);
                    rpos += rep_len;
                }
                did_sub = 1;
            } else {
                /* Copy the match as-is */
                int mlen = (int)(me - ms);
                if (rpos + mlen < LINE_SIZE) {
                    memcpy(result + rpos, ms, (size_t)mlen);
                    rpos += mlen;
                }
            }

            /* Advance past match */
            if (me == ms) {
                /* Zero-length match: copy one char and advance */
                if (*me && rpos < LINE_SIZE - 1) {
                    result[rpos++] = *me;
                    p = me + 1;
                } else {
                    break;
                }
            } else {
                p = me;
            }

            /* If not global and we've done one replacement, copy rest */
            if (!sub->global && did_sub && target != 0) {
                int rest = (int)strlen(p);
                if (rpos + rest < LINE_SIZE) {
                    memcpy(result + rpos, p, (size_t)rest);
                    rpos += rest;
                }
                break;
            }
        } else {
            /* No more matches; copy rest */
            int rest = (int)strlen(p);
            if (rpos + rest < LINE_SIZE) {
                memcpy(result + rpos, p, (size_t)rest);
                rpos += rest;
            }
            break;
        }
    }

    result[rpos] = '\0';

    if (did_sub) {
        strncpy(line, result, (size_t)(linesize - 1));
        line[linesize - 1] = '\0';
    }

    return did_sub;
}

/* ========================================================================
 * Transliterate (y command)
 * ======================================================================== */

static void do_xlate(sed_cmd_t *cmd, char *line)
{
    xlate_data_t *xl = &cmd->u.xlate;
    for (char *p = line; *p; p++) {
        for (int i = 0; i < xl->len; i++) {
            if (*p == xl->src[i]) {
                *p = xl->dst[i];
                break;
            }
        }
    }
}

/* ========================================================================
 * Output helpers
 * ======================================================================== */

static void output_line(const char *line, FILE *out)
{
    fputs(line, out);
    /* Ensure newline at end */
    int len = (int)strlen(line);
    if (len == 0 || line[len - 1] != '\n')
        fputc('\n', out);
}

/* ========================================================================
 * Main Processing
 * ======================================================================== */

/* Read all lines from file for last-line detection */
typedef struct {
    char **lines;
    int nlines;
    int capacity;
} line_buffer_t;

static void linebuf_init(line_buffer_t *lb)
{
    lb->lines = NULL;
    lb->nlines = 0;
    lb->capacity = 0;
}

static void linebuf_add(line_buffer_t *lb, const char *line)
{
    if (lb->nlines >= lb->capacity) {
        int newcap = lb->capacity ? lb->capacity * 2 : 256;
        lb->lines = realloc(lb->lines, (size_t)newcap * sizeof(char *));
        lb->capacity = newcap;
    }
    lb->lines[lb->nlines++] = strdup(line);
}

static void linebuf_free(line_buffer_t *lb)
{
    for (int i = 0; i < lb->nlines; i++)
        free(lb->lines[i]);
    free(lb->lines);
    lb->lines = NULL;
    lb->nlines = 0;
    lb->capacity = 0;
}

static void process_stream(FILE *in, FILE *out)
{
    /* First, read all lines so we can detect last line */
    line_buffer_t lb;
    linebuf_init(&lb);

    char buf[LINE_SIZE];
    while (fgets(buf, LINE_SIZE, in)) {
        /* Strip trailing newline for processing */
        int len = (int)strlen(buf);
        if (len > 0 && buf[len - 1] == '\n')
            buf[len - 1] = '\0';
        linebuf_add(&lb, buf);
    }

    /* Process each line */
    for (int i = 0; i < lb.nlines; i++) {
        char line[LINE_SIZE];
        strncpy(line, lb.lines[i], LINE_SIZE - 1);
        line[LINE_SIZE - 1] = '\0';

        int lineno = i + 1;
        int is_last = (i == lb.nlines - 1);
        int deleted = 0;
        int printed __attribute__((unused)) = 0;  /* explicit print from p command or s///p */
        char *append_text = NULL;

        for (int ci = 0; ci < ncmds; ci++) {
            sed_cmd_t *cmd = &commands[ci];

            if (!cmd_applies(cmd, line, lineno, is_last))
                continue;

            switch (cmd->type) {
            case CMD_DELETE:
                deleted = 1;
                break;

            case CMD_PRINT:
                output_line(line, out);
                printed = 1;
                break;

            case CMD_QUIT:
                if (!opt_n && !deleted)
                    output_line(line, out);
                fflush(out);
                close_wfiles();
                linebuf_free(&lb);
                exit(0);
                break;

            case CMD_SUB: {
                int did = do_sub(cmd, line, LINE_SIZE);
                if (did && cmd->u.sub.print) {
                    output_line(line, out);
                    printed = 1;
                }
                if (did && cmd->u.sub.wfile) {
                    FILE *wfp = get_wfile(cmd->u.sub.wfile);
                    if (wfp)
                        output_line(line, wfp);
                }
                break;
            }

            case CMD_XLATE:
                do_xlate(cmd, line);
                break;

            case CMD_LINENUM:
                fprintf(out, "%d\n", lineno);
                break;

            case CMD_NEXT:
                /* Print current line (if -n not set), then read next */
                if (!opt_n && !deleted)
                    output_line(line, out);
                /* Move to next input line */
                i++;
                if (i < lb.nlines) {
                    strncpy(line, lb.lines[i], LINE_SIZE - 1);
                    line[LINE_SIZE - 1] = '\0';
                    lineno = i + 1;
                    is_last = (i == lb.nlines - 1);
                    deleted = 0;
                    printed = 0;
                }
                break;

            case CMD_APPEND:
                /* Append after current line is output */
                append_text = cmd->u.text;
                break;

            case CMD_INSERT:
                output_line(cmd->u.text, out);
                break;

            case CMD_CHANGE:
                /* Replace line; don't output original */
                output_line(cmd->u.text, out);
                deleted = 1;
                break;

            case CMD_WRITE: {
                FILE *wfp = get_wfile(cmd->u.text);
                if (wfp)
                    output_line(line, wfp);
                break;
            }

            case CMD_NOOP:
                break;
            }

            if (deleted)
                break;
        }

        /* Default output */
        if (!opt_n && !deleted)
            output_line(line, out);

        /* Append text after line */
        if (append_text)
            output_line(append_text, out);
    }

    linebuf_free(&lb);
}

/* Process a single file */
static void process_file(const char *filename)
{
    FILE *in;
    FILE *out = stdout;

    if (!filename || strcmp(filename, "-") == 0) {
        in = stdin;
    } else {
        in = fopen(filename, "r");
        if (!in) {
            fprintf(stderr, "%s: %s: %s\n", progname, filename,
                    strerror(errno));
            return;
        }
    }

    if (opt_inplace && filename && strcmp(filename, "-") != 0) {
        /* Read entire file, process, write back */
        /* Create temp output buffer */
        char tmpname[4096];
        snprintf(tmpname, sizeof(tmpname), "%s.sedXXXXXX", filename);

        /* Use a unique temp name based on pid */
        snprintf(tmpname, sizeof(tmpname), "%s.sed%d", filename,
                 (int)getpid());

        out = fopen(tmpname, "w");
        if (!out) {
            fprintf(stderr, "%s: cannot create temp file: %s\n",
                    progname, strerror(errno));
            if (in != stdin)
                fclose(in);
            return;
        }

        process_stream(in, out);
        fclose(out);
        if (in != stdin)
            fclose(in);

        /* Rename temp to original */
        /* Since we don't have rename(), we copy */
        FILE *src = fopen(tmpname, "r");
        FILE *dst = fopen(filename, "w");
        if (src && dst) {
            char buf[4096];
            size_t n;
            while ((n = fread(buf, 1, sizeof(buf), src)) > 0)
                fwrite(buf, 1, n, dst);
        }
        if (src)
            fclose(src);
        if (dst)
            fclose(dst);
        unlink(tmpname);
    } else {
        process_stream(in, out);
        if (in != stdin)
            fclose(in);
    }
}

/* ========================================================================
 * Main
 * ======================================================================== */

int main(int argc, char *argv[])
{
    int first_file = argc;
    int have_script = 0;

    /* Parse options */
    int i;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [-n] [-e script] [-i] [-f file] [script] [file...]\n",
                    progname);
            return 0;
        }
        if (argv[i][0] == '-' && argv[i][1] != '\0') {
            if (strcmp(argv[i], "--") == 0) {
                i++;
                first_file = i;
                break;
            }

            const char *p = &argv[i][1];
            while (*p) {
                switch (*p) {
                case 'n':
                    opt_n = 1;
                    p++;
                    break;

                case 'e':
                    p++;
                    if (*p) {
                        /* -eSCRIPT */
                        if (nscripts < MAX_SCRIPTS)
                            scripts[nscripts++] = strdup(p);
                        have_script = 1;
                        p = "";
                    } else if (i + 1 < argc) {
                        /* -e SCRIPT */
                        i++;
                        if (nscripts < MAX_SCRIPTS)
                            scripts[nscripts++] = strdup(argv[i]);
                        have_script = 1;
                    } else {
                        fprintf(stderr, "%s: -e requires an argument\n",
                                progname);
                        return 2;
                    }
                    break;

                case 'f': {
                    p++;
                    const char *fname;
                    if (*p) {
                        fname = p;
                        p = "";
                    } else if (i + 1 < argc) {
                        i++;
                        fname = argv[i];
                    } else {
                        fprintf(stderr, "%s: -f requires an argument\n",
                                progname);
                        return 2;
                    }

                    FILE *sf = fopen(fname, "r");
                    if (!sf) {
                        fprintf(stderr, "%s: %s: %s\n", progname, fname,
                                strerror(errno));
                        return 1;
                    }
                    char sbuf[LINE_SIZE];
                    char *script_text = malloc(LINE_SIZE);
                    script_text[0] = '\0';
                    int slen = 0;
                    while (fgets(sbuf, LINE_SIZE, sf)) {
                        int blen = (int)strlen(sbuf);
                        if (slen + blen < LINE_SIZE - 1) {
                            memcpy(script_text + slen, sbuf, (size_t)blen);
                            slen += blen;
                            script_text[slen] = '\0';
                        }
                    }
                    fclose(sf);
                    if (nscripts < MAX_SCRIPTS)
                        scripts[nscripts++] = script_text;
                    else
                        free(script_text);
                    have_script = 1;
                    break;
                }

                case 'i':
                    opt_inplace = 1;
                    p++;
                    break;

                default:
                    fprintf(stderr, "%s: invalid option -- '%c'\n",
                            progname, *p);
                    usage();
                    break;
                }
            }
        } else {
            first_file = i;
            break;
        }
    }

    /* If no -e or -f, first non-option arg is the script */
    if (!have_script) {
        if (first_file >= argc) {
            fprintf(stderr, "%s: no script specified\n", progname);
            usage();
        }
        scripts[nscripts++] = strdup(argv[first_file]);
        first_file++;
    }

    /* Parse all scripts */
    for (int s = 0; s < nscripts; s++)
        parse_script(scripts[s]);

    /* Process files */
    if (first_file >= argc) {
        process_file(NULL); /* stdin */
    } else {
        for (int f = first_file; f < argc; f++)
            process_file(argv[f]);
    }

    fflush(stdout);
    close_wfiles();

    /* Free scripts */
    for (int s = 0; s < nscripts; s++)
        free(scripts[s]);

    return 0;
}
