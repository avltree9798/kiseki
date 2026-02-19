/*
 * Kiseki OS - Shell Word Expansion
 *
 * Implements the full bash expansion pipeline:
 *   1. Brace expansion      {a,b,c}, {1..10}
 *   2. Tilde expansion      ~, ~user
 *   3. Parameter expansion   $VAR, ${VAR}, ${VAR:-default}, etc.
 *   4. Command substitution  $(cmd), `cmd`
 *   5. Arithmetic expansion  $((expr))
 *   6. Word splitting        IFS
 *   7. Filename globbing     *, ?, [...]
 *   8. Quote removal
 */

#ifndef _EXPAND_H
#define _EXPAND_H

#include "shell.h"

/* ---------- Word list (dynamic array of strings) ---------- */

/* word_list_t is defined in shell.h */

word_list_t    *word_list_new(void);
void            word_list_add(word_list_t *wl, const char *word);
void            word_list_add_list(word_list_t *dst, word_list_t *src);
void            word_list_free(word_list_t *wl);

/* ---------- Main expansion entry points ---------- */

/* Expand a single word through the full expansion pipeline.
 * Returns a word_list (may expand to multiple words after splitting/globbing) */
word_list_t    *expand_word(const char *word, shell_state_t *state);

/* Expand an array of words. Each word goes through full expansion.
 * Results are concatenated into a single word_list. */
word_list_t    *expand_words(char **words, int nwords, shell_state_t *state);

/* Expand a word but suppress word splitting and globbing (for assignments,
 * here-doc bodies without quoting, etc.) */
char           *expand_word_nosplit(const char *word, shell_state_t *state);

/* Expand only the assignment value (right side of VAR=...) */
char           *expand_assignment_value(const char *value,
                                        shell_state_t *state);

/* ---------- Individual expansion stages ---------- */

/* Brace expansion: {a,b,c} -> a b c; {1..5} -> 1 2 3 4 5 */
word_list_t    *expand_braces(const char *word);

/* Tilde expansion: ~ -> $HOME, ~user -> /home/user */
char           *expand_tilde(const char *word, shell_state_t *state);

/* Parameter and variable expansion: $VAR, ${VAR:-default}, etc. */
char           *expand_parameters(const char *word, shell_state_t *state);

/* Command substitution: $(cmd), `cmd` */
char           *expand_command_subst(const char *cmd, shell_state_t *state);

/* Arithmetic expansion: $((expr)) */
char           *expand_arithmetic(const char *expr, shell_state_t *state);

/* Word splitting: split on IFS characters */
word_list_t    *split_on_ifs(const char *word, shell_state_t *state);

/* Filename globbing: expand *, ?, [...] patterns */
word_list_t    *expand_pattern(const char *pattern);

/* Quote removal: strip unquoted quotes and process escape sequences */
char           *remove_quotes(const char *word);

/* ---------- Arithmetic evaluator ---------- */

/* Evaluate an arithmetic expression string.
 * Supports: + - * / % == != < > <= >= && || ! ~ & | ^ << >>
 *           parentheses, decimal/octal/hex literals, variable references
 * Sets *err to non-zero on error. Returns result as long. */
long            arith_eval(const char *expr, shell_state_t *state, int *err);

/* ---------- Glob / pattern matching ---------- */

/* Match a string against a shell glob pattern (*, ?, [...])
 * Returns 1 on match, 0 on no match. */
int             glob_match(const char *pattern, const char *string);

#endif /* _EXPAND_H */
