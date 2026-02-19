/*
 * printf - format and print data
 *
 * Usage: printf FORMAT [ARGUMENT...]
 *
 * FORMAT supports C printf % specifiers and backslash escape sequences.
 * If more arguments remain than the format consumes, the format is reused.
 *
 * Kiseki OS coreutils
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static const char *progname = "printf";

static int exit_status = 0;

/*
 * Argument state: pointer to current arg and end of args.
 */
static int arg_idx;
static int arg_count;
static char **arg_vec;

static const char *next_arg(void)
{
    if (arg_idx >= arg_count)
        return "";
    return arg_vec[arg_idx++];
}

/*
 * Convert a string argument to a long integer.
 * If the string starts with ' or ", return the character value.
 */
static long get_long(void)
{
    const char *s = next_arg();

    if ((s[0] == '\'' || s[0] == '"') && s[1] != '\0')
        return (unsigned char)s[1];

    errno = 0;
    char *end;
    long val = strtol(s, &end, 0);
    if (errno != 0 || (end != NULL && *end != '\0')) {
        fprintf(stderr, "%s: '%s': expected a numeric value\n", progname, s);
        exit_status = 1;
    }
    return val;
}

static unsigned long get_ulong(void)
{
    const char *s = next_arg();

    if ((s[0] == '\'' || s[0] == '"') && s[1] != '\0')
        return (unsigned char)s[1];

    errno = 0;
    char *end;
    unsigned long val = strtoul(s, &end, 0);
    if (errno != 0 || (end != NULL && *end != '\0')) {
        fprintf(stderr, "%s: '%s': expected a numeric value\n", progname, s);
        exit_status = 1;
    }
    return val;
}

/*
 * Simple strtod implementation for freestanding environment.
 * Handles: optional sign, integer part, optional fractional part,
 * optional exponent (e/E followed by optional sign and digits).
 */
static double simple_strtod(const char *s, char **endptr)
{
    const char *p = s;
    double sign = 1.0;
    double result = 0.0;

    /* Skip whitespace */
    while (*p == ' ' || *p == '\t')
        p++;

    /* Sign */
    if (*p == '-') { sign = -1.0; p++; }
    else if (*p == '+') { p++; }

    /* Integer part */
    int has_digits = 0;
    while (*p >= '0' && *p <= '9') {
        result = result * 10.0 + (*p - '0');
        p++;
        has_digits = 1;
    }

    /* Fractional part */
    if (*p == '.') {
        p++;
        double frac = 0.1;
        while (*p >= '0' && *p <= '9') {
            result += (*p - '0') * frac;
            frac *= 0.1;
            p++;
            has_digits = 1;
        }
    }

    if (!has_digits) {
        if (endptr)
            *endptr = (char *)s;
        return 0.0;
    }

    /* Exponent */
    if (*p == 'e' || *p == 'E') {
        p++;
        int exp_sign = 1;
        int exp_val = 0;
        if (*p == '-') { exp_sign = -1; p++; }
        else if (*p == '+') { p++; }
        while (*p >= '0' && *p <= '9') {
            exp_val = exp_val * 10 + (*p - '0');
            p++;
        }
        double mul = 1.0;
        for (int i = 0; i < exp_val; i++)
            mul *= 10.0;
        if (exp_sign < 0)
            result /= mul;
        else
            result *= mul;
    }

    if (endptr)
        *endptr = (char *)p;
    return sign * result;
}

static double get_double(void)
{
    const char *s = next_arg();

    if ((s[0] == '\'' || s[0] == '"') && s[1] != '\0')
        return (unsigned char)s[1];

    char *end;
    double val = simple_strtod(s, &end);
    if (end == s || *end != '\0') {
        fprintf(stderr, "%s: '%s': expected a numeric value\n", progname, s);
        exit_status = 1;
    }
    return val;
}

/*
 * Parse a backslash escape sequence starting after the backslash.
 * Advances *p past the consumed characters.
 * Returns the character to output, or -1 for \c (stop output).
 */
static int parse_escape(const char **p)
{
    char c = **p;
    (*p)++;

    switch (c) {
    case '\\': return '\\';
    case 'a':  return '\a';
    case 'b':  return '\b';
    case 'f':  return '\f';
    case 'n':  return '\n';
    case 'r':  return '\r';
    case 't':  return '\t';
    case 'v':  return '\v';
    case 'c':  return -1; /* stop printing */

    case '0': {
        /* Octal: \0NNN (up to 3 octal digits after the 0) */
        unsigned int val = 0;
        for (int i = 0; i < 3 && **p >= '0' && **p <= '7'; i++) {
            val = val * 8 + (unsigned int)(**p - '0');
            (*p)++;
        }
        return (int)(val & 0xFF);
    }

    case 'x': {
        /* Hex: \xHH (up to 2 hex digits) */
        unsigned int val = 0;
        for (int i = 0; i < 2; i++) {
            char h = **p;
            if (h >= '0' && h <= '9')
                val = val * 16 + (unsigned int)(h - '0');
            else if (h >= 'a' && h <= 'f')
                val = val * 16 + (unsigned int)(h - 'a' + 10);
            else if (h >= 'A' && h <= 'F')
                val = val * 16 + (unsigned int)(h - 'A' + 10);
            else
                break;
            (*p)++;
        }
        return (int)(val & 0xFF);
    }

    default:
        /* Unknown escape: output the backslash and the character */
        putchar('\\');
        return (int)(unsigned char)c;
    }
}

/*
 * Process the format string once with the current argument position.
 * Returns 0 normally, -1 if \c was encountered (stop all output).
 */
static int process_format(const char *fmt)
{
    const char *p = fmt;

    while (*p) {
        if (*p == '\\' && p[1]) {
            p++;
            int ch = parse_escape(&p);
            if (ch < 0)
                return -1; /* \c: stop */
            putchar(ch);
            continue;
        }

        if (*p == '%') {
            p++;

            /* %% → literal percent */
            if (*p == '%') {
                putchar('%');
                p++;
                continue;
            }

            /*
             * Build a format specifier to pass to libc printf().
             * Format: %[flags][width][.precision][length]type
             */
            char fmtbuf[128];
            int fi = 0;
            fmtbuf[fi++] = '%';

            /* Flags: -, +, space, 0, #, ' */
            while (*p == '-' || *p == '+' || *p == ' ' ||
                   *p == '0' || *p == '#' || *p == '\'') {
                if (fi < (int)sizeof(fmtbuf) - 10)
                    fmtbuf[fi++] = *p;
                p++;
            }

            /* Width: number or * */
            int width = 0;
            int has_width = 0;
            if (*p == '*') {
                width = (int)get_long();
                has_width = 1;
                fmtbuf[fi++] = '*';
                p++;
            } else {
                while (*p >= '0' && *p <= '9') {
                    if (fi < (int)sizeof(fmtbuf) - 10)
                        fmtbuf[fi++] = *p;
                    p++;
                }
            }

            /* Precision */
            int prec = 0;
            int has_prec = 0;
            if (*p == '.') {
                if (fi < (int)sizeof(fmtbuf) - 10)
                    fmtbuf[fi++] = '.';
                p++;
                if (*p == '*') {
                    prec = (int)get_long();
                    has_prec = 1;
                    fmtbuf[fi++] = '*';
                    p++;
                } else {
                    while (*p >= '0' && *p <= '9') {
                        if (fi < (int)sizeof(fmtbuf) - 10)
                            fmtbuf[fi++] = *p;
                        p++;
                    }
                }
            }

            /* Conversion specifier */
            char conv = *p;
            if (conv == '\0') {
                /* Incomplete format */
                fmtbuf[fi] = '\0';
                fputs(fmtbuf, stdout);
                break;
            }

            switch (conv) {
            case 'd':
            case 'i': {
                fmtbuf[fi++] = 'l';
                fmtbuf[fi++] = 'd';
                fmtbuf[fi] = '\0';
                long val = get_long();
                if (has_width && has_prec)
                    printf(fmtbuf, width, prec, val);
                else if (has_width)
                    printf(fmtbuf, width, val);
                else if (has_prec)
                    printf(fmtbuf, prec, val);
                else
                    printf(fmtbuf, val);
                break;
            }
            case 'o':
            case 'u':
            case 'x':
            case 'X': {
                fmtbuf[fi++] = 'l';
                fmtbuf[fi++] = conv;
                fmtbuf[fi] = '\0';
                unsigned long val = get_ulong();
                if (has_width && has_prec)
                    printf(fmtbuf, width, prec, val);
                else if (has_width)
                    printf(fmtbuf, width, val);
                else if (has_prec)
                    printf(fmtbuf, prec, val);
                else
                    printf(fmtbuf, val);
                break;
            }
            case 'f':
            case 'e':
            case 'E':
            case 'g':
            case 'G': {
                fmtbuf[fi++] = conv;
                fmtbuf[fi] = '\0';
                double val = get_double();
                if (has_width && has_prec)
                    printf(fmtbuf, width, prec, val);
                else if (has_width)
                    printf(fmtbuf, width, val);
                else if (has_prec)
                    printf(fmtbuf, prec, val);
                else
                    printf(fmtbuf, val);
                break;
            }
            case 'c': {
                fmtbuf[fi++] = 'c';
                fmtbuf[fi] = '\0';
                const char *s = next_arg();
                int ch;
                if ((s[0] == '\'' || s[0] == '"') && s[1] != '\0')
                    ch = (unsigned char)s[1];
                else
                    ch = s[0] ? (unsigned char)s[0] : 0;
                if (has_width)
                    printf(fmtbuf, width, ch);
                else
                    printf(fmtbuf, ch);
                break;
            }
            case 's': {
                fmtbuf[fi++] = 's';
                fmtbuf[fi] = '\0';
                const char *s = next_arg();
                if (has_width && has_prec)
                    printf(fmtbuf, width, prec, s);
                else if (has_width)
                    printf(fmtbuf, width, s);
                else if (has_prec)
                    printf(fmtbuf, prec, s);
                else
                    printf(fmtbuf, s);
                break;
            }
            case 'b': {
                /* %b: print string with escape interpretation (no %formats) */
                const char *s = next_arg();
                while (*s) {
                    if (*s == '\\' && s[1]) {
                        s++;
                        int ch = parse_escape(&s);
                        if (ch < 0)
                            return -1;
                        putchar(ch);
                    } else {
                        putchar(*s);
                        s++;
                    }
                }
                break;
            }
            default:
                /* Unknown specifier: print as-is */
                fmtbuf[fi++] = conv;
                fmtbuf[fi] = '\0';
                fputs(fmtbuf, stdout);
                break;
            }
            p++;
            continue;
        }

        /* Regular character */
        putchar(*p);
        p++;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s FORMAT [ARGUMENT...]\n", progname);
        return 1;
    }

    const char *fmt = argv[1];
    arg_vec = argv;
    arg_count = argc;
    arg_idx = 2;

    /*
     * Process the format string. If arguments remain after one pass,
     * reuse the format string until all arguments are consumed.
     */
    do {
        int save = arg_idx;
        if (process_format(fmt) < 0)
            break; /* \c encountered */
        /* If no arguments were consumed and we have leftover args, break
         * to avoid infinite loop with a format that has no specifiers */
        if (arg_idx == save)
            break;
    } while (arg_idx < arg_count);

    return exit_status;
}
