/*
 * echo - print arguments to standard output
 *
 * Usage: echo [-neE] [STRING ...]
 *
 * Flags:
 *   -n  Do not output trailing newline
 *   -e  Enable interpretation of backslash escapes
 *   -E  Disable interpretation of backslash escapes (default)
 *
 * Escape sequences (with -e):
 *   \\   backslash
 *   \a   alert (bell)
 *   \b   backspace
 *   \f   form feed
 *   \n   newline
 *   \r   carriage return
 *   \t   horizontal tab
 *   \0NNN  octal value (1-3 digits)
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void print_escaped(const char *s)
{
    while (*s) {
        if (*s == '\\' && s[1]) {
            s++;
            switch (*s) {
            case '\\': putchar('\\'); break;
            case 'a':  putchar('\a'); break;
            case 'b':  putchar('\b'); break;
            case 'f':  putchar('\f'); break;
            case 'n':  putchar('\n'); break;
            case 'r':  putchar('\r'); break;
            case 't':  putchar('\t'); break;
            case '0': {
                /* Octal: \0NNN (up to 3 octal digits) */
                s++;
                unsigned int val = 0;
                int i;
                for (i = 0; i < 3 && *s >= '0' && *s <= '7'; i++, s++)
                    val = val * 8 + (*s - '0');
                putchar((char)val);
                continue; /* s already advanced past digits */
            }
            default:
                /* Unknown escape: print backslash and character */
                putchar('\\');
                putchar(*s);
                break;
            }
        } else {
            putchar(*s);
        }
        s++;
    }
}

int main(int argc, char *argv[])
{
    int no_newline = 0;
    int escape = 0;
    int i = 1;

    /* Parse flags: echo treats only leading args starting with '-' as flags,
     * and only if they contain only n/e/E characters */
    while (i < argc && argv[i][0] == '-' && argv[i][1] != '\0') {
        const char *p = &argv[i][1];
        int valid = 1;
        while (*p) {
            if (*p != 'n' && *p != 'e' && *p != 'E') {
                valid = 0;
                break;
            }
            p++;
        }
        if (!valid)
            break;
        /* Apply the flags */
        p = &argv[i][1];
        while (*p) {
            switch (*p) {
            case 'n': no_newline = 1; break;
            case 'e': escape = 1;     break;
            case 'E': escape = 0;     break;
            }
            p++;
        }
        i++;
    }

    /* Print arguments separated by spaces */
    int first = 1;
    for (; i < argc; i++) {
        if (!first)
            putchar(' ');
        first = 0;
        if (escape)
            print_escaped(argv[i]);
        else
            fputs(argv[i], stdout);
    }

    if (!no_newline)
        putchar('\n');

    return 0;
}
