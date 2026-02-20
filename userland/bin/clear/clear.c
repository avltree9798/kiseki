/*
 * clear - clear the terminal screen
 *
 * Kiseki OS coreutils
 *
 * macOS-compatible clear command. Outputs ANSI escape sequences
 * to clear the screen and move the cursor to the home position.
 *
 * Reference: ncurses clear(1), ANSI X3.64 / ECMA-48
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char *progname = "clear";

/*
 * ANSI escape sequences:
 *   ESC[H    - Move cursor to home position (1,1)
 *   ESC[2J   - Clear entire screen
 *   ESC[3J   - Clear scrollback buffer (xterm extension)
 *
 * macOS Terminal.app and most modern terminals support all three.
 */
#define CLEAR_SCREEN    "\033[H\033[2J"
#define CLEAR_SCROLLBACK "\033[H\033[2J\033[3J"

static void usage(void)
{
    fprintf(stderr, "Usage: %s [-x]\n", progname);
    fprintf(stderr, "Clear the terminal screen.\n\n");
    fprintf(stderr, "  -x      also clear the scrollback buffer\n");
    fprintf(stderr, "  --help  display this help and exit\n");
}

int main(int argc, char *argv[])
{
    int clear_scrollback = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            usage();
            return 0;
        } else if (strcmp(argv[i], "-x") == 0) {
            clear_scrollback = 1;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "%s: invalid option -- '%s'\n", progname, argv[i]);
            usage();
            return 1;
        }
    }

    /* Output the appropriate escape sequence */
    if (clear_scrollback) {
        write(STDOUT_FILENO, CLEAR_SCROLLBACK, sizeof(CLEAR_SCROLLBACK) - 1);
    } else {
        write(STDOUT_FILENO, CLEAR_SCREEN, sizeof(CLEAR_SCREEN) - 1);
    }

    return 0;
}
