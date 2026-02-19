/*
 * yes - output a string repeatedly until killed
 *
 * Usage: yes [STRING ...]
 *
 * If no STRING is given, output "y" repeatedly.
 * If multiple arguments are given, join them with spaces.
 *
 * Kiseki OS coreutils
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    char buf[8192];

    if (argc <= 1) {
        /* Default: output "y\n" */
        buf[0] = 'y';
        buf[1] = '\n';
        buf[2] = '\0';
    } else {
        /* Join arguments with spaces */
        size_t off = 0;
        for (int i = 1; i < argc; i++) {
            size_t len = strlen(argv[i]);
            if (off + len + 2 > sizeof(buf))
                break;
            memcpy(buf + off, argv[i], len);
            off += len;
            if (i + 1 < argc)
                buf[off++] = ' ';
        }
        buf[off++] = '\n';
        buf[off] = '\0';
    }

    size_t len = strlen(buf);
    for (;;) {
        if (write(STDOUT_FILENO, buf, len) < 0)
            return 1;
    }

    return 0;
}
