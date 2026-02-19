/*
 * dirname - strip last component from file name
 *
 * Usage: dirname NAME...
 *
 * Kiseki OS coreutils
 */

#include <stdio.h>
#include <string.h>

static const char *progname = "dirname";

static void do_dirname(const char *path)
{
    size_t len = strlen(path);

    /* Handle empty string */
    if (len == 0) {
        puts(".");
        return;
    }

    /* Strip trailing slashes */
    while (len > 1 && path[len - 1] == '/')
        len--;

    /* If entire string is just "/", return "/" */
    if (len == 1 && path[0] == '/') {
        puts("/");
        return;
    }

    /* Strip last non-slash component */
    while (len > 0 && path[len - 1] != '/')
        len--;

    /* If no slash was found, return "." */
    if (len == 0) {
        puts(".");
        return;
    }

    /* Strip trailing slashes from directory part */
    while (len > 1 && path[len - 1] == '/')
        len--;

    fwrite(path, 1, len, stdout);
    putchar('\n');
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s NAME...\n", progname);
        return 1;
    }

    int first_arg = 1;

    /* Skip -- if present */
    if (argc > 1 && strcmp(argv[1], "--") == 0)
        first_arg = 2;

    if (first_arg >= argc) {
        fprintf(stderr, "Usage: %s NAME...\n", progname);
        return 1;
    }

    for (int i = first_arg; i < argc; i++)
        do_dirname(argv[i]);

    return 0;
}
