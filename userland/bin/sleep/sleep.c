/*
 * sleep - delay for a specified amount of time
 *
 * Kiseki OS coreutils
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

static const char *progname = "sleep";

static void usage(void)
{
    fprintf(stderr, "Usage: %s NUMBER[SUFFIX]...\n", progname);
    fprintf(stderr, "Pause for NUMBER seconds.\n");
    fprintf(stderr, "SUFFIX may be 's' (seconds), 'm' (minutes), "
            "'h' (hours), or 'd' (days).\n");
    fprintf(stderr, "Multiple arguments are summed.\n");
}

/*
 * Parse a simple decimal/floating-point number manually.
 * Returns seconds as integer + microsecond parts.
 * Sets *endp to the character after the number.
 * Returns -1 on error.
 */
static int parse_duration(const char *s, unsigned int *secs,
                          useconds_t *usecs)
{
    const char *p = s;
    unsigned long whole = 0;
    unsigned long frac = 0;
    unsigned long frac_div = 1;

    /* Skip leading whitespace */
    while (*p == ' ' || *p == '\t')
        p++;

    if (*p == '\0') {
        fprintf(stderr, "%s: missing operand\n", progname);
        return -1;
    }

    /* Parse integer part */
    if (*p < '0' || *p > '9') {
        if (*p != '.') {
            fprintf(stderr, "%s: invalid time interval '%s'\n", progname, s);
            return -1;
        }
    }
    while (*p >= '0' && *p <= '9') {
        whole = whole * 10 + (unsigned long)(*p - '0');
        p++;
    }

    /* Parse fractional part */
    if (*p == '.') {
        p++;
        while (*p >= '0' && *p <= '9') {
            frac = frac * 10 + (unsigned long)(*p - '0');
            frac_div *= 10;
            p++;
        }
    }

    /* Parse suffix */
    unsigned long multiplier = 1;
    if (*p == 's' || *p == '\0') {
        multiplier = 1;
        if (*p == 's') p++;
    } else if (*p == 'm') {
        multiplier = 60;
        p++;
    } else if (*p == 'h') {
        multiplier = 3600;
        p++;
    } else if (*p == 'd') {
        multiplier = 86400;
        p++;
    } else {
        fprintf(stderr, "%s: invalid suffix '%c' in '%s'\n", progname, *p, s);
        return -1;
    }

    if (*p != '\0') {
        fprintf(stderr, "%s: invalid time interval '%s'\n", progname, s);
        return -1;
    }

    /* Compute total microseconds from fractional part */
    unsigned long frac_us = 0;
    if (frac_div > 1) {
        frac_us = (frac * 1000000UL) / frac_div;
    }

    /* Apply multiplier */
    unsigned long total_secs = whole * multiplier;
    unsigned long total_usecs = frac_us * multiplier;

    /* Carry over microseconds into seconds */
    total_secs += total_usecs / 1000000UL;
    total_usecs = total_usecs % 1000000UL;

    *secs = (unsigned int)total_secs;
    *usecs = (useconds_t)total_usecs;
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage();
        return 1;
    }

    if (strcmp(argv[1], "--help") == 0) {
        usage();
        return 0;
    }

    unsigned int total_secs = 0;
    useconds_t total_usecs = 0;

    for (int i = 1; i < argc; i++) {
        unsigned int s = 0;
        useconds_t us = 0;

        if (parse_duration(argv[i], &s, &us) < 0)
            return 1;

        total_secs += s;
        total_usecs += us;

        /* Carry */
        if (total_usecs >= 1000000) {
            total_secs += total_usecs / 1000000;
            total_usecs = total_usecs % 1000000;
        }
    }

    /* Sleep the whole seconds */
    if (total_secs > 0)
        sleep(total_secs);

    /* Sleep the remaining microseconds */
    if (total_usecs > 0)
        usleep(total_usecs);

    return 0;
}
