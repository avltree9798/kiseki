/*
 * date - print or set the system date and time
 *
 * Usage: date [-u] [+FORMAT]
 *
 * Flags:
 *   -u        print UTC (default, since we only support UTC)
 *   --help    display help and exit
 *
 * Format specifiers:
 *   %Y  four-digit year          %m  month (01-12)
 *   %d  day of month (01-31)     %H  hour (00-23)
 *   %M  minute (00-59)           %S  second (00-59)
 *   %a  abbreviated weekday      %A  full weekday name
 *   %b  abbreviated month name   %B  full month name
 *   %j  day of year (001-366)    %u  day of week (1=Mon..7=Sun)
 *   %s  seconds since epoch      %n  newline
 *   %t  tab                      %%  literal percent
 *
 * Default format: "%a %b %e %H:%M:%S UTC %Y"
 * (%e is day of month, space-padded)
 *
 * Time is obtained by reading the ARM64 generic timer (cntvct_el0)
 * plus the Unix epoch offset stored in the CommPage. Since the RTC
 * integration is not yet complete, we read a boot-time epoch file
 * at /etc/epoch if available, or default to epoch 0 (1970-01-01).
 *
 * Kiseki OS coreutils
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

static const char *progname = "date";

/* ========================================================================== */
/* Epoch-to-calendar conversion (UTC only)                                    */
/* ========================================================================== */

struct tm_simple {
    int tm_sec;     /* 0-59 */
    int tm_min;     /* 0-59 */
    int tm_hour;    /* 0-23 */
    int tm_mday;    /* 1-31 */
    int tm_mon;     /* 0-11 */
    int tm_year;    /* years since 1900 */
    int tm_wday;    /* 0=Sunday, 1=Monday, ... 6=Saturday */
    int tm_yday;    /* 0-365 */
};

static int is_leap_year(int year)
{
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

static int days_in_month(int month, int year)
{
    static const int dtab[12] = {
        31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
    };
    if (month == 1 && is_leap_year(year))
        return 29;
    return dtab[month];
}

static int days_in_year(int year)
{
    return is_leap_year(year) ? 366 : 365;
}

/*
 * Convert epoch seconds (UTC) to broken-down time.
 * Handles dates from 1970 onwards correctly, including leap years.
 */
static void epoch_to_tm(time_t epoch, struct tm_simple *tm)
{
    long long rem = (long long)epoch;
    int year, month;

    /* Handle negative epochs (before 1970) minimally */
    if (rem < 0) {
        memset(tm, 0, sizeof(*tm));
        return;
    }

    /* Compute day of week: Jan 1, 1970 was a Thursday (wday=4) */
    long long total_days = rem / 86400;
    tm->tm_wday = (int)((total_days + 4) % 7);
    if (tm->tm_wday < 0)
        tm->tm_wday += 7;

    /* Time within the day */
    rem = rem % 86400;
    tm->tm_hour = (int)(rem / 3600);
    rem %= 3600;
    tm->tm_min = (int)(rem / 60);
    tm->tm_sec = (int)(rem % 60);

    /* Walk years from 1970 */
    year = 1970;
    while (total_days >= days_in_year(year)) {
        total_days -= days_in_year(year);
        year++;
    }
    tm->tm_year = year - 1900;
    tm->tm_yday = (int)total_days;

    /* Walk months */
    month = 0;
    while (month < 11 && total_days >= days_in_month(month, year)) {
        total_days -= days_in_month(month, year);
        month++;
    }
    tm->tm_mon = month;
    tm->tm_mday = (int)total_days + 1;
}

/* ========================================================================== */
/* Name tables                                                                */
/* ========================================================================== */

static const char *weekday_abbr[] = {
    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};

static const char *weekday_full[] = {
    "Sunday", "Monday", "Tuesday", "Wednesday",
    "Thursday", "Friday", "Saturday"
};

static const char *month_abbr[] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

static const char *month_full[] = {
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December"
};

/* ========================================================================== */
/* Time acquisition                                                           */
/* ========================================================================== */

/*
 * Get the current time as epoch seconds.
 *
 * Uses time() which on Kiseki OS goes through the libSystem syscall
 * wrapper. If that returns -1 (not implemented), falls back to reading
 * /etc/epoch (a boot-time snapshot of the Unix timestamp).
 */
static time_t get_epoch_seconds(void)
{
    time_t now = time(NULL);
    if (now != (time_t)-1)
        return now;

    /* Fallback: read boot-time epoch from /etc/epoch */
    time_t boot_epoch = 0;
    FILE *fp = fopen("/etc/epoch", "r");
    if (fp) {
        char buf[32];
        if (fgets(buf, (int)sizeof(buf), fp))
            boot_epoch = (time_t)strtol(buf, NULL, 10);
        fclose(fp);
    }

    return boot_epoch;
}

/* ========================================================================== */
/* Format string processing                                                   */
/* ========================================================================== */

static void format_time(const char *fmt, const struct tm_simple *tm,
                        time_t epoch)
{
    const char *p = fmt;
    char numbuf[32];

    while (*p) {
        if (*p != '%') {
            putchar(*p);
            p++;
            continue;
        }
        p++; /* skip '%' */
        if (*p == '\0')
            break;

        switch (*p) {
        case 'Y': /* four-digit year */
            printf("%04d", tm->tm_year + 1900);
            break;
        case 'm': /* month 01-12 */
            printf("%02d", tm->tm_mon + 1);
            break;
        case 'd': /* day of month 01-31 */
            printf("%02d", tm->tm_mday);
            break;
        case 'e': /* day of month, space-padded */
            printf("%2d", tm->tm_mday);
            break;
        case 'H': /* hour 00-23 */
            printf("%02d", tm->tm_hour);
            break;
        case 'M': /* minute 00-59 */
            printf("%02d", tm->tm_min);
            break;
        case 'S': /* second 00-59 */
            printf("%02d", tm->tm_sec);
            break;
        case 'a': /* abbreviated weekday */
            fputs(weekday_abbr[tm->tm_wday], stdout);
            break;
        case 'A': /* full weekday */
            fputs(weekday_full[tm->tm_wday], stdout);
            break;
        case 'b': /* abbreviated month */
        case 'h': /* %h is the same as %b */
            fputs(month_abbr[tm->tm_mon], stdout);
            break;
        case 'B': /* full month */
            fputs(month_full[tm->tm_mon], stdout);
            break;
        case 'j': /* day of year 001-366 */
            printf("%03d", tm->tm_yday + 1);
            break;
        case 'u': /* ISO day of week: 1=Monday..7=Sunday */
            printf("%d", tm->tm_wday == 0 ? 7 : tm->tm_wday);
            break;
        case 'w': /* day of week: 0=Sunday..6=Saturday */
            printf("%d", tm->tm_wday);
            break;
        case 's': /* seconds since epoch */
            snprintf(numbuf, sizeof(numbuf), "%ld", (long)epoch);
            fputs(numbuf, stdout);
            break;
        case 'n': /* newline */
            putchar('\n');
            break;
        case 't': /* tab */
            putchar('\t');
            break;
        case '%': /* literal % */
            putchar('%');
            break;
        case 'Z': /* timezone abbreviation */
            fputs("UTC", stdout);
            break;
        case 'F': /* %Y-%m-%d */
            printf("%04d-%02d-%02d",
                   tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);
            break;
        case 'T': /* %H:%M:%S */
            printf("%02d:%02d:%02d",
                   tm->tm_hour, tm->tm_min, tm->tm_sec);
            break;
        case 'R': /* %H:%M */
            printf("%02d:%02d", tm->tm_hour, tm->tm_min);
            break;
        case 'D': /* %m/%d/%y */
            printf("%02d/%02d/%02d",
                   tm->tm_mon + 1, tm->tm_mday,
                   (tm->tm_year + 1900) % 100);
            break;
        case 'c': /* locale date and time (use default format) */
            printf("%s %s %2d %02d:%02d:%02d %04d",
                   weekday_abbr[tm->tm_wday],
                   month_abbr[tm->tm_mon],
                   tm->tm_mday,
                   tm->tm_hour, tm->tm_min, tm->tm_sec,
                   tm->tm_year + 1900);
            break;
        case 'x': /* locale date */
            printf("%02d/%02d/%04d",
                   tm->tm_mon + 1, tm->tm_mday, tm->tm_year + 1900);
            break;
        case 'X': /* locale time */
            printf("%02d:%02d:%02d",
                   tm->tm_hour, tm->tm_min, tm->tm_sec);
            break;
        case 'y': /* two-digit year */
            printf("%02d", (tm->tm_year + 1900) % 100);
            break;
        case 'C': /* century */
            printf("%02d", (tm->tm_year + 1900) / 100);
            break;
        case 'I': /* hour 01-12 */
            {
                int h = tm->tm_hour % 12;
                if (h == 0) h = 12;
                printf("%02d", h);
            }
            break;
        case 'p': /* AM/PM */
            fputs(tm->tm_hour < 12 ? "AM" : "PM", stdout);
            break;
        case 'P': /* am/pm */
            fputs(tm->tm_hour < 12 ? "am" : "pm", stdout);
            break;
        case 'r': /* 12-hour time with AM/PM */
            {
                int h = tm->tm_hour % 12;
                if (h == 0) h = 12;
                printf("%02d:%02d:%02d %s",
                       h, tm->tm_min, tm->tm_sec,
                       tm->tm_hour < 12 ? "AM" : "PM");
            }
            break;
        default:
            /* Unknown specifier: print as-is */
            putchar('%');
            putchar(*p);
            break;
        }
        p++;
    }
}

/* ========================================================================== */
/* Usage and main                                                             */
/* ========================================================================== */

static void usage(void)
{
    fprintf(stderr, "Usage: %s [-u] [+FORMAT]\n", progname);
    fprintf(stderr, "Display the current time.\n\n");
    fprintf(stderr, "  -u        print UTC time (default)\n");
    fprintf(stderr, "  +FORMAT   output format string\n");
    fprintf(stderr, "  --help    display this help and exit\n");
}

int main(int argc, char *argv[])
{
    const char *format = NULL;

    /* Parse options */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            usage();
            return 0;
        }
        if (strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--utc") == 0 ||
            strcmp(argv[i], "--universal") == 0) {
            /* UTC is the default and only mode */
            continue;
        }
        if (argv[i][0] == '+') {
            format = &argv[i][1];
            continue;
        }
        if (argv[i][0] == '-' && argv[i][1] != '\0') {
            fprintf(stderr, "%s: invalid option -- '%s'\n",
                    progname, argv[i]);
            usage();
            return 1;
        }
        fprintf(stderr, "%s: extra operand '%s'\n", progname, argv[i]);
        usage();
        return 1;
    }

    /* Default format: "Thu Jan  1 00:00:00 UTC 1970" */
    if (!format)
        format = "%a %b %e %H:%M:%S UTC %Y";

    /* Get current time */
    time_t now = get_epoch_seconds();

    /* Convert to broken-down time */
    struct tm_simple tm;
    epoch_to_tm(now, &tm);

    /* Format and print */
    format_time(format, &tm, now);
    putchar('\n');

    return 0;
}
