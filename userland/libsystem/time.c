/*
 * Kiseki OS - Time Functions Implementation
 */

#include <time.h>
#include <string.h>
#include <syscall.h>

/* Days in each month (non-leap year) */
static const int _days_in_month[] = {
    31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

/* Days before each month (non-leap year) */
static const int _days_before_month[] = {
    0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
};

static int _is_leap_year(int year)
{
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

/* Static buffer for ctime/asctime */
static char _time_buf[26];

/* Static struct for gmtime/localtime */
static struct tm _tm_buf;

time_t time(time_t *tloc)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) < 0)
        return (time_t)-1;
    if (tloc)
        *tloc = ts.tv_sec;
    return ts.tv_sec;
}

clock_t clock(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts) < 0)
        return (clock_t)-1;
    return ts.tv_sec * CLOCKS_PER_SEC + ts.tv_nsec / 1000;
}

double difftime(time_t time1, time_t time0)
{
    return (double)(time1 - time0);
}

/* Convert time_t to struct tm (UTC) */
struct tm *gmtime_r(const time_t *timep, struct tm *result)
{
    time_t t = *timep;
    int days, rem;
    int y;
    const int *ip;

    days = (int)(t / 86400);
    rem = (int)(t % 86400);
    if (rem < 0) {
        rem += 86400;
        days--;
    }

    result->tm_hour = rem / 3600;
    rem %= 3600;
    result->tm_min = rem / 60;
    result->tm_sec = rem % 60;

    /* January 1, 1970 was a Thursday (day 4) */
    result->tm_wday = (days + 4) % 7;
    if (result->tm_wday < 0)
        result->tm_wday += 7;

    y = 1970;
    while (days < 0 || days >= (_is_leap_year(y) ? 366 : 365)) {
        int newy;
        int leaps;

        /* Guess year and refine */
        newy = y + days / 365;
        if (days < 0)
            --newy;
        leaps = (newy - 1) / 4 - (newy - 1) / 100 + (newy - 1) / 400;
        leaps -= (y - 1) / 4 - (y - 1) / 100 + (y - 1) / 400;
        days -= (newy - y) * 365 + leaps;
        y = newy;
    }

    result->tm_year = y - 1900;
    result->tm_yday = days;

    ip = _days_before_month;
    int leap = _is_leap_year(y);
    for (result->tm_mon = 0; result->tm_mon < 11; result->tm_mon++) {
        int mdays = ip[result->tm_mon + 1] - ip[result->tm_mon];
        if (result->tm_mon == 1 && leap)
            mdays++;
        if (days < mdays)
            break;
        days -= mdays;
    }
    result->tm_mday = days + 1;
    result->tm_isdst = 0;

    return result;
}

struct tm *gmtime(const time_t *timep)
{
    return gmtime_r(timep, &_tm_buf);
}

/* localtime - for now, same as gmtime (no timezone support) */
struct tm *localtime_r(const time_t *timep, struct tm *result)
{
    return gmtime_r(timep, result);
}

struct tm *localtime(const time_t *timep)
{
    return localtime_r(timep, &_tm_buf);
}

/* Convert struct tm to time_t */
time_t mktime(struct tm *tm)
{
    int y = tm->tm_year + 1900;
    int m = tm->tm_mon;
    int d = tm->tm_mday;

    /* Normalize month */
    while (m < 0) { m += 12; y--; }
    while (m >= 12) { m -= 12; y++; }

    /* Days from epoch to start of year */
    int days = (y - 1970) * 365;
    days += (y - 1969) / 4;
    days -= (y - 1901) / 100;
    days += (y - 1601) / 400;

    /* Add days in year */
    days += _days_before_month[m];
    if (m > 1 && _is_leap_year(y))
        days++;
    days += d - 1;

    time_t t = (time_t)days * 86400;
    t += tm->tm_hour * 3600 + tm->tm_min * 60 + tm->tm_sec;

    /* Update tm struct */
    gmtime_r(&t, tm);

    return t;
}

/* Format: "Wed Jun 30 21:49:08 1993\n" */
static const char *_wday_name[] = {
    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};

static const char *_mon_name[] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

char *asctime_r(const struct tm *tm, char *buf)
{
    /* Format: "Www Mmm dd hh:mm:ss yyyy\n\0" */
    char *p = buf;
    
    /* Day of week */
    const char *wday = _wday_name[tm->tm_wday % 7];
    *p++ = wday[0]; *p++ = wday[1]; *p++ = wday[2];
    *p++ = ' ';
    
    /* Month */
    const char *mon = _mon_name[tm->tm_mon % 12];
    *p++ = mon[0]; *p++ = mon[1]; *p++ = mon[2];
    *p++ = ' ';
    
    /* Day */
    if (tm->tm_mday < 10) {
        *p++ = ' ';
        *p++ = '0' + tm->tm_mday;
    } else {
        *p++ = '0' + tm->tm_mday / 10;
        *p++ = '0' + tm->tm_mday % 10;
    }
    *p++ = ' ';
    
    /* Hour */
    *p++ = '0' + tm->tm_hour / 10;
    *p++ = '0' + tm->tm_hour % 10;
    *p++ = ':';
    
    /* Minute */
    *p++ = '0' + tm->tm_min / 10;
    *p++ = '0' + tm->tm_min % 10;
    *p++ = ':';
    
    /* Second */
    *p++ = '0' + tm->tm_sec / 10;
    *p++ = '0' + tm->tm_sec % 10;
    *p++ = ' ';
    
    /* Year */
    int year = tm->tm_year + 1900;
    *p++ = '0' + (year / 1000) % 10;
    *p++ = '0' + (year / 100) % 10;
    *p++ = '0' + (year / 10) % 10;
    *p++ = '0' + year % 10;
    *p++ = '\n';
    *p = '\0';
    
    return buf;
}

char *asctime(const struct tm *tm)
{
    return asctime_r(tm, _time_buf);
}

char *ctime_r(const time_t *timep, char *buf)
{
    struct tm tm;
    localtime_r(timep, &tm);
    return asctime_r(&tm, buf);
}

char *ctime(const time_t *timep)
{
    return ctime_r(timep, _time_buf);
}

/* Minimal strftime - enough for TCC */
size_t strftime(char *s, size_t max, const char *format, const struct tm *tm)
{
    size_t i = 0;
    
    while (*format && i < max - 1) {
        if (*format != '%') {
            s[i++] = *format++;
            continue;
        }
        format++;
        
        char buf[32];
        const char *str = buf;
        
        switch (*format++) {
            case 'a': str = _wday_name[tm->tm_wday % 7]; break;
            case 'b':
            case 'h': str = _mon_name[tm->tm_mon % 12]; break;
            case 'd':
                buf[0] = '0' + tm->tm_mday / 10;
                buf[1] = '0' + tm->tm_mday % 10;
                buf[2] = '\0';
                break;
            case 'H':
                buf[0] = '0' + tm->tm_hour / 10;
                buf[1] = '0' + tm->tm_hour % 10;
                buf[2] = '\0';
                break;
            case 'M':
                buf[0] = '0' + tm->tm_min / 10;
                buf[1] = '0' + tm->tm_min % 10;
                buf[2] = '\0';
                break;
            case 'S':
                buf[0] = '0' + tm->tm_sec / 10;
                buf[1] = '0' + tm->tm_sec % 10;
                buf[2] = '\0';
                break;
            case 'Y': {
                int y = tm->tm_year + 1900;
                buf[0] = '0' + (y / 1000) % 10;
                buf[1] = '0' + (y / 100) % 10;
                buf[2] = '0' + (y / 10) % 10;
                buf[3] = '0' + y % 10;
                buf[4] = '\0';
                break;
            }
            case 'm':
                buf[0] = '0' + (tm->tm_mon + 1) / 10;
                buf[1] = '0' + (tm->tm_mon + 1) % 10;
                buf[2] = '\0';
                break;
            case '%':
                buf[0] = '%';
                buf[1] = '\0';
                break;
            case 'n':
                buf[0] = '\n';
                buf[1] = '\0';
                break;
            case 't':
                buf[0] = '\t';
                buf[1] = '\0';
                break;
            default:
                buf[0] = '%';
                buf[1] = format[-1];
                buf[2] = '\0';
                break;
        }
        
        while (*str && i < max - 1)
            s[i++] = *str++;
    }
    
    s[i] = '\0';
    return i;
}

/* POSIX clock functions - syscall wrappers */
int clock_gettime(clockid_t clk_id, struct timespec *tp)
{
    return (int)syscall2(SYS_clock_gettime, (long)clk_id, (long)tp);
}

int clock_settime(clockid_t clk_id, const struct timespec *tp)
{
    return (int)syscall2(SYS_clock_settime, (long)clk_id, (long)tp);
}

int nanosleep(const struct timespec *req, struct timespec *rem)
{
    return (int)syscall2(SYS_nanosleep, (long)req, (long)rem);
}
