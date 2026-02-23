/*
 * Kiseki OS - Time Functions
 */

#ifndef _LIBSYSTEM_TIME_H
#define _LIBSYSTEM_TIME_H

#include <types.h>

/* Clock types */
#define CLOCK_REALTIME           0
#define CLOCK_MONOTONIC          1
#define CLOCK_PROCESS_CPUTIME_ID 2
#define CLOCK_THREAD_CPUTIME_ID  3

typedef int clockid_t;
typedef long clock_t;

#define CLOCKS_PER_SEC  1000000

/* Time structure */
struct tm {
    int tm_sec;     /* Seconds (0-60) */
    int tm_min;     /* Minutes (0-59) */
    int tm_hour;    /* Hours (0-23) */
    int tm_mday;    /* Day of month (1-31) */
    int tm_mon;     /* Month (0-11) */
    int tm_year;    /* Year - 1900 */
    int tm_wday;    /* Day of week (0-6, Sunday = 0) */
    int tm_yday;    /* Day of year (0-365) */
    int tm_isdst;   /* Daylight saving time flag */
};

/* Time functions */
time_t time(time_t *tloc);
clock_t clock(void);
double difftime(time_t time1, time_t time0);
time_t mktime(struct tm *tm);

/* Conversion functions */
char *ctime(const time_t *timep);
char *ctime_r(const time_t *timep, char *buf);
struct tm *gmtime(const time_t *timep);
struct tm *gmtime_r(const time_t *timep, struct tm *result);
struct tm *localtime(const time_t *timep);
struct tm *localtime_r(const time_t *timep, struct tm *result);
char *asctime(const struct tm *tm);
char *asctime_r(const struct tm *tm, char *buf);
size_t strftime(char *s, size_t max, const char *format, const struct tm *tm);

/* POSIX extensions */
int clock_gettime(clockid_t clk_id, struct timespec *tp);
int clock_settime(clockid_t clk_id, const struct timespec *tp);
int clock_getres(clockid_t clk_id, struct timespec *res);
int nanosleep(const struct timespec *req, struct timespec *rem);

/* C11 time functions */
#define TIME_UTC 1
int timespec_get(struct timespec *ts, int base);

/* Timer functions (stubs for compatibility) */
typedef void *timer_t;
struct itimerspec {
    struct timespec it_interval;
    struct timespec it_value;
};
int timer_create(clockid_t clockid, void *sevp, timer_t *timerid);
int timer_delete(timer_t timerid);
int timer_settime(timer_t timerid, int flags, const struct itimerspec *new_value, struct itimerspec *old_value);
int timer_gettime(timer_t timerid, struct itimerspec *curr_value);

#endif /* _LIBSYSTEM_TIME_H */
