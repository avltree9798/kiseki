/*
 * Kiseki OS - sys/time.h
 */

#ifndef _LIBSYSTEM_SYS_TIME_H
#define _LIBSYSTEM_SYS_TIME_H

#include <types.h>

/* timeval structure */
struct timeval {
    time_t      tv_sec;     /* Seconds */
    suseconds_t tv_usec;    /* Microseconds */
};

/* timezone structure (obsolete but still used) */
struct timezone {
    int tz_minuteswest;     /* Minutes west of GMT */
    int tz_dsttime;         /* DST correction type */
};

/* Get time of day */
int gettimeofday(struct timeval *tv, struct timezone *tz);
int settimeofday(const struct timeval *tv, const struct timezone *tz);

/* Timer operations */
#define ITIMER_REAL    0
#define ITIMER_VIRTUAL 1
#define ITIMER_PROF    2

struct itimerval {
    struct timeval it_interval;  /* Timer interval */
    struct timeval it_value;     /* Current value */
};

int getitimer(int which, struct itimerval *curr_value);
int setitimer(int which, const struct itimerval *new_value,
              struct itimerval *old_value);

/* Time comparison macros */
#define timerclear(tvp)         ((tvp)->tv_sec = (tvp)->tv_usec = 0)
#define timerisset(tvp)         ((tvp)->tv_sec || (tvp)->tv_usec)
#define timercmp(a, b, CMP)     \
    (((a)->tv_sec == (b)->tv_sec) ? \
     ((a)->tv_usec CMP (b)->tv_usec) : \
     ((a)->tv_sec CMP (b)->tv_sec))
#define timeradd(a, b, result)  \
    do { \
        (result)->tv_sec = (a)->tv_sec + (b)->tv_sec; \
        (result)->tv_usec = (a)->tv_usec + (b)->tv_usec; \
        if ((result)->tv_usec >= 1000000) { \
            ++(result)->tv_sec; \
            (result)->tv_usec -= 1000000; \
        } \
    } while (0)
#define timersub(a, b, result)  \
    do { \
        (result)->tv_sec = (a)->tv_sec - (b)->tv_sec; \
        (result)->tv_usec = (a)->tv_usec - (b)->tv_usec; \
        if ((result)->tv_usec < 0) { \
            --(result)->tv_sec; \
            (result)->tv_usec += 1000000; \
        } \
    } while (0)

#endif /* _LIBSYSTEM_SYS_TIME_H */
