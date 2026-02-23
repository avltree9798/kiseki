/*
 * Kiseki OS - Resource Usage Definitions
 *
 * Darwin ARM64 ABI compatible struct rusage and related definitions.
 */

#ifndef _LIBSYSTEM_SYS_RESOURCE_H
#define _LIBSYSTEM_SYS_RESOURCE_H

#include <sys/time.h>

/*
 * struct rusage - Resource usage statistics (Darwin ARM64: 144 bytes)
 *
 * Used by wait4(), getrusage() to report resource consumption.
 */
struct rusage {
    struct timeval ru_utime;    /*   0: User time used */
    struct timeval ru_stime;    /*  16: System time used */
    long    ru_maxrss;          /*  32: Max resident set size */
    long    ru_ixrss;           /*  40: Integral shared text memory size */
    long    ru_idrss;           /*  48: Integral unshared data size */
    long    ru_isrss;           /*  56: Integral unshared stack size */
    long    ru_minflt;          /*  64: Page reclaims (soft page faults) */
    long    ru_majflt;          /*  72: Page faults (hard page faults) */
    long    ru_nswap;           /*  80: Swaps */
    long    ru_inblock;         /*  88: Block input operations */
    long    ru_oublock;         /*  96: Block output operations */
    long    ru_msgsnd;          /* 104: IPC messages sent */
    long    ru_msgrcv;          /* 112: IPC messages received */
    long    ru_nsignals;        /* 120: Signals received */
    long    ru_nvcsw;           /* 128: Voluntary context switches */
    long    ru_nivcsw;          /* 136: Involuntary context switches */
};                              /* 144: Total size */

/* Resource limit identifiers */
#define RLIMIT_CPU          0   /* CPU time per process */
#define RLIMIT_FSIZE        1   /* File size */
#define RLIMIT_DATA         2   /* Data segment size */
#define RLIMIT_STACK        3   /* Stack size */
#define RLIMIT_CORE         4   /* Core file size */
#define RLIMIT_AS           5   /* Address space (mapped memory) */
#define RLIMIT_RSS          5   /* Alias for RLIMIT_AS on Darwin */
#define RLIMIT_MEMLOCK      6   /* Locked memory */
#define RLIMIT_NPROC        7   /* Number of processes */
#define RLIMIT_NOFILE       8   /* Number of open files */
#define RLIM_NLIMITS        9   /* Number of resource limits */

/* Special rlim_t values */
#define RLIM_INFINITY       ((rlim_t)((1ULL << 63) - 1))
#define RLIM_SAVED_MAX      RLIM_INFINITY
#define RLIM_SAVED_CUR      RLIM_INFINITY

/* Resource limit type */
typedef uint64_t rlim_t;

/* Resource limit structure */
struct rlimit {
    rlim_t  rlim_cur;           /* Current (soft) limit */
    rlim_t  rlim_max;           /* Maximum (hard) limit */
};

/* getrusage() who argument */
#define RUSAGE_SELF         0   /* Current process */
#define RUSAGE_CHILDREN     (-1) /* Terminated child processes */

/* Priority identifiers for getpriority/setpriority */
#define PRIO_PROCESS        0   /* Process priority */
#define PRIO_PGRP           1   /* Process group priority */
#define PRIO_USER           2   /* User priority */

/* Function prototypes */
int getrusage(int who, struct rusage *rusage);
int getrlimit(int resource, struct rlimit *rlp);
int setrlimit(int resource, const struct rlimit *rlp);
int getpriority(int which, id_t who);
int setpriority(int which, id_t who, int prio);

#endif /* _LIBSYSTEM_SYS_RESOURCE_H */
