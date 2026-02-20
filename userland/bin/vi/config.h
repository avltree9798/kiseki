/*
 * Kiseki OS configuration for levee (vi)
 *
 * Levee is a small vi clone by David L. Parsons.
 * This configuration targets Kiseki's VT100-compatible terminal.
 */
#ifndef __AC_LEVEE_D
#define __AC_LEVEE_D 1

/* Target platform */
#define OS_UNIX 1

/* Edit buffer size (64KB should be plenty) */
#define EDITSIZE 65536

/* Standard headers we have */
#define HAVE_STRING_H 1
#define HAVE_MEMSET 1
#define HAVE_STRCHR 1
#define HAVE_STRDUP 1
#define HAVE_SIGNAL_H 1
#define HAVE_TERMIOS_H 1
#define HAVE_TCGETATTR 1
#define HAVE_PWD_H 1
#define HAVE_BASENAME 1
#define HAVE_SYS_WAIT_H 1
#define HAVE_ERRNO_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_UNISTD_H 1
#define HAVE_PID_T 1

/* Process ID type */
#define os_pid_t pid_t

/* Use termcap library (our libSystem provides minimal termcap) */
#define USE_TERMCAP 1
#define HAVE_TERMCAP_H 1

/* No glob() - use levee's built-in filename handling */
/* #undef USING_GLOB */
/* #undef HAVE_GLOB_H */
/* #undef HAVE_GLOB */

/* No getopt.h header - getopt() is in libSystem */
/* #undef HAVE_GETOPT_H */

/* Hard EOL (always use \n) */
#define HARD_EOL 1

/* Use stdio for output buffering */
#define USING_STDIO 1

/* Paths for helper programs */
#define PATH_SED "/bin/sed"

#endif /* __AC_LEVEE_D */
