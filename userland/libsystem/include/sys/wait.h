/*
 * Kiseki OS - Process Wait
 */

#ifndef _LIBSYSTEM_SYS_WAIT_H
#define _LIBSYSTEM_SYS_WAIT_H

#include <types.h>

/*
 * Wait status encoding (XNU/BSD-compatible):
 *
 * Bits 15-8: exit status (if WIFEXITED)
 * Bits  7-0: signal number (if WIFSIGNALED), or 0x7f (if WIFSTOPPED)
 * Bit     7: core dump flag (if WIFSIGNALED)
 *
 * WIFEXITED:   low 7 bits == 0
 * WIFSIGNALED: low 7 bits != 0 && != 0x7f
 * WIFSTOPPED:  low 8 bits == 0x7f
 */

#define WIFEXITED(status)       (((status) & 0x7f) == 0)
#define WEXITSTATUS(status)     (((status) >> 8) & 0xff)
#define WIFSIGNALED(status)     (((status) & 0x7f) != 0 && ((status) & 0x7f) != 0x7f)
#define WTERMSIG(status)        ((status) & 0x7f)
#define WCOREDUMP(status)       ((status) & 0x80)
#define WIFSTOPPED(status)      (((status) & 0xff) == 0x7f)
#define WSTOPSIG(status)        (((status) >> 8) & 0xff)
#define WIFCONTINUED(status)    ((status) == 0xffff)

/* Options for waitpid */
#define WNOHANG         0x01
#define WUNTRACED       0x02
#define WCONTINUED      0x10

pid_t   wait(int *status);
pid_t   waitpid(pid_t pid, int *status, int options);
pid_t   wait4(pid_t pid, int *status, int options, void *rusage);

#endif /* _LIBSYSTEM_SYS_WAIT_H */
