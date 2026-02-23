/*
 * Kiseki OS - POSIX-like Unistd Wrappers
 */

#ifndef _LIBSYSTEM_UNISTD_H
#define _LIBSYSTEM_UNISTD_H

#include <types.h>

/* Standard file descriptors */
#define STDIN_FILENO    0
#define STDOUT_FILENO   1
#define STDERR_FILENO   2

/* access() mode flags */
#define F_OK            0       /* Test for existence */
#define X_OK            1       /* Test for execute permission */
#define W_OK            2       /* Test for write permission */
#define R_OK            4       /* Test for read permission */

/* lseek whence (also in stdio.h) */
#define SEEK_SET        0
#define SEEK_CUR        1
#define SEEK_END        2

/* File I/O */
ssize_t read(int fd, void *buf, size_t count);
ssize_t write(int fd, const void *buf, size_t count);
int     close(int fd);
off_t   lseek(int fd, off_t offset, int whence);

/* File descriptor manipulation */
int     dup(int oldfd);
int     dup2(int oldfd, int newfd);
int     pipe(int pipefd[2]);

/* Process control */
pid_t   fork(void);
int     execve(const char *pathname, char *const argv[], char *const envp[]);
int     execvp(const char *file, char *const argv[]);
int     execv(const char *pathname, char *const argv[]);
void    _exit(int status) __attribute__((noreturn));

/* Process IDs */
pid_t   getpid(void);
pid_t   getppid(void);
uid_t   getuid(void);
uid_t   geteuid(void);
gid_t   getgid(void);
int     setuid(uid_t uid);

/* Session and process group */
pid_t   setsid(void);
int     setpgid(pid_t pid, pid_t pgid);
pid_t   getpgrp(void);
pid_t   tcgetpgrp(int fd);
int     tcsetpgrp(int fd, pid_t pgrp);

/* File operations */
int     access(const char *pathname, int mode);
int     unlink(const char *pathname);
int     rmdir(const char *pathname);
int     chdir(const char *path);
int     fchdir(int fd);
char   *getcwd(char *buf, size_t size);
ssize_t readlink(const char *pathname, char *buf, size_t bufsiz);
int     isatty(int fd);
int     link(const char *oldpath, const char *newpath);
int     symlink(const char *target, const char *linkpath);
int     chroot(const char *path);

/* File truncation */
int     truncate(const char *path, off_t length);
int     ftruncate(int fd, off_t length);

/* File sync */
int     fsync(int fd);
int     fdatasync(int fd);
void    sync(void);

/* Device control */
int     ioctl(int fd, unsigned long request, ...);

/* Credential management */
int     setgid(gid_t gid);
gid_t   getegid(void);
int     seteuid(uid_t euid);
int     setegid(gid_t egid);
int     setreuid(uid_t ruid, uid_t euid);
int     setregid(gid_t rgid, gid_t egid);
int     getgroups(int size, gid_t list[]);
int     setgroups(int size, const gid_t *list);

/* Hostname */
int     gethostname(char *name, size_t len);
int     sethostname(const char *name, size_t len);
int     getdomainname(char *name, size_t len);
int     setdomainname(const char *name, size_t len);

/* System information */
int     getpagesize(void);
int     getdtablesize(void);
long    sysconf(int name);
long    pathconf(const char *path, int name);
long    fpathconf(int fd, int name);
size_t  confstr(int name, char *buf, size_t len);

/* Process scheduling */
int     nice(int inc);
unsigned int alarm(unsigned int seconds);
int     pause(void);

/* Misc */
unsigned int sleep(unsigned int seconds);
int     usleep(useconds_t usec);

/* Entropy */
int     getentropy(void *buf, size_t buflen);

/* sysconf names */
#define _SC_ARG_MAX             1
#define _SC_CHILD_MAX           2
#define _SC_CLK_TCK             3
#define _SC_NGROUPS_MAX         4
#define _SC_OPEN_MAX            5
#define _SC_STREAM_MAX          6
#define _SC_TZNAME_MAX          7
#define _SC_JOB_CONTROL         8
#define _SC_SAVED_IDS           9
#define _SC_VERSION             10
#define _SC_PAGESIZE            11
#define _SC_PAGE_SIZE           _SC_PAGESIZE
#define _SC_NPROCESSORS_CONF    57
#define _SC_NPROCESSORS_ONLN    58

/* pathconf/fpathconf names */
#define _PC_LINK_MAX            1
#define _PC_MAX_CANON           2
#define _PC_MAX_INPUT           3
#define _PC_NAME_MAX            4
#define _PC_PATH_MAX            5
#define _PC_PIPE_BUF            6
#define _PC_CHOWN_RESTRICTED    7
#define _PC_NO_TRUNC            8
#define _PC_VDISABLE            9

/* confstr names */
#define _CS_PATH                1

/* brk/sbrk - not available on XNU, malloc uses mmap instead */

/* Environment (declared here, defined in stdlib.c) */
extern char **environ;

#endif /* _LIBSYSTEM_UNISTD_H */
