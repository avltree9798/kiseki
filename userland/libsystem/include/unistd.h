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
char   *getcwd(char *buf, size_t size);
ssize_t readlink(const char *pathname, char *buf, size_t bufsiz);
int     isatty(int fd);
int     link(const char *oldpath, const char *newpath);
int     symlink(const char *target, const char *linkpath);

/* Device control */
int     ioctl(int fd, unsigned long request, ...);

/* Misc */
unsigned int sleep(unsigned int seconds);
int     usleep(useconds_t usec);

/* brk/sbrk - not available on XNU, malloc uses mmap instead */

/* Environment (declared here, defined in stdlib.c) */
extern char **environ;

#endif /* _LIBSYSTEM_UNISTD_H */
