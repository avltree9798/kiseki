/*
 * Kiseki OS - /sbin/init (PID 1)
 *
 * Classic BSD init: spawns getty on the console, waits for it to exit,
 * respawns. Also reaps orphaned zombie processes.
 *
 * Boot chain:
 *   kernel → init → getty → login → shell
 *
 * Compiled with: clang -o init init.c
 * (Normal macOS arm64 Mach-O binary, runs on Kiseki via dyld + libSystem)
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>

/*
 * Spawn getty on the console.
 * Returns the child PID, or -1 on failure.
 */
static int spawn_getty(void)
{
    int pid = fork();

    if (pid < 0) {
        /* fork failed */
        printf("init: fork failed\n");
        return -1;
    }

    if (pid == 0) {
        /* Child: exec getty */
        char *argv[] = { "getty", "/dev/console", NULL };
        char *envp[] = {
            "PATH=/bin:/sbin:/usr/bin:/usr/sbin",
            "HOME=/root",
            "TERM=vt100",
            "USER=root",
            "SHELL=/bin/bash",
            NULL
        };

        execve("/sbin/getty", argv, envp);

        /* If getty doesn't exist, try running login directly */
        argv[0] = "login";
        execve("/bin/login", argv, envp);

        /* Last resort: try bash */
        argv[0] = "-bash";
        execve("/bin/bash", argv, envp);

        printf("init: cannot exec getty, login, or bash\n");
        _exit(1);
    }

    /* Parent: return child PID */
    return pid;
}

int main(void)
{
    printf("\n");
    printf("Kiseki OS v0.1\n");
    printf("Copyright (c) 2026 Kiseki Project\n");
    printf("\n");

    /* We should be PID 1 */
    int mypid = getpid();
    if (mypid != 1) {
        printf("init: warning: running as PID %d (expected 1)\n", mypid);
    }

    /* Main loop: spawn getty, wait for it, respawn */
    for (;;) {
        int getty_pid = spawn_getty();
        if (getty_pid < 0) {
            printf("init: failed to spawn getty, retrying in 3s...\n");
            /* Simple busy-wait delay (no real sleep syscall yet) */
            for (volatile int i = 0; i < 50000000; i++)
                ;
            continue;
        }

        printf("init: spawned getty (PID %d)\n", getty_pid);

        /* Wait for the getty/login/shell chain to exit */
        for (;;) {
            int status = 0;
            int rpid = wait4(-1, &status, 0, NULL);

            if (rpid < 0) {
                /* No more children — shouldn't happen for init */
                break;
            }

            if (rpid == getty_pid) {
                /* Our getty exited — respawn it */
                printf("\ninit: getty (PID %d) exited with status %d\n",
                       rpid, (status >> 8) & 0xFF);
                break;
            }

            /* Reaped an orphaned zombie — keep waiting for getty */
        }
    }

    /* Should never reach here */
    return 0;
}
