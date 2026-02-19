/*
 * Kiseki OS - /sbin/halt, /sbin/reboot, /sbin/shutdown
 *
 * System power management commands. These call the reboot() syscall
 * with appropriate flags to halt (power off) or reboot the system.
 *
 * Built as three separate binaries (halt, reboot, shutdown) from
 * the same source. The command name (argv[0]) determines the action.
 *
 * Usage:
 *   halt              — Power off the system
 *   reboot            — Reboot the system
 *   shutdown [-h|-r]  — Shutdown with -h (halt) or -r (reboot)
 *   shutdown          — Default: halt
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* XNU reboot() howto flags */
#define RB_AUTOBOOT     0       /* Reboot */
#define RB_HALT         0x08    /* Halt (power off) */

/* reboot syscall number (XNU SYS_reboot = 55) */
static int sys_reboot(int howto)
{
    long ret;
    __asm__ volatile(
        "mov x0, %1\n"
        "mov x16, #55\n"
        "svc #0x80\n"
        "mov %0, x0\n"
        : "=r"(ret)
        : "r"((long)howto)
        : "x0", "x1", "x16", "memory"
    );
    return (int)ret;
}

int main(int argc, char *argv[])
{
    const char *progname = argv[0];
    int howto = RB_HALT;  /* Default: halt */

    /* Determine action from program name */
    /* Find basename */
    const char *base = progname;
    for (const char *p = progname; *p; p++) {
        if (*p == '/')
            base = p + 1;
    }

    if (strcmp(base, "reboot") == 0) {
        howto = RB_AUTOBOOT;
    } else if (strcmp(base, "halt") == 0) {
        howto = RB_HALT;
    } else if (strcmp(base, "shutdown") == 0) {
        /* Parse -h / -r flags */
        howto = RB_HALT;  /* shutdown defaults to halt */
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "-r") == 0)
                howto = RB_AUTOBOOT;
            else if (strcmp(argv[i], "-h") == 0)
                howto = RB_HALT;
        }
    }

    if (howto & RB_HALT) {
        printf("The system is going down for halt NOW!\n");
    } else {
        printf("The system is going down for reboot NOW!\n");
    }

    /* Call the reboot syscall */
    int ret = sys_reboot(howto);
    if (ret != 0) {
        fprintf(stderr, "%s: reboot syscall failed (are you root?)\n", base);
        return 1;
    }

    /* Should not reach here */
    return 0;
}
