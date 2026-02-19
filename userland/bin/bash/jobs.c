/*
 * Kiseki OS - Shell Job Control
 *
 * Manages background and stopped jobs, process groups,
 * terminal ownership, and SIGCHLD handling.
 */

#include "shell.h"

/* ---------- Global shell state (for signal handler) ---------- */

extern shell_state_t *g_shell;

/* ---------- Signal names (for display) ---------- */

static const char *signal_name(int sig)
{
    switch (sig) {
    case SIGHUP:  return "Hangup";
    case SIGINT:  return "Interrupt";
    case SIGQUIT: return "Quit";
    case SIGILL:  return "Illegal instruction";
    case SIGTRAP: return "Trace/BPT trap";
    case SIGABRT: return "Abort trap";
    case SIGFPE:  return "Floating point exception";
    case SIGKILL: return "Killed";
    case SIGBUS:  return "Bus error";
    case SIGSEGV: return "Segmentation fault";
    case SIGPIPE: return "Broken pipe";
    case SIGALRM: return "Alarm clock";
    case SIGTERM: return "Terminated";
    case SIGTSTP: return "Suspended";
    case SIGCONT: return "Continued";
    case SIGTTIN: return "Stopped (tty input)";
    case SIGTTOU: return "Stopped (tty output)";
    default:      return "Signal";
    }
}

/* ---------- SIGCHLD handler ---------- */

static void sigchld_handler(int sig)
{
    (void)sig;

    if (!g_shell) return;

    int saved_errno = errno;
    pid_t pid;
    int wstatus;

    while ((pid = waitpid(-1, &wstatus, WNOHANG | WUNTRACED)) > 0) {
        /* Find the job that owns this pid */
        for (int i = 0; i < MAX_JOBS; i++) {
            job_t *job = &g_shell->jobs[i];
            if (job->pgid == 0) continue;

            for (int j = 0; j < job->npids; j++) {
                if (job->pids[j] != pid) continue;

                if (WIFEXITED(wstatus)) {
                    job->statuses[j] = WEXITSTATUS(wstatus);
                    /* Check if all pids in job are done */
                    int all_done = 1;
                    for (int k = 0; k < job->npids; k++) {
                        if (job->statuses[k] < 0)
                            all_done = 0;
                    }
                    if (all_done) {
                        job->status = JOB_DONE;
                        job->notified = 0;
                    }
                } else if (WIFSIGNALED(wstatus)) {
                    job->statuses[j] = 128 + WTERMSIG(wstatus);
                    job->status = JOB_TERMINATED;
                    job->notified = 0;
                } else if (WIFSTOPPED(wstatus)) {
                    job->status = JOB_STOPPED;
                    job->notified = 0;
                }
                goto next_pid;
            }
        }
next_pid:
        ;
    }

    errno = saved_errno;
}

/* ---------- job_init ---------- */

void job_init(shell_state_t *state)
{
    /* Initialize job table */
    memset(state->jobs, 0, sizeof(state->jobs));
    state->njobs = 0;
    state->next_job_id = 1;

    if (!state->opts.interactive)
        return;

    /* Get the terminal fd */
    state->terminal_fd = STDIN_FILENO;
    if (!isatty(state->terminal_fd))
        state->terminal_fd = -1;

    if (state->terminal_fd < 0)
        return;

    /* Loop until we are in the foreground */
    while (tcgetpgrp(state->terminal_fd) != (state->shell_pgid = getpgrp())) {
        kill(-state->shell_pgid, SIGTTIN);
    }

    /* Put ourselves in our own process group */
    state->shell_pgid = getpid();
    if (setpgid(state->shell_pgid, state->shell_pgid) < 0) {
        /* May fail if already group leader, that's ok */
    }

    /* Take control of terminal */
    tcsetpgrp(state->terminal_fd, state->shell_pgid);

    /* Install SIGCHLD handler */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigchld_handler;
    sa.sa_flags = SA_RESTART;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGCHLD, &sa, NULL);
}

/* ---------- job_add ---------- */

int job_add(shell_state_t *state, pid_t pgid, const char *cmd_str)
{
    /* Find a free slot */
    for (int i = 0; i < MAX_JOBS; i++) {
        if (state->jobs[i].pgid == 0) {
            job_t *job = &state->jobs[i];
            job->id = state->next_job_id++;
            job->pgid = pgid;
            job->pids = malloc(sizeof(pid_t));
            job->pids[0] = pgid;
            job->npids = 1;
            job->statuses = malloc(sizeof(int));
            job->statuses[0] = -1; /* Pending */
            job->status = JOB_RUNNING;
            job->command = cmd_str ? strdup(cmd_str) : strdup("");
            job->foreground = 0;
            job->notified = 0;
            state->njobs++;
            return job->id;
        }
    }
    fprintf(stderr, "bash: too many jobs\n");
    return -1;
}

/* ---------- job_remove ---------- */

void job_remove(shell_state_t *state, int job_id)
{
    for (int i = 0; i < MAX_JOBS; i++) {
        if (state->jobs[i].id == job_id && state->jobs[i].pgid > 0) {
            free(state->jobs[i].pids);
            free(state->jobs[i].statuses);
            free(state->jobs[i].command);
            memset(&state->jobs[i], 0, sizeof(job_t));
            if (state->njobs > 0) state->njobs--;
            return;
        }
    }
}

/* ---------- job_find_by_pid ---------- */

job_t *job_find_by_pid(shell_state_t *state, pid_t pid)
{
    for (int i = 0; i < MAX_JOBS; i++) {
        if (state->jobs[i].pgid == 0) continue;
        for (int j = 0; j < state->jobs[i].npids; j++) {
            if (state->jobs[i].pids[j] == pid)
                return &state->jobs[i];
        }
    }
    return NULL;
}

/* ---------- job_notify ---------- */

void job_notify(shell_state_t *state)
{
    for (int i = 0; i < MAX_JOBS; i++) {
        job_t *job = &state->jobs[i];
        if (job->pgid == 0) continue;
        if (job->notified) continue;

        switch (job->status) {
        case JOB_DONE:
            fprintf(stderr, "[%d]+  Done\t\t\t%s\n",
                    job->id, job->command ? job->command : "");
            job->notified = 1;
            /* Clean up */
            job_remove(state, job->id);
            break;

        case JOB_TERMINATED:
            fprintf(stderr, "[%d]+  Terminated\t\t%s\n",
                    job->id, job->command ? job->command : "");
            job->notified = 1;
            job_remove(state, job->id);
            break;

        case JOB_STOPPED:
            if (!job->notified) {
                fprintf(stderr, "[%d]+  Stopped\t\t\t%s\n",
                        job->id, job->command ? job->command : "");
                job->notified = 1;
            }
            break;

        case JOB_RUNNING:
            break;
        }
    }
}

/* ---------- job_fg ---------- */

int job_fg(shell_state_t *state, int job_id)
{
    for (int i = 0; i < MAX_JOBS; i++) {
        if (state->jobs[i].id != job_id || state->jobs[i].pgid == 0)
            continue;

        job_t *job = &state->jobs[i];

        /* Give terminal to job's process group */
        if (state->terminal_fd >= 0)
            tcsetpgrp(state->terminal_fd, job->pgid);

        /* Send SIGCONT if stopped */
        if (job->status == JOB_STOPPED)
            kill(-job->pgid, SIGCONT);

        job->status = JOB_RUNNING;
        job->foreground = 1;

        /* Wait for job */
        int wstatus;
        pid_t wpid;
        do {
            wpid = waitpid(-job->pgid, &wstatus, WUNTRACED);
        } while (wpid < 0 && errno == EINTR);

        /* Restore terminal to shell */
        if (state->terminal_fd >= 0)
            tcsetpgrp(state->terminal_fd, state->shell_pgid);

        if (WIFEXITED(wstatus)) {
            int status = WEXITSTATUS(wstatus);
            job_remove(state, job_id);
            return status;
        }
        if (WIFSTOPPED(wstatus)) {
            job->status = JOB_STOPPED;
            job->notified = 0;
            fprintf(stderr, "\n[%d]+  Stopped\t\t\t%s\n",
                    job->id, job->command ? job->command : "");
            return 128 + WSTOPSIG(wstatus);
        }
        if (WIFSIGNALED(wstatus)) {
            int sig = WTERMSIG(wstatus);
            fprintf(stderr, "%s: %d\n", signal_name(sig), (int)wpid);
            job_remove(state, job_id);
            return 128 + sig;
        }

        return 0;
    }

    fprintf(stderr, "bash: fg: %%%d: no such job\n", job_id);
    return 1;
}

/* ---------- job_bg ---------- */

int job_bg(shell_state_t *state, int job_id)
{
    for (int i = 0; i < MAX_JOBS; i++) {
        if (state->jobs[i].id != job_id || state->jobs[i].pgid == 0)
            continue;

        job_t *job = &state->jobs[i];

        kill(-job->pgid, SIGCONT);
        job->status = JOB_RUNNING;
        job->foreground = 0;

        fprintf(stderr, "[%d]+ %s &\n",
                job->id, job->command ? job->command : "");
        return 0;
    }

    fprintf(stderr, "bash: bg: %%%d: no such job\n", job_id);
    return 1;
}

/* ---------- job_wait ---------- */

int job_wait(shell_state_t *state, pid_t pid)
{
    job_t *job = job_find_by_pid(state, pid);
    if (!job) {
        /* Not tracked as a job, just waitpid */
        int wstatus;
        pid_t wpid = waitpid(pid, &wstatus, 0);
        if (wpid < 0) return 127;
        if (WIFEXITED(wstatus)) return WEXITSTATUS(wstatus);
        if (WIFSIGNALED(wstatus)) return 128 + WTERMSIG(wstatus);
        return 0;
    }

    /* Wait for the job's process group */
    while (job->status == JOB_RUNNING) {
        int wstatus;
        pid_t wpid = waitpid(-job->pgid, &wstatus, WUNTRACED);
        if (wpid < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
            int status = WIFEXITED(wstatus) ?
                         WEXITSTATUS(wstatus) : 128 + WTERMSIG(wstatus);
            job->status = WIFEXITED(wstatus) ? JOB_DONE : JOB_TERMINATED;
            return status;
        }
        if (WIFSTOPPED(wstatus)) {
            job->status = JOB_STOPPED;
            return 128 + WSTOPSIG(wstatus);
        }
    }

    return 0;
}

/* ---------- job_format ---------- */

void job_format(job_t *job, char *buf, size_t bufsz)
{
    if (!job || !buf || bufsz == 0) return;

    const char *status_str;
    switch (job->status) {
    case JOB_RUNNING:    status_str = "Running"; break;
    case JOB_STOPPED:    status_str = "Stopped"; break;
    case JOB_DONE:       status_str = "Done"; break;
    case JOB_TERMINATED: status_str = "Terminated"; break;
    default:             status_str = "Unknown"; break;
    }

    snprintf(buf, bufsz, "[%d]%c  %-12s %s",
             job->id,
             '+',  /* Simplified: always mark as current */
             status_str,
             job->command ? job->command : "");
}
