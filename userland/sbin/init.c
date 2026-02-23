/*
 * Kiseki OS - /sbin/init (PID 1) — launchd-style process manager
 *
 * Modeled after macOS launchd: reads daemon configurations from XML
 * plist files, pre-creates Mach service ports before launching daemons,
 * and manages the getty/login/shell chain on the console.
 *
 * Boot chain:
 *   kernel -> init -> { system daemons, getty -> login -> shell }
 *
 * Service readiness (matching macOS launchd):
 *   1. init scans /System/Library/LaunchDaemons/ for .plist files
 *   2. Parses each XML plist to extract Label, Program, MachServices
 *   3. For each MachService: allocates a receive port and registers
 *      it in the bootstrap namespace
 *   4. Forks and execs the daemon
 *   5. Daemon calls bootstrap_check_in() to claim its receive right
 *   6. Clients can bootstrap_look_up() at any time — no race condition
 *
 * Compiled with: clang -target arm64-apple-macos11
 * (arm64 Mach-O binary, runs on Kiseki via dyld + libSystem)
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <dirent.h>
#include <mach/mach.h>

/*
 * On macOS, bootstrap_register/bootstrap_check_in are in
 * <servers/bootstrap.h>. At runtime on Kiseki, these resolve to
 * libSystem traps. We declare them here to avoid depending on
 * the macOS SDK's version of the header.
 */
extern int bootstrap_register(unsigned int bp, const char *name,
                              unsigned int sp);
extern int bootstrap_look_up(unsigned int bp, const char *name,
                             unsigned int *sp);

/* ============================================================================
 * Constants
 * ============================================================================ */

#define LAUNCHD_SYSTEM_PATH     "/System/Library/LaunchDaemons"
#define LAUNCHD_LIBRARY_PATH    "/Library/LaunchDaemons"

#define MAX_JOBS                32
#define MAX_MACH_SERVICES       8       /* Per job */
#define MAX_LABEL_LEN           128
#define MAX_PROGRAM_LEN         256
#define MAX_SERVICE_NAME_LEN    128

/* Maximum plist file size we'll read (64KB should be plenty) */
#define MAX_PLIST_SIZE          (64 * 1024)

/* ============================================================================
 * Job Descriptor
 *
 * Each loaded plist becomes a job. Mirrors launchd's internal job struct.
 * ============================================================================ */

struct launchd_job {
    int     active;                     /* Slot in use */
    char    label[MAX_LABEL_LEN];       /* Unique job identifier */
    char    program[MAX_PROGRAM_LEN];   /* Executable path */

    /* Mach services this job advertises */
    int     num_services;
    char    service_names[MAX_MACH_SERVICES][MAX_SERVICE_NAME_LEN];
    unsigned int service_ports[MAX_MACH_SERVICES]; /* Port names in init's IPC space */

    int     keep_alive;                 /* KeepAlive flag */
    int     pid;                        /* Child PID once launched, -1 if not running */
};

static struct launchd_job jobs[MAX_JOBS];
static int num_jobs = 0;

/* ============================================================================
 * XML Plist Parser
 *
 * Minimal XML parser for Apple property list files. Handles the subset
 * of XML used by launchd plists:
 *
 *   <plist version="1.0">
 *   <dict>
 *     <key>Label</key>
 *     <string>...</string>
 *     <key>ProgramArguments</key>
 *     <array>
 *       <string>...</string>
 *     </array>
 *     <key>MachServices</key>
 *     <dict>
 *       <key>service.name</key>
 *       <true/>
 *     </dict>
 *     <key>KeepAlive</key>
 *     <true/>
 *   </dict>
 *   </plist>
 *
 * We skip <?xml?>, <!DOCTYPE>, and process only the tags we care about.
 * ============================================================================ */

/*
 * Skip past the next '>' character. Returns pointer after '>', or NULL
 * if end of string reached.
 */
static const char *skip_tag(const char *p)
{
    while (*p && *p != '>')
        p++;
    return *p ? p + 1 : NULL;
}

/*
 * Check if we're at a specific XML tag. Case-sensitive.
 * Example: at_tag(p, "key") matches "<key>" or "<key ..."
 */
static int at_tag(const char *p, const char *tag)
{
    if (*p != '<')
        return 0;
    p++;
    int len = (int)strlen(tag);
    if (strncmp(p, tag, len) != 0)
        return 0;
    /* Must be followed by '>' or whitespace (for attributes) */
    char c = p[len];
    return (c == '>' || c == ' ' || c == '\t' || c == '\n' || c == '\r');
}

/*
 * Check if we're at a closing tag: </tag>
 */
static int at_close_tag(const char *p, const char *tag)
{
    if (p[0] != '<' || p[1] != '/')
        return 0;
    p += 2;
    int len = (int)strlen(tag);
    if (strncmp(p, tag, len) != 0)
        return 0;
    return p[len] == '>';
}

/*
 * Check if we're at a self-closing tag like <true/> or <false/>
 */
static int at_self_closing(const char *p, const char *tag)
{
    if (*p != '<')
        return 0;
    p++;
    int len = (int)strlen(tag);
    if (strncmp(p, tag, len) != 0)
        return 0;
    /* Must be followed by "/>" */
    return (p[len] == '/' && p[len + 1] == '>');
}

/*
 * Skip whitespace (spaces, tabs, newlines).
 */
static const char *xml_skip_ws(const char *p)
{
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
    return p;
}

/*
 * Extract text content between current position and the next '<'.
 * Copies into buf (up to buflen-1 chars), null-terminates.
 * Returns pointer to the '<' that ended the text.
 */
static const char *extract_text(const char *p, char *buf, int buflen)
{
    int i = 0;
    while (*p && *p != '<' && i < buflen - 1) {
        buf[i++] = *p++;
    }
    buf[i] = '\0';
    return p;
}

/*
 * Read the text content of an element like <string>text</string>.
 * Assumes p points to the opening '<string>'.
 * Returns pointer past '</string>', or NULL on error.
 * Copies the text content into buf.
 */
static const char *read_element_text(const char *p, const char *tag,
                                     char *buf, int buflen)
{
    /* Skip the opening tag */
    p = skip_tag(p);
    if (p == NULL)
        return NULL;

    /* Extract text content */
    p = extract_text(p, buf, buflen);

    /* Skip the closing tag */
    if (at_close_tag(p, tag)) {
        p = skip_tag(p);
    }

    return p;
}

/*
 * Parse a plist dict's MachServices sub-dict.
 * Extracts service names (the <key> values within the dict).
 * Assumes p points to the opening <dict> of MachServices.
 * Returns pointer past </dict>.
 */
static const char *parse_mach_services(const char *p, struct launchd_job *job)
{
    /* Skip <dict> */
    p = skip_tag(p);
    if (p == NULL)
        return NULL;

    while (*p) {
        p = xml_skip_ws(p);
        if (*p == '\0')
            break;

        /* End of MachServices dict */
        if (at_close_tag(p, "dict")) {
            p = skip_tag(p);
            break;
        }

        /* Each entry is: <key>service.name</key> <true/> */
        if (at_tag(p, "key")) {
            char svc_name[MAX_SERVICE_NAME_LEN];
            p = read_element_text(p, "key", svc_name, sizeof(svc_name));
            if (p == NULL)
                break;

            p = xml_skip_ws(p);

            /* Skip the value (<true/>, <false/>, <integer>...</integer>, etc.) */
            if (at_self_closing(p, "true") || at_self_closing(p, "false")) {
                p = skip_tag(p);
            } else {
                /* Skip any other value element */
                p = skip_tag(p);    /* opening tag */
                if (p) {
                    /* Find and skip closing tag */
                    while (*p && *p != '<')
                        p++;
                    if (*p)
                        p = skip_tag(p);
                }
            }

            /* Record the service name */
            if (job->num_services < MAX_MACH_SERVICES && svc_name[0]) {
                strncpy(job->service_names[job->num_services],
                        svc_name, MAX_SERVICE_NAME_LEN - 1);
                job->service_names[job->num_services][MAX_SERVICE_NAME_LEN - 1] = '\0';
                job->num_services++;
            }
        } else {
            /* Skip unknown content */
            p = skip_tag(p);
            if (p == NULL)
                break;
        }
    }

    return p;
}

/*
 * Parse ProgramArguments array: <array><string>...</string>...</array>
 * We take the first <string> as the program path.
 */
static const char *parse_program_arguments(const char *p, struct launchd_job *job)
{
    /* Skip <array> */
    p = skip_tag(p);
    if (p == NULL)
        return NULL;

    int first = 1;
    while (*p) {
        p = xml_skip_ws(p);
        if (*p == '\0')
            break;

        if (at_close_tag(p, "array")) {
            p = skip_tag(p);
            break;
        }

        if (at_tag(p, "string")) {
            char val[MAX_PROGRAM_LEN];
            p = read_element_text(p, "string", val, sizeof(val));
            if (p == NULL)
                break;

            /* First string element is the program path */
            if (first && val[0]) {
                strncpy(job->program, val, MAX_PROGRAM_LEN - 1);
                job->program[MAX_PROGRAM_LEN - 1] = '\0';
                first = 0;
            }
        } else {
            p = skip_tag(p);
            if (p == NULL)
                break;
        }
    }

    return p;
}

/*
 * Parse the top-level <dict> of a launchd plist.
 * Extracts Label, Program/ProgramArguments, MachServices, KeepAlive.
 */
static const char *parse_top_dict(const char *p, struct launchd_job *job)
{
    /* Skip <dict> */
    p = skip_tag(p);
    if (p == NULL)
        return NULL;

    while (*p) {
        p = xml_skip_ws(p);
        if (*p == '\0')
            break;

        /* End of top-level dict */
        if (at_close_tag(p, "dict")) {
            p = skip_tag(p);
            break;
        }

        if (at_tag(p, "key")) {
            char key[64];
            p = read_element_text(p, "key", key, sizeof(key));
            if (p == NULL)
                break;

            p = xml_skip_ws(p);

            if (strcmp(key, "Label") == 0) {
                if (at_tag(p, "string")) {
                    p = read_element_text(p, "string",
                                          job->label, MAX_LABEL_LEN);
                }
            } else if (strcmp(key, "Program") == 0) {
                if (at_tag(p, "string")) {
                    p = read_element_text(p, "string",
                                          job->program, MAX_PROGRAM_LEN);
                }
            } else if (strcmp(key, "ProgramArguments") == 0) {
                if (at_tag(p, "array")) {
                    p = parse_program_arguments(p, job);
                }
            } else if (strcmp(key, "MachServices") == 0) {
                if (at_tag(p, "dict")) {
                    p = parse_mach_services(p, job);
                }
            } else if (strcmp(key, "KeepAlive") == 0) {
                if (at_self_closing(p, "true")) {
                    job->keep_alive = 1;
                    p = skip_tag(p);
                } else if (at_self_closing(p, "false")) {
                    job->keep_alive = 0;
                    p = skip_tag(p);
                } else {
                    /* KeepAlive can also be a dict (conditions) — skip it */
                    if (at_tag(p, "dict")) {
                        /* Simple skip: find matching </dict> */
                        int depth = 1;
                        p = skip_tag(p);
                        while (p && *p && depth > 0) {
                            if (at_tag(p, "dict"))
                                depth++;
                            else if (at_close_tag(p, "dict"))
                                depth--;
                            p = skip_tag(p);
                        }
                    }
                }
            } else {
                /*
                 * Unknown key — skip its value.
                 * Handle self-closing (<true/>, <false/>), simple elements
                 * (<string>...</string>, <integer>...</integer>),
                 * and nested containers (<dict>...</dict>, <array>...</array>).
                 */
                if (at_self_closing(p, "true") || at_self_closing(p, "false")) {
                    p = skip_tag(p);
                } else if (at_tag(p, "dict")) {
                    int depth = 1;
                    p = skip_tag(p);
                    while (p && *p && depth > 0) {
                        if (at_tag(p, "dict"))
                            depth++;
                        else if (at_close_tag(p, "dict"))
                            depth--;
                        if (p) p = skip_tag(p);
                    }
                } else if (at_tag(p, "array")) {
                    int depth = 1;
                    p = skip_tag(p);
                    while (p && *p && depth > 0) {
                        if (at_tag(p, "array"))
                            depth++;
                        else if (at_close_tag(p, "array"))
                            depth--;
                        if (p) p = skip_tag(p);
                    }
                } else {
                    /* Simple element: skip to closing tag */
                    p = skip_tag(p);    /* opening tag */
                    if (p) {
                        while (*p && *p != '<')
                            p++;
                        if (*p)
                            p = skip_tag(p);    /* closing tag */
                    }
                }
            }

            if (p == NULL)
                break;
        } else {
            /* Skip unknown elements (e.g., comments) */
            p = skip_tag(p);
            if (p == NULL)
                break;
        }
    }

    return p;
}

/*
 * Parse an XML plist file from a memory buffer.
 * Returns 0 on success, -1 on error.
 */
static int parse_plist(const char *buf, struct launchd_job *job)
{
    memset(job, 0, sizeof(*job));
    job->pid = -1;

    const char *p = buf;

    /* Skip everything until we find the top-level <dict> */
    while (*p) {
        p = xml_skip_ws(p);
        if (*p == '\0')
            break;

        if (*p == '<') {
            /* Skip <?xml ... ?> processing instructions */
            if (p[1] == '?') {
                while (*p && !(p[0] == '?' && p[1] == '>'))
                    p++;
                if (*p)
                    p += 2;
                continue;
            }

            /* Skip <!DOCTYPE ...> */
            if (p[1] == '!') {
                p = skip_tag(p);
                if (p == NULL)
                    return -1;
                continue;
            }

            /* Skip <plist ...> */
            if (at_tag(p, "plist")) {
                p = skip_tag(p);
                if (p == NULL)
                    return -1;
                continue;
            }

            /* Found the top-level <dict> */
            if (at_tag(p, "dict")) {
                p = parse_top_dict(p, job);
                break;
            }

            /* Skip </plist> or other tags */
            p = skip_tag(p);
            if (p == NULL)
                return -1;
        } else {
            p++;
        }
    }

    /* Validate: must have at least Label and Program */
    if (job->label[0] == '\0' || job->program[0] == '\0')
        return -1;

    job->active = 1;
    return 0;
}

/*
 * Read a file into a malloc'd buffer. Returns NULL on error.
 * Caller must free() the returned buffer.
 */
static char *read_file(const char *path)
{
    FILE *f = fopen(path, "r");
    if (f == NULL)
        return NULL;

    /* Get file size */
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 0 || size > MAX_PLIST_SIZE) {
        fclose(f);
        return NULL;
    }

    char *buf = malloc((size_t)size + 1);
    if (buf == NULL) {
        fclose(f);
        return NULL;
    }

    size_t nread = fread(buf, 1, (size_t)size, f);
    fclose(f);

    buf[nread] = '\0';
    return buf;
}

/* ============================================================================
 * Load Plists from a Directory
 *
 * Scans a directory for .plist files, parses each one, and adds it
 * to the jobs array. Matches launchd scanning /System/Library/LaunchDaemons.
 * ============================================================================ */

static int has_suffix(const char *str, const char *suffix)
{
    int slen = (int)strlen(str);
    int xlen = (int)strlen(suffix);
    if (xlen > slen)
        return 0;
    return strcmp(str + slen - xlen, suffix) == 0;
}

static void load_plists_from_dir(const char *dirpath)
{
    DIR *d = opendir(dirpath);
    if (d == NULL) {
        /* Directory doesn't exist -- not an error, just no jobs from here */
        return;
    }

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (num_jobs >= MAX_JOBS)
            break;

        /* Skip non-.plist files */
        if (!has_suffix(ent->d_name, ".plist"))
            continue;

        /* Build full path */
        char path[512];
        int plen = snprintf(path, sizeof(path), "%s/%s", dirpath, ent->d_name);
        if (plen < 0 || plen >= (int)sizeof(path))
            continue;

        /* Read the file into memory */
        char *buf = read_file(path);
        if (buf == NULL) {
            printf("init: warning: cannot read %s\n", path);
            continue;
        }

        /* Parse the XML plist */
        struct launchd_job *job = &jobs[num_jobs];
        if (parse_plist(buf, job) == 0) {
            printf("init: loaded '%s' from %s\n", job->label, path);
            if (job->num_services > 0) {
                for (int i = 0; i < job->num_services; i++)
                    printf("init:   MachService: %s\n", job->service_names[i]);
            }
            num_jobs++;
        } else {
            printf("init: warning: failed to parse %s\n", path);
        }

        free(buf);
    }

    closedir(d);
}

/* ============================================================================
 * Mach Service Pre-Creation
 *
 * For each job's MachServices, init allocates a receive port and registers
 * it in the bootstrap namespace. This happens BEFORE the daemon is launched,
 * so clients can bootstrap_look_up() immediately.
 *
 * On macOS, launchd does exactly this: it holds the receive right until the
 * daemon calls bootstrap_check_in(), at which point launchd transfers the
 * right to the daemon.
 * ============================================================================ */

static int precreate_mach_services(struct launchd_job *job)
{
    for (int i = 0; i < job->num_services; i++) {
        unsigned int port = MACH_PORT_NULL;

        /*
         * Allocate a receive port in init's IPC space.
         * mach_port_allocate(task_self, MACH_PORT_RIGHT_RECEIVE, &port)
         */
        int kr = mach_port_allocate(mach_task_self(),
                                    MACH_PORT_RIGHT_RECEIVE,
                                    &port);
        if (kr != 0) {
            printf("init: mach_port_allocate failed for '%s': %d\n",
                   job->service_names[i], kr);
            return -1;
        }

        /*
         * Register in the bootstrap namespace.
         * After this, bootstrap_look_up(name) will find this port.
         * The daemon will later call bootstrap_check_in(name) to
         * receive the receive right.
         */
        kr = bootstrap_register(MACH_PORT_NULL,
                                job->service_names[i],
                                port);
        if (kr != 0) {
            printf("init: bootstrap_register failed for '%s': %d\n",
                   job->service_names[i], kr);
            return -1;
        }

        job->service_ports[i] = port;
        printf("init: registered service '%s' (port %u)\n",
               job->service_names[i], port);
    }

    return 0;
}

/* ============================================================================
 * Daemon Launch
 *
 * Fork+exec a daemon. The daemon inherits no special state -- it discovers
 * its service port via bootstrap_check_in() just like on macOS.
 * ============================================================================ */

static int launch_daemon(struct launchd_job *job)
{
    int pid = fork();

    if (pid < 0) {
        printf("init: fork failed for '%s'\n", job->label);
        return -1;
    }

    if (pid == 0) {
        /* Child: exec the daemon */
        const char *name = job->program;
        const char *slash = strrchr(job->program, '/');
        if (slash != NULL)
            name = slash + 1;

        char *argv[] = { (char *)name, NULL };
        char *envp[] = {
            "PATH=/bin:/sbin:/usr/bin:/usr/sbin",
            NULL
        };

        execve(job->program, argv, envp);

        /* exec failed */
        printf("init: cannot exec '%s'\n", job->program);
        _exit(1);
    }

    /* Parent */
    job->pid = pid;
    return pid;
}

/* ============================================================================
 * System Daemon Startup
 *
 * This is the launchd boot sequence:
 *   1. Load plist configs from well-known directories
 *   2. Pre-create all Mach service ports
 *   3. Launch all daemons
 *
 * Directories scanned (matching macOS):
 *   /System/Library/LaunchDaemons  -- system daemons (shipped with OS)
 *   /Library/LaunchDaemons         -- third-party/user-installed daemons
 * ============================================================================ */

static void start_system_daemons(void)
{
    /* Phase 1: Load all plist configurations */
    load_plists_from_dir(LAUNCHD_SYSTEM_PATH);
    load_plists_from_dir(LAUNCHD_LIBRARY_PATH);

    if (num_jobs == 0) {
        printf("init: no launch daemons found\n");
        return;
    }

    printf("init: %d job(s) loaded\n", num_jobs);

    /* Phase 2: Pre-create all Mach service ports */
    for (int i = 0; i < num_jobs; i++) {
        if (jobs[i].num_services > 0) {
            if (precreate_mach_services(&jobs[i]) < 0) {
                printf("init: warning: failed to pre-create services for '%s'\n",
                       jobs[i].label);
            }
        }
    }

    /* Phase 3: Launch all daemons */
    for (int i = 0; i < num_jobs; i++) {
        int pid = launch_daemon(&jobs[i]);
        if (pid > 0) {
            printf("init: started '%s' (pid %d)\n", jobs[i].label, pid);
        } else {
            printf("init: warning: failed to launch '%s'\n", jobs[i].label);
        }
    }
}

/* ============================================================================
 * Getty / Console
 * ============================================================================ */

static int spawn_getty(void)
{
    int pid = fork();

    if (pid < 0) {
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

    return pid;
}

/* ============================================================================
 * Daemon Reaping & KeepAlive
 * ============================================================================ */

static void handle_daemon_exit(int pid, int status)
{
    for (int i = 0; i < num_jobs; i++) {
        if (jobs[i].active && jobs[i].pid == pid) {
            int code = (status >> 8) & 0xFF;
            printf("init: '%s' (pid %d) exited, status=%d\n",
                   jobs[i].label, pid, code);
            jobs[i].pid = -1;

            /* KeepAlive: relaunch if set */
            if (jobs[i].keep_alive) {
                int new_pid = launch_daemon(&jobs[i]);
                if (new_pid > 0) {
                    printf("init: relaunched '%s' (pid %d)\n",
                           jobs[i].label, new_pid);
                }
            }
            return;
        }
    }
}

/* ============================================================================
 * Main
 * ============================================================================ */

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

    /* Start system daemons (launchd-style) */
    start_system_daemons();

    /* Main loop: spawn getty, reap children */
    for (;;) {
        int getty_pid = spawn_getty();
        if (getty_pid < 0) {
            printf("init: failed to spawn getty, retrying...\n");
            for (volatile int i = 0; i < 50000000; i++)
                ;
            continue;
        }

        printf("init: spawned getty (pid %d)\n", getty_pid);

        for (;;) {
            int status = 0;
            int rpid = wait4(-1, &status, 0, NULL);

            if (rpid < 0)
                break;

            if (rpid == getty_pid) {
                printf("\ninit: getty (pid %d) exited, status=%d\n",
                       rpid, (status >> 8) & 0xFF);
                break;
            }

            /* Check if a daemon exited */
            handle_daemon_exit(rpid, status);
        }
    }

    return 0;
}
