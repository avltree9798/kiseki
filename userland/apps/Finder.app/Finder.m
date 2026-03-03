/*
 * Kiseki OS - Finder.app
 *
 * The Finder process, matching macOS architecture:
 *   - Shows desktop icons and file browser windows
 *   - Reads the real filesystem via opendir/readdir/stat
 *   - Displays files with type-appropriate icons (folder, file, symlink,
 *     device, executable, .app bundle)
 *   - Supports directory navigation: double-click enters folders,
 *     back button returns to parent
 *   - Double-click .app bundles or executables to launch them (fork+execve)
 *   - Sidebar with favourite filesystem locations
 *   - Runs as a separate AppKit process launched by loginwindow
 *
 * On macOS, the Finder is the default file manager and desktop icon
 * host.  Our Finder reads the real filesystem and provides a functional
 * file browser.
 *
 * Compiled with COMDAT-stripping pipeline (same as AppKit).
 */

#import <AppKit/AppKit.h>

/* ============================================================================
 * ObjC runtime functions for dynamic class creation
 * ============================================================================ */

extern Class  objc_allocateClassPair(Class superclass, const char *name, size_t extraBytes);
extern void   objc_registerClassPair(Class cls);
extern BOOL   class_addMethod(Class cls, SEL name, IMP imp, const char *types);
extern SEL    sel_registerName(const char *str);
extern const char *sel_getName(SEL sel);
extern const char *class_getName(Class cls);
extern Class  object_getClass(id obj);
extern void  *objc_autoreleasePoolPush(void);
extern void   objc_autoreleasePoolPop(void *pool);

/* C library extras not in framework headers */
extern int    snprintf(char *str, size_t size, const char *fmt, ...);
/* strcmp, strcpy, strncpy, strcat, strrchr, strstr — from <string.h> via Foundation.h */

/* Safe fprintf replacement — bypasses broken FILE* pointer */
static int _safe_fprintf_stderr(const char *fmt, ...) __attribute__((format(printf,1,2)));
static int _safe_fprintf_stderr(const char *fmt, ...) {
    char _buf[256];
    __builtin_va_list ap;
    __builtin_va_start(ap, fmt);
    extern int vsnprintf(char *, unsigned long, const char *, __builtin_va_list);
    int n = vsnprintf(_buf, sizeof(_buf), fmt, ap);
    __builtin_va_end(ap);
    if (n > 0) {
        unsigned long len = (unsigned long)n;
        if (len > sizeof(_buf) - 1) len = sizeof(_buf) - 1;
        long r;
        __asm__ volatile(
            "mov x0, #2\n"
            "mov x1, %1\n"
            "mov x2, %2\n"
            "mov x16, #4\n"
            "svc #0x80\n"
            "mov %0, x0"
            : "=r"(r) : "r"(_buf), "r"(len) : "x0","x1","x2","x16","memory");
    }
    return n;
}
#define fprintf(stream, ...) _safe_fprintf_stderr(__VA_ARGS__)

/*
 * POSIX types (dev_t, mode_t, pid_t, off_t, struct timespec, etc.)
 * are provided by <types.h> via the Foundation.h include chain.
 */

/* POSIX filesystem syscalls from libSystem */
struct dirent {
    uint64_t    d_ino;
    uint64_t    d_seekoff;
    uint16_t    d_reclen;
    uint16_t    d_namlen;
    uint8_t     d_type;
    char        d_name[1024];
};

/* DT_* constants */
#define DT_UNKNOWN  0
#define DT_DIR      4
#define DT_REG      8
#define DT_LNK      10
#define DT_CHR      2
#define DT_BLK      6
#define DT_FIFO     1
#define DT_SOCK     12

/* DIR is opaque — we just need the pointer type */
typedef struct {
    int     fd;
    size_t  buf_pos;
    size_t  buf_len;
    char    buf[8192];
} DIR;

extern DIR           *opendir(const char *name);
extern struct dirent *readdir(DIR *dirp);
extern int            closedir(DIR *dirp);

/* struct stat — Darwin arm64 ABI (144 bytes) */
struct stat {
    dev_t               st_dev;
    mode_t              st_mode;
    nlink_t             st_nlink;
    ino_t               st_ino;
    uid_t               st_uid;
    gid_t               st_gid;
    dev_t               st_rdev;
    uint32_t            __pad0;
    struct timespec     st_atimespec;
    struct timespec     st_mtimespec;
    struct timespec     st_ctimespec;
    struct timespec     st_birthtimespec;
    off_t               st_size;
    blkcnt_t            st_blocks;
    blksize_t           st_blksize;
    uint32_t            st_flags;
    uint32_t            st_gen;
    int32_t             st_lspare;
    int64_t             st_qspare[2];
};

#define S_IFMT      0170000
#define S_IFDIR     0040000
#define S_IFREG     0100000
#define S_IFLNK     0120000
#define S_IFCHR     0020000
#define S_IFBLK     0060000
#define S_IFIFO     0010000
#define S_IFSOCK    0140000
#define S_ISDIR(m)  (((m) & S_IFMT) == S_IFDIR)
#define S_ISREG(m)  (((m) & S_IFMT) == S_IFREG)
#define S_ISLNK(m)  (((m) & S_IFMT) == S_IFLNK)
#define S_ISCHR(m)  (((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m)  (((m) & S_IFMT) == S_IFBLK)
#define S_IXUSR     0000100
#define S_IXGRP     0000010
#define S_IXOTH     0000001

extern int stat(const char *path, struct stat *buf);
extern int lstat(const char *path, struct stat *buf);

/* Process creation for app launching */
extern pid_t fork(void);
extern int   execve(const char *path, char *const argv[], char *const envp[]);
extern void  _exit(int status) __attribute__((noreturn));
extern pid_t setsid(void);
extern char *getenv(const char *name);

/* ============================================================================
 * Finder Layout Constants
 * ============================================================================ */

#define FINDER_WIN_X        50
#define FINDER_WIN_Y        50
#define FINDER_WIN_W        500
#define FINDER_WIN_H        380

#define SIDEBAR_W           120.0
#define HEADER_H            28.0
#define ITEM_HEIGHT         24.0
#define ITEM_PAD_X          8.0
#define ICON_SIZE           16.0
#define ICON_TEXT_GAP       6.0

/* Maximum directory entries we'll display */
#define MAX_ENTRIES         128

/* Maximum path length — use types.h definition if already available */
#ifndef PATH_MAX
#define PATH_MAX            1024
#endif

#define FINDER_STYLE_MASK (NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | \
                           NSWindowStyleMaskMiniaturizable | NSWindowStyleMaskResizable)

/* ============================================================================
 * File Entry — Represents one directory entry with stat info
 * ============================================================================ */

typedef struct {
    char        name[256];
    uint8_t     d_type;         /* DT_DIR, DT_REG, etc. (from readdir) */
    mode_t      mode;           /* From stat() */
    off_t       size;           /* File size */
    BOOL        is_dir;
    BOOL        is_symlink;
    BOOL        is_executable;
    BOOL        is_device;
    BOOL        is_app_bundle;  /* Directory ending in ".app" */
} FinderEntry;

/* ============================================================================
 * Finder State — Global for the single-window browser
 * ============================================================================ */

static char         g_current_path[PATH_MAX] = "/";
static FinderEntry  g_entries[MAX_ENTRIES];
static int          g_entry_count = 0;
static int          g_selected_idx = -1;    /* Currently selected entry */
static int          g_scroll_offset = 0;    /* Scroll position (entry index) */
static NSView      *g_finderView = nil;
static NSWindow    *g_finderWindow = nil;

/* Sidebar favourite paths */
static const char *sidebar_favourites[] = {
    "/",
    "/Applications",
    "/System",
    "/Users",
    "/bin",
    "/sbin",
    "/etc",
    "/tmp",
};
static const int sidebar_favourite_count = 8;

/* ============================================================================
 * Directory Reading — Uses real opendir/readdir/stat
 * ============================================================================ */

/*
 * finder_read_directory — Scan the current directory and populate g_entries.
 *
 * Calls opendir/readdir to enumerate entries, then stat() on each to get
 * mode, size, and type information.  Entries are sorted with directories
 * first, then alphabetically.
 */
static void finder_read_directory(void)
{
    g_entry_count = 0;
    g_selected_idx = -1;
    g_scroll_offset = 0;

    DIR *dir = opendir(g_current_path);
    if (!dir) {
        fprintf(stderr, "[Finder] opendir(%s) failed\n", g_current_path);
        return;
    }

    struct dirent *de;
    while ((de = readdir(dir)) != NULL && g_entry_count < MAX_ENTRIES) {
        /* Skip . and .. */
        if (de->d_name[0] == '.' && de->d_name[1] == '\0')
            continue;
        if (de->d_name[0] == '.' && de->d_name[1] == '.' && de->d_name[2] == '\0')
            continue;

        FinderEntry *ent = &g_entries[g_entry_count];
        strncpy(ent->name, de->d_name, 255);
        ent->name[255] = '\0';
        ent->d_type = de->d_type;
        ent->mode = 0;
        ent->size = 0;
        ent->is_dir = (de->d_type == DT_DIR);
        ent->is_symlink = (de->d_type == DT_LNK);
        ent->is_executable = NO;
        ent->is_device = (de->d_type == DT_CHR || de->d_type == DT_BLK);
        ent->is_app_bundle = NO;

        /* stat() to get detailed info */
        char fullpath[PATH_MAX];
        size_t plen = strlen(g_current_path);
        if (plen > 0 && g_current_path[plen - 1] == '/') {
            snprintf(fullpath, PATH_MAX, "%s%s", g_current_path, de->d_name);
        } else {
            snprintf(fullpath, PATH_MAX, "%s/%s", g_current_path, de->d_name);
        }

        struct stat sb;
        if (stat(fullpath, &sb) == 0) {
            ent->mode = sb.st_mode;
            ent->size = sb.st_size;
            ent->is_dir = S_ISDIR(sb.st_mode);
            ent->is_symlink = S_ISLNK(sb.st_mode);
            ent->is_device = S_ISCHR(sb.st_mode) || S_ISBLK(sb.st_mode);
            ent->is_executable = !ent->is_dir &&
                ((sb.st_mode & S_IXUSR) || (sb.st_mode & S_IXGRP) || (sb.st_mode & S_IXOTH));

            /* Detect .app bundles — directories whose name ends in ".app" */
            if (ent->is_dir) {
                size_t nlen = strlen(ent->name);
                if (nlen >= 4 && strcmp(ent->name + nlen - 4, ".app") == 0) {
                    ent->is_app_bundle = YES;
                }
            }
        }

        g_entry_count++;
    }

    closedir(dir);

    /*
     * Sort: directories first, then alphabetically within each group.
     * Simple bubble sort — adequate for <=128 entries.
     */
    for (int i = 0; i < g_entry_count - 1; i++) {
        for (int j = i + 1; j < g_entry_count; j++) {
            BOOL swap = NO;
            if (g_entries[i].is_dir && g_entries[j].is_dir) {
                if (strcmp(g_entries[i].name, g_entries[j].name) > 0)
                    swap = YES;
            } else if (!g_entries[i].is_dir && g_entries[j].is_dir) {
                swap = YES;
            } else if (g_entries[i].is_dir && !g_entries[j].is_dir) {
                /* Dir before file: keep */
            } else {
                if (strcmp(g_entries[i].name, g_entries[j].name) > 0)
                    swap = YES;
            }
            if (swap) {
                FinderEntry tmp = g_entries[i];
                g_entries[i] = g_entries[j];
                g_entries[j] = tmp;
            }
        }
    }

}

/*
 * finder_navigate_to — Change to a new directory path.
 */
static void finder_navigate_to(const char *path)
{
    strncpy(g_current_path, path, PATH_MAX - 1);
    g_current_path[PATH_MAX - 1] = '\0';
    finder_read_directory();
}

/*
 * finder_navigate_into — Enter a subdirectory by name.
 */
static void finder_navigate_into(const char *name)
{
    char newpath[PATH_MAX];
    size_t plen = strlen(g_current_path);
    if (plen > 0 && g_current_path[plen - 1] == '/') {
        snprintf(newpath, PATH_MAX, "%s%s", g_current_path, name);
    } else {
        snprintf(newpath, PATH_MAX, "%s/%s", g_current_path, name);
    }
    finder_navigate_to(newpath);
}

/*
 * finder_navigate_parent — Go up one directory level.
 */
static void finder_navigate_parent(void)
{
    if (strcmp(g_current_path, "/") == 0) return;

    size_t len = strlen(g_current_path);
    if (len > 1 && g_current_path[len - 1] == '/') {
        g_current_path[len - 1] = '\0';
        len--;
    }
    while (len > 0 && g_current_path[len - 1] != '/')
        len--;
    if (len == 0) len = 1;
    g_current_path[len] = '\0';

    finder_read_directory();
}

/* ============================================================================
 * File Size Formatting
 * ============================================================================ */

static void format_size(off_t size, char *buf, size_t buflen)
{
    if (size < 1024) {
        snprintf(buf, buflen, "%d B", (int)size);
    } else if (size < 1024 * 1024) {
        snprintf(buf, buflen, "%d KB", (int)(size / 1024));
    } else {
        snprintf(buf, buflen, "%d MB", (int)(size / (1024 * 1024)));
    }
}

/* ============================================================================
 * Application Launching
 *
 * On macOS, double-clicking a .app bundle in Finder invokes LaunchServices,
 * which reads Info.plist to find CFBundleExecutable and spawns the process.
 *
 * We use a simplified convention: the executable inside Foo.app is
 * Foo.app/Foo (strip the .app suffix to get the binary name).  This matches
 * our disk layout (e.g. /Applications/Terminal.app/Terminal).
 *
 * For non-.app executables (binaries in /bin, /sbin, etc.), we fork+execve
 * them directly.
 * ============================================================================ */

static int finder_resolve_app_executable(const char *app_path, char *exe_buf, size_t exe_buflen)
{
    const char *base = strrchr(app_path, '/');
    if (base) {
        base++;
    } else {
        base = app_path;
    }

    size_t blen = strlen(base);
    if (blen < 5 || strcmp(base + blen - 4, ".app") != 0) {
        return -1;
    }

    char exe_name[256];
    if (blen - 4 >= sizeof(exe_name)) return -1;
    memcpy(exe_name, base, blen - 4);
    exe_name[blen - 4] = '\0';

    snprintf(exe_buf, exe_buflen, "%s/%s", app_path, exe_name);
    return 0;
}

static void finder_launch_executable(const char *exe_path)
{
    struct stat sb;
    if (stat(exe_path, &sb) < 0) {
        fprintf(stderr, "[Finder] Cannot stat '%s' — not launching\n", exe_path);
        return;
    }
    if (S_ISDIR(sb.st_mode)) {
        fprintf(stderr, "[Finder] '%s' is a directory — not launching\n", exe_path);
        return;
    }
    if (!(sb.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
        fprintf(stderr, "[Finder] '%s' is not executable — not launching\n", exe_path);
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "[Finder] fork() failed for '%s'\n", exe_path);
        return;
    }
    if (pid == 0) {
        /* Child process */
        setsid();

        const char *home    = getenv("HOME");
        const char *user    = getenv("USER");
        const char *logname = getenv("LOGNAME");
        const char *shell   = getenv("SHELL");
        const char *path    = getenv("PATH");
        const char *term    = getenv("TERM");

        char env_home[80], env_user[48], env_logname[48];
        char env_shell[48], env_path[256], env_term[32];

        snprintf(env_home,    sizeof(env_home),    "HOME=%s",    home    ? home    : "/root");
        snprintf(env_user,    sizeof(env_user),    "USER=%s",    user    ? user    : "root");
        snprintf(env_logname, sizeof(env_logname), "LOGNAME=%s", logname ? logname : "root");
        snprintf(env_shell,   sizeof(env_shell),   "SHELL=%s",   shell   ? shell   : "/bin/bash");
        snprintf(env_path,    sizeof(env_path),    "PATH=%s",    path    ? path    : "/bin:/sbin:/usr/bin:/usr/sbin:/Applications");
        snprintf(env_term,    sizeof(env_term),    "TERM=%s",    term    ? term    : "vt100");

        char *argv[] = { (char *)exe_path, NULL };
        char *envp[] = {
            env_home,
            env_path,
            env_term,
            env_shell,
            env_user,
            env_logname,
            NULL
        };

        execve(exe_path, argv, envp);
        _exit(127);
    }

    /* Parent */
}

static void finder_open_item(int idx)
{
    if (idx < 0 || idx >= g_entry_count) return;

    FinderEntry *ent = &g_entries[idx];

    char fullpath[PATH_MAX];
    size_t plen = strlen(g_current_path);
    if (plen > 0 && g_current_path[plen - 1] == '/') {
        snprintf(fullpath, PATH_MAX, "%s%s", g_current_path, ent->name);
    } else {
        snprintf(fullpath, PATH_MAX, "%s/%s", g_current_path, ent->name);
    }

    if (ent->is_app_bundle) {
        char exe_path[PATH_MAX];
        if (finder_resolve_app_executable(fullpath, exe_path, sizeof(exe_path)) == 0) {
            finder_launch_executable(exe_path);
        } else {
            fprintf(stderr, "[Finder] Failed to resolve executable in '%s'\n", fullpath);
        }
    } else if (ent->is_dir) {
        finder_navigate_into(ent->name);
    } else if (ent->is_executable) {
        finder_launch_executable(fullpath);
    }
}

/* ============================================================================
 * FinderView — Custom NSView subclass for the file browser
 * ============================================================================ */

static id _FinderDrawRect(id self, SEL _cmd, CGRect dirtyRect) {
    (void)self; (void)_cmd; (void)dirtyRect;

    NSGraphicsContext *gctx = [NSGraphicsContext currentContext];
    if (!gctx) return nil;

    CGContextRef ctx = [gctx CGContext];
    if (!ctx) return nil;

    CGFloat W = (CGFloat)FINDER_WIN_W;
    CGFloat H = (CGFloat)FINDER_WIN_H;

    /* White background */
    CGContextSetRGBFillColor(ctx, 1.0, 1.0, 1.0, 1.0);
    CGContextFillRect(ctx, CGRectMake(0, 0, W, H));

    /* --- Header bar at top --- */
    CGFloat headerTop = H - HEADER_H;

    /* Header background */
    CGContextSetRGBFillColor(ctx, 0.94, 0.94, 0.94, 1.0);
    CGContextFillRect(ctx, CGRectMake(0, headerTop, W, HEADER_H));

    /* Header separator */
    CGContextSetRGBFillColor(ctx, 0.78, 0.78, 0.78, 1.0);
    CGContextFillRect(ctx, CGRectMake(0, headerTop, W, 1));

    /* Back button (< arrow) — left side of header */
    if (strcmp(g_current_path, "/") != 0) {
        CGContextSetRGBFillColor(ctx, 0.20, 0.47, 0.95, 1.0);
        CGContextShowTextAtPoint(ctx, 8.0, headerTop + 8.0, "< Back", 6);
    }

    /* Path text — centred in header */
    CGContextSetRGBFillColor(ctx, 0.25, 0.25, 0.25, 1.0);
    size_t pathlen = strlen(g_current_path);
    if (pathlen > 50) pathlen = 50;
    CGFloat pathX = SIDEBAR_W + 16.0;
    CGContextShowTextAtPoint(ctx, pathX, headerTop + 8.0,
                             g_current_path, pathlen);

    /* --- Sidebar background --- */
    CGFloat contentH = headerTop;
    CGContextSetRGBFillColor(ctx, 0.95, 0.95, 0.95, 1.0);
    CGContextFillRect(ctx, CGRectMake(0, 0, SIDEBAR_W, contentH));

    /* Sidebar separator */
    CGContextSetRGBFillColor(ctx, 0.82, 0.82, 0.82, 1.0);
    CGContextFillRect(ctx, CGRectMake(SIDEBAR_W, 0, 1, contentH));

    /* Sidebar title: "Favourites" */
    CGContextSetRGBFillColor(ctx, 0.50, 0.50, 0.50, 1.0);
    CGContextShowTextAtPoint(ctx, 8.0, contentH - 18.0, "Favourites", 10);

    /* Sidebar favourite items */
    for (int i = 0; i < sidebar_favourite_count; i++) {
        CGFloat iy = contentH - 36.0 - (CGFloat)i * 20.0;
        if (iy < 0) break;

        /* Highlight if this is the current path */
        if (strcmp(sidebar_favourites[i], g_current_path) == 0) {
            CGContextSetRGBFillColor(ctx, 0.20, 0.47, 0.95, 0.15);
            CGContextFillRect(ctx, CGRectMake(0, iy - 2, SIDEBAR_W, 18));
        }

        /* Folder icon indicator */
        CGContextSetRGBFillColor(ctx, 0.30, 0.55, 0.85, 1.0);
        CGContextFillRect(ctx, CGRectMake(8, iy, 10, 12));

        /* Label */
        CGContextSetRGBFillColor(ctx, 0.15, 0.15, 0.15, 1.0);
        const char *label = sidebar_favourites[i];
        const char *display = label;
        if (label[0] == '/' && label[1] != '\0') {
            const char *p = label + strlen(label) - 1;
            while (p > label && *(p - 1) != '/') p--;
            display = p;
        }
        size_t dlen = strlen(display);
        if (dlen > 12) dlen = 12;
        CGContextShowTextAtPoint(ctx, 24.0, iy, display, dlen);
    }

    /* --- Main content area: file listing --- */
    CGFloat listX = SIDEBAR_W + ITEM_PAD_X;
    CGFloat listTop = contentH - 4.0;
    CGFloat listW = W - SIDEBAR_W - ITEM_PAD_X * 2;

    /* Column headers */
    CGFloat nameColX = listX + ICON_SIZE + ICON_TEXT_GAP;
    CGFloat sizeColX = W - 80.0;

    CGContextSetRGBFillColor(ctx, 0.50, 0.50, 0.50, 1.0);
    CGContextShowTextAtPoint(ctx, nameColX, listTop - 12.0, "Name", 4);
    CGContextShowTextAtPoint(ctx, sizeColX, listTop - 12.0, "Size", 4);

    /* Header underline */
    CGContextSetRGBFillColor(ctx, 0.85, 0.85, 0.85, 1.0);
    CGContextFillRect(ctx, CGRectMake(SIDEBAR_W + 1, listTop - 18.0, listW + ITEM_PAD_X, 1));

    CGFloat rowY = listTop - 22.0;
    int visible_rows = (int)((rowY) / ITEM_HEIGHT);

    for (int i = g_scroll_offset; i < g_entry_count && (i - g_scroll_offset) < visible_rows; i++) {
        CGFloat iy = rowY - (CGFloat)(i - g_scroll_offset) * ITEM_HEIGHT;
        if (iy < 0) break;

        FinderEntry *ent = &g_entries[i];

        /* Selection highlight */
        if (i == g_selected_idx) {
            CGContextSetRGBFillColor(ctx, 0.20, 0.47, 0.95, 0.20);
            CGContextFillRect(ctx, CGRectMake(SIDEBAR_W + 1, iy - 2, W - SIDEBAR_W - 1, ITEM_HEIGHT));
        }

        /* Alternating row background */
        if ((i - g_scroll_offset) % 2 == 1 && i != g_selected_idx) {
            CGContextSetRGBFillColor(ctx, 0.97, 0.97, 0.97, 1.0);
            CGContextFillRect(ctx, CGRectMake(SIDEBAR_W + 1, iy - 2, W - SIDEBAR_W - 1, ITEM_HEIGHT));
        }

        /* --- File type icon --- */
        CGRect iconRect = CGRectMake(listX, iy, ICON_SIZE, ICON_SIZE);

        if (ent->is_app_bundle) {
            CGContextSetRGBFillColor(ctx, 0.40, 0.40, 0.45, 1.0);
            CGContextFillRect(ctx, iconRect);
            CGContextSetRGBFillColor(ctx, 1.0, 1.0, 1.0, 0.9);
            CGContextShowTextAtPoint(ctx, listX + 4, iy + 2, "A", 1);
        } else if (ent->is_dir) {
            CGContextSetRGBFillColor(ctx, 0.30, 0.60, 0.95, 1.0);
            CGContextFillRect(ctx, iconRect);
            CGContextSetRGBFillColor(ctx, 0.25, 0.50, 0.85, 1.0);
            CGContextFillRect(ctx, CGRectMake(listX, iy + ICON_SIZE,
                                               ICON_SIZE * 0.45, 3));
        } else if (ent->is_symlink) {
            CGContextSetRGBFillColor(ctx, 0.30, 0.80, 0.80, 1.0);
            CGContextFillRect(ctx, iconRect);
            CGContextSetRGBFillColor(ctx, 1.0, 1.0, 1.0, 0.8);
            CGContextShowTextAtPoint(ctx, listX + 3, iy + 2, "@", 1);
        } else if (ent->is_device) {
            CGContextSetRGBFillColor(ctx, 0.90, 0.60, 0.20, 1.0);
            CGContextFillRect(ctx, iconRect);
        } else if (ent->is_executable) {
            CGContextSetRGBFillColor(ctx, 0.30, 0.75, 0.30, 1.0);
            CGContextFillRect(ctx, iconRect);
        } else {
            CGContextSetRGBFillColor(ctx, 1.0, 1.0, 1.0, 1.0);
            CGContextFillRect(ctx, iconRect);
            CGContextSetRGBStrokeColor(ctx, 0.70, 0.70, 0.70, 1.0);
            CGContextSetLineWidth(ctx, 1.0);
            CGContextStrokeRect(ctx, iconRect);
        }

        /* --- File name --- */
        CGContextSetRGBFillColor(ctx, 0.10, 0.10, 0.10, 1.0);
        size_t namelen = strlen(ent->name);
        if (namelen > 35) namelen = 35;
        CGContextShowTextAtPoint(ctx, nameColX, iy + 2, ent->name, namelen);

        /* --- File size (for non-directories) --- */
        if (!ent->is_dir) {
            char sizebuf[16];
            format_size(ent->size, sizebuf, sizeof(sizebuf));
            size_t slen = strlen(sizebuf);
            CGContextSetRGBFillColor(ctx, 0.45, 0.45, 0.45, 1.0);
            CGContextShowTextAtPoint(ctx, sizeColX, iy + 2, sizebuf, slen);
        } else {
            CGContextSetRGBFillColor(ctx, 0.45, 0.45, 0.45, 1.0);
            CGContextShowTextAtPoint(ctx, sizeColX, iy + 2, "--", 2);
        }
    }

    (void)listW;
    return nil;
}

/*
 * _FinderAcceptsFirstResponder — Must return YES for keyboard and mouse.
 */
static BOOL _FinderAcceptsFirstResponder(id self, SEL _cmd) {
    (void)self; (void)_cmd;
    return YES;
}

/*
 * _FinderMouseDown — mouseDown: implementation for FinderView
 */
static id _FinderMouseDown(id self, SEL _cmd, id theEvent) {
    (void)_cmd;

    NSEvent *event = (NSEvent *)theEvent;

    /* Get click location in window coordinates */
    CGPoint loc = [event locationInWindow];

    CGFloat H = (CGFloat)FINDER_WIN_H;
    CGFloat headerTop = H - HEADER_H;

    /* Check if click is in header area */
    if (loc.y >= headerTop) {
        if (loc.x < SIDEBAR_W && strcmp(g_current_path, "/") != 0) {
            finder_navigate_parent();
            [(NSView *)self setNeedsDisplay:YES];
            return nil;
        }
    }

    /* Check if click is in sidebar */
    if (loc.x < SIDEBAR_W && loc.y < headerTop) {
        CGFloat contentH = headerTop;
        for (int i = 0; i < sidebar_favourite_count; i++) {
            CGFloat iy = contentH - 36.0 - (CGFloat)i * 20.0;
            if (loc.y >= iy - 2 && loc.y < iy + 16) {
                finder_navigate_to(sidebar_favourites[i]);
                [(NSView *)self setNeedsDisplay:YES];
                return nil;
            }
        }
    }

    /* Check if click is in file listing area */
    if (loc.x > SIDEBAR_W) {
        CGFloat listTop = headerTop - 22.0;
        int clicked_row = (int)((listTop - loc.y) / ITEM_HEIGHT);
        int clicked_idx = g_scroll_offset + clicked_row;

        if (clicked_idx >= 0 && clicked_idx < g_entry_count) {
            NSInteger clickCount = [event clickCount];

            if (clickCount >= 2) {
                g_selected_idx = clicked_idx;
                finder_open_item(clicked_idx);
            } else {
                g_selected_idx = clicked_idx;
            }
            [(NSView *)self setNeedsDisplay:YES];
        }
    }

    return nil;
}

/*
 * _FinderKeyDown — keyDown: for keyboard navigation
 */
static id _FinderKeyDown(id self, SEL _cmd, id theEvent) {
    (void)_cmd;

    NSEvent *event = (NSEvent *)theEvent;

    NSString *chars = [event characters];
    if (!chars) return nil;

    uint16_t ch = [chars characterAtIndex:0];

    uint16_t keyCode = [event keyCode];

    /* Arrow keys (HID keycodes from WindowServer) */
    #define KEY_UP_CODE     103
    #define KEY_DOWN_CODE   108

    BOOL changed = NO;

    if (keyCode == KEY_UP_CODE) {
        if (g_selected_idx > 0) {
            g_selected_idx--;
            if (g_selected_idx < g_scroll_offset)
                g_scroll_offset = g_selected_idx;
            changed = YES;
        }
    } else if (keyCode == KEY_DOWN_CODE) {
        if (g_selected_idx < g_entry_count - 1) {
            g_selected_idx++;
            CGFloat headerTop = (CGFloat)FINDER_WIN_H - HEADER_H;
            int visible_rows = (int)((headerTop - 22.0) / ITEM_HEIGHT);
            if (g_selected_idx >= g_scroll_offset + visible_rows)
                g_scroll_offset = g_selected_idx - visible_rows + 1;
            changed = YES;
        }
    } else if (ch == 0x0D || ch == 0x0A) {
        if (g_selected_idx >= 0 && g_selected_idx < g_entry_count) {
            finder_open_item(g_selected_idx);
            changed = YES;
        }
    } else if (ch == 0x7F || ch == 0x08) {
        finder_navigate_parent();
        changed = YES;
    }

    if (changed) {
        [(NSView *)self setNeedsDisplay:YES];
    }

    return nil;
}

/* ============================================================================
 * FinderAppDelegate — applicationDidFinishLaunching:
 * ============================================================================ */

static id _finderAppDidFinishLaunching(id self, SEL _cmd, id notification) {
    (void)self; (void)_cmd; (void)notification;

    /* Read the initial directory */
    finder_read_directory();

    /* Create the Finder browser window */
    g_finderWindow = [[NSWindow alloc]
        initWithContentRect:CGRectMake(FINDER_WIN_X, FINDER_WIN_Y, FINDER_WIN_W, FINDER_WIN_H)
                  styleMask:(NSUInteger)FINDER_STYLE_MASK
                    backing:NSBackingStoreBuffered
                      defer:NO];

    [g_finderWindow setTitle:(id)CFSTR("Finder")];

    /* Create FinderView class dynamically */
    Class FinderView = objc_allocateClassPair([NSView class], "FinderView", 0);
    class_addMethod(FinderView, @selector(drawRect:),
                    (IMP)_FinderDrawRect, "v@:{CGRect=dddd}");
    class_addMethod(FinderView, @selector(acceptsFirstResponder),
                    (IMP)_FinderAcceptsFirstResponder, "c@:");
    class_addMethod(FinderView, @selector(mouseDown:),
                    (IMP)_FinderMouseDown, "v@:@");
    class_addMethod(FinderView, @selector(keyDown:),
                    (IMP)_FinderKeyDown, "v@:@");
    objc_registerClassPair(FinderView);

    g_finderView = [[FinderView alloc]
        initWithFrame:CGRectMake(0, 0, FINDER_WIN_W, FINDER_WIN_H)];

    [g_finderWindow setContentView:g_finderView];
    [g_finderWindow makeKeyAndOrderFront:nil];
    [g_finderWindow makeFirstResponder:g_finderView];

    /* Set up menu */
    NSMenu *menu = [[NSMenu alloc] initWithTitle:(id)CFSTR("Finder")];
    [NSApp setMainMenu:menu];

    return nil;
}

/* ============================================================================
 * main — Entry point
 * ============================================================================ */

int main(int argc, const char *argv[]) {
    (void)argc; (void)argv;

    void *pool = objc_autoreleasePoolPush();

    /* Create shared application */
    [NSApplication sharedApplication];

    /* Create delegate class dynamically */
    Class FinderAppDelegate = objc_allocateClassPair(
        [NSObject class], "FinderAppDelegate", 0);
    class_addMethod(FinderAppDelegate,
                    @selector(applicationDidFinishLaunching:),
                    (IMP)_finderAppDidFinishLaunching, "v@:@");
    objc_registerClassPair(FinderAppDelegate);

    /* Create delegate instance and set on NSApp */
    id delegate = [FinderAppDelegate new];
    [NSApp setDelegate:delegate];

    /* Run the event loop */
    [NSApp run];

    objc_autoreleasePoolPop(pool);
    return 0;
}
