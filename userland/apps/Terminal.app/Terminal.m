/*
 * Kiseki OS - Terminal.app
 *
 * A real terminal emulator faithfully matching macOS Terminal.app architecture:
 *   - Allocates a PTY pair via openpty()
 *   - Forks a child process running /bin/bash with proper session setup
 *   - Full VT100/ANSI terminal emulator (matching WindowServer's built-in
 *     implementation which follows XNU gc_putchar)
 *   - 80x24 character cell display with 8-colour SGR, bold, underline, reverse
 *   - Non-blocking reads from PTY master fd each run loop iteration
 *   - Keyboard input written to PTY master fd (not a local buffer)
 *
 * Dual-target: compiles with both -fobjc-runtime=gnustep-1.9 (Kiseki)
 * and -fobjc-runtime=macosx (macOS).  Uses the C runtime API throughout
 * (objc_msgSend, objc_getClass, etc.) so no @interface/@implementation
 * is needed for AppKit classes.
 *
 * Compiled with COMDAT-stripping pipeline (same as AppKit / Dock.app).
 *
 * Reference: WindowServer.c term_putc(), XNU osfmk/console/video_console.c
 */

#import <AppKit/AppKit.h>

/* ============================================================================
 * ObjC runtime functions for dynamic class creation
 * ============================================================================ */

extern Class  objc_allocateClassPair(Class superclass, const char *name, size_t extraBytes);
extern void   objc_registerClassPair(Class cls);
extern BOOL   class_addMethod(Class cls, SEL name, IMP imp, const char *types);
extern void  *objc_autoreleasePoolPush(void);
extern void   objc_autoreleasePoolPop(void *pool);

/* C library extras not in framework headers */
extern int    fprintf(void *stream, const char *fmt, ...);
extern int    snprintf(char *str, size_t size, const char *fmt, ...);
/* memmove — from <string.h> via Foundation.h */
extern void **__stderrp;
#define stderr (*__stderrp)

/*
 * POSIX types (pid_t, ssize_t, etc.) are provided by <types.h>
 * via the Foundation.h include chain.
 */

/* POSIX / BSD syscall wrappers from libSystem */
extern int   openpty(int *master, int *slave, char *name, void *termp, void *winp);
extern pid_t fork(void);
extern int   execve(const char *path, char *const argv[], char *const envp[]);
extern void  _exit(int status) __attribute__((noreturn));
extern int   close(int fd);
extern int   dup2(int oldfd, int newfd);
extern pid_t setsid(void);
extern ssize_t read(int fd, void *buf, size_t count);
extern ssize_t write(int fd, const void *buf, size_t count);
extern int   fcntl(int fd, int cmd, ...);
extern pid_t waitpid(pid_t pid, int *status, int options);
extern int   ioctl(int fd, unsigned long request, ...);
extern char *getenv(const char *name);

/* fcntl commands */
#define F_GETFL         3
#define F_SETFL         4
#define O_NONBLOCK      0x0004
#define O_RDWR          0x0002

/* ioctl for controlling terminal */
#define TIOCSCTTY       0x20007461
#define TIOCSWINSZ      0x80087467

/* waitpid flags */
#define WNOHANG         1

/* stdin/stdout/stderr fd numbers */
#define STDIN_FILENO    0
#define STDOUT_FILENO   1
#define STDERR_FILENO   2

/* struct winsize for TIOCSWINSZ */
struct winsize {
    uint16_t ws_row;
    uint16_t ws_col;
    uint16_t ws_xpixel;
    uint16_t ws_ypixel;
};

/* errno — we only need EAGAIN */
extern int errno;
#define EAGAIN          35

/* ============================================================================
 * HID Keycodes (matching WindowServer.c definitions)
 *
 * These are Linux-style HID keycodes sent by WindowServer in
 * ws_event_key_t.keycode for client-managed windows.
 * ============================================================================ */

#define KEY_ESC             1
#define KEY_BACKSPACE       14
#define KEY_TAB             15
#define KEY_ENTER           28
#define KEY_LEFTCTRL        29
#define KEY_LEFTSHIFT       42
#define KEY_RIGHTSHIFT      54
#define KEY_LEFTALT         56
#define KEY_CAPSLOCK        58
#define KEY_F1              59
#define KEY_F2              60
#define KEY_F3              61
#define KEY_F4              62
#define KEY_F5              63
#define KEY_F6              64
#define KEY_F7              65
#define KEY_F8              66
#define KEY_F9              67
#define KEY_F10             68
#define KEY_F11             87
#define KEY_F12             88
#define KEY_RIGHTCTRL       97
#define KEY_RIGHTALT        100
#define KEY_HOME            102
#define KEY_UP              103
#define KEY_PAGEUP          104
#define KEY_LEFT            105
#define KEY_RIGHT           106
#define KEY_END             107
#define KEY_DOWN            108
#define KEY_PAGEDOWN        109
#define KEY_INSERT          110
#define KEY_DELETE          111

/* ============================================================================
 * Terminal Constants — Matching WindowServer's built-in terminal
 * ============================================================================ */

#define TERM_COLS           80
#define TERM_ROWS           24
#define CHAR_WIDTH          8
#define CHAR_HEIGHT         16
#define TERM_WIDTH          (TERM_COLS * CHAR_WIDTH)    /* 640 */
#define TERM_HEIGHT         (TERM_ROWS * CHAR_HEIGHT)   /* 384 */

/* VT100 parser states (matching XNU gc_putchar / WindowServer.c) */
#define VT_NORMAL           0
#define VT_ESC              1
#define VT_CSI_INIT         2
#define VT_CSI_PARS         3
#define VT_DEC_PRIV         4

#define VT_MAXPARS          16

/* SGR attribute flags */
#define ATTR_NONE           0x00
#define ATTR_BOLD           0x01
#define ATTR_UNDERLINE      0x02
#define ATTR_REVERSE        0x04

/* Default ANSI colour indices */
#define DEFAULT_FG_IDX      7       /* White/light grey */
#define DEFAULT_BG_IDX      0       /* Black */

/* ============================================================================
 * ANSI Colour Tables (RGB float values for CGContext)
 *
 * Standard 8-colour ANSI palette. Bold promotes to bright.
 * ============================================================================ */

static const CGFloat ansi_colours_r[8] = { 0.00, 0.67, 0.00, 0.67, 0.00, 0.67, 0.00, 0.80 };
static const CGFloat ansi_colours_g[8] = { 0.00, 0.00, 0.67, 0.67, 0.00, 0.00, 0.67, 0.80 };
static const CGFloat ansi_colours_b[8] = { 0.00, 0.00, 0.00, 0.00, 0.67, 0.67, 0.67, 0.80 };

static const CGFloat ansi_bright_r[8]  = { 0.33, 1.00, 0.33, 1.00, 0.33, 1.00, 0.33, 1.00 };
static const CGFloat ansi_bright_g[8]  = { 0.33, 0.33, 1.00, 1.00, 0.33, 0.33, 1.00, 1.00 };
static const CGFloat ansi_bright_b[8]  = { 0.33, 0.33, 0.33, 0.33, 1.00, 1.00, 1.00, 1.00 };

/* ============================================================================
 * Terminal State — Per-window VT100 emulator state
 *
 * Matching WindowServer.c struct ws_term_state exactly.
 * ============================================================================ */

static struct {
    /* Character cell grid (struct-of-arrays, matching WindowServer) */
    unsigned char   cells[TERM_ROWS][TERM_COLS];
    uint8_t         cell_fg[TERM_ROWS][TERM_COLS];
    uint8_t         cell_bg[TERM_ROWS][TERM_COLS];
    uint8_t         cell_attr[TERM_ROWS][TERM_COLS];

    /* Cursor position (0-based) */
    uint32_t        cur_col;
    uint32_t        cur_row;

    /* VT100 parser state (matching XNU gc_putchar) */
    int             vt_state;
    uint32_t        vt_par[VT_MAXPARS];
    uint32_t        vt_numpars;

    /* Current text attributes */
    uint8_t         vt_attr;
    uint8_t         vt_fg_idx;
    uint8_t         vt_bg_idx;

    /* Autowrap mode (DECAWM) */
    int             vt_wrap_mode;

    /* Saved cursor (DECSC/DECRC) */
    uint32_t        saved_col;
    uint32_t        saved_row;
    uint8_t         saved_attr;
    uint8_t         saved_fg_idx;
    uint8_t         saved_bg_idx;

    /* Dirty flag — set when content has changed */
    int             dirty;
} term;

/* PTY state */
static int       g_master_fd = -1;      /* PTY master file descriptor */
static pid_t     g_shell_pid = -1;      /* Shell child process PID */
static NSView   *g_terminalView = nil;  /* Cached view for redraw */
static NSWindow *g_window = nil;        /* Cached window */

/* ============================================================================
 * VT100 Terminal Emulator
 *
 * Faithfully matching WindowServer.c term_init/term_putc/term_scroll_up/
 * term_clear_row/term_csi_dispatch/term_dec_priv_dispatch.
 *
 * Reference: XNU osfmk/console/video_console.c gc_putchar()
 * ============================================================================ */

static void term_init(void)
{
    memset(&term, 0, sizeof(term));
    term.vt_state = VT_NORMAL;
    term.vt_attr = ATTR_NONE;
    term.vt_fg_idx = DEFAULT_FG_IDX;
    term.vt_bg_idx = DEFAULT_BG_IDX;
    term.vt_wrap_mode = 1;

    for (uint32_t r = 0; r < TERM_ROWS; r++) {
        for (uint32_t c = 0; c < TERM_COLS; c++) {
            term.cells[r][c] = ' ';
            term.cell_fg[r][c] = DEFAULT_FG_IDX;
            term.cell_bg[r][c] = DEFAULT_BG_IDX;
            term.cell_attr[r][c] = ATTR_NONE;
        }
    }
    term.dirty = 1;
}

static void term_scroll_up(void)
{
    memmove(&term.cells[0], &term.cells[1],
            (TERM_ROWS - 1) * TERM_COLS);
    memmove(&term.cell_fg[0], &term.cell_fg[1],
            (TERM_ROWS - 1) * TERM_COLS);
    memmove(&term.cell_bg[0], &term.cell_bg[1],
            (TERM_ROWS - 1) * TERM_COLS);
    memmove(&term.cell_attr[0], &term.cell_attr[1],
            (TERM_ROWS - 1) * TERM_COLS);

    for (uint32_t c = 0; c < TERM_COLS; c++) {
        term.cells[TERM_ROWS - 1][c] = ' ';
        term.cell_fg[TERM_ROWS - 1][c] = term.vt_fg_idx;
        term.cell_bg[TERM_ROWS - 1][c] = term.vt_bg_idx;
        term.cell_attr[TERM_ROWS - 1][c] = ATTR_NONE;
    }
    term.dirty = 1;
}

static void term_scroll_down(void)
{
    memmove(&term.cells[1], &term.cells[0],
            (TERM_ROWS - 1) * TERM_COLS);
    memmove(&term.cell_fg[1], &term.cell_fg[0],
            (TERM_ROWS - 1) * TERM_COLS);
    memmove(&term.cell_bg[1], &term.cell_bg[0],
            (TERM_ROWS - 1) * TERM_COLS);
    memmove(&term.cell_attr[1], &term.cell_attr[0],
            (TERM_ROWS - 1) * TERM_COLS);

    for (uint32_t c = 0; c < TERM_COLS; c++) {
        term.cells[0][c] = ' ';
        term.cell_fg[0][c] = term.vt_fg_idx;
        term.cell_bg[0][c] = term.vt_bg_idx;
        term.cell_attr[0][c] = ATTR_NONE;
    }
    term.dirty = 1;
}

static void term_clear_row(uint32_t row, uint32_t from, uint32_t to)
{
    if (to > TERM_COLS) to = TERM_COLS;
    for (uint32_t c = from; c < to; c++) {
        term.cells[row][c] = ' ';
        term.cell_fg[row][c] = term.vt_fg_idx;
        term.cell_bg[row][c] = term.vt_bg_idx;
        term.cell_attr[row][c] = ATTR_NONE;
    }
    term.dirty = 1;
}

static void term_csi_dispatch(unsigned char cmd)
{
    uint32_t n;

    switch (cmd) {
    case 'A':
        n = term.vt_par[0] ? term.vt_par[0] : 1;
        if (n > term.cur_row) term.cur_row = 0;
        else term.cur_row -= n;
        break;

    case 'B':
        n = term.vt_par[0] ? term.vt_par[0] : 1;
        term.cur_row += n;
        if (term.cur_row >= TERM_ROWS) term.cur_row = TERM_ROWS - 1;
        break;

    case 'C':
        n = term.vt_par[0] ? term.vt_par[0] : 1;
        term.cur_col += n;
        if (term.cur_col >= TERM_COLS) term.cur_col = TERM_COLS - 1;
        break;

    case 'D':
        n = term.vt_par[0] ? term.vt_par[0] : 1;
        if (n > term.cur_col) term.cur_col = 0;
        else term.cur_col -= n;
        break;

    case 'H':
    case 'f':
        term.cur_row = term.vt_par[0] ? term.vt_par[0] - 1 : 0;
        term.cur_col = (term.vt_numpars >= 2 && term.vt_par[1]) ?
                        term.vt_par[1] - 1 : 0;
        if (term.cur_row >= TERM_ROWS) term.cur_row = TERM_ROWS - 1;
        if (term.cur_col >= TERM_COLS) term.cur_col = TERM_COLS - 1;
        break;

    case 'G':
        term.cur_col = term.vt_par[0] ? term.vt_par[0] - 1 : 0;
        if (term.cur_col >= TERM_COLS) term.cur_col = TERM_COLS - 1;
        break;

    case 'd':
        term.cur_row = term.vt_par[0] ? term.vt_par[0] - 1 : 0;
        if (term.cur_row >= TERM_ROWS) term.cur_row = TERM_ROWS - 1;
        break;

    case 'J':
        switch (term.vt_par[0]) {
        case 0:
            term_clear_row(term.cur_row, term.cur_col, TERM_COLS);
            for (uint32_t r = term.cur_row + 1; r < TERM_ROWS; r++)
                term_clear_row(r, 0, TERM_COLS);
            break;
        case 1:
            for (uint32_t r = 0; r < term.cur_row; r++)
                term_clear_row(r, 0, TERM_COLS);
            term_clear_row(term.cur_row, 0, term.cur_col + 1);
            break;
        case 2:
            for (uint32_t r = 0; r < TERM_ROWS; r++)
                term_clear_row(r, 0, TERM_COLS);
            break;
        }
        break;

    case 'K':
        switch (term.vt_par[0]) {
        case 0: term_clear_row(term.cur_row, term.cur_col, TERM_COLS); break;
        case 1: term_clear_row(term.cur_row, 0, term.cur_col + 1); break;
        case 2: term_clear_row(term.cur_row, 0, TERM_COLS); break;
        }
        break;

    case 'X':
        n = term.vt_par[0] ? term.vt_par[0] : 1;
        term_clear_row(term.cur_row, term.cur_col, term.cur_col + n);
        break;

    case 'P':
        n = term.vt_par[0] ? term.vt_par[0] : 1;
        if (term.cur_col + n > TERM_COLS) n = TERM_COLS - term.cur_col;
        for (uint32_t c = term.cur_col; c + n < TERM_COLS; c++) {
            term.cells[term.cur_row][c] = term.cells[term.cur_row][c + n];
            term.cell_fg[term.cur_row][c] = term.cell_fg[term.cur_row][c + n];
            term.cell_bg[term.cur_row][c] = term.cell_bg[term.cur_row][c + n];
            term.cell_attr[term.cur_row][c] = term.cell_attr[term.cur_row][c + n];
        }
        term_clear_row(term.cur_row, TERM_COLS - n, TERM_COLS);
        term.dirty = 1;
        break;

    case 'L':
        n = term.vt_par[0] ? term.vt_par[0] : 1;
        if (term.cur_row + n < TERM_ROWS) {
            for (uint32_t r = TERM_ROWS - 1; r >= term.cur_row + n; r--) {
                memcpy(term.cells[r], term.cells[r - n], TERM_COLS);
                memcpy(term.cell_fg[r], term.cell_fg[r - n], TERM_COLS);
                memcpy(term.cell_bg[r], term.cell_bg[r - n], TERM_COLS);
                memcpy(term.cell_attr[r], term.cell_attr[r - n], TERM_COLS);
            }
        }
        for (uint32_t r = term.cur_row; r < term.cur_row + n && r < TERM_ROWS; r++)
            term_clear_row(r, 0, TERM_COLS);
        term.dirty = 1;
        break;

    case 'M':
        n = term.vt_par[0] ? term.vt_par[0] : 1;
        if (term.cur_row + n < TERM_ROWS) {
            for (uint32_t r = term.cur_row; r + n < TERM_ROWS; r++) {
                memcpy(term.cells[r], term.cells[r + n], TERM_COLS);
                memcpy(term.cell_fg[r], term.cell_fg[r + n], TERM_COLS);
                memcpy(term.cell_bg[r], term.cell_bg[r + n], TERM_COLS);
                memcpy(term.cell_attr[r], term.cell_attr[r + n], TERM_COLS);
            }
        }
        for (uint32_t r = TERM_ROWS - n; r < TERM_ROWS; r++)
            term_clear_row(r, 0, TERM_COLS);
        term.dirty = 1;
        break;

    case 'm':
        for (uint32_t i = 0; i < term.vt_numpars; i++) {
            uint32_t p = term.vt_par[i];
            if (p == 0) {
                term.vt_attr = ATTR_NONE;
                term.vt_fg_idx = DEFAULT_FG_IDX;
                term.vt_bg_idx = DEFAULT_BG_IDX;
            } else if (p == 1) { term.vt_attr |= ATTR_BOLD;
            } else if (p == 4) { term.vt_attr |= ATTR_UNDERLINE;
            } else if (p == 7) { term.vt_attr |= ATTR_REVERSE;
            } else if (p == 22) { term.vt_attr &= (uint8_t)~ATTR_BOLD;
            } else if (p == 24) { term.vt_attr &= (uint8_t)~ATTR_UNDERLINE;
            } else if (p == 27) { term.vt_attr &= (uint8_t)~ATTR_REVERSE;
            } else if (p >= 30 && p <= 37) { term.vt_fg_idx = (uint8_t)(p - 30);
            } else if (p >= 40 && p <= 47) { term.vt_bg_idx = (uint8_t)(p - 40);
            } else if (p == 39) { term.vt_fg_idx = DEFAULT_FG_IDX;
            } else if (p == 49) { term.vt_bg_idx = DEFAULT_BG_IDX;
            }
        }
        break;

    case 'r':
        term.cur_row = 0;
        term.cur_col = 0;
        break;

    default:
        break;
    }
}

static void term_dec_priv_dispatch(unsigned char cmd)
{
    if (cmd == 'h' && term.vt_par[0] == 7)
        term.vt_wrap_mode = 1;
    else if (cmd == 'l' && term.vt_par[0] == 7)
        term.vt_wrap_mode = 0;
}

static void term_putc(unsigned char ch)
{
    switch (term.vt_state) {

    case VT_NORMAL:
        switch (ch) {
        case 0x00: break;
        case 0x07: break;
        case '\b': case 0x7F:
            if (term.cur_col > 0) term.cur_col--;
            break;
        case '\t': {
            uint32_t next = (term.cur_col + 8) & ~7u;
            if (next >= TERM_COLS) next = TERM_COLS - 1;
            term.cur_col = next;
            break;
        }
        case '\n': case 0x0B: case 0x0C:
            term.cur_row++;
            if (term.cur_row >= TERM_ROWS) {
                term_scroll_up();
                term.cur_row = TERM_ROWS - 1;
            }
            term.dirty = 1;
            break;
        case '\r':
            term.cur_col = 0;
            break;
        case 0x1B:
            term.vt_state = VT_ESC;
            break;
        default:
            if (ch >= 0x20) {
                term.cells[term.cur_row][term.cur_col] = ch;
                term.cell_fg[term.cur_row][term.cur_col] = term.vt_fg_idx;
                term.cell_bg[term.cur_row][term.cur_col] = term.vt_bg_idx;
                term.cell_attr[term.cur_row][term.cur_col] = term.vt_attr;
                term.dirty = 1;
                term.cur_col++;
                if (term.cur_col >= TERM_COLS) {
                    if (term.vt_wrap_mode) {
                        term.cur_col = 0;
                        term.cur_row++;
                        if (term.cur_row >= TERM_ROWS) {
                            term_scroll_up();
                            term.cur_row = TERM_ROWS - 1;
                        }
                    } else {
                        term.cur_col = TERM_COLS - 1;
                    }
                }
            }
            break;
        }
        break;

    case VT_ESC:
        term.vt_state = VT_NORMAL;
        switch (ch) {
        case '[': term.vt_state = VT_CSI_INIT; break;
        case 'c':
            term_init();
            break;
        case 'D':
            term.cur_row++;
            if (term.cur_row >= TERM_ROWS) {
                term_scroll_up();
                term.cur_row = TERM_ROWS - 1;
            }
            term.dirty = 1;
            break;
        case 'M':
            if (term.cur_row == 0) {
                term_scroll_down();
            } else {
                term.cur_row--;
            }
            break;
        case '7':
            term.saved_col = term.cur_col;
            term.saved_row = term.cur_row;
            term.saved_attr = term.vt_attr;
            term.saved_fg_idx = term.vt_fg_idx;
            term.saved_bg_idx = term.vt_bg_idx;
            break;
        case '8':
            term.cur_col = term.saved_col;
            term.cur_row = term.saved_row;
            term.vt_attr = term.saved_attr;
            term.vt_fg_idx = term.saved_fg_idx;
            term.vt_bg_idx = term.saved_bg_idx;
            if (term.cur_row >= TERM_ROWS) term.cur_row = TERM_ROWS - 1;
            if (term.cur_col >= TERM_COLS) term.cur_col = TERM_COLS - 1;
            break;
        default: break;
        }
        break;

    case VT_CSI_INIT:
        for (uint32_t i = 0; i < VT_MAXPARS; i++)
            term.vt_par[i] = 0;
        term.vt_numpars = 0;
        term.vt_state = VT_CSI_PARS;
        /* FALLTHROUGH */

    case VT_CSI_PARS:
        if (ch == '?') {
            term.vt_state = VT_DEC_PRIV;
        } else if (ch >= '0' && ch <= '9') {
            term.vt_par[term.vt_numpars] =
                term.vt_par[term.vt_numpars] * 10 + (ch - '0');
        } else if (ch == ';') {
            if (term.vt_numpars < VT_MAXPARS - 1)
                term.vt_numpars++;
        } else {
            term.vt_numpars++;
            term.vt_state = VT_NORMAL;
            term_csi_dispatch(ch);
        }
        break;

    case VT_DEC_PRIV:
        if (ch >= '0' && ch <= '9') {
            term.vt_par[0] = term.vt_par[0] * 10 + (ch - '0');
        } else {
            term.vt_state = VT_NORMAL;
            term_dec_priv_dispatch(ch);
        }
        break;

    default:
        term.vt_state = VT_NORMAL;
        break;
    }
}

/* ============================================================================
 * PTY Setup — Fork shell process with proper session management
 * ============================================================================ */

static int term_setup_pty(void)
{
    int master_fd = -1, slave_fd = -1;

    if (openpty(&master_fd, &slave_fd, NULL, NULL, NULL) < 0) {
        fprintf(stderr, "[Terminal] openpty() failed\n");
        return -1;
    }

    int flags = fcntl(master_fd, F_GETFL, 0);
    fcntl(master_fd, F_SETFL, flags | O_NONBLOCK);

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "[Terminal] fork() failed\n");
        close(master_fd);
        close(slave_fd);
        return -1;
    }

    if (pid == 0) {
        /* === Child process === */
        close(master_fd);
        setsid();
        ioctl(slave_fd, TIOCSCTTY, 0);

        struct winsize ws;
        ws.ws_row = TERM_ROWS;
        ws.ws_col = TERM_COLS;
        ws.ws_xpixel = TERM_WIDTH;
        ws.ws_ypixel = TERM_HEIGHT;
        ioctl(slave_fd, TIOCSWINSZ, &ws);

        dup2(slave_fd, STDIN_FILENO);
        dup2(slave_fd, STDOUT_FILENO);
        dup2(slave_fd, STDERR_FILENO);
        if (slave_fd > STDERR_FILENO)
            close(slave_fd);

        const char *home    = getenv("HOME");
        const char *user    = getenv("USER");
        const char *logname = getenv("LOGNAME");
        const char *shell   = getenv("SHELL");
        const char *path_env = getenv("PATH");

        char env_home[80], env_user[48], env_logname[48];
        char env_shell[48], env_path[256];

        snprintf(env_home,    sizeof(env_home),    "HOME=%s",    home     ? home     : "/root");
        snprintf(env_user,    sizeof(env_user),    "USER=%s",    user     ? user     : "root");
        snprintf(env_logname, sizeof(env_logname), "LOGNAME=%s", logname  ? logname  : "root");
        snprintf(env_shell,   sizeof(env_shell),   "SHELL=%s",   shell    ? shell    : "/bin/bash");
        snprintf(env_path,    sizeof(env_path),    "PATH=%s",    path_env ? path_env : "/bin:/sbin:/usr/bin:/usr/sbin");

        char *envp[] = {
            env_home,
            env_path,
            "TERM=vt100",
            env_shell,
            env_user,
            env_logname,
            "COLUMNS=80",
            "LINES=24",
            NULL
        };

        const char *user_shell = shell ? shell : "/bin/bash";
        char *argv[] = { (char *)user_shell, "--login", NULL };
        execve(user_shell, argv, envp);

        argv[0] = "/bin/bash";
        execve("/bin/bash", argv, envp);

        argv[0] = "/bin/sh";
        execve("/bin/sh", argv, envp);

        _exit(127);
    }

    /* === Parent process === */
    close(slave_fd);

    g_master_fd = master_fd;
    g_shell_pid = pid;

    fprintf(stderr, "[Terminal] PTY established: master_fd=%d, shell PID=%d\n",
            master_fd, pid);
    return 0;
}

/* ============================================================================
 * PTY I/O — Non-blocking read from master fd
 * ============================================================================ */

static void term_read_pty(void)
{
    if (g_master_fd < 0) return;

    char buf[4096];
    ssize_t n = read(g_master_fd, buf, sizeof(buf));

    if (n > 0) {
        for (ssize_t i = 0; i < n; i++)
            term_putc((unsigned char)buf[i]);
    } else if (n == 0) {
        fprintf(stderr, "[Terminal] Shell exited (EOF on master)\n");
        close(g_master_fd);
        g_master_fd = -1;

        if (g_shell_pid > 0) {
            int status = 0;
            waitpid(g_shell_pid, &status, 0);
            g_shell_pid = -1;
        }
    }
}

/* ============================================================================
 * TerminalView — Custom NSView subclass for the terminal display
 * ============================================================================ */

static id _TerminalDrawRect(id self, SEL _cmd, CGRect dirtyRect) {
    (void)self; (void)_cmd; (void)dirtyRect;

    NSGraphicsContext *gctx = [NSGraphicsContext currentContext];
    if (!gctx) return nil;

    CGContextRef ctx = [gctx CGContext];
    if (!ctx) return nil;

    /* Render each cell */
    for (uint32_t row = 0; row < TERM_ROWS; row++) {
        CGFloat y = (CGFloat)(TERM_HEIGHT - (row + 1) * CHAR_HEIGHT);

        for (uint32_t col = 0; col < TERM_COLS; col++) {
            CGFloat x = (CGFloat)(col * CHAR_WIDTH);
            unsigned char ch = term.cells[row][col];
            uint8_t fg_idx = term.cell_fg[row][col];
            uint8_t bg_idx = term.cell_bg[row][col];
            uint8_t attr = term.cell_attr[row][col];

            CGFloat fg_r, fg_g, fg_b;
            CGFloat bg_r, bg_g, bg_b;

            if (attr & ATTR_REVERSE) {
                fg_r = ansi_colours_r[bg_idx & 7];
                fg_g = ansi_colours_g[bg_idx & 7];
                fg_b = ansi_colours_b[bg_idx & 7];
                bg_r = ansi_colours_r[fg_idx & 7];
                bg_g = ansi_colours_g[fg_idx & 7];
                bg_b = ansi_colours_b[fg_idx & 7];
            } else {
                if (attr & ATTR_BOLD) {
                    fg_r = ansi_bright_r[fg_idx & 7];
                    fg_g = ansi_bright_g[fg_idx & 7];
                    fg_b = ansi_bright_b[fg_idx & 7];
                } else {
                    fg_r = ansi_colours_r[fg_idx & 7];
                    fg_g = ansi_colours_g[fg_idx & 7];
                    fg_b = ansi_colours_b[fg_idx & 7];
                }
                bg_r = ansi_colours_r[bg_idx & 7];
                bg_g = ansi_colours_g[bg_idx & 7];
                bg_b = ansi_colours_b[bg_idx & 7];
            }

            CGContextSetRGBFillColor(ctx, bg_r, bg_g, bg_b, 1.0);
            CGContextFillRect(ctx, CGRectMake(x, y, CHAR_WIDTH, CHAR_HEIGHT));

            if (ch > ' ' && ch < 0x7F) {
                CGContextSetRGBFillColor(ctx, fg_r, fg_g, fg_b, 1.0);
                CGContextShowTextAtPoint(ctx, x, y, (const char *)&ch, 1);
            }

            if (attr & ATTR_UNDERLINE) {
                CGContextSetRGBFillColor(ctx, fg_r, fg_g, fg_b, 1.0);
                CGContextFillRect(ctx, CGRectMake(x, y, CHAR_WIDTH, 1));
            }
        }
    }

    /* Draw block cursor */
    if (term.cur_row < TERM_ROWS && term.cur_col < TERM_COLS) {
        CGFloat cx = (CGFloat)(term.cur_col * CHAR_WIDTH);
        CGFloat cy = (CGFloat)(TERM_HEIGHT - (term.cur_row + 1) * CHAR_HEIGHT);
        unsigned char ch = term.cells[term.cur_row][term.cur_col];
        uint8_t fg_idx = term.cell_fg[term.cur_row][term.cur_col];
        uint8_t bg_idx = term.cell_bg[term.cur_row][term.cur_col];
        uint8_t attr   = term.cell_attr[term.cur_row][term.cur_col];

        CGFloat cur_fg_r, cur_fg_g, cur_fg_b;
        CGFloat cur_bg_r, cur_bg_g, cur_bg_b;

        if (attr & ATTR_REVERSE) {
            cur_bg_r = ansi_colours_r[bg_idx & 7];
            cur_bg_g = ansi_colours_g[bg_idx & 7];
            cur_bg_b = ansi_colours_b[bg_idx & 7];
            cur_fg_r = ansi_colours_r[fg_idx & 7];
            cur_fg_g = ansi_colours_g[fg_idx & 7];
            cur_fg_b = ansi_colours_b[fg_idx & 7];
        } else {
            cur_bg_r = (attr & ATTR_BOLD) ? ansi_bright_r[fg_idx & 7] : ansi_colours_r[fg_idx & 7];
            cur_bg_g = (attr & ATTR_BOLD) ? ansi_bright_g[fg_idx & 7] : ansi_colours_g[fg_idx & 7];
            cur_bg_b = (attr & ATTR_BOLD) ? ansi_bright_b[fg_idx & 7] : ansi_colours_b[fg_idx & 7];
            cur_fg_r = ansi_colours_r[bg_idx & 7];
            cur_fg_g = ansi_colours_g[bg_idx & 7];
            cur_fg_b = ansi_colours_b[bg_idx & 7];
        }

        CGContextSetRGBFillColor(ctx, cur_bg_r, cur_bg_g, cur_bg_b, 1.0);
        CGContextFillRect(ctx, CGRectMake(cx, cy, CHAR_WIDTH, CHAR_HEIGHT));

        if (ch > ' ' && ch < 0x7F) {
            CGContextSetRGBFillColor(ctx, cur_fg_r, cur_fg_g, cur_fg_b, 1.0);
            CGContextShowTextAtPoint(ctx, cx, cy, (const char *)&ch, 1);
        }
    }

    return nil;
}

static BOOL _TerminalAcceptsFirstResponder(id self, SEL _cmd) {
    (void)self; (void)_cmd;
    return YES;
}

static id _TerminalKeyDown(id self, SEL _cmd, id theEvent) {
    (void)_cmd;

    if (g_master_fd < 0) return nil;

    NSEvent *event = (NSEvent *)theEvent;

    uint16_t keyCode = [event keyCode];
    NSUInteger modifiers = [event modifierFlags];
    NSString *chars = [event characters];

    /* Special keys: send VT100 escape sequences to PTY master */
    switch (keyCode) {
    case KEY_UP:
        write(g_master_fd, "\033[A", 3);
        goto done;
    case KEY_DOWN:
        write(g_master_fd, "\033[B", 3);
        goto done;
    case KEY_RIGHT:
        write(g_master_fd, "\033[C", 3);
        goto done;
    case KEY_LEFT:
        write(g_master_fd, "\033[D", 3);
        goto done;
    case KEY_HOME:
        write(g_master_fd, "\033[H", 3);
        goto done;
    case KEY_END:
        write(g_master_fd, "\033[F", 3);
        goto done;
    case KEY_DELETE:
        write(g_master_fd, "\033[3~", 4);
        goto done;
    case KEY_PAGEUP:
        write(g_master_fd, "\033[5~", 4);
        goto done;
    case KEY_PAGEDOWN:
        write(g_master_fd, "\033[6~", 4);
        goto done;
    }

    /* Regular characters */
    if (!chars) return nil;

    uint16_t ch = [chars characterAtIndex:0];

    if (ch == 0) return nil;

    if ((modifiers & NSEventModifierFlagControl) && ch >= 'a' && ch <= 'z') {
        char ctrl = (char)(ch - 'a' + 1);
        write(g_master_fd, &ctrl, 1);
    } else if ((modifiers & NSEventModifierFlagControl) && ch >= 'A' && ch <= 'Z') {
        char ctrl = (char)(ch - 'A' + 1);
        write(g_master_fd, &ctrl, 1);
    } else if (ch < 0x80) {
        char c = (char)ch;
        write(g_master_fd, &c, 1);
    }

done:
    [(NSView *)self setNeedsDisplay:YES];

    return nil;
}

/* ============================================================================
 * NSApplication Run Loop Integration
 * ============================================================================ */

static void term_poll_and_redraw(void)
{
    if (g_master_fd < 0) return;

    int old_dirty = term.dirty;
    term_read_pty();

    if (term.dirty && g_terminalView) {
        [g_terminalView setNeedsDisplay:YES];
    }

    if (g_shell_pid > 0) {
        int status = 0;
        pid_t ret = waitpid(g_shell_pid, &status, WNOHANG);
        if (ret > 0) {
            fprintf(stderr, "[Terminal] Shell process %d exited\n", g_shell_pid);
            g_shell_pid = -1;
        }
    }

    (void)old_dirty;
}

/* ============================================================================
 * TerminalAppDelegate
 * ============================================================================ */

static id _termAppDidFinishLaunching(id self, SEL _cmd, id notification) {
    (void)self; (void)_cmd; (void)notification;

    /* Initialise VT100 terminal state */
    term_init();

    /* Set up PTY + fork shell */
    if (term_setup_pty() < 0) {
        fprintf(stderr, "[Terminal] Failed to set up PTY, running in dumb mode\n");
    }

    /* Create the terminal window */
    g_window = [[NSWindow alloc]
        initWithContentRect:CGRectMake(100, 100, TERM_WIDTH, TERM_HEIGHT)
                  styleMask:(NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
                             NSWindowStyleMaskMiniaturizable | NSWindowStyleMaskResizable)
                    backing:NSBackingStoreBuffered
                      defer:NO];

    [g_window setTitle:(id)CFSTR("Terminal")];

    /* Create TerminalView class dynamically */
    Class TerminalView = objc_allocateClassPair(
        [NSView class], "TerminalView", 0);
    class_addMethod(TerminalView, @selector(drawRect:),
                    (IMP)_TerminalDrawRect, "v@:{CGRect=dddd}");
    class_addMethod(TerminalView, @selector(acceptsFirstResponder),
                    (IMP)_TerminalAcceptsFirstResponder, "c@:");
    class_addMethod(TerminalView, @selector(keyDown:),
                    (IMP)_TerminalKeyDown, "v@:@");
    objc_registerClassPair(TerminalView);

    /* Instantiate TerminalView */
    NSView *termView = [[TerminalView alloc]
        initWithFrame:CGRectMake(0, 0, TERM_WIDTH, TERM_HEIGHT)];

    g_terminalView = termView;

    /* Set TerminalView as content view and show window */
    [g_window setContentView:termView];
    [g_window makeKeyAndOrderFront:nil];
    [g_window makeFirstResponder:termView];

    /* Set up menu bar */
    NSMenu *menu = [[NSMenu alloc] initWithTitle:(id)CFSTR("Terminal")];
    [NSApp setMainMenu:menu];

    fprintf(stderr, "[Terminal] Window created (%dx%d), PTY master=%d, shell PID=%d\n",
            TERM_WIDTH, TERM_HEIGHT, g_master_fd, g_shell_pid);
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
    Class TerminalAppDelegate = objc_allocateClassPair(
        [NSObject class], "TerminalAppDelegate", 0);
    class_addMethod(TerminalAppDelegate,
                    @selector(applicationDidFinishLaunching:),
                    (IMP)_termAppDidFinishLaunching, "v@:@");
    objc_registerClassPair(TerminalAppDelegate);

    /* Create delegate instance and set on NSApp */
    id delegate = [TerminalAppDelegate new];
    [NSApp setDelegate:delegate];

    /*
     * Custom run loop with PTY polling.
     *
     * Instead of calling [NSApp run] which enters a closed loop we
     * cannot modify, we replicate the run loop here with PTY polling
     * injected.
     */

    /* Step 1: finishLaunching */
    [NSApp finishLaunching];

    /* Step 2: Event loop with PTY polling */
    for (;;) {
        /* 2a. Poll for one WindowServer event (10ms timeout) */
        NSEvent *event = [NSApp nextEventMatchingMask:(NSUInteger)0xFFFFFFFF
                                            untilDate:nil
                                               inMode:(id)CFSTR("kCFRunLoopDefaultMode")
                                              dequeue:YES];

        if (event) {
            [NSApp sendEvent:event];
        }

        /* 2c-d. Poll PTY and feed VT100 emulator */
        term_poll_and_redraw();

        /* 2e. Display dirty windows */
        if (g_window) {
            [g_window displayIfNeeded];
        }
    }

    objc_autoreleasePoolPop(pool);
    return 0;
}
