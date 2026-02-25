/*
 * Kiseki OS - loginwindow
 *
 * Faithful reimplementation of macOS /System/Library/CoreServices/loginwindow.app.
 *
 * On macOS, loginwindow is launched by launchd via
 * /System/Library/LaunchDaemons/com.apple.loginwindow.plist.
 * It is a GUI application that:
 *   1. Connects to WindowServer as a client
 *   2. Presents the login UI (username + password fields)
 *   3. Authenticates the user against /etc/passwd + /etc/shadow
 *   4. After authentication, sets up the user session by launching:
 *      - Dock.app
 *      - Finder.app
 *      - SystemUIServer.app
 *      - Terminal.app (as a convenience for development)
 *   5. Monitors child processes and relaunches critical ones on crash
 *   6. Handles logout (kill all user processes, re-show login window)
 *
 * This implementation uses raw Mach IPC to talk to WindowServer,
 * matching how macOS loginwindow uses CoreGraphics/SkyLight SPI
 * directly rather than going through AppKit.
 *
 * Build: Added to userland/sbin/Makefile PROGS list.
 * Plist: config/LaunchDaemons/uk.co.avltree9798.loginwindow.plist
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

/* ============================================================================
 * WindowServer IPC Protocol Constants
 *
 * Must match WindowServer.c definitions exactly.
 * ============================================================================ */

#define WS_SERVICE_NAME         "uk.co.avltree9798.WindowServer"

/* Request IDs */
#define WS_MSG_CONNECT          1000
#define WS_MSG_DISCONNECT       1001
#define WS_MSG_CREATE_WINDOW    1010
#define WS_MSG_DESTROY_WINDOW   1011
#define WS_MSG_ORDER_WINDOW     1012
#define WS_MSG_SET_TITLE        1013
#define WS_MSG_DRAW_RECT        1020

/* Reply IDs */
#define WS_REPLY_CONNECT        2000
#define WS_REPLY_CREATE_WINDOW  2010

/* Event IDs */
#define WS_EVENT_KEY_DOWN       3000
#define WS_EVENT_KEY_UP         3001
#define WS_EVENT_MOUSE_DOWN     3010

/* Ordering */
#define WS_ORDER_OUT            0
#define WS_ORDER_FRONT          1
#define WS_ORDER_BACK           2

/* HID keycodes (matching WindowServer) */
#define KEY_BACKSPACE           14
#define KEY_TAB                 15
#define KEY_ENTER               28

/* HID modifier flags */
#define HID_FLAG_SHIFT          (1 << 0)
#define HID_FLAG_CTRL           (1 << 1)
#define HID_FLAG_ALT            (1 << 2)
#define HID_FLAG_CAPSLOCK       (1 << 3)

/* Screen dimensions */
#define SCREEN_WIDTH            1280
#define SCREEN_HEIGHT           800

/* Login window dimensions */
#define LOGIN_WIN_W             360
#define LOGIN_WIN_H             260
#define LOGIN_WIN_X             ((SCREEN_WIDTH - LOGIN_WIN_W) / 2)
#define LOGIN_WIN_Y             ((SCREEN_HEIGHT - LOGIN_WIN_H) / 2 - 40)

/* Font dimensions (8x16 bitmap) */
#define FONT_W                  8
#define FONT_H                  16

/* Field geometry */
#define FIELD_W                 240
#define FIELD_H                 24
#define FIELD_X                 ((LOGIN_WIN_W - FIELD_W) / 2)
#define BUTTON_W                100
#define BUTTON_H                28

/* ============================================================================
 * IPC Message Structures (matching WindowServer.c)
 * ============================================================================ */

typedef struct {
    mach_msg_header_t   header;
    char                app_name[64];
    int32_t             pid;
} ws_msg_connect_t;

typedef struct {
    mach_msg_header_t   header;
    int32_t             conn_id;
    kern_return_t       result;
} ws_reply_connect_t;

typedef struct {
    mach_msg_header_t   header;
    int32_t             conn_id;
    int32_t             x, y;
    uint32_t            width, height;
    uint32_t            style_mask;
    char                title[64];
} ws_msg_create_window_t;

typedef struct {
    mach_msg_header_t   header;
    int32_t             window_id;
    kern_return_t       result;
} ws_reply_create_window_t;

typedef struct {
    mach_msg_header_t       header;
    mach_msg_body_t         body;
    mach_msg_ool_descriptor_t surface_desc;
    int32_t                 conn_id;
    int32_t                 window_id;
    uint32_t                dst_x, dst_y;
    uint32_t                width, height;
    uint32_t                src_rowbytes;
} ws_msg_draw_rect_t;

typedef struct {
    mach_msg_header_t   header;
    int32_t             conn_id;
    int32_t             window_id;
    int32_t             order;
} ws_msg_order_window_t;

typedef struct {
    mach_msg_header_t   header;
    int32_t             window_id;
    uint32_t            keycode;
    uint32_t            characters;
    uint32_t            modifiers;
    uint16_t            is_repeat;
    uint16_t            _pad;
} ws_event_key_t;

typedef struct {
    mach_msg_header_t   header;
    int32_t             window_id;
    int32_t             x, y;
    int32_t             screen_x, screen_y;
    uint32_t            button;
    uint32_t            modifiers;
    uint32_t            click_count;
} ws_event_mouse_t;

typedef union {
    mach_msg_header_t   header;
    uint8_t             _pad[4096 + 256];
} ws_msg_buffer_t;

/* ============================================================================
 * Connection State
 * ============================================================================ */

static mach_port_t  g_service_port = MACH_PORT_NULL;
static mach_port_t  g_event_port = MACH_PORT_NULL;
static int32_t      g_conn_id = -1;
static int32_t      g_win_id = -1;

/* Pixel buffer for the login window */
static uint32_t    *g_pixels = NULL;
static uint32_t     g_pixels_w = LOGIN_WIN_W;
static uint32_t     g_pixels_h = LOGIN_WIN_H;
static uint32_t     g_pixels_stride = LOGIN_WIN_W * 4;

/* Login state */
#define FIELD_MAX   32
static char login_username[FIELD_MAX];
static int  login_username_len = 0;
static char login_password[FIELD_MAX];
static int  login_password_len = 0;
static int  login_field = 0;    /* 0 = username, 1 = password */
static int  login_active = 1;   /* 1 = showing login, 0 = session active */
static char login_error[64];    /* Error message to display */

/* Session PIDs (child processes launched after login) */
static pid_t g_dock_pid = -1;
static pid_t g_finder_pid = -1;
static pid_t g_sysui_pid = -1;
static pid_t g_terminal_pid = -1;

/* ============================================================================
 * WindowServer IPC Helpers
 * ============================================================================ */

static int ws_connect(void)
{
    kern_return_t kr;

    kr = bootstrap_look_up(MACH_PORT_NULL, WS_SERVICE_NAME, &g_service_port);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "[loginwindow] bootstrap_look_up failed: %d\n", kr);
        return -1;
    }

    /* Allocate event port for receiving async events */
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &g_event_port);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "[loginwindow] mach_port_allocate failed: %d\n", kr);
        return -1;
    }

    /* Send connect message */
    struct {
        ws_msg_connect_t    send;
        ws_reply_connect_t  recv;
    } msg;
    memset(&msg, 0, sizeof(msg));

    msg.send.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND,
                                                 MACH_MSG_TYPE_MAKE_SEND);
    msg.send.header.msgh_size = sizeof(msg.send);
    msg.send.header.msgh_remote_port = g_service_port;
    msg.send.header.msgh_local_port = g_event_port;
    msg.send.header.msgh_id = WS_MSG_CONNECT;
    strncpy(msg.send.app_name, "loginwindow", 63);
    msg.send.pid = getpid();

    kr = mach_msg(&msg.send.header,
                  MACH_SEND_MSG | MACH_RCV_MSG,
                  sizeof(msg.send),
                  sizeof(msg.recv),
                  g_event_port,
                  MACH_MSG_TIMEOUT_NONE,
                  MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "[loginwindow] WS_MSG_CONNECT failed: %d\n", kr);
        return -1;
    }

    g_conn_id = msg.recv.conn_id;
    fprintf(stderr, "[loginwindow] Connected to WindowServer, conn_id=%d\n", g_conn_id);
    return 0;
}

static int32_t ws_create_window(int32_t x, int32_t y, uint32_t w, uint32_t h,
                                 uint32_t style, const char *title)
{
    struct {
        ws_msg_create_window_t  send;
        ws_reply_create_window_t recv;
    } msg;
    memset(&msg, 0, sizeof(msg));

    msg.send.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND,
                                                 MACH_MSG_TYPE_MAKE_SEND);
    msg.send.header.msgh_size = sizeof(msg.send);
    msg.send.header.msgh_remote_port = g_service_port;
    msg.send.header.msgh_local_port = g_event_port;
    msg.send.header.msgh_id = WS_MSG_CREATE_WINDOW;
    msg.send.conn_id = g_conn_id;
    msg.send.x = x;
    msg.send.y = y;
    msg.send.width = w;
    msg.send.height = h;
    msg.send.style_mask = style;
    if (title) strncpy(msg.send.title, title, 63);

    kern_return_t kr = mach_msg(&msg.send.header,
                                MACH_SEND_MSG | MACH_RCV_MSG,
                                sizeof(msg.send),
                                sizeof(msg.recv),
                                g_event_port,
                                MACH_MSG_TIMEOUT_NONE,
                                MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) return -1;
    return msg.recv.window_id;
}

static void ws_draw_rect(int32_t win_id, uint32_t dx, uint32_t dy,
                          uint32_t w, uint32_t h,
                          void *pixels, uint32_t rowbytes)
{
    ws_msg_draw_rect_t msg;
    memset(&msg, 0, sizeof(msg));

    msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) |
                           MACH_MSGH_BITS_COMPLEX;
    msg.header.msgh_size = sizeof(msg);
    msg.header.msgh_remote_port = g_service_port;
    msg.header.msgh_id = WS_MSG_DRAW_RECT;
    msg.body.msgh_descriptor_count = 1;
    msg.surface_desc.address = pixels;
    msg.surface_desc.size = rowbytes * h;
    msg.surface_desc.deallocate = 0;
    msg.surface_desc.copy = MACH_MSG_VIRTUAL_COPY;
    msg.surface_desc.type = MACH_MSG_OOL_DESCRIPTOR;
    msg.conn_id = g_conn_id;
    msg.window_id = win_id;
    msg.dst_x = dx;
    msg.dst_y = dy;
    msg.width = w;
    msg.height = h;
    msg.src_rowbytes = rowbytes;

    mach_msg(&msg.header, MACH_SEND_MSG, sizeof(msg), 0,
             MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
}

static void ws_order_window(int32_t win_id, int32_t order)
{
    ws_msg_order_window_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    msg.header.msgh_size = sizeof(msg);
    msg.header.msgh_remote_port = g_service_port;
    msg.header.msgh_id = WS_MSG_ORDER_WINDOW;
    msg.conn_id = g_conn_id;
    msg.window_id = win_id;
    msg.order = order;

    mach_msg(&msg.header, MACH_SEND_MSG, sizeof(msg), 0,
             MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
}

/* ============================================================================
 * Software Pixel Rendering (BGRA 32bpp)
 *
 * Matches WindowServer's pixel format: VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM
 * Byte order: [Blue, Green, Red, Alpha] = 0xAARRGGBB in little-endian
 * ============================================================================ */

static inline uint32_t px_rgba(uint8_t r, uint8_t g, uint8_t b, uint8_t a)
{
    return ((uint32_t)a << 24) | ((uint32_t)r << 16) |
           ((uint32_t)g << 8) | (uint32_t)b;
}

static void px_fill_rect(uint32_t *buf, uint32_t stride,
                          int x, int y, int w, int h, uint32_t colour)
{
    uint32_t row_pixels = stride / 4;
    for (int ry = y; ry < y + h && ry < (int)g_pixels_h; ry++) {
        for (int rx = x; rx < x + w && rx < (int)g_pixels_w; rx++) {
            if (rx >= 0 && ry >= 0)
                buf[ry * row_pixels + rx] = colour;
        }
    }
}

/*
 * VGA 8x16 Bitmap Font (CP437)
 *
 * Standard IBM PC font — each glyph is 16 bytes, one per scanline,
 * MSB = leftmost pixel.  256 glyphs, 4096 bytes total.
 * Same data as kernel/kern/font8x16.c.
 */
#include "font8x16.inc"

static void px_draw_char(uint32_t *buf, uint32_t stride,
                          int x, int y, char ch, uint32_t colour)
{
    uint8_t idx = (uint8_t)ch;
    const unsigned char *glyph = lw_font8x16[idx];
    uint32_t row_pixels = stride / 4;

    for (int row = 0; row < FONT_H; row++) {
        uint8_t bits = glyph[row];
        int py = y + row;
        if (py < 0 || py >= (int)g_pixels_h) continue;
        for (int col = 0; col < FONT_W; col++) {
            if (bits & (0x80 >> col)) {
                int px = x + col;
                if (px >= 0 && px < (int)g_pixels_w)
                    buf[py * row_pixels + px] = colour;
            }
        }
    }
}

static void px_draw_text(uint32_t *buf, uint32_t stride,
                          int x, int y, const char *text, uint32_t colour)
{
    for (int i = 0; text[i]; i++) {
        px_draw_char(buf, stride, x + i * FONT_W, y, text[i], colour);
    }
}

/* ============================================================================
 * Login Window Rendering
 * ============================================================================ */

static void render_login_window(void)
{
    uint32_t W = g_pixels_w;
    uint32_t H = g_pixels_h;
    uint32_t stride = g_pixels_stride;

    /* Clear to window background (light grey) */
    px_fill_rect(g_pixels, stride, 0, 0, W, H, px_rgba(0xF0, 0xF0, 0xF0, 0xFF));

    /* Border */
    px_fill_rect(g_pixels, stride, 0, 0, W, 1, px_rgba(0xC0, 0xC0, 0xC0, 0xFF));
    px_fill_rect(g_pixels, stride, 0, H-1, W, 1, px_rgba(0xC0, 0xC0, 0xC0, 0xFF));
    px_fill_rect(g_pixels, stride, 0, 0, 1, H, px_rgba(0xC0, 0xC0, 0xC0, 0xFF));
    px_fill_rect(g_pixels, stride, W-1, 0, 1, H, px_rgba(0xC0, 0xC0, 0xC0, 0xFF));

    uint32_t col_dark = px_rgba(0x30, 0x30, 0x30, 0xFF);
    uint32_t col_grey = px_rgba(0x80, 0x80, 0x80, 0xFF);
    uint32_t col_white = px_rgba(0xFF, 0xFF, 0xFF, 0xFF);
    uint32_t col_blue = px_rgba(0x00, 0x7A, 0xFF, 0xFF);
    uint32_t col_red = px_rgba(0xCC, 0x00, 0x00, 0xFF);
    uint32_t col_field_bg = px_rgba(0xFF, 0xFF, 0xFF, 0xFF);
    uint32_t col_field_border = px_rgba(0xB0, 0xB0, 0xB0, 0xFF);

    /* Title: "Kiseki OS" */
    px_draw_text(g_pixels, stride, (W - 9 * FONT_W) / 2, 20, "Kiseki OS", col_dark);

    /* Subtitle */
    px_draw_text(g_pixels, stride, (W - 22 * FONT_W) / 2, 42, "Enter your credentials", col_grey);

    /* Username label */
    px_draw_text(g_pixels, stride, FIELD_X, 72, "Username:", col_dark);

    /* Username field background */
    px_fill_rect(g_pixels, stride, FIELD_X, 90, FIELD_W, FIELD_H, col_field_bg);
    /* Field border */
    px_fill_rect(g_pixels, stride, FIELD_X, 90, FIELD_W, 1, col_field_border);
    px_fill_rect(g_pixels, stride, FIELD_X, 90+FIELD_H-1, FIELD_W, 1, col_field_border);
    px_fill_rect(g_pixels, stride, FIELD_X, 90, 1, FIELD_H, col_field_border);
    px_fill_rect(g_pixels, stride, FIELD_X+FIELD_W-1, 90, 1, FIELD_H, col_field_border);
    /* Active field highlight */
    if (login_field == 0) {
        px_fill_rect(g_pixels, stride, FIELD_X, 90+FIELD_H-2, FIELD_W, 2, col_blue);
    }
    /* Username text */
    if (login_username_len > 0) {
        px_draw_text(g_pixels, stride, FIELD_X + 4, 94, login_username, col_dark);
    }
    /* Cursor */
    if (login_field == 0) {
        int cx = FIELD_X + 4 + login_username_len * FONT_W;
        px_fill_rect(g_pixels, stride, cx, 93, 2, FIELD_H - 6, col_dark);
    }

    /* Password label */
    px_draw_text(g_pixels, stride, FIELD_X, 126, "Password:", col_dark);

    /* Password field background */
    px_fill_rect(g_pixels, stride, FIELD_X, 144, FIELD_W, FIELD_H, col_field_bg);
    px_fill_rect(g_pixels, stride, FIELD_X, 144, FIELD_W, 1, col_field_border);
    px_fill_rect(g_pixels, stride, FIELD_X, 144+FIELD_H-1, FIELD_W, 1, col_field_border);
    px_fill_rect(g_pixels, stride, FIELD_X, 144, 1, FIELD_H, col_field_border);
    px_fill_rect(g_pixels, stride, FIELD_X+FIELD_W-1, 144, 1, FIELD_H, col_field_border);
    if (login_field == 1) {
        px_fill_rect(g_pixels, stride, FIELD_X, 144+FIELD_H-2, FIELD_W, 2, col_blue);
    }
    /* Password bullets */
    for (int i = 0; i < login_password_len; i++) {
        /* Draw bullet (filled circle approximated as a 6x6 filled square) */
        int bx = FIELD_X + 4 + i * FONT_W + 1;
        px_fill_rect(g_pixels, stride, bx, 150, 5, 5, col_dark);
    }
    if (login_field == 1) {
        int cx = FIELD_X + 4 + login_password_len * FONT_W;
        px_fill_rect(g_pixels, stride, cx, 147, 2, FIELD_H - 6, col_dark);
    }

    /* Error message (if any) */
    if (login_error[0]) {
        int elen = (int)strlen(login_error);
        px_draw_text(g_pixels, stride, (W - elen * FONT_W) / 2, 178, login_error, col_red);
    }

    /* Login button */
    int btn_x = (W - BUTTON_W) / 2;
    int btn_y = 200;
    px_fill_rect(g_pixels, stride, btn_x, btn_y, BUTTON_W, BUTTON_H, col_blue);
    /* Button text "Log In" */
    px_draw_text(g_pixels, stride, btn_x + (BUTTON_W - 6 * FONT_W) / 2,
                 btn_y + (BUTTON_H - 14) / 2, "Log In", col_white);
}

/* ============================================================================
 * Authentication — /etc/passwd + /etc/shadow
 *
 * Reuses the same approach as login.c:
 *   1. Look up username in /etc/passwd
 *   2. Look up password hash in /etc/shadow
 *   3. Verify: empty hash = no password, "plain:X" = plaintext, else strcmp
 * ============================================================================ */

typedef struct {
    char name[32];
    int  uid;
    int  gid;
    char home[64];
    char shell[32];
} passwd_entry_t;

/* Authenticated user details — populated by attempt_login(), consumed by launch_app() */
static passwd_entry_t g_auth_user;

static int lookup_passwd(const char *username, passwd_entry_t *pw)
{
    FILE *fp = fopen("/etc/passwd", "r");
    if (!fp) return -1;

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\n') continue;

        /* Parse: name:x:uid:gid:gecos:home:shell */
        char *fields[7] = {0};
        int nfields = 0;
        char *p = line;
        for (int i = 0; i < 7 && *p; i++) {
            fields[i] = p;
            nfields++;
            char *colon = strchr(p, ':');
            if (colon) {
                *colon = '\0';
                p = colon + 1;
            } else {
                /* Strip trailing newline */
                char *nl = strchr(p, '\n');
                if (nl) *nl = '\0';
                break;
            }
        }
        if (nfields < 7) continue;

        if (strcmp(fields[0], username) == 0) {
            strncpy(pw->name, fields[0], 31);
            pw->uid = atoi(fields[2]);
            pw->gid = atoi(fields[3]);
            strncpy(pw->home, fields[5], 63);
            strncpy(pw->shell, fields[6], 31);
            fclose(fp);
            return 0;
        }
    }
    fclose(fp);
    return -1;
}

static int lookup_shadow(const char *username, char *hash, size_t hashlen)
{
    FILE *fp = fopen("/etc/shadow", "r");
    if (!fp) {
        /* No shadow file — treat as no password required */
        hash[0] = '\0';
        return 0;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;

        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon = '\0';

        if (strcmp(line, username) == 0) {
            char *hashstart = colon + 1;
            char *hashend = strchr(hashstart, ':');
            if (hashend) *hashend = '\0';
            char *nl = strchr(hashstart, '\n');
            if (nl) *nl = '\0';
            strncpy(hash, hashstart, hashlen - 1);
            hash[hashlen - 1] = '\0';
            fclose(fp);
            return 0;
        }
    }
    fclose(fp);
    /* User not in shadow — no password */
    hash[0] = '\0';
    return 0;
}

static int verify_password(const char *stored, const char *entered)
{
    /* Empty stored hash: no password required */
    if (stored[0] == '\0') return 1;

    /* Locked account */
    if (strcmp(stored, "!") == 0 || strcmp(stored, "*") == 0) return 0;

    /* Plaintext: "plain:password" */
    if (strncmp(stored, "plain:", 6) == 0) {
        return strcmp(stored + 6, entered) == 0;
    }

    /* Direct comparison fallback */
    return strcmp(stored, entered) == 0;
}

static int attempt_login(void)
{
    passwd_entry_t pw;
    memset(&pw, 0, sizeof(pw));

    if (lookup_passwd(login_username, &pw) < 0) {
        snprintf(login_error, sizeof(login_error), "Unknown user: %s", login_username);
        return -1;
    }

    char stored_hash[128];
    lookup_shadow(login_username, stored_hash, sizeof(stored_hash));

    if (!verify_password(stored_hash, login_password)) {
        snprintf(login_error, sizeof(login_error), "Incorrect password");
        return -1;
    }

    login_error[0] = '\0';

    /* Stash authenticated user details for session launch */
    memcpy(&g_auth_user, &pw, sizeof(passwd_entry_t));

    fprintf(stderr, "[loginwindow] Authentication successful for user '%s' (uid=%d gid=%d home=%s shell=%s)\n",
            pw.name, pw.uid, pw.gid, pw.home, pw.shell);
    return 0;
}

/* ============================================================================
 * GUI Session Launch — Fork+exec Dock, Finder, SystemUIServer, Terminal
 *
 * On macOS, loginwindow launches these core processes after authentication:
 *   /System/Library/CoreServices/Dock.app
 *   /System/Library/CoreServices/Finder.app
 *   /System/Library/CoreServices/SystemUIServer.app
 *
 * We also launch Terminal.app as a convenience (macOS doesn't do this
 * by default — it's a Login Item).
 * ============================================================================ */

static pid_t launch_app(const char *path, const char *name)
{
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "[loginwindow] fork() for %s failed: %s\n", name, strerror(errno));
        return -1;
    }
    if (pid == 0) {
        /* Child process — run as the authenticated user */

        /*
         * Build environment from g_auth_user.
         * On macOS, loginwindow sets HOME, USER, LOGNAME, SHELL, PATH, TERM,
         * DISPLAY, and various Apple-internal variables.  We set the essentials.
         */
        char env_home[80];
        char env_user[48];
        char env_logname[48];
        char env_shell[48];
        snprintf(env_home,    sizeof(env_home),    "HOME=%s",  g_auth_user.home);
        snprintf(env_user,    sizeof(env_user),    "USER=%s",  g_auth_user.name);
        snprintf(env_logname, sizeof(env_logname), "LOGNAME=%s", g_auth_user.name);
        snprintf(env_shell,   sizeof(env_shell),   "SHELL=%s", g_auth_user.shell);

        char *argv[] = { (char *)path, NULL };
        char *envp[] = {
            env_home,
            "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/Applications",
            "TERM=vt100",
            env_shell,
            env_user,
            env_logname,
            NULL
        };

        /*
         * Drop privileges to the authenticated user.
         * setgid() before setuid() — standard Unix practice: once you drop
         * uid=0 you cannot change gid any more.
         */
        if (g_auth_user.gid != 0) setgid(g_auth_user.gid);
        if (g_auth_user.uid != 0) setuid(g_auth_user.uid);

        execve(path, argv, envp);
        fprintf(stderr, "[loginwindow] execve(%s) failed: %s\n", path, strerror(errno));
        _exit(127);
    }

    fprintf(stderr, "[loginwindow] Launched %s (PID %d)\n", name, pid);
    return pid;
}

static void launch_gui_session(void)
{
    fprintf(stderr, "[loginwindow] Starting GUI session...\n");

    /*
     * Launch order matches macOS loginwindow:
     *   1. Dock (desktop wallpaper + dock bar)
     *   2. Finder (file manager + desktop icons)
     *   3. SystemUIServer (menu bar extras: clock, etc.)
     *   4. Terminal (convenience — not standard macOS behaviour)
     */
    g_dock_pid = launch_app("/Applications/Dock.app/Dock", "Dock.app");
    g_finder_pid = launch_app("/Applications/Finder.app/Finder", "Finder.app");
    g_sysui_pid = launch_app("/Applications/SystemUIServer.app/SystemUIServer", "SystemUIServer.app");
    g_terminal_pid = launch_app("/Applications/Terminal.app/Terminal", "Terminal.app");

    /*
     * Hide the login window.
     *
     * On real macOS, loginwindow orders its window out and keeps it
     * alive (ready to re-show for screen lock / fast-user-switch).
     * We do the same: send WS_ORDER_OUT so WindowServer stops
     * compositing it and repaints the desktop background, then set
     * login_active = 0 so our event loop enters the child-monitoring
     * path instead of the UI-event path.
     */
    ws_order_window(g_win_id, WS_ORDER_OUT);
    login_active = 0;
}

/* ============================================================================
 * Child Process Monitoring
 *
 * On macOS, loginwindow monitors Dock/Finder/SystemUIServer and relaunches
 * them if they crash.  This is critical — if Finder crashes, the desktop
 * becomes unusable without a relaunch.
 * ============================================================================ */

static void reap_children(void)
{
    int status;
    pid_t pid;

    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        const char *name = "unknown";
        pid_t *pidp = NULL;
        const char *path = NULL;

        if (pid == g_dock_pid) {
            name = "Dock.app"; pidp = &g_dock_pid;
            path = "/Applications/Dock.app/Dock";
        } else if (pid == g_finder_pid) {
            name = "Finder.app"; pidp = &g_finder_pid;
            path = "/Applications/Finder.app/Finder";
        } else if (pid == g_sysui_pid) {
            name = "SystemUIServer.app"; pidp = &g_sysui_pid;
            path = "/Applications/SystemUIServer.app/SystemUIServer";
        } else if (pid == g_terminal_pid) {
            name = "Terminal.app"; pidp = &g_terminal_pid;
            /* Don't relaunch Terminal — user may have intentionally closed it */
            fprintf(stderr, "[loginwindow] %s (PID %d) exited\n", name, pid);
            g_terminal_pid = -1;
            continue;
        }

        fprintf(stderr, "[loginwindow] %s (PID %d) exited, relaunching...\n",
                name, pid);

        if (pidp && path) {
            *pidp = launch_app(path, name);
        }
    }
}

/* ============================================================================
 * Event Loop — Poll WindowServer events for the login window
 * ============================================================================ */

static int poll_event(ws_msg_buffer_t *buf, mach_msg_timeout_t timeout_ms)
{
    memset(buf, 0, sizeof(*buf));
    kern_return_t kr = mach_msg(&buf->header,
                                MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                                0,
                                sizeof(*buf),
                                g_event_port,
                                timeout_ms,
                                MACH_PORT_NULL);
    return (kr == KERN_SUCCESS) ? 1 : 0;
}

static void handle_key_event(ws_event_key_t *ev)
{
    if (!login_active) return;

    uint32_t keycode = ev->keycode;
    uint32_t ch = ev->characters;

    if (keycode == KEY_TAB) {
        /* Toggle between username and password fields */
        login_field = 1 - login_field;
    } else if (keycode == KEY_ENTER) {
        /* Attempt login */
        if (attempt_login() == 0) {
            launch_gui_session();
            return;
        }
    } else if (keycode == KEY_BACKSPACE) {
        /* Delete last character */
        if (login_field == 0 && login_username_len > 0) {
            login_username[--login_username_len] = '\0';
        } else if (login_field == 1 && login_password_len > 0) {
            login_password[--login_password_len] = '\0';
        }
        login_error[0] = '\0';
    } else if (ch >= 0x20 && ch < 0x7F) {
        /* Printable character */
        if (login_field == 0 && login_username_len < FIELD_MAX - 1) {
            login_username[login_username_len++] = (char)ch;
            login_username[login_username_len] = '\0';
        } else if (login_field == 1 && login_password_len < FIELD_MAX - 1) {
            login_password[login_password_len++] = (char)ch;
            login_password[login_password_len] = '\0';
        }
        login_error[0] = '\0';
    }
}

static void handle_mouse_event(ws_event_mouse_t *ev)
{
    if (!login_active) return;

    int mx = ev->x;
    int my = ev->y;

    /* Check login button click */
    int btn_x = (LOGIN_WIN_W - BUTTON_W) / 2;
    int btn_y = 200;
    if (mx >= btn_x && mx < btn_x + BUTTON_W &&
        my >= btn_y && my < btn_y + BUTTON_H) {
        if (attempt_login() == 0) {
            launch_gui_session();
            return;
        }
    }

    /* Check username field click */
    if (mx >= FIELD_X && mx < FIELD_X + FIELD_W &&
        my >= 90 && my < 90 + FIELD_H) {
        login_field = 0;
    }

    /* Check password field click */
    if (mx >= FIELD_X && mx < FIELD_X + FIELD_W &&
        my >= 144 && my < 144 + FIELD_H) {
        login_field = 1;
    }
}

/* ============================================================================
 * main — loginwindow entry point
 *
 * Lifecycle (matching macOS loginwindow):
 *   1. Connect to WindowServer
 *   2. Create borderless login window
 *   3. Render login UI and flush to WindowServer
 *   4. Event loop: process keyboard/mouse, authenticate
 *   5. On successful login: hide login window, launch GUI session
 *   6. Monitor children, relaunch on crash
 *   7. (Future: handle logout → re-show login window)
 * ============================================================================ */

int main(int argc, char *argv[])
{
    (void)argc; (void)argv;

    fprintf(stderr, "[loginwindow] Starting (PID %d)\n", getpid());

    /* Allocate pixel buffer */
    g_pixels = calloc(g_pixels_w * g_pixels_h, 4);
    if (!g_pixels) {
        fprintf(stderr, "[loginwindow] Failed to allocate pixel buffer\n");
        return 1;
    }

    /* Initialise login state */
    memset(login_username, 0, sizeof(login_username));
    memset(login_password, 0, sizeof(login_password));
    memset(login_error, 0, sizeof(login_error));

    /* Connect to WindowServer */
    if (ws_connect() < 0) {
        fprintf(stderr, "[loginwindow] Cannot connect to WindowServer, retrying...\n");
        /* Retry loop — WindowServer may not be ready yet */
        for (int retry = 0; retry < 50; retry++) {
            usleep(100000);  /* 100ms */
            if (ws_connect() == 0) break;
        }
        if (g_conn_id < 0) {
            fprintf(stderr, "[loginwindow] Failed to connect to WindowServer\n");
            return 1;
        }
    }

    /* Create the login window (borderless, centred on screen) */
    g_win_id = ws_create_window(LOGIN_WIN_X, LOGIN_WIN_Y,
                                 LOGIN_WIN_W, LOGIN_WIN_H,
                                 0,  /* NSWindowStyleMaskBorderless */
                                 "loginwindow");
    if (g_win_id < 0) {
        fprintf(stderr, "[loginwindow] Failed to create window\n");
        return 1;
    }

    /* Render initial login screen */
    render_login_window();
    ws_draw_rect(g_win_id, 0, 0, g_pixels_w, g_pixels_h,
                 g_pixels, g_pixels_stride);
    ws_order_window(g_win_id, WS_ORDER_FRONT);

    fprintf(stderr, "[loginwindow] Login window created at (%d, %d) %dx%d\n",
            LOGIN_WIN_X, LOGIN_WIN_Y, LOGIN_WIN_W, LOGIN_WIN_H);

    /* Main event loop */
    ws_msg_buffer_t buf;
    int dirty = 0;  /* Only re-render when content actually changed */
    for (;;) {
        if (login_active) {
            /* Login mode: poll for events with short timeout */
            if (poll_event(&buf, 100)) {
                mach_msg_id_t mid = buf.header.msgh_id;

                if (mid == WS_EVENT_KEY_DOWN) {
                    handle_key_event((ws_event_key_t *)&buf);
                    dirty = 1;
                } else if (mid == WS_EVENT_MOUSE_DOWN) {
                    handle_mouse_event((ws_event_mouse_t *)&buf);
                    dirty = 1;
                }

                /* Re-render and flush only if content changed */
                if (login_active && dirty) {
                    render_login_window();
                    ws_draw_rect(g_win_id, 0, 0, g_pixels_w, g_pixels_h,
                                 g_pixels, g_pixels_stride);
                    dirty = 0;
                }
            }
        } else {
            /* Session active: monitor children, process events slowly */
            reap_children();

            /* Sleep briefly to avoid burning CPU */
            if (poll_event(&buf, 1000)) {
                /* Process any events we receive (e.g., window close) */
            }
        }
    }

    /* Not reached */
    free(g_pixels);
    return 0;
}
