/*
 * Kiseki OS - WindowServer
 *
 * The WindowServer daemon owns the display framebuffer, composites all
 * on-screen windows, processes HID events (keyboard + mouse), and manages
 * the login flow and terminal emulation.  It is the equivalent of macOS's
 * WindowServer (Quartz Compositor) combined with loginwindow.app.
 *
 * Architecture (matching macOS):
 *   1. Claims the WindowServer service port via bootstrap_check_in()
 *   2. Opens IOFramebuffer via IOKit, maps VRAM
 *   3. Opens IOHIDSystem via IOKit, maps HID event ring
 *   4. Draws desktop, menu bar, login window
 *   5. Runs a 60 Hz event loop: poll HID ring -> process events ->
 *      read PTY masters -> redraw dirty regions -> flush
 *
 * On macOS, WindowServer is launched by launchd from
 * /System/Library/LaunchDaemons/com.apple.WindowServer.plist.
 * Here, launchd (init) launches it from
 * /System/Library/LaunchDaemons/uk.co.avltree9798.WindowServer.plist.
 *
 * Boot chain: kernel -> launchd (init) -> WindowServer
 *
 * Reference: macOS WindowServer (private), Quartz Compositor,
 *            IOHIDSystem, loginwindow.app, Terminal.app
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <IOKit/IOKitLib.h>

/* openpty() — declared in <util.h> on macOS, provided by libSystem */
int openpty(int *, int *, char *, void *, void *);

/* ============================================================================
 * Constants
 * ============================================================================ */

/* WindowServer Mach service name */
#define WS_SERVICE_NAME         "uk.co.avltree9798.WindowServer"

/* Display dimensions (VirtIO GPU default) */
#define WS_MAX_WIDTH            1280
#define WS_MAX_HEIGHT           800

/* NSWindowStyleMask values (matching AppKit) */
#define NSWindowStyleMaskBorderless         0
#define NSWindowStyleMaskTitled             (1 << 0)
#define NSWindowStyleMaskClosable           (1 << 1)
#define NSWindowStyleMaskMiniaturizable     (1 << 2)
#define NSWindowStyleMaskResizable          (1 << 3)

/* Font dimensions */
#define FONT_WIDTH              8
#define FONT_HEIGHT             16

/* Menu bar height (matches macOS) */
#define MENUBAR_HEIGHT          22

/* Window title bar height (matches macOS) */
#define TITLEBAR_HEIGHT         22

/* Window border/shadow width */
#define WINDOW_BORDER           1

/* Maximum number of windows */
#define WS_MAX_WINDOWS          16

/* Terminal dimensions (characters) */
#define TERM_COLS               80
#define TERM_ROWS               24

/* Terminal pixel dimensions (content area) */
#define TERM_WIDTH              (TERM_COLS * FONT_WIDTH)     /* 640 */
#define TERM_HEIGHT             (TERM_ROWS * FONT_HEIGHT)    /* 384 */

/* Window dimensions including chrome */
#define TERM_WIN_WIDTH          (TERM_WIDTH + 2 * WINDOW_BORDER)
#define TERM_WIN_HEIGHT         (TERM_HEIGHT + TITLEBAR_HEIGHT + 2 * WINDOW_BORDER)

/* Login window dimensions */
/* Login UI has been moved to /sbin/loginwindow (separate process) */

/* Mouse cursor dimensions */
#define CURSOR_WIDTH            12
#define CURSOR_HEIGHT           18

/* VirtIO tablet absolute coordinate range */
#define TABLET_ABS_MAX          32767

/* VT100 parser states (matching XNU gc_putchar) */
#define VT_NORMAL               0
#define VT_ESC                  1
#define VT_CSI_INIT             2
#define VT_CSI_PARS             3
#define VT_DEC_PRIV             4

/* ============================================================================
 * WindowServer IPC Protocol
 *
 * Modelled on macOS Quartz/SkyLight CGSConnection + CGSWindow.
 * Clients (AppKit NSApplication) connect via the service port and
 * receive a connection ID + event reply port for bidirectional IPC.
 *
 * Protocol flow (matching macOS CGSConnection lifecycle):
 *   1. Client sends WS_MSG_CONNECT → gets conn_id + event port
 *   2. Client sends WS_MSG_CREATE_WINDOW → gets window_id
 *   3. Client sends WS_MSG_DRAW_RECT with OOL pixel data → WS blits
 *   4. Client sends WS_MSG_SET_TITLE, WS_MSG_ORDER_WINDOW, etc.
 *   5. WindowServer sends WS_EVENT_* to client's event port
 *   6. Client sends WS_MSG_SET_MENU → WS updates menu bar
 *   7. Client sends WS_MSG_DISCONNECT → cleanup
 *
 * Message IDs use Mach msgh_id field (matching CGS private MIG IDs):
 *   Request:  1000-1999 (client → WindowServer)
 *   Reply:    2000-2999 (WindowServer → client, in response)
 *   Event:    3000-3999 (WindowServer → client, async)
 * ============================================================================ */

/* --- Request message IDs (client → WindowServer) --- */
#define WS_MSG_CONNECT              1000    /* Connect to WindowServer */
#define WS_MSG_DISCONNECT           1001    /* Disconnect */
#define WS_MSG_CREATE_WINDOW        1010    /* Create a new window */
#define WS_MSG_DESTROY_WINDOW       1011    /* Destroy a window */
#define WS_MSG_ORDER_WINDOW         1012    /* Order (show/hide/front) */
#define WS_MSG_SET_TITLE            1013    /* Set window title */
#define WS_MSG_SET_FRAME            1014    /* Move/resize window */
#define WS_MSG_DRAW_RECT            1020    /* Blit pixel data into window */
#define WS_MSG_SET_MENU             1030    /* Set app menu items */
#define WS_MSG_CREATE_PTY_WINDOW    1040    /* Create terminal window with PTY */

/* --- Reply message IDs (WindowServer → client, synchronous) --- */
#define WS_REPLY_CONNECT            2000
#define WS_REPLY_CREATE_WINDOW      2010
#define WS_REPLY_GENERIC            2099    /* Generic OK/error reply */
#define WS_REPLY_CREATE_PTY_WINDOW  2040

/* --- Event message IDs (WindowServer → client, asynchronous) --- */
#define WS_EVENT_KEY_DOWN           3000
#define WS_EVENT_KEY_UP             3001
#define WS_EVENT_MOUSE_DOWN         3010
#define WS_EVENT_MOUSE_UP           3011
#define WS_EVENT_MOUSE_MOVED        3012
#define WS_EVENT_MOUSE_DRAGGED      3013
#define WS_EVENT_WINDOW_ACTIVATE    3020
#define WS_EVENT_WINDOW_DEACTIVATE  3021
#define WS_EVENT_WINDOW_CLOSE       3022
#define WS_EVENT_WINDOW_RESIZE      3023

/* --- Window ordering constants (matching NSWindowOrderingMode) --- */
#define WS_ORDER_OUT                0       /* Hide */
#define WS_ORDER_FRONT              1       /* Bring to front */
#define WS_ORDER_BACK               2       /* Send to back */

/* --- Maximum IPC buffer size --- */
#define WS_MSG_MAX_SIZE             4096    /* Max inline message */
#define WS_MAX_MENU_ITEMS           16
#define WS_MENU_TITLE_MAX           32

/* --- Maximum client connections --- */
#define WS_MAX_CONNECTIONS          16

/* --- IPC Message Structures --- */

/*
 * WS_MSG_CONNECT request:
 *   Client sends its reply port in msgh_local_port.
 *   WindowServer allocates a connection and returns conn_id.
 */
typedef struct {
    mach_msg_header_t   header;
    char                app_name[64];   /* Application name for menu bar */
    int32_t             pid;            /* Client PID */
} ws_msg_connect_t;

typedef struct {
    mach_msg_header_t   header;
    int32_t             conn_id;        /* Assigned connection ID, or -1 on error */
    kern_return_t       result;
} ws_reply_connect_t;

/*
 * WS_MSG_CREATE_WINDOW request:
 *   Creates a new client-managed window (no built-in terminal).
 */
typedef struct {
    mach_msg_header_t   header;
    int32_t             conn_id;
    int32_t             x, y;
    uint32_t            width, height;  /* Content area size (excl. chrome) */
    uint32_t            style_mask;     /* Window style flags */
    char                title[64];
} ws_msg_create_window_t;

typedef struct {
    mach_msg_header_t   header;
    int32_t             window_id;      /* Assigned window ID, or -1 on error */
    kern_return_t       result;
} ws_reply_create_window_t;

/*
 * WS_MSG_DESTROY_WINDOW request
 */
typedef struct {
    mach_msg_header_t   header;
    int32_t             conn_id;
    int32_t             window_id;
} ws_msg_destroy_window_t;

/*
 * WS_MSG_ORDER_WINDOW request
 */
typedef struct {
    mach_msg_header_t   header;
    int32_t             conn_id;
    int32_t             window_id;
    int32_t             order;          /* WS_ORDER_OUT, WS_ORDER_FRONT, etc. */
} ws_msg_order_window_t;

/*
 * WS_MSG_SET_TITLE request
 */
typedef struct {
    mach_msg_header_t   header;
    int32_t             conn_id;
    int32_t             window_id;
    char                title[64];
} ws_msg_set_title_t;

/*
 * WS_MSG_SET_FRAME request
 */
typedef struct {
    mach_msg_header_t   header;
    int32_t             conn_id;
    int32_t             window_id;
    int32_t             x, y;
    uint32_t            width, height;
} ws_msg_set_frame_t;

/*
 * WS_MSG_DRAW_RECT request:
 *   Blit pixel data into a window's content area.
 *   Uses Mach OOL descriptor to transfer the pixel buffer.
 *   Pixel format: BGRA 32bpp (matching framebuffer).
 */
typedef struct {
    mach_msg_header_t       header;
    mach_msg_body_t         body;
    mach_msg_ool_descriptor_t surface_desc;
    int32_t                 conn_id;
    int32_t                 window_id;
    uint32_t                dst_x, dst_y;     /* Offset within content area */
    uint32_t                width, height;    /* Size of rect being drawn */
    uint32_t                src_rowbytes;     /* Bytes per row in OOL data */
} ws_msg_draw_rect_t;

/*
 * WS_MSG_SET_MENU request:
 *   Sets the application's menu bar items.
 *   When this app is foreground, WindowServer displays these items.
 */
typedef struct {
    mach_msg_header_t   header;
    int32_t             conn_id;
    uint32_t            item_count;
    struct {
        char            title[WS_MENU_TITLE_MAX];
        int32_t         tag;            /* Identifier for menu callbacks */
        int32_t         enabled;
    } items[WS_MAX_MENU_ITEMS];
} ws_msg_set_menu_t;

/*
 * WS_MSG_CREATE_PTY_WINDOW request:
 *   Creates a window with a built-in PTY + shell (terminal window).
 *   WindowServer manages the terminal emulator internally.
 *   Returns master PTY fd (nope — can't pass fds via Mach IPC easily).
 *   Instead, returns window_id. The shell runs inside WindowServer.
 */
typedef struct {
    mach_msg_header_t   header;
    int32_t             conn_id;
    int32_t             x, y;
    char                title[64];
} ws_msg_create_pty_window_t;

typedef struct {
    mach_msg_header_t   header;
    int32_t             window_id;
    kern_return_t       result;
} ws_reply_create_pty_window_t;

/*
 * Generic reply (for SET_TITLE, SET_FRAME, ORDER_WINDOW, etc.)
 */
typedef struct {
    mach_msg_header_t   header;
    kern_return_t       result;
} ws_reply_generic_t;

/*
 * Event messages (WindowServer → client)
 */
typedef struct {
    mach_msg_header_t   header;
    int32_t             window_id;
    uint32_t            keycode;
    uint32_t            characters;     /* ASCII character, or 0 */
    uint32_t            modifiers;      /* Modifier flags */
    uint16_t            is_repeat;
    uint16_t            _pad;
} ws_event_key_t;

typedef struct {
    mach_msg_header_t   header;
    int32_t             window_id;
    int32_t             x, y;           /* Window-relative coordinates */
    int32_t             screen_x, screen_y; /* Screen coordinates */
    uint32_t            button;         /* Button number (0=left, 1=right, 2=middle) */
    uint32_t            modifiers;
    uint32_t            click_count;
} ws_event_mouse_t;

typedef struct {
    mach_msg_header_t   header;
    int32_t             window_id;
} ws_event_window_t;

typedef struct {
    mach_msg_header_t   header;
    int32_t             window_id;
    uint32_t            new_width;
    uint32_t            new_height;
} ws_event_resize_t;

/* --- Receive buffer: large enough for biggest msg + OOL --- */
typedef union {
    mach_msg_header_t   header;
    uint8_t             _pad[WS_MSG_MAX_SIZE + 256];
} ws_msg_buffer_t;

/* ============================================================================
 * Client Connection State (CGSConnection equivalent)
 *
 * Each connected client (AppKit NSApplication) gets a connection slot.
 * The event_port is used to send asynchronous events to the client.
 * ============================================================================ */

struct ws_connection {
    int             active;
    int32_t         conn_id;
    mach_port_t     event_port;         /* Send right to client's event port */
    int32_t         pid;
    char            app_name[64];
    int32_t         window_ids[WS_MAX_WINDOWS]; /* Windows owned by this conn */
    int             window_count;

    /* Menu bar items for this application */
    struct {
        char        title[WS_MENU_TITLE_MAX];
        int32_t     tag;
        int32_t     enabled;
    } menu_items[WS_MAX_MENU_ITEMS];
    int             menu_item_count;
};

static struct ws_connection ws_connections[WS_MAX_CONNECTIONS];
static int                  ws_connection_count = 0;

/* Which connection is the foreground app (owns the menu bar) */
static int                  ws_foreground_conn = -1;

/* Forward declarations for IPC event delivery (defined before main) */
static void ws_cleanup_dead_connection(int conn_id);
static void ws_send_key_event_to_client(int window_idx, uint32_t msg_id,
                                         uint32_t keycode, uint32_t character,
                                         uint32_t modifiers);
static void ws_send_mouse_event_to_client(int window_idx, uint32_t msg_id,
                                            int32_t sx, int32_t sy,
                                            uint32_t button, uint32_t modifiers);

/* Maximum CSI parameters (matching XNU MAXPARS) */
#define VT_MAXPARS              16

/* SGR attribute flags */
#define ATTR_NONE               0x00
#define ATTR_BOLD               0x01
#define ATTR_UNDERLINE          0x02
#define ATTR_REVERSE            0x04

/* Default ANSI colour indices */
#define DEFAULT_FG_IDX          7       /* White/light grey */
#define DEFAULT_BG_IDX          0       /* Black */

/* ============================================================================
 * Colour Constants (BGRA pixel format)
 *
 * VirtIO GPU uses VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM:
 *   bits [7:0]   = Blue
 *   bits [15:8]  = Green
 *   bits [23:16] = Red
 *   bits [31:24] = Alpha (0xFF)
 * ============================================================================ */

static inline uint32_t ws_rgb(uint8_t r, uint8_t g, uint8_t b)
{
    return (uint32_t)b | ((uint32_t)g << 8) |
           ((uint32_t)r << 16) | (0xFFu << 24);
}

/* Desktop background: Solid Aqua Blue (#3A6EA5) */
#define COL_DESKTOP             ws_rgb(0x3A, 0x6E, 0xA5)

/* Menu bar */
#define COL_MENUBAR             ws_rgb(0xEA, 0xEA, 0xEA)
#define COL_MENUBAR_SEP         ws_rgb(0xB4, 0xB4, 0xB4)
#define COL_MENUBAR_TEXT        ws_rgb(0x00, 0x00, 0x00)

/* Window chrome */
#define COL_TITLEBAR            ws_rgb(0xE8, 0xE8, 0xE8)
#define COL_TITLEBAR_TEXT       ws_rgb(0x4A, 0x4A, 0x4A)
#define COL_WIN_BORDER          ws_rgb(0xAA, 0xAA, 0xAA)

/* Traffic light buttons */
#define COL_BTN_CLOSE           ws_rgb(0xFF, 0x5F, 0x57)
#define COL_BTN_MINIMISE        ws_rgb(0xFF, 0xBD, 0x2E)
#define COL_BTN_ZOOM            ws_rgb(0x28, 0xCA, 0x41)

/* Terminal */
#define COL_TERM_BG             ws_rgb(0x1E, 0x1E, 0x1E)
#define COL_TERM_FG             ws_rgb(0xC0, 0xC0, 0xC0)

/* Login window */
/* COL_LOGIN_* colours removed — login UI now in /sbin/loginwindow */

/* Cursor */
#define COL_CURSOR_BLACK        ws_rgb(0x00, 0x00, 0x00)
#define COL_CURSOR_WHITE        ws_rgb(0xFF, 0xFF, 0xFF)

/* ============================================================================
 * HID Event Ring Structures
 *
 * These MUST match the kernel's struct hid_event / struct hid_event_ring
 * exactly. Redefined locally because WindowServer.c is a userland binary
 * compiled against the macOS SDK, not kernel headers.
 * ============================================================================ */

#define HID_EVENT_RING_SIZE     256

#define HID_EVENT_KEY_DOWN      1
#define HID_EVENT_KEY_UP        2
#define HID_EVENT_MOUSE_MOVE    3
#define HID_EVENT_MOUSE_DOWN    4
#define HID_EVENT_MOUSE_UP      5

#define HID_FLAG_SHIFT          (1 << 0)
#define HID_FLAG_CTRL           (1 << 1)
#define HID_FLAG_ALT            (1 << 2)
#define HID_FLAG_CAPSLOCK       (1 << 3)

struct hid_event {
    uint32_t type;
    uint32_t keycode;
    uint32_t abs_x;
    uint32_t abs_y;
    uint32_t buttons;
    uint32_t flags;
    uint64_t timestamp;
};

struct hid_event_ring {
    volatile uint32_t write_idx;
    volatile uint32_t read_idx;
    uint32_t size;
    uint32_t _pad;
    struct hid_event events[HID_EVENT_RING_SIZE];
};

/* ============================================================================
 * Linux Keycodes (matching kernel/include/drivers/virtio_input.h)
 * ============================================================================ */

#define KEY_ESC             1
#define KEY_1               2
#define KEY_2               3
#define KEY_3               4
#define KEY_4               5
#define KEY_5               6
#define KEY_6               7
#define KEY_7               8
#define KEY_8               9
#define KEY_9               10
#define KEY_0               11
#define KEY_MINUS           12
#define KEY_EQUAL           13
#define KEY_BACKSPACE       14
#define KEY_TAB             15
#define KEY_Q               16
#define KEY_W               17
#define KEY_E               18
#define KEY_R               19
#define KEY_T               20
#define KEY_Y               21
#define KEY_U               22
#define KEY_I               23
#define KEY_O               24
#define KEY_P               25
#define KEY_LEFTBRACE       26
#define KEY_RIGHTBRACE      27
#define KEY_ENTER           28
#define KEY_LEFTCTRL        29
#define KEY_A               30
#define KEY_S               31
#define KEY_D               32
#define KEY_F               33
#define KEY_G               34
#define KEY_H               35
#define KEY_J               36
#define KEY_K               37
#define KEY_L               38
#define KEY_SEMICOLON       39
#define KEY_APOSTROPHE      40
#define KEY_GRAVE           41
#define KEY_LEFTSHIFT       42
#define KEY_BACKSLASH       43
#define KEY_Z               44
#define KEY_X               45
#define KEY_C               46
#define KEY_V               47
#define KEY_B               48
#define KEY_N               49
#define KEY_M               50
#define KEY_COMMA           51
#define KEY_DOT             52
#define KEY_SLASH           53
#define KEY_RIGHTSHIFT      54
#define KEY_KPASTERISK      55
#define KEY_LEFTALT         56
#define KEY_SPACE           57
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
#define KEY_NUMLOCK         69
#define KEY_SCROLLLOCK      70
#define KEY_KP7             71
#define KEY_KP8             72
#define KEY_KP9             73
#define KEY_KPMINUS         74
#define KEY_KP4             75
#define KEY_KP5             76
#define KEY_KP6             77
#define KEY_KPPLUS          78
#define KEY_KP1             79
#define KEY_KP2             80
#define KEY_KP3             81
#define KEY_KP0             82
#define KEY_KPDOT           83
#define KEY_F11             87
#define KEY_F12             88
#define KEY_KPENTER         96
#define KEY_RIGHTCTRL       97
#define KEY_KPSLASH         98
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
 * Embedded 8x16 VGA Bitmap Font (CP437)
 *
 * This is the canonical public-domain CP437 font from the IBM PC VGA BIOS.
 * Each of the 256 glyphs is 16 bytes — one byte per scanline, MSB = leftmost
 * pixel. Identical to kernel/kern/font8x16.c but embedded here because
 * WindowServer is a userland binary with no access to kernel symbols.
 *
 * Encoding: 8 pixels wide, 16 pixels tall, 1 bit/pixel, row-major.
 * Total size: 256 x 16 = 4096 bytes.
 * ============================================================================ */

static const uint8_t font8x16_data[256][16] = {
    /* 0x00 - NUL (blank) */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0x01 - SOH (smiley, outline) */
    { 0x00, 0x00, 0x7e, 0x81, 0xa5, 0x81, 0x81, 0xbd,
      0x99, 0x81, 0x81, 0x7e, 0x00, 0x00, 0x00, 0x00 },
    /* 0x02 - STX (smiley, filled) */
    { 0x00, 0x00, 0x7e, 0xff, 0xdb, 0xff, 0xff, 0xc3,
      0xe7, 0xff, 0xff, 0x7e, 0x00, 0x00, 0x00, 0x00 },
    /* 0x03 - ETX (heart) */
    { 0x00, 0x00, 0x00, 0x00, 0x6c, 0xfe, 0xfe, 0xfe,
      0xfe, 0x7c, 0x38, 0x10, 0x00, 0x00, 0x00, 0x00 },
    /* 0x04 - EOT (diamond) */
    { 0x00, 0x00, 0x00, 0x00, 0x10, 0x38, 0x7c, 0xfe,
      0x7c, 0x38, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0x05 - ENQ (club) */
    { 0x00, 0x00, 0x00, 0x18, 0x3c, 0x3c, 0xe7, 0xe7,
      0xe7, 0x18, 0x18, 0x3c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x06 - ACK (spade) */
    { 0x00, 0x00, 0x00, 0x18, 0x3c, 0x7e, 0xff, 0xff,
      0x7e, 0x18, 0x18, 0x3c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x07 - BEL (bullet) */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x3c,
      0x3c, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0x08 - BS (inverse bullet) */
    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe7, 0xc3,
      0xc3, 0xe7, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
    /* 0x09 - HT (circle, outline) */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x66, 0x42,
      0x42, 0x66, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0x0A - LF (inverse circle) */
    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xc3, 0x99, 0xbd,
      0xbd, 0x99, 0xc3, 0xff, 0xff, 0xff, 0xff, 0xff },
    /* 0x0B - VT (male sign) */
    { 0x00, 0x00, 0x1e, 0x0e, 0x1a, 0x32, 0x78, 0xcc,
      0xcc, 0xcc, 0xcc, 0x78, 0x00, 0x00, 0x00, 0x00 },
    /* 0x0C - FF (female sign) */
    { 0x00, 0x00, 0x3c, 0x66, 0x66, 0x66, 0x66, 0x3c,
      0x18, 0x7e, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00 },
    /* 0x0D - CR (note) */
    { 0x00, 0x00, 0x3f, 0x33, 0x3f, 0x30, 0x30, 0x30,
      0x30, 0x70, 0xf0, 0xe0, 0x00, 0x00, 0x00, 0x00 },
    /* 0x0E - SO (double note) */
    { 0x00, 0x00, 0x7f, 0x63, 0x7f, 0x63, 0x63, 0x63,
      0x63, 0x67, 0xe7, 0xe6, 0xc0, 0x00, 0x00, 0x00 },
    /* 0x0F - SI (sun) */
    { 0x00, 0x00, 0x00, 0x18, 0x18, 0xdb, 0x3c, 0xe7,
      0x3c, 0xdb, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00 },
    /* 0x10 - DLE (right-pointing triangle) */
    { 0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfe, 0xf8,
      0xf0, 0xe0, 0xc0, 0x80, 0x00, 0x00, 0x00, 0x00 },
    /* 0x11 - DC1 (left-pointing triangle) */
    { 0x00, 0x02, 0x06, 0x0e, 0x1e, 0x3e, 0xfe, 0x3e,
      0x1e, 0x0e, 0x06, 0x02, 0x00, 0x00, 0x00, 0x00 },
    /* 0x12 - DC2 (up-down arrow) */
    { 0x00, 0x00, 0x18, 0x3c, 0x7e, 0x18, 0x18, 0x18,
      0x7e, 0x3c, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0x13 - DC3 (double exclamation) */
    { 0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
      0x66, 0x00, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00 },
    /* 0x14 - DC4 (paragraph mark) */
    { 0x00, 0x00, 0x7f, 0xdb, 0xdb, 0xdb, 0x7b, 0x1b,
      0x1b, 0x1b, 0x1b, 0x1b, 0x00, 0x00, 0x00, 0x00 },
    /* 0x15 - NAK (section mark) */
    { 0x00, 0x7c, 0xc6, 0x60, 0x38, 0x6c, 0xc6, 0xc6,
      0x6c, 0x38, 0x0c, 0xc6, 0x7c, 0x00, 0x00, 0x00 },
    /* 0x16 - SYN (thick underline) */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xfe, 0xfe, 0xfe, 0xfe, 0x00, 0x00, 0x00, 0x00 },
    /* 0x17 - ETB (up-down arrow with base) */
    { 0x00, 0x00, 0x18, 0x3c, 0x7e, 0x18, 0x18, 0x18,
      0x7e, 0x3c, 0x18, 0x7e, 0x00, 0x00, 0x00, 0x00 },
    /* 0x18 - CAN (up arrow) */
    { 0x00, 0x00, 0x18, 0x3c, 0x7e, 0x18, 0x18, 0x18,
      0x18, 0x18, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00 },
    /* 0x19 - EM (down arrow) */
    { 0x00, 0x00, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18,
      0x18, 0x7e, 0x3c, 0x18, 0x00, 0x00, 0x00, 0x00 },
    /* 0x1A - SUB (right arrow) */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x0c, 0xfe,
      0x0c, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0x1B - ESC (left arrow) */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x60, 0xfe,
      0x60, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0x1C - FS (right angle) */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xc0,
      0xc0, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0x1D - GS (left-right arrow) */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x66, 0xff,
      0x66, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0x1E - RS (up-pointing triangle) */
    { 0x00, 0x00, 0x00, 0x00, 0x10, 0x38, 0x38, 0x7c,
      0x7c, 0xfe, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0x1F - US (down-pointing triangle) */
    { 0x00, 0x00, 0x00, 0x00, 0xfe, 0xfe, 0x7c, 0x7c,
      0x38, 0x38, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00 },

    /* 0x20 - Space */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0x21 - ! */
    { 0x00, 0x00, 0x18, 0x3c, 0x3c, 0x3c, 0x18, 0x18,
      0x18, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00 },
    /* 0x22 - " */
    { 0x00, 0x66, 0x66, 0x66, 0x24, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0x23 - # */
    { 0x00, 0x00, 0x00, 0x6c, 0x6c, 0xfe, 0x6c, 0x6c,
      0x6c, 0xfe, 0x6c, 0x6c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x24 - $ */
    { 0x18, 0x18, 0x7c, 0xc6, 0xc2, 0xc0, 0x7c, 0x06,
      0x06, 0x86, 0xc6, 0x7c, 0x18, 0x18, 0x00, 0x00 },
    /* 0x25 - % */
    { 0x00, 0x00, 0x00, 0x00, 0xc2, 0xc6, 0x0c, 0x18,
      0x30, 0x60, 0xc6, 0x86, 0x00, 0x00, 0x00, 0x00 },
    /* 0x26 - & */
    { 0x00, 0x00, 0x38, 0x6c, 0x6c, 0x38, 0x76, 0xdc,
      0xcc, 0xcc, 0xcc, 0x76, 0x00, 0x00, 0x00, 0x00 },
    /* 0x27 - ' */
    { 0x00, 0x30, 0x30, 0x30, 0x60, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0x28 - ( */
    { 0x00, 0x00, 0x0c, 0x18, 0x30, 0x30, 0x30, 0x30,
      0x30, 0x30, 0x18, 0x0c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x29 - ) */
    { 0x00, 0x00, 0x30, 0x18, 0x0c, 0x0c, 0x0c, 0x0c,
      0x0c, 0x0c, 0x18, 0x30, 0x00, 0x00, 0x00, 0x00 },
    /* 0x2A - * */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x3c, 0xff,
      0x3c, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0x2B - + */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x7e,
      0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0x2C - , */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x18, 0x18, 0x18, 0x30, 0x00, 0x00, 0x00 },
    /* 0x2D - - */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0x2E - . */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00 },
    /* 0x2F - / */
    { 0x00, 0x00, 0x00, 0x00, 0x02, 0x06, 0x0c, 0x18,
      0x30, 0x60, 0xc0, 0x80, 0x00, 0x00, 0x00, 0x00 },
    /* 0x30 - 0 */
    { 0x00, 0x00, 0x7c, 0xc6, 0xc6, 0xce, 0xde, 0xf6,
      0xe6, 0xc6, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x31 - 1 */
    { 0x00, 0x00, 0x18, 0x38, 0x78, 0x18, 0x18, 0x18,
      0x18, 0x18, 0x18, 0x7e, 0x00, 0x00, 0x00, 0x00 },
    /* 0x32 - 2 */
    { 0x00, 0x00, 0x7c, 0xc6, 0x06, 0x0c, 0x18, 0x30,
      0x60, 0xc0, 0xc6, 0xfe, 0x00, 0x00, 0x00, 0x00 },
    /* 0x33 - 3 */
    { 0x00, 0x00, 0x7c, 0xc6, 0x06, 0x06, 0x3c, 0x06,
      0x06, 0x06, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x34 - 4 */
    { 0x00, 0x00, 0x0c, 0x1c, 0x3c, 0x6c, 0xcc, 0xfe,
      0x0c, 0x0c, 0x0c, 0x1e, 0x00, 0x00, 0x00, 0x00 },
    /* 0x35 - 5 */
    { 0x00, 0x00, 0xfe, 0xc0, 0xc0, 0xc0, 0xfc, 0x06,
      0x06, 0x06, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x36 - 6 */
    { 0x00, 0x00, 0x38, 0x60, 0xc0, 0xc0, 0xfc, 0xc6,
      0xc6, 0xc6, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x37 - 7 */
    { 0x00, 0x00, 0xfe, 0xc6, 0x06, 0x06, 0x0c, 0x18,
      0x30, 0x30, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00 },
    /* 0x38 - 8 */
    { 0x00, 0x00, 0x7c, 0xc6, 0xc6, 0xc6, 0x7c, 0xc6,
      0xc6, 0xc6, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x39 - 9 */
    { 0x00, 0x00, 0x7c, 0xc6, 0xc6, 0xc6, 0x7e, 0x06,
      0x06, 0x06, 0x0c, 0x78, 0x00, 0x00, 0x00, 0x00 },
    /* 0x3A - : */
    { 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00,
      0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0x3B - ; */
    { 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00,
      0x00, 0x18, 0x18, 0x30, 0x00, 0x00, 0x00, 0x00 },
    /* 0x3C - < */
    { 0x00, 0x00, 0x00, 0x06, 0x0c, 0x18, 0x30, 0x60,
      0x30, 0x18, 0x0c, 0x06, 0x00, 0x00, 0x00, 0x00 },
    /* 0x3D - = */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x7e, 0x00, 0x00,
      0x7e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0x3E - > */
    { 0x00, 0x00, 0x00, 0x60, 0x30, 0x18, 0x0c, 0x06,
      0x0c, 0x18, 0x30, 0x60, 0x00, 0x00, 0x00, 0x00 },
    /* 0x3F - ? */
    { 0x00, 0x00, 0x7c, 0xc6, 0xc6, 0x0c, 0x18, 0x18,
      0x18, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00 },
    /* 0x40 - @ */
    { 0x00, 0x00, 0x00, 0x7c, 0xc6, 0xc6, 0xde, 0xde,
      0xde, 0xdc, 0xc0, 0x7c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x41 - A */
    { 0x00, 0x00, 0x10, 0x38, 0x6c, 0xc6, 0xc6, 0xfe,
      0xc6, 0xc6, 0xc6, 0xc6, 0x00, 0x00, 0x00, 0x00 },
    /* 0x42 - B */
    { 0x00, 0x00, 0xfc, 0x66, 0x66, 0x66, 0x7c, 0x66,
      0x66, 0x66, 0x66, 0xfc, 0x00, 0x00, 0x00, 0x00 },
    /* 0x43 - C */
    { 0x00, 0x00, 0x3c, 0x66, 0xc2, 0xc0, 0xc0, 0xc0,
      0xc0, 0xc2, 0x66, 0x3c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x44 - D */
    { 0x00, 0x00, 0xf8, 0x6c, 0x66, 0x66, 0x66, 0x66,
      0x66, 0x66, 0x6c, 0xf8, 0x00, 0x00, 0x00, 0x00 },
    /* 0x45 - E */
    { 0x00, 0x00, 0xfe, 0x66, 0x62, 0x68, 0x78, 0x68,
      0x60, 0x62, 0x66, 0xfe, 0x00, 0x00, 0x00, 0x00 },
    /* 0x46 - F */
    { 0x00, 0x00, 0xfe, 0x66, 0x62, 0x68, 0x78, 0x68,
      0x60, 0x60, 0x60, 0xf0, 0x00, 0x00, 0x00, 0x00 },
    /* 0x47 - G */
    { 0x00, 0x00, 0x3c, 0x66, 0xc2, 0xc0, 0xc0, 0xde,
      0xc6, 0xc6, 0x66, 0x3a, 0x00, 0x00, 0x00, 0x00 },
    /* 0x48 - H */
    { 0x00, 0x00, 0xc6, 0xc6, 0xc6, 0xc6, 0xfe, 0xc6,
      0xc6, 0xc6, 0xc6, 0xc6, 0x00, 0x00, 0x00, 0x00 },
    /* 0x49 - I */
    { 0x00, 0x00, 0x3c, 0x18, 0x18, 0x18, 0x18, 0x18,
      0x18, 0x18, 0x18, 0x3c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x4A - J */
    { 0x00, 0x00, 0x1e, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
      0xcc, 0xcc, 0xcc, 0x78, 0x00, 0x00, 0x00, 0x00 },
    /* 0x4B - K */
    { 0x00, 0x00, 0xe6, 0x66, 0x66, 0x6c, 0x78, 0x78,
      0x6c, 0x66, 0x66, 0xe6, 0x00, 0x00, 0x00, 0x00 },
    /* 0x4C - L */
    { 0x00, 0x00, 0xf0, 0x60, 0x60, 0x60, 0x60, 0x60,
      0x60, 0x62, 0x66, 0xfe, 0x00, 0x00, 0x00, 0x00 },
    /* 0x4D - M */
    { 0x00, 0x00, 0xc6, 0xee, 0xfe, 0xfe, 0xd6, 0xc6,
      0xc6, 0xc6, 0xc6, 0xc6, 0x00, 0x00, 0x00, 0x00 },
    /* 0x4E - N */
    { 0x00, 0x00, 0xc6, 0xe6, 0xf6, 0xfe, 0xde, 0xce,
      0xc6, 0xc6, 0xc6, 0xc6, 0x00, 0x00, 0x00, 0x00 },
    /* 0x4F - O */
    { 0x00, 0x00, 0x7c, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6,
      0xc6, 0xc6, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x50 - P */
    { 0x00, 0x00, 0xfc, 0x66, 0x66, 0x66, 0x7c, 0x60,
      0x60, 0x60, 0x60, 0xf0, 0x00, 0x00, 0x00, 0x00 },
    /* 0x51 - Q */
    { 0x00, 0x00, 0x7c, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6,
      0xc6, 0xd6, 0xde, 0x7c, 0x0c, 0x0e, 0x00, 0x00 },
    /* 0x52 - R */
    { 0x00, 0x00, 0xfc, 0x66, 0x66, 0x66, 0x7c, 0x6c,
      0x66, 0x66, 0x66, 0xe6, 0x00, 0x00, 0x00, 0x00 },
    /* 0x53 - S */
    { 0x00, 0x00, 0x7c, 0xc6, 0xc6, 0x60, 0x38, 0x0c,
      0x06, 0xc6, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x54 - T */
    { 0x00, 0x00, 0xff, 0xdb, 0x99, 0x18, 0x18, 0x18,
      0x18, 0x18, 0x18, 0x3c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x55 - U */
    { 0x00, 0x00, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6,
      0xc6, 0xc6, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x56 - V */
    { 0x00, 0x00, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6,
      0xc6, 0x6c, 0x38, 0x10, 0x00, 0x00, 0x00, 0x00 },
    /* 0x57 - W */
    { 0x00, 0x00, 0xc6, 0xc6, 0xc6, 0xc6, 0xd6, 0xd6,
      0xd6, 0xfe, 0xee, 0x6c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x58 - X */
    { 0x00, 0x00, 0xc6, 0xc6, 0x6c, 0x7c, 0x38, 0x38,
      0x7c, 0x6c, 0xc6, 0xc6, 0x00, 0x00, 0x00, 0x00 },
    /* 0x59 - Y */
    { 0x00, 0x00, 0xc6, 0xc6, 0xc6, 0x6c, 0x38, 0x18,
      0x18, 0x18, 0x18, 0x3c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x5A - Z */
    { 0x00, 0x00, 0xfe, 0xc6, 0x86, 0x0c, 0x18, 0x30,
      0x60, 0xc2, 0xc6, 0xfe, 0x00, 0x00, 0x00, 0x00 },
    /* 0x5B - [ */
    { 0x00, 0x00, 0x3c, 0x30, 0x30, 0x30, 0x30, 0x30,
      0x30, 0x30, 0x30, 0x3c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x5C - \ */
    { 0x00, 0x00, 0x00, 0x80, 0xc0, 0xe0, 0x70, 0x38,
      0x1c, 0x0e, 0x06, 0x02, 0x00, 0x00, 0x00, 0x00 },
    /* 0x5D - ] */
    { 0x00, 0x00, 0x3c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
      0x0c, 0x0c, 0x0c, 0x3c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x5E - ^ */
    { 0x10, 0x38, 0x6c, 0xc6, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0x5F - _ */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00 },
    /* 0x60 - ` */
    { 0x30, 0x30, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0x61 - a */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x0c, 0x7c,
      0xcc, 0xcc, 0xcc, 0x76, 0x00, 0x00, 0x00, 0x00 },
    /* 0x62 - b */
    { 0x00, 0x00, 0xe0, 0x60, 0x60, 0x78, 0x6c, 0x66,
      0x66, 0x66, 0x66, 0x7c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x63 - c */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x7c, 0xc6, 0xc0,
      0xc0, 0xc0, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x64 - d */
    { 0x00, 0x00, 0x1c, 0x0c, 0x0c, 0x3c, 0x6c, 0xcc,
      0xcc, 0xcc, 0xcc, 0x76, 0x00, 0x00, 0x00, 0x00 },
    /* 0x65 - e */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x7c, 0xc6, 0xfe,
      0xc0, 0xc0, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x66 - f */
    { 0x00, 0x00, 0x38, 0x6c, 0x64, 0x60, 0xf0, 0x60,
      0x60, 0x60, 0x60, 0xf0, 0x00, 0x00, 0x00, 0x00 },
    /* 0x67 - g */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x76, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0x7c, 0x0c, 0xcc, 0x78, 0x00 },
    /* 0x68 - h */
    { 0x00, 0x00, 0xe0, 0x60, 0x60, 0x6c, 0x76, 0x66,
      0x66, 0x66, 0x66, 0xe6, 0x00, 0x00, 0x00, 0x00 },
    /* 0x69 - i */
    { 0x00, 0x00, 0x18, 0x18, 0x00, 0x38, 0x18, 0x18,
      0x18, 0x18, 0x18, 0x3c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x6A - j */
    { 0x00, 0x00, 0x06, 0x06, 0x00, 0x0e, 0x06, 0x06,
      0x06, 0x06, 0x06, 0x06, 0x66, 0x66, 0x3c, 0x00 },
    /* 0x6B - k */
    { 0x00, 0x00, 0xe0, 0x60, 0x60, 0x66, 0x6c, 0x78,
      0x78, 0x6c, 0x66, 0xe6, 0x00, 0x00, 0x00, 0x00 },
    /* 0x6C - l */
    { 0x00, 0x00, 0x38, 0x18, 0x18, 0x18, 0x18, 0x18,
      0x18, 0x18, 0x18, 0x3c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x6D - m */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0xec, 0xfe, 0xd6,
      0xd6, 0xd6, 0xd6, 0xc6, 0x00, 0x00, 0x00, 0x00 },
    /* 0x6E - n */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0xdc, 0x66, 0x66,
      0x66, 0x66, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00 },
    /* 0x6F - o */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x7c, 0xc6, 0xc6,
      0xc6, 0xc6, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x70 - p */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0xdc, 0x66, 0x66,
      0x66, 0x66, 0x66, 0x7c, 0x60, 0x60, 0xf0, 0x00 },
    /* 0x71 - q */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x76, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0x7c, 0x0c, 0x0c, 0x1e, 0x00 },
    /* 0x72 - r */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0xdc, 0x76, 0x66,
      0x60, 0x60, 0x60, 0xf0, 0x00, 0x00, 0x00, 0x00 },
    /* 0x73 - s */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x7c, 0xc6, 0x60,
      0x38, 0x0c, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x74 - t */
    { 0x00, 0x00, 0x10, 0x30, 0x30, 0xfc, 0x30, 0x30,
      0x30, 0x30, 0x36, 0x1c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x75 - u */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0x76, 0x00, 0x00, 0x00, 0x00 },
    /* 0x76 - v */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0xc6, 0xc6, 0xc6,
      0xc6, 0xc6, 0x6c, 0x38, 0x00, 0x00, 0x00, 0x00 },
    /* 0x77 - w */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0xc6, 0xc6, 0xd6,
      0xd6, 0xd6, 0xfe, 0x6c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x78 - x */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0xc6, 0x6c, 0x38,
      0x38, 0x38, 0x6c, 0xc6, 0x00, 0x00, 0x00, 0x00 },
    /* 0x79 - y */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0xc6, 0xc6, 0xc6,
      0xc6, 0xc6, 0xc6, 0x7e, 0x06, 0x0c, 0xf8, 0x00 },
    /* 0x7A - z */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xcc, 0x18,
      0x30, 0x60, 0xc6, 0xfe, 0x00, 0x00, 0x00, 0x00 },
    /* 0x7B - { */
    { 0x00, 0x00, 0x0e, 0x18, 0x18, 0x18, 0x70, 0x18,
      0x18, 0x18, 0x18, 0x0e, 0x00, 0x00, 0x00, 0x00 },
    /* 0x7C - | */
    { 0x00, 0x00, 0x18, 0x18, 0x18, 0x18, 0x00, 0x18,
      0x18, 0x18, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00 },
    /* 0x7D - } */
    { 0x00, 0x00, 0x70, 0x18, 0x18, 0x18, 0x0e, 0x18,
      0x18, 0x18, 0x18, 0x70, 0x00, 0x00, 0x00, 0x00 },
    /* 0x7E - ~ */
    { 0x00, 0x00, 0x76, 0xdc, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0x7F - DEL (solid block placeholder) */
    { 0x00, 0x00, 0x00, 0x00, 0x10, 0x38, 0x6c, 0xc6,
      0xc6, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },

    /* 0x80 - C-cedilla (upper) */
    { 0x00, 0x00, 0x3c, 0x66, 0xc2, 0xc0, 0xc0, 0xc0,
      0xc2, 0x66, 0x3c, 0x0c, 0x06, 0x7c, 0x00, 0x00 },
    /* 0x81 - u-diaeresis */
    { 0x00, 0x00, 0xcc, 0x00, 0x00, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0x76, 0x00, 0x00, 0x00, 0x00 },
    /* 0x82 - e-acute */
    { 0x00, 0x0c, 0x18, 0x30, 0x00, 0x7c, 0xc6, 0xfe,
      0xc0, 0xc0, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x83 - a-circumflex */
    { 0x00, 0x10, 0x38, 0x6c, 0x00, 0x78, 0x0c, 0x7c,
      0xcc, 0xcc, 0xcc, 0x76, 0x00, 0x00, 0x00, 0x00 },
    /* 0x84 - a-diaeresis */
    { 0x00, 0x00, 0xcc, 0x00, 0x00, 0x78, 0x0c, 0x7c,
      0xcc, 0xcc, 0xcc, 0x76, 0x00, 0x00, 0x00, 0x00 },
    /* 0x85 - a-grave */
    { 0x00, 0x60, 0x30, 0x18, 0x00, 0x78, 0x0c, 0x7c,
      0xcc, 0xcc, 0xcc, 0x76, 0x00, 0x00, 0x00, 0x00 },
    /* 0x86 - a-ring */
    { 0x00, 0x38, 0x6c, 0x38, 0x00, 0x78, 0x0c, 0x7c,
      0xcc, 0xcc, 0xcc, 0x76, 0x00, 0x00, 0x00, 0x00 },
    /* 0x87 - c-cedilla */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x7c, 0xc6, 0xc0,
      0xc0, 0xc0, 0xc6, 0x7c, 0x18, 0x70, 0x00, 0x00 },
    /* 0x88 - e-circumflex */
    { 0x00, 0x10, 0x38, 0x6c, 0x00, 0x7c, 0xc6, 0xfe,
      0xc0, 0xc0, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x89 - e-diaeresis */
    { 0x00, 0x00, 0xc6, 0x00, 0x00, 0x7c, 0xc6, 0xfe,
      0xc0, 0xc0, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x8A - e-grave */
    { 0x00, 0x60, 0x30, 0x18, 0x00, 0x7c, 0xc6, 0xfe,
      0xc0, 0xc0, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x8B - i-diaeresis */
    { 0x00, 0x00, 0x66, 0x00, 0x00, 0x38, 0x18, 0x18,
      0x18, 0x18, 0x18, 0x3c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x8C - i-circumflex */
    { 0x00, 0x18, 0x3c, 0x66, 0x00, 0x38, 0x18, 0x18,
      0x18, 0x18, 0x18, 0x3c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x8D - i-grave */
    { 0x00, 0x60, 0x30, 0x18, 0x00, 0x38, 0x18, 0x18,
      0x18, 0x18, 0x18, 0x3c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x8E - A-diaeresis */
    { 0x00, 0xc6, 0x00, 0x10, 0x38, 0x6c, 0xc6, 0xc6,
      0xfe, 0xc6, 0xc6, 0xc6, 0x00, 0x00, 0x00, 0x00 },
    /* 0x8F - A-ring */
    { 0x38, 0x6c, 0x38, 0x10, 0x38, 0x6c, 0xc6, 0xfe,
      0xc6, 0xc6, 0xc6, 0xc6, 0x00, 0x00, 0x00, 0x00 },
    /* 0x90 - E-acute */
    { 0x0c, 0x18, 0x00, 0xfe, 0x66, 0x62, 0x68, 0x78,
      0x68, 0x62, 0x66, 0xfe, 0x00, 0x00, 0x00, 0x00 },
    /* 0x91 - ae ligature */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x6e, 0x3b, 0x1b,
      0x7e, 0xd8, 0xdc, 0x77, 0x00, 0x00, 0x00, 0x00 },
    /* 0x92 - AE ligature */
    { 0x00, 0x00, 0x3e, 0x6c, 0xcc, 0xcc, 0xfe, 0xcc,
      0xcc, 0xcc, 0xcc, 0xce, 0x00, 0x00, 0x00, 0x00 },
    /* 0x93 - o-circumflex */
    { 0x00, 0x10, 0x38, 0x6c, 0x00, 0x7c, 0xc6, 0xc6,
      0xc6, 0xc6, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x94 - o-diaeresis */
    { 0x00, 0x00, 0xc6, 0x00, 0x00, 0x7c, 0xc6, 0xc6,
      0xc6, 0xc6, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x95 - o-grave */
    { 0x00, 0x60, 0x30, 0x18, 0x00, 0x7c, 0xc6, 0xc6,
      0xc6, 0xc6, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x96 - u-circumflex */
    { 0x00, 0x30, 0x78, 0xcc, 0x00, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0x76, 0x00, 0x00, 0x00, 0x00 },
    /* 0x97 - u-grave */
    { 0x00, 0x60, 0x30, 0x18, 0x00, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0x76, 0x00, 0x00, 0x00, 0x00 },
    /* 0x98 - y-diaeresis */
    { 0x00, 0x00, 0xc6, 0x00, 0x00, 0xc6, 0xc6, 0xc6,
      0xc6, 0xc6, 0xc6, 0x7e, 0x06, 0x0c, 0x78, 0x00 },
    /* 0x99 - O-diaeresis */
    { 0x00, 0xc6, 0x00, 0x7c, 0xc6, 0xc6, 0xc6, 0xc6,
      0xc6, 0xc6, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x9A - U-diaeresis */
    { 0x00, 0xc6, 0x00, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6,
      0xc6, 0xc6, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00 },
    /* 0x9B - cent sign */
    { 0x00, 0x18, 0x18, 0x7c, 0xc6, 0xc0, 0xc0, 0xc0,
      0xc6, 0x7c, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00 },
    /* 0x9C - pound sign */
    { 0x00, 0x38, 0x6c, 0x64, 0x60, 0xf0, 0x60, 0x60,
      0x60, 0x60, 0xe6, 0xfc, 0x00, 0x00, 0x00, 0x00 },
    /* 0x9D - yen sign */
    { 0x00, 0x00, 0xc6, 0xc6, 0x6c, 0x6c, 0x38, 0xfe,
      0x38, 0xfe, 0x38, 0x38, 0x00, 0x00, 0x00, 0x00 },
    /* 0x9E - Pt (peseta) */
    { 0x00, 0xf8, 0xcc, 0xcc, 0xf8, 0xc4, 0xcc, 0xde,
      0xcc, 0xcc, 0xcc, 0xc6, 0x00, 0x00, 0x00, 0x00 },
    /* 0x9F - f-hook (florin) */
    { 0x00, 0x0e, 0x1b, 0x18, 0x18, 0x18, 0x7e, 0x18,
      0x18, 0x18, 0xd8, 0x70, 0x00, 0x00, 0x00, 0x00 },
    /* 0xA0 - a-acute */
    { 0x00, 0x18, 0x30, 0x60, 0x00, 0x78, 0x0c, 0x7c,
      0xcc, 0xcc, 0xcc, 0x76, 0x00, 0x00, 0x00, 0x00 },
    /* 0xA1 - i-acute */
    { 0x00, 0x0c, 0x18, 0x30, 0x00, 0x38, 0x18, 0x18,
      0x18, 0x18, 0x18, 0x3c, 0x00, 0x00, 0x00, 0x00 },
    /* 0xA2 - o-acute */
    { 0x00, 0x18, 0x30, 0x60, 0x00, 0x7c, 0xc6, 0xc6,
      0xc6, 0xc6, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00 },
    /* 0xA3 - u-acute */
    { 0x00, 0x18, 0x30, 0x60, 0x00, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0x76, 0x00, 0x00, 0x00, 0x00 },
    /* 0xA4 - n-tilde */
    { 0x00, 0x00, 0x76, 0xdc, 0x00, 0xdc, 0x66, 0x66,
      0x66, 0x66, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00 },
    /* 0xA5 - N-tilde */
    { 0x76, 0xdc, 0x00, 0xc6, 0xe6, 0xf6, 0xfe, 0xde,
      0xce, 0xc6, 0xc6, 0xc6, 0x00, 0x00, 0x00, 0x00 },
    /* 0xA6 - feminine ordinal */
    { 0x00, 0x3c, 0x6c, 0x6c, 0x3e, 0x00, 0x7e, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0xA7 - masculine ordinal */
    { 0x00, 0x38, 0x6c, 0x6c, 0x38, 0x00, 0x7c, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0xA8 - inverted question mark */
    { 0x00, 0x00, 0x30, 0x30, 0x00, 0x30, 0x30, 0x60,
      0xc0, 0xc6, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00 },
    /* 0xA9 - reversed not sign (left corner) */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xc0,
      0xc0, 0xc0, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0xAA - not sign (right corner) */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x06,
      0x06, 0x06, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0xAB - one-half fraction */
    { 0x00, 0xc0, 0xc0, 0xc2, 0xc6, 0xcc, 0x18, 0x30,
      0x60, 0xce, 0x9b, 0x06, 0x0c, 0x1f, 0x00, 0x00 },
    /* 0xAC - one-quarter fraction */
    { 0x00, 0xc0, 0xc0, 0xc2, 0xc6, 0xcc, 0x18, 0x30,
      0x66, 0xce, 0x96, 0x3e, 0x06, 0x06, 0x00, 0x00 },
    /* 0xAD - inverted exclamation mark */
    { 0x00, 0x00, 0x18, 0x18, 0x00, 0x18, 0x18, 0x18,
      0x3c, 0x3c, 0x3c, 0x18, 0x00, 0x00, 0x00, 0x00 },
    /* 0xAE - left-pointing double angle */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x36, 0x6c, 0xd8,
      0x6c, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0xAF - right-pointing double angle */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0xd8, 0x6c, 0x36,
      0x6c, 0xd8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },

    /* 0xB0 - light shade */
    { 0x11, 0x44, 0x11, 0x44, 0x11, 0x44, 0x11, 0x44,
      0x11, 0x44, 0x11, 0x44, 0x11, 0x44, 0x11, 0x44 },
    /* 0xB1 - medium shade */
    { 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa,
      0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa },
    /* 0xB2 - dark shade */
    { 0xdd, 0x77, 0xdd, 0x77, 0xdd, 0x77, 0xdd, 0x77,
      0xdd, 0x77, 0xdd, 0x77, 0xdd, 0x77, 0xdd, 0x77 },
    /* 0xB3 - box light vertical */
    { 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18,
      0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18 },
    /* 0xB4 - box light vertical and left */
    { 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0xf8,
      0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18 },
    /* 0xB5 - box vertical single and left double */
    { 0x18, 0x18, 0x18, 0x18, 0x18, 0xf8, 0x18, 0xf8,
      0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18 },
    /* 0xB6 - box double vertical and left */
    { 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0xf6,
      0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36 },
    /* 0xB7 - box double down and left */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe,
      0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36 },
    /* 0xB8 - box down single and left double */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x18, 0xf8,
      0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18 },
    /* 0xB9 - box double vertical and left */
    { 0x36, 0x36, 0x36, 0x36, 0x36, 0xf6, 0x06, 0xf6,
      0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36 },
    /* 0xBA - box double vertical */
    { 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
      0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36 },
    /* 0xBB - box double down and left */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x06, 0xf6,
      0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36 },
    /* 0xBC - box double up and left */
    { 0x36, 0x36, 0x36, 0x36, 0x36, 0xf6, 0x06, 0xfe,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0xBD - box double up and left */
    { 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0xfe,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0xBE - box up single and left double */
    { 0x18, 0x18, 0x18, 0x18, 0x18, 0xf8, 0x18, 0xf8,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0xBF - box light down and left */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8,
      0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18 },

    /* 0xC0 - box light up and right */
    { 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x1f,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0xC1 - box light up and horizontal */
    { 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0xff,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0xC2 - box light down and horizontal */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
      0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18 },
    /* 0xC3 - box light vertical and right */
    { 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x1f,
      0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18 },
    /* 0xC4 - box light horizontal */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0xC5 - box light vertical and horizontal */
    { 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0xff,
      0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18 },
    /* 0xC6 - box vertical single and right double */
    { 0x18, 0x18, 0x18, 0x18, 0x18, 0x1f, 0x18, 0x1f,
      0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18 },
    /* 0xC7 - box double vertical and right */
    { 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x37,
      0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36 },
    /* 0xC8 - box double up and right */
    { 0x36, 0x36, 0x36, 0x36, 0x36, 0x37, 0x30, 0x3f,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0xC9 - box double down and right */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f, 0x30, 0x37,
      0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36 },
    /* 0xCA - box double up and horizontal */
    { 0x36, 0x36, 0x36, 0x36, 0x36, 0xf7, 0x00, 0xff,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0xCB - box double down and horizontal */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0xf7,
      0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36 },
    /* 0xCC - box double vertical and right */
    { 0x36, 0x36, 0x36, 0x36, 0x36, 0x37, 0x30, 0x37,
      0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36 },
    /* 0xCD - box double horizontal */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0xff,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0xCE - box double vertical and horizontal */
    { 0x36, 0x36, 0x36, 0x36, 0x36, 0xf7, 0x00, 0xf7,
      0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36 },
    /* 0xCF - box up single and horizontal double */
    { 0x18, 0x18, 0x18, 0x18, 0x18, 0xff, 0x00, 0xff,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },

    /* 0xD0 - box double up and horizontal */
    { 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x3f,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0xD1 - box down single and horizontal double */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0xff,
      0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18 },
    /* 0xD2 - box double down and horizontal */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f,
      0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36 },
    /* 0xD3 - box double up and right */
    { 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0xf7,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0xD4 - box up double and right single */
    { 0x18, 0x18, 0x18, 0x18, 0x18, 0x1f, 0x18, 0x1f,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0xD5 - box down double and right single */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x18, 0x1f,
      0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18 },
    /* 0xD6 - box double down and right */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf7,
      0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36 },
    /* 0xD7 - box double vertical and horizontal */
    { 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0xff,
      0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36 },
    /* 0xD8 - box vertical single and horizontal double */
    { 0x18, 0x18, 0x18, 0x18, 0x18, 0xff, 0x18, 0xff,
      0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18 },
    /* 0xD9 - box light up and left */
    { 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0xf8,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0xDA - box light down and right */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f,
      0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18 },
    /* 0xDB - full block */
    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
    /* 0xDC - lower half block */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
    /* 0xDD - left half block */
    { 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
      0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0 },
    /* 0xDE - right half block */
    { 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,
      0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f },
    /* 0xDF - upper half block */
    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },

    /* 0xE0 - alpha (Greek) */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x76, 0xdc, 0xd8,
      0xd8, 0xd8, 0xdc, 0x76, 0x00, 0x00, 0x00, 0x00 },
    /* 0xE1 - beta / sharp-s (German) */
    { 0x00, 0x00, 0x78, 0xcc, 0xcc, 0xcc, 0xd8, 0xcc,
      0xc6, 0xc6, 0xc6, 0xcc, 0x00, 0x00, 0x00, 0x00 },
    /* 0xE2 - Gamma */
    { 0x00, 0x00, 0xfe, 0xc6, 0xc6, 0xc0, 0xc0, 0xc0,
      0xc0, 0xc0, 0xc0, 0xc0, 0x00, 0x00, 0x00, 0x00 },
    /* 0xE3 - pi */
    { 0x00, 0x00, 0x00, 0x00, 0xfe, 0x6c, 0x6c, 0x6c,
      0x6c, 0x6c, 0x6c, 0x6c, 0x00, 0x00, 0x00, 0x00 },
    /* 0xE4 - Sigma (upper) */
    { 0x00, 0x00, 0x00, 0xfe, 0xc6, 0x60, 0x30, 0x18,
      0x30, 0x60, 0xc6, 0xfe, 0x00, 0x00, 0x00, 0x00 },
    /* 0xE5 - sigma (lower) */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x7e, 0xd8, 0xd8,
      0xd8, 0xd8, 0xd8, 0x70, 0x00, 0x00, 0x00, 0x00 },
    /* 0xE6 - mu */
    { 0x00, 0x00, 0x00, 0x00, 0x66, 0x66, 0x66, 0x66,
      0x66, 0x7c, 0x60, 0x60, 0xc0, 0x00, 0x00, 0x00 },
    /* 0xE7 - tau */
    { 0x00, 0x00, 0x00, 0x00, 0x76, 0xdc, 0x18, 0x18,
      0x18, 0x18, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00 },
    /* 0xE8 - Phi */
    { 0x00, 0x00, 0x00, 0x7e, 0x18, 0x3c, 0x66, 0x66,
      0x66, 0x3c, 0x18, 0x7e, 0x00, 0x00, 0x00, 0x00 },
    /* 0xE9 - Theta */
    { 0x00, 0x00, 0x00, 0x38, 0x6c, 0xc6, 0xc6, 0xfe,
      0xc6, 0xc6, 0x6c, 0x38, 0x00, 0x00, 0x00, 0x00 },
    /* 0xEA - Omega */
    { 0x00, 0x00, 0x38, 0x6c, 0xc6, 0xc6, 0xc6, 0xc6,
      0x6c, 0x6c, 0x6c, 0xee, 0x00, 0x00, 0x00, 0x00 },
    /* 0xEB - delta */
    { 0x00, 0x00, 0x1e, 0x30, 0x18, 0x0c, 0x3e, 0x66,
      0x66, 0x66, 0x66, 0x3c, 0x00, 0x00, 0x00, 0x00 },
    /* 0xEC - infinity */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x76, 0xdb, 0xdb,
      0xdb, 0xdb, 0x76, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0xED - phi (lower) */
    { 0x00, 0x00, 0x00, 0x02, 0x06, 0x7c, 0xce, 0xd6,
      0xe6, 0x7c, 0xc0, 0x80, 0x00, 0x00, 0x00, 0x00 },
    /* 0xEE - epsilon */
    { 0x00, 0x00, 0x1c, 0x30, 0x60, 0x60, 0x7c, 0x60,
      0x60, 0x60, 0x30, 0x1c, 0x00, 0x00, 0x00, 0x00 },
    /* 0xEF - intersection */
    { 0x00, 0x00, 0x00, 0x7c, 0xc6, 0xc6, 0xc6, 0xc6,
      0xc6, 0xc6, 0xc6, 0xc6, 0x00, 0x00, 0x00, 0x00 },

    /* 0xF0 - identical to (triple bar) */
    { 0x00, 0x00, 0x00, 0x00, 0xfe, 0x00, 0x00, 0xfe,
      0x00, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0xF1 - plus-minus */
    { 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x7e, 0x18,
      0x18, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00 },
    /* 0xF2 - greater-than or equal to */
    { 0x00, 0x00, 0x00, 0x30, 0x18, 0x0c, 0x06, 0x0c,
      0x18, 0x30, 0x00, 0x7e, 0x00, 0x00, 0x00, 0x00 },
    /* 0xF3 - less-than or equal to */
    { 0x00, 0x00, 0x00, 0x0c, 0x18, 0x30, 0x60, 0x30,
      0x18, 0x0c, 0x00, 0x7e, 0x00, 0x00, 0x00, 0x00 },
    /* 0xF4 - top of integral */
    { 0x00, 0x00, 0x0e, 0x1b, 0x1b, 0x18, 0x18, 0x18,
      0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18 },
    /* 0xF5 - bottom of integral */
    { 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18,
      0xd8, 0xd8, 0xd8, 0x70, 0x00, 0x00, 0x00, 0x00 },
    /* 0xF6 - division sign */
    { 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00, 0x7e,
      0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0xF7 - approximately equal */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x76, 0xdc, 0x00,
      0x76, 0xdc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0xF8 - degree sign */
    { 0x00, 0x38, 0x6c, 0x6c, 0x38, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0xF9 - bullet operator (middle dot) */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18,
      0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0xFA - middle dot (small) */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0xFB - square root */
    { 0x00, 0x0f, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0xec,
      0x6c, 0x6c, 0x3c, 0x1c, 0x00, 0x00, 0x00, 0x00 },
    /* 0xFC - superscript n */
    { 0x00, 0xd8, 0x6c, 0x6c, 0x6c, 0x6c, 0x6c, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0xFD - superscript 2 (squared) */
    { 0x00, 0x70, 0xd8, 0x30, 0x60, 0xc8, 0xf8, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0xFE - filled square */
    { 0x00, 0x00, 0x00, 0x00, 0x7c, 0x7c, 0x7c, 0x7c,
      0x7c, 0x7c, 0x7c, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 0xFF - non-breaking space (blank) */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
};

/* ============================================================================
 * Mouse Cursor Sprite (12x18 pixels)
 *
 * Classic macOS arrow cursor. Values: 0=transparent, 1=black, 2=white.
 * ============================================================================ */

static const uint8_t cursor_sprite[CURSOR_HEIGHT][CURSOR_WIDTH] = {
    { 1,0,0,0,0,0,0,0,0,0,0,0 },
    { 1,1,0,0,0,0,0,0,0,0,0,0 },
    { 1,2,1,0,0,0,0,0,0,0,0,0 },
    { 1,2,2,1,0,0,0,0,0,0,0,0 },
    { 1,2,2,2,1,0,0,0,0,0,0,0 },
    { 1,2,2,2,2,1,0,0,0,0,0,0 },
    { 1,2,2,2,2,2,1,0,0,0,0,0 },
    { 1,2,2,2,2,2,2,1,0,0,0,0 },
    { 1,2,2,2,2,2,2,2,1,0,0,0 },
    { 1,2,2,2,2,2,2,2,2,1,0,0 },
    { 1,2,2,2,2,2,2,2,2,2,1,0 },
    { 1,2,2,2,2,2,2,1,1,1,1,1 },
    { 1,2,2,2,1,2,2,1,0,0,0,0 },
    { 1,2,2,1,0,1,2,2,1,0,0,0 },
    { 1,2,1,0,0,1,2,2,1,0,0,0 },
    { 1,1,0,0,0,0,1,2,2,1,0,0 },
    { 1,0,0,0,0,0,1,2,2,1,0,0 },
    { 0,0,0,0,0,0,0,1,1,0,0,0 },
};

/* ============================================================================
 * ANSI Colour Table (BGRA format, matching kernel fbconsole.c)
 * ============================================================================ */

static const uint32_t ansi_colours[8] = {
    0xFF000000,  /* 0: Black   */
    0xFF0000AA,  /* 1: Red     */
    0xFF00AA00,  /* 2: Green   */
    0xFF00AAAA,  /* 3: Yellow  */
    0xFFAA0000,  /* 4: Blue    */
    0xFFAA00AA,  /* 5: Magenta */
    0xFFAAAA00,  /* 6: Cyan    */
    0xFFCCCCCC,  /* 7: White   */
};

static const uint32_t ansi_bright_colours[8] = {
    0xFF555555,  /* 0: Bright Black  */
    0xFF0055FF,  /* 1: Bright Red    */
    0xFF55FF55,  /* 2: Bright Green  */
    0xFF55FFFF,  /* 3: Bright Yellow */
    0xFFFF5555,  /* 4: Bright Blue   */
    0xFFFF55FF,  /* 5: Bright Magenta*/
    0xFFFFFF55,  /* 6: Bright Cyan   */
    0xFFFFFFFF,  /* 7: Bright White  */
};

/* ============================================================================
 * Keycode-to-ASCII Conversion Tables
 *
 * Standard US QWERTY keymap. Matching the kernel's virtio_input.c tables
 * exactly — these are redefined here since WindowServer is userland.
 * ============================================================================ */

static const char keymap_normal[128] = {
    /*  0 */ 0, 0x1B, '1', '2', '3', '4', '5', '6',
    /*  8 */ '7', '8', '9', '0', '-', '=', '\b', '\t',
    /* 16 */ 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i',
    /* 24 */ 'o', 'p', '[', ']', '\n', 0, 'a', 's',
    /* 32 */ 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';',
    /* 40 */ '\'', '`', 0, '\\', 'z', 'x', 'c', 'v',
    /* 48 */ 'b', 'n', 'm', ',', '.', '/', 0, '*',
    /* 56 */ 0, ' ', 0, 0, 0, 0, 0, 0,
    /* 64 */ 0, 0, 0, 0, 0, 0, 0, '7',
    /* 72 */ '8', '9', '-', '4', '5', '6', '+', '1',
    /* 80 */ '2', '3', '0', '.', 0, 0, 0, 0,
    /* 88 */ 0, 0, 0, 0, 0, 0, 0, 0,
    /* 96 */ '\n', 0, '/', 0, 0, 0, 0, 0,
    /* 104 */ 0, 0, 0, 0, 0, 0, 0, 0,
    /* 112 */ 0, 0, 0, 0, 0, 0, 0, 0,
    /* 120 */ 0, 0, 0, 0, 0, 0, 0, 0,
};

static const char keymap_shift[128] = {
    /*  0 */ 0, 0x1B, '!', '@', '#', '$', '%', '^',
    /*  8 */ '&', '*', '(', ')', '_', '+', '\b', '\t',
    /* 16 */ 'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I',
    /* 24 */ 'O', 'P', '{', '}', '\n', 0, 'A', 'S',
    /* 32 */ 'D', 'F', 'G', 'H', 'J', 'K', 'L', ':',
    /* 40 */ '"', '~', 0, '|', 'Z', 'X', 'C', 'V',
    /* 48 */ 'B', 'N', 'M', '<', '>', '?', 0, '*',
    /* 56 */ 0, ' ', 0, 0, 0, 0, 0, 0,
    /* 64 */ 0, 0, 0, 0, 0, 0, 0, '7',
    /* 72 */ '8', '9', '-', '4', '5', '6', '+', '1',
    /* 80 */ '2', '3', '0', '.', 0, 0, 0, 0,
    /* 88 */ 0, 0, 0, 0, 0, 0, 0, 0,
    /* 96 */ '\n', 0, '/', 0, 0, 0, 0, 0,
    /* 104 */ 0, 0, 0, 0, 0, 0, 0, 0,
    /* 112 */ 0, 0, 0, 0, 0, 0, 0, 0,
    /* 120 */ 0, 0, 0, 0, 0, 0, 0, 0,
};

/* ============================================================================
 * Framebuffer State
 * ============================================================================ */

static io_connect_t     ws_fb_connect = IO_OBJECT_NULL;
static volatile uint32_t *ws_framebuffer = NULL;
static uint32_t         ws_fb_width = 0;
static uint32_t         ws_fb_height = 0;
static uint32_t         ws_fb_pitch = 0;
static uint32_t         ws_fb_bpp = 0;

/* ============================================================================
 * IOHIDSystem State
 * ============================================================================ */

static io_connect_t     ws_hid_connect = IO_OBJECT_NULL;
static struct hid_event_ring *ws_hid_ring = NULL;

/* ============================================================================
 * Mouse Cursor State
 * ============================================================================ */

static int32_t  cursor_x = 0;
static int32_t  cursor_y = 0;
static int32_t  cursor_buttons = 0;
static uint32_t cursor_save_under[CURSOR_WIDTH * CURSOR_HEIGHT];
static int32_t  cursor_save_x = -1;
static int32_t  cursor_save_y = -1;
static int      cursor_visible = 0;

/*
 * When a window is destroyed its pixels remain in VRAM until the next
 * full redraw.  The normal any_dirty check only examines active windows,
 * so destroying a window never triggers a repaint.  This flag forces a
 * full desktop + window redraw on the next frame.
 */
static int      ws_needs_full_redraw = 0;

/*
 * Double-click tracking.
 *
 * On macOS, the WindowServer (SkyLight/CGXServer) tracks click timing and
 * spatial proximity to compute click_count. If a mouseDown arrives within
 * DOUBLE_CLICK_TIME_MS of the previous mouseDown and within DOUBLE_CLICK_DIST
 * pixels, click_count is incremented; otherwise it resets to 1.
 *
 * This matches the behaviour of CGSEventRecord's clickState in CoreGraphics.
 */
#define DOUBLE_CLICK_TIME_MS    500     /* Same as macOS default */
#define DOUBLE_CLICK_DIST       5       /* Pixels — macOS uses ~4 */

static struct timeval   dc_last_time = {0, 0};
static int32_t          dc_last_x = -1000;
static int32_t          dc_last_y = -1000;
static uint32_t         dc_click_count = 0;

/* ============================================================================
 * Drawing Primitives
 * ============================================================================ */

static inline void ws_put_pixel(uint32_t x, uint32_t y, uint32_t colour)
{
    if (x >= ws_fb_width || y >= ws_fb_height)
        return;
    uint32_t pixel_stride = ws_fb_pitch / 4;
    ws_framebuffer[y * pixel_stride + x] = colour;
}

static inline uint32_t ws_get_pixel(uint32_t x, uint32_t y)
{
    if (x >= ws_fb_width || y >= ws_fb_height)
        return 0;
    uint32_t pixel_stride = ws_fb_pitch / 4;
    return ws_framebuffer[y * pixel_stride + x];
}

static void ws_fill_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h,
                          uint32_t colour)
{
    uint32_t pixel_stride = ws_fb_pitch / 4;
    uint32_t x_end = x + w;
    uint32_t y_end = y + h;
    if (x_end > ws_fb_width) x_end = ws_fb_width;
    if (y_end > ws_fb_height) y_end = ws_fb_height;

    for (uint32_t py = y; py < y_end; py++) {
        volatile uint32_t *row = &ws_framebuffer[py * pixel_stride];
        for (uint32_t px = x; px < x_end; px++)
            row[px] = colour;
    }
}

/* Draw a single character at pixel position (px, py) */
static void ws_draw_char(uint32_t px, uint32_t py, unsigned char ch,
                          uint32_t fg, uint32_t bg)
{
    const uint8_t *glyph = font8x16_data[ch];
    uint32_t pixel_stride = ws_fb_pitch / 4;

    for (uint32_t y = 0; y < FONT_HEIGHT; y++) {
        uint8_t bits = glyph[y];
        if (py + y >= ws_fb_height) break;
        volatile uint32_t *row = &ws_framebuffer[(py + y) * pixel_stride];
        for (uint32_t x = 0; x < FONT_WIDTH; x++) {
            if (px + x >= ws_fb_width) break;
            row[px + x] = (bits & (0x80 >> x)) ? fg : bg;
        }
    }
}

/* Draw a string at pixel position (px, py) */
static void ws_draw_string(uint32_t px, uint32_t py, const char *str,
                            uint32_t fg, uint32_t bg)
{
    while (*str) {
        if (px + FONT_WIDTH > ws_fb_width) break;
        ws_draw_char(px, py, (unsigned char)*str, fg, bg);
        px += FONT_WIDTH;
        str++;
    }
}

/* Draw a filled circle (for traffic light buttons) */
static void ws_draw_circle(uint32_t cx, uint32_t cy, uint32_t r,
                            uint32_t colour)
{
    /* Simple Bresenham-style filled circle */
    for (int32_t dy = -(int32_t)r; dy <= (int32_t)r; dy++) {
        for (int32_t dx = -(int32_t)r; dx <= (int32_t)r; dx++) {
            if (dx * dx + dy * dy <= (int32_t)(r * r)) {
                ws_put_pixel((uint32_t)((int32_t)cx + dx),
                             (uint32_t)((int32_t)cy + dy),
                             colour);
            }
        }
    }
}

/* ============================================================================
 * Mouse Cursor Compositing (save-under technique)
 *
 * Before drawing the cursor, save the pixels underneath. When moving,
 * restore saved pixels, save new location, then draw cursor.
 * This is the same technique macOS WindowServer uses for the
 * hardware cursor fallback path.
 * ============================================================================ */

static void ws_cursor_save(int32_t x, int32_t y)
{
    for (uint32_t cy = 0; cy < CURSOR_HEIGHT; cy++) {
        for (uint32_t cx = 0; cx < CURSOR_WIDTH; cx++) {
            int32_t sx = x + (int32_t)cx;
            int32_t sy = y + (int32_t)cy;
            if (sx >= 0 && sx < (int32_t)ws_fb_width &&
                sy >= 0 && sy < (int32_t)ws_fb_height) {
                cursor_save_under[cy * CURSOR_WIDTH + cx] =
                    ws_get_pixel((uint32_t)sx, (uint32_t)sy);
            }
        }
    }
    cursor_save_x = x;
    cursor_save_y = y;
}

static void ws_cursor_restore(void)
{
    if (cursor_save_x < 0) return;

    for (uint32_t cy = 0; cy < CURSOR_HEIGHT; cy++) {
        for (uint32_t cx = 0; cx < CURSOR_WIDTH; cx++) {
            int32_t sx = cursor_save_x + (int32_t)cx;
            int32_t sy = cursor_save_y + (int32_t)cy;
            if (sx >= 0 && sx < (int32_t)ws_fb_width &&
                sy >= 0 && sy < (int32_t)ws_fb_height) {
                ws_put_pixel((uint32_t)sx, (uint32_t)sy,
                             cursor_save_under[cy * CURSOR_WIDTH + cx]);
            }
        }
    }
}

static void ws_cursor_draw(int32_t x, int32_t y)
{
    for (uint32_t cy = 0; cy < CURSOR_HEIGHT; cy++) {
        for (uint32_t cx = 0; cx < CURSOR_WIDTH; cx++) {
            uint8_t v = cursor_sprite[cy][cx];
            if (v == 0) continue;  /* Transparent */

            int32_t sx = x + (int32_t)cx;
            int32_t sy = y + (int32_t)cy;
            if (sx >= 0 && sx < (int32_t)ws_fb_width &&
                sy >= 0 && sy < (int32_t)ws_fb_height) {
                uint32_t col = (v == 1) ? COL_CURSOR_BLACK : COL_CURSOR_WHITE;
                ws_put_pixel((uint32_t)sx, (uint32_t)sy, col);
            }
        }
    }
}

/* ============================================================================
 * Framebuffer Flush
 * ============================================================================ */

static void ws_flush_display(void)
{
    if (ws_fb_connect == IO_OBJECT_NULL) return;
    IOConnectCallScalarMethod(ws_fb_connect, kIOFBMethodFlushAll,
                              NULL, 0, NULL, NULL);
}

static void ws_flush_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h)
{
    if (ws_fb_connect == IO_OBJECT_NULL) return;
    uint64_t input[4] = { x, y, w, h };
    IOConnectCallScalarMethod(ws_fb_connect, kIOFBMethodFlushRect,
                              input, 4, NULL, NULL);
}

/* ============================================================================
 * Window System — Terminal State
 *
 * Each window contains a VT100 terminal emulator state, matching the
 * kernel's fbconsole.c architecture. The terminal state includes cursor
 * position, attribute state, scroll buffer, and VT100 parser state.
 * ============================================================================ */

struct ws_term_state {
    /* Character cell grid */
    unsigned char   cells[TERM_ROWS][TERM_COLS];        /* Character data */
    uint8_t         cell_fg[TERM_ROWS][TERM_COLS];      /* FG colour index */
    uint8_t         cell_bg[TERM_ROWS][TERM_COLS];      /* BG colour index */
    uint8_t         cell_attr[TERM_ROWS][TERM_COLS];    /* Attributes */

    /* Cursor position (0-based, in character cells) */
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
};

/* ============================================================================
 * Window System — Window Structure
 *
 * Each window has a position, size, title, and optional PTY connection.
 * The surface buffer holds the composited content (title bar + content).
 *
 * On macOS, each window has a CGSWindow ID managed by Quartz Compositor.
 * We maintain a simpler flat array with z-ordering by index (higher = front).
 * ============================================================================ */

struct ws_window {
    int             active;             /* Window exists */
    int32_t         x, y;              /* Screen position (top-left) */
    uint32_t        width, height;     /* Total size including chrome */
    char            title[64];         /* Window title */
    uint32_t        style_mask;        /* NSWindowStyleMask: 0 = borderless */

    /* Window type: 0 = internal terminal, 1 = client-managed */
    int             client_managed;
    int32_t         conn_id;            /* Owning connection (-1 = internal) */

    /* Surface buffer for client-managed windows (BGRA, content area only) */
    uint32_t       *surface;            /* malloc'd pixel buffer */
    uint32_t        surface_width;      /* Content area width */
    uint32_t        surface_height;     /* Content area height */

    /* PTY connection (for terminal windows) */
    int             pty_master_fd;     /* Master side FD (-1 if none) */
    int             pty_slave_fd;      /* Slave side FD (-1 if none) */
    pid_t           shell_pid;         /* PID of child shell process */

    /* Terminal emulator state */
    struct ws_term_state term;

    /* Visibility / ordering */
    int             visible;            /* 1 = shown, 0 = hidden */

    /* Dirty tracking */
    int             needs_redraw;      /* Full window redraw needed */
};

/* Window pool */
static struct ws_window ws_windows[WS_MAX_WINDOWS];
static int              ws_window_count = 0;
static int              ws_focus_idx = -1;      /* Index of focused window */

/* Login State: removed — login UI is now /sbin/loginwindow (separate process) */

/* ============================================================================
 * Global Keyboard Modifier State (tracked from HID events)
 * ============================================================================ */

static int ws_shift_held = 0;
static int ws_ctrl_held = 0;
static int ws_alt_held = 0;
static int ws_capslock_on = 0;

/* ============================================================================
 * IOKit Framebuffer Setup
 *
 * Identical flow to macOS WindowServer's IOKit usage:
 *   1. IOServiceGetMatchingService("IOFramebuffer")
 *   2. IOServiceOpen -> user client connection
 *   3. IOConnectCallScalarMethod(sel=0) -> framebuffer info
 *   4. IOConnectMapMemory64(type=0) -> map VRAM
 * ============================================================================ */

static int ws_open_framebuffer(void)
{
    kern_return_t kr;

    printf("[WindowServer] Looking up IOFramebuffer service...\n");
    io_service_t service = IOServiceGetMatchingService(
        kIOMasterPortDefault,
        IOServiceMatching("IOFramebuffer"));

    if (service == IO_OBJECT_NULL) {
        fprintf(stderr, "[WindowServer] ERROR: IOFramebuffer not found\n");
        return -1;
    }
    printf("[WindowServer] Found IOFramebuffer (port %u)\n", service);

    kr = IOServiceOpen(service, mach_task_self(), 0, &ws_fb_connect);
    IOObjectRelease(service);

    if (kr != kIOReturnSuccess) {
        fprintf(stderr, "[WindowServer] ERROR: IOServiceOpen(FB) failed: 0x%x\n", kr);
        return -1;
    }
    printf("[WindowServer] Opened IOFramebuffer connection (port %u)\n",
           ws_fb_connect);

    /* Get framebuffer info */
    uint64_t scalar_out[5] = {0};
    uint32_t scalar_out_cnt = 5;

    kr = IOConnectCallScalarMethod(ws_fb_connect, kIOFBMethodGetInfo,
                                   NULL, 0, scalar_out, &scalar_out_cnt);
    if (kr != kIOReturnSuccess) {
        fprintf(stderr, "[WindowServer] ERROR: GetInfo failed: 0x%x\n", kr);
        IOServiceClose(ws_fb_connect);
        ws_fb_connect = IO_OBJECT_NULL;
        return -1;
    }

    ws_fb_width  = (uint32_t)scalar_out[0];
    ws_fb_height = (uint32_t)scalar_out[1];
    ws_fb_pitch  = (uint32_t)scalar_out[2];
    ws_fb_bpp    = (uint32_t)scalar_out[3];

    printf("[WindowServer] Display: %ux%u, pitch=%u, bpp=%u\n",
           ws_fb_width, ws_fb_height, ws_fb_pitch, ws_fb_bpp);

    /* Map VRAM */
    mach_vm_address_t fb_addr = 0;
    mach_vm_size_t fb_size = 0;

    kr = IOConnectMapMemory64(ws_fb_connect, kIOFBMemoryTypeVRAM,
                              mach_task_self(),
                              &fb_addr, &fb_size, kIOMapAnywhere);
    if (kr != kIOReturnSuccess) {
        fprintf(stderr, "[WindowServer] ERROR: MapMemory(FB) failed: 0x%x\n", kr);
        IOServiceClose(ws_fb_connect);
        ws_fb_connect = IO_OBJECT_NULL;
        return -1;
    }

    ws_framebuffer = (volatile uint32_t *)(uintptr_t)fb_addr;
    printf("[WindowServer] Mapped VRAM at 0x%llx, size 0x%llx\n",
           (unsigned long long)fb_addr, (unsigned long long)fb_size);

    return 0;
}

/* ============================================================================
 * IOHIDSystem Setup
 *
 * Open IOHIDSystem and map the HID event ring buffer.
 * This is how macOS WindowServer receives input events from the kernel.
 * ============================================================================ */

static int ws_open_hid_system(void)
{
    kern_return_t kr;

    printf("[WindowServer] Looking up IOHIDSystem service...\n");
    io_service_t service = IOServiceGetMatchingService(
        kIOMasterPortDefault,
        IOServiceMatching("IOHIDSystem"));

    if (service == IO_OBJECT_NULL) {
        fprintf(stderr, "[WindowServer] WARNING: IOHIDSystem not found\n");
        return -1;
    }
    printf("[WindowServer] Found IOHIDSystem (port %u)\n", service);

    kr = IOServiceOpen(service, mach_task_self(), 0, &ws_hid_connect);
    IOObjectRelease(service);

    if (kr != kIOReturnSuccess) {
        fprintf(stderr, "[WindowServer] ERROR: IOServiceOpen(HID) failed: 0x%x\n", kr);
        return -1;
    }
    printf("[WindowServer] Opened IOHIDSystem connection (port %u)\n",
           ws_hid_connect);

    /* Map HID event ring (memory type 0) */
    mach_vm_address_t ring_addr = 0;
    mach_vm_size_t ring_size = 0;

    kr = IOConnectMapMemory64(ws_hid_connect, 0,
                              mach_task_self(),
                              &ring_addr, &ring_size, kIOMapAnywhere);
    if (kr != kIOReturnSuccess) {
        fprintf(stderr, "[WindowServer] ERROR: MapMemory(HID) failed: 0x%x\n", kr);
        IOServiceClose(ws_hid_connect);
        ws_hid_connect = IO_OBJECT_NULL;
        return -1;
    }

    ws_hid_ring = (struct hid_event_ring *)(uintptr_t)ring_addr;
    printf("[WindowServer] Mapped HID ring at 0x%llx, size 0x%llx "
           "(ring size=%u)\n",
           (unsigned long long)ring_addr, (unsigned long long)ring_size,
           ws_hid_ring->size);

    return 0;
}

/* ============================================================================
 * Desktop and Menu Bar Drawing
 * ============================================================================ */

static void ws_draw_desktop(void)
{
    /* Fill entire screen with desktop background */
    ws_fill_rect(0, 0, ws_fb_width, ws_fb_height, COL_DESKTOP);

    /* Menu bar: 22 pixels tall, light grey (matching macOS) */
    ws_fill_rect(0, 0, ws_fb_width, MENUBAR_HEIGHT, COL_MENUBAR);

    /* 1-pixel separator below menu bar */
    ws_fill_rect(0, MENUBAR_HEIGHT, ws_fb_width, 1, COL_MENUBAR_SEP);

    /*
     * Menu bar layout (matching macOS):
     *   Left side:  Apple menu ("Kiseki") + App name (bold) + app menus
     *   Right side: SystemUIServer extras (clock, etc.) — handled by events
     *
     * If a foreground app is connected, show its name and menu items.
     */
    uint32_t menu_x = 10;
    ws_draw_string(menu_x, 3, "Kiseki", COL_MENUBAR_TEXT, COL_MENUBAR);
    menu_x += 6 * FONT_WIDTH + 16;  /* "Kiseki" + gap */

    if (ws_foreground_conn >= 0 && ws_foreground_conn < WS_MAX_CONNECTIONS) {
        struct ws_connection *conn = &ws_connections[ws_foreground_conn];
        if (conn->active) {
            /* App name in bold-style (we only have one font, so just draw it) */
            ws_draw_string(menu_x, 3, conn->app_name,
                           COL_MENUBAR_TEXT, COL_MENUBAR);
            menu_x += (uint32_t)strlen(conn->app_name) * FONT_WIDTH + 16;

            /* Menu items */
            for (int i = 0; i < conn->menu_item_count; i++) {
                uint32_t col = conn->menu_items[i].enabled ?
                    COL_MENUBAR_TEXT : COL_MENUBAR_SEP;
                ws_draw_string(menu_x, 3, conn->menu_items[i].title,
                               col, COL_MENUBAR);
                menu_x += (uint32_t)strlen(conn->menu_items[i].title) *
                           FONT_WIDTH + 16;
            }
        }
    }
}

/* ws_draw_login_window removed — login UI now in /sbin/loginwindow */

/* ============================================================================
 * VT100 Terminal Emulator
 *
 * Character-at-a-time state machine matching XNU's gc_putchar().
 * Processes CSI sequences for cursor movement, erase, and SGR colours.
 * ============================================================================ */

static void term_init(struct ws_term_state *ts)
{
    memset(ts, 0, sizeof(*ts));
    ts->vt_state = VT_NORMAL;
    ts->vt_attr = ATTR_NONE;
    ts->vt_fg_idx = DEFAULT_FG_IDX;
    ts->vt_bg_idx = DEFAULT_BG_IDX;
    ts->vt_wrap_mode = 1;

    /* Fill cells with spaces */
    for (uint32_t r = 0; r < TERM_ROWS; r++) {
        for (uint32_t c = 0; c < TERM_COLS; c++) {
            ts->cells[r][c] = ' ';
            ts->cell_fg[r][c] = DEFAULT_FG_IDX;
            ts->cell_bg[r][c] = DEFAULT_BG_IDX;
            ts->cell_attr[r][c] = ATTR_NONE;
        }
    }
    ts->dirty = 1;
}

static void term_scroll_up(struct ws_term_state *ts)
{
    /* Move rows 1..TERM_ROWS-1 up to 0..TERM_ROWS-2 */
    memmove(&ts->cells[0], &ts->cells[1],
            (TERM_ROWS - 1) * TERM_COLS);
    memmove(&ts->cell_fg[0], &ts->cell_fg[1],
            (TERM_ROWS - 1) * TERM_COLS);
    memmove(&ts->cell_bg[0], &ts->cell_bg[1],
            (TERM_ROWS - 1) * TERM_COLS);
    memmove(&ts->cell_attr[0], &ts->cell_attr[1],
            (TERM_ROWS - 1) * TERM_COLS);

    /* Clear bottom row */
    for (uint32_t c = 0; c < TERM_COLS; c++) {
        ts->cells[TERM_ROWS - 1][c] = ' ';
        ts->cell_fg[TERM_ROWS - 1][c] = ts->vt_fg_idx;
        ts->cell_bg[TERM_ROWS - 1][c] = ts->vt_bg_idx;
        ts->cell_attr[TERM_ROWS - 1][c] = ATTR_NONE;
    }
    ts->dirty = 1;
}

static void term_clear_row(struct ws_term_state *ts, uint32_t row,
                            uint32_t from, uint32_t to)
{
    if (to > TERM_COLS) to = TERM_COLS;
    for (uint32_t c = from; c < to; c++) {
        ts->cells[row][c] = ' ';
        ts->cell_fg[row][c] = ts->vt_fg_idx;
        ts->cell_bg[row][c] = ts->vt_bg_idx;
        ts->cell_attr[row][c] = ATTR_NONE;
    }
    ts->dirty = 1;
}

/* CSI command dispatch (matching XNU gc_putc_gotpars) */
static void term_csi_dispatch(struct ws_term_state *ts, unsigned char cmd)
{
    uint32_t n;

    switch (cmd) {
    case 'A':   /* CUU — Cursor Up */
        n = ts->vt_par[0] ? ts->vt_par[0] : 1;
        if (n > ts->cur_row) ts->cur_row = 0;
        else ts->cur_row -= n;
        break;

    case 'B':   /* CUD — Cursor Down */
        n = ts->vt_par[0] ? ts->vt_par[0] : 1;
        ts->cur_row += n;
        if (ts->cur_row >= TERM_ROWS) ts->cur_row = TERM_ROWS - 1;
        break;

    case 'C':   /* CUF — Cursor Forward */
        n = ts->vt_par[0] ? ts->vt_par[0] : 1;
        ts->cur_col += n;
        if (ts->cur_col >= TERM_COLS) ts->cur_col = TERM_COLS - 1;
        break;

    case 'D':   /* CUB — Cursor Back */
        n = ts->vt_par[0] ? ts->vt_par[0] : 1;
        if (n > ts->cur_col) ts->cur_col = 0;
        else ts->cur_col -= n;
        break;

    case 'H':   /* CUP — Cursor Position */
    case 'f':   /* HVP */
        ts->cur_row = ts->vt_par[0] ? ts->vt_par[0] - 1 : 0;
        ts->cur_col = (ts->vt_numpars >= 2 && ts->vt_par[1]) ?
                       ts->vt_par[1] - 1 : 0;
        if (ts->cur_row >= TERM_ROWS) ts->cur_row = TERM_ROWS - 1;
        if (ts->cur_col >= TERM_COLS) ts->cur_col = TERM_COLS - 1;
        break;

    case 'G':   /* CHA — Cursor Horizontal Absolute */
        ts->cur_col = ts->vt_par[0] ? ts->vt_par[0] - 1 : 0;
        if (ts->cur_col >= TERM_COLS) ts->cur_col = TERM_COLS - 1;
        break;

    case 'd':   /* VPA — Vertical Position Absolute */
        ts->cur_row = ts->vt_par[0] ? ts->vt_par[0] - 1 : 0;
        if (ts->cur_row >= TERM_ROWS) ts->cur_row = TERM_ROWS - 1;
        break;

    case 'J':   /* ED — Erase in Display */
        switch (ts->vt_par[0]) {
        case 0: /* Cursor to end */
            term_clear_row(ts, ts->cur_row, ts->cur_col, TERM_COLS);
            for (uint32_t r = ts->cur_row + 1; r < TERM_ROWS; r++)
                term_clear_row(ts, r, 0, TERM_COLS);
            break;
        case 1: /* Start to cursor */
            for (uint32_t r = 0; r < ts->cur_row; r++)
                term_clear_row(ts, r, 0, TERM_COLS);
            term_clear_row(ts, ts->cur_row, 0, ts->cur_col + 1);
            break;
        case 2: /* Entire screen */
            for (uint32_t r = 0; r < TERM_ROWS; r++)
                term_clear_row(ts, r, 0, TERM_COLS);
            break;
        }
        break;

    case 'K':   /* EL — Erase in Line */
        switch (ts->vt_par[0]) {
        case 0: term_clear_row(ts, ts->cur_row, ts->cur_col, TERM_COLS); break;
        case 1: term_clear_row(ts, ts->cur_row, 0, ts->cur_col + 1); break;
        case 2: term_clear_row(ts, ts->cur_row, 0, TERM_COLS); break;
        }
        break;

    case 'X':   /* ECH — Erase Characters */
        n = ts->vt_par[0] ? ts->vt_par[0] : 1;
        term_clear_row(ts, ts->cur_row, ts->cur_col, ts->cur_col + n);
        break;

    case 'm':   /* SGR — Select Graphic Rendition */
        for (uint32_t i = 0; i < ts->vt_numpars; i++) {
            uint32_t p = ts->vt_par[i];
            if (p == 0) {
                ts->vt_attr = ATTR_NONE;
                ts->vt_fg_idx = DEFAULT_FG_IDX;
                ts->vt_bg_idx = DEFAULT_BG_IDX;
            } else if (p == 1) { ts->vt_attr |= ATTR_BOLD;
            } else if (p == 4) { ts->vt_attr |= ATTR_UNDERLINE;
            } else if (p == 7) { ts->vt_attr |= ATTR_REVERSE;
            } else if (p == 22) { ts->vt_attr &= ~ATTR_BOLD;
            } else if (p == 24) { ts->vt_attr &= ~ATTR_UNDERLINE;
            } else if (p == 27) { ts->vt_attr &= ~ATTR_REVERSE;
            } else if (p >= 30 && p <= 37) { ts->vt_fg_idx = (uint8_t)(p - 30);
            } else if (p >= 40 && p <= 47) { ts->vt_bg_idx = (uint8_t)(p - 40);
            } else if (p == 39) { ts->vt_fg_idx = DEFAULT_FG_IDX;
            } else if (p == 49) { ts->vt_bg_idx = DEFAULT_BG_IDX;
            }
        }
        break;

    case 'r':   /* DECSTBM — reset cursor home */
        ts->cur_row = 0;
        ts->cur_col = 0;
        break;

    default:
        break;
    }
}

/* DEC private mode dispatch (ESC [ ? n h/l) */
static void term_dec_priv_dispatch(struct ws_term_state *ts, unsigned char cmd)
{
    if (cmd == 'h' && ts->vt_par[0] == 7)
        ts->vt_wrap_mode = 1;
    else if (cmd == 'l' && ts->vt_par[0] == 7)
        ts->vt_wrap_mode = 0;
    /* Other DEC modes silently ignored */
}

/*
 * term_putc - Process one character through the VT100 state machine.
 *
 * Matching XNU gc_putchar() exactly.
 */
static void term_putc(struct ws_term_state *ts, unsigned char ch)
{
    switch (ts->vt_state) {

    case VT_NORMAL:
        switch (ch) {
        case 0x00: break;           /* NUL */
        case 0x07: break;           /* BEL */
        case '\b': case 0x7F:       /* BS / DEL */
            if (ts->cur_col > 0) ts->cur_col--;
            break;
        case '\t': {                /* HT */
            uint32_t next = (ts->cur_col + 8) & ~7u;
            if (next >= TERM_COLS) next = TERM_COLS - 1;
            ts->cur_col = next;
            break;
        }
        case '\n': case 0x0B: case 0x0C:   /* LF / VT / FF */
            ts->cur_row++;
            if (ts->cur_row >= TERM_ROWS) {
                term_scroll_up(ts);
                ts->cur_row = TERM_ROWS - 1;
            }
            ts->dirty = 1;
            break;
        case '\r':                  /* CR */
            ts->cur_col = 0;
            break;
        case 0x1B:                  /* ESC */
            ts->vt_state = VT_ESC;
            break;
        default:
            if (ch >= 0x20) {
                ts->cells[ts->cur_row][ts->cur_col] = ch;
                ts->cell_fg[ts->cur_row][ts->cur_col] = ts->vt_fg_idx;
                ts->cell_bg[ts->cur_row][ts->cur_col] = ts->vt_bg_idx;
                ts->cell_attr[ts->cur_row][ts->cur_col] = ts->vt_attr;
                ts->dirty = 1;
                ts->cur_col++;
                if (ts->cur_col >= TERM_COLS) {
                    if (ts->vt_wrap_mode) {
                        ts->cur_col = 0;
                        ts->cur_row++;
                        if (ts->cur_row >= TERM_ROWS) {
                            term_scroll_up(ts);
                            ts->cur_row = TERM_ROWS - 1;
                        }
                    } else {
                        ts->cur_col = TERM_COLS - 1;
                    }
                }
            }
            break;
        }
        break;

    case VT_ESC:
        ts->vt_state = VT_NORMAL;
        switch (ch) {
        case '[': ts->vt_state = VT_CSI_INIT; break;
        case 'c': /* RIS */
            term_init(ts);
            break;
        case 'D': /* IND */
            ts->cur_row++;
            if (ts->cur_row >= TERM_ROWS) {
                term_scroll_up(ts);
                ts->cur_row = TERM_ROWS - 1;
            }
            ts->dirty = 1;
            break;
        case 'M': /* RI */
            if (ts->cur_row == 0) {
                /* Scroll down — move rows down, clear top */
                memmove(&ts->cells[1], &ts->cells[0],
                        (TERM_ROWS - 1) * TERM_COLS);
                memmove(&ts->cell_fg[1], &ts->cell_fg[0],
                        (TERM_ROWS - 1) * TERM_COLS);
                memmove(&ts->cell_bg[1], &ts->cell_bg[0],
                        (TERM_ROWS - 1) * TERM_COLS);
                memmove(&ts->cell_attr[1], &ts->cell_attr[0],
                        (TERM_ROWS - 1) * TERM_COLS);
                term_clear_row(ts, 0, 0, TERM_COLS);
            } else {
                ts->cur_row--;
            }
            break;
        case '7': /* DECSC */
            ts->saved_col = ts->cur_col;
            ts->saved_row = ts->cur_row;
            ts->saved_attr = ts->vt_attr;
            ts->saved_fg_idx = ts->vt_fg_idx;
            ts->saved_bg_idx = ts->vt_bg_idx;
            break;
        case '8': /* DECRC */
            ts->cur_col = ts->saved_col;
            ts->cur_row = ts->saved_row;
            ts->vt_attr = ts->saved_attr;
            ts->vt_fg_idx = ts->saved_fg_idx;
            ts->vt_bg_idx = ts->saved_bg_idx;
            if (ts->cur_row >= TERM_ROWS) ts->cur_row = TERM_ROWS - 1;
            if (ts->cur_col >= TERM_COLS) ts->cur_col = TERM_COLS - 1;
            break;
        default: break;
        }
        break;

    case VT_CSI_INIT:
        for (uint32_t i = 0; i < VT_MAXPARS; i++)
            ts->vt_par[i] = 0;
        ts->vt_numpars = 0;
        ts->vt_state = VT_CSI_PARS;
        /* FALLTHROUGH */

    case VT_CSI_PARS:
        if (ch == '?') {
            ts->vt_state = VT_DEC_PRIV;
        } else if (ch >= '0' && ch <= '9') {
            ts->vt_par[ts->vt_numpars] =
                ts->vt_par[ts->vt_numpars] * 10 + (ch - '0');
        } else if (ch == ';') {
            if (ts->vt_numpars < VT_MAXPARS - 1)
                ts->vt_numpars++;
        } else {
            ts->vt_numpars++;
            ts->vt_state = VT_NORMAL;
            term_csi_dispatch(ts, ch);
        }
        break;

    case VT_DEC_PRIV:
        if (ch >= '0' && ch <= '9') {
            ts->vt_par[0] = ts->vt_par[0] * 10 + (ch - '0');
        } else {
            ts->vt_state = VT_NORMAL;
            term_dec_priv_dispatch(ts, ch);
        }
        break;

    default:
        ts->vt_state = VT_NORMAL;
        break;
    }
}

/* ============================================================================
 * Window Drawing / Compositing
 *
 * Draws a single window (title bar + terminal content) directly into
 * the framebuffer. macOS uses a back-to-front painter's algorithm;
 * we do the same — draw windows in z-order (array index).
 * ============================================================================ */

static uint32_t term_resolve_fg(uint8_t fg_idx, uint8_t attr)
{
    if (attr & ATTR_REVERSE) {
        /* Swap: use bg as fg */
        return ansi_colours[DEFAULT_BG_IDX];
    }
    if (attr & ATTR_BOLD)
        return ansi_bright_colours[fg_idx & 7];
    return ansi_colours[fg_idx & 7];
}

static uint32_t term_resolve_bg(uint8_t bg_idx, uint8_t attr)
{
    if (attr & ATTR_REVERSE)
        return ansi_colours[DEFAULT_FG_IDX];
    return ansi_colours[bg_idx & 7];
}

static void ws_draw_window(struct ws_window *win)
{
    int32_t wx = win->x;
    int32_t wy = win->y;
    uint32_t ww = win->width;
    uint32_t wh = win->height;

    /* Content area origin depends on whether the window has chrome */
    uint32_t content_x, content_y;

    if (win->style_mask == NSWindowStyleMaskBorderless) {
        /* Borderless: no chrome at all — content starts at window origin */
        content_x = (uint32_t)wx;
        content_y = (uint32_t)wy;
    } else {
        /* Titled: draw border, title bar, traffic lights */

        /* Window border */
        ws_fill_rect((uint32_t)wx, (uint32_t)wy, ww, 1, COL_WIN_BORDER);
        ws_fill_rect((uint32_t)wx, (uint32_t)(wy + (int32_t)wh - 1), ww, 1, COL_WIN_BORDER);
        ws_fill_rect((uint32_t)wx, (uint32_t)wy, 1, wh, COL_WIN_BORDER);
        ws_fill_rect((uint32_t)(wx + (int32_t)ww - 1), (uint32_t)wy, 1, wh, COL_WIN_BORDER);

        /* Title bar background */
        ws_fill_rect((uint32_t)(wx + 1), (uint32_t)(wy + 1),
                     ww - 2, TITLEBAR_HEIGHT, COL_TITLEBAR);

        /* Traffic light buttons (close/minimise/zoom) */
        uint32_t btn_y = (uint32_t)(wy + 1) + TITLEBAR_HEIGHT / 2;
        ws_draw_circle((uint32_t)(wx + 14), btn_y, 5, COL_BTN_CLOSE);
        ws_draw_circle((uint32_t)(wx + 34), btn_y, 5, COL_BTN_MINIMISE);
        ws_draw_circle((uint32_t)(wx + 54), btn_y, 5, COL_BTN_ZOOM);

        /* Window title (centred in title bar) */
        uint32_t title_len = (uint32_t)strlen(win->title);
        uint32_t title_px = (uint32_t)(wx + 1) +
                             (ww - 2 - title_len * FONT_WIDTH) / 2;
        ws_draw_string(title_px, (uint32_t)(wy + 3),
                       win->title, COL_TITLEBAR_TEXT, COL_TITLEBAR);

        /* Separator line below title bar */
        ws_fill_rect((uint32_t)(wx + 1),
                     (uint32_t)(wy + 1 + TITLEBAR_HEIGHT),
                     ww - 2, 1, COL_WIN_BORDER);

        content_x = (uint32_t)(wx + WINDOW_BORDER);
        content_y = (uint32_t)(wy + WINDOW_BORDER + TITLEBAR_HEIGHT + 1);
    }

    if (win->client_managed && win->surface) {
        /* Client-managed window: blit surface buffer directly to framebuffer */
        uint32_t sw = win->surface_width;
        uint32_t sh = win->surface_height;
        uint32_t pixel_stride = ws_fb_pitch / 4;

        for (uint32_t sy = 0; sy < sh; sy++) {
            uint32_t dy = content_y + sy;
            if (dy >= ws_fb_height) break;
            volatile uint32_t *dst_row = &ws_framebuffer[dy * pixel_stride];
            uint32_t *src_row = &win->surface[sy * sw];
            for (uint32_t sx = 0; sx < sw; sx++) {
                uint32_t dx = content_x + sx;
                if (dx >= ws_fb_width) break;
                dst_row[dx] = src_row[sx];
            }
        }
    } else {
        /* Internal terminal window: render VT100 cell grid */
        struct ws_term_state *ts = &win->term;

        for (uint32_t r = 0; r < TERM_ROWS; r++) {
            for (uint32_t c = 0; c < TERM_COLS; c++) {
                uint32_t px = content_x + c * FONT_WIDTH;
                uint32_t py = content_y + r * FONT_HEIGHT;
                uint32_t fg = term_resolve_fg(ts->cell_fg[r][c],
                                               ts->cell_attr[r][c]);
                uint32_t bg = term_resolve_bg(ts->cell_bg[r][c],
                                               ts->cell_attr[r][c]);
                ws_draw_char(px, py, ts->cells[r][c], fg, bg);
            }
        }

        /* Draw cursor (block cursor at current position) */
        {
            uint32_t cx = content_x + ts->cur_col * FONT_WIDTH;
            uint32_t cy = content_y + ts->cur_row * FONT_HEIGHT;
            unsigned char ch = ts->cells[ts->cur_row][ts->cur_col];
            uint32_t fg = term_resolve_bg(ts->cell_bg[ts->cur_row][ts->cur_col],
                                           ts->cell_attr[ts->cur_row][ts->cur_col]);
            uint32_t bg = term_resolve_fg(ts->cell_fg[ts->cur_row][ts->cur_col],
                                           ts->cell_attr[ts->cur_row][ts->cur_col]);
            ws_draw_char(cx, cy, ch, fg, bg);
        }

        ts->dirty = 0;
    }

    win->needs_redraw = 0;
}

/* ============================================================================
 * Window Creation — Terminal Window with PTY
 *
 * Creates a new terminal window with a PTY pair, forks a shell process.
 * This mirrors macOS Terminal.app's architecture: PTY pair + fork/exec.
 * ============================================================================ */

static int ws_create_terminal_window(const char *title, int32_t x, int32_t y)
{
    if (ws_window_count >= WS_MAX_WINDOWS) {
        fprintf(stderr, "[WindowServer] Window limit reached\n");
        return -1;
    }

    int idx = ws_window_count;
    struct ws_window *win = &ws_windows[idx];
    memset(win, 0, sizeof(*win));

    win->active = 1;
    win->x = x;
    win->y = y;
    win->width = TERM_WIN_WIDTH;
    win->height = TERM_WIN_HEIGHT;
    strncpy(win->title, title, sizeof(win->title) - 1);
    win->client_managed = 0;
    win->conn_id = -1;
    win->surface = NULL;
    win->surface_width = 0;
    win->surface_height = 0;
    win->pty_master_fd = -1;
    win->pty_slave_fd = -1;
    win->shell_pid = -1;
    win->visible = 1;
    win->needs_redraw = 1;

    /* Initialise terminal emulator state */
    term_init(&win->term);

    /* Allocate PTY pair */
    int master_fd = -1, slave_fd = -1;
    if (openpty(&master_fd, &slave_fd, NULL, NULL, NULL) < 0) {
        fprintf(stderr, "[WindowServer] openpty failed: %d\n", errno);
        win->active = 0;
        return -1;
    }

    win->pty_master_fd = master_fd;
    win->pty_slave_fd = slave_fd;

    /* Set master to non-blocking for polling */
    int flags = fcntl(master_fd, F_GETFL, 0);
    fcntl(master_fd, F_SETFL, flags | O_NONBLOCK);

    /* Fork child process for shell */
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "[WindowServer] fork failed: %d\n", errno);
        close(master_fd);
        close(slave_fd);
        win->active = 0;
        return -1;
    }

    if (pid == 0) {
        /* Child process — become session leader, set up PTY slave as stdio */
        close(master_fd);

        setsid();

        /* Redirect stdin/stdout/stderr to slave PTY */
        dup2(slave_fd, STDIN_FILENO);
        dup2(slave_fd, STDOUT_FILENO);
        dup2(slave_fd, STDERR_FILENO);
        if (slave_fd > STDERR_FILENO)
            close(slave_fd);

        /* Set controlling terminal */
        /* ioctl(STDIN_FILENO, TIOCSCTTY, 0); -- may not be available */

        /* Set environment */
        char *envp[] = {
            "HOME=/root",
            "PATH=/bin:/sbin:/usr/bin:/usr/sbin",
            "TERM=vt100",
            "SHELL=/bin/bash",
            "USER=root",
            "LOGNAME=root",
            NULL
        };

        char *argv[] = { "/bin/bash", "--login", NULL };
        execve("/bin/bash", argv, envp);

        /* If exec fails, try /bin/sh */
        argv[0] = "/bin/sh";
        execve("/bin/sh", argv, envp);

        _exit(127);
    }

    /* Parent — close slave side */
    close(slave_fd);
    win->pty_slave_fd = -1;
    win->shell_pid = pid;

    ws_window_count++;
    ws_focus_idx = idx;

    printf("[WindowServer] Created terminal window '%s' (PTY master=%d, "
           "shell PID=%d)\n", title, master_fd, pid);

    return idx;
}

/* ============================================================================
 * Keycode-to-ASCII Conversion
 *
 * Takes modifier state into account. Matches kernel's keycode_to_char().
 * ============================================================================ */

static char ws_keycode_to_char(uint32_t code)
{
    if (code >= 128) return 0;

    char c;
    int shifted = ws_shift_held;

    /* Caps lock toggles shift for letters only */
    if (ws_capslock_on &&
        keymap_normal[code] >= 'a' && keymap_normal[code] <= 'z')
        shifted = !shifted;

    c = shifted ? keymap_shift[code] : keymap_normal[code];

    /* Ctrl key: produce control character */
    if (ws_ctrl_held && c != 0) {
        if (c >= 'a' && c <= 'z') return c - 'a' + 1;
        if (c >= 'A' && c <= 'Z') return c - 'A' + 1;
        if (c == '[' || c == '{') return 0x1B;
        if (c == '\\' || c == '|') return 0x1C;
        if (c == ']' || c == '}') return 0x1D;
    }

    return c;
}

/* ============================================================================
 * HID Event Processing
 *
 * Read events from the shared HID event ring and dispatch:
 *   - Key events: update modifier state, inject into focused window's PTY
 *   - Mouse events: update cursor position, handle clicks
 * ============================================================================ */

static uint32_t ws_hid_poll_count = 0;
static uint32_t ws_hid_move_count = 0;

static void ws_process_hid_events(void)
{
    if (!ws_hid_ring) return;

    ws_hid_poll_count++;

    while (ws_hid_ring->read_idx != ws_hid_ring->write_idx) {
        /*
         * Memory barrier: ensure event data written by the kernel
         * producer is visible to us BEFORE we read it.  The kernel
         * issues dmb ish before updating write_idx; we must issue
         * dmb ish after observing the new write_idx but before
         * loading the event payload.
         */
        __asm__ volatile("dmb ish" ::: "memory");
        uint32_t slot = ws_hid_ring->read_idx % ws_hid_ring->size;
        struct hid_event ev = ws_hid_ring->events[slot];
        ws_hid_ring->read_idx++;

        if (ev.type == HID_EVENT_MOUSE_MOVE) {
            ws_hid_move_count++;
        }

        switch (ev.type) {

        case HID_EVENT_KEY_DOWN:
        case HID_EVENT_KEY_UP: {
            int is_down = (ev.type == HID_EVENT_KEY_DOWN);

            /* Update modifier state */
            switch (ev.keycode) {
            case KEY_LEFTSHIFT: case KEY_RIGHTSHIFT:
                ws_shift_held = is_down; continue;
            case KEY_LEFTCTRL: case KEY_RIGHTCTRL:
                ws_ctrl_held = is_down; continue;
            case KEY_LEFTALT: case KEY_RIGHTALT:
                ws_alt_held = is_down; continue;
            case KEY_CAPSLOCK:
                if (is_down) ws_capslock_on = !ws_capslock_on;
                continue;
            }

            if (!is_down) continue;  /* Only process key-down */

            /* Forward key events to the focused window (if any) */
            if (ws_focus_idx >= 0 &&
                       ws_windows[ws_focus_idx].active) {
                struct ws_window *win = &ws_windows[ws_focus_idx];

                if (win->client_managed) {
                    /* Client-managed window: forward key event via IPC */
                    uint32_t mods = 0;
                    if (ws_shift_held) mods |= HID_FLAG_SHIFT;
                    if (ws_ctrl_held)  mods |= HID_FLAG_CTRL;
                    if (ws_alt_held)   mods |= HID_FLAG_ALT;
                    if (ws_capslock_on) mods |= HID_FLAG_CAPSLOCK;

                    char c = ws_keycode_to_char(ev.keycode);
                    ws_send_key_event_to_client(
                        ws_focus_idx, WS_EVENT_KEY_DOWN,
                        ev.keycode, (uint32_t)(unsigned char)c, mods);
                } else if (win->pty_master_fd >= 0) {
                    /* Internal terminal: send keystrokes to PTY master */
                    int fd = win->pty_master_fd;

                    switch (ev.keycode) {
                    case KEY_UP:
                        write(fd, "\033[A", 3); break;
                    case KEY_DOWN:
                        write(fd, "\033[B", 3); break;
                    case KEY_RIGHT:
                        write(fd, "\033[C", 3); break;
                    case KEY_LEFT:
                        write(fd, "\033[D", 3); break;
                    case KEY_HOME:
                        write(fd, "\033[H", 3); break;
                    case KEY_END:
                        write(fd, "\033[F", 3); break;
                    case KEY_DELETE:
                        write(fd, "\033[3~", 4); break;
                    case KEY_PAGEUP:
                        write(fd, "\033[5~", 4); break;
                    case KEY_PAGEDOWN:
                        write(fd, "\033[6~", 4); break;
                    default: {
                        char c = ws_keycode_to_char(ev.keycode);
                        if (c != 0)
                            write(fd, &c, 1);
                        break;
                    }
                    }
                }
            }
            break;
        }

        case HID_EVENT_MOUSE_MOVE: {
            /* Scale absolute coords (0-32767) to screen coordinates */
            cursor_x = (int32_t)((uint64_t)ev.abs_x * ws_fb_width / (TABLET_ABS_MAX + 1));
            cursor_y = (int32_t)((uint64_t)ev.abs_y * ws_fb_height / (TABLET_ABS_MAX + 1));
            if (cursor_x >= (int32_t)ws_fb_width)
                cursor_x = (int32_t)ws_fb_width - 1;
            if (cursor_y >= (int32_t)ws_fb_height)
                cursor_y = (int32_t)ws_fb_height - 1;
            cursor_buttons = (int32_t)ev.buttons;

            /* Forward mouse-moved / mouse-dragged to focused client window */
            if (ws_focus_idx >= 0 && ws_windows[ws_focus_idx].active &&
                ws_windows[ws_focus_idx].client_managed) {
                uint32_t mid = (cursor_buttons & 1)
                    ? WS_EVENT_MOUSE_DRAGGED : WS_EVENT_MOUSE_MOVED;
                ws_send_mouse_event_to_client(ws_focus_idx, mid,
                    cursor_x, cursor_y, 0, ev.flags);
            }
            break;
        }

        case HID_EVENT_MOUSE_DOWN:
            cursor_buttons = (int32_t)ev.buttons;
            /* Handle click on window close button or forward to client */
            if (ev.buttons & 1) {
                for (int i = ws_window_count - 1; i >= 0; i--) {
                    struct ws_window *win = &ws_windows[i];
                    if (!win->active || !win->visible) continue;
                    /* Check close button (circle at wx+14, wy+12, r=5) */
                    int32_t dx = cursor_x - (win->x + 14);
                    int32_t dy = cursor_y - (win->y + 1 + (int32_t)TITLEBAR_HEIGHT / 2);
                    if (dx * dx + dy * dy <= 25) {
                        if (win->client_managed) {
                            /* Send close event to client app */
                            if (win->conn_id >= 0 &&
                                win->conn_id < WS_MAX_CONNECTIONS &&
                                ws_connections[win->conn_id].active) {
                                ws_event_window_t ev_msg;
                                memset(&ev_msg, 0, sizeof(ev_msg));
                                ev_msg.header.msgh_bits = MACH_MSGH_BITS(
                                    MACH_MSG_TYPE_COPY_SEND, 0);
                                ev_msg.header.msgh_size = sizeof(ev_msg);
                                ev_msg.header.msgh_remote_port =
                                    ws_connections[win->conn_id].event_port;
                                ev_msg.header.msgh_id = WS_EVENT_WINDOW_CLOSE;
                                ev_msg.window_id = i;
                                {
                                    mach_msg_return_t cmr = mach_msg(
                                        &ev_msg.header, MACH_SEND_MSG |
                                        MACH_SEND_TIMEOUT, sizeof(ev_msg),
                                        0, 0, 100, 0);
                                    if (cmr != MACH_MSG_SUCCESS &&
                                        cmr != MACH_SEND_TIMED_OUT) {
                                        ws_cleanup_dead_connection(
                                            win->conn_id);
                                    }
                                }
                            }
                        } else {
                            /* Internal terminal: close PTY + kill shell */
                            if (win->pty_master_fd >= 0)
                                close(win->pty_master_fd);
                            if (win->shell_pid > 0)
                                kill(win->shell_pid, SIGTERM);
                        }
                        if (win->surface) {
                            free(win->surface);
                            win->surface = NULL;
                        }
                        win->active = 0;
                        ws_needs_full_redraw = 1;
                        if (ws_focus_idx == i)
                            ws_focus_idx = -1;
                        break;
                    }
                    /* Hit test: is the click within this window's frame? */
                    if (cursor_x >= win->x &&
                        cursor_x < win->x + (int32_t)win->width &&
                        cursor_y >= win->y &&
                        cursor_y < win->y + (int32_t)win->height) {
                        ws_focus_idx = i;
                        /* Check if click is in title bar (focus only) */
                        if (cursor_y < win->y + (int32_t)TITLEBAR_HEIGHT + 1) {
                            break;  /* title bar — focus set, no content event */
                        }
                        /* Content area — forward to client */
                        if (win->client_managed) {
                            ws_send_mouse_event_to_client(i,
                                WS_EVENT_MOUSE_DOWN,
                                cursor_x, cursor_y, 0, ev.flags);
                        }
                        break;
                    }
                }
            }
            break;

        case HID_EVENT_MOUSE_UP:
            cursor_buttons = (int32_t)ev.buttons;
            /* Forward mouse-up to focused client window */
            if (ws_focus_idx >= 0 && ws_windows[ws_focus_idx].active &&
                ws_windows[ws_focus_idx].client_managed) {
                ws_send_mouse_event_to_client(ws_focus_idx,
                    WS_EVENT_MOUSE_UP,
                    cursor_x, cursor_y, 0, ev.flags);
            }
            break;
        }
    }
}

/* ============================================================================
 * PTY Output Processing
 *
 * Read data from each terminal window's PTY master and feed it through
 * the VT100 terminal emulator.
 * ============================================================================ */

static void ws_process_pty_output(void)
{
    char buf[512];

    for (int i = 0; i < ws_window_count; i++) {
        struct ws_window *win = &ws_windows[i];
        if (!win->active || win->pty_master_fd < 0)
            continue;

        /* Non-blocking read from PTY master */
        ssize_t n = read(win->pty_master_fd, buf, sizeof(buf));
        if (n > 0) {
            for (ssize_t j = 0; j < n; j++)
                term_putc(&win->term, (unsigned char)buf[j]);
        } else if (n == 0) {
            /* EOF — shell exited */
            printf("[WindowServer] Shell exited for window %d\n", i);
            close(win->pty_master_fd);
            win->pty_master_fd = -1;
        }
        /* n < 0 with errno=EAGAIN is normal (no data) */
    }
}

/* ============================================================================
 * IPC Event Delivery — Send Events to Connected Clients
 *
 * When a HID event targets a client-managed window, we forward it to
 * the owning client's event port. This is how macOS WindowServer sends
 * NSEvent to applications (through CGSConnection event port).
 * ============================================================================ */

/*
 * ws_cleanup_dead_connection - Clean up after a client whose port has died.
 *
 * On macOS, WindowServer receives MACH_NOTIFY_DEAD_NAME when a client dies.
 * We detect dead clients when mach_msg send fails with an error other than
 * MACH_SEND_TIMED_OUT (which indicates a full queue, not a dead port).
 *
 * This is equivalent to macOS's CGXHandleDeadClient / _CGSConnectionDied.
 */
static void ws_cleanup_dead_connection(int conn_id)
{
    if (conn_id < 0 || conn_id >= WS_MAX_CONNECTIONS) return;
    struct ws_connection *conn = &ws_connections[conn_id];
    if (!conn->active) return;

    printf("[WindowServer] Dead client detected: '%s' (conn %d, pid %d)\n",
           conn->app_name, conn_id, conn->pid);

    /* Close all windows owned by this connection */
    for (int i = 0; i < WS_MAX_WINDOWS; i++) {
        if (ws_windows[i].active && ws_windows[i].conn_id == conn_id) {
            if (ws_windows[i].surface) {
                free(ws_windows[i].surface);
                ws_windows[i].surface = NULL;
            }
            ws_windows[i].active = 0;
            ws_needs_full_redraw = 1;
            if (ws_focus_idx == i)
                ws_focus_idx = -1;
        }
    }

    conn->active = 0;
    if (ws_connection_count > 0)
        ws_connection_count--;

    if (ws_foreground_conn == conn_id) {
        /* Find next active connection for foreground */
        ws_foreground_conn = -1;
        for (int i = 0; i < WS_MAX_CONNECTIONS; i++) {
            if (ws_connections[i].active) {
                ws_foreground_conn = i;
                break;
            }
        }
    }
}

static void ws_send_key_event_to_client(int window_idx, uint32_t msg_id,
                                         uint32_t keycode, uint32_t character,
                                         uint32_t modifiers)
{
    struct ws_window *win = &ws_windows[window_idx];
    if (!win->client_managed || win->conn_id < 0) return;

    struct ws_connection *conn = &ws_connections[win->conn_id];
    if (!conn->active || conn->event_port == MACH_PORT_NULL) return;

    ws_event_key_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    ev.header.msgh_size = sizeof(ev);
    ev.header.msgh_remote_port = conn->event_port;
    ev.header.msgh_id = msg_id;
    ev.window_id = window_idx;
    ev.keycode = keycode;
    ev.characters = character;
    ev.modifiers = modifiers;

    mach_msg_return_t kr = mach_msg(&ev.header,
             MACH_SEND_MSG | MACH_SEND_TIMEOUT,
             sizeof(ev), 0, 0, 50, 0);
    if (kr != MACH_MSG_SUCCESS && kr != MACH_SEND_TIMED_OUT) {
        /* Send failed — client port is likely dead. Clean up connection. */
        ws_cleanup_dead_connection(win->conn_id);
    }
}

static void ws_send_mouse_event_to_client(int window_idx, uint32_t msg_id,
                                            int32_t sx, int32_t sy,
                                            uint32_t button, uint32_t modifiers)
{
    struct ws_window *win = &ws_windows[window_idx];
    if (!win->client_managed || win->conn_id < 0) return;

    struct ws_connection *conn = &ws_connections[win->conn_id];
    if (!conn->active || conn->event_port == MACH_PORT_NULL) return;

    ws_event_mouse_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    ev.header.msgh_size = sizeof(ev);
    ev.header.msgh_remote_port = conn->event_port;
    ev.header.msgh_id = msg_id;
    ev.window_id = window_idx;
    /* Window-relative coordinates */
    ev.x = sx - win->x - WINDOW_BORDER;
    ev.y = sy - win->y - WINDOW_BORDER - TITLEBAR_HEIGHT - 1;
    ev.screen_x = sx;
    ev.screen_y = sy;
    ev.button = button;
    ev.modifiers = modifiers;

    /*
     * Compute click_count for mouseDown events.
     *
     * On macOS, CGSEventRecord tracks multi-click state. If a mouseDown
     * arrives within DOUBLE_CLICK_TIME_MS of the previous mouseDown and
     * within DOUBLE_CLICK_DIST pixels, click_count increments (supporting
     * double-click, triple-click, etc.); otherwise it resets to 1.
     *
     * We only track this for mouseDown — mouseUp/mouseMoved always get 1.
     */
    if (msg_id == WS_EVENT_MOUSE_DOWN) {
        struct timeval now;
        gettimeofday(&now, NULL);

        long elapsed_ms = (now.tv_sec - dc_last_time.tv_sec) * 1000
                        + (now.tv_usec - dc_last_time.tv_usec) / 1000;

        int32_t dx = sx - dc_last_x;
        int32_t dy = sy - dc_last_y;
        if (dx < 0) dx = -dx;
        if (dy < 0) dy = -dy;

        if (elapsed_ms < DOUBLE_CLICK_TIME_MS &&
            dx <= DOUBLE_CLICK_DIST && dy <= DOUBLE_CLICK_DIST) {
            dc_click_count++;
        } else {
            dc_click_count = 1;
        }

        dc_last_time = now;
        dc_last_x = sx;
        dc_last_y = sy;

        ev.click_count = dc_click_count;
    } else {
        ev.click_count = 1;
    }

    {
        mach_msg_return_t mr2 = mach_msg(&ev.header,
                 MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                 sizeof(ev), 0, 0, 50, 0);
        if (mr2 != MACH_MSG_SUCCESS && mr2 != MACH_SEND_TIMED_OUT) {
            /* Send failed — client port is likely dead. Clean up. */
            ws_cleanup_dead_connection(win->conn_id);
        }
    }
}

/* ============================================================================
 * IPC Message Handler
 *
 * Processes one Mach message from the service port. Called from the main
 * loop when mach_msg(MACH_RCV_TIMEOUT) succeeds.
 *
 * On macOS, WindowServer's MIG subsystem handles these messages via
 * CGXServer (SkyLight). We implement the subset needed by AppKit.
 * ============================================================================ */

static void ws_send_reply(mach_port_t reply_port, mach_msg_id_t reply_id,
                           void *reply, mach_msg_size_t size)
{
    mach_msg_header_t *hdr = (mach_msg_header_t *)reply;
    hdr->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    hdr->msgh_size = size;
    hdr->msgh_remote_port = reply_port;
    hdr->msgh_local_port = MACH_PORT_NULL;
    hdr->msgh_id = reply_id;

    mach_msg(hdr, MACH_SEND_MSG | MACH_SEND_TIMEOUT, size, 0, 0, 100, 0);
}

static void ws_handle_ipc_message(mach_msg_header_t *msg)
{
    mach_port_t reply_port = msg->msgh_remote_port;

    /*
     * Ignore msgh_id == 0: these are CFRunLoopWakeUp() messages that
     * occasionally arrive on the service port.  CFRunLoopWakeUp() sends
     * a bare mach_msg_header_t with msgh_id = 0 to wake a sleeping
     * CFRunLoop.  Under certain IPC-space lifecycle conditions these
     * can be delivered to the wrong port.  They are harmless — just
     * discard them silently.
     */
    if (msg->msgh_id == 0)
        return;

    switch (msg->msgh_id) {

    /* ---- WS_MSG_CONNECT ---- */
    case WS_MSG_CONNECT: {
        ws_msg_connect_t *req = (ws_msg_connect_t *)msg;
        ws_reply_connect_t reply;
        memset(&reply, 0, sizeof(reply));

        /* Find a free connection slot */
        int slot = -1;
        for (int i = 0; i < WS_MAX_CONNECTIONS; i++) {
            if (!ws_connections[i].active) {
                slot = i;
                break;
            }
        }

        if (slot < 0) {
            reply.conn_id = -1;
            reply.result = KERN_RESOURCE_SHORTAGE;
        } else {
            struct ws_connection *conn = &ws_connections[slot];
            memset(conn, 0, sizeof(*conn));
            conn->active = 1;
            conn->conn_id = slot;
            conn->event_port = reply_port;  /* Client's reply port becomes event port */
            conn->pid = req->pid;
            strncpy(conn->app_name, req->app_name, sizeof(conn->app_name) - 1);
            ws_connection_count++;

            /* If no foreground app yet, make this one foreground */
            if (ws_foreground_conn < 0)
                ws_foreground_conn = slot;

            printf("[WindowServer] Client connected: '%s' (PID %d) → conn %d\n",
                   conn->app_name, conn->pid, slot);

            reply.conn_id = slot;
            reply.result = KERN_SUCCESS;
        }

        /* Reply via the client's send-once right that came in msgh_local_port */
        ws_send_reply(reply_port, WS_REPLY_CONNECT, &reply, sizeof(reply));
        break;
    }

    /* ---- WS_MSG_DISCONNECT ---- */
    case WS_MSG_DISCONNECT: {
        ws_msg_connect_t *req = (ws_msg_connect_t *)msg;
        int32_t cid = req->pid;  /* Re-use pid field for conn_id in disconnect */

        /* Actually, disconnect passes conn_id differently. Let's use a generic approach */
        /* Extract conn_id from after header */
        int32_t conn_id = *(int32_t *)(msg + 1);

        if (conn_id >= 0 && conn_id < WS_MAX_CONNECTIONS &&
            ws_connections[conn_id].active) {
            struct ws_connection *conn = &ws_connections[conn_id];
            printf("[WindowServer] Client disconnected: '%s' (conn %d)\n",
                   conn->app_name, conn_id);

            /* Close all windows owned by this connection */
            for (int i = 0; i < WS_MAX_WINDOWS; i++) {
                if (ws_windows[i].active && ws_windows[i].conn_id == conn_id) {
                    if (ws_windows[i].surface) {
                        free(ws_windows[i].surface);
                        ws_windows[i].surface = NULL;
                    }
                    ws_windows[i].active = 0;
                    ws_needs_full_redraw = 1;
                    if (ws_focus_idx == i)
                        ws_focus_idx = -1;
                }
            }

            conn->active = 0;
            ws_connection_count--;

            if (ws_foreground_conn == conn_id) {
                /* Find next active connection for foreground */
                ws_foreground_conn = -1;
                for (int i = 0; i < WS_MAX_CONNECTIONS; i++) {
                    if (ws_connections[i].active) {
                        ws_foreground_conn = i;
                        break;
                    }
                }
            }
        }

        if (reply_port != MACH_PORT_NULL) {
            ws_reply_generic_t reply;
            memset(&reply, 0, sizeof(reply));
            reply.result = KERN_SUCCESS;
            ws_send_reply(reply_port, WS_REPLY_GENERIC, &reply, sizeof(reply));
        }
        break;
    }

    /* ---- WS_MSG_CREATE_WINDOW ---- */
    case WS_MSG_CREATE_WINDOW: {
        ws_msg_create_window_t *req = (ws_msg_create_window_t *)msg;
        ws_reply_create_window_t reply;
        memset(&reply, 0, sizeof(reply));

        if (req->conn_id < 0 || req->conn_id >= WS_MAX_CONNECTIONS ||
            !ws_connections[req->conn_id].active) {
            reply.window_id = -1;
            reply.result = KERN_INVALID_ARGUMENT;
        } else if (ws_window_count >= WS_MAX_WINDOWS) {
            reply.window_id = -1;
            reply.result = KERN_RESOURCE_SHORTAGE;
        } else {
            int idx = ws_window_count;
            struct ws_window *win = &ws_windows[idx];
            memset(win, 0, sizeof(*win));

            uint32_t cw = req->width;
            uint32_t ch = req->height;
            if (cw == 0) cw = 400;
            if (ch == 0) ch = 300;
            if (cw > WS_MAX_WIDTH) cw = WS_MAX_WIDTH;
            if (ch > WS_MAX_HEIGHT) ch = WS_MAX_HEIGHT;

            win->active = 1;
            win->x = req->x;
            win->y = req->y;
            win->style_mask = req->style_mask;

            if (req->style_mask == NSWindowStyleMaskBorderless) {
                /* Borderless: no title bar, no border — content IS the window */
                win->width = cw;
                win->height = ch;
            } else {
                /* Titled: add title bar + border chrome */
                win->width = cw + 2 * WINDOW_BORDER;
                win->height = ch + TITLEBAR_HEIGHT + 2 * WINDOW_BORDER + 1;
            }

            strncpy(win->title, req->title, sizeof(win->title) - 1);
            win->client_managed = 1;
            win->conn_id = req->conn_id;
            win->surface_width = cw;
            win->surface_height = ch;
            win->surface = (uint32_t *)calloc(cw * ch, sizeof(uint32_t));
            win->pty_master_fd = -1;
            win->pty_slave_fd = -1;
            win->shell_pid = -1;
            win->visible = 1;
            win->needs_redraw = 1;

            ws_window_count++;
            ws_focus_idx = idx;

            /* Track in connection */
            struct ws_connection *conn = &ws_connections[req->conn_id];
            if (conn->window_count < WS_MAX_WINDOWS) {
                conn->window_ids[conn->window_count++] = idx;
            }

            /* Make this the foreground app */
            ws_foreground_conn = req->conn_id;

            printf("[WindowServer] Created client window %d: '%s' (%ux%u) "
                   "for conn %d\n", idx, win->title, cw, ch, req->conn_id);

            reply.window_id = idx;
            reply.result = KERN_SUCCESS;
        }

        ws_send_reply(reply_port, WS_REPLY_CREATE_WINDOW,
                       &reply, sizeof(reply));
        break;
    }

    /* ---- WS_MSG_DESTROY_WINDOW ---- */
    case WS_MSG_DESTROY_WINDOW: {
        ws_msg_destroy_window_t *req = (ws_msg_destroy_window_t *)msg;

        if (req->window_id >= 0 && req->window_id < WS_MAX_WINDOWS &&
            ws_windows[req->window_id].active &&
            ws_windows[req->window_id].conn_id == req->conn_id) {
            struct ws_window *win = &ws_windows[req->window_id];
            if (win->surface) {
                free(win->surface);
                win->surface = NULL;
            }
            win->active = 0;
            ws_needs_full_redraw = 1;
            if (ws_focus_idx == req->window_id)
                ws_focus_idx = -1;
        }

        if (reply_port != MACH_PORT_NULL) {
            ws_reply_generic_t reply;
            memset(&reply, 0, sizeof(reply));
            reply.result = KERN_SUCCESS;
            ws_send_reply(reply_port, WS_REPLY_GENERIC,
                           &reply, sizeof(reply));
        }
        break;
    }

    /* ---- WS_MSG_ORDER_WINDOW ---- */
    case WS_MSG_ORDER_WINDOW: {
        ws_msg_order_window_t *req = (ws_msg_order_window_t *)msg;

        if (req->window_id >= 0 && req->window_id < WS_MAX_WINDOWS &&
            ws_windows[req->window_id].active &&
            ws_windows[req->window_id].conn_id == req->conn_id) {
            struct ws_window *win = &ws_windows[req->window_id];
            switch (req->order) {
            case WS_ORDER_OUT:
                win->visible = 0;
                ws_needs_full_redraw = 1;   /* Repaint desktop under hidden window */
                break;
            case WS_ORDER_FRONT:
                win->visible = 1;
                ws_focus_idx = req->window_id;
                ws_foreground_conn = req->conn_id;
                win->needs_redraw = 1;
                break;
            case WS_ORDER_BACK:
                win->visible = 1;
                break;
            }
        }

        if (reply_port != MACH_PORT_NULL) {
            ws_reply_generic_t reply;
            memset(&reply, 0, sizeof(reply));
            reply.result = KERN_SUCCESS;
            ws_send_reply(reply_port, WS_REPLY_GENERIC,
                           &reply, sizeof(reply));
        }
        break;
    }

    /* ---- WS_MSG_SET_TITLE ---- */
    case WS_MSG_SET_TITLE: {
        ws_msg_set_title_t *req = (ws_msg_set_title_t *)msg;

        if (req->window_id >= 0 && req->window_id < WS_MAX_WINDOWS &&
            ws_windows[req->window_id].active &&
            ws_windows[req->window_id].conn_id == req->conn_id) {
            strncpy(ws_windows[req->window_id].title, req->title,
                    sizeof(ws_windows[req->window_id].title) - 1);
            ws_windows[req->window_id].needs_redraw = 1;
        }

        if (reply_port != MACH_PORT_NULL) {
            ws_reply_generic_t reply;
            memset(&reply, 0, sizeof(reply));
            reply.result = KERN_SUCCESS;
            ws_send_reply(reply_port, WS_REPLY_GENERIC,
                           &reply, sizeof(reply));
        }
        break;
    }

    /* ---- WS_MSG_SET_FRAME ---- */
    case WS_MSG_SET_FRAME: {
        ws_msg_set_frame_t *req = (ws_msg_set_frame_t *)msg;

        if (req->window_id >= 0 && req->window_id < WS_MAX_WINDOWS &&
            ws_windows[req->window_id].active &&
            ws_windows[req->window_id].conn_id == req->conn_id) {
            struct ws_window *win = &ws_windows[req->window_id];
            win->x = req->x;
            win->y = req->y;
            if (req->width > 0 && req->height > 0) {
                /* Resize: reallocate surface */
                uint32_t cw = req->width;
                uint32_t ch = req->height;
                if (cw > WS_MAX_WIDTH) cw = WS_MAX_WIDTH;
                if (ch > WS_MAX_HEIGHT) ch = WS_MAX_HEIGHT;

                win->width = cw + 2 * WINDOW_BORDER;
                win->height = ch + TITLEBAR_HEIGHT + 2 * WINDOW_BORDER + 1;

                if (win->surface) free(win->surface);
                win->surface_width = cw;
                win->surface_height = ch;
                win->surface = (uint32_t *)calloc(cw * ch, sizeof(uint32_t));
            }
            win->needs_redraw = 1;
        }

        if (reply_port != MACH_PORT_NULL) {
            ws_reply_generic_t reply;
            memset(&reply, 0, sizeof(reply));
            reply.result = KERN_SUCCESS;
            ws_send_reply(reply_port, WS_REPLY_GENERIC,
                           &reply, sizeof(reply));
        }
        break;
    }

    /* ---- WS_MSG_DRAW_RECT ---- */
    case WS_MSG_DRAW_RECT: {
        ws_msg_draw_rect_t *req = (ws_msg_draw_rect_t *)msg;

        if (req->window_id >= 0 && req->window_id < WS_MAX_WINDOWS &&
            ws_windows[req->window_id].active &&
            ws_windows[req->window_id].conn_id == req->conn_id &&
            ws_windows[req->window_id].surface) {

            struct ws_window *win = &ws_windows[req->window_id];

            /* Check for OOL pixel data */
            if ((req->header.msgh_bits & MACH_MSGH_BITS_COMPLEX) &&
                req->body.msgh_descriptor_count >= 1 &&
                req->surface_desc.address != NULL) {

                uint32_t *src = (uint32_t *)req->surface_desc.address;
                uint32_t dw = req->width;
                uint32_t dh = req->height;
                uint32_t dx = req->dst_x;
                uint32_t dy = req->dst_y;
                uint32_t src_stride = req->src_rowbytes / 4;

                /* Blit into window surface */
                for (uint32_t y = 0; y < dh; y++) {
                    if (dy + y >= win->surface_height) break;
                    uint32_t *dst_row = &win->surface[(dy + y) * win->surface_width];
                    uint32_t *src_row = &src[y * src_stride];
                    for (uint32_t x = 0; x < dw; x++) {
                        if (dx + x >= win->surface_width) break;
                        dst_row[dx + x] = src_row[x];
                    }
                }
                win->needs_redraw = 1;

                /* Free the OOL pages mapped by the kernel into our VA space */
                munmap(req->surface_desc.address, req->surface_desc.size);
            }
        }

        /* DRAW_RECT is fire-and-forget — no reply needed */
        /* But if client sent with reply port, acknowledge */
        if (reply_port != MACH_PORT_NULL) {
            ws_reply_generic_t reply;
            memset(&reply, 0, sizeof(reply));
            reply.result = KERN_SUCCESS;
            ws_send_reply(reply_port, WS_REPLY_GENERIC,
                           &reply, sizeof(reply));
        }
        break;
    }

    /* ---- WS_MSG_SET_MENU ---- */
    case WS_MSG_SET_MENU: {
        ws_msg_set_menu_t *req = (ws_msg_set_menu_t *)msg;

        if (req->conn_id >= 0 && req->conn_id < WS_MAX_CONNECTIONS &&
            ws_connections[req->conn_id].active) {
            struct ws_connection *conn = &ws_connections[req->conn_id];
            conn->menu_item_count = (int)req->item_count;
            if (conn->menu_item_count > WS_MAX_MENU_ITEMS)
                conn->menu_item_count = WS_MAX_MENU_ITEMS;

            for (int i = 0; i < conn->menu_item_count; i++) {
                strncpy(conn->menu_items[i].title, req->items[i].title,
                        WS_MENU_TITLE_MAX - 1);
                conn->menu_items[i].tag = req->items[i].tag;
                conn->menu_items[i].enabled = req->items[i].enabled;
            }

            printf("[WindowServer] Menu updated for conn %d: %d items\n",
                   req->conn_id, conn->menu_item_count);
        }

        if (reply_port != MACH_PORT_NULL) {
            ws_reply_generic_t reply;
            memset(&reply, 0, sizeof(reply));
            reply.result = KERN_SUCCESS;
            ws_send_reply(reply_port, WS_REPLY_GENERIC,
                           &reply, sizeof(reply));
        }
        break;
    }

    /* ---- WS_MSG_CREATE_PTY_WINDOW ---- */
    case WS_MSG_CREATE_PTY_WINDOW: {
        ws_msg_create_pty_window_t *req = (ws_msg_create_pty_window_t *)msg;
        ws_reply_create_pty_window_t reply;
        memset(&reply, 0, sizeof(reply));

        if (req->conn_id < 0 || req->conn_id >= WS_MAX_CONNECTIONS ||
            !ws_connections[req->conn_id].active) {
            reply.window_id = -1;
            reply.result = KERN_INVALID_ARGUMENT;
        } else {
            int idx = ws_create_terminal_window(req->title, req->x, req->y);
            if (idx >= 0) {
                /* Mark this terminal window as belonging to the connection */
                ws_windows[idx].conn_id = req->conn_id;
                struct ws_connection *conn = &ws_connections[req->conn_id];
                if (conn->window_count < WS_MAX_WINDOWS)
                    conn->window_ids[conn->window_count++] = idx;
                ws_foreground_conn = req->conn_id;

                reply.window_id = idx;
                reply.result = KERN_SUCCESS;
            } else {
                reply.window_id = -1;
                reply.result = KERN_RESOURCE_SHORTAGE;
            }
        }

        ws_send_reply(reply_port, WS_REPLY_CREATE_PTY_WINDOW,
                       &reply, sizeof(reply));
        break;
    }

    default:
        fprintf(stderr, "[WindowServer] Unknown message ID: %d\n", msg->msgh_id);
        if (reply_port != MACH_PORT_NULL) {
            ws_reply_generic_t reply;
            memset(&reply, 0, sizeof(reply));
            reply.result = KERN_INVALID_ARGUMENT;
            ws_send_reply(reply_port, WS_REPLY_GENERIC,
                           &reply, sizeof(reply));
        }
        break;
    }
}

/* ============================================================================
 * Main Entry Point
 * ============================================================================ */

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    printf("[WindowServer] Starting (PID %d)\n", getpid());

    /* Ignore SIGPIPE (writes to closed PTY) */
    signal(SIGPIPE, SIG_IGN);

    /* ----------------------------------------------------------------
     * Step 1: Claim Mach service port
     * ---------------------------------------------------------------- */
    mach_port_t service_port = MACH_PORT_NULL;
    kern_return_t kr = bootstrap_check_in(
        MACH_PORT_NULL, WS_SERVICE_NAME, &service_port);

    if (kr != KERN_SUCCESS || service_port == MACH_PORT_NULL) {
        fprintf(stderr, "[WindowServer] bootstrap_check_in failed: %d\n", kr);
        fprintf(stderr, "[WindowServer] Allocating own service port\n");
        kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
                                &service_port);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "[WindowServer] FATAL: Cannot allocate port\n");
            return 1;
        }
        bootstrap_register(MACH_PORT_NULL, WS_SERVICE_NAME, service_port);
    }
    printf("[WindowServer] Claimed service port %u\n", service_port);

    /* ----------------------------------------------------------------
     * Step 2: Open IOFramebuffer and map VRAM
     * ---------------------------------------------------------------- */
    if (ws_open_framebuffer() != 0) {
        fprintf(stderr, "[WindowServer] FATAL: Cannot open framebuffer\n");
        return 1;
    }

    /* ----------------------------------------------------------------
     * Step 3: Open IOHIDSystem and map event ring
     * ---------------------------------------------------------------- */
    if (ws_open_hid_system() != 0) {
        fprintf(stderr, "[WindowServer] WARNING: No HID — continuing without input\n");
    }

    /* ----------------------------------------------------------------
     * Step 4: Initialise connection table and window state
     * ---------------------------------------------------------------- */
    memset(ws_windows, 0, sizeof(ws_windows));
    memset(ws_connections, 0, sizeof(ws_connections));

    /* Centre cursor on screen */
    cursor_x = (int32_t)(ws_fb_width / 2);
    cursor_y = (int32_t)(ws_fb_height / 2);

    /* ----------------------------------------------------------------
     * Step 5: Draw initial desktop (blue background + menu bar)
     *
     * The login UI is now handled by /sbin/loginwindow, which connects
     * to us via Mach IPC just like any other AppKit client.
     * ---------------------------------------------------------------- */
    ws_draw_desktop();
    ws_cursor_save(cursor_x, cursor_y);
    ws_cursor_draw(cursor_x, cursor_y);
    cursor_visible = 1;
    ws_flush_display();

    printf("[WindowServer] Desktop drawn, entering event loop\n");

    /* ----------------------------------------------------------------
     * Step 6: Main event loop (~60 Hz)
     *
     * On macOS, WindowServer uses CFRunLoop with mach_msg and
     * IOHIDSystem event sources. We combine:
     *   1. mach_msg(MACH_RCV_TIMEOUT, 16ms) — receive IPC from clients
     *   2. Process HID events from shared memory ring
     *   3. Read PTY master output
     *   4. Redraw dirty windows
     *   5. Composite cursor
     *   6. Flush framebuffer
     *
     * The mach_msg timeout replaces usleep(16000) — the 16ms timeout
     * provides the ~60Hz cadence while also receiving client messages
     * with zero additional latency.
     * ---------------------------------------------------------------- */
    ws_msg_buffer_t ipc_buf;

    static uint32_t ws_loop_count = 0;
    for (;;) {
        ws_loop_count++;

        if (ws_loop_count == 1) {
            printf("[WindowServer] First loop iteration starting\n");
        }

        /* 1. Check for IPC messages from clients (non-blocking / 16ms timeout)
         *
         * On macOS, WindowServer uses mach_msg_server() with CFRunLoop.
         * We do a single mach_msg receive with MACH_RCV_TIMEOUT to
         * process at most one message per frame, then proceed with
         * rendering. Multiple messages per frame are handled by doing
         * a tight loop of non-blocking receives before rendering.
         */
        for (int ipc_batch = 0; ipc_batch < 32; ipc_batch++) {
            memset(&ipc_buf, 0, sizeof(mach_msg_header_t));
            mach_msg_return_t mr = mach_msg(
                &ipc_buf.header,
                MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                0,                              /* send_size */
                sizeof(ipc_buf),               /* rcv_size */
                service_port,                  /* rcv_name */
                (ipc_batch == 0) ? 16 : 0,    /* timeout: 16ms first, then 0 */
                MACH_PORT_NULL);               /* notify */

            if (ws_loop_count <= 2 && ipc_batch == 0) {
                printf("[WindowServer] loop=%u mach_msg returned %d\n",
                       ws_loop_count, (int)mr);
            }

            if (mr == MACH_MSG_SUCCESS) {
                ws_handle_ipc_message(&ipc_buf.header);
            } else {
                break;  /* MACH_RCV_TIMED_OUT or error — no more messages */
            }
        }

        /* 2. Process HID events */
        ws_process_hid_events();

        /* Diagnostic: log loop progress every 256 iterations */
        if ((ws_loop_count & 0xFF) == 0) {
            printf("[WindowServer] loop=%u hid_ridx=%u hid_widx=%u\n",
                   ws_loop_count,
                   ws_hid_ring ? ws_hid_ring->read_idx : 0,
                   ws_hid_ring ? ws_hid_ring->write_idx : 0);
        }

        /* 3. Read PTY output */
        ws_process_pty_output();

        /* 4. Redraw */
        int needs_flush = 0;

        /* Restore cursor (erase from VRAM) before any drawing */
        if (cursor_visible) {
            ws_cursor_restore();
            cursor_visible = 0;
        }

        /* Redraw windows if any are dirty or a window was recently destroyed */
        {
            int any_dirty = ws_needs_full_redraw;
            ws_needs_full_redraw = 0;
            for (int i = 0; i < ws_window_count; i++) {
                if (ws_windows[i].active && ws_windows[i].visible &&
                    (ws_windows[i].needs_redraw ||
                     (!ws_windows[i].client_managed && ws_windows[i].term.dirty)))
                    any_dirty = 1;
            }

            if (any_dirty) {
                /* Full redraw: desktop + all visible windows back-to-front */
                ws_draw_desktop();
                for (int i = 0; i < ws_window_count; i++) {
                    if (ws_windows[i].active && ws_windows[i].visible)
                        ws_draw_window(&ws_windows[i]);
                }
                needs_flush = 1;
            }
        }

        /* 5. Draw cursor at (possibly updated) position.
         *
         * Save-under compositing: save pixels underneath the cursor,
         * draw the cursor sprite, mark visible. On the next frame,
         * ws_cursor_restore() puts the saved pixels back — erasing
         * the cursor cleanly before any new drawing.
         *
         * The save always happens AFTER any full redraw, so the
         * save-under captures clean (cursor-free) background pixels.
         */
        ws_cursor_save(cursor_x, cursor_y);
        ws_cursor_draw(cursor_x, cursor_y);
        cursor_visible = 1;
        needs_flush = 1;  /* Always flush — cursor may have moved */

        /* 6. Flush */
        if (needs_flush)
            ws_flush_display();
    }

    /* Unreachable */
    IOServiceClose(ws_fb_connect);
    if (ws_hid_connect != IO_OBJECT_NULL)
        IOServiceClose(ws_hid_connect);
    return 0;
}

