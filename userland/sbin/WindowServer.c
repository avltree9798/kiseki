/*
 * Kiseki OS - WindowServer
 *
 * Full compositing window server with Mach IPC. Handles client connections,
 * window creation, pixel blitting, z-ordered compositing, title bar drawing,
 * menu bar, cursor, and HID event dispatch to clients.
 *
 * Architecture (matching macOS WindowServer / SkyLight):
 *   - Single service port receives all client requests
 *   - Each client gets a connection ID and an event port (for WS→client events)
 *   - Windows have backing stores; clients blit pixels via DRAW_RECT (OOL Mach msg)
 *   - Compositor merges: desktop + windows (back-to-front) + cursor → framebuffer
 *   - HID events from kernel ring → routed to topmost window's client event port
 *
 * IPC protocol matches AppKit.m Section 8-9 exactly.
 *
 * Boot chain: kernel → init → WindowServer
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <IOKit/IOKitLib.h>
#include <sys/mman.h>

/* ============================================================================
 * Constants
 * ============================================================================ */

#define WS_SERVICE_NAME     "uk.co.avltree9798.WindowServer"
#define TABLET_ABS_MAX      32767

#define MAX_CLIENTS         16
#define MAX_WINDOWS         64
#define MAX_MENU_ITEMS      16
#define MENU_TITLE_MAX      32

#define TITLEBAR_H          22
#define MENUBAR_H           22

/* ============================================================================
 * IPC Protocol — must match AppKit.m exactly
 * ============================================================================ */

/* Client → Server message IDs */
#define WS_MSG_CONNECT          1000
#define WS_MSG_DISCONNECT       1001
#define WS_MSG_CREATE_WINDOW    1010
#define WS_MSG_DESTROY_WINDOW   1011
#define WS_MSG_ORDER_WINDOW     1012
#define WS_MSG_SET_TITLE        1013
#define WS_MSG_SET_FRAME        1014
#define WS_MSG_DRAW_RECT        1020
#define WS_MSG_SET_MENU         1030

/* Server → Client reply IDs */
#define WS_REPLY_CONNECT        2000
#define WS_REPLY_CREATE_WINDOW  2010
#define WS_REPLY_GENERIC        2099

/* Server → Client event IDs */
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

/* Window ordering */
#define WS_ORDER_OUT    0
#define WS_ORDER_FRONT  1
#define WS_ORDER_BACK   2

/* ============================================================================
 * IPC Message Structures — must match AppKit.m layout exactly
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
    mach_msg_header_t   header;
    int32_t             conn_id;
    int32_t             window_id;
} ws_msg_destroy_window_t;

typedef struct {
    mach_msg_header_t   header;
    int32_t             conn_id;
    int32_t             window_id;
    int32_t             order;
} ws_msg_order_window_t;

typedef struct {
    mach_msg_header_t   header;
    int32_t             conn_id;
    int32_t             window_id;
    char                title[64];
} ws_msg_set_title_t;

typedef struct {
    mach_msg_header_t   header;
    int32_t             conn_id;
    int32_t             window_id;
    int32_t             x, y;
    uint32_t            width, height;
} ws_msg_set_frame_t;

typedef struct {
    mach_msg_header_t           header;
    mach_msg_body_t             body;
    mach_msg_ool_descriptor_t   surface_desc;
    int32_t                     conn_id;
    int32_t                     window_id;
    uint32_t                    dst_x, dst_y;
    uint32_t                    width, height;
    uint32_t                    src_rowbytes;
} ws_msg_draw_rect_t;

typedef struct {
    mach_msg_header_t   header;
    int32_t             conn_id;
    uint32_t            item_count;
    struct {
        char            title[MENU_TITLE_MAX];
        int32_t         tag;
        int32_t         enabled;
    } items[MAX_MENU_ITEMS];
} ws_msg_set_menu_t;

/* Event messages (Server → Client) */
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

typedef struct {
    mach_msg_header_t   header;
    int32_t             window_id;
} ws_event_window_t;

/* Receive buffer — large enough for any message including OOL */
typedef union {
    mach_msg_header_t   header;
    ws_msg_connect_t    connect;
    ws_msg_create_window_t create_window;
    ws_msg_draw_rect_t  draw_rect;
    ws_msg_set_menu_t   set_menu;
    uint8_t             raw[4096 + 256];
} ws_rcv_buffer_t;

/* ============================================================================
 * Colours — BGRA (VirtIO GPU B8G8R8X8)
 * ============================================================================ */

static inline uint32_t rgb(uint8_t r, uint8_t g, uint8_t b)
{
    return (uint32_t)b | ((uint32_t)g << 8) |
           ((uint32_t)r << 16) | (0xFFu << 24);
}

#define COL_DESKTOP         rgb(0x3A, 0x6E, 0xA5)
#define COL_MENUBAR         rgb(0xEA, 0xEA, 0xEA)
#define COL_MENUBAR_TEXT    rgb(0x00, 0x00, 0x00)
#define COL_MENUBAR_SEP     rgb(0xB4, 0xB4, 0xB4)
#define COL_BLACK           rgb(0x00, 0x00, 0x00)
#define COL_WHITE           rgb(0xFF, 0xFF, 0xFF)
#define COL_TITLEBAR_ACTIVE rgb(0xE8, 0xE8, 0xE8)
#define COL_TITLEBAR_INACTIVE rgb(0xF6, 0xF6, 0xF6)
#define COL_TITLEBAR_TEXT   rgb(0x4D, 0x4D, 0x4D)
#define COL_TITLEBAR_SEP    rgb(0xC0, 0xC0, 0xC0)
#define COL_CLOSE_BTN       rgb(0xFF, 0x5F, 0x57)
#define COL_WINDOW_SHADOW   rgb(0x40, 0x40, 0x40)

/* ============================================================================
 * HID Event Ring (must match kernel hid_event.h exactly)
 * ============================================================================ */

#define HID_EVENT_RING_SIZE     256
#define HID_EVENT_KEY_DOWN      1
#define HID_EVENT_KEY_UP        2
#define HID_EVENT_MOUSE_MOVE    3
#define HID_EVENT_MOUSE_DOWN    4
#define HID_EVENT_MOUSE_UP      5

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
 * HID Modifier Flags (must match kernel hid_event.h)
 * ============================================================================ */

#define HID_FLAG_SHIFT      (1 << 0)
#define HID_FLAG_CTRL       (1 << 1)
#define HID_FLAG_ALT        (1 << 2)
#define HID_FLAG_CAPSLOCK   (1 << 3)

/* ============================================================================
 * Keycode-to-ASCII Translation (US QWERTY)
 *
 * Must match kernel/drivers/virtio/virtio_input.c keymaps exactly.
 * Linux keycodes 0-127.  0 = no printable character.
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

/*
 * keycode_to_char - Convert a Linux keycode + HID modifier flags to ASCII.
 *
 * Handles shift, capslock, and ctrl modifiers.
 * Returns 0 for non-printable keys (modifiers, function keys, etc.)
 */
static uint32_t keycode_to_char(uint32_t code, uint32_t flags)
{
    if (code >= 128)
        return 0;

    bool shifted = (flags & HID_FLAG_SHIFT) != 0;
    bool capslock = (flags & HID_FLAG_CAPSLOCK) != 0;

    /* Caps lock toggles shift for letter keys only */
    if (capslock && keymap_normal[code] >= 'a' && keymap_normal[code] <= 'z')
        shifted = !shifted;

    char c = shifted ? keymap_shift[code] : keymap_normal[code];

    /* Ctrl+letter produces control character (Ctrl+A=0x01 .. Ctrl+Z=0x1A) */
    if ((flags & HID_FLAG_CTRL) && c != 0) {
        if (c >= 'a' && c <= 'z')
            return (uint32_t)(c - 'a' + 1);
        if (c >= 'A' && c <= 'Z')
            return (uint32_t)(c - 'A' + 1);
    }

    return (uint32_t)(unsigned char)c;
}

/* ============================================================================
 * 8x16 bitmap font (embedded)
 * ============================================================================ */

#include "font8x16.inc"  /* provides lw_font8x16[256][16] */
#define font8x16_data lw_font8x16

#define FONT_W  8
#define FONT_H  16

/* ============================================================================
 * Client Connection
 * ============================================================================ */

struct ws_client {
    bool            active;
    int32_t         conn_id;
    mach_port_t     event_port;     /* Send right to client's event port */
    int32_t         pid;
    char            app_name[64];
    /* Active menu for this client */
    uint32_t        menu_count;
    struct {
        char        title[MENU_TITLE_MAX];
        int32_t     tag;
        int32_t     enabled;
    } menu_items[MAX_MENU_ITEMS];
};

static struct ws_client clients[MAX_CLIENTS];
static int32_t next_conn_id = 1;

/* ============================================================================
 * Window
 * ============================================================================ */

#define WS_STYLE_TITLED     (1 << 0)
#define WS_STYLE_CLOSABLE   (1 << 1)

struct ws_window {
    bool            active;
    int32_t         window_id;
    int32_t         conn_id;        /* Owning client */
    int32_t         x, y;           /* Screen position (top of content area) */
    uint32_t        width, height;  /* Content size */
    uint32_t        style_mask;
    char            title[64];
    bool            visible;
    bool            is_key;         /* Frontmost / key window */

    /* Backing store — BGRA pixels, allocated by WindowServer */
    uint32_t       *backing;
    uint32_t        backing_stride; /* pixels per row */
};

static struct ws_window windows[MAX_WINDOWS];
static int32_t next_window_id = 1;

/* Z-order: indices into windows[], front (top) first */
static int32_t z_order[MAX_WINDOWS];
static int     z_count = 0;

/* Currently focused (key) window index in z_order */
static int32_t key_window_id = -1;

/* ============================================================================
 * Framebuffer State
 * ============================================================================ */

static io_connect_t     fb_conn = IO_OBJECT_NULL;
static volatile uint32_t *fb_pixels = NULL;
static uint32_t         fb_w = 0, fb_h = 0, fb_pitch = 0;

/* HID state */
static io_connect_t     hid_conn = IO_OBJECT_NULL;
static struct hid_event_ring *hid_ring = NULL;

/* Cursor */
static int32_t  cur_x = 0, cur_y = 0;
static bool     mouse_is_down = false;
static int32_t  drag_window_id = -1;     /* Window being dragged by title bar */
static int32_t  drag_offset_x = 0, drag_offset_y = 0;

/* Service port */
static mach_port_t svc_port = MACH_PORT_NULL;

/* Compositing dirty flag */
static bool compositor_dirty = true;

/* Active client whose menu is shown in the menu bar */
static int32_t active_menu_conn_id = -1;

/* ============================================================================
 * Cursor bitmap
 * ============================================================================ */

#define CURSOR_W 12
#define CURSOR_H 18
static uint32_t cursor_under[CURSOR_W * CURSOR_H];
static int32_t  cursor_saved_x = -1, cursor_saved_y = -1;

static const uint8_t cursor_bmp[CURSOR_H][CURSOR_W] = {
    {1,0,0,0,0,0,0,0,0,0,0,0},
    {1,1,0,0,0,0,0,0,0,0,0,0},
    {1,2,1,0,0,0,0,0,0,0,0,0},
    {1,2,2,1,0,0,0,0,0,0,0,0},
    {1,2,2,2,1,0,0,0,0,0,0,0},
    {1,2,2,2,2,1,0,0,0,0,0,0},
    {1,2,2,2,2,2,1,0,0,0,0,0},
    {1,2,2,2,2,2,2,1,0,0,0,0},
    {1,2,2,2,2,2,2,2,1,0,0,0},
    {1,2,2,2,2,2,2,2,2,1,0,0},
    {1,2,2,2,2,2,1,1,1,1,1,0},
    {1,2,2,1,2,2,1,0,0,0,0,0},
    {1,2,1,0,1,2,2,1,0,0,0,0},
    {1,1,0,0,1,2,2,1,0,0,0,0},
    {1,0,0,0,0,1,2,2,1,0,0,0},
    {0,0,0,0,0,1,2,2,1,0,0,0},
    {0,0,0,0,0,0,1,2,1,0,0,0},
    {0,0,0,0,0,0,1,1,0,0,0,0},
};

/* ============================================================================
 * Drawing Primitives
 * ============================================================================ */

static inline uint32_t pixel_stride(void) { return fb_pitch / 4; }

static inline void put_pixel(uint32_t x, uint32_t y, uint32_t c)
{
    if (x < fb_w && y < fb_h)
        fb_pixels[y * pixel_stride() + x] = c;
}

static inline uint32_t get_pixel(uint32_t x, uint32_t y)
{
    if (x < fb_w && y < fb_h)
        return fb_pixels[y * pixel_stride() + x];
    return 0;
}

static void fill_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint32_t c)
{
    uint32_t stride = pixel_stride();
    uint32_t xe = x + w, ye = y + h;
    if (xe > fb_w) xe = fb_w;
    if (ye > fb_h) ye = fb_h;
    for (uint32_t py = y; py < ye; py++) {
        volatile uint32_t *row = &fb_pixels[py * stride];
        for (uint32_t px = x; px < xe; px++)
            row[px] = c;
    }
}

static void draw_char(uint32_t px, uint32_t py, unsigned char ch,
                      uint32_t fg, uint32_t bg)
{
    const uint8_t *glyph = font8x16_data[ch];
    uint32_t stride = pixel_stride();
    for (uint32_t y = 0; y < FONT_H && py + y < fb_h; y++) {
        uint8_t bits = glyph[y];
        volatile uint32_t *row = &fb_pixels[(py + y) * stride];
        for (uint32_t x = 0; x < FONT_W && px + x < fb_w; x++)
            row[px + x] = (bits & (0x80 >> x)) ? fg : bg;
    }
}

/* Draw char with transparent background (only draws foreground pixels) */
static void draw_char_transparent(uint32_t px, uint32_t py, unsigned char ch,
                                  uint32_t fg)
{
    const uint8_t *glyph = font8x16_data[ch];
    uint32_t stride = pixel_stride();
    for (uint32_t y = 0; y < FONT_H && py + y < fb_h; y++) {
        uint8_t bits = glyph[y];
        volatile uint32_t *row = &fb_pixels[(py + y) * stride];
        for (uint32_t x = 0; x < FONT_W && px + x < fb_w; x++) {
            if (bits & (0x80 >> x))
                row[px + x] = fg;
        }
    }
}

static void draw_string(uint32_t px, uint32_t py, const char *s,
                        uint32_t fg, uint32_t bg) __attribute__((unused));
static void draw_string(uint32_t px, uint32_t py, const char *s,
                        uint32_t fg, uint32_t bg)
{
    while (*s) {
        if (px + FONT_W > fb_w) break;
        draw_char(px, py, (unsigned char)*s++, fg, bg);
        px += FONT_W;
    }
}

static void draw_string_transparent(uint32_t px, uint32_t py, const char *s,
                                    uint32_t fg)
{
    while (*s) {
        if (px + FONT_W > fb_w) break;
        draw_char_transparent(px, py, (unsigned char)*s++, fg);
        px += FONT_W;
    }
}

/* ============================================================================
 * Cursor save/restore/draw (operates on framebuffer directly)
 * ============================================================================ */

static void cursor_save(int32_t x, int32_t y)
{
    cursor_saved_x = x;
    cursor_saved_y = y;
    for (int dy = 0; dy < CURSOR_H; dy++)
        for (int dx = 0; dx < CURSOR_W; dx++)
            cursor_under[dy * CURSOR_W + dx] = get_pixel((uint32_t)(x + dx),
                                                          (uint32_t)(y + dy));
}

static void cursor_restore(void)
{
    if (cursor_saved_x < 0) return;
    for (int dy = 0; dy < CURSOR_H; dy++)
        for (int dx = 0; dx < CURSOR_W; dx++)
            put_pixel((uint32_t)(cursor_saved_x + dx),
                      (uint32_t)(cursor_saved_y + dy),
                      cursor_under[dy * CURSOR_W + dx]);
    cursor_saved_x = -1;
}

static void cursor_draw(int32_t x, int32_t y)
{
    for (int dy = 0; dy < CURSOR_H; dy++)
        for (int dx = 0; dx < CURSOR_W; dx++) {
            uint8_t p = cursor_bmp[dy][dx];
            if (p == 1) put_pixel((uint32_t)(x + dx), (uint32_t)(y + dy), COL_BLACK);
            else if (p == 2) put_pixel((uint32_t)(x + dx), (uint32_t)(y + dy), COL_WHITE);
        }
}

/* ============================================================================
 * GPU Flush
 * ============================================================================ */

static bool flush_error_printed = false;
static void flush_fb(void)
{
    if (fb_conn == IO_OBJECT_NULL) return;
    IOConnectCallScalarMethod(fb_conn, kIOFBMethodFlushAll,
                              NULL, 0, NULL, NULL);
}

/* ============================================================================
 * Busy-wait delay (ARM generic timer, no syscalls)
 * ============================================================================ */

static void delay_ms(uint32_t ms)
{
    uint64_t freq, start, target;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(freq));
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(start));
    target = start + (freq * ms) / 1000;
    while (1) {
        uint64_t now;
        __asm__ volatile("mrs %0, cntvct_el0" : "=r"(now));
        if (now >= target) break;
    }
}

/* ============================================================================
 * IOKit Setup
 * ============================================================================ */

static int open_framebuffer(void)
{
    kern_return_t kr;
    io_service_t svc = IOServiceGetMatchingService(
        kIOMasterPortDefault, IOServiceMatching("IOFramebuffer"));
    if (svc == IO_OBJECT_NULL) {
        printf("[WS] IOFramebuffer not found\n");
        return -1;
    }

    kr = IOServiceOpen(svc, mach_task_self(), 0, &fb_conn);
    IOObjectRelease(svc);
    if (kr != 0) { printf("[WS] IOServiceOpen(FB) failed: 0x%x\n", kr); return -1; }

    uint64_t out[5] = {0};
    uint32_t cnt = 5;
    kr = IOConnectCallScalarMethod(fb_conn, kIOFBMethodGetInfo,
                                   NULL, 0, out, &cnt);
    if (kr != 0) { printf("[WS] GetInfo failed: 0x%x\n", kr); return -1; }

    fb_w     = (uint32_t)out[0];
    fb_h     = (uint32_t)out[1];
    fb_pitch = (uint32_t)out[2];

    printf("[WS] Display: %ux%u pitch=%u\n", fb_w, fb_h, fb_pitch);

    mach_vm_address_t addr = 0;
    mach_vm_size_t size = 0;
    kr = IOConnectMapMemory64(fb_conn, kIOFBMemoryTypeVRAM,
                              mach_task_self(), &addr, &size, kIOMapAnywhere);
    if (kr != 0) { printf("[WS] MapMemory(FB) failed: 0x%x\n", kr); return -1; }

    fb_pixels = (volatile uint32_t *)(uintptr_t)addr;
    printf("[WS] VRAM mapped at %p size 0x%llx\n", (void *)addr,
           (unsigned long long)size);
    return 0;
}

static int open_hid(void)
{
    kern_return_t kr;
    io_service_t svc = IOServiceGetMatchingService(
        kIOMasterPortDefault, IOServiceMatching("IOHIDSystem"));
    if (svc == IO_OBJECT_NULL) {
        printf("[WS] IOHIDSystem not found\n");
        return -1;
    }

    kr = IOServiceOpen(svc, mach_task_self(), 0, &hid_conn);
    IOObjectRelease(svc);
    if (kr != 0) { printf("[WS] IOServiceOpen(HID) failed: 0x%x\n", kr); return -1; }

    mach_vm_address_t addr = 0;
    mach_vm_size_t size = 0;
    kr = IOConnectMapMemory64(hid_conn, 0, mach_task_self(),
                              &addr, &size, kIOMapAnywhere);
    if (kr != 0) { printf("[WS] MapMemory(HID) failed: 0x%x\n", kr); return -1; }

    hid_ring = (struct hid_event_ring *)(uintptr_t)addr;
    printf("[WS] HID ring at %p size 0x%llx\n", (void *)addr,
           (unsigned long long)size);
    return 0;
}

/* ============================================================================
 * Client Management
 * ============================================================================ */

static struct ws_client *find_client(int32_t conn_id)
{
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && clients[i].conn_id == conn_id)
            return &clients[i];
    }
    return NULL;
}

static struct ws_client *alloc_client(void)
{
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i].active)
            return &clients[i];
    }
    return NULL;
}

/* ============================================================================
 * Window Management
 * ============================================================================ */

static struct ws_window *find_window(int32_t window_id)
{
    for (int i = 0; i < MAX_WINDOWS; i++) {
        if (windows[i].active && windows[i].window_id == window_id)
            return &windows[i];
    }
    return NULL;
}

static struct ws_window *alloc_window(void)
{
    for (int i = 0; i < MAX_WINDOWS; i++) {
        if (!windows[i].active)
            return &windows[i];
    }
    return NULL;
}

/* Get the window Y top including title bar */
static int32_t window_frame_y(const struct ws_window *w)
{
    if (w->style_mask & WS_STYLE_TITLED)
        return w->y - TITLEBAR_H;
    return w->y;
}

/* Get the window total height including title bar */
static uint32_t window_frame_h(const struct ws_window *w)
{
    if (w->style_mask & WS_STYLE_TITLED)
        return w->height + TITLEBAR_H;
    return w->height;
}

/* Z-order: bring window to front */
static void z_bring_to_front(int32_t window_id)
{
    /* Find and remove */
    int found = -1;
    for (int i = 0; i < z_count; i++) {
        if (z_order[i] == window_id) {
            found = i;
            break;
        }
    }
    if (found >= 0) {
        for (int i = found; i < z_count - 1; i++)
            z_order[i] = z_order[i + 1];
        z_count--;
    }
    /* Add at front (index 0) */
    for (int i = z_count; i > 0; i--)
        z_order[i] = z_order[i - 1];
    z_order[0] = window_id;
    z_count++;
}

/* Z-order: send window to back */
static void z_send_to_back(int32_t window_id)
{
    /* Find and remove */
    int found = -1;
    for (int i = 0; i < z_count; i++) {
        if (z_order[i] == window_id) {
            found = i;
            break;
        }
    }
    if (found >= 0) {
        for (int i = found; i < z_count - 1; i++)
            z_order[i] = z_order[i + 1];
        z_count--;
    }
    /* Add at back */
    z_order[z_count++] = window_id;
}

/* Z-order: remove window */
static void z_remove(int32_t window_id)
{
    int found = -1;
    for (int i = 0; i < z_count; i++) {
        if (z_order[i] == window_id) {
            found = i;
            break;
        }
    }
    if (found >= 0) {
        for (int i = found; i < z_count - 1; i++)
            z_order[i] = z_order[i + 1];
        z_count--;
    }
}

/* Update key window — the frontmost visible window */
static void update_key_window(void)
{
    int32_t old_key = key_window_id;
    key_window_id = -1;

    for (int i = 0; i < z_count; i++) {
        struct ws_window *w = find_window(z_order[i]);
        if (w && w->visible) {
            key_window_id = w->window_id;
            break;
        }
    }

    /* Send activate/deactivate events if key window changed */
    if (old_key != key_window_id) {
        /* Deactivate old */
        if (old_key >= 0) {
            struct ws_window *ow = find_window(old_key);
            if (ow) {
                ow->is_key = false;
                struct ws_client *c = find_client(ow->conn_id);
                if (c && c->event_port != MACH_PORT_NULL) {
                    ws_event_window_t evt;
                    memset(&evt, 0, sizeof(evt));
                    evt.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
                    evt.header.msgh_size = sizeof(evt);
                    evt.header.msgh_remote_port = c->event_port;
                    evt.header.msgh_id = WS_EVENT_WINDOW_DEACTIVATE;
                    evt.window_id = old_key;
                    mach_msg(&evt.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                             sizeof(evt), 0, MACH_PORT_NULL, 10, MACH_PORT_NULL);
                }
            }
        }
        /* Activate new */
        if (key_window_id >= 0) {
            struct ws_window *nw = find_window(key_window_id);
            if (nw) {
                nw->is_key = true;
                active_menu_conn_id = nw->conn_id;
                struct ws_client *c = find_client(nw->conn_id);
                if (c && c->event_port != MACH_PORT_NULL) {
                    ws_event_window_t evt;
                    memset(&evt, 0, sizeof(evt));
                    evt.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
                    evt.header.msgh_size = sizeof(evt);
                    evt.header.msgh_remote_port = c->event_port;
                    evt.header.msgh_id = WS_EVENT_WINDOW_ACTIVATE;
                    evt.window_id = key_window_id;
                    mach_msg(&evt.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                             sizeof(evt), 0, MACH_PORT_NULL, 10, MACH_PORT_NULL);
                }
            }
        }
        compositor_dirty = true;
    }
}

/* ============================================================================
 * IPC Message Handlers
 * ============================================================================ */

static void handle_connect(ws_rcv_buffer_t *buf)
{
    ws_msg_connect_t *msg = &buf->connect;

    /* After kernel copyout, ports are swapped per XNU convention:
     *   msgh_remote_port = sender's reply port (client's event port)
     *   msgh_local_port  = receiver's own port (our service port)
     * The client's event port comes as msgh_remote_port. */
    mach_port_t reply_port = msg->header.msgh_remote_port;

    struct ws_client *c = alloc_client();
    ws_reply_connect_t reply;
    memset(&reply, 0, sizeof(reply));
    reply.header.msgh_size = sizeof(reply);
    reply.header.msgh_id = WS_REPLY_CONNECT;

    if (!c) {
        printf("[WS] CONNECT: no free client slots\n");
        reply.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
        reply.header.msgh_remote_port = reply_port;
        reply.conn_id = -1;
        reply.result = KERN_RESOURCE_SHORTAGE;
        mach_msg(&reply.header, MACH_SEND_MSG, sizeof(reply), 0,
                 MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        return;
    }

    memset(c, 0, sizeof(*c));
    c->active = true;
    c->conn_id = next_conn_id++;
    c->event_port = reply_port;  /* Save client's event port for sending events */
    c->pid = msg->pid;
    strncpy(c->app_name, msg->app_name, 63);
    c->app_name[63] = '\0';

    printf("[WS] CONNECT: '%s' pid=%d conn_id=%d event_port=%u\n",
           c->app_name, c->pid, c->conn_id, c->event_port);

    /* Send reply back on the same port the message came from.
     * AppKit does send+receive on the same call — the reply goes back
     * on the client's local port (which became our reply_port). */
    reply.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    reply.header.msgh_remote_port = reply_port;
    reply.conn_id = c->conn_id;
    reply.result = KERN_SUCCESS;

    kern_return_t kr = mach_msg(&reply.header, MACH_SEND_MSG, sizeof(reply), 0,
                                MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        printf("[WS] CONNECT reply failed: kr=%d\n", kr);
    }

    /* Set as active menu client if first client */
    if (active_menu_conn_id < 0)
        active_menu_conn_id = c->conn_id;
}

static void handle_disconnect(ws_rcv_buffer_t *buf)
{
    ws_msg_destroy_window_t *msg = (ws_msg_destroy_window_t *)buf;
    int32_t conn_id = msg->conn_id;

    printf("[WS] DISCONNECT: conn_id=%d\n", conn_id);

    /* Destroy all windows owned by this client */
    for (int i = 0; i < MAX_WINDOWS; i++) {
        if (windows[i].active && windows[i].conn_id == conn_id) {
            z_remove(windows[i].window_id);
            if (windows[i].backing) {
                free(windows[i].backing);
                windows[i].backing = NULL;
            }
            windows[i].active = false;
        }
    }

    struct ws_client *c = find_client(conn_id);
    if (c) {
        c->active = false;
        if (active_menu_conn_id == conn_id)
            active_menu_conn_id = -1;
    }

    update_key_window();
    compositor_dirty = true;
}

static void handle_create_window(ws_rcv_buffer_t *buf)
{
    ws_msg_create_window_t *msg = &buf->create_window;
    mach_port_t reply_port = msg->header.msgh_remote_port;

    ws_reply_create_window_t reply;
    memset(&reply, 0, sizeof(reply));
    reply.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    reply.header.msgh_size = sizeof(reply);
    reply.header.msgh_remote_port = reply_port;
    reply.header.msgh_id = WS_REPLY_CREATE_WINDOW;

    struct ws_client *c = find_client(msg->conn_id);
    if (!c) {
        printf("[WS] CREATE_WINDOW: unknown conn_id=%d\n", msg->conn_id);
        reply.window_id = -1;
        reply.result = KERN_INVALID_ARGUMENT;
        mach_msg(&reply.header, MACH_SEND_MSG, sizeof(reply), 0,
                 MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        return;
    }

    struct ws_window *w = alloc_window();
    if (!w) {
        printf("[WS] CREATE_WINDOW: no free window slots\n");
        reply.window_id = -1;
        reply.result = KERN_RESOURCE_SHORTAGE;
        mach_msg(&reply.header, MACH_SEND_MSG, sizeof(reply), 0,
                 MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        return;
    }

    /* Clamp dimensions */
    uint32_t ww = msg->width;
    uint32_t wh = msg->height;
    if (ww == 0) ww = 100;
    if (wh == 0) wh = 100;
    if (ww > fb_w) ww = fb_w;
    if (wh > fb_h) wh = fb_h;

    memset(w, 0, sizeof(*w));
    w->active = true;
    w->window_id = next_window_id++;
    w->conn_id = msg->conn_id;
    w->x = msg->x;
    w->y = msg->y;
    /* If titled, shift content Y down by title bar height so the title bar
     * starts at the requested Y position */
    if (msg->style_mask & WS_STYLE_TITLED)
        w->y = msg->y + TITLEBAR_H;
    w->width = ww;
    w->height = wh;
    w->style_mask = msg->style_mask;
    strncpy(w->title, msg->title, 63);
    w->title[63] = '\0';
    w->visible = false;  /* Not visible until ORDER_FRONT */
    w->is_key = false;

    /* Allocate backing store */
    w->backing_stride = ww;
    w->backing = calloc(ww * wh, sizeof(uint32_t));
    if (!w->backing) {
        printf("[WS] CREATE_WINDOW: backing store alloc failed (%ux%u)\n", ww, wh);
        w->active = false;
        reply.window_id = -1;
        reply.result = KERN_RESOURCE_SHORTAGE;
        mach_msg(&reply.header, MACH_SEND_MSG, sizeof(reply), 0,
                 MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        return;
    }

    /* Fill backing with window background colour (light grey, BGRA) */
    uint32_t bg = rgb(0xEC, 0xEC, 0xEC);
    for (uint32_t i = 0; i < ww * wh; i++)
        w->backing[i] = bg;

    /* Add to z-order (front) */
    z_bring_to_front(w->window_id);

    printf("[WS] CREATE_WINDOW: id=%d conn=%d '%s' %dx%d at (%d,%d) style=0x%x\n",
           w->window_id, w->conn_id, w->title,
           w->width, w->height, w->x, w->y, w->style_mask);

    reply.window_id = w->window_id;
    reply.result = KERN_SUCCESS;
    kern_return_t kr = mach_msg(&reply.header, MACH_SEND_MSG, sizeof(reply), 0,
                                MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        printf("[WS] CREATE_WINDOW reply failed: kr=%d\n", kr);
    }
}

static void handle_destroy_window(ws_rcv_buffer_t *buf)
{
    ws_msg_destroy_window_t *msg = (ws_msg_destroy_window_t *)buf;
    struct ws_window *w = find_window(msg->window_id);
    if (!w || w->conn_id != msg->conn_id) return;

    printf("[WS] DESTROY_WINDOW: id=%d\n", msg->window_id);

    z_remove(w->window_id);
    if (w->backing) {
        free(w->backing);
        w->backing = NULL;
    }
    w->active = false;

    update_key_window();
    compositor_dirty = true;
}

static void handle_order_window(ws_rcv_buffer_t *buf)
{
    ws_msg_order_window_t *msg = (ws_msg_order_window_t *)buf;
    struct ws_window *w = find_window(msg->window_id);
    if (!w || w->conn_id != msg->conn_id) return;

    switch (msg->order) {
    case WS_ORDER_FRONT:
        w->visible = true;
        z_bring_to_front(w->window_id);
        break;
    case WS_ORDER_BACK:
        w->visible = true;
        z_send_to_back(w->window_id);
        break;
    case WS_ORDER_OUT:
        w->visible = false;
        break;
    }

    update_key_window();
    compositor_dirty = true;
}

static void handle_set_title(ws_rcv_buffer_t *buf)
{
    ws_msg_set_title_t *msg = (ws_msg_set_title_t *)buf;
    struct ws_window *w = find_window(msg->window_id);
    if (!w || w->conn_id != msg->conn_id) return;

    strncpy(w->title, msg->title, 63);
    w->title[63] = '\0';
    compositor_dirty = true;
}

static void handle_set_frame(ws_rcv_buffer_t *buf)
{
    ws_msg_set_frame_t *msg = (ws_msg_set_frame_t *)buf;
    struct ws_window *w = find_window(msg->window_id);
    if (!w || w->conn_id != msg->conn_id) return;

    uint32_t new_w = msg->width;
    uint32_t new_h = msg->height;
    if (new_w == 0) new_w = 1;
    if (new_h == 0) new_h = 1;
    if (new_w > fb_w) new_w = fb_w;
    if (new_h > fb_h) new_h = fb_h;

    w->x = msg->x;
    w->y = msg->y;
    if (w->style_mask & WS_STYLE_TITLED)
        w->y = msg->y + TITLEBAR_H;

    /* Realloc backing store if size changed */
    if (new_w != w->width || new_h != w->height) {
        if (w->backing) free(w->backing);
        w->width = new_w;
        w->height = new_h;
        w->backing_stride = new_w;
        w->backing = calloc(new_w * new_h, sizeof(uint32_t));
        /* Fill with background */
        if (w->backing) {
            uint32_t bg = rgb(0xEC, 0xEC, 0xEC);
            for (uint32_t i = 0; i < new_w * new_h; i++)
                w->backing[i] = bg;
        }
    }

    compositor_dirty = true;
}

/*
 * free_ool_data - Free OOL memory mapped into our address space by the kernel.
 *
 * Every DRAW_RECT carries an OOL descriptor whose pages are mapped into
 * WindowServer's address space during mach_msg receive.  If we don't
 * munmap them after copying pixels, every draw leaks the entire pixel
 * buffer (e.g. 1000 pages for the Dock's 1280x800 desktop).
 */
static void free_ool_data(mach_msg_ool_descriptor_t *desc)
{
    if (desc->address && desc->size > 0) {
        uint64_t addr = (uint64_t)(uintptr_t)desc->address;
        uint64_t size = desc->size;
        uint64_t page_mask = 4096 - 1;
        uint64_t aligned_addr = addr & ~page_mask;
        uint64_t aligned_size = ((addr + size + page_mask) & ~page_mask) - aligned_addr;
        munmap((void *)(uintptr_t)aligned_addr, (size_t)aligned_size);
    }
}

static void handle_draw_rect(ws_rcv_buffer_t *buf)
{
    ws_msg_draw_rect_t *msg = &buf->draw_rect;
    struct ws_window *w = find_window(msg->window_id);
    if (!w || w->conn_id != msg->conn_id || !w->backing) {
        printf("[WS] DRAW_RECT: REJECTED w=%p conn_ok=%d backing=%p\n",
               (void *)w, w ? (w->conn_id == msg->conn_id) : -1,
               w ? (void *)w->backing : NULL);
        free_ool_data(&msg->surface_desc);
        return;
    }

    /* The OOL descriptor's address now points to mapped memory in our space
     * (the kernel did copyout into our address space) */
    const uint32_t *src_pixels = (const uint32_t *)(uintptr_t)msg->surface_desc.address;
    uint32_t src_rowbytes = msg->src_rowbytes;
    uint32_t dx = msg->dst_x;
    uint32_t dy = msg->dst_y;
    uint32_t bw = msg->width;
    uint32_t bh = msg->height;

    if (!src_pixels || bw == 0 || bh == 0) {
        printf("[WS] DRAW_RECT: REJECTED null_pixels=%d bw=%u bh=%u\n",
               src_pixels == NULL, bw, bh);
        free_ool_data(&msg->surface_desc);
        return;
    }

    /* Clamp to window bounds */
    if (dx >= w->width || dy >= w->height) {
        free_ool_data(&msg->surface_desc);
        return;
    }
    if (dx + bw > w->width)  bw = w->width - dx;
    if (dy + bh > w->height) bh = w->height - dy;

    /* Copy pixels into the window's backing store.
     *
     * AppKit sends BGRA pixels with kCGImageAlphaPremultipliedFirst |
     * kCGBitmapByteOrder32Little, which is native BGRA8888 — same as
     * our framebuffer format. Direct copy.
     */
    uint32_t src_stride = src_rowbytes / 4;  /* pixels per row in source */
    for (uint32_t row = 0; row < bh; row++) {
        const uint32_t *srow = src_pixels + row * src_stride;
        uint32_t *drow = w->backing + (dy + row) * w->backing_stride + dx;
        memcpy(drow, srow, bw * sizeof(uint32_t));
    }

    /* Free the OOL memory now that pixels have been copied */
    free_ool_data(&msg->surface_desc);

    compositor_dirty = true;
}

static void handle_set_menu(ws_rcv_buffer_t *buf)
{
    ws_msg_set_menu_t *msg = (ws_msg_set_menu_t *)buf;
    struct ws_client *c = find_client(msg->conn_id);
    if (!c) return;

    c->menu_count = msg->item_count;
    if (c->menu_count > MAX_MENU_ITEMS) c->menu_count = MAX_MENU_ITEMS;

    for (uint32_t i = 0; i < c->menu_count; i++) {
        strncpy(c->menu_items[i].title, msg->items[i].title, MENU_TITLE_MAX - 1);
        c->menu_items[i].title[MENU_TITLE_MAX - 1] = '\0';
        c->menu_items[i].tag = msg->items[i].tag;
        c->menu_items[i].enabled = msg->items[i].enabled;
    }

    compositor_dirty = true;
}

/* ============================================================================
 * IPC Dispatch
 * ============================================================================ */

static void dispatch_message(ws_rcv_buffer_t *buf)
{
    mach_msg_id_t msg_id = buf->header.msgh_id;

    switch (msg_id) {
    case WS_MSG_CONNECT:        handle_connect(buf);        break;
    case WS_MSG_DISCONNECT:     handle_disconnect(buf);     break;
    case WS_MSG_CREATE_WINDOW:  handle_create_window(buf);  break;
    case WS_MSG_DESTROY_WINDOW: handle_destroy_window(buf); break;
    case WS_MSG_ORDER_WINDOW:   handle_order_window(buf);   break;
    case WS_MSG_SET_TITLE:      handle_set_title(buf);      break;
    case WS_MSG_SET_FRAME:      handle_set_frame(buf);      break;
    case WS_MSG_DRAW_RECT:      handle_draw_rect(buf);      break;
    case WS_MSG_SET_MENU:       handle_set_menu(buf);       break;
    default: {
        static uint32_t unknown_count = 0;
        unknown_count++;
        if (unknown_count <= 3) {
            printf("[WS] Unknown message ID: %d (bits=0x%x size=%u)\n",
                   msg_id, buf->header.msgh_bits, buf->header.msgh_size);
        }
        break;
    }
    }
}

/* ============================================================================
 * Compositor — draws desktop + windows + menu bar onto the framebuffer
 *
 * This is called when compositor_dirty is set. Draws back-to-front:
 *   1. Desktop background
 *   2. Windows (z-order, back to front) with title bars
 *   3. Menu bar (on top of everything)
 *   4. (Cursor is drawn separately after compositing)
 * ============================================================================ */

static void composite(void)
{
    if (!fb_pixels) return;

    uint32_t stride = pixel_stride();

    /* 1. Desktop background */
    fill_rect(0, 0, fb_w, fb_h, COL_DESKTOP);

    /* 2. Windows — draw back to front (z_order[z_count-1] is backmost) */
    for (int zi = z_count - 1; zi >= 0; zi--) {
        struct ws_window *w = find_window(z_order[zi]);
        if (!w || !w->visible || !w->backing) continue;

        int32_t frame_y = window_frame_y(w);
        uint32_t frame_h = window_frame_h(w);
        int32_t wx = w->x;

        /* Draw 1px shadow (right and bottom) */
        {
            int32_t sx = wx + 1;
            int32_t sy = frame_y + 1;
            uint32_t sw = w->width + 1;
            uint32_t sh = frame_h + 1;
            /* Bottom shadow line */
            if (frame_y + (int32_t)frame_h >= 0 && frame_y + (int32_t)frame_h < (int32_t)fb_h) {
                for (uint32_t px = 0; px < sw && sx + (int32_t)px < (int32_t)fb_w; px++) {
                    if (sx + (int32_t)px >= 0)
                        put_pixel((uint32_t)(sx + (int32_t)px),
                                  (uint32_t)(frame_y + (int32_t)frame_h), COL_WINDOW_SHADOW);
                }
            }
            /* Right shadow line */
            if (wx + (int32_t)w->width >= 0 && wx + (int32_t)w->width < (int32_t)fb_w) {
                for (uint32_t py = 0; py < sh && sy + (int32_t)py < (int32_t)fb_h; py++) {
                    if (sy + (int32_t)py >= 0)
                        put_pixel((uint32_t)(wx + (int32_t)w->width),
                                  (uint32_t)(sy + (int32_t)py), COL_WINDOW_SHADOW);
                }
            }
        }

        /* Draw title bar if titled */
        if (w->style_mask & WS_STYLE_TITLED) {
            int32_t ty = frame_y;
            uint32_t tbar_col = w->is_key ? COL_TITLEBAR_ACTIVE : COL_TITLEBAR_INACTIVE;

            /* Title bar background */
            if (ty >= 0 && ty < (int32_t)fb_h && wx >= 0) {
                for (uint32_t py = 0; py < TITLEBAR_H && (uint32_t)(ty + (int32_t)py) < fb_h; py++) {
                    volatile uint32_t *row = &fb_pixels[(ty + (int32_t)py) * stride];
                    for (uint32_t px = 0; px < w->width && (uint32_t)(wx + (int32_t)px) < fb_w; px++) {
                        if (wx + (int32_t)px >= 0)
                            row[wx + (int32_t)px] = tbar_col;
                    }
                }
            }

            /* Title bar separator line */
            if (ty + TITLEBAR_H - 1 >= 0 && (uint32_t)(ty + TITLEBAR_H - 1) < fb_h) {
                for (uint32_t px = 0; px < w->width && (uint32_t)(wx + (int32_t)px) < fb_w; px++) {
                    if (wx + (int32_t)px >= 0)
                        put_pixel((uint32_t)(wx + (int32_t)px),
                                  (uint32_t)(ty + TITLEBAR_H - 1), COL_TITLEBAR_SEP);
                }
            }

            /* Close button (red circle) */
            if (w->style_mask & WS_STYLE_CLOSABLE) {
                int32_t bx = wx + 8;
                int32_t by = ty + 5;
                /* Simple 12x12 filled circle approximation */
                for (int dy = 0; dy < 12; dy++) {
                    for (int dx = 0; dx < 12; dx++) {
                        int cx = dx - 5, cy = dy - 5;
                        if (cx*cx + cy*cy <= 25) {
                            int32_t px = bx + dx;
                            int32_t py = by + dy;
                            if (px >= 0 && px < (int32_t)fb_w &&
                                py >= 0 && py < (int32_t)fb_h)
                                put_pixel((uint32_t)px, (uint32_t)py, COL_CLOSE_BTN);
                        }
                    }
                }
            }

            /* Title text — centred in title bar */
            if (w->title[0]) {
                uint32_t title_len = (uint32_t)strlen(w->title);
                uint32_t text_w = title_len * FONT_W;
                int32_t tx_x = wx + (int32_t)(w->width / 2) - (int32_t)(text_w / 2);
                int32_t tx_y = ty + (TITLEBAR_H - FONT_H) / 2;
                if (tx_x >= 0 && tx_y >= 0) {
                    draw_string_transparent((uint32_t)tx_x, (uint32_t)tx_y,
                                            w->title, COL_TITLEBAR_TEXT);
                }
            }
        }

        /* Draw window content (backing store) */
        for (uint32_t row = 0; row < w->height; row++) {
            int32_t sy = w->y + (int32_t)row;
            if (sy < 0 || (uint32_t)sy >= fb_h) continue;

            const uint32_t *src = w->backing + row * w->backing_stride;
            volatile uint32_t *dst = &fb_pixels[(uint32_t)sy * stride];

            for (uint32_t col = 0; col < w->width; col++) {
                int32_t sx = wx + (int32_t)col;
                if (sx < 0 || (uint32_t)sx >= fb_w) continue;
                dst[(uint32_t)sx] = src[col];
            }
        }
    }

    /* 3. Menu bar (always on top) */
    fill_rect(0, 0, fb_w, MENUBAR_H, COL_MENUBAR);
    fill_rect(0, MENUBAR_H, fb_w, 1, COL_MENUBAR_SEP);

    /* Apple/Kiseki logo at left */
    draw_string_transparent(10, 3, "KisekiOS", COL_MENUBAR_TEXT);

    /* Active client's menu items */
    struct ws_client *menu_client = find_client(active_menu_conn_id);
    if (menu_client && menu_client->menu_count > 0) {
        uint32_t mx = 10 + 6 * FONT_W + 16;  /* After "Kiseki" + gap */
        for (uint32_t i = 0; i < menu_client->menu_count; i++) {
            draw_string_transparent(mx, 3, menu_client->menu_items[i].title,
                                    COL_MENUBAR_TEXT);
            mx += ((uint32_t)strlen(menu_client->menu_items[i].title) + 2) * FONT_W;
        }
    }

    compositor_dirty = false;
}

/* ============================================================================
 * HID Event Processing & Dispatch
 * ============================================================================ */

/* Find which window the cursor is over (topmost visible window) */
static struct ws_window *window_at_point(int32_t px, int32_t py)
{
    for (int i = 0; i < z_count; i++) {
        struct ws_window *w = find_window(z_order[i]);
        if (!w || !w->visible) continue;

        int32_t fy = window_frame_y(w);
        uint32_t fh = window_frame_h(w);

        if (px >= w->x && px < w->x + (int32_t)w->width &&
            py >= fy && py < fy + (int32_t)fh) {
            return w;
        }
    }
    return NULL;
}

/* Check if a point is in the title bar of a window */
static bool point_in_titlebar(const struct ws_window *w, int32_t px, int32_t py)
{
    if (!(w->style_mask & WS_STYLE_TITLED)) return false;
    int32_t ty = window_frame_y(w);
    return (px >= w->x && px < w->x + (int32_t)w->width &&
            py >= ty && py < ty + TITLEBAR_H);
}

/* Check if a point is on the close button */
static bool point_on_close_button(const struct ws_window *w, int32_t px, int32_t py)
{
    if (!(w->style_mask & (WS_STYLE_TITLED | WS_STYLE_CLOSABLE))) return false;
    int32_t ty = window_frame_y(w);
    int32_t bx = w->x + 8 + 5;   /* Centre of close button */
    int32_t by = ty + 5 + 5;
    int dx = px - bx, dy = py - by;
    return (dx*dx + dy*dy <= 36);  /* Slightly larger hit area */
}

/* Send a mouse event to a client */
static void send_mouse_event(struct ws_client *c, int32_t window_id,
                              int32_t msg_id,
                              int32_t wx, int32_t wy,
                              int32_t sx, int32_t sy,
                              uint32_t button, uint32_t mods, uint32_t clicks)
{
    if (!c || c->event_port == MACH_PORT_NULL) return;

    ws_event_mouse_t evt;
    memset(&evt, 0, sizeof(evt));
    evt.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    evt.header.msgh_size = sizeof(evt);
    evt.header.msgh_remote_port = c->event_port;
    evt.header.msgh_id = msg_id;
    evt.window_id = window_id;
    evt.x = wx;
    evt.y = wy;
    evt.screen_x = sx;
    evt.screen_y = sy;
    evt.button = button;
    evt.modifiers = mods;
    evt.click_count = clicks;

    mach_msg(&evt.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
             sizeof(evt), 0, MACH_PORT_NULL, 5, MACH_PORT_NULL);
}

/* Send a key event to a client */
static void send_key_event(struct ws_client *c, int32_t window_id,
                            int32_t msg_id,
                            uint32_t keycode, uint32_t characters,
                            uint32_t mods, uint16_t is_repeat)
{
    if (!c || c->event_port == MACH_PORT_NULL) return;

    ws_event_key_t evt;
    memset(&evt, 0, sizeof(evt));
    evt.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    evt.header.msgh_size = sizeof(evt);
    evt.header.msgh_remote_port = c->event_port;
    evt.header.msgh_id = msg_id;
    evt.window_id = window_id;
    evt.keycode = keycode;
    evt.characters = characters;
    evt.modifiers = mods;
    evt.is_repeat = is_repeat;

    mach_msg(&evt.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
             sizeof(evt), 0, MACH_PORT_NULL, 5, MACH_PORT_NULL);
}

static bool process_hid(void)
{
    if (!hid_ring) return false;
    bool processed_any = false;

    while (hid_ring->read_idx != hid_ring->write_idx) {
        processed_any = true;
        __asm__ volatile("dmb ish" ::: "memory");
        uint32_t slot = hid_ring->read_idx % HID_EVENT_RING_SIZE;
        struct hid_event ev = hid_ring->events[slot];
        __asm__ volatile("dmb ish" ::: "memory");
        hid_ring->read_idx++;

        switch (ev.type) {
        case HID_EVENT_MOUSE_MOVE: {
            cur_x = (int32_t)((uint64_t)ev.abs_x * fb_w / (TABLET_ABS_MAX + 1));
            cur_y = (int32_t)((uint64_t)ev.abs_y * fb_h / (TABLET_ABS_MAX + 1));
            if (cur_x < 0) cur_x = 0;
            if (cur_y < 0) cur_y = 0;
            if ((uint32_t)cur_x >= fb_w) cur_x = (int32_t)(fb_w - 1);
            if ((uint32_t)cur_y >= fb_h) cur_y = (int32_t)(fb_h - 1);

            /* Window dragging */
            if (mouse_is_down && drag_window_id >= 0) {
                struct ws_window *dw = find_window(drag_window_id);
                if (dw) {
                    dw->x = cur_x - drag_offset_x;
                    dw->y = cur_y - drag_offset_y;
                    compositor_dirty = true;
                }
            }

            /* Send MOUSE_MOVED or MOUSE_DRAGGED to key window client */
            if (key_window_id >= 0) {
                struct ws_window *kw = find_window(key_window_id);
                if (kw) {
                    struct ws_client *c = find_client(kw->conn_id);
                    if (c) {
                        int32_t wx = cur_x - kw->x;
                        int32_t wy = cur_y - kw->y;
                        int32_t msg = mouse_is_down ? WS_EVENT_MOUSE_DRAGGED
                                                    : WS_EVENT_MOUSE_MOVED;
                        send_mouse_event(c, kw->window_id, msg,
                                        wx, wy, cur_x, cur_y, 0, 0, 0);
                    }
                }
            }
            break;
        }

        case HID_EVENT_MOUSE_DOWN: {
            mouse_is_down = true;
            drag_window_id = -1;

            struct ws_window *hit = window_at_point(cur_x, cur_y);
            if (hit) {
                /* Bring to front if not already */
                if (hit->window_id != key_window_id) {
                    z_bring_to_front(hit->window_id);
                    update_key_window();
                    compositor_dirty = true;
                }

                /* Check close button */
                if (point_on_close_button(hit, cur_x, cur_y)) {
                    /* Send close event to client */
                    struct ws_client *c = find_client(hit->conn_id);
                    if (c && c->event_port != MACH_PORT_NULL) {
                        ws_event_window_t evt;
                        memset(&evt, 0, sizeof(evt));
                        evt.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
                        evt.header.msgh_size = sizeof(evt);
                        evt.header.msgh_remote_port = c->event_port;
                        evt.header.msgh_id = WS_EVENT_WINDOW_CLOSE;
                        evt.window_id = hit->window_id;
                        mach_msg(&evt.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                                 sizeof(evt), 0, MACH_PORT_NULL, 5, MACH_PORT_NULL);
                    }
                    break;
                }

                /* Check title bar drag */
                if (point_in_titlebar(hit, cur_x, cur_y)) {
                    drag_window_id = hit->window_id;
                    drag_offset_x = cur_x - hit->x;
                    drag_offset_y = cur_y - hit->y;
                    break;
                }

                /* Content area click — send to client */
                struct ws_client *c = find_client(hit->conn_id);
                if (c) {
                    int32_t wx = cur_x - hit->x;
                    int32_t wy = cur_y - hit->y;
                    send_mouse_event(c, hit->window_id, WS_EVENT_MOUSE_DOWN,
                                    wx, wy, cur_x, cur_y,
                                    ev.buttons, ev.flags, 1);
                }
            }
            break;
        }

        case HID_EVENT_MOUSE_UP: {
            mouse_is_down = false;
            drag_window_id = -1;

            /* Send to key window client */
            if (key_window_id >= 0) {
                struct ws_window *kw = find_window(key_window_id);
                if (kw) {
                    struct ws_client *c = find_client(kw->conn_id);
                    if (c) {
                        int32_t wx = cur_x - kw->x;
                        int32_t wy = cur_y - kw->y;
                        send_mouse_event(c, kw->window_id, WS_EVENT_MOUSE_UP,
                                        wx, wy, cur_x, cur_y,
                                        ev.buttons, ev.flags, 1);
                    }
                }
            }
            break;
        }

        case HID_EVENT_KEY_DOWN:
        case HID_EVENT_KEY_UP: {
            /* Route to key window's client */
            if (key_window_id >= 0) {
                struct ws_window *kw = find_window(key_window_id);
                if (kw) {
                    struct ws_client *c = find_client(kw->conn_id);
                    if (c) {
                        int32_t msg_id = (ev.type == HID_EVENT_KEY_DOWN)
                                         ? WS_EVENT_KEY_DOWN : WS_EVENT_KEY_UP;
                        uint32_t ascii = keycode_to_char(ev.keycode, ev.flags);
                        send_key_event(c, kw->window_id, msg_id,
                                      ev.keycode, ascii, ev.flags, 0);
                    }
                }
            }
            break;
        }

        default:
            break;
        }
    }

    return processed_any;
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(int argc, char *argv[])
{
    (void)argc; (void)argv;

    printf("[WS] Starting WindowServer (PID %d)\n", getpid());
    signal(SIGPIPE, SIG_IGN);

    /* Initialize client and window arrays */
    memset(clients, 0, sizeof(clients));
    memset(windows, 0, sizeof(windows));
    memset(z_order, 0, sizeof(z_order));

    /* Claim Mach service port.
     * init (PID 1) pre-creates and registers this port in the bootstrap
     * namespace. We check-in to receive the existing port. If that fails,
     * we allocate our own and register it. */
    kern_return_t kr = bootstrap_check_in(
        MACH_PORT_NULL, WS_SERVICE_NAME, &svc_port);
    if (kr != 0 || svc_port == MACH_PORT_NULL) {
        kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
                                &svc_port);
        if (kr == 0)
            bootstrap_register(MACH_PORT_NULL, WS_SERVICE_NAME, svc_port);
    }
    printf("[WS] Service port: %u\n", svc_port);

    /* Open framebuffer */
    if (open_framebuffer() != 0) {
        printf("[WS] FATAL: no framebuffer\n");
        return 1;
    }

    /* Open HID */
    if (open_hid() != 0)
        printf("[WS] WARNING: no HID input\n");

    /* Initial cursor position */
    cur_x = (int32_t)(fb_w / 2);
    cur_y = (int32_t)(fb_h / 2);

    /* Initial composit + flush */
    composite();
    cursor_save(cur_x, cur_y);
    cursor_draw(cur_x, cur_y);
    flush_fb();
    printf("[WS] Desktop drawn, entering event loop\n");

    /*
     * Main event loop.
     *
     * Architecture: We use a tight non-blocking poll loop that:
     *   1. Drains all pending Mach IPC messages (non-blocking, timeout=0)
     *   2. Drains all HID events from the kernel ring
     *   3. Re-composites if dirty
     *   4. Redraws cursor + flushes GPU
     *   5. If nothing happened this iteration, yields with a short
     *      blocking receive (1ms timeout) to avoid busy-spinning
     *
     * The non-blocking poll (MACH_RCV_TIMEOUT with timeout=0) returns
     * immediately from the kernel via semaphore_trywait — no 10ms tick
     * rounding. This gives us the lowest possible latency for cursor
     * movement and IPC message handling.
     */
    ws_rcv_buffer_t rcv_buf;
    for (;;) {
        bool did_work = false;

        /* 1. Drain all pending IPC messages (non-blocking poll) */
        for (;;) {
            memset(&rcv_buf, 0, sizeof(rcv_buf));
            rcv_buf.header.msgh_size = sizeof(rcv_buf);
            rcv_buf.header.msgh_local_port = svc_port;

            kr = mach_msg(&rcv_buf.header,
                         MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                         0,                     /* send_size */
                         sizeof(rcv_buf),       /* rcv_size */
                         svc_port,              /* rcv_name */
                         0,                     /* timeout=0: non-blocking poll */
                         MACH_PORT_NULL);

            if (kr == MACH_MSG_SUCCESS) {
                dispatch_message(&rcv_buf);
                did_work = true;
            } else {
                break;  /* MACH_RCV_TIMED_OUT or error — queue drained */
            }
        }

        /* 2. Process HID events */
        cursor_restore();
        if (process_hid())
            did_work = true;

        /* 3. Composite if dirty */
        if (compositor_dirty) {
            composite();
            did_work = true;
        }

        /* 4. Draw cursor */
        cursor_save(cur_x, cur_y);
        cursor_draw(cur_x, cur_y);

        /* 5. Flush GPU (only when something changed) */
        if (did_work) {
            flush_fb();
        }

        /* 6. If nothing happened this iteration, yield CPU briefly. */
        if (!did_work) {
            memset(&rcv_buf, 0, sizeof(rcv_buf));
            rcv_buf.header.msgh_size = sizeof(rcv_buf);
            rcv_buf.header.msgh_local_port = svc_port;

            kr = mach_msg(&rcv_buf.header,
                         MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                         0,
                         sizeof(rcv_buf),
                         svc_port,
                         50,                    /* 50ms idle sleep to reduce CPU usage */
                         MACH_PORT_NULL);

            if (kr == MACH_MSG_SUCCESS) {
                dispatch_message(&rcv_buf);
            }
        }
    }

    return 0;
}
