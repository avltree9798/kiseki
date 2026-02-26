/*
 * Kiseki OS - WindowServer (rewritten from scratch)
 *
 * Minimal display server. Claims the framebuffer via IOKit, processes
 * HID events, composites the desktop. Built up incrementally:
 *
 *   Phase 1: Map FB, fill blue, flush in a loop
 *   Phase 2: Desktop + menu bar + mouse cursor
 *   Phase 3: Login window
 *   Phase 4: Terminal + PTY
 *
 * Boot chain: kernel -> init -> WindowServer
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <IOKit/IOKitLib.h>

/* openpty() */
int openpty(int *, int *, char *, void *, void *);

/* bootstrap_register is declared in <servers/bootstrap.h> (deprecated but available) */

/* ============================================================================
 * Constants
 * ============================================================================ */

#define WS_SERVICE_NAME     "uk.co.avltree9798.WindowServer"
#define TABLET_ABS_MAX      32767

/* Colours — BGRA (VirtIO GPU B8G8R8X8) */
static inline uint32_t rgb(uint8_t r, uint8_t g, uint8_t b)
{
    return (uint32_t)b | ((uint32_t)g << 8) |
           ((uint32_t)r << 16) | (0xFFu << 24);
}

#define COL_DESKTOP         rgb(0x3A, 0x6E, 0xA5)
#define COL_MENUBAR         rgb(0xEA, 0xEA, 0xEA)
#define COL_MENUBAR_SEP     rgb(0xB4, 0xB4, 0xB4)
#define COL_BLACK           rgb(0x00, 0x00, 0x00)
#define COL_WHITE           rgb(0xFF, 0xFF, 0xFF)

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
 * 8x16 bitmap font (embedded)
 * ============================================================================ */

#include "font8x16.inc"  /* provides lw_font8x16[256][16] */
#define font8x16_data lw_font8x16

#define FONT_W  8
#define FONT_H  16

/* ============================================================================
 * Framebuffer state
 * ============================================================================ */

static io_connect_t     fb_conn = IO_OBJECT_NULL;
static volatile uint32_t *fb_pixels = NULL;
static uint32_t         fb_w = 0, fb_h = 0, fb_pitch = 0;

/* HID state */
static io_connect_t     hid_conn = IO_OBJECT_NULL;
static struct hid_event_ring *hid_ring = NULL;

/* Cursor */
static int32_t  cur_x = 0, cur_y = 0;

/* Cursor save-under buffer */
#define CURSOR_W 12
#define CURSOR_H 18
static uint32_t cursor_under[CURSOR_W * CURSOR_H];
static int32_t  cursor_saved_x = -1, cursor_saved_y = -1;

/* Simple arrow cursor bitmap (1=black, 2=white, 0=transparent) */
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
 * Drawing primitives
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

static void draw_string(uint32_t px, uint32_t py, const char *s,
                        uint32_t fg, uint32_t bg)
{
    while (*s) {
        if (px + FONT_W > fb_w) break;
        draw_char(px, py, (unsigned char)*s++, fg, bg);
        px += FONT_W;
    }
}

/* ============================================================================
 * Cursor save / restore / draw
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
 * GPU flush
 * ============================================================================ */

static bool flush_error_printed = false;
static void flush_fb(void)
{
    if (fb_conn == IO_OBJECT_NULL) return;
    int kr = IOConnectCallScalarMethod(fb_conn, kIOFBMethodFlushAll,
                                       NULL, 0, NULL, NULL);
    if (kr != 0 && !flush_error_printed) {
        printf("[WS] flush failed: kr=0x%x\n", kr);
        flush_error_printed = true;
    }
}

/* ============================================================================
 * Desktop drawing
 * ============================================================================ */

#define MENUBAR_H 22

static void draw_desktop(void)
{
    fill_rect(0, 0, fb_w, fb_h, COL_DESKTOP);
    fill_rect(0, 0, fb_w, MENUBAR_H, COL_MENUBAR);
    fill_rect(0, MENUBAR_H, fb_w, 1, COL_MENUBAR_SEP);
    draw_string(10, 3, "Kiseki", COL_BLACK, COL_MENUBAR);
}

/* ============================================================================
 * HID event processing
 * ============================================================================ */

static void process_hid(void)
{
    if (!hid_ring) return;

    while (hid_ring->read_idx != hid_ring->write_idx) {
        __asm__ volatile("dmb ish" ::: "memory");  /* acquire */
        uint32_t slot = hid_ring->read_idx % HID_EVENT_RING_SIZE;
        struct hid_event ev = hid_ring->events[slot];
        __asm__ volatile("dmb ish" ::: "memory");  /* release */
        hid_ring->read_idx++;

        switch (ev.type) {
        case HID_EVENT_MOUSE_MOVE:
            cur_x = (int32_t)((uint64_t)ev.abs_x * fb_w / (TABLET_ABS_MAX + 1));
            cur_y = (int32_t)((uint64_t)ev.abs_y * fb_h / (TABLET_ABS_MAX + 1));
            if (cur_x < 0) cur_x = 0;
            if (cur_y < 0) cur_y = 0;
            if ((uint32_t)cur_x >= fb_w) cur_x = (int32_t)(fb_w - 1);
            if ((uint32_t)cur_y >= fb_h) cur_y = (int32_t)(fb_h - 1);
            break;
        default:
            break;
        }
    }
}

/* ============================================================================
 * IOKit setup
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
 * Busy-wait delay (no syscalls)
 * ============================================================================ */

static void delay_ms(uint32_t ms)
{
    /*
     * Read the ARM generic timer to implement a precise delay without
     * any syscalls. This avoids potential nanosleep/usleep bugs.
     */
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
 * Main
 * ============================================================================ */

int main(int argc, char *argv[])
{
    (void)argc; (void)argv;

    printf("[WS] Starting (PID %d)\n", getpid());
    signal(SIGPIPE, SIG_IGN);

    /* Claim Mach service port */
    mach_port_t svc_port = MACH_PORT_NULL;
    kern_return_t kr = bootstrap_check_in(
        MACH_PORT_NULL, WS_SERVICE_NAME, &svc_port);
    if (kr != 0 || svc_port == MACH_PORT_NULL) {
        kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
                                &svc_port);
        if (kr == 0)
            bootstrap_register(MACH_PORT_NULL, WS_SERVICE_NAME, svc_port);
    }

    /* Open framebuffer */
    if (open_framebuffer() != 0) {
        printf("[WS] FATAL: no framebuffer\n");
        return 1;
    }

    /* Open HID */
    if (open_hid() != 0)
        printf("[WS] WARNING: no HID input\n");

    /* Initial draw */
    cur_x = (int32_t)(fb_w / 2);
    cur_y = (int32_t)(fb_h / 2);

    draw_desktop();
    cursor_save(cur_x, cur_y);
    cursor_draw(cur_x, cur_y);
    flush_fb();
    printf("[WS] Desktop drawn, entering event loop\n");

    /* Event loop — ~60fps using timer-based delay (no syscalls) */
    for (;;) {
        /* Restore cursor before processing */
        cursor_restore();

        /* Process input */
        process_hid();

        /* Redraw cursor at new position */
        cursor_save(cur_x, cur_y);
        cursor_draw(cur_x, cur_y);

        /* Flush display */
        flush_fb();

        /* ~16ms delay (~60fps) using ARM timer, no syscalls */
        delay_ms(16);
    }

    return 0;
}
