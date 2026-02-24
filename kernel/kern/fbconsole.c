/*
 * Kiseki OS - Framebuffer Console with VT100/ANSI Escape Sequence Parser
 *
 * Renders text onto the VirtIO GPU framebuffer using the built-in
 * 8x16 VGA bitmap font. Provides a VT100-compatible text console with
 * cursor tracking, line wrapping, vertical scrolling, and ANSI escape
 * sequence handling (cursor movement, erase, colour/SGR attributes).
 *
 * The ANSI parser is modelled after XNU's gc_putchar() state machine
 * in osfmk/console/video_console.c, which is derived from NetBSD's
 * ite.c (University of Utah, 1988). The state machine processes one
 * character at a time and handles:
 *
 *   - CSI sequences (ESC [ ...): cursor movement (A/B/C/D), cursor
 *     position (H/f), erase display (J), erase line (K), SGR/colour (m)
 *   - Simple ESC sequences: ESC c (reset), ESC D (index), ESC M
 *     (reverse index), ESC 7/8 (save/restore cursor)
 *   - DEC private modes: ESC [ ? 25 h/l (cursor show/hide),
 *     ESC [ ? 7 h/l (autowrap on/off)
 *
 * Architecture:
 *   - Maintains a cursor position (row, col) in character cells
 *   - Each cell is 8x16 pixels (matching the VGA font)
 *   - Text grid dimensions: (fb_width / 8) columns x (fb_height / 16) rows
 *   - Scrolling copies the framebuffer up by 16 pixel rows
 *   - Dirty tracking: flushes only changed rows
 *
 * Reference: XNU osfmk/console/video_console.c (gc_putchar, gc_putc_*)
 *            Linux drivers/video/console/fbcon.c
 */

#include <kiseki/types.h>
#include <kern/kprintf.h>
#include <kern/sync.h>
#include <kern/tty.h>
#include <kern/fbconsole.h>
#include <drivers/virtio_gpu.h>

/* ============================================================================
 * Font Data (defined in font8x16.c)
 * ============================================================================ */

extern const uint8_t font8x16_data[256][16];

#define FONT_WIDTH  8
#define FONT_HEIGHT 16

/* ============================================================================
 * ANSI Colour Table
 *
 * B8G8R8X8 format: byte 0 = Blue, byte 1 = Green, byte 2 = Red, byte 3 = X
 * We pack as a uint32_t where bits [7:0]=B, [15:8]=G, [23:16]=R, [31:24]=X.
 *
 * Standard 8 ANSI colours, matching XNU's vc_colors[] for 32-bit depth.
 * ============================================================================ */

static const uint32_t ansi_colours[8] = {
    0x00000000,  /* 0: Black   (R=00, G=00, B=00) */
    0x000000AA,  /* 1: Red     (R=AA, G=00, B=00) */
    0x0000AA00,  /* 2: Green   (R=00, G=AA, B=00) */
    0x0000AAAA,  /* 3: Yellow  (R=AA, G=AA, B=00) — dark yellow/brown */
    0x00AA0000,  /* 4: Blue    (R=00, G=00, B=AA) */
    0x00AA00AA,  /* 5: Magenta (R=AA, G=00, B=AA) */
    0x00AAAA00,  /* 6: Cyan    (R=00, G=AA, B=AA) */
    0x00CCCCCC,  /* 7: White   (R=CC, G=CC, B=CC) — light grey */
};

/* Bright variants for bold text (SGR 1 + colour) */
static const uint32_t ansi_bright_colours[8] = {
    0x00555555,  /* 0: Bright Black  (dark grey) */
    0x000055FF,  /* 1: Bright Red */
    0x0055FF55,  /* 2: Bright Green */
    0x0055FFFF,  /* 3: Bright Yellow */
    0x00FF5555,  /* 4: Bright Blue */
    0x00FF55FF,  /* 5: Bright Magenta */
    0x00FFFF55,  /* 6: Bright Cyan */
    0x00FFFFFF,  /* 7: Bright White */
};

/* Default colours */
#define DEFAULT_FG_IDX  7   /* White */
#define DEFAULT_BG_IDX  0   /* Black */

/* ============================================================================
 * VT100 State Machine (modelled after XNU gc_putchar)
 *
 * States match XNU's enum vt100state_e.
 * ============================================================================ */

enum vt100state {
    ES_NORMAL   = 0,    /* Ground state — printing characters */
    ES_ESC      = 1,    /* Received ESC, waiting for next byte */
    ES_CSI_INIT = 2,    /* Received ESC [, initialising parameters */
    ES_CSI_PARS = 3,    /* Collecting CSI numeric parameters */
    ES_CSI_EXEC = 4,    /* Parameters collected, dispatching command */
    ES_DEC_PRIV = 5,    /* DEC private mode (ESC [ ?) */
};

/* Maximum CSI parameters — matches XNU MAXPARS */
#define VT100_MAXPARS   16

/* SGR attribute flags */
#define ATTR_NONE       0x00
#define ATTR_BOLD       0x01
#define ATTR_UNDERLINE  0x02
#define ATTR_REVERSE    0x04

/* ============================================================================
 * Console State
 * ============================================================================ */

static bool fb_active = false;

/*
 * fbconsole_lock — Protects ALL mutable console state: cursor position,
 * VT100 parser state, dirty tracking, and framebuffer pixel writes.
 *
 * Must use irqsave variant because kprintf can be called from interrupt
 * context (e.g., trap handler), while tty_write calls fbconsole_putc from
 * thread context. Without irqsave, an interrupt arriving while tty_write
 * holds the lock would deadlock.
 *
 * IMPORTANT: This lock must NEVER be held during GPU command submission
 * (virtio_gpu_flush). Pattern: lock → pixel writes + dirty tracking →
 * snapshot dirty region → unlock → GPU flush with snapshot (outside lock).
 *
 * Reference: XNU osfmk/console/video_console.c vcputc_lock
 */
static spinlock_t fbconsole_lock = SPINLOCK_INIT;

/* Framebuffer parameters (cached from virtio_gpu_get_fb) */
static uint32_t *fb_base;      /* Pointer to framebuffer pixel data */
static uint32_t  fb_width;     /* Width in pixels */
static uint32_t  fb_height;    /* Height in pixels */
static uint32_t  fb_pitch;     /* Bytes per row */

/* Text grid dimensions */
static uint32_t cols;           /* Number of text columns */
static uint32_t rows;           /* Number of text rows */

/* Cursor position (0-based) */
static uint32_t cur_col;
static uint32_t cur_row;

/* VT100 parser state */
static enum vt100state vt_state;
static uint32_t vt_par[VT100_MAXPARS];  /* CSI parameter values */
static uint32_t vt_numpars;              /* Number of parameters collected */

/* Text attributes */
static uint8_t  vt_attr;                /* ATTR_BOLD | ATTR_UNDERLINE | ATTR_REVERSE */
static uint8_t  vt_fg_idx;             /* Foreground colour index (0–7) */
static uint8_t  vt_bg_idx;             /* Background colour index (0–7) */

/* Autowrap mode (DECAWM) — enabled by default, matches XNU */
static bool vt_wrap_mode;

/* Saved cursor state (ESC 7 / ESC 8, matching XNU DECSC/DECRC) */
static uint32_t saved_col;
static uint32_t saved_row;
static uint8_t  saved_attr;
static uint8_t  saved_fg_idx;
static uint8_t  saved_bg_idx;

/* Dirty row tracking for efficient flushing.
 * We track the topmost and bottommost dirty pixel row. */
static uint32_t dirty_top;
static uint32_t dirty_bottom;
static bool     has_dirty;

/* The fbconsole's own TTY */
static struct tty fbcon_tty;

/* ============================================================================
 * Colour Helpers
 * ============================================================================ */

/*
 * current_fg / current_bg - Resolve the effective foreground and background
 * pixel colours, accounting for bold (bright) and reverse attributes.
 */
static uint32_t current_fg(void)
{
    uint8_t fg = vt_fg_idx;
    uint8_t bg = vt_bg_idx;

    if (vt_attr & ATTR_REVERSE) {
        uint8_t tmp = fg;
        fg = bg;
        bg = tmp;
        (void)bg;
    }

    if (vt_attr & ATTR_BOLD)
        return ansi_bright_colours[fg & 7];
    return ansi_colours[fg & 7];
}

static uint32_t current_bg(void)
{
    uint8_t fg = vt_fg_idx;
    uint8_t bg = vt_bg_idx;

    if (vt_attr & ATTR_REVERSE) {
        uint8_t tmp = fg;
        fg = bg;
        bg = tmp;
        (void)fg;
    }

    return ansi_colours[bg & 7];
}

/* ============================================================================
 * Pixel Drawing
 * ============================================================================ */

static inline void fb_put_pixel(uint32_t x, uint32_t y, uint32_t colour)
{
    if (x >= fb_width || y >= fb_height)
        return;
    uint32_t *row = (uint32_t *)((uint8_t *)fb_base + y * fb_pitch);
    row[x] = colour;
}

/*
 * fb_draw_glyph - Render an 8x16 glyph at a character cell position.
 */
static void fb_draw_glyph(uint32_t col, uint32_t row,
                           uint8_t ch, uint32_t fg, uint32_t bg)
{
    uint32_t px = col * FONT_WIDTH;
    uint32_t py = row * FONT_HEIGHT;

    const uint8_t *glyph = font8x16_data[ch];

    for (uint32_t y = 0; y < FONT_HEIGHT; y++) {
        uint8_t bits = glyph[y];
        uint32_t *rowptr = (uint32_t *)((uint8_t *)fb_base +
                                         (py + y) * fb_pitch);
        for (uint32_t x = 0; x < FONT_WIDTH; x++) {
            uint32_t colour = (bits & (0x80 >> x)) ? fg : bg;
            if (px + x < fb_width)
                rowptr[px + x] = colour;
        }
    }
}

/*
 * fb_clear_row - Fill a text row with the current background colour.
 */
static void fb_clear_row(uint32_t row)
{
    uint32_t bg = current_bg();
    uint32_t py = row * FONT_HEIGHT;
    for (uint32_t y = 0; y < FONT_HEIGHT && (py + y) < fb_height; y++) {
        uint32_t *rowptr = (uint32_t *)((uint8_t *)fb_base +
                                         (py + y) * fb_pitch);
        for (uint32_t x = 0; x < fb_width; x++)
            rowptr[x] = bg;
    }
}

/*
 * fb_clear_cells - Clear a range of character cells on a single row.
 *
 * Used by Erase in Line (EL) and Erase Characters (ECH) commands.
 */
static void fb_clear_cells(uint32_t row, uint32_t start_col, uint32_t end_col)
{
    uint32_t bg = current_bg();

    if (end_col > cols) end_col = cols;
    if (start_col >= end_col) return;

    uint32_t px_start = start_col * FONT_WIDTH;
    uint32_t px_end = end_col * FONT_WIDTH;
    if (px_end > fb_width) px_end = fb_width;

    uint32_t py = row * FONT_HEIGHT;
    for (uint32_t y = 0; y < FONT_HEIGHT && (py + y) < fb_height; y++) {
        uint32_t *rowptr = (uint32_t *)((uint8_t *)fb_base +
                                         (py + y) * fb_pitch);
        for (uint32_t x = px_start; x < px_end; x++)
            rowptr[x] = bg;
    }
}

/* ============================================================================
 * Dirty Tracking and Flushing
 * ============================================================================ */

static void mark_dirty(uint32_t row)
{
    uint32_t py_top = row * FONT_HEIGHT;
    uint32_t py_bot = py_top + FONT_HEIGHT;
    if (py_bot > fb_height) py_bot = fb_height;

    if (!has_dirty) {
        dirty_top = py_top;
        dirty_bottom = py_bot;
        has_dirty = true;
    } else {
        if (py_top < dirty_top) dirty_top = py_top;
        if (py_bot > dirty_bottom) dirty_bottom = py_bot;
    }
}

static void mark_all_dirty(void)
{
    dirty_top = 0;
    dirty_bottom = fb_height;
    has_dirty = true;
}

static bool take_dirty_snapshot(uint32_t *out_top, uint32_t *out_bottom)
{
    if (!has_dirty || !fb_active)
        return false;

    *out_top = dirty_top;
    *out_bottom = dirty_bottom;
    has_dirty = false;
    return true;
}

static void gpu_flush_region(uint32_t top, uint32_t bottom)
{
    uint32_t h = bottom - top;
    if (h > 0)
        virtio_gpu_flush(0, top, fb_width, h);
}

/* ============================================================================
 * Scrolling
 * ============================================================================ */

static void fb_scroll_up(void)
{
    uint32_t row_bytes = fb_pitch;
    uint32_t scroll_pixels = FONT_HEIGHT;
    uint32_t copy_height = fb_height - scroll_pixels;

    uint8_t *base = (uint8_t *)fb_base;
    for (uint32_t y = 0; y < copy_height; y++) {
        uint32_t *dst = (uint32_t *)(base + y * row_bytes);
        uint32_t *src = (uint32_t *)(base + (y + scroll_pixels) * row_bytes);
        for (uint32_t x = 0; x < fb_width; x++)
            dst[x] = src[x];
    }

    fb_clear_row(rows - 1);
    mark_all_dirty();
}

/*
 * fb_scroll_down - Scroll the framebuffer down by one text row.
 *
 * Used by ESC M (Reverse Index) when cursor is at the top.
 */
static void fb_scroll_down(void)
{
    uint32_t row_bytes = fb_pitch;
    uint32_t scroll_pixels = FONT_HEIGHT;
    uint32_t copy_height = fb_height - scroll_pixels;

    uint8_t *base = (uint8_t *)fb_base;
    /* Copy rows downward — must work from bottom to top to avoid overlap */
    for (uint32_t y = copy_height; y > 0; y--) {
        uint32_t *dst = (uint32_t *)(base + (y - 1 + scroll_pixels) * row_bytes);
        uint32_t *src = (uint32_t *)(base + (y - 1) * row_bytes);
        for (uint32_t x = 0; x < fb_width; x++)
            dst[x] = src[x];
    }

    fb_clear_row(0);
    mark_all_dirty();
}

/* ============================================================================
 * VT100 Parser — CSI Command Dispatch
 *
 * Called when all CSI parameters have been collected and the final
 * command byte arrives. Matches XNU's gc_putc_gotpars().
 * ============================================================================ */

static bool vt_csi_dispatch(unsigned char cmd)
{
    bool needs_flush = false;
    uint32_t n;

    switch (cmd) {

    /* --- Cursor Movement ------------------------------------------------- */

    case 'A':   /* CUU — Cursor Up */
        n = vt_par[0] ? vt_par[0] : 1;
        if (n > cur_row)
            cur_row = 0;
        else
            cur_row -= n;
        break;

    case 'B':   /* CUD — Cursor Down */
        n = vt_par[0] ? vt_par[0] : 1;
        cur_row += n;
        if (cur_row >= rows)
            cur_row = rows - 1;
        break;

    case 'C':   /* CUF — Cursor Forward */
        n = vt_par[0] ? vt_par[0] : 1;
        cur_col += n;
        if (cur_col >= cols)
            cur_col = cols - 1;
        break;

    case 'D':   /* CUB — Cursor Back */
        n = vt_par[0] ? vt_par[0] : 1;
        if (n > cur_col)
            cur_col = 0;
        else
            cur_col -= n;
        break;

    case 'H':   /* CUP — Cursor Position (1-indexed) */
    case 'f':   /* HVP — Horizontal and Vertical Position */
        cur_row = vt_par[0] ? vt_par[0] - 1 : 0;
        cur_col = (vt_numpars >= 2 && vt_par[1]) ? vt_par[1] - 1 : 0;
        if (cur_row >= rows) cur_row = rows - 1;
        if (cur_col >= cols) cur_col = cols - 1;
        break;

    case 'G':   /* CHA — Cursor Horizontal Absolute (1-indexed) */
        cur_col = vt_par[0] ? vt_par[0] - 1 : 0;
        if (cur_col >= cols) cur_col = cols - 1;
        break;

    case 'd':   /* VPA — Vertical Position Absolute (1-indexed) */
        cur_row = vt_par[0] ? vt_par[0] - 1 : 0;
        if (cur_row >= rows) cur_row = rows - 1;
        break;

    /* --- Erase Commands -------------------------------------------------- */

    case 'J':   /* ED — Erase in Display */
        switch (vt_par[0]) {
        case 0: /* Cursor to end of screen */
            /* Clear rest of current line */
            fb_clear_cells(cur_row, cur_col, cols);
            mark_dirty(cur_row);
            /* Clear all rows below */
            for (uint32_t r = cur_row + 1; r < rows; r++) {
                fb_clear_row(r);
                mark_dirty(r);
            }
            break;
        case 1: /* Start of screen to cursor */
            /* Clear all rows above */
            for (uint32_t r = 0; r < cur_row; r++) {
                fb_clear_row(r);
                mark_dirty(r);
            }
            /* Clear current line up to cursor */
            fb_clear_cells(cur_row, 0, cur_col + 1);
            mark_dirty(cur_row);
            break;
        case 2: /* Entire screen */
            for (uint32_t r = 0; r < rows; r++) {
                fb_clear_row(r);
                mark_dirty(r);
            }
            break;
        }
        needs_flush = true;
        break;

    case 'K':   /* EL — Erase in Line */
        switch (vt_par[0]) {
        case 0: /* Cursor to end of line */
            fb_clear_cells(cur_row, cur_col, cols);
            break;
        case 1: /* Start of line to cursor */
            fb_clear_cells(cur_row, 0, cur_col + 1);
            break;
        case 2: /* Entire line */
            fb_clear_cells(cur_row, 0, cols);
            break;
        }
        mark_dirty(cur_row);
        needs_flush = true;
        break;

    case 'X':   /* ECH — Erase Characters */
        n = vt_par[0] ? vt_par[0] : 1;
        fb_clear_cells(cur_row, cur_col, cur_col + n);
        mark_dirty(cur_row);
        needs_flush = true;
        break;

    /* --- SGR — Select Graphic Rendition --------------------------------- */

    case 'm': {
        /*
         * Process each parameter. SGR 0 resets, 1 = bold, 4 = underline,
         * 7 = reverse, 22 = bold off, 24 = underline off, 27 = reverse off,
         * 30–37 = fg colour, 40–47 = bg colour.
         *
         * Matches XNU gc_putc_gotpars() case 'm'.
         */
        for (uint32_t i = 0; i < vt_numpars; i++) {
            uint32_t p = vt_par[i];

            if (p == 0) {
                /* Reset all attributes */
                vt_attr = ATTR_NONE;
                vt_fg_idx = DEFAULT_FG_IDX;
                vt_bg_idx = DEFAULT_BG_IDX;
            } else if (p == 1) {
                vt_attr |= ATTR_BOLD;
            } else if (p == 4) {
                vt_attr |= ATTR_UNDERLINE;
            } else if (p == 7) {
                vt_attr |= ATTR_REVERSE;
            } else if (p == 22) {
                vt_attr &= ~ATTR_BOLD;
            } else if (p == 24) {
                vt_attr &= ~ATTR_UNDERLINE;
            } else if (p == 27) {
                vt_attr &= ~ATTR_REVERSE;
            } else if (p >= 30 && p <= 37) {
                vt_fg_idx = (uint8_t)(p - 30);
            } else if (p >= 40 && p <= 47) {
                vt_bg_idx = (uint8_t)(p - 40);
            } else if (p == 39) {
                /* Default foreground */
                vt_fg_idx = DEFAULT_FG_IDX;
            } else if (p == 49) {
                /* Default background */
                vt_bg_idx = DEFAULT_BG_IDX;
            }
            /* Other SGR codes (2, 3, 5, 8, 9, 38, 48, 90–107, etc.)
             * are silently ignored, matching XNU behaviour. */
        }
        break;
    }

    /* --- Scroll Region --------------------------------------------------- */

    case 'r':   /* DECSTBM — Set Scrolling Region */
        /* We don't implement scroll regions yet; acknowledge by
         * resetting cursor to home. Matches XNU default behaviour. */
        cur_row = 0;
        cur_col = 0;
        break;

    /* --- Other CSI commands (gracefully ignored) ------------------------- */

    case 'L':   /* IL — Insert Lines (would need scroll region) */
    case 'M':   /* DL — Delete Lines (would need scroll region) */
    case 'P':   /* DCH — Delete Characters */
    case '@':   /* ICH — Insert Characters */
    case 'S':   /* SU — Scroll Up */
    case 'T':   /* SD — Scroll Down */
    case 'g':   /* TBC — Tab Clear */
    case 'h':   /* SM — Set Mode (non-DEC) */
    case 'l':   /* RM — Reset Mode (non-DEC) */
    case 'n':   /* DSR — Device Status Report (would need response) */
    case 's':   /* SCP — Save Cursor Position (ANSI.SYS) */
    case 'u':   /* RCP — Restore Cursor Position (ANSI.SYS) */
    case 'c':   /* DA — Device Attributes (would need response) */
    case 'q':   /* DECLL — LED control */
        /* Silently ignored */
        break;

    default:
        /* Unknown CSI final byte — ignore */
        break;
    }

    return needs_flush;
}

/* ============================================================================
 * VT100 Parser — DEC Private Mode Dispatch
 *
 * Handles ESC [ ? <n> h/l sequences. Matches XNU's gc_putc_askcmd().
 * ============================================================================ */

static void vt_dec_priv_dispatch(unsigned char cmd)
{
    switch (cmd) {
    case 'h':   /* Set mode */
        switch (vt_par[0]) {
        case 7:     /* DECAWM — Auto Wrap Mode on */
            vt_wrap_mode = true;
            break;
        case 25:    /* DECTCEM — Cursor visible (ignored — no cursor yet) */
            break;
        case 1049:  /* Alternate screen buffer (ignored) */
            break;
        }
        break;

    case 'l':   /* Reset mode */
        switch (vt_par[0]) {
        case 7:     /* DECAWM — Auto Wrap Mode off */
            vt_wrap_mode = false;
            break;
        case 25:    /* DECTCEM — Cursor invisible (ignored) */
            break;
        case 1049:  /* Alternate screen buffer (ignored) */
            break;
        }
        break;

    default:
        /* Unknown DEC private final byte — ignore */
        break;
    }
}

/* ============================================================================
 * VT100 Parser — Main Entry Point
 *
 * Character-at-a-time state machine matching XNU's gc_putchar().
 * Called with fbconsole_lock held.
 *
 * Returns true if the caller should flush the dirty region to the GPU.
 * ============================================================================ */

static bool fbconsole_putc_locked(char c)
{
    unsigned char ch = (unsigned char)c;
    bool needs_flush = false;

    switch (vt_state) {

    /* -------------------------------------------------------------------- */
    case ES_NORMAL:
    /* -------------------------------------------------------------------- */
        switch (ch) {

        case 0x00:  /* NUL — ignore */
            break;

        case 0x07:  /* BEL — no audible bell */
            break;

        case '\b':  /* BS — Backspace */
        case 0x7F:  /* DEL — also backspace */
            if (cur_col > 0)
                cur_col--;
            break;

        case '\t':  /* HT — Horizontal Tab */
        {
            uint32_t next = (cur_col + 8) & ~7u;
            if (next >= cols)
                next = cols - 1;
            /* Fill with spaces using current attributes */
            while (cur_col < next) {
                fb_draw_glyph(cur_col, cur_row, ' ',
                              current_fg(), current_bg());
                cur_col++;
            }
            mark_dirty(cur_row);
            break;
        }

        case '\n':  /* LF — Line Feed */
        case 0x0B:  /* VT — Vertical Tab (treated as LF) */
        case 0x0C:  /* FF — Form Feed (treated as LF) */
            cur_row++;
            if (cur_row >= rows) {
                fb_scroll_up();
                cur_row = rows - 1;
            }
            mark_dirty(cur_row);
            needs_flush = true;
            break;

        case '\r':  /* CR — Carriage Return */
            cur_col = 0;
            break;

        case 0x0E:  /* SO — Shift Out (select G1 charset — ignored) */
        case 0x0F:  /* SI — Shift In (select G0 charset — ignored) */
            break;

        case 0x1B:  /* ESC — start escape sequence */
            vt_state = ES_ESC;
            break;

        default:
            if (ch >= 0x20) {
                /* Printable character — draw with current attributes */
                fb_draw_glyph(cur_col, cur_row, ch,
                              current_fg(), current_bg());
                mark_dirty(cur_row);
                cur_col++;

                if (cur_col >= cols) {
                    if (vt_wrap_mode) {
                        cur_col = 0;
                        cur_row++;
                        if (cur_row >= rows) {
                            fb_scroll_up();
                            cur_row = rows - 1;
                        }
                        needs_flush = true;
                    } else {
                        /* No wrap: stay at last column */
                        cur_col = cols - 1;
                    }
                }
            }
            /* Control characters < 0x20 not handled above are ignored */
            break;
        }
        break;

    /* -------------------------------------------------------------------- */
    case ES_ESC:
    /* -------------------------------------------------------------------- */
        /*
         * Received ESC, now dispatch based on the following byte.
         * Matches XNU gc_putc_esc().
         */
        vt_state = ES_NORMAL;  /* Default: return to normal */

        switch (ch) {
        case '[':   /* CSI introducer */
            vt_state = ES_CSI_INIT;
            break;

        case 'c':   /* RIS — Full Reset */
            vt_attr = ATTR_NONE;
            vt_fg_idx = DEFAULT_FG_IDX;
            vt_bg_idx = DEFAULT_BG_IDX;
            vt_wrap_mode = true;
            cur_row = 0;
            cur_col = 0;
            /* Clear screen */
            for (uint32_t r = 0; r < rows; r++)
                fb_clear_row(r);
            mark_all_dirty();
            needs_flush = true;
            break;

        case 'D':   /* IND — Index (line feed, XNU gc_putc_esc case 'D') */
            cur_row++;
            if (cur_row >= rows) {
                fb_scroll_up();
                cur_row = rows - 1;
            }
            mark_dirty(cur_row);
            needs_flush = true;
            break;

        case 'E':   /* NEL — Next Line (CR + LF) */
            cur_col = 0;
            cur_row++;
            if (cur_row >= rows) {
                fb_scroll_up();
                cur_row = rows - 1;
            }
            mark_dirty(cur_row);
            needs_flush = true;
            break;

        case 'M':   /* RI — Reverse Index */
            if (cur_row == 0) {
                fb_scroll_down();
                needs_flush = true;
            } else {
                cur_row--;
            }
            break;

        case '7':   /* DECSC — Save Cursor */
            saved_col = cur_col;
            saved_row = cur_row;
            saved_attr = vt_attr;
            saved_fg_idx = vt_fg_idx;
            saved_bg_idx = vt_bg_idx;
            break;

        case '8':   /* DECRC — Restore Cursor */
            cur_col = saved_col;
            cur_row = saved_row;
            vt_attr = saved_attr;
            vt_fg_idx = saved_fg_idx;
            vt_bg_idx = saved_bg_idx;
            if (cur_row >= rows) cur_row = rows - 1;
            if (cur_col >= cols) cur_col = cols - 1;
            break;

        case 'H':   /* HTS — Horizontal Tab Set (ignored) */
        case '>':   /* DECKPNM — Normal keypad (ignored) */
        case '=':   /* DECKPAM — Application keypad (ignored) */
        case '(':   /* ESC ( — G0 charset select (ignored) */
        case ')':   /* ESC ) — G1 charset select (ignored) */
        case '#':   /* ESC # — DEC char size (ignored) */
        case 'Z':   /* DECID — Identify terminal (ignored) */
        default:
            /* Unknown ESC sequence — already reset to ES_NORMAL */
            break;
        }
        break;

    /* -------------------------------------------------------------------- */
    case ES_CSI_INIT:
    /* -------------------------------------------------------------------- */
        /*
         * Received ESC [, now initialise parameter storage and immediately
         * process this character. Matches XNU gc_putc_square().
         */
        for (uint32_t i = 0; i < VT100_MAXPARS; i++)
            vt_par[i] = 0;
        vt_numpars = 0;
        vt_state = ES_CSI_PARS;

        /* Fall through to parameter collection — process this char */
        /* FALLTHROUGH */

    /* -------------------------------------------------------------------- */
    case ES_CSI_PARS:
    /* -------------------------------------------------------------------- */
        /*
         * Collecting CSI parameters (digits and semicolons).
         * Matches XNU gc_putc_getpars().
         */
        if (ch == '?') {
            /* DEC private mode introducer */
            vt_state = ES_DEC_PRIV;
        } else if (ch >= '0' && ch <= '9') {
            /* Accumulate digit into current parameter */
            vt_par[vt_numpars] = vt_par[vt_numpars] * 10 + (ch - '0');
        } else if (ch == ';') {
            /* Advance to next parameter */
            if (vt_numpars < VT100_MAXPARS - 1)
                vt_numpars++;
        } else {
            /* Final byte — dispatch the command */
            vt_numpars++;  /* Convert from index to count */
            vt_state = ES_NORMAL;
            needs_flush = vt_csi_dispatch(ch);
        }
        break;

    /* -------------------------------------------------------------------- */
    case ES_DEC_PRIV:
    /* -------------------------------------------------------------------- */
        /*
         * DEC private mode parameter collection (ESC [ ? ...).
         * Matches XNU gc_putc_askcmd().
         */
        if (ch >= '0' && ch <= '9') {
            vt_par[0] = vt_par[0] * 10 + (ch - '0');
        } else {
            /* Final byte — dispatch DEC private command */
            vt_state = ES_NORMAL;
            vt_dec_priv_dispatch(ch);
        }
        break;

    /* -------------------------------------------------------------------- */
    default:
    /* -------------------------------------------------------------------- */
        /* Unknown state — self-correct to normal (matches XNU default) */
        vt_state = ES_NORMAL;
        break;
    }

    return needs_flush;
}

/* ============================================================================
 * Public Output Functions
 * ============================================================================ */

/*
 * fbconsole_putc - Write one character to the framebuffer console.
 *
 * Acquires fbconsole_lock to protect cursor state and pixel writes,
 * then releases it BEFORE submitting any GPU commands.
 */
void fbconsole_putc(char c)
{
    if (!fb_active)
        return;

    uint64_t irqflags;
    uint32_t snap_top, snap_bottom;
    bool do_flush;

    spin_lock_irqsave(&fbconsole_lock, &irqflags);
    bool needs_flush = fbconsole_putc_locked(c);
    do_flush = needs_flush && take_dirty_snapshot(&snap_top, &snap_bottom);
    spin_unlock_irqrestore(&fbconsole_lock, irqflags);

    if (do_flush)
        gpu_flush_region(snap_top, snap_bottom);
}

/*
 * fbconsole_flush - Explicitly flush any pending dirty region to the GPU.
 */
void fbconsole_flush(void)
{
    if (!fb_active)
        return;

    uint64_t irqflags;
    uint32_t snap_top, snap_bottom;
    bool do_flush;

    spin_lock_irqsave(&fbconsole_lock, &irqflags);
    do_flush = take_dirty_snapshot(&snap_top, &snap_bottom);
    spin_unlock_irqrestore(&fbconsole_lock, irqflags);

    if (do_flush)
        gpu_flush_region(snap_top, snap_bottom);
}

/* ============================================================================
 * TTY Setup
 * ============================================================================ */

static void fbcon_tty_init(void)
{
    struct tty *tp = &fbcon_tty;
    struct termios *t = &tp->t_termios;

    /* Clear everything */
    for (uint64_t i = 0; i < sizeof(*tp); i++)
        ((uint8_t *)tp)[i] = 0;

    /* Same termios as console_tty (serial) — see tty.c tty_init() */
    t->c_iflag = ICRNL | IXON | IXANY | IMAXBEL;
    t->c_oflag = OPOST | ONLCR | OXTABS;
    t->c_cflag = CS8 | CREAD | CLOCAL;
    t->c_lflag = ECHO | ECHOE | ECHOK | ECHOKE | ECHOCTL |
                 ICANON | ISIG | IEXTEN;

    t->c_cc[VEOF]     = 0x04;
    t->c_cc[VEOL]     = 0xFF;
    t->c_cc[VEOL2]    = 0xFF;
    t->c_cc[VERASE]   = 0x7F;
    t->c_cc[VWERASE]  = 0x17;
    t->c_cc[VKILL]    = 0x15;
    t->c_cc[VREPRINT] = 0x12;
    t->c_cc[VINTR]    = 0x03;
    t->c_cc[VQUIT]    = 0x1C;
    t->c_cc[VSUSP]    = 0x1A;
    t->c_cc[VDSUSP]   = 0x19;
    t->c_cc[VSTART]   = 0x11;
    t->c_cc[VSTOP]    = 0x13;
    t->c_cc[VLNEXT]   = 0x16;
    t->c_cc[VDISCARD] = 0x0F;
    t->c_cc[VMIN]     = 1;
    t->c_cc[VTIME]    = 0;
    t->c_cc[VSTATUS]  = 0x14;

    t->c_ispeed = B115200;
    t->c_ospeed = B115200;

    /* Window size from the text grid */
    tp->t_winsize.ws_row = (uint16_t)rows;
    tp->t_winsize.ws_col = (uint16_t)cols;
    tp->t_winsize.ws_xpixel = (uint16_t)fb_width;
    tp->t_winsize.ws_ypixel = (uint16_t)fb_height;

    tp->t_pgrp = 0;
    tp->t_session = 0;
    tp->t_flags = TTY_OPENED;

    /* Output goes to framebuffer */
    tp->t_putc = fbconsole_putc;
    tp->t_devprivate = NULL;

    tp->t_linepos = 0;
    tp->t_rawhead = 0;
    tp->t_rawtail = 0;
    tp->t_rawcount = 0;
}

/* ============================================================================
 * Public API
 * ============================================================================ */

int fbconsole_init(void)
{
    const struct framebuffer_info *fb = virtio_gpu_get_fb();
    if (!fb || !fb->active) {
        kprintf("[fbconsole] No framebuffer available\n");
        return -1;
    }

    fb_base   = (uint32_t *)fb->phys_addr;
    fb_width  = fb->width;
    fb_height = fb->height;
    fb_pitch  = fb->pitch;

    /* Calculate text grid */
    cols = fb_width / FONT_WIDTH;
    rows = fb_height / FONT_HEIGHT;

    if (cols == 0 || rows == 0) {
        kprintf("[fbconsole] Framebuffer too small for text console\n");
        return -1;
    }

    /* Initialise cursor and VT100 parser state */
    cur_col = 0;
    cur_row = 0;
    has_dirty = false;
    vt_state = ES_NORMAL;
    vt_attr = ATTR_NONE;
    vt_fg_idx = DEFAULT_FG_IDX;
    vt_bg_idx = DEFAULT_BG_IDX;
    vt_wrap_mode = true;
    saved_col = 0;
    saved_row = 0;
    saved_attr = ATTR_NONE;
    saved_fg_idx = DEFAULT_FG_IDX;
    saved_bg_idx = DEFAULT_BG_IDX;

    /* Clear the screen to background colour */
    uint32_t total_pixels = fb_width * fb_height;
    for (uint32_t i = 0; i < total_pixels; i++)
        fb_base[i] = ansi_colours[DEFAULT_BG_IDX];

    fb_active = true;

    /* Flush the initial clear to display */
    virtio_gpu_flush_all();

    /* Initialise the fbconsole TTY */
    fbcon_tty_init();

    kprintf("[fbconsole] %ux%u text grid (%ux%u pixels, %u bpp)\n",
            cols, rows, fb_width, fb_height, fb->bpp);

    return 0;
}

struct tty *fbconsole_get_tty(void)
{
    if (!fb_active)
        return NULL;
    return &fbcon_tty;
}

bool fbconsole_active(void)
{
    return fb_active;
}
