/*
 * Kiseki OS - VirtIO Input Driver (Keyboard + Tablet)
 *
 * Receives keyboard events from QEMU's virtio-keyboard-device and
 * absolute pointer events from QEMU's virtio-tablet-device. Supports
 * TWO simultaneous VirtIO input devices by distinguishing them via
 * config space queries (EV_BITS for EV_ABS vs EV_KEY).
 *
 * Architecture:
 *   1. Scan MMIO slots for VirtIO input devices (type 18)
 *   2. Query config space to identify keyboard vs tablet
 *   3. Set up separate eventq (queue 0) for each device
 *   4. On IRQ, process completed event buffers from the used ring
 *   5. Keyboard: convert keycodes to ASCII, inject into fbcon TTY
 *   6. Tablet: track absolute cursor position and button state
 *   7. Both: push HID events into shared ring buffer for userland
 *   8. Re-post consumed buffers to keep the eventqs fed
 *
 * The driver maintains modifier state (shift, ctrl, alt, capslock)
 * and uses a standard US QWERTY keymap for scancode-to-ASCII conversion.
 *
 * Reference: VirtIO Specification v1.2, Section 5.8 -- Input Device
 *            Linux drivers/virtio/virtio_input.c
 *            Linux include/uapi/linux/input-event-codes.h
 */

#include <kiseki/types.h>
#include <kiseki/platform.h>
#include <kern/kprintf.h>
#include <kern/tty.h>
#include <kern/fbconsole.h>
#include <kern/hid_event.h>
#include <drivers/virtio.h>
#include <drivers/virtio_input.h>
#include <drivers/gic.h>

/* ============================================================================
 * MMIO Helpers (same as virtio_blk.c / virtio_gpu.c)
 * ============================================================================ */

static inline void mmio_write32(uint64_t addr, uint32_t val)
{
    *(volatile uint32_t *)addr = val;
}

static inline uint32_t mmio_read32(uint64_t addr)
{
    return *(volatile uint32_t *)addr;
}

static inline uint8_t mmio_read8(uint64_t addr)
{
    return *(volatile uint8_t *)addr;
}

static inline void mmio_write8(uint64_t addr, uint8_t val)
{
    *(volatile uint8_t *)addr = val;
}

static inline void dsb(void)
{
    __asm__ volatile("dsb sy" ::: "memory");
}

/* ============================================================================
 * VirtIO Input Config Space Offsets (from MMIO base + 0x100)
 *
 * struct virtio_input_config {
 *     u8 select;      // +0x100
 *     u8 subsel;      // +0x101
 *     u8 size;        // +0x102
 *     u8 reserved[5]; // +0x103..0x107
 *     u8 data[128];   // +0x108..0x187
 * };
 * ============================================================================ */

#define VIRTIO_INPUT_CONFIG_SELECT  0x100
#define VIRTIO_INPUT_CONFIG_SUBSEL  0x101
#define VIRTIO_INPUT_CONFIG_SIZE    0x102
#define VIRTIO_INPUT_CONFIG_DATA    0x108

/* ============================================================================
 * Driver State — Keyboard
 * ============================================================================ */

static struct virtio_device kbd_dev;
static bool kbd_found = false;
static uint32_t kbd_irq_num = 0;

/* ============================================================================
 * Driver State — Tablet
 * ============================================================================ */

static struct virtio_device tablet_dev;
static bool tablet_found = false;
static uint32_t tablet_irq_num = 0;

/* Tablet cursor state (accumulated between SYN events) */
static uint32_t tablet_abs_x = 0;
static uint32_t tablet_abs_y = 0;
static uint32_t tablet_buttons = 0;     /* Bitmask: bit0=left, bit1=right, bit2=middle */
static bool tablet_abs_x_dirty = false;
static bool tablet_abs_y_dirty = false;

/* ============================================================================
 * Keyboard Modifier State
 * ============================================================================ */

static bool shift_held = false;     /* Either shift key pressed */
static bool ctrl_held = false;      /* Either ctrl key pressed */
static bool alt_held = false;       /* Either alt key pressed */
static bool capslock_on = false;    /* Caps lock toggled on */

/* ============================================================================
 * HID Event Ring Buffer
 *
 * Statically allocated in BSS. The physical address is used by
 * IOHIDSystem to create an IOMemoryDescriptor for userland mapping.
 * ============================================================================ */

static struct hid_event_ring g_hid_ring __aligned(PAGE_SIZE);

struct hid_event_ring *hid_event_ring_get(void)
{
    return &g_hid_ring;
}

uint64_t hid_event_ring_get_phys(void)
{
    return (uint64_t)&g_hid_ring;
}

uint64_t hid_event_ring_get_size(void)
{
    return (uint64_t)sizeof(struct hid_event_ring);
}

/*
 * hid_ring_push - Push an event into the HID ring buffer.
 *
 * Called from IRQ context. Single-producer so no locking needed.
 * If the ring is full (consumer not keeping up), the event is dropped.
 */
static void hid_ring_push(const struct hid_event *ev)
{
    struct hid_event_ring *ring = &g_hid_ring;
    uint32_t widx = ring->write_idx;
    uint32_t ridx = ring->read_idx;

    /* Check if ring is full */
    if ((widx - ridx) >= ring->size)
        return;     /* Drop event — consumer not keeping up */

    uint32_t slot = widx % ring->size;
    ring->events[slot] = *ev;

    __asm__ volatile("dmb ish" ::: "memory");
    ring->write_idx = widx + 1;
}

/*
 * hid_get_modifier_flags - Return current modifier bitmask for HID events.
 */
static uint32_t hid_get_modifier_flags(void)
{
    uint32_t flags = 0;
    if (shift_held)     flags |= HID_FLAG_SHIFT;
    if (ctrl_held)      flags |= HID_FLAG_CTRL;
    if (alt_held)       flags |= HID_FLAG_ALT;
    if (capslock_on)    flags |= HID_FLAG_CAPSLOCK;
    return flags;
}

/* ============================================================================
 * DMA Pages for Eventq — Keyboard (Queue 0)
 * ============================================================================ */

static uint8_t kbd_eventq_pages[3 * PAGE_SIZE] __aligned(PAGE_SIZE);

/* ============================================================================
 * DMA Pages for Eventq — Tablet (Queue 0)
 * ============================================================================ */

static uint8_t tablet_eventq_pages[3 * PAGE_SIZE] __aligned(PAGE_SIZE);

/* ============================================================================
 * Event Buffers — separate pools for keyboard and tablet
 * ============================================================================ */

#define NUM_EVENT_BUFS  64

static struct virtio_input_event kbd_event_bufs[NUM_EVENT_BUFS] __aligned(16);
static struct virtio_input_event tablet_event_bufs[NUM_EVENT_BUFS] __aligned(16);

/* ============================================================================
 * Eventq Setup (parameterised for both devices)
 * ============================================================================ */

static int input_setup_eventq(struct virtio_device *dev,
                               uint8_t *dma_pages, uint64_t dma_size,
                               const char *label)
{
    uint64_t base = dev->base;

    /* Select queue 0 (eventq) */
    mmio_write32(base + VIRTIO_MMIO_QUEUE_SEL, 0);
    dsb();

    uint32_t max_size = mmio_read32(base + VIRTIO_MMIO_QUEUE_NUM_MAX);
    if (max_size == 0) {
        kprintf("[%s] eventq not available\n", label);
        return -1;
    }

    uint32_t num = max_size;
    if (num > VIRTQ_MAX_SIZE)
        num = VIRTQ_MAX_SIZE;

    struct virtqueue *vq = &dev->vq[0];
    vq->num = num;

    /* Zero the DMA region */
    for (uint64_t i = 0; i < dma_size; i++)
        dma_pages[i] = 0;

    /* Layout: desc | avail | (padding) | used */
    vq->desc  = (struct virtq_desc *)dma_pages;
    vq->avail = (struct virtq_avail *)(dma_pages + num * sizeof(struct virtq_desc));
    vq->used  = (struct virtq_used *)
                    (dma_pages + ALIGN_UP(num * sizeof(struct virtq_desc)
                                    + sizeof(struct virtq_avail)
                                    + num * sizeof(uint16_t),
                                    PAGE_SIZE));

    /* Initialise free descriptor list */
    for (uint32_t i = 0; i < num; i++) {
        vq->desc[i].next = (uint16_t)(i + 1);
        vq->desc[i].flags = 0;
    }
    vq->desc[num - 1].next = 0;
    vq->free_head = 0;
    vq->num_free = num;
    vq->last_used_idx = 0;

    /* Set queue size */
    mmio_write32(base + VIRTIO_MMIO_QUEUE_NUM, num);
    dsb();

    if (dev->version == 1) {
        /* Legacy interface */
        mmio_write32(base + VIRTIO_MMIO_GUEST_PAGE_SIZE, PAGE_SIZE);
        dsb();
        mmio_write32(base + VIRTIO_MMIO_QUEUE_PFN,
                     (uint32_t)((uint64_t)dma_pages / PAGE_SIZE));
    } else {
        /* Modern interface */
        uint64_t desc_pa  = (uint64_t)vq->desc;
        uint64_t avail_pa = (uint64_t)vq->avail;
        uint64_t used_pa  = (uint64_t)vq->used;

        mmio_write32(base + VIRTIO_MMIO_QUEUE_DESC_LOW,
                     (uint32_t)(desc_pa & 0xFFFFFFFF));
        mmio_write32(base + VIRTIO_MMIO_QUEUE_DESC_HIGH,
                     (uint32_t)(desc_pa >> 32));
        mmio_write32(base + VIRTIO_MMIO_QUEUE_AVAIL_LOW,
                     (uint32_t)(avail_pa & 0xFFFFFFFF));
        mmio_write32(base + VIRTIO_MMIO_QUEUE_AVAIL_HIGH,
                     (uint32_t)(avail_pa >> 32));
        mmio_write32(base + VIRTIO_MMIO_QUEUE_USED_LOW,
                     (uint32_t)(used_pa & 0xFFFFFFFF));
        mmio_write32(base + VIRTIO_MMIO_QUEUE_USED_HIGH,
                     (uint32_t)(used_pa >> 32));
        dsb();
        mmio_write32(base + VIRTIO_MMIO_QUEUE_READY, 1);
    }

    dsb();
    kprintf("[%s] eventq: %u descriptors\n", label, num);
    return 0;
}

/* ============================================================================
 * Virtqueue Helpers (parameterised)
 * ============================================================================ */

static int input_alloc_desc(struct virtqueue *vq)
{
    if (vq->num_free == 0)
        return -1;
    uint32_t idx = vq->free_head;
    vq->free_head = vq->desc[idx].next;
    vq->num_free--;
    return (int)idx;
}

static void input_free_desc(struct virtqueue *vq, uint32_t idx)
{
    vq->desc[idx].next = (uint16_t)vq->free_head;
    vq->desc[idx].flags = 0;
    vq->free_head = idx;
    vq->num_free++;
}

/*
 * input_post_event_buf - Post a single event buffer to the eventq.
 *
 * The buffer is device-writable (the device fills it with an event).
 */
static void input_post_event_buf(struct virtio_device *dev,
                                  struct virtqueue *vq,
                                  struct virtio_input_event *event_bufs,
                                  uint32_t buf_idx)
{
    int desc = input_alloc_desc(vq);
    if (desc < 0)
        return;     /* Out of descriptors */

    vq->desc[desc].addr  = (uint64_t)&event_bufs[buf_idx];
    vq->desc[desc].len   = sizeof(struct virtio_input_event);
    vq->desc[desc].flags = VIRTQ_DESC_F_WRITE;
    vq->desc[desc].next  = 0;

    /* Add to available ring */
    uint16_t avail_idx = vq->avail->idx;
    vq->avail->ring[avail_idx % vq->num] = (uint16_t)desc;
    __asm__ volatile("dmb ish" ::: "memory");
    vq->avail->idx = avail_idx + 1;
    __asm__ volatile("dmb ish" ::: "memory");

    /* Notify device */
    mmio_write32(dev->base + VIRTIO_MMIO_QUEUE_NOTIFY, 0);
}

/* ============================================================================
 * Config Space Query
 *
 * Query the VirtIO input config space to determine device capabilities.
 * Returns the size of data returned (0 = not supported).
 * ============================================================================ */

static uint8_t input_query_config(uint64_t base, uint8_t select,
                                   uint8_t subsel)
{
    mmio_write8(base + VIRTIO_INPUT_CONFIG_SELECT, select);
    mmio_write8(base + VIRTIO_INPUT_CONFIG_SUBSEL, subsel);
    dsb();
    return mmio_read8(base + VIRTIO_INPUT_CONFIG_SIZE);
}

/*
 * input_device_supports_abs - Check if device supports EV_ABS events.
 *
 * Queries VIRTIO_INPUT_CFG_EV_BITS with subsel=EV_ABS. If size > 0,
 * the device supports absolute axis events (tablet/touchscreen).
 */
static bool input_device_supports_abs(uint64_t base)
{
    return input_query_config(base, VIRTIO_INPUT_CFG_EV_BITS, EV_ABS) > 0;
}

/*
 * input_device_supports_key - Check if device supports EV_KEY events.
 *
 * Queries VIRTIO_INPUT_CFG_EV_BITS with subsel=EV_KEY.
 */
static bool input_device_supports_key(uint64_t base)
{
    return input_query_config(base, VIRTIO_INPUT_CFG_EV_BITS, EV_KEY) > 0;
}

/* ============================================================================
 * Keycode-to-ASCII Conversion
 *
 * Standard US QWERTY keymap. Two tables: normal and shifted.
 * Covers keycodes 0--127. Entries of 0 mean "no printable character".
 * ============================================================================ */

/* Normal (unshifted) keymap */
static const char keymap_normal[128] = {
    /*  0 */ 0, 0x1B, '1', '2', '3', '4', '5', '6',       /* ESC, 1-6 */
    /*  8 */ '7', '8', '9', '0', '-', '=', '\b', '\t',     /* 7-0, -, =, BS, TAB */
    /* 16 */ 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i',      /* Q-I */
    /* 24 */ 'o', 'p', '[', ']', '\n', 0, 'a', 's',        /* O-P, [, ], ENTER, LCTRL, A, S */
    /* 32 */ 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';',      /* D-L, ; */
    /* 40 */ '\'', '`', 0, '\\', 'z', 'x', 'c', 'v',      /* ', `, LSHIFT, \, Z-V */
    /* 48 */ 'b', 'n', 'm', ',', '.', '/', 0, '*',         /* B-M, , . /, RSHIFT, KP* */
    /* 56 */ 0, ' ', 0, 0, 0, 0, 0, 0,                     /* LALT, SPACE, CAPS, F1-F5 */
    /* 64 */ 0, 0, 0, 0, 0, 0, 0, '7',                     /* F6-F10, NUM, SCROLL, KP7 */
    /* 72 */ '8', '9', '-', '4', '5', '6', '+', '1',       /* KP8-9, KP-, KP4-6, KP+, KP1 */
    /* 80 */ '2', '3', '0', '.', 0, 0, 0, 0,               /* KP2-3, KP0, KP., ?, ?, F11, F12 */
    /* 88 */ 0, 0, 0, 0, 0, 0, 0, 0,
    /* 96 */ '\n', 0, '/', 0, 0, 0, 0, 0,                   /* KPENTER, RCTRL, KP/ */
    /* 104 */ 0, 0, 0, 0, 0, 0, 0, 0,
    /* 112 */ 0, 0, 0, 0, 0, 0, 0, 0,
    /* 120 */ 0, 0, 0, 0, 0, 0, 0, 0,
};

/* Shifted keymap */
static const char keymap_shift[128] = {
    /*  0 */ 0, 0x1B, '!', '@', '#', '$', '%', '^',        /* ESC, !-^ */
    /*  8 */ '&', '*', '(', ')', '_', '+', '\b', '\t',     /* &-), _, +, BS, TAB */
    /* 16 */ 'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I',     /* Q-I */
    /* 24 */ 'O', 'P', '{', '}', '\n', 0, 'A', 'S',       /* O-P, {, }, ENTER, CTRL, A, S */
    /* 32 */ 'D', 'F', 'G', 'H', 'J', 'K', 'L', ':',     /* D-L, : */
    /* 40 */ '"', '~', 0, '|', 'Z', 'X', 'C', 'V',       /* ", ~, LSHIFT, |, Z-V */
    /* 48 */ 'B', 'N', 'M', '<', '>', '?', 0, '*',        /* B-M, <, >, ?, RSHIFT, KP* */
    /* 56 */ 0, ' ', 0, 0, 0, 0, 0, 0,                    /* LALT, SPACE, CAPS, F1-F5 */
    /* 64 */ 0, 0, 0, 0, 0, 0, 0, '7',                    /* F6-F10, NUM, SCROLL, KP7 */
    /* 72 */ '8', '9', '-', '4', '5', '6', '+', '1',      /* KP8-9, KP-, KP4-6, KP+, KP1 */
    /* 80 */ '2', '3', '0', '.', 0, 0, 0, 0,              /* KP2-3, KP0, KP., ?, ?, F11, F12 */
    /* 88 */ 0, 0, 0, 0, 0, 0, 0, 0,
    /* 96 */ '\n', 0, '/', 0, 0, 0, 0, 0,                  /* KPENTER, RCTRL, KP/ */
    /* 104 */ 0, 0, 0, 0, 0, 0, 0, 0,
    /* 112 */ 0, 0, 0, 0, 0, 0, 0, 0,
    /* 120 */ 0, 0, 0, 0, 0, 0, 0, 0,
};

/*
 * keycode_to_char - Convert a Linux keycode to an ASCII character.
 *
 * Takes modifier state (shift, ctrl, capslock) into account.
 * Returns 0 for non-printable keys (modifiers, function keys, etc.)
 */
static char keycode_to_char(uint16_t code)
{
    if (code >= 128)
        return 0;

    char c;
    bool shifted = shift_held;

    /*
     * Caps lock only affects letters (a-z / A-Z).
     * If caps lock is on, toggle the shift state for letter keys.
     */
    if (capslock_on && keymap_normal[code] >= 'a' && keymap_normal[code] <= 'z')
        shifted = !shifted;

    if (shifted)
        c = keymap_shift[code];
    else
        c = keymap_normal[code];

    /*
     * Ctrl key: for alphabetic characters, produce the control character.
     * Ctrl+A = 0x01, Ctrl+B = 0x02, ..., Ctrl+Z = 0x1A.
     * Ctrl+C = 0x03 (SIGINT), Ctrl+D = 0x04 (EOF), etc.
     * Also handle Ctrl+[ = ESC (0x1B), Ctrl+\ = 0x1C, Ctrl+] = 0x1D.
     */
    if (ctrl_held && c != 0) {
        if (c >= 'a' && c <= 'z')
            return c - 'a' + 1;
        if (c >= 'A' && c <= 'Z')
            return c - 'A' + 1;
        if (c == '[' || c == '{')
            return 0x1B;    /* ESC */
        if (c == '\\' || c == '|')
            return 0x1C;    /* FS */
        if (c == ']' || c == '}')
            return 0x1D;    /* GS */
        if (c == '?' || c == '/')
            return 0x7F;    /* DEL */
    }

    return c;
}

/* ============================================================================
 * Keyboard Event Processing
 * ============================================================================ */

/*
 * kbd_process_event - Process a single VirtIO keyboard event.
 *
 * Handles EV_KEY events: updates modifier state for shift/ctrl/capslock,
 * converts keycodes to ASCII for key-press and key-repeat events,
 * injects the resulting character into the fbconsole TTY, and pushes
 * HID events into the shared ring buffer.
 */
static void kbd_process_event(const struct virtio_input_event *ev)
{
    if (ev->type != EV_KEY)
        return;     /* We only care about key events for keyboard */

    uint16_t code = ev->code;
    uint32_t value = ev->value;

    /*
     * Push HID event for key down/up (before modifier handling,
     * so userland gets raw keycode events for all keys including modifiers).
     */
    {
        struct hid_event hev;
        hev.type = (value == KEY_RELEASED) ? HID_EVENT_KEY_UP : HID_EVENT_KEY_DOWN;
        hev.keycode = code;
        hev.abs_x = 0;
        hev.abs_y = 0;
        hev.buttons = 0;
        hev.flags = hid_get_modifier_flags();
        hev.timestamp = 0;     /* TODO: kernel timestamp */
        hid_ring_push(&hev);
    }

    /*
     * Update modifier key state.
     * Modifier keys don't produce characters themselves.
     */
    switch (code) {
    case KEY_LEFTSHIFT:
    case KEY_RIGHTSHIFT:
        shift_held = (value != KEY_RELEASED);
        return;
    case KEY_LEFTCTRL:
    case KEY_RIGHTCTRL:
        ctrl_held = (value != KEY_RELEASED);
        return;
    case KEY_LEFTALT:
    case KEY_RIGHTALT:
        alt_held = (value != KEY_RELEASED);
        return;
    case KEY_CAPSLOCK:
        /* Toggle on key press only (not release or repeat) */
        if (value == KEY_PRESSED)
            capslock_on = !capslock_on;
        return;
    default:
        break;
    }

    /*
     * Only process key-press and key-repeat events for TTY injection.
     * Key-release events don't generate characters.
     */
    if (value == KEY_RELEASED)
        return;

    /*
     * Handle special keys that produce VT100/ANSI escape sequences
     * rather than single characters.
     */
    struct tty *tp = fbconsole_get_tty();
    if (!tp)
        return;

    switch (code) {
    case KEY_UP:
        tty_input_char_tp(tp, 0x1B);
        tty_input_char_tp(tp, '[');
        tty_input_char_tp(tp, 'A');
        return;
    case KEY_DOWN:
        tty_input_char_tp(tp, 0x1B);
        tty_input_char_tp(tp, '[');
        tty_input_char_tp(tp, 'B');
        return;
    case KEY_RIGHT:
        tty_input_char_tp(tp, 0x1B);
        tty_input_char_tp(tp, '[');
        tty_input_char_tp(tp, 'C');
        return;
    case KEY_LEFT:
        tty_input_char_tp(tp, 0x1B);
        tty_input_char_tp(tp, '[');
        tty_input_char_tp(tp, 'D');
        return;
    case KEY_HOME:
        tty_input_char_tp(tp, 0x1B);
        tty_input_char_tp(tp, '[');
        tty_input_char_tp(tp, 'H');
        return;
    case KEY_END:
        tty_input_char_tp(tp, 0x1B);
        tty_input_char_tp(tp, '[');
        tty_input_char_tp(tp, 'F');
        return;
    case KEY_DELETE:
        tty_input_char_tp(tp, 0x1B);
        tty_input_char_tp(tp, '[');
        tty_input_char_tp(tp, '3');
        tty_input_char_tp(tp, '~');
        return;
    case KEY_PAGEUP:
        tty_input_char_tp(tp, 0x1B);
        tty_input_char_tp(tp, '[');
        tty_input_char_tp(tp, '5');
        tty_input_char_tp(tp, '~');
        return;
    case KEY_PAGEDOWN:
        tty_input_char_tp(tp, 0x1B);
        tty_input_char_tp(tp, '[');
        tty_input_char_tp(tp, '6');
        tty_input_char_tp(tp, '~');
        return;
    case KEY_INSERT:
        tty_input_char_tp(tp, 0x1B);
        tty_input_char_tp(tp, '[');
        tty_input_char_tp(tp, '2');
        tty_input_char_tp(tp, '~');
        return;
    default:
        break;
    }

    /*
     * Convert keycode to ASCII and inject into the fbconsole TTY.
     */
    char c = keycode_to_char(code);
    if (c != 0)
        tty_input_char_tp(tp, c);
}

/* ============================================================================
 * Tablet Event Processing
 * ============================================================================ */

/*
 * tablet_process_event - Process a single VirtIO tablet event.
 *
 * Handles:
 *   EV_ABS with ABS_X/ABS_Y: update accumulated cursor position
 *   EV_KEY with BTN_LEFT/RIGHT/MIDDLE: update button state, push HID event
 *   EV_SYN (type=0, code=0): batch complete, push mouse move HID event
 */
static void tablet_process_event(const struct virtio_input_event *ev)
{
    switch (ev->type) {
    case EV_ABS:
        if (ev->code == ABS_X) {
            tablet_abs_x = ev->value;
            tablet_abs_x_dirty = true;
        } else if (ev->code == ABS_Y) {
            tablet_abs_y = ev->value;
            tablet_abs_y_dirty = true;
        }
        break;

    case EV_KEY: {
        /* Mouse button press/release */
        uint32_t btn_bit = 0;
        uint16_t btn_code = ev->code;

        if (btn_code == BTN_LEFT)
            btn_bit = (1 << 0);
        else if (btn_code == BTN_RIGHT)
            btn_bit = (1 << 1);
        else if (btn_code == BTN_MIDDLE)
            btn_bit = (1 << 2);
        else
            break;  /* Unknown button */

        if (ev->value != KEY_RELEASED)
            tablet_buttons |= btn_bit;
        else
            tablet_buttons &= ~btn_bit;

        /* Push HID mouse button event */
        struct hid_event hev;
        hev.type = (ev->value != KEY_RELEASED) ?
                   HID_EVENT_MOUSE_DOWN : HID_EVENT_MOUSE_UP;
        hev.keycode = btn_code;
        hev.abs_x = tablet_abs_x;
        hev.abs_y = tablet_abs_y;
        hev.buttons = tablet_buttons;
        hev.flags = hid_get_modifier_flags();
        hev.timestamp = 0;     /* TODO: kernel timestamp */
        hid_ring_push(&hev);
        break;
    }

    case EV_SYN:
        if (ev->code == 0 && (tablet_abs_x_dirty || tablet_abs_y_dirty)) {
            /* SYN_REPORT: push accumulated mouse move */
            struct hid_event hev;
            hev.type = HID_EVENT_MOUSE_MOVE;
            hev.keycode = 0;
            hev.abs_x = tablet_abs_x;
            hev.abs_y = tablet_abs_y;
            hev.buttons = tablet_buttons;
            hev.flags = hid_get_modifier_flags();
            hev.timestamp = 0;     /* TODO: kernel timestamp */
            hid_ring_push(&hev);

            tablet_abs_x_dirty = false;
            tablet_abs_y_dirty = false;
        }
        break;

    default:
        break;
    }
}

/* ============================================================================
 * Generic IRQ Handler (processes used ring for a given device)
 * ============================================================================ */

static void input_handle_irq(struct virtio_device *dev,
                              struct virtio_input_event *event_bufs,
                              void (*process_fn)(const struct virtio_input_event *))
{
    /* ACK the interrupt */
    uint32_t isr = mmio_read32(dev->base + VIRTIO_MMIO_INTERRUPT_STATUS);
    if (isr)
        mmio_write32(dev->base + VIRTIO_MMIO_INTERRUPT_ACK, isr);

    struct virtqueue *vq = &dev->vq[0];

    __asm__ volatile("dmb ish" ::: "memory");

    while (vq->last_used_idx != vq->used->idx) {
        uint32_t used_slot = vq->last_used_idx % vq->num;
        uint32_t desc_idx = vq->used->ring[used_slot].id;

        /* Recover buffer index from descriptor's address */
        uint64_t buf_addr = vq->desc[desc_idx].addr;
        uint32_t buf_idx = (uint32_t)(
            (buf_addr - (uint64_t)&event_bufs[0]) /
            sizeof(struct virtio_input_event));

        if (buf_idx < NUM_EVENT_BUFS) {
            __asm__ volatile("dmb ish" ::: "memory");
            process_fn(&event_bufs[buf_idx]);
        }

        /* Free the descriptor and re-post the buffer */
        input_free_desc(vq, desc_idx);
        vq->last_used_idx++;

        if (buf_idx < NUM_EVENT_BUFS)
            input_post_event_buf(dev, vq, event_bufs, buf_idx);
    }
}

/* ============================================================================
 * Public IRQ Handlers
 * ============================================================================ */

void virtio_input_irq_handler(void)
{
    if (!kbd_found)
        return;
    input_handle_irq(&kbd_dev, kbd_event_bufs, kbd_process_event);
}

void virtio_input_tablet_irq_handler(void)
{
    if (!tablet_found)
        return;
    input_handle_irq(&tablet_dev, tablet_event_bufs, tablet_process_event);
}

/* ============================================================================
 * Device Initialisation Helper
 *
 * Shared init logic for both keyboard and tablet.
 * ============================================================================ */

static int input_init_one(struct virtio_device *dev, uint64_t base,
                           uint32_t irq, uint8_t *dma_pages,
                           uint64_t dma_size,
                           struct virtio_input_event *event_bufs,
                           const char *label)
{
    /*
     * Feature negotiation.
     * VirtIO input has no device-specific features.
     * Request VIRTIO_F_VERSION_1 if supported.
     */
    uint64_t features = virtio_negotiate_features(dev, VIRTIO_F_VERSION_1);
    kprintf("[%s] Negotiated features: 0x%lx\n", label, features);

    /* Set up eventq (queue 0) */
    if (input_setup_eventq(dev, dma_pages, dma_size, label) < 0) {
        kprintf("[%s] Failed to set up eventq\n", label);
        mmio_write32(base + VIRTIO_MMIO_STATUS, VIRTIO_STATUS_FAILED);
        return -1;
    }

    /* Set DRIVER_OK — device is now live */
    dev->status |= VIRTIO_STATUS_DRIVER_OK;
    mmio_write32(base + VIRTIO_MMIO_STATUS, dev->status);
    dsb();

    /* Enable GIC interrupt */
    gic_enable_irq(irq);

    /*
     * Pre-post event buffers to the eventq.
     */
    struct virtqueue *vq = &dev->vq[0];
    uint32_t to_post = NUM_EVENT_BUFS;
    if (to_post > vq->num)
        to_post = vq->num;

    for (uint32_t b = 0; b < to_post; b++)
        input_post_event_buf(dev, vq, event_bufs, b);

    kprintf("[%s] Posted %u event buffers\n", label, to_post);

    return 0;
}

/* ============================================================================
 * Initialisation
 * ============================================================================ */

int virtio_input_init(void)
{
    kprintf("[virtio-input] Scanning for VirtIO input devices...\n");

    /* Initialise the HID event ring */
    g_hid_ring.write_idx = 0;
    g_hid_ring.read_idx = 0;
    g_hid_ring.size = HID_EVENT_RING_SIZE;
    g_hid_ring._pad = 0;

    /* Temporary device struct for probing */
    struct virtio_device probe_dev;
    int found_count = 0;

    /* Scan all 32 MMIO transport slots */
    for (uint32_t i = 0; i < VIRTIO_MMIO_COUNT; i++) {
        uint64_t base = VIRTIO_MMIO_BASE + i * VIRTIO_MMIO_STRIDE;
        uint32_t irq  = VIRTIO_MMIO_IRQ_BASE + i;

        int ret = virtio_init_device(&probe_dev, base, irq);
        if (ret < 0)
            continue;

        if (probe_dev.device_id != VIRTIO_DEV_INPUT) {
            /* Not an input device -- reset and move on */
            mmio_write32(base + VIRTIO_MMIO_STATUS, 0);
            dsb();
            continue;
        }

        /*
         * Found a VirtIO input device. Query config space to determine
         * whether it's a keyboard or tablet.
         *
         * Strategy:
         *   - If supports EV_ABS: it's a tablet (absolute pointing device)
         *   - If supports EV_KEY but not EV_ABS: it's a keyboard
         */
        bool supports_abs = input_device_supports_abs(base);
        bool supports_key = input_device_supports_key(base);

        if (supports_abs && !tablet_found) {
            /* This is the tablet */
            tablet_dev = probe_dev;
            tablet_irq_num = irq;

            kprintf("[virtio-tablet] Found tablet at MMIO slot %u "
                    "(base=0x%lx, IRQ=%u, version=%u)\n",
                    i, base, irq, probe_dev.version);

            ret = input_init_one(&tablet_dev, base, irq,
                                  tablet_eventq_pages,
                                  sizeof(tablet_eventq_pages),
                                  tablet_event_bufs,
                                  "virtio-tablet");
            if (ret == 0) {
                tablet_found = true;
                found_count++;
                kprintf("[virtio-tablet] Tablet ready (absolute coordinates)\n");
            }
        } else if (supports_key && !kbd_found) {
            /* This is the keyboard */
            kbd_dev = probe_dev;
            kbd_irq_num = irq;

            kprintf("[virtio-input] Found keyboard at MMIO slot %u "
                    "(base=0x%lx, IRQ=%u, version=%u)\n",
                    i, base, irq, probe_dev.version);

            ret = input_init_one(&kbd_dev, base, irq,
                                  kbd_eventq_pages,
                                  sizeof(kbd_eventq_pages),
                                  kbd_event_bufs,
                                  "virtio-input");
            if (ret == 0) {
                kbd_found = true;
                found_count++;
                kprintf("[virtio-input] Keyboard ready (US QWERTY layout)\n");
            }
        } else {
            /* Already have this device type, or unrecognised — skip */
            kprintf("[virtio-input] Skipping input device at slot %u "
                    "(abs=%u, key=%u, kbd_found=%u, tablet_found=%u)\n",
                    i, supports_abs, supports_key, kbd_found, tablet_found);
            mmio_write32(base + VIRTIO_MMIO_STATUS, 0);
            dsb();
        }

        /* Stop scanning once we have both devices */
        if (kbd_found && tablet_found)
            break;
    }

    if (found_count == 0) {
        kprintf("[virtio-input] No VirtIO input devices found\n");
        return -1;
    }

    kprintf("[virtio-input] Initialised %d input device(s) "
            "(kbd=%u, tablet=%u)\n", found_count, kbd_found, tablet_found);
    return 0;
}

uint32_t virtio_input_get_irq(void)
{
    return kbd_irq_num;
}

uint32_t virtio_input_tablet_get_irq(void)
{
    return tablet_irq_num;
}
