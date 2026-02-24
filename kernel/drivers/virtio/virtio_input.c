/*
 * Kiseki OS - VirtIO Input Keyboard Driver
 *
 * Receives keyboard events from QEMU's virtio-keyboard-device and
 * injects characters into the framebuffer console TTY. This allows
 * the OS to be operated from a QEMU graphical display window like
 * a physical machine with a monitor and keyboard.
 *
 * Architecture:
 *   1. Scan MMIO slots for VirtIO input device (type 18)
 *   2. Set up eventq (queue 0) with pre-posted receive buffers
 *   3. On IRQ, process completed event buffers from the used ring
 *   4. Convert Linux keycodes to ASCII (with shift/ctrl/capslock)
 *   5. Inject resulting characters into fbcon_tty via tty_input_char_tp()
 *   6. Re-post consumed buffers to keep the eventq fed
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

static inline void dsb(void)
{
    __asm__ volatile("dsb sy" ::: "memory");
}

/* ============================================================================
 * Driver State
 * ============================================================================ */

static struct virtio_device inputdev;
static bool inputdev_found = false;

/* The input device's GIC IRQ number */
static uint32_t input_irq_num = 0;

/* ============================================================================
 * Keyboard Modifier State
 * ============================================================================ */

static bool shift_held = false;     /* Either shift key pressed */
static bool ctrl_held = false;      /* Either ctrl key pressed */
static bool capslock_on = false;    /* Caps lock toggled on */

/* ============================================================================
 * DMA Pages for Eventq (Queue 0)
 *
 * Same pattern as the GPU controlq. We need physically contiguous
 * memory for the descriptor table, available ring, and used ring.
 * ============================================================================ */

static uint8_t eventq_pages[3 * PAGE_SIZE] __aligned(PAGE_SIZE);

/* ============================================================================
 * Event Buffers
 *
 * The VirtIO input device writes events into device-writable buffers
 * that the driver posts to the eventq. We pre-post a pool of buffers
 * at init time. When the device delivers an event, we process it and
 * re-post the buffer.
 *
 * Each buffer holds one struct virtio_input_event (8 bytes).
 * We allocate a static array of event buffers.
 * ============================================================================ */

#define NUM_EVENT_BUFS  64

static struct virtio_input_event event_bufs[NUM_EVENT_BUFS] __aligned(16);

/* ============================================================================
 * Eventq Setup
 * ============================================================================ */

static int input_setup_eventq(struct virtio_device *dev)
{
    uint64_t base = dev->base;

    /* Select queue 0 (eventq) */
    mmio_write32(base + VIRTIO_MMIO_QUEUE_SEL, 0);
    dsb();

    uint32_t max_size = mmio_read32(base + VIRTIO_MMIO_QUEUE_NUM_MAX);
    if (max_size == 0) {
        kprintf("[virtio-input] eventq not available\n");
        return -1;
    }

    uint32_t num = max_size;
    if (num > VIRTQ_MAX_SIZE)
        num = VIRTQ_MAX_SIZE;

    struct virtqueue *vq = &dev->vq[0];
    vq->num = num;

    /* Zero the DMA region */
    uint8_t *mem = eventq_pages;
    for (uint64_t i = 0; i < sizeof(eventq_pages); i++)
        mem[i] = 0;

    /* Layout: desc | avail | (padding) | used */
    vq->desc  = (struct virtq_desc *)mem;
    vq->avail = (struct virtq_avail *)(mem + num * sizeof(struct virtq_desc));
    vq->used  = (struct virtq_used *)
                    (mem + ALIGN_UP(num * sizeof(struct virtq_desc)
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
                     (uint32_t)((uint64_t)mem / PAGE_SIZE));
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
    kprintf("[virtio-input] eventq: %u descriptors\n", num);
    return 0;
}

/* ============================================================================
 * Virtqueue Helpers
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
 * We use the buffer index as the descriptor index for simplicity.
 */
static void input_post_event_buf(struct virtqueue *vq, uint32_t buf_idx)
{
    int desc = input_alloc_desc(vq);
    if (desc < 0)
        return;     /* Out of descriptors — shouldn't happen */

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
    mmio_write32(inputdev.base + VIRTIO_MMIO_QUEUE_NOTIFY, 0);
}

/* ============================================================================
 * Keycode-to-ASCII Conversion
 *
 * Standard US QWERTY keymap. Two tables: normal and shifted.
 * Covers keycodes 0--127. Entries of 0 mean "no printable character".
 *
 * This matches the standard PC keyboard layout that QEMU emulates.
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
 * Event Processing
 * ============================================================================ */

/*
 * input_process_event - Process a single VirtIO input event.
 *
 * Handles EV_KEY events: updates modifier state for shift/ctrl/capslock,
 * converts keycodes to ASCII for key-press and key-repeat events,
 * and injects the resulting character into the fbconsole TTY.
 */
static void input_process_event(const struct virtio_input_event *ev)
{
    if (ev->type != EV_KEY)
        return;     /* We only care about key events */

    uint16_t code = ev->code;
    uint32_t value = ev->value;

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
        /* Alt is tracked but not used for ASCII conversion yet */
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
     * Only process key-press and key-repeat events.
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
 * IRQ Handler
 * ============================================================================ */

void virtio_input_irq_handler(void)
{
    if (!inputdev_found)
        return;

    /* ACK the interrupt */
    uint32_t isr = mmio_read32(inputdev.base + VIRTIO_MMIO_INTERRUPT_STATUS);
    if (isr)
        mmio_write32(inputdev.base + VIRTIO_MMIO_INTERRUPT_ACK, isr);

    struct virtqueue *vq = &inputdev.vq[0];

    /*
     * Process all completed event buffers from the used ring.
     *
     * The device places completed descriptors in the used ring.
     * We compare our last_used_idx against the device's used->idx
     * to find new entries.
     */
    __asm__ volatile("dmb ish" ::: "memory");

    while (vq->last_used_idx != vq->used->idx) {
        uint32_t used_slot = vq->last_used_idx % vq->num;
        uint32_t desc_idx = vq->used->ring[used_slot].id;

        /* The descriptor points to one of our event_bufs entries.
         * Recover the buffer index from the descriptor's address. */
        uint64_t buf_addr = vq->desc[desc_idx].addr;
        uint32_t buf_idx = (uint32_t)(
            (buf_addr - (uint64_t)&event_bufs[0]) /
            sizeof(struct virtio_input_event));

        if (buf_idx < NUM_EVENT_BUFS) {
            __asm__ volatile("dmb ish" ::: "memory");
            input_process_event(&event_bufs[buf_idx]);
        }

        /* Free the descriptor and re-post the buffer */
        input_free_desc(vq, desc_idx);
        vq->last_used_idx++;

        if (buf_idx < NUM_EVENT_BUFS)
            input_post_event_buf(vq, buf_idx);
    }
}

/* ============================================================================
 * Initialisation
 * ============================================================================ */

int virtio_input_init(void)
{
    kprintf("[virtio-input] Scanning for VirtIO input device...\n");

    /* Scan all 32 MMIO transport slots */
    for (uint32_t i = 0; i < VIRTIO_MMIO_COUNT; i++) {
        uint64_t base = VIRTIO_MMIO_BASE + i * VIRTIO_MMIO_STRIDE;
        uint32_t irq  = VIRTIO_MMIO_IRQ_BASE + i;

        int ret = virtio_init_device(&inputdev, base, irq);
        if (ret < 0)
            continue;

        if (inputdev.device_id != VIRTIO_DEV_INPUT) {
            /* Not an input device -- reset and move on */
            mmio_write32(base + VIRTIO_MMIO_STATUS, 0);
            dsb();
            continue;
        }

        kprintf("[virtio-input] Found input device at MMIO slot %u "
                "(base=0x%lx, IRQ=%u, version=%u)\n",
                i, base, irq, inputdev.version);
        input_irq_num = irq;

        /*
         * Feature negotiation.
         * VirtIO input has no device-specific features.
         * Request VIRTIO_F_VERSION_1 if supported.
         */
        uint64_t features = virtio_negotiate_features(&inputdev,
                                                       VIRTIO_F_VERSION_1);
        kprintf("[virtio-input] Negotiated features: 0x%lx\n", features);

        /* Set up eventq (queue 0) */
        if (input_setup_eventq(&inputdev) < 0) {
            kprintf("[virtio-input] Failed to set up eventq\n");
            mmio_write32(base + VIRTIO_MMIO_STATUS, VIRTIO_STATUS_FAILED);
            return -1;
        }

        /* Set DRIVER_OK — device is now live */
        inputdev.status |= VIRTIO_STATUS_DRIVER_OK;
        mmio_write32(base + VIRTIO_MMIO_STATUS, inputdev.status);
        dsb();

        inputdev_found = true;

        /* Enable GIC interrupt */
        gic_enable_irq(irq);

        /*
         * Pre-post event buffers to the eventq.
         *
         * The device needs buffers available in the eventq before
         * it can deliver events. We post NUM_EVENT_BUFS buffers
         * (or as many as fit in the queue).
         */
        struct virtqueue *vq = &inputdev.vq[0];
        uint32_t to_post = NUM_EVENT_BUFS;
        if (to_post > vq->num)
            to_post = vq->num;

        for (uint32_t b = 0; b < to_post; b++)
            input_post_event_buf(vq, b);

        kprintf("[virtio-input] Posted %u event buffers\n", to_post);
        kprintf("[virtio-input] Keyboard ready (US QWERTY layout)\n");

        return 0;
    }

    kprintf("[virtio-input] No VirtIO input device found\n");
    return -1;
}

uint32_t virtio_input_get_irq(void)
{
    return input_irq_num;
}
