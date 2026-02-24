/*
 * Kiseki OS - HID Event Ring Buffer
 *
 * Shared memory ring buffer for delivering human interface device events
 * (keyboard, mouse/tablet) from the kernel to userland. The kernel writes
 * events from VirtIO input IRQ handlers; WindowServer reads them via
 * IOHIDSystem's IOConnectMapMemory.
 *
 * The ring is a single-producer (kernel IRQ handler) / single-consumer
 * (WindowServer main loop) lock-free queue. The kernel advances write_idx;
 * userland advances read_idx. Both indices wrap modulo HID_EVENT_RING_SIZE.
 *
 * Reference: macOS IOHIDSystem shared memory event ring
 */

#ifndef _KERN_HID_EVENT_H
#define _KERN_HID_EVENT_H

#include <kiseki/types.h>

/* ============================================================================
 * HID Event Ring Configuration
 * ============================================================================ */

#define HID_EVENT_RING_SIZE     256     /* Must be power of 2 */

/* ============================================================================
 * HID Event Types
 * ============================================================================ */

#define HID_EVENT_KEY_DOWN      1       /* Keyboard key pressed */
#define HID_EVENT_KEY_UP        2       /* Keyboard key released */
#define HID_EVENT_MOUSE_MOVE    3       /* Mouse/tablet cursor moved */
#define HID_EVENT_MOUSE_DOWN    4       /* Mouse button pressed */
#define HID_EVENT_MOUSE_UP      5       /* Mouse button released */

/* ============================================================================
 * HID Event Structure
 *
 * Unified event structure for all HID event types. Fields are interpreted
 * based on the event type:
 *
 *   KEY_DOWN / KEY_UP:
 *     keycode  = Linux keycode (KEY_A, KEY_ENTER, etc.)
 *     flags    = modifier bitmask (shift, ctrl, alt, etc.)
 *
 *   MOUSE_MOVE:
 *     abs_x    = absolute X position (0-32767)
 *     abs_y    = absolute Y position (0-32767)
 *     buttons  = current button state bitmask
 *
 *   MOUSE_DOWN / MOUSE_UP:
 *     keycode  = button code (BTN_LEFT, BTN_RIGHT, BTN_MIDDLE)
 *     abs_x    = absolute X position at time of click
 *     abs_y    = absolute Y position at time of click
 *     buttons  = current button state bitmask
 * ============================================================================ */

struct hid_event {
    uint32_t type;          /* HID_EVENT_* type */
    uint32_t keycode;       /* For key events: Linux keycode */
    uint32_t abs_x;         /* For mouse: absolute X (0-32767) */
    uint32_t abs_y;         /* For mouse: absolute Y (0-32767) */
    uint32_t buttons;       /* Mouse button state bitmask */
    uint32_t flags;         /* Modifier flags (shift, ctrl, alt, etc.) */
    uint64_t timestamp;     /* Kernel timestamp (nanoseconds) */
};

/* ============================================================================
 * HID Event Ring Buffer
 *
 * Layout: header (write_idx, read_idx, size, pad) followed by the event
 * array. The entire structure is mapped into userland via IOConnectMapMemory.
 *
 * write_idx and read_idx are monotonically increasing indices. The actual
 * array slot is (idx % size). The ring is empty when write_idx == read_idx
 * and full when (write_idx - read_idx) == size.
 * ============================================================================ */

struct hid_event_ring {
    volatile uint32_t write_idx;    /* Written by kernel */
    volatile uint32_t read_idx;     /* Written by userland */
    uint32_t size;                  /* HID_EVENT_RING_SIZE */
    uint32_t _pad;
    struct hid_event events[HID_EVENT_RING_SIZE];
};

/* ============================================================================
 * Modifier Flag Bits (for hid_event.flags)
 * ============================================================================ */

#define HID_FLAG_SHIFT          (1 << 0)
#define HID_FLAG_CTRL           (1 << 1)
#define HID_FLAG_ALT            (1 << 2)
#define HID_FLAG_CAPSLOCK       (1 << 3)

/* ============================================================================
 * Kernel API
 * ============================================================================ */

/*
 * hid_event_ring_get - Get the global HID event ring.
 *
 * Returns a pointer to the kernel's HID event ring buffer.
 * This is the same buffer that is mapped into userland via IOHIDSystem.
 */
struct hid_event_ring *hid_event_ring_get(void);

/*
 * hid_event_ring_get_phys - Get the physical address of the HID event ring.
 *
 * Used by IOHIDSystem to create an IOMemoryDescriptor for mapping.
 */
uint64_t hid_event_ring_get_phys(void);

/*
 * hid_event_ring_get_size - Get the total byte size of the HID event ring.
 */
uint64_t hid_event_ring_get_size(void);

#endif /* _KERN_HID_EVENT_H */
