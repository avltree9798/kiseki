/*
 * Kiseki OS - VirtIO Input Device Driver
 *
 * Implements the VirtIO input specification for keyboard input.
 * The driver receives Linux input events from QEMU's virtio-keyboard-device,
 * converts scancodes to ASCII characters, and injects them into the
 * framebuffer console TTY via tty_input_char_tp().
 *
 * VirtIO input uses two virtqueues:
 *   - Queue 0 (eventq): device -> driver, delivers input events
 *   - Queue 1 (statusq): driver -> device, for LED updates (unused)
 *
 * Events match the Linux struct input_event layout (but only 8 bytes):
 *   { uint16_t type, uint16_t code, uint32_t value }
 *
 * Reference: VirtIO Specification v1.2, Section 5.8 -- Input Device
 *            Linux include/uapi/linux/input-event-codes.h
 */

#ifndef _DRIVERS_VIRTIO_INPUT_H
#define _DRIVERS_VIRTIO_INPUT_H

#include <kiseki/types.h>

/* ============================================================================
 * VirtIO Input Event Types (matching Linux input subsystem)
 * ============================================================================ */

#define EV_SYN      0x00    /* Synchronisation event */
#define EV_KEY      0x01    /* Key press/release */
#define EV_REL      0x02    /* Relative axis (mouse) */
#define EV_ABS      0x03    /* Absolute axis (touchscreen) */
#define EV_MSC      0x04    /* Miscellaneous */
#define EV_LED      0x11    /* LED */
#define EV_REP      0x14    /* Autorepeat */

/* Key event values */
#define KEY_RELEASED    0
#define KEY_PRESSED     1
#define KEY_REPEAT      2

/* ============================================================================
 * Linux Keycodes (subset needed for a standard keyboard)
 *
 * These match include/uapi/linux/input-event-codes.h exactly.
 * QEMU's virtio-keyboard sends these codes for EV_KEY events.
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
 * VirtIO Input Event Structure
 *
 * This is the structure placed in the eventq buffers. The device fills
 * it in when an input event occurs. Matches the VirtIO spec exactly.
 * ============================================================================ */

struct virtio_input_event {
    uint16_t type;      /* Event type (EV_KEY, EV_REL, ...) */
    uint16_t code;      /* Event code (KEY_A, REL_X, ...) */
    uint32_t value;     /* Event value (1=pressed, 0=released, ...) */
} __packed;

/* ============================================================================
 * VirtIO Input Configuration Select Values
 *
 * Used to query device configuration via the config space.
 * ============================================================================ */

#define VIRTIO_INPUT_CFG_UNSET      0x00
#define VIRTIO_INPUT_CFG_ID_NAME    0x01    /* Device name string */
#define VIRTIO_INPUT_CFG_ID_SERIAL  0x02    /* Serial number string */
#define VIRTIO_INPUT_CFG_ID_DEVIDS  0x03    /* Device IDs (bus, vendor, product) */
#define VIRTIO_INPUT_CFG_PROP_BITS  0x10    /* Input properties bitmap */
#define VIRTIO_INPUT_CFG_EV_BITS    0x11    /* Supported event types bitmap */
#define VIRTIO_INPUT_CFG_ABS_INFO   0x12    /* Absolute axis info */

/* ============================================================================
 * Public API
 * ============================================================================ */

/*
 * virtio_input_init - Scan for and initialise a VirtIO input keyboard.
 *
 * Scans all 32 MMIO slots for a VirtIO input device (type 18).
 * Sets up the eventq with pre-posted receive buffers and enables
 * the GIC interrupt for event delivery.
 *
 * Must be called after fbconsole_init() so keyboard input has a
 * TTY to feed into.
 *
 * Returns 0 on success, -1 if no keyboard found.
 */
int virtio_input_init(void);

/*
 * virtio_input_irq_handler - Handle a VirtIO input interrupt.
 *
 * Called from irq_dispatch() when the input device's IRQ fires.
 * Processes all completed event buffers, converts keycodes to
 * ASCII, and injects characters into the fbconsole TTY.
 */
void virtio_input_irq_handler(void);

/*
 * virtio_input_get_irq - Return the GIC IRQ number for the input device.
 *
 * Returns 0 if no input device has been initialised.
 */
uint32_t virtio_input_get_irq(void);

#endif /* _DRIVERS_VIRTIO_INPUT_H */
