/*
 * Kiseki OS - IOKit IOHIDSystem Driver
 *
 * IOHIDSystem exposes the kernel's HID event ring buffer to userland.
 * WindowServer (or any HID consumer) finds this service via
 * IOServiceGetMatchingService("IOHIDSystem"), opens a connection via
 * IOServiceOpen(), and maps the event ring via IOConnectMapMemory(0).
 *
 * The mapped memory is a struct hid_event_ring containing keyboard
 * and mouse/tablet events written by VirtIO input IRQ handlers.
 *
 * Inheritance:
 *   io_object -> io_registry_entry -> io_service -> io_hid_system
 *
 * User client:
 *   io_object -> io_registry_entry -> io_service -> io_user_client
 *             -> io_hid_system_user_client
 *
 * Memory types (via IOConnectMapMemory):
 *   0 - HID event ring: maps the hid_event_ring structure
 *
 * Reference: macOS IOHIDSystem (IOKit/hidsystem)
 */

#ifndef _IOKIT_IO_HID_SYSTEM_H
#define _IOKIT_IO_HID_SYSTEM_H

#include <iokit/io_service.h>
#include <iokit/io_user_client.h>
#include <iokit/io_memory_descriptor.h>

/* ============================================================================
 * IOHIDSystem Memory Types
 * ============================================================================ */

#define kIOHIDMemoryTypeEventRing   0   /* HID event ring buffer */

/* ============================================================================
 * io_hid_system - IOHIDSystem service
 *
 * Wraps the kernel's HID event ring buffer.
 * One singleton instance created during boot.
 * ============================================================================ */

struct io_hid_system {
    /* Base service (MUST be first for upcast) */
    struct io_service           service;

    /* Memory descriptor for the event ring physical pages */
    struct io_memory_descriptor *ring_mem_desc;

    /* Active flag */
    bool                        active;
};

/* ============================================================================
 * io_hid_system_user_client - User client for IOHIDSystem
 * ============================================================================ */

struct io_hid_system_user_client {
    /* Base user client (MUST be first for upcast) */
    struct io_user_client       uc;

    /* Back-pointer to the owning HID system service */
    struct io_hid_system        *hid_system;
};

/* ============================================================================
 * IOHIDSystem API
 * ============================================================================ */

/*
 * io_hid_system_init_driver - Initialise and register the IOHIDSystem.
 *
 * Called from main.c after virtio_input_init().
 * Creates the io_hid_system service, sets up the event ring memory
 * descriptor, and registers the service in the I/O Registry.
 */
void io_hid_system_init_driver(void);

/* ============================================================================
 * Class Metadata
 * ============================================================================ */

extern const struct io_class_meta io_hid_system_meta;
extern const struct io_class_meta io_hid_system_uc_meta;

#endif /* _IOKIT_IO_HID_SYSTEM_H */
