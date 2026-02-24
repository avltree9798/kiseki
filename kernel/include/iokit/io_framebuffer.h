/*
 * Kiseki OS - IOKit IOFramebuffer Driver
 *
 * IOFramebuffer wraps the VirtIO GPU hardware behind an IOKit service
 * interface. WindowServer (and any other userland client) opens this
 * service via IOServiceOpen to obtain an IOUserClient connection,
 * then maps the framebuffer memory via IOConnectMapMemory and issues
 * flush commands via IOConnectCallMethod.
 *
 * Inheritance:
 *   io_object -> io_registry_entry -> io_service -> io_framebuffer
 *
 * User client:
 *   io_object -> io_registry_entry -> io_service -> io_user_client
 *              -> io_framebuffer_user_client
 *
 * External methods (via IOConnectCallMethod):
 *   0 - GetFramebufferInfo:  returns width, height, pitch, bpp, format
 *   1 - FlushRect:           flushes a dirty rectangle to the display
 *   2 - FlushAll:            flushes the entire framebuffer
 *
 * Memory types (via IOConnectMapMemory):
 *   0 - Framebuffer VRAM:    maps the physical framebuffer pages
 *
 * Reference: XNU IOGraphics/IOFramebuffer.cpp
 */

#ifndef _IOKIT_IO_FRAMEBUFFER_H
#define _IOKIT_IO_FRAMEBUFFER_H

#include <iokit/io_service.h>
#include <iokit/io_user_client.h>
#include <iokit/io_memory_descriptor.h>

/* Forward declarations */
struct framebuffer_info;

/* ============================================================================
 * IOFramebuffer External Method Selectors
 * ============================================================================ */

#define kIOFBMethodGetInfo          0   /* Get framebuffer info (5 scalars out) */
#define kIOFBMethodFlushRect        1   /* Flush rect (4 scalars in: x,y,w,h) */
#define kIOFBMethodFlushAll         2   /* Flush entire display (no args) */
#define kIOFBMethodCount            3

/* ============================================================================
 * IOFramebuffer Memory Types
 * ============================================================================ */

#define kIOFBMemoryTypeVRAM         0   /* Physical framebuffer VRAM */

/* ============================================================================
 * io_framebuffer - IOFramebuffer service
 *
 * Wraps the VirtIO GPU framebuffer. One instance created during
 * IOKit initialisation.
 * ============================================================================ */

struct io_framebuffer {
    /* Base service (MUST be first for upcast) */
    struct io_service           service;

    /* Cached framebuffer info from VirtIO GPU */
    uint64_t                    fb_phys_addr;
    uint32_t                    fb_width;
    uint32_t                    fb_height;
    uint32_t                    fb_pitch;
    uint32_t                    fb_bpp;
    uint32_t                    fb_format;
    bool                        fb_active;

    /* Memory descriptor for the framebuffer physical pages */
    struct io_memory_descriptor *fb_mem_desc;
};

/* ============================================================================
 * io_framebuffer_user_client - User client for IOFramebuffer
 * ============================================================================ */

struct io_framebuffer_user_client {
    /* Base user client (MUST be first for upcast) */
    struct io_user_client       uc;

    /* Back-pointer to the owning framebuffer service */
    struct io_framebuffer       *framebuffer;
};

/* ============================================================================
 * IOFramebuffer API
 * ============================================================================ */

/*
 * io_framebuffer_init_driver - Initialise and register the IOFramebuffer.
 *
 * Called from iokit_init() after the VirtIO GPU is initialised.
 * Creates the io_framebuffer service, attaches it to the root,
 * and registers it (triggering matching).
 */
void io_framebuffer_init_driver(void);

/* ============================================================================
 * Class Metadata
 * ============================================================================ */

extern const struct io_class_meta io_framebuffer_meta;
extern const struct io_class_meta io_framebuffer_uc_meta;

#endif /* _IOKIT_IO_FRAMEBUFFER_H */
