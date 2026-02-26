/*
 * Kiseki OS - IOKit IOFramebuffer Driver
 *
 * IOFramebuffer wraps the VirtIO GPU hardware behind an IOKit service
 * interface. WindowServer (and any other userland client) opens this
 * service via IOServiceOpen to obtain an IOUserClient connection,
 * then maps the framebuffer memory via IOConnectMapMemory and issues
 * flush commands via IOConnectCallMethod.
 *
 * Inheritance chain:
 *   io_object -> io_registry_entry -> io_service -> io_framebuffer
 *
 * User client:
 *   io_object -> io_registry_entry -> io_service -> io_user_client
 *             -> io_framebuffer_user_client
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
 *            XNU IOGraphics/IOFramebufferUserClient.cpp
 */

#include <kiseki/types.h>
#include <kern/kprintf.h>
#include <kern/sync.h>
#include <kern/thread.h>
#include <kern/fbconsole.h>
#include <iokit/io_framebuffer.h>
#include <iokit/io_registry.h>
#include <iokit/io_property.h>
#include <iokit/iokit_types.h>
#include <drivers/virtio_gpu.h>

/* ============================================================================
 * Forward Declarations
 * ============================================================================ */

static struct io_service *
fb_probe(struct io_service *service, struct io_service *provider,
         int32_t *score);

static bool
fb_start(struct io_service *service, struct io_service *provider);

static void
fb_stop(struct io_service *service, struct io_service *provider);

static IOReturn
fb_new_user_client(struct io_service *service, struct task *owning_task,
                   uint32_t type, struct io_user_client **client_out);

static IOReturn
fb_uc_client_memory_for_type(struct io_user_client *client, uint32_t type,
                             IOOptionBits *options,
                             struct io_memory_descriptor **memory_out);

static IOReturn
fb_uc_client_close(struct io_user_client *client);

/* External method handlers */
static IOReturn
fb_method_get_info(struct io_user_client *client, void *reference,
                   struct io_external_method_args *args);

static IOReturn
fb_method_flush_rect(struct io_user_client *client, void *reference,
                     struct io_external_method_args *args);

static IOReturn
fb_method_flush_all(struct io_user_client *client, void *reference,
                    struct io_external_method_args *args);

/* ============================================================================
 * Class Metadata
 *
 * IOFramebuffer inherits from IOService.
 * IOFramebufferUserClient inherits from IOUserClient.
 * ============================================================================ */

const struct io_class_meta io_framebuffer_meta = {
    .class_name = "IOFramebuffer",
    .super_meta = &io_service_meta,
    .instance_size = sizeof(struct io_framebuffer),
};

const struct io_class_meta io_framebuffer_uc_meta = {
    .class_name = "IOFramebufferUserClient",
    .super_meta = &io_user_client_meta,
    .instance_size = sizeof(struct io_framebuffer_user_client),
};

/* ============================================================================
 * Static Pools
 *
 * Only one IOFramebuffer (single GPU), but we may have multiple user
 * clients (multiple processes opening the service).
 * ============================================================================ */

#define IO_FRAMEBUFFER_POOL_SIZE        4
#define IO_FRAMEBUFFER_UC_POOL_SIZE     16

static struct io_framebuffer fb_pool[IO_FRAMEBUFFER_POOL_SIZE];
static bool fb_pool_used[IO_FRAMEBUFFER_POOL_SIZE];
static spinlock_t fb_pool_lock = SPINLOCK_INIT;  /* IOK-H3: protect pool */

static struct io_framebuffer_user_client fb_uc_pool[IO_FRAMEBUFFER_UC_POOL_SIZE];
static bool fb_uc_pool_used[IO_FRAMEBUFFER_UC_POOL_SIZE];
static spinlock_t fb_uc_pool_lock = SPINLOCK_INIT;  /* IOK-H3: protect pool */

static struct io_framebuffer *io_framebuffer_alloc(void)
{
    uint64_t flags;
    spin_lock_irqsave(&fb_pool_lock, &flags);
    for (int i = 0; i < IO_FRAMEBUFFER_POOL_SIZE; i++) {
        if (!fb_pool_used[i]) {
            fb_pool_used[i] = true;
            spin_unlock_irqrestore(&fb_pool_lock, flags);
            return &fb_pool[i];
        }
    }
    spin_unlock_irqrestore(&fb_pool_lock, flags);
    return NULL;
}

static void io_framebuffer_free_to_pool(struct io_framebuffer *fb)
{
    int idx = (int)(fb - fb_pool);
    if (idx >= 0 && idx < IO_FRAMEBUFFER_POOL_SIZE) {
        uint64_t flags;
        spin_lock_irqsave(&fb_pool_lock, &flags);
        fb_pool_used[idx] = false;
        spin_unlock_irqrestore(&fb_pool_lock, flags);
    }
}

static struct io_framebuffer_user_client *io_framebuffer_uc_alloc(void)
{
    uint64_t flags;
    spin_lock_irqsave(&fb_uc_pool_lock, &flags);
    for (int i = 0; i < IO_FRAMEBUFFER_UC_POOL_SIZE; i++) {
        if (!fb_uc_pool_used[i]) {
            fb_uc_pool_used[i] = true;
            spin_unlock_irqrestore(&fb_uc_pool_lock, flags);
            return &fb_uc_pool[i];
        }
    }
    spin_unlock_irqrestore(&fb_uc_pool_lock, flags);
    return NULL;
}

static void io_framebuffer_uc_free_to_pool(struct io_framebuffer_user_client *uc)
{
    int idx = (int)(uc - fb_uc_pool);
    if (idx >= 0 && idx < IO_FRAMEBUFFER_UC_POOL_SIZE) {
        uint64_t flags;
        spin_lock_irqsave(&fb_uc_pool_lock, &flags);
        fb_uc_pool_used[idx] = false;
        spin_unlock_irqrestore(&fb_uc_pool_lock, flags);
    }
}

/* ============================================================================
 * IOFramebuffer Vtable
 *
 * Overrides probe/start/stop/newUserClient from io_service_vtable.
 * The base io_object and io_registry_entry methods use defaults.
 * ============================================================================ */

/*
 * Default base vtable entries (io_object level).
 * free: return the framebuffer to the static pool.
 */
static void fb_free(struct io_object *obj)
{
    struct io_framebuffer *fb = (struct io_framebuffer *)obj;
    io_framebuffer_free_to_pool(fb);
}

static const struct io_service_vtable io_framebuffer_vtable = {
    .base = {
        .base = {
            .free = fb_free,
        },
        /* io_registry_entry_vtable: no overrides needed */
    },
    .probe          = fb_probe,
    .start          = fb_start,
    .stop           = fb_stop,
    .getWorkLoop    = NULL,
    .message        = NULL,
    .newUserClient  = fb_new_user_client,
};

/* ============================================================================
 * IOFramebufferUserClient Vtable
 *
 * Overrides externalMethod, clientMemoryForType, clientClose.
 * ============================================================================ */

static void fb_uc_free(struct io_object *obj)
{
    struct io_framebuffer_user_client *uc =
        (struct io_framebuffer_user_client *)obj;
    io_framebuffer_uc_free_to_pool(uc);
}

static const struct io_user_client_vtable io_framebuffer_uc_vtable = {
    .base = {
        .base = {
            .base = {
                .free = fb_uc_free,
            },
        },
        .probe          = NULL,
        .start          = NULL,
        .stop           = NULL,
        .getWorkLoop    = NULL,
        .message        = NULL,
        .newUserClient  = NULL,
    },
    /*
     * externalMethod is NULL — dispatch goes through the dispatch table
     * set by io_user_client_set_dispatch_table() in fb_new_user_client().
     *
     * On XNU, IOFramebufferUserClient::externalMethod() overrides to
     * call IOUserClient::externalMethod() (the base class), which does
     * the dispatch table lookup. Setting NULL here achieves the same:
     * io_user_client_call_method() skips the vtable call and falls
     * through to the dispatch table directly.
     */
    .externalMethod         = NULL,
    .clientMemoryForType    = fb_uc_client_memory_for_type,
    .clientClose            = fb_uc_client_close,
};

/* ============================================================================
 * External Method Dispatch Table
 *
 * Each entry defines the method function and expected argument counts.
 * The dispatch table is set on the user client at open time, and
 * io_user_client_call_method() validates counts before calling.
 *
 * Reference: XNU IOFramebufferUserClient::externalMethod()
 * ============================================================================ */

static const struct io_external_method_dispatch fb_methods[kIOFBMethodCount] = {
    [kIOFBMethodGetInfo] = {
        .function               = fb_method_get_info,
        .checkScalarInputCount  = 0,
        .checkStructureInputSize = 0,
        .checkScalarOutputCount = 5,    /* width, height, pitch, bpp, format */
        .checkStructureOutputSize = 0,
    },
    [kIOFBMethodFlushRect] = {
        .function               = fb_method_flush_rect,
        .checkScalarInputCount  = 4,    /* x, y, width, height */
        .checkStructureInputSize = 0,
        .checkScalarOutputCount = 0,
        .checkStructureOutputSize = 0,
    },
    [kIOFBMethodFlushAll] = {
        .function               = fb_method_flush_all,
        .checkScalarInputCount  = 0,
        .checkStructureInputSize = 0,
        .checkScalarOutputCount = 0,
        .checkStructureOutputSize = 0,
    },
};

/* ============================================================================
 * The singleton IOFramebuffer instance
 * ============================================================================ */

static struct io_framebuffer *g_framebuffer = NULL;

/* ============================================================================
 * IOFramebuffer Driver Lifecycle
 * ============================================================================ */

/*
 * fb_probe - Check if this driver can drive the given provider.
 *
 * For the IOFramebuffer, the provider is the root IOResources service.
 * We probe by checking if the VirtIO GPU is initialised and active.
 *
 * Reference: XNU IOFramebuffer::probe()
 */
static struct io_service *
fb_probe(struct io_service *service, struct io_service *provider,
         int32_t *score)
{
    (void)provider;

    const struct framebuffer_info *fb = virtio_gpu_get_fb();
    if (fb == NULL || !fb->active) {
        kprintf("[IOFramebuffer] probe: no VirtIO GPU found\n");
        return NULL;
    }

    /* Accept with default score */
    if (score)
        *score = 1000;

    kprintf("[IOFramebuffer] probe: VirtIO GPU found (%ux%u)\n",
            fb->width, fb->height);
    return service;
}

/*
 * fb_start - Start the IOFramebuffer driver.
 *
 * Caches the VirtIO GPU framebuffer info, creates the IOMemoryDescriptor
 * for the framebuffer physical pages, and sets IOKit properties.
 *
 * Reference: XNU IOFramebuffer::start()
 */
static bool
fb_start(struct io_service *service, struct io_service *provider)
{
    (void)provider;

    struct io_framebuffer *fb = (struct io_framebuffer *)service;
    const struct framebuffer_info *gpu_fb = virtio_gpu_get_fb();

    if (gpu_fb == NULL || !gpu_fb->active) {
        kprintf("[IOFramebuffer] start: VirtIO GPU not active\n");
        return false;
    }

    /* Cache framebuffer info */
    fb->fb_phys_addr = gpu_fb->phys_addr;
    fb->fb_width     = gpu_fb->width;
    fb->fb_height    = gpu_fb->height;
    fb->fb_pitch     = gpu_fb->pitch;
    fb->fb_bpp       = gpu_fb->bpp;
    fb->fb_format    = gpu_fb->format;
    fb->fb_active    = true;

    /*
     * Create an IOMemoryDescriptor for the framebuffer physical pages.
     *
     * The framebuffer memory is allocated by virtio_gpu_init() as a
     * contiguous physical block. We describe it as a single physical
     * range. WindowServer will map this into its address space via
     * IOConnectMapMemory -> clientMemoryForType.
     *
     * Cache mode: kIOMapWriteCombineCache — write-combining is the
     * standard cache mode for framebuffers on ARM64. It allows the
     * CPU to batch writes without requiring explicit flushes for
     * each pixel, while ensuring coherency with the DMA engine.
     *
     * Reference: XNU IOFramebuffer creates IODeviceMemory for VRAM.
     */
    uint64_t fb_size = (uint64_t)fb->fb_pitch * (uint64_t)fb->fb_height;

    fb->fb_mem_desc = io_memory_descriptor_create_with_phys_range(
        fb->fb_phys_addr,
        fb_size,
        kIODirectionInOut,
        kIOMapWriteCombineCache);

    if (fb->fb_mem_desc == NULL) {
        kprintf("[IOFramebuffer] start: failed to create memory descriptor\n");
        fb->fb_active = false;
        return false;
    }

    /*
     * Set IOKit properties on the service's property table.
     * These are visible to userland via IORegistryEntryGetProperty.
     *
     * Reference: XNU IOFramebuffer::start() sets IOFBWidth, IOFBHeight, etc.
     */
    struct io_prop_table *props = &fb->service.entry.prop_table;

    io_prop_set_string(props, "IOClass", "IOFramebuffer");
    io_prop_set_string(props, "IOProviderClass", "IOResources");
    io_prop_set_string(props, "IOMatchCategory", "IOFramebuffer");
    io_prop_set_number(props, "IOFBWidth", fb->fb_width);
    io_prop_set_number(props, "IOFBHeight", fb->fb_height);
    io_prop_set_number(props, "IOFBPitch", fb->fb_pitch);
    io_prop_set_number(props, "IOFBBitsPerPixel", fb->fb_bpp);
    io_prop_set_number(props, "IOFBPixelFormat", fb->fb_format);
    io_prop_set_number(props, "IOFBPhysicalAddress",
                       (uint64_t)fb->fb_phys_addr);
    io_prop_set_number(props, "IOFBMemorySize", fb_size);

    kprintf("[IOFramebuffer] start: %ux%u, %u bpp, pitch=%u, phys=0x%lx\n",
            fb->fb_width, fb->fb_height, fb->fb_bpp, fb->fb_pitch,
            (uint64_t)fb->fb_phys_addr);

    g_framebuffer = fb;

    return true;
}

/*
 * fb_stop - Stop the IOFramebuffer driver.
 *
 * Releases the memory descriptor. The VirtIO GPU itself is not shut
 * down — it remains available for re-probe.
 *
 * Reference: XNU IOFramebuffer::stop()
 */
static void
fb_stop(struct io_service *service, struct io_service *provider)
{
    (void)provider;

    struct io_framebuffer *fb = (struct io_framebuffer *)service;

    fb->fb_active = false;

    if (fb->fb_mem_desc) {
        io_object_release(&fb->fb_mem_desc->obj);
        fb->fb_mem_desc = NULL;
    }

    if (g_framebuffer == fb)
        g_framebuffer = NULL;

    kprintf("[IOFramebuffer] stop\n");
}

/* ============================================================================
 * IOFramebuffer newUserClient
 *
 * Called when userland calls IOServiceOpen() on the IOFramebuffer service.
 * Creates an io_framebuffer_user_client with the external method dispatch
 * table and a back-pointer to the framebuffer.
 *
 * Reference: XNU IOFramebuffer::newUserClient()
 * ============================================================================ */

static IOReturn
fb_new_user_client(struct io_service *service, struct task *owning_task,
                   uint32_t type, struct io_user_client **client_out)
{
    struct io_framebuffer *fb = (struct io_framebuffer *)service;

    if (!fb->fb_active) {
        kprintf("[IOFramebuffer] newUserClient: framebuffer not active\n");
        return kIOReturnNotReady;
    }

    /* Allocate the user client from the pool */
    struct io_framebuffer_user_client *fb_uc = io_framebuffer_uc_alloc();
    if (fb_uc == NULL) {
        kprintf("[IOFramebuffer] newUserClient: pool exhausted\n");
        return kIOReturnNoMemory;
    }

    /* Initialise the base user client */
    IOReturn ret = io_user_client_init(
        &fb_uc->uc,
        &io_framebuffer_uc_vtable,
        &io_framebuffer_uc_meta,
        service,
        owning_task,
        type);

    if (ret != kIOReturnSuccess) {
        io_framebuffer_uc_free_to_pool(fb_uc);
        return ret;
    }

    /* Set the external method dispatch table */
    io_user_client_set_dispatch_table(&fb_uc->uc, fb_methods,
                                      kIOFBMethodCount);

    /* Set the back-pointer to the owning framebuffer */
    fb_uc->framebuffer = fb;

    *client_out = &fb_uc->uc;

    /*
     * IOK-C1: Disable fbconsole now that a user client (WindowServer)
     * has opened the framebuffer. This prevents the dual-writer race
     * where both fbconsole and WindowServer write pixels and flush.
     *
     * On macOS, the boot console is disabled when WindowServer registers
     * with IOFramebuffer (via vc_progress_set / disableConsoleOutput).
     */
    fbconsole_disable();

    kprintf("[IOFramebuffer] newUserClient: created for task (type=%u), "
            "fbconsole disabled\n", type);

    return kIOReturnSuccess;
}


/* ============================================================================
 * External Method: GetFramebufferInfo (selector 0)
 *
 * No inputs. Returns 5 scalars:
 *   [0] = width
 *   [1] = height
 *   [2] = pitch (bytes per row)
 *   [3] = bpp (bits per pixel)
 *   [4] = format (VIRTIO_GPU_FORMAT_*)
 *
 * Reference: macOS IOFramebuffer uses IOFBGetCurrentDisplayModeAndDepth
 *            and IOFBGetPixelInformation; we simplify to a single call.
 * ============================================================================ */

static IOReturn
fb_method_get_info(struct io_user_client *client, void *reference,
                   struct io_external_method_args *args)
{
    (void)reference;

    struct io_framebuffer_user_client *fb_uc =
        (struct io_framebuffer_user_client *)client;
    struct io_framebuffer *fb = fb_uc->framebuffer;

    if (!fb || !fb->fb_active)
        return kIOReturnNotReady;

    if (args->scalarOutputCount < 5)
        return kIOReturnBadArgument;

    args->scalarOutput[0] = fb->fb_width;
    args->scalarOutput[1] = fb->fb_height;
    args->scalarOutput[2] = fb->fb_pitch;
    args->scalarOutput[3] = fb->fb_bpp;
    args->scalarOutput[4] = fb->fb_format;

    return kIOReturnSuccess;
}

/* ============================================================================
 * External Method: FlushRect (selector 1)
 *
 * 4 scalar inputs: x, y, width, height.
 * Transfers the rectangle from backing to host and flushes.
 *
 * Reference: macOS IOFramebuffer damage notification via
 *            IOFBNotifyServerRedraw / IOSurface dirty rects.
 * ============================================================================ */

static IOReturn
fb_method_flush_rect(struct io_user_client *client, void *reference,
                     struct io_external_method_args *args)
{
    (void)reference;

    struct io_framebuffer_user_client *fb_uc =
        (struct io_framebuffer_user_client *)client;
    struct io_framebuffer *fb = fb_uc->framebuffer;

    if (!fb || !fb->fb_active)
        return kIOReturnNotReady;

    if (args->scalarInputCount < 4)
        return kIOReturnBadArgument;

    uint32_t x      = (uint32_t)args->scalarInput[0];
    uint32_t y      = (uint32_t)args->scalarInput[1];
    uint32_t width  = (uint32_t)args->scalarInput[2];
    uint32_t height = (uint32_t)args->scalarInput[3];

    /*
     * IOK-H6: Clamp to framebuffer bounds using subtraction form
     * to prevent integer overflow. If x + width overflows uint32_t,
     * the comparison `x + width > fb_width` would be wrong.
     * Instead: `width > fb_width - x` is safe since x < fb_width.
     */
    if (x >= fb->fb_width || y >= fb->fb_height)
        return kIOReturnBadArgument;
    if (width > fb->fb_width - x)
        width = fb->fb_width - x;
    if (height > fb->fb_height - y)
        height = fb->fb_height - y;

    if (width == 0 || height == 0)
        return kIOReturnSuccess;

    virtio_gpu_flush(x, y, width, height);

    return kIOReturnSuccess;
}

/* ============================================================================
 * External Method: FlushAll (selector 2)
 *
 * No inputs, no outputs. Flushes the entire framebuffer.
 * ============================================================================ */

static IOReturn
fb_method_flush_all(struct io_user_client *client, void *reference,
                    struct io_external_method_args *args)
{
    (void)reference;
    (void)args;

    struct io_framebuffer_user_client *fb_uc =
        (struct io_framebuffer_user_client *)client;
    struct io_framebuffer *fb = fb_uc->framebuffer;

    if (!fb || !fb->fb_active)
        return kIOReturnNotReady;

    virtio_gpu_flush_all();

    return kIOReturnSuccess;
}

/* ============================================================================
 * IOFramebufferUserClient — clientMemoryForType
 *
 * Called by IOConnectMapMemory. Returns an IOMemoryDescriptor for the
 * requested memory type. Only type 0 (kIOFBMemoryTypeVRAM) is supported.
 *
 * The caller (io_user_client_map_memory) will then map the descriptor
 * into the owning task's address space.
 *
 * Reference: XNU IOFramebuffer::clientMemoryForType()
 * ============================================================================ */

static IOReturn
fb_uc_client_memory_for_type(struct io_user_client *client, uint32_t type,
                             IOOptionBits *options,
                             struct io_memory_descriptor **memory_out)
{
    struct io_framebuffer_user_client *fb_uc =
        (struct io_framebuffer_user_client *)client;
    struct io_framebuffer *fb = fb_uc->framebuffer;

    if (!fb || !fb->fb_active)
        return kIOReturnNotReady;

    if (type != kIOFBMemoryTypeVRAM) {
        kprintf("[IOFramebuffer] clientMemoryForType: unsupported type %u\n",
                type);
        return kIOReturnBadArgument;
    }

    if (fb->fb_mem_desc == NULL)
        return kIOReturnInternalError;

    /*
     * Return the framebuffer memory descriptor. Retain it since the
     * caller (map logic) will eventually release.
     */
    io_object_retain(&fb->fb_mem_desc->obj);

    *memory_out = fb->fb_mem_desc;

    if (options)
        *options = kIOMapWriteCombineCache;

    return kIOReturnSuccess;
}

/* ============================================================================
 * IOFramebufferUserClient — clientClose
 *
 * Called when the user client connection is closed.
 *
 * Reference: XNU IOFramebufferUserClient::clientClose()
 * ============================================================================ */

static IOReturn
fb_uc_client_close(struct io_user_client *client)
{
    struct io_framebuffer_user_client *fb_uc =
        (struct io_framebuffer_user_client *)client;

    kprintf("[IOFramebuffer] clientClose\n");

    fb_uc->framebuffer = NULL;

    /*
     * Re-enable fbconsole when the last user client disconnects.
     * This allows the text console to resume if WindowServer crashes.
     */
    fbconsole_enable();

    return kIOReturnSuccess;
}

/* ============================================================================
 * io_framebuffer_init_driver — Boot-time initialisation
 *
 * Called from iokit_init() after the VirtIO GPU has been initialised.
 * Allocates the IOFramebuffer service, probes it, starts it, and
 * registers it in the I/O Registry.
 *
 * This follows the XNU IOKit matching model where the platform expert
 * publishes nub services and drivers are matched against them. Since
 * Kiseki has a single fixed GPU, we short-circuit the matching and
 * directly create and start the driver.
 *
 * Reference: XNU IOPlatformExpert publishes IOResources, then
 *            IOFramebuffer personality matches against it.
 * ============================================================================ */

void io_framebuffer_init_driver(void)
{
    const struct framebuffer_info *gpu_fb = virtio_gpu_get_fb();
    if (gpu_fb == NULL || !gpu_fb->active) {
        kprintf("[IOFramebuffer] init: no VirtIO GPU — skipping\n");
        return;
    }

    /* Allocate the framebuffer service from the static pool */
    struct io_framebuffer *fb = io_framebuffer_alloc();
    if (fb == NULL) {
        kprintf("[IOFramebuffer] init: pool exhausted\n");
        return;
    }

    /*
     * Initialise as an IOService.
     *
     * The name "IOFramebuffer" is the IOKit class name that userland
     * matches against (via IOServiceGetMatchingServices with
     * IOServiceMatching("IOFramebuffer")).
     */
    IOReturn ret = io_service_init(
        &fb->service,
        &io_framebuffer_vtable,
        &io_framebuffer_meta,
        "IOFramebuffer");

    if (ret != kIOReturnSuccess) {
        kprintf("[IOFramebuffer] init: io_service_init failed (0x%x)\n", ret);
        io_framebuffer_free_to_pool(fb);
        return;
    }

    /* Set IONameMatch for userland matching */
    io_prop_set_string(&fb->service.entry.prop_table,
                       "IONameMatch", "IOFramebuffer");

    /* Zero the framebuffer-specific fields */
    fb->fb_phys_addr = 0;
    fb->fb_width = 0;
    fb->fb_height = 0;
    fb->fb_pitch = 0;
    fb->fb_bpp = 0;
    fb->fb_format = 0;
    fb->fb_active = false;
    fb->fb_mem_desc = NULL;

    /*
     * Probe — check if the VirtIO GPU is available.
     */
    int32_t score = 0;
    struct io_service *probe_result = fb_probe(&fb->service, NULL, &score);
    if (probe_result == NULL) {
        kprintf("[IOFramebuffer] init: probe failed\n");
        io_framebuffer_free_to_pool(fb);
        return;
    }

    /*
     * Start — cache framebuffer info, create memory descriptor.
     */
    bool started = fb_start(&fb->service, NULL);
    if (!started) {
        kprintf("[IOFramebuffer] init: start failed\n");
        io_framebuffer_free_to_pool(fb);
        return;
    }

    /*
     * Attach to the root IOResources entry and register.
     * This makes the service discoverable via IOServiceGetMatchingService.
     */
    if (g_io_registry.initialised && g_io_registry.root) {
        struct io_service *root_svc = (struct io_service *)g_io_registry.root;
        io_service_attach(&fb->service, root_svc);
    }

    io_service_register(&fb->service);

    kprintf("[IOFramebuffer] init: registered IOFramebuffer service\n");
    kprintf("[IOFramebuffer]   %ux%u, %u bpp, format=%u\n",
            fb->fb_width, fb->fb_height, fb->fb_bpp, fb->fb_format);
}
