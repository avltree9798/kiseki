/*
 * Kiseki OS - IOKit IOHIDSystem Driver
 *
 * IOHIDSystem exposes the kernel's HID event ring buffer to userland.
 * WindowServer finds this service via IOServiceGetMatchingService("IOHIDSystem"),
 * opens a connection via IOServiceOpen(), and maps the event ring buffer
 * into its address space via IOConnectMapMemory(connect, 0, ...).
 *
 * The event ring is a lock-free SPSC queue written by VirtIO input IRQ
 * handlers and read by WindowServer.
 *
 * Inheritance chain:
 *   io_object -> io_registry_entry -> io_service -> io_hid_system
 *
 * User client:
 *   io_object -> io_registry_entry -> io_service -> io_user_client
 *             -> io_hid_system_user_client
 *
 * Memory types (via IOConnectMapMemory):
 *   0 - HID event ring buffer (struct hid_event_ring)
 *
 * Reference: macOS IOHIDSystem (IOKit/hidsystem)
 */

#include <kiseki/types.h>
#include <kern/kprintf.h>
#include <kern/sync.h>
#include <kern/hid_event.h>
#include <iokit/io_hid_system.h>
#include <iokit/io_registry.h>
#include <iokit/io_property.h>
#include <iokit/iokit_types.h>

/* ============================================================================
 * Forward Declarations
 * ============================================================================ */

static struct io_service *
hid_probe(struct io_service *service, struct io_service *provider,
          int32_t *score);

static bool
hid_start(struct io_service *service, struct io_service *provider);

static void
hid_stop(struct io_service *service, struct io_service *provider);

static IOReturn
hid_new_user_client(struct io_service *service, struct task *owning_task,
                    uint32_t type, struct io_user_client **client_out);

static IOReturn
hid_uc_client_memory_for_type(struct io_user_client *client, uint32_t type,
                               IOOptionBits *options,
                               struct io_memory_descriptor **memory_out);

static IOReturn
hid_uc_client_close(struct io_user_client *client);

/* ============================================================================
 * Class Metadata
 * ============================================================================ */

const struct io_class_meta io_hid_system_meta = {
    .class_name = "IOHIDSystem",
    .super_meta = &io_service_meta,
    .instance_size = sizeof(struct io_hid_system),
};

const struct io_class_meta io_hid_system_uc_meta = {
    .class_name = "IOHIDSystemUserClient",
    .super_meta = &io_user_client_meta,
    .instance_size = sizeof(struct io_hid_system_user_client),
};

/* ============================================================================
 * Static Pools
 * ============================================================================ */

#define IO_HID_SYSTEM_POOL_SIZE     4
#define IO_HID_SYSTEM_UC_POOL_SIZE  16

static struct io_hid_system hid_pool[IO_HID_SYSTEM_POOL_SIZE];
static bool hid_pool_used[IO_HID_SYSTEM_POOL_SIZE];
static spinlock_t hid_pool_lock = SPINLOCK_INIT;  /* IOK-H3: protect pool */

static struct io_hid_system_user_client hid_uc_pool[IO_HID_SYSTEM_UC_POOL_SIZE];
static bool hid_uc_pool_used[IO_HID_SYSTEM_UC_POOL_SIZE];
static spinlock_t hid_uc_pool_lock = SPINLOCK_INIT;  /* IOK-H3: protect pool */

static struct io_hid_system *io_hid_system_alloc(void)
{
    uint64_t flags;
    spin_lock_irqsave(&hid_pool_lock, &flags);
    for (int i = 0; i < IO_HID_SYSTEM_POOL_SIZE; i++) {
        if (!hid_pool_used[i]) {
            hid_pool_used[i] = true;
            spin_unlock_irqrestore(&hid_pool_lock, flags);
            return &hid_pool[i];
        }
    }
    spin_unlock_irqrestore(&hid_pool_lock, flags);
    return NULL;
}

static void io_hid_system_free_to_pool(struct io_hid_system *hid)
{
    int idx = (int)(hid - hid_pool);
    if (idx >= 0 && idx < IO_HID_SYSTEM_POOL_SIZE) {
        uint64_t flags;
        spin_lock_irqsave(&hid_pool_lock, &flags);
        hid_pool_used[idx] = false;
        spin_unlock_irqrestore(&hid_pool_lock, flags);
    }
}

static struct io_hid_system_user_client *io_hid_system_uc_alloc(void)
{
    uint64_t flags;
    spin_lock_irqsave(&hid_uc_pool_lock, &flags);
    for (int i = 0; i < IO_HID_SYSTEM_UC_POOL_SIZE; i++) {
        if (!hid_uc_pool_used[i]) {
            hid_uc_pool_used[i] = true;
            spin_unlock_irqrestore(&hid_uc_pool_lock, flags);
            return &hid_uc_pool[i];
        }
    }
    spin_unlock_irqrestore(&hid_uc_pool_lock, flags);
    return NULL;
}

static void io_hid_system_uc_free_to_pool(struct io_hid_system_user_client *uc)
{
    int idx = (int)(uc - hid_uc_pool);
    if (idx >= 0 && idx < IO_HID_SYSTEM_UC_POOL_SIZE) {
        uint64_t flags;
        spin_lock_irqsave(&hid_uc_pool_lock, &flags);
        hid_uc_pool_used[idx] = false;
        spin_unlock_irqrestore(&hid_uc_pool_lock, flags);
    }
}

/* ============================================================================
 * IOHIDSystem Vtable
 * ============================================================================ */

static void hid_free(struct io_object *obj)
{
    struct io_hid_system *hid = (struct io_hid_system *)obj;
    io_hid_system_free_to_pool(hid);
}

static const struct io_service_vtable io_hid_system_vtable = {
    .base = {
        .base = {
            .free = hid_free,
        },
    },
    .probe          = hid_probe,
    .start          = hid_start,
    .stop           = hid_stop,
    .getWorkLoop    = NULL,
    .message        = NULL,
    .newUserClient  = hid_new_user_client,
};

/* ============================================================================
 * IOHIDSystemUserClient Vtable
 * ============================================================================ */

static void hid_uc_free(struct io_object *obj)
{
    struct io_hid_system_user_client *uc =
        (struct io_hid_system_user_client *)obj;
    io_hid_system_uc_free_to_pool(uc);
}

static const struct io_user_client_vtable io_hid_system_uc_vtable = {
    .base = {
        .base = {
            .base = {
                .free = hid_uc_free,
            },
        },
        .probe          = NULL,
        .start          = NULL,
        .stop           = NULL,
        .getWorkLoop    = NULL,
        .message        = NULL,
        .newUserClient  = NULL,
    },
    .externalMethod         = NULL,
    .clientMemoryForType    = hid_uc_client_memory_for_type,
    .clientClose            = hid_uc_client_close,
};

/* ============================================================================
 * The singleton IOHIDSystem instance
 * ============================================================================ */

static struct io_hid_system *g_hid_system = NULL;

/* ============================================================================
 * IOHIDSystem Driver Lifecycle
 * ============================================================================ */

static struct io_service *
hid_probe(struct io_service *service, struct io_service *provider,
          int32_t *score)
{
    (void)provider;

    /* The HID event ring is always available */
    struct hid_event_ring *ring = hid_event_ring_get();
    if (ring == NULL) {
        kprintf("[IOHIDSystem] probe: no HID event ring\n");
        return NULL;
    }

    if (score)
        *score = 1000;

    kprintf("[IOHIDSystem] probe: HID event ring available\n");
    return service;
}

static bool
hid_start(struct io_service *service, struct io_service *provider)
{
    (void)provider;

    struct io_hid_system *hid = (struct io_hid_system *)service;

    uint64_t ring_phys = hid_event_ring_get_phys();
    uint64_t ring_size = hid_event_ring_get_size();

    if (ring_phys == 0 || ring_size == 0) {
        kprintf("[IOHIDSystem] start: HID event ring not available\n");
        return false;
    }

    /*
     * Create an IOMemoryDescriptor for the HID event ring.
     * This will be mapped into userland via IOConnectMapMemory.
     */
    hid->ring_mem_desc = io_memory_descriptor_create_with_phys_range(
        ring_phys,
        ring_size,
        kIODirectionInOut,
        0);     /* Default cache mode (cacheable) */

    if (hid->ring_mem_desc == NULL) {
        kprintf("[IOHIDSystem] start: failed to create memory descriptor\n");
        return false;
    }

    /* Set IOKit properties */
    struct io_prop_table *props = &hid->service.entry.prop_table;

    io_prop_set_string(props, "IOClass", "IOHIDSystem");
    io_prop_set_string(props, "IOProviderClass", "IOResources");
    io_prop_set_string(props, "IOMatchCategory", "IOHIDSystem");
    io_prop_set_number(props, "IOHIDRingSize",
                       (uint64_t)sizeof(struct hid_event_ring));
    io_prop_set_number(props, "IOHIDEventCount",
                       (uint64_t)HID_EVENT_RING_SIZE);

    hid->active = true;
    g_hid_system = hid;

    kprintf("[IOHIDSystem] start: ring phys=0x%lx size=%lu\n",
            ring_phys, ring_size);

    return true;
}

static void
hid_stop(struct io_service *service, struct io_service *provider)
{
    (void)provider;

    struct io_hid_system *hid = (struct io_hid_system *)service;

    hid->active = false;

    if (hid->ring_mem_desc) {
        io_object_release(&hid->ring_mem_desc->obj);
        hid->ring_mem_desc = NULL;
    }

    if (g_hid_system == hid)
        g_hid_system = NULL;

    kprintf("[IOHIDSystem] stop\n");
}

/* ============================================================================
 * IOHIDSystem newUserClient
 * ============================================================================ */

static IOReturn
hid_new_user_client(struct io_service *service, struct task *owning_task,
                    uint32_t type, struct io_user_client **client_out)
{
    struct io_hid_system *hid = (struct io_hid_system *)service;

    if (!hid->active) {
        kprintf("[IOHIDSystem] newUserClient: not active\n");
        return kIOReturnNotReady;
    }

    struct io_hid_system_user_client *hid_uc = io_hid_system_uc_alloc();
    if (hid_uc == NULL) {
        kprintf("[IOHIDSystem] newUserClient: pool exhausted\n");
        return kIOReturnNoMemory;
    }

    IOReturn ret = io_user_client_init(
        &hid_uc->uc,
        &io_hid_system_uc_vtable,
        &io_hid_system_uc_meta,
        service,
        owning_task,
        type);

    if (ret != kIOReturnSuccess) {
        io_hid_system_uc_free_to_pool(hid_uc);
        return ret;
    }

    /* No external methods — only memory mapping */
    hid_uc->hid_system = hid;

    *client_out = &hid_uc->uc;

    kprintf("[IOHIDSystem] newUserClient: created for task (type=%u)\n", type);

    return kIOReturnSuccess;
}

/* ============================================================================
 * IOHIDSystemUserClient - clientMemoryForType
 * ============================================================================ */

static IOReturn
hid_uc_client_memory_for_type(struct io_user_client *client, uint32_t type,
                               IOOptionBits *options,
                               struct io_memory_descriptor **memory_out)
{
    struct io_hid_system_user_client *hid_uc =
        (struct io_hid_system_user_client *)client;
    struct io_hid_system *hid = hid_uc->hid_system;

    if (!hid || !hid->active)
        return kIOReturnNotReady;

    if (type != kIOHIDMemoryTypeEventRing) {
        kprintf("[IOHIDSystem] clientMemoryForType: unsupported type %u\n",
                type);
        return kIOReturnBadArgument;
    }

    if (hid->ring_mem_desc == NULL)
        return kIOReturnInternalError;

    io_object_retain(&hid->ring_mem_desc->obj);

    *memory_out = hid->ring_mem_desc;

    if (options)
        *options = 0;   /* Default cache mode */

    return kIOReturnSuccess;
}

/* ============================================================================
 * IOHIDSystemUserClient - clientClose
 * ============================================================================ */

static IOReturn
hid_uc_client_close(struct io_user_client *client)
{
    struct io_hid_system_user_client *hid_uc =
        (struct io_hid_system_user_client *)client;

    kprintf("[IOHIDSystem] clientClose\n");

    hid_uc->hid_system = NULL;

    return kIOReturnSuccess;
}

/* ============================================================================
 * io_hid_system_init_driver - Boot-time initialisation
 * ============================================================================ */

void io_hid_system_init_driver(void)
{
    struct hid_event_ring *ring = hid_event_ring_get();
    if (ring == NULL) {
        kprintf("[IOHIDSystem] init: no HID event ring — skipping\n");
        return;
    }

    struct io_hid_system *hid = io_hid_system_alloc();
    if (hid == NULL) {
        kprintf("[IOHIDSystem] init: pool exhausted\n");
        return;
    }

    IOReturn ret = io_service_init(
        &hid->service,
        &io_hid_system_vtable,
        &io_hid_system_meta,
        "IOHIDSystem");

    if (ret != kIOReturnSuccess) {
        kprintf("[IOHIDSystem] init: io_service_init failed (0x%x)\n", ret);
        io_hid_system_free_to_pool(hid);
        return;
    }

    /* Set IONameMatch for userland matching */
    io_prop_set_string(&hid->service.entry.prop_table,
                       "IONameMatch", "IOHIDSystem");

    /* Zero driver-specific fields */
    hid->ring_mem_desc = NULL;
    hid->active = false;

    /* Probe */
    int32_t score = 0;
    struct io_service *probe_result = hid_probe(&hid->service, NULL, &score);
    if (probe_result == NULL) {
        kprintf("[IOHIDSystem] init: probe failed\n");
        io_hid_system_free_to_pool(hid);
        return;
    }

    /* Start */
    bool started = hid_start(&hid->service, NULL);
    if (!started) {
        kprintf("[IOHIDSystem] init: start failed\n");
        io_hid_system_free_to_pool(hid);
        return;
    }

    /* Attach to the root and register */
    if (g_io_registry.initialised && g_io_registry.root) {
        struct io_service *root_svc = (struct io_service *)g_io_registry.root;
        io_service_attach(&hid->service, root_svc);
    }

    io_service_register(&hid->service);

    kprintf("[IOHIDSystem] init: registered IOHIDSystem service\n");
}
