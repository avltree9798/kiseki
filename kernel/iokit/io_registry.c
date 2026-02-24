/*
 * Kiseki OS - IOKit Registry & Catalogue Implementation
 *
 * Global I/O Registry singleton, driver catalogue with XNU-style matching
 * algorithm, and iokit_init() boot entry point.
 *
 * Reference: XNU iokit/Kernel/IORegistryEntry.cpp (gRegistryRoot),
 *            iokit/Kernel/IOCatalogue.cpp
 */

#include <iokit/io_registry.h>
#include <iokit/io_service.h>
#include <iokit/io_framebuffer.h>
#include <iokit/iokit_types.h>
#include <mach/ipc.h>
#include <kern/kprintf.h>

/* ============================================================================
 * String Helper
 * ============================================================================ */

static int
reg_strcmp(const char *a, const char *b)
{
    while (*a && (*a == *b)) {
        a++;
        b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

static void
reg_strncpy(char *dst, const char *src, uint32_t max)
{
    uint32_t i;
    for (i = 0; i < max - 1 && src[i]; i++)
        dst[i] = src[i];
    dst[i] = '\0';
}

/* ============================================================================
 * Global Registry Singleton
 * ============================================================================ */

struct io_registry g_io_registry;

/* ============================================================================
 * io_registry_init
 *
 * Creates the root registry entry ("IOResources") which serves as the
 * root of the IOService plane. On XNU, this is the gRegistryRoot.
 *
 * Reference: XNU IORegistryEntry::initialize()
 * ============================================================================ */

void
io_registry_init(void)
{
    if (g_io_registry.initialised)
        return;

    /* Initialise the registry lock */
    mutex_init(&g_io_registry.lock);

    /* Start entry IDs at 1 (0 = invalid) */
    g_io_registry.next_entry_id = 1;

    /* Clear catalogue */
    g_io_registry.catalogue_count = 0;
    for (uint32_t i = 0; i < IO_CATALOGUE_MAX_PERSONALITIES; i++)
        g_io_registry.catalogue[i].active = false;

    /* Allocate and initialise the root entry */
    struct io_registry_entry *root = io_registry_entry_alloc();
    if (!root) {
        kprintf("IOKit: PANIC: cannot allocate root registry entry\n");
        return;
    }

    io_registry_entry_init(root, NULL, &io_registry_entry_meta, "IOResources");

    /*
     * Set standard root properties (XNU convention).
     * On macOS, the root entry is an IOResources node that holds
     * system-wide resource properties.
     */
    io_prop_set_string(&root->prop_table, kIOClassKey, "IOResources");
    io_prop_set_string(&root->prop_table, "IOProviderClass", "IOResources");

    g_io_registry.root = root;
    g_io_registry.initialised = true;

    kprintf("IOKit: I/O Registry initialised (root=%p, entry_id=%u)\n",
            root, root->entry_id);
}

struct io_registry_entry *
io_registry_get_root(void)
{
    return g_io_registry.root;
}

uint32_t
io_registry_assign_entry_id(void)
{
    /*
     * Simple monotonic counter. Protected by being called during
     * io_registry_entry_init() which is serialised.
     */
    return __atomic_fetch_add(&g_io_registry.next_entry_id, 1,
                              __ATOMIC_RELAXED);
}

/* ============================================================================
 * Catalogue API
 *
 * Driver personalities are registered at boot by built-in drivers.
 * When a new service is registered, the catalogue finds matching
 * personalities and instantiates drivers.
 *
 * Reference: XNU iokit/Kernel/IOCatalogue.cpp
 * ============================================================================ */

IOReturn
io_catalogue_add_personality(const char *class_name,
                             const char *provider_class,
                             int32_t probe_score,
                             const char *match_category,
                             const struct io_prop_table *match_props,
                             io_driver_init_fn init_fn)
{
    if (!class_name || !provider_class || !init_fn)
        return kIOReturnBadArgument;

    mutex_lock(&g_io_registry.lock);

    /* Find a free slot */
    struct io_driver_personality *slot = NULL;
    for (uint32_t i = 0; i < IO_CATALOGUE_MAX_PERSONALITIES; i++) {
        if (!g_io_registry.catalogue[i].active) {
            slot = &g_io_registry.catalogue[i];
            break;
        }
    }

    if (!slot) {
        mutex_unlock(&g_io_registry.lock);
        return kIOReturnNoSpace;
    }

    slot->active = true;
    reg_strncpy(slot->class_name, class_name, IO_REGISTRY_NAME_MAX);
    reg_strncpy(slot->provider_class, provider_class, IO_REGISTRY_NAME_MAX);
    slot->probe_score = probe_score;

    if (match_category)
        reg_strncpy(slot->match_category, match_category, IO_REGISTRY_NAME_MAX);
    else
        slot->match_category[0] = '\0';

    if (match_props)
        io_prop_copy(&slot->match_properties, match_props);
    else
        io_prop_table_init(&slot->match_properties);

    slot->init_fn = init_fn;

    g_io_registry.catalogue_count++;

    mutex_unlock(&g_io_registry.lock);

    kprintf("IOKit: registered personality '%s' for provider '%s' (score=%d)\n",
            class_name, provider_class, (int)probe_score);

    return kIOReturnSuccess;
}

/*
 * io_catalogue_find_drivers_for_service
 *
 * Implements the XNU matching algorithm:
 *   1. Filter by IOProviderClass
 *   2. Filter by IOPropertyMatch
 *   3. Sort by IOProbeScore (descending)
 *   4. Return best matches per category
 *
 * Reference: XNU IOService::probeCandidates()
 */
uint32_t
io_catalogue_find_drivers_for_service(struct io_service *provider,
                                      struct io_driver_personality **out_matches,
                                      uint32_t max_matches)
{
    if (!provider || !out_matches || max_matches == 0)
        return 0;

    /* Get provider's class name from its metadata */
    const char *provider_class = provider->entry.obj.meta->class_name;

    /*
     * Phase 1: Collect all personalities whose IOProviderClass matches
     *          the provider's class.
     */
    struct io_driver_personality *candidates[IO_CATALOGUE_MAX_PERSONALITIES];
    uint32_t candidate_count = 0;

    mutex_lock(&g_io_registry.lock);

    for (uint32_t i = 0; i < IO_CATALOGUE_MAX_PERSONALITIES; i++) {
        struct io_driver_personality *p = &g_io_registry.catalogue[i];
        if (!p->active)
            continue;

        /* Check IOProviderClass match */
        if (reg_strcmp(p->provider_class, provider_class) != 0)
            continue;

        /* Check IOPropertyMatch if present */
        if (p->match_properties.count > 0) {
            if (!io_prop_match(&provider->entry.prop_table,
                               &p->match_properties))
                continue;
        }

        candidates[candidate_count++] = p;
    }

    mutex_unlock(&g_io_registry.lock);

    /*
     * Phase 2: Sort by probe score (descending).
     * Simple insertion sort — catalogue is small.
     */
    for (uint32_t i = 1; i < candidate_count; i++) {
        struct io_driver_personality *key = candidates[i];
        int32_t j = (int32_t)i - 1;
        while (j >= 0 && candidates[j]->probe_score < key->probe_score) {
            candidates[j + 1] = candidates[j];
            j--;
        }
        candidates[j + 1] = key;
    }

    /*
     * Phase 3: Group by IOMatchCategory.
     *
     * On XNU, within each match category only the highest-scoring
     * personality wins. Different categories allow multiple drivers
     * to attach to the same provider simultaneously.
     *
     * We use a simple approach: track seen categories and skip
     * duplicates (since candidates are sorted by score, the first
     * in each category is the highest).
     */
    char seen_categories[IO_CATALOGUE_MAX_PERSONALITIES][IO_REGISTRY_NAME_MAX];
    uint32_t seen_count = 0;
    uint32_t result_count = 0;

    for (uint32_t i = 0; i < candidate_count && result_count < max_matches; i++) {
        struct io_driver_personality *p = candidates[i];

        /* Check if this category has already been seen */
        if (p->match_category[0] != '\0') {
            bool already_seen = false;
            for (uint32_t s = 0; s < seen_count; s++) {
                if (reg_strcmp(seen_categories[s], p->match_category) == 0) {
                    already_seen = true;
                    break;
                }
            }
            if (already_seen)
                continue;

            /* Record this category */
            reg_strncpy(seen_categories[seen_count], p->match_category,
                        IO_REGISTRY_NAME_MAX);
            seen_count++;
        }

        out_matches[result_count++] = p;
    }

    return result_count;
}

/*
 * io_catalogue_start_matching
 *
 * Called when a service is registered. Finds matching personalities,
 * instantiates drivers, and calls probe() then start().
 *
 * Reference: XNU IOService::doServiceMatch()
 */
IOReturn
io_catalogue_start_matching(struct io_service *service)
{
    if (!service)
        return kIOReturnBadArgument;

    struct io_driver_personality *matches[IO_CATALOGUE_MAX_PERSONALITIES];
    uint32_t match_count = io_catalogue_find_drivers_for_service(
        service, matches, IO_CATALOGUE_MAX_PERSONALITIES);

    if (match_count == 0)
        return kIOReturnSuccess; /* No drivers — that's OK */

    kprintf("IOKit: matching '%s': %u candidate(s)\n",
            io_registry_entry_get_name(&service->entry), match_count);

    /* Increment busy count during matching */
    io_service_adjust_busy(service, 1);

    for (uint32_t i = 0; i < match_count; i++) {
        struct io_driver_personality *p = matches[i];

        kprintf("IOKit:   trying '%s' (score=%d)\n",
                p->class_name, (int)p->probe_score);

        /* Instantiate the driver via its init function */
        struct io_service *driver = p->init_fn(service);
        if (!driver) {
            kprintf("IOKit:   '%s' init failed\n", p->class_name);
            continue;
        }

        /* Probe */
        const struct io_service_vtable *vt =
            (const struct io_service_vtable *)driver->entry.obj.vtable;

        int32_t score = p->probe_score;
        if (vt->probe) {
            struct io_service *result = vt->probe(driver, service, &score);
            if (!result || score < 0) {
                kprintf("IOKit:   '%s' probe rejected (score=%d)\n",
                        p->class_name, (int)score);
                io_object_release(&driver->entry.obj);
                continue;
            }
        }

        /* Attach to provider */
        io_service_attach(driver, service);

        /* Start */
        if (vt->start) {
            bool started = vt->start(driver, service);
            if (!started) {
                kprintf("IOKit:   '%s' start failed\n", p->class_name);
                io_service_detach(driver, service);
                io_object_release(&driver->entry.obj);
                continue;
            }
        }

        /* Mark as matched */
        driver->state[0] |= kIOServiceMatchedState;

        kprintf("IOKit:   '%s' started successfully\n", p->class_name);

        /* Register the driver (which may trigger further matching) */
        io_service_register(driver);
    }

    /* Decrement busy count */
    io_service_adjust_busy(service, -1);

    return kIOReturnSuccess;
}

/* ============================================================================
 * iokit_init - IOKit subsystem initialisation
 *
 * Called from kernel boot sequence (main.c) after ipc_init().
 * ============================================================================ */

void
iokit_init(void)
{
    kprintf("IOKit: initialising IOKit subsystem\n");

    /* Initialise the global I/O Registry */
    io_registry_init();

    /*
     * Allocate the IOKit master port and register it in the bootstrap
     * namespace. Userland calls bootstrap_look_up("uk.co.avltree9798.iokit")
     * to get a send right, then sends IOServiceGetMatchingService messages
     * to this port.
     *
     * On XNU, this is the "IOServiceMasterPort" registered during
     * IOKit initialisation. We use our reverse-DNS prefix.
     */
    struct ipc_port *master_port = ipc_port_alloc();
    if (master_port != NULL) {
        master_port->kobject = &g_io_registry;
        master_port->kobject_type = IKOT_MASTER_DEVICE;
        g_io_registry.master_port = master_port;

        kern_return_t kr = bootstrap_register_kernel(
            "uk.co.avltree9798.iokit", master_port);
        if (kr == KERN_SUCCESS) {
            kprintf("IOKit: master port registered in bootstrap\n");
        } else {
            kprintf("IOKit: WARNING: failed to register master port (%d)\n", kr);
        }
    } else {
        kprintf("IOKit: WARNING: failed to allocate master port\n");
    }

    /*
     * Built-in IOKit drivers are NOT initialised here.
     *
     * IOFramebuffer depends on the VirtIO GPU being initialised first,
     * which happens later in the boot sequence (Phase 16b). The kernel
     * main.c calls io_framebuffer_init_driver() after virtio_gpu_init()
     * completes.
     *
     * This matches XNU's model where IOKit matching runs asynchronously
     * after drivers have registered their personalities.
     */

    kprintf("IOKit: initialisation complete\n");
}
