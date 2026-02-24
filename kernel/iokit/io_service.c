/*
 * Kiseki OS - IOKit Service Implementation
 *
 * IOService base class: driver lifecycle, provider/client management,
 * service state, registry integration, and matching.
 *
 * Reference: XNU iokit/Kernel/IOService.cpp
 */

#include <iokit/io_service.h>
#include <iokit/io_registry.h>
#include <kern/kprintf.h>

/* ============================================================================
 * Class Metadata
 * ============================================================================ */

const struct io_class_meta io_service_meta = {
    .class_name     = "IOService",
    .super_meta     = &io_registry_entry_meta,
    .instance_size  = sizeof(struct io_service),
};

/* ============================================================================
 * Static Pool
 * ============================================================================ */

static struct io_service service_pool[IO_SERVICE_POOL_SIZE];
static bool service_pool_used[IO_SERVICE_POOL_SIZE];
static spinlock_t service_pool_lock = SPINLOCK_INIT;

struct io_service *
io_service_alloc(void)
{
    uint64_t flags;
    spin_lock_irqsave(&service_pool_lock, &flags);

    for (uint32_t i = 0; i < IO_SERVICE_POOL_SIZE; i++) {
        if (!service_pool_used[i]) {
            service_pool_used[i] = true;

            /* Zero the service */
            uint8_t *p = (uint8_t *)&service_pool[i];
            for (uint32_t j = 0; j < sizeof(struct io_service); j++)
                p[j] = 0;

            service_pool[i].service_pool_allocated = true;
            service_pool[i].service_pool_index = i;

            spin_unlock_irqrestore(&service_pool_lock, flags);
            return &service_pool[i];
        }
    }

    spin_unlock_irqrestore(&service_pool_lock, flags);
    kprintf("IOKit: WARN: io_service pool exhausted (%d entries)\n",
            IO_SERVICE_POOL_SIZE);
    return NULL;
}

void
io_service_free_to_pool(struct io_service *service)
{
    if (!service || !service->service_pool_allocated)
        return;

    uint64_t flags;
    spin_lock_irqsave(&service_pool_lock, &flags);

    uint32_t idx = service->service_pool_index;
    if (idx < IO_SERVICE_POOL_SIZE) {
        service_pool_used[idx] = false;
    }

    spin_unlock_irqrestore(&service_pool_lock, flags);
}

/* ============================================================================
 * Default vtable
 * ============================================================================ */

static void
service_free(struct io_object *obj)
{
    struct io_service *service = (struct io_service *)obj;
    io_service_free_to_pool(service);
}

static struct io_service *
service_default_probe(struct io_service *service,
                      struct io_service *provider,
                      int32_t *score)
{
    (void)provider;
    (void)score;
    /* Default probe always succeeds */
    return service;
}

static bool
service_default_start(struct io_service *service,
                      struct io_service *provider)
{
    (void)service;
    (void)provider;
    /* Default start always succeeds */
    return true;
}

static void
service_default_stop(struct io_service *service,
                     struct io_service *provider)
{
    (void)service;
    (void)provider;
}

static struct io_work_loop *
service_default_get_work_loop(struct io_service *service)
{
    /* Default: return provider's work loop */
    if (service->provider) {
        const struct io_service_vtable *pvt =
            (const struct io_service_vtable *)service->provider->entry.obj.vtable;
        if (pvt->getWorkLoop)
            return pvt->getWorkLoop(service->provider);
    }
    return NULL;
}

static IOReturn
service_default_message(struct io_service *service, uint32_t type,
                        struct io_service *provider, void *argument)
{
    (void)service;
    (void)type;
    (void)provider;
    (void)argument;
    return kIOReturnUnsupported;
}

static IOReturn
service_default_new_user_client(struct io_service *service,
                                struct task *owning_task,
                                uint32_t type,
                                struct io_user_client **client_out)
{
    (void)service;
    (void)owning_task;
    (void)type;
    (void)client_out;
    return kIOReturnUnsupported;
}

static const struct io_service_vtable default_service_vtable = {
    .base = {
        .base = {
            .free = service_free,
        },
        .getProperty = NULL,    /* Will use default from registry entry */
        .setProperty = NULL,
    },
    .probe          = service_default_probe,
    .start          = service_default_start,
    .stop           = service_default_stop,
    .getWorkLoop    = service_default_get_work_loop,
    .message        = service_default_message,
    .newUserClient  = service_default_new_user_client,
};

/* ============================================================================
 * io_service_init
 * ============================================================================ */

IOReturn
io_service_init(struct io_service *service,
                const struct io_service_vtable *vtable,
                const struct io_class_meta *meta,
                const char *name)
{
    if (!service)
        return kIOReturnBadArgument;

    const struct io_service_vtable *vt = vtable ? vtable : &default_service_vtable;

    /* Initialise base io_registry_entry */
    IOReturn ret = io_registry_entry_init(
        &service->entry,
        (const struct io_registry_entry_vtable *)vt,
        meta ? meta : &io_service_meta,
        name);

    if (ret != kIOReturnSuccess)
        return ret;

    /* Initialise service-specific fields */
    service->provider = NULL;
    service->client_count = 0;
    service->state[0] = 0;
    service->state[1] = 0;
    service->busy_count = 0;
    service->work_loop = NULL;
    service->service_port = NULL;

    for (uint32_t i = 0; i < IO_SERVICE_MAX_CLIENTS; i++)
        service->clients[i] = NULL;

    return kIOReturnSuccess;
}

/* ============================================================================
 * Service Registration
 *
 * Reference: XNU IOService::registerService()
 * ============================================================================ */

IOReturn
io_service_register(struct io_service *service)
{
    if (!service)
        return kIOReturnBadArgument;

    /* Mark as registered */
    service->state[0] |= kIOServiceRegisteredState;

    /* Attach to provider in IOService plane (if we have one) */
    if (service->provider) {
        io_registry_entry_attach_to_parent(
            &service->entry,
            &service->provider->entry,
            IO_PLANE_SERVICE);
    } else {
        /* Top-level service: attach to registry root */
        struct io_registry_entry *root = io_registry_get_root();
        if (root) {
            io_registry_entry_attach_to_parent(
                &service->entry, root, IO_PLANE_SERVICE);
        }
    }

    kprintf("IOKit: registered service '%s' (entry_id=%u)\n",
            io_registry_entry_get_name(&service->entry),
            service->entry.entry_id);

    /* Trigger matching — find drivers for this new service */
    return io_catalogue_start_matching(service);
}

/* ============================================================================
 * Provider / Client Management
 *
 * Reference: XNU IOService::attach() / IOService::detach()
 * ============================================================================ */

IOReturn
io_service_attach(struct io_service *client, struct io_service *provider)
{
    if (!client || !provider)
        return kIOReturnBadArgument;

    /* Add to provider's client list */
    if (provider->client_count >= IO_SERVICE_MAX_CLIENTS)
        return kIOReturnNoSpace;

    provider->clients[provider->client_count] = client;
    provider->client_count++;

    /* Set client's provider */
    client->provider = provider;

    /* Retain the client */
    io_object_retain(&client->entry.obj);

    return kIOReturnSuccess;
}

IOReturn
io_service_detach(struct io_service *client, struct io_service *provider)
{
    if (!client || !provider)
        return kIOReturnBadArgument;

    /* Remove from provider's client list */
    for (uint32_t i = 0; i < provider->client_count; i++) {
        if (provider->clients[i] == client) {
            /* Shift remaining clients */
            for (uint32_t j = i; j < provider->client_count - 1; j++)
                provider->clients[j] = provider->clients[j + 1];
            provider->clients[provider->client_count - 1] = NULL;
            provider->client_count--;

            /* Clear client's provider */
            client->provider = NULL;

            /* Release */
            io_object_release(&client->entry.obj);
            return kIOReturnSuccess;
        }
    }

    return kIOReturnNotFound;
}

/* ============================================================================
 * Termination
 *
 * Reference: XNU IOService::terminate()
 * ============================================================================ */

IOReturn
io_service_terminate(struct io_service *service)
{
    if (!service)
        return kIOReturnBadArgument;

    /* Mark inactive */
    service->state[0] |= kIOServiceInactiveState;

    /* Call stop() */
    const struct io_service_vtable *vt =
        (const struct io_service_vtable *)service->entry.obj.vtable;
    if (vt->stop && service->provider)
        vt->stop(service, service->provider);

    /* Detach from provider */
    if (service->provider) {
        io_service_detach(service, service->provider);
        io_registry_entry_detach_from_parent(
            &service->entry,
            &service->provider->entry,
            IO_PLANE_SERVICE);
    }

    return kIOReturnSuccess;
}

/* ============================================================================
 * Accessors
 * ============================================================================ */

struct io_service *
io_service_get_provider(struct io_service *service)
{
    return service ? service->provider : NULL;
}

uint32_t
io_service_get_state(struct io_service *service)
{
    return service ? service->state[0] : 0;
}

void
io_service_adjust_busy(struct io_service *service, int32_t delta)
{
    if (!service)
        return;
    __atomic_add_fetch(&service->busy_count, delta, __ATOMIC_RELAXED);

    /* Propagate busy count up to provider (XNU behaviour) */
    if (service->provider)
        io_service_adjust_busy(service->provider, delta);
}

IOReturn
io_service_wait_quiet(struct io_service *service)
{
    if (!service)
        return kIOReturnBadArgument;

    /* Spin wait on busy count (simple implementation) */
    while (__atomic_load_n(&service->busy_count, __ATOMIC_ACQUIRE) > 0) {
        /* Yield to other threads */
        /* thread_sleep_ticks(1) would be better but busy wait is acceptable
         * during boot for IOKit matching */
    }

    return kIOReturnSuccess;
}

/* ============================================================================
 * Service Matching (userland-initiated)
 *
 * These walk the IOService plane to find services matching given properties.
 *
 * Reference: XNU IOService::copyMatchingService()
 * ============================================================================ */

/*
 * Recursive helper: search entry and all its children in the
 * IOService plane.
 */
static void
find_matching_recursive(struct io_registry_entry *entry,
                        const struct io_prop_table *match_props,
                        struct io_service **out_services,
                        uint32_t max_services,
                        uint32_t *count)
{
    if (*count >= max_services)
        return;

    /* Check if this entry is an io_service and matches */
    if (io_object_is_class(&entry->obj, &io_service_meta)) {
        struct io_service *svc = (struct io_service *)entry;

        /* Must be registered and not inactive */
        if ((svc->state[0] & kIOServiceRegisteredState) &&
            !(svc->state[0] & kIOServiceInactiveState)) {
            if (io_prop_match(&entry->prop_table, match_props)) {
                out_services[*count] = svc;
                (*count)++;
            }
        }
    }

    /* Recurse into children in IOService plane */
    uint32_t child_count = io_registry_entry_get_child_count(entry,
                                                              IO_PLANE_SERVICE);
    for (uint32_t i = 0; i < child_count && *count < max_services; i++) {
        struct io_registry_entry *child =
            io_registry_entry_get_child(entry, IO_PLANE_SERVICE, i);
        if (child)
            find_matching_recursive(child, match_props,
                                    out_services, max_services, count);
    }
}

struct io_service *
io_service_get_matching_service(const struct io_prop_table *match_props)
{
    struct io_service *result = NULL;
    uint32_t count = 0;

    struct io_registry_entry *root = io_registry_get_root();
    if (!root)
        return NULL;

    find_matching_recursive(root, match_props, &result, 1, &count);
    return result;
}

uint32_t
io_service_get_matching_services(const struct io_prop_table *match_props,
                                 struct io_service **out_services,
                                 uint32_t max_services)
{
    uint32_t count = 0;

    struct io_registry_entry *root = io_registry_get_root();
    if (!root || !out_services || max_services == 0)
        return 0;

    find_matching_recursive(root, match_props, out_services,
                            max_services, &count);
    return count;
}
