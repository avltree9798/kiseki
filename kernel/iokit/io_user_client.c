/*
 * Kiseki OS - IOKit User Client Implementation
 *
 * Implements IOUserClient: external method dispatch, memory mapping
 * via IOConnectMapMemory, and user client lifecycle.
 *
 * Reference: XNU iokit/Kernel/IOUserClient.cpp
 */

#include <iokit/io_user_client.h>
#include <kern/kprintf.h>

/* ============================================================================
 * Class Metadata
 * ============================================================================ */

const struct io_class_meta io_user_client_meta = {
    .class_name     = "IOUserClient",
    .super_meta     = &io_service_meta,
    .instance_size  = sizeof(struct io_user_client),
};

/* ============================================================================
 * Static Pool
 * ============================================================================ */

static struct io_user_client uc_pool[IO_USER_CLIENT_POOL_SIZE];
static bool uc_pool_used[IO_USER_CLIENT_POOL_SIZE];
static spinlock_t uc_pool_lock = SPINLOCK_INIT;

struct io_user_client *
io_user_client_alloc(void)
{
    uint64_t flags;
    spin_lock_irqsave(&uc_pool_lock, &flags);

    for (uint32_t i = 0; i < IO_USER_CLIENT_POOL_SIZE; i++) {
        if (!uc_pool_used[i]) {
            uc_pool_used[i] = true;

            uint8_t *p = (uint8_t *)&uc_pool[i];
            for (uint32_t j = 0; j < sizeof(struct io_user_client); j++)
                p[j] = 0;

            uc_pool[i].uc_pool_allocated = true;
            uc_pool[i].uc_pool_index = i;

            spin_unlock_irqrestore(&uc_pool_lock, flags);
            return &uc_pool[i];
        }
    }

    spin_unlock_irqrestore(&uc_pool_lock, flags);
    return NULL;
}

void
io_user_client_free_to_pool(struct io_user_client *client)
{
    if (!client || !client->uc_pool_allocated)
        return;

    uint64_t flags;
    spin_lock_irqsave(&uc_pool_lock, &flags);
    if (client->uc_pool_index < IO_USER_CLIENT_POOL_SIZE)
        uc_pool_used[client->uc_pool_index] = false;
    spin_unlock_irqrestore(&uc_pool_lock, flags);
}

/* ============================================================================
 * Default vtable
 * ============================================================================ */

static void
uc_free(struct io_object *obj)
{
    struct io_user_client *uc = (struct io_user_client *)obj;

    /* Release all mappings */
    for (uint32_t i = 0; i < uc->mapping_count; i++) {
        if (uc->mappings[i]) {
            io_memory_map_unmap(uc->mappings[i]);
            io_object_release(&uc->mappings[i]->obj);
            uc->mappings[i] = NULL;
        }
    }

    io_user_client_free_to_pool(uc);
}

static IOReturn
uc_default_external_method(struct io_user_client *client,
                           uint32_t selector,
                           struct io_external_method_args *args)
{
    (void)client;
    (void)selector;
    (void)args;
    return kIOReturnUnsupported;
}

static IOReturn
uc_default_client_memory_for_type(struct io_user_client *client,
                                  uint32_t type,
                                  IOOptionBits *options,
                                  struct io_memory_descriptor **memory_out)
{
    (void)client;
    (void)type;
    (void)options;
    (void)memory_out;
    return kIOReturnUnsupported;
}

static IOReturn
uc_default_client_close(struct io_user_client *client)
{
    (void)client;
    return kIOReturnSuccess;
}

static const struct io_user_client_vtable default_uc_vtable = {
    .base = {
        .base = {
            .base = {
                .free = uc_free,
            },
            .getProperty = NULL,
            .setProperty = NULL,
        },
        .probe          = NULL,
        .start          = NULL,
        .stop           = NULL,
        .getWorkLoop    = NULL,
        .message        = NULL,
        .newUserClient  = NULL,
    },
    .externalMethod         = uc_default_external_method,
    .clientMemoryForType    = uc_default_client_memory_for_type,
    .clientClose            = uc_default_client_close,
};

/* ============================================================================
 * io_user_client_init
 * ============================================================================ */

IOReturn
io_user_client_init(struct io_user_client *client,
                    const struct io_user_client_vtable *vtable,
                    const struct io_class_meta *meta,
                    struct io_service *owner_service,
                    struct task *owning_task,
                    uint32_t type)
{
    if (!client)
        return kIOReturnBadArgument;

    const struct io_user_client_vtable *vt = vtable ? vtable : &default_uc_vtable;

    /* Initialise base io_service */
    IOReturn ret = io_service_init(&client->service,
                                   (const struct io_service_vtable *)vt,
                                   meta ? meta : &io_user_client_meta,
                                   "IOUserClient");
    if (ret != kIOReturnSuccess)
        return ret;

    client->owning_task = owning_task;
    client->owner_service = owner_service;
    client->dispatch_table = NULL;
    client->dispatch_table_count = 0;
    client->mapping_count = 0;
    client->connect_port = NULL;
    client->connect_type = type;

    for (uint32_t i = 0; i < IO_USER_CLIENT_MAX_MAPPINGS; i++)
        client->mappings[i] = NULL;

    return kIOReturnSuccess;
}

/* ============================================================================
 * Dispatch Table
 * ============================================================================ */

void
io_user_client_set_dispatch_table(struct io_user_client *client,
                                  const struct io_external_method_dispatch *table,
                                  uint32_t count)
{
    if (!client)
        return;
    client->dispatch_table = table;
    client->dispatch_table_count = count;
}

/* ============================================================================
 * External Method Dispatch
 *
 * Validates argument counts, then dispatches to the method function.
 *
 * Reference: XNU IOUserClient::externalMethod()
 * ============================================================================ */

IOReturn
io_user_client_call_method(struct io_user_client *client,
                           uint32_t selector,
                           struct io_external_method_args *args)
{
    if (!client || !args)
        return kIOReturnBadArgument;

    /*
     * First, try the vtable's externalMethod (allows subclasses to
     * override entirely, like XNU does).
     */
    const struct io_user_client_vtable *vt =
        (const struct io_user_client_vtable *)client->service.entry.obj.vtable;

    if (vt->externalMethod) {
        IOReturn ret = vt->externalMethod(client, selector, args);
        if (ret != kIOReturnUnsupported)
            return ret;
    }

    /* Fall back to dispatch table */
    if (!client->dispatch_table || selector >= client->dispatch_table_count)
        return kIOReturnBadMessageID;

    const struct io_external_method_dispatch *method =
        &client->dispatch_table[selector];

    if (!method->function)
        return kIOReturnUnsupported;

    /* Validate argument counts */
    if (args->scalarInputCount != method->checkScalarInputCount)
        return kIOReturnBadArgument;
    if (args->structureInputSize != method->checkStructureInputSize)
        return kIOReturnBadArgument;
    if (args->scalarOutputCount != method->checkScalarOutputCount)
        return kIOReturnBadArgument;
    if (method->checkStructureOutputSize != 0 &&
        args->structureOutputSize < method->checkStructureOutputSize)
        return kIOReturnBadArgument;

    return method->function(client, NULL, args);
}

/* ============================================================================
 * Memory Mapping
 *
 * Reference: XNU is_io_connect_map_memory_into_task()
 * ============================================================================ */

IOReturn
io_user_client_map_memory(struct io_user_client *client,
                          uint32_t type,
                          IOOptionBits options,
                          uint64_t *address,
                          uint64_t *size)
{
    if (!client || !address || !size)
        return kIOReturnBadArgument;

    /* Call clientMemoryForType to get the descriptor */
    const struct io_user_client_vtable *vt =
        (const struct io_user_client_vtable *)client->service.entry.obj.vtable;

    if (!vt->clientMemoryForType)
        return kIOReturnUnsupported;

    struct io_memory_descriptor *desc = NULL;
    IOOptionBits desc_options = 0;
    IOReturn ret = vt->clientMemoryForType(client, type, &desc_options, &desc);
    if (ret != kIOReturnSuccess || !desc)
        return ret != kIOReturnSuccess ? ret : kIOReturnError;

    /* Combine options */
    IOOptionBits map_options = options | desc_options;

    /* Map into the owning task */
    struct io_memory_map *map = io_memory_descriptor_map(
        desc, client->owning_task, map_options);
    if (!map) {
        io_object_release(&desc->obj);
        return kIOReturnVMError;
    }

    /*
     * Store the mapping in the user client's mapping table.
     *
     * On XNU, the IOUserClient maintains a dynamically-allocated
     * OSArray of IOMemoryMap objects. We use a fixed-size array.
     * If the array is full, fail the operation rather than leaking
     * the mapping (the map was created with refcount=1 by
     * io_memory_descriptor_map, and we must not release it without
     * storing it, or the mapped memory would be freed while still
     * in the user's address space).
     */
    if (client->mapping_count >= IO_USER_CLIENT_MAX_MAPPINGS) {
        kprintf("[io_user_client] map_memory: mapping table full (%u)\n",
                IO_USER_CLIENT_MAX_MAPPINGS);
        io_memory_map_unmap(map);
        io_object_release(&map->obj);
        io_object_release(&desc->obj);
        return kIOReturnNoResources;
    }

    client->mappings[client->mapping_count] = map;
    client->mapping_count++;
    /* The mapping array now owns the reference from io_memory_descriptor_map */

    *address = io_memory_map_get_virtual_address(map);
    *size = io_memory_map_get_length(map);

    /*
     * Release the descriptor reference obtained from clientMemoryForType.
     * The map object retains its own reference (via io_object_retain in
     * io_memory_descriptor_map), so the descriptor remains alive.
     *
     * On XNU, is_io_connect_map_memory_into_task() does the same:
     * the descriptor returned by clientMemoryForType is released after
     * the map is created.
     */
    io_object_release(&desc->obj);

    return kIOReturnSuccess;
}

/* ============================================================================
 * Close
 * ============================================================================ */

IOReturn
io_user_client_close(struct io_user_client *client)
{
    if (!client)
        return kIOReturnBadArgument;

    /* Call clientClose */
    const struct io_user_client_vtable *vt =
        (const struct io_user_client_vtable *)client->service.entry.obj.vtable;

    if (vt->clientClose)
        vt->clientClose(client);

    /* Unmap all mappings */
    for (uint32_t i = 0; i < client->mapping_count; i++) {
        if (client->mappings[i]) {
            io_memory_map_unmap(client->mappings[i]);
            io_object_release(&client->mappings[i]->obj);
            client->mappings[i] = NULL;
        }
    }
    client->mapping_count = 0;

    return kIOReturnSuccess;
}
