/*
 * Kiseki OS - IOKit Registry Entry Implementation
 *
 * Implements the IORegistryEntry base class: property management,
 * plane linkage, name/location, and static pool allocation.
 *
 * Reference: XNU iokit/Kernel/IORegistryEntry.cpp
 */

#include <iokit/io_registry_entry.h>
#include <iokit/io_registry.h>
#include <kern/kprintf.h>

/* ============================================================================
 * String Helpers (freestanding)
 * ============================================================================ */

static void
re_strncpy(char *dst, const char *src, uint32_t max)
{
    uint32_t i;
    for (i = 0; i < max - 1 && src[i]; i++)
        dst[i] = src[i];
    dst[i] = '\0';
}

/* ============================================================================
 * Class Metadata
 * ============================================================================ */

const struct io_class_meta io_registry_entry_meta = {
    .class_name     = "IORegistryEntry",
    .super_meta     = &io_object_meta,
    .instance_size  = sizeof(struct io_registry_entry),
};

/* ============================================================================
 * Static Pool
 *
 * All registry entries are allocated from this pool.
 * No kernel heap — static arrays only.
 * ============================================================================ */

static struct io_registry_entry entry_pool[IO_REGISTRY_ENTRY_POOL_SIZE];
static bool entry_pool_used[IO_REGISTRY_ENTRY_POOL_SIZE];
static spinlock_t entry_pool_lock = SPINLOCK_INIT;

struct io_registry_entry *
io_registry_entry_alloc(void)
{
    uint64_t flags;
    spin_lock_irqsave(&entry_pool_lock, &flags);

    for (uint32_t i = 0; i < IO_REGISTRY_ENTRY_POOL_SIZE; i++) {
        if (!entry_pool_used[i]) {
            entry_pool_used[i] = true;

            /* Zero the entry */
            uint8_t *p = (uint8_t *)&entry_pool[i];
            for (uint32_t j = 0; j < sizeof(struct io_registry_entry); j++)
                p[j] = 0;

            entry_pool[i].pool_allocated = true;
            entry_pool[i].pool_index = i;

            spin_unlock_irqrestore(&entry_pool_lock, flags);
            return &entry_pool[i];
        }
    }

    spin_unlock_irqrestore(&entry_pool_lock, flags);
    kprintf("IOKit: WARN: io_registry_entry pool exhausted (%d entries)\n",
            IO_REGISTRY_ENTRY_POOL_SIZE);
    return NULL;
}

void
io_registry_entry_free_to_pool(struct io_registry_entry *entry)
{
    if (!entry || !entry->pool_allocated)
        return;

    uint64_t flags;
    spin_lock_irqsave(&entry_pool_lock, &flags);

    uint32_t idx = entry->pool_index;
    if (idx < IO_REGISTRY_ENTRY_POOL_SIZE) {
        entry_pool_used[idx] = false;
    }

    spin_unlock_irqrestore(&entry_pool_lock, flags);
}

/* ============================================================================
 * Default vtable
 * ============================================================================ */

static void
registry_entry_free(struct io_object *obj)
{
    struct io_registry_entry *entry = (struct io_registry_entry *)obj;
    io_registry_entry_free_to_pool(entry);
}

static const struct io_prop_value *
registry_entry_get_property(struct io_registry_entry *entry, const char *key)
{
    return io_prop_get(&entry->prop_table, key);
}

static IOReturn
registry_entry_set_property(struct io_registry_entry *entry,
                            const char *key,
                            const struct io_prop_value *value)
{
    if (!entry || !key || !value)
        return kIOReturnBadArgument;

    switch (value->type) {
    case IO_PROP_STRING:
        return io_prop_set_string(&entry->prop_table, key, value->u.string);
    case IO_PROP_NUMBER:
        return io_prop_set_number(&entry->prop_table, key, value->u.number);
    case IO_PROP_BOOL:
        return io_prop_set_bool(&entry->prop_table, key, value->u.boolean);
    case IO_PROP_DATA:
        return io_prop_set_data(&entry->prop_table, key,
                                value->u.data.bytes, value->u.data.length);
    default:
        return kIOReturnBadArgument;
    }
}

static const struct io_registry_entry_vtable default_registry_entry_vtable = {
    .base = {
        .free = registry_entry_free,
    },
    .getProperty = registry_entry_get_property,
    .setProperty = registry_entry_set_property,
};

/* ============================================================================
 * io_registry_entry_init
 * ============================================================================ */

IOReturn
io_registry_entry_init(struct io_registry_entry *entry,
                       const struct io_registry_entry_vtable *vtable,
                       const struct io_class_meta *meta,
                       const char *name)
{
    if (!entry)
        return kIOReturnBadArgument;

    /* Initialise base io_object */
    const struct io_registry_entry_vtable *vt = vtable ? vtable
                                                       : &default_registry_entry_vtable;
    io_object_init(&entry->obj,
                   (const struct io_object_vtable *)vt,
                   meta ? meta : &io_registry_entry_meta);

    /* Assign unique entry ID */
    entry->entry_id = io_registry_assign_entry_id();

    /* Set name */
    if (name)
        re_strncpy(entry->name, name, IO_REGISTRY_NAME_MAX);
    else
        entry->name[0] = '\0';

    entry->location[0] = '\0';

    /* Initialise property table */
    io_prop_table_init(&entry->prop_table);

    /* Set class name as a property (XNU convention) */
    if (meta)
        io_prop_set_string(&entry->prop_table, kIOClassKey, meta->class_name);

    /* Initialise plane links */
    for (uint32_t p = 0; p < IO_PLANE_MAX; p++) {
        entry->planes[p].parent = NULL;
        entry->planes[p].child_count = 0;
        for (uint32_t c = 0; c < IO_REGISTRY_MAX_CHILDREN; c++)
            entry->planes[p].children[c] = NULL;
    }

    /* Initialise arb lock */
    mutex_init(&entry->arb_lock);

    return kIOReturnSuccess;
}

/* ============================================================================
 * Name / Location
 * ============================================================================ */

const char *
io_registry_entry_get_name(struct io_registry_entry *entry)
{
    if (!entry)
        return "";
    return entry->name;
}

void
io_registry_entry_set_name(struct io_registry_entry *entry, const char *name)
{
    if (!entry || !name)
        return;
    re_strncpy(entry->name, name, IO_REGISTRY_NAME_MAX);
}

void
io_registry_entry_set_location(struct io_registry_entry *entry,
                               const char *location)
{
    if (!entry || !location)
        return;
    re_strncpy(entry->location, location, IO_REGISTRY_LOCATION_MAX);
}

/* ============================================================================
 * Property Access (via vtable dispatch)
 * ============================================================================ */

const struct io_prop_value *
io_registry_entry_get_property(struct io_registry_entry *entry,
                               const char *key)
{
    if (!entry || !key)
        return NULL;

    const struct io_registry_entry_vtable *vt =
        (const struct io_registry_entry_vtable *)entry->obj.vtable;

    if (vt->getProperty)
        return vt->getProperty(entry, key);

    /* Fallback: direct table lookup */
    return io_prop_get(&entry->prop_table, key);
}

IOReturn
io_registry_entry_set_property_string(struct io_registry_entry *entry,
                                      const char *key, const char *value)
{
    if (!entry || !key || !value)
        return kIOReturnBadArgument;
    return io_prop_set_string(&entry->prop_table, key, value);
}

IOReturn
io_registry_entry_set_property_number(struct io_registry_entry *entry,
                                      const char *key, uint64_t value)
{
    if (!entry || !key)
        return kIOReturnBadArgument;
    return io_prop_set_number(&entry->prop_table, key, value);
}

IOReturn
io_registry_entry_set_property_bool(struct io_registry_entry *entry,
                                    const char *key, bool value)
{
    if (!entry || !key)
        return kIOReturnBadArgument;
    return io_prop_set_bool(&entry->prop_table, key, value);
}

/* ============================================================================
 * Plane Manipulation
 *
 * Reference: XNU IORegistryEntry::attachToParent(),
 *            IORegistryEntry::detachFromParent()
 * ============================================================================ */

IOReturn
io_registry_entry_attach_to_parent(struct io_registry_entry *entry,
                                   struct io_registry_entry *parent,
                                   uint32_t plane)
{
    if (!entry || !parent || plane >= IO_PLANE_MAX)
        return kIOReturnBadArgument;

    struct io_plane_link *plink = &parent->planes[plane];

    /* Check for space */
    if (plink->child_count >= IO_REGISTRY_MAX_CHILDREN)
        return kIOReturnNoSpace;

    /* Check not already attached */
    for (uint32_t i = 0; i < plink->child_count; i++) {
        if (plink->children[i] == entry)
            return kIOReturnSuccess; /* Already attached */
    }

    /* Attach */
    plink->children[plink->child_count] = entry;
    plink->child_count++;

    /* Set child's parent link */
    entry->planes[plane].parent = parent;

    /* Retain child (parent holds a reference) */
    io_object_retain(&entry->obj);

    return kIOReturnSuccess;
}

IOReturn
io_registry_entry_detach_from_parent(struct io_registry_entry *entry,
                                     struct io_registry_entry *parent,
                                     uint32_t plane)
{
    if (!entry || !parent || plane >= IO_PLANE_MAX)
        return kIOReturnBadArgument;

    struct io_plane_link *plink = &parent->planes[plane];

    /* Find and remove */
    for (uint32_t i = 0; i < plink->child_count; i++) {
        if (plink->children[i] == entry) {
            /* Shift remaining children down */
            for (uint32_t j = i; j < plink->child_count - 1; j++)
                plink->children[j] = plink->children[j + 1];
            plink->children[plink->child_count - 1] = NULL;
            plink->child_count--;

            /* Clear child's parent link */
            entry->planes[plane].parent = NULL;

            /* Release child reference */
            io_object_release(&entry->obj);

            return kIOReturnSuccess;
        }
    }

    return kIOReturnNotFound;
}

struct io_registry_entry *
io_registry_entry_get_parent(struct io_registry_entry *entry, uint32_t plane)
{
    if (!entry || plane >= IO_PLANE_MAX)
        return NULL;
    return entry->planes[plane].parent;
}

uint32_t
io_registry_entry_get_child_count(struct io_registry_entry *entry,
                                  uint32_t plane)
{
    if (!entry || plane >= IO_PLANE_MAX)
        return 0;
    return entry->planes[plane].child_count;
}

struct io_registry_entry *
io_registry_entry_get_child(struct io_registry_entry *entry,
                            uint32_t plane, uint32_t index)
{
    if (!entry || plane >= IO_PLANE_MAX)
        return NULL;
    if (index >= entry->planes[plane].child_count)
        return NULL;
    return entry->planes[plane].children[index];
}
