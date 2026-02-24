/*
 * Kiseki OS - IOKit Registry Entry
 *
 * Base class for all objects in the I/O Registry. Each registry entry
 * has a name, location, property table, and plane linkage (parent/child
 * relationships within registry planes like IOService, IODeviceTree).
 *
 * Inherits from io_object (first field), enabling safe upcasting.
 *
 * Reference: XNU iokit/Kernel/IORegistryEntry.cpp,
 *            iokit/IOKit/IORegistryEntry.h
 */

#ifndef _IOKIT_IO_REGISTRY_ENTRY_H
#define _IOKIT_IO_REGISTRY_ENTRY_H

#include <iokit/io_object.h>
#include <iokit/io_property.h>

/* ============================================================================
 * Registry Plane IDs
 *
 * XNU supports multiple planes (IOService, IODeviceTree, IOPower, IOUSB).
 * We implement the primary planes.
 * ============================================================================ */

#define IO_PLANE_SERVICE         0      /* IOService plane (driver matching) */
#define IO_PLANE_DEVICE_TREE     1      /* IODeviceTree plane (device tree) */
#define IO_PLANE_POWER           2      /* IOPower plane (power management) */
#define IO_PLANE_MAX             3

/* Maximum children per entry per plane */
#define IO_REGISTRY_MAX_CHILDREN    32

/* Maximum name/location length */
#define IO_REGISTRY_NAME_MAX        64
#define IO_REGISTRY_LOCATION_MAX    64

/* ============================================================================
 * io_plane_link - Linkage within a single registry plane
 *
 * Each IORegistryEntry can appear in multiple planes simultaneously.
 * Each plane has its own parent/children relationships.
 *
 * Reference: XNU IORegistryEntry::registryTable() per plane
 * ============================================================================ */

struct io_plane_link {
    struct io_registry_entry    *parent;                        /* Parent in this plane */
    struct io_registry_entry    *children[IO_REGISTRY_MAX_CHILDREN]; /* Children */
    uint32_t                    child_count;                    /* Active child count */
};

/* ============================================================================
 * io_registry_entry_vtable - Virtual methods for registry entries
 *
 * Extends io_object_vtable. The base io_object_vtable is embedded as
 * the first field to maintain vtable inheritance.
 * ============================================================================ */

struct io_registry_entry_vtable {
    /* Parent vtable (must be first for safe upcast) */
    struct io_object_vtable     base;

    /*
     * getProperty - Look up a property in this entry.
     *
     * Default implementation looks in the entry's prop_table.
     * Subclasses may override to provide computed properties.
     *
     * Reference: XNU IORegistryEntry::getProperty()
     */
    const struct io_prop_value *(*getProperty)(struct io_registry_entry *entry,
                                               const char *key);

    /*
     * setProperty - Set a property on this entry.
     *
     * Reference: XNU IORegistryEntry::setProperty()
     */
    IOReturn (*setProperty)(struct io_registry_entry *entry,
                            const char *key,
                            const struct io_prop_value *value);
};

/* ============================================================================
 * io_registry_entry - Registry entry structure
 *
 * First field is io_object for inheritance. An io_registry_entry pointer
 * can be safely cast to io_object*.
 *
 * Reference: XNU IORegistryEntry (iokit/Kernel/IORegistryEntry.cpp)
 * ============================================================================ */

struct io_registry_entry {
    /* Base object (MUST be first for upcast) */
    struct io_object            obj;

    /* Entry identity */
    uint32_t                    entry_id;       /* Unique registry entry ID */
    char                        name[IO_REGISTRY_NAME_MAX];
    char                        location[IO_REGISTRY_LOCATION_MAX];

    /* Property table — replaces OSDictionary */
    struct io_prop_table        prop_table;

    /* Plane linkage — one set of parent/children per plane */
    struct io_plane_link        planes[IO_PLANE_MAX];

    /* Arbitrary property lock (serialises property access) */
    mutex_t                     arb_lock;

    /* Pool tracking */
    bool                        pool_allocated; /* true if from static pool */
    uint32_t                    pool_index;     /* Index in static pool */
};

/* ============================================================================
 * io_registry_entry API
 * ============================================================================ */

/*
 * io_registry_entry_init - Initialise a registry entry.
 *
 * Sets up property table, plane links, name, and base object fields.
 * Called by subclass init functions (e.g., io_service_init).
 *
 * @entry:  Entry to initialise
 * @vtable: Vtable for the concrete class (cast from subclass vtable)
 * @meta:   Class metadata for the concrete class
 * @name:   Entry name (e.g., "IOResources", "AppleVirtIOGPU")
 *
 * Returns kIOReturnSuccess.
 */
IOReturn io_registry_entry_init(struct io_registry_entry *entry,
                                const struct io_registry_entry_vtable *vtable,
                                const struct io_class_meta *meta,
                                const char *name);

/*
 * io_registry_entry_get_name - Get the entry's name.
 */
const char *io_registry_entry_get_name(struct io_registry_entry *entry);

/*
 * io_registry_entry_set_name - Set the entry's name.
 */
void io_registry_entry_set_name(struct io_registry_entry *entry,
                                const char *name);

/*
 * io_registry_entry_set_location - Set the entry's location string.
 *
 * Reference: XNU IORegistryEntry::setLocation()
 */
void io_registry_entry_set_location(struct io_registry_entry *entry,
                                    const char *location);

/*
 * io_registry_entry_get_property - Look up a property.
 *
 * Dispatches through vtable for subclass override.
 */
const struct io_prop_value *
io_registry_entry_get_property(struct io_registry_entry *entry,
                               const char *key);

/*
 * io_registry_entry_set_property_string - Set a string property.
 */
IOReturn io_registry_entry_set_property_string(struct io_registry_entry *entry,
                                               const char *key,
                                               const char *value);

/*
 * io_registry_entry_set_property_number - Set a numeric property.
 */
IOReturn io_registry_entry_set_property_number(struct io_registry_entry *entry,
                                               const char *key,
                                               uint64_t value);

/*
 * io_registry_entry_set_property_bool - Set a boolean property.
 */
IOReturn io_registry_entry_set_property_bool(struct io_registry_entry *entry,
                                             const char *key, bool value);

/* ============================================================================
 * Registry Plane Manipulation
 *
 * Reference: XNU IORegistryEntry::attachToParent(),
 *            IORegistryEntry::detachFromParent()
 * ============================================================================ */

/*
 * io_registry_entry_attach_to_parent - Attach entry as child of parent
 *                                       in the specified plane.
 *
 * @entry:   Child entry
 * @parent:  Parent entry
 * @plane:   Plane ID (IO_PLANE_SERVICE, etc.)
 *
 * Returns kIOReturnSuccess or kIOReturnNoSpace.
 */
IOReturn io_registry_entry_attach_to_parent(struct io_registry_entry *entry,
                                            struct io_registry_entry *parent,
                                            uint32_t plane);

/*
 * io_registry_entry_detach_from_parent - Remove entry from parent in plane.
 */
IOReturn io_registry_entry_detach_from_parent(struct io_registry_entry *entry,
                                              struct io_registry_entry *parent,
                                              uint32_t plane);

/*
 * io_registry_entry_get_parent - Get parent in a plane.
 *
 * Returns parent entry or NULL.
 */
struct io_registry_entry *
io_registry_entry_get_parent(struct io_registry_entry *entry, uint32_t plane);

/*
 * io_registry_entry_get_child_count - Get number of children in a plane.
 */
uint32_t io_registry_entry_get_child_count(struct io_registry_entry *entry,
                                           uint32_t plane);

/*
 * io_registry_entry_get_child - Get child at index in a plane.
 */
struct io_registry_entry *
io_registry_entry_get_child(struct io_registry_entry *entry,
                            uint32_t plane, uint32_t index);

/* ============================================================================
 * Class Metadata
 * ============================================================================ */

extern const struct io_class_meta io_registry_entry_meta;

/* ============================================================================
 * Static Pool
 * ============================================================================ */

#define IO_REGISTRY_ENTRY_POOL_SIZE     256

/*
 * io_registry_entry_alloc - Allocate a registry entry from the static pool.
 *
 * Returns a zeroed entry with pool_allocated=true, or NULL if exhausted.
 */
struct io_registry_entry *io_registry_entry_alloc(void);

/*
 * io_registry_entry_free_to_pool - Return entry to pool.
 *
 * Called from the vtable free method when retain count hits zero.
 */
void io_registry_entry_free_to_pool(struct io_registry_entry *entry);

#endif /* _IOKIT_IO_REGISTRY_ENTRY_H */
