/*
 * Kiseki OS - IOKit Registry (Global)
 *
 * The I/O Registry is a dynamic database of IOKit objects forming a tree
 * structure. It is organised into planes (IOService, IODeviceTree, IOPower)
 * where each plane provides a different view of the same set of objects.
 *
 * This file defines the global registry singleton and its API.
 *
 * Reference: XNU iokit/Kernel/IORegistryEntry.cpp (gRegistryRoot),
 *            iokit/IOKit/IORegistryEntry.h
 */

#ifndef _IOKIT_IO_REGISTRY_H
#define _IOKIT_IO_REGISTRY_H

#include <iokit/io_registry_entry.h>

/* Forward declaration */
struct ipc_port;

/* ============================================================================
 * IOKit Driver Personality
 *
 * A personality is a dictionary of matching properties that describes
 * when a driver should be loaded/instantiated. Equivalent to the
 * IOKitPersonalities dictionary in an Info.plist on macOS.
 *
 * On XNU, personalities are stored in IOCatalogue (an OSDictionary array).
 * We use a flat struct array.
 *
 * Reference: XNU iokit/Kernel/IOCatalogue.cpp
 * ============================================================================ */

#define IO_CATALOGUE_MAX_PERSONALITIES  64

/*
 * io_driver_personality - Static driver matching entry
 *
 * Fields:
 *   class_name:      IOClass — the driver class to instantiate
 *   provider_class:  IOProviderClass — what the driver attaches to
 *   probe_score:     IOProbeScore — higher wins
 *   match_category:  IOMatchCategory — for multi-driver matching
 *   properties:      Additional matching properties
 *   init_fn:         Function to create/initialise the driver instance
 *   active:          Slot is in use
 */

/* Forward declaration for init function */
struct io_service;

typedef struct io_service *(*io_driver_init_fn)(struct io_service *provider);

struct io_driver_personality {
    bool                    active;
    char                    class_name[IO_REGISTRY_NAME_MAX];
    char                    provider_class[IO_REGISTRY_NAME_MAX];
    int32_t                 probe_score;
    char                    match_category[IO_REGISTRY_NAME_MAX];
    struct io_prop_table    match_properties;
    io_driver_init_fn       init_fn;        /* Creates and returns the driver */
};

/* ============================================================================
 * io_registry - Global I/O Registry Singleton
 *
 * Contains:
 *   - Root registry entry (parent of all top-level entries)
 *   - Driver catalogue (array of personalities)
 *   - Entry and service pools
 *   - Registry lock
 *
 * Reference: XNU iokit/Kernel/IORegistryEntry.cpp (gRegistryRoot)
 * ============================================================================ */

struct io_registry {
    /* Root of the IOService plane — "IOResources" equivalent */
    struct io_registry_entry    *root;

    /* Driver catalogue — static array of personalities */
    struct io_driver_personality catalogue[IO_CATALOGUE_MAX_PERSONALITIES];
    uint32_t                    catalogue_count;

    /* Global registry lock */
    mutex_t                     lock;

    /* Monotonic entry ID counter */
    uint32_t                    next_entry_id;

    /* Initialised flag */
    bool                        initialised;

    /* IOKit master port (IKOT_MASTER_DEVICE) — registered in bootstrap */
    struct ipc_port             *master_port;
};

/* Global registry singleton */
extern struct io_registry g_io_registry;

/* ============================================================================
 * Registry API
 * ============================================================================ */

/*
 * io_registry_init - Initialise the global I/O Registry.
 *
 * Creates the root entry ("IOResources"), initialises the catalogue
 * and pools. Must be called once during boot, after ipc_init().
 *
 * Reference: XNU IORegistryEntry::initialize()
 */
void io_registry_init(void);

/*
 * io_registry_get_root - Get the root registry entry.
 *
 * Reference: XNU IORegistryEntry::getRegistryRoot()
 */
struct io_registry_entry *io_registry_get_root(void);

/*
 * io_registry_assign_entry_id - Assign a unique entry ID.
 *
 * Called during io_registry_entry_init().
 */
uint32_t io_registry_assign_entry_id(void);

/* ============================================================================
 * Catalogue API
 *
 * Reference: XNU iokit/Kernel/IOCatalogue.cpp
 * ============================================================================ */

/*
 * io_catalogue_add_personality - Register a driver personality.
 *
 * @class_name:     IOClass name
 * @provider_class: IOProviderClass to match against
 * @probe_score:    Matching priority (higher = preferred)
 * @match_category: Category string (or NULL)
 * @match_props:    Additional property matching criteria (or NULL)
 * @init_fn:        Driver initialisation function
 *
 * Returns kIOReturnSuccess or kIOReturnNoSpace.
 */
IOReturn io_catalogue_add_personality(const char *class_name,
                                      const char *provider_class,
                                      int32_t probe_score,
                                      const char *match_category,
                                      const struct io_prop_table *match_props,
                                      io_driver_init_fn init_fn);

/*
 * io_catalogue_find_drivers_for_service - Find matching driver personalities
 *                                          for a given provider service.
 *
 * Implements the XNU matching algorithm:
 *   1. Filter by IOProviderClass (must match provider's class name)
 *   2. Filter by IONameMatch (if present, must match provider's name)
 *   3. Filter by IOPropertyMatch (all match properties must exist in provider)
 *   4. Sort by IOProbeScore (descending)
 *   5. Group by IOMatchCategory — only highest-scoring per category wins
 *
 * @provider:     The service seeking drivers
 * @out_matches:  Array to fill with matching personalities
 * @max_matches:  Size of out_matches array
 *
 * Returns the number of matches found.
 *
 * Reference: XNU IOService::probeCandidates()
 */
uint32_t io_catalogue_find_drivers_for_service(
    struct io_service *provider,
    struct io_driver_personality **out_matches,
    uint32_t max_matches);

/*
 * io_catalogue_start_matching - Trigger matching for a newly registered
 *                                service.
 *
 * Finds all matching driver personalities, instantiates the best match
 * per category, calls probe() then start() on each.
 *
 * Reference: XNU IOService::doServiceMatch()
 *
 * @service: The newly registered service to match against.
 *
 * Returns kIOReturnSuccess or error.
 */
IOReturn io_catalogue_start_matching(struct io_service *service);

/* ============================================================================
 * IOKit Subsystem Init
 *
 * Called from kernel main.c during boot.
 * ============================================================================ */

/*
 * iokit_init - Initialise the entire IOKit subsystem.
 *
 * Calls io_registry_init(), sets up the IOKit master port in the
 * bootstrap namespace, and registers built-in driver personalities.
 */
void iokit_init(void);

#endif /* _IOKIT_IO_REGISTRY_H */
