/*
 * Kiseki OS - IOKit Service (io_service)
 *
 * IOService is the base class for all IOKit drivers. It provides:
 *   - Driver lifecycle: init, probe, start, stop, free
 *   - Provider/client relationships
 *   - Service state tracking (registered, matched, inactive)
 *   - Busy state for synchronisation
 *   - Integration with the I/O Registry and matching system
 *
 * Inherits from io_registry_entry (first field).
 *
 * Reference: XNU iokit/Kernel/IOService.cpp, iokit/IOKit/IOService.h
 */

#ifndef _IOKIT_IO_SERVICE_H
#define _IOKIT_IO_SERVICE_H

#include <iokit/io_registry_entry.h>

/* Forward declarations */
struct task;
struct io_user_client;

/* Maximum client (child driver) count per service */
#define IO_SERVICE_MAX_CLIENTS      16

/* ============================================================================
 * io_service_vtable - Virtual methods for IOService
 *
 * Extends io_registry_entry_vtable. Each driver subclass provides its
 * own vtable with overrides for probe(), start(), stop(), etc.
 *
 * Reference: XNU IOService virtual methods
 * ============================================================================ */

struct io_service_vtable {
    /* Parent vtable (must be first) */
    struct io_registry_entry_vtable     base;

    /*
     * probe - Check if this driver can drive the given provider.
     *
     * Called after matching but before start(). The driver examines
     * the provider's properties and hardware to determine compatibility.
     * Returns a probe score (>= 0 to accept, < 0 to reject).
     *
     * @service:  The driver being probed
     * @provider: The provider service
     * @score:    In/out — initial score from personality, driver may adjust
     *
     * Returns the service if probe succeeds (score >= 0), NULL if rejected.
     *
     * Reference: XNU IOService::probe()
     */
    struct io_service *(*probe)(struct io_service *service,
                                struct io_service *provider,
                                int32_t *score);

    /*
     * start - Start the driver.
     *
     * Called after probe() succeeds. The driver should initialise hardware,
     * create user client ports, register sub-services, etc.
     *
     * Returns true if started successfully.
     *
     * Reference: XNU IOService::start()
     */
    bool (*start)(struct io_service *service, struct io_service *provider);

    /*
     * stop - Stop the driver.
     *
     * Called during termination. The driver should release hardware resources.
     *
     * Reference: XNU IOService::stop()
     */
    void (*stop)(struct io_service *service, struct io_service *provider);

    /*
     * getWorkLoop - Get the driver's work loop.
     *
     * Returns the IOWorkLoop for this driver, or NULL if none.
     * Default implementation returns the provider's work loop.
     *
     * Reference: XNU IOService::getWorkLoop()
     */
    struct io_work_loop *(*getWorkLoop)(struct io_service *service);

    /*
     * message - Receive a message from another IOKit object.
     *
     * Used for power management, termination, and custom messages.
     *
     * Reference: XNU IOService::message()
     */
    IOReturn (*message)(struct io_service *service, uint32_t type,
                        struct io_service *provider, void *argument);

    /*
     * newUserClient - Create a new user client connection.
     *
     * Called when userland opens a connection to this service via
     * IOServiceOpen(). The driver creates an io_user_client subclass.
     *
     * @service:    This service
     * @owning_task: The task opening the connection
     * @type:       Connection type (driver-defined)
     * @client_out: On success, the new user client
     *
     * Returns kIOReturnSuccess or error.
     *
     * Reference: XNU IOService::newUserClient()
     */
    IOReturn (*newUserClient)(struct io_service *service,
                              struct task *owning_task,
                              uint32_t type,
                              struct io_user_client **client_out);
};

/* ============================================================================
 * io_service - IOKit service/driver object
 *
 * First field is io_registry_entry for inheritance chain:
 *   io_object -> io_registry_entry -> io_service
 *
 * Reference: XNU IOService (iokit/Kernel/IOService.cpp)
 * ============================================================================ */

struct io_service {
    /* Base registry entry (MUST be first for upcast) */
    struct io_registry_entry    entry;

    /* Provider (the service this driver attached to) */
    struct io_service           *provider;

    /* Clients (child drivers attached to this service) */
    struct io_service           *clients[IO_SERVICE_MAX_CLIENTS];
    uint32_t                    client_count;

    /* Service state (bitmask of kIOService*State) */
    uint32_t                    state[2];

    /* Busy count — incremented during matching, decremented when done */
    int32_t                     busy_count;

    /* Work loop for this driver (may be NULL) */
    struct io_work_loop         *work_loop;

    /* Mach port for this service (for userland IOKit access) */
    struct ipc_port             *service_port;

    /* Pool tracking */
    bool                        service_pool_allocated;
    uint32_t                    service_pool_index;
};

/* ============================================================================
 * io_service API
 * ============================================================================ */

/*
 * io_service_init - Initialise an io_service.
 *
 * @service:  Service to initialise
 * @vtable:   Vtable for the concrete driver class
 * @meta:     Class metadata
 * @name:     Service name
 *
 * Returns kIOReturnSuccess.
 */
IOReturn io_service_init(struct io_service *service,
                         const struct io_service_vtable *vtable,
                         const struct io_class_meta *meta,
                         const char *name);

/*
 * io_service_register - Register a service in the I/O Registry.
 *
 * Attaches the service to its provider in the IOService plane,
 * sets kIOServiceRegisteredState, and triggers matching.
 *
 * Reference: XNU IOService::registerService()
 */
IOReturn io_service_register(struct io_service *service);

/*
 * io_service_attach - Attach a client (child driver) to this service.
 *
 * Reference: XNU IOService::attach()
 */
IOReturn io_service_attach(struct io_service *client,
                           struct io_service *provider);

/*
 * io_service_detach - Detach a client from this service.
 *
 * Reference: XNU IOService::detach()
 */
IOReturn io_service_detach(struct io_service *client,
                           struct io_service *provider);

/*
 * io_service_terminate - Begin termination of a service.
 *
 * Sets kIOServiceInactiveState, calls stop() on the driver,
 * and detaches from the provider.
 *
 * Reference: XNU IOService::terminate()
 */
IOReturn io_service_terminate(struct io_service *service);

/*
 * io_service_get_provider - Get the provider of this service.
 */
struct io_service *io_service_get_provider(struct io_service *service);

/*
 * io_service_get_state - Get the service state bitmask.
 */
uint32_t io_service_get_state(struct io_service *service);

/*
 * io_service_adjust_busy - Adjust the busy count.
 *
 * Reference: XNU IOService::adjustBusy()
 */
void io_service_adjust_busy(struct io_service *service, int32_t delta);

/*
 * io_service_wait_quiet - Wait until busy count reaches zero.
 *
 * Reference: XNU IOService::waitQuiet()
 */
IOReturn io_service_wait_quiet(struct io_service *service);

/* ============================================================================
 * Service Matching (userland-initiated)
 *
 * These functions find services by matching dictionaries,
 * equivalent to IOServiceGetMatchingServices().
 * ============================================================================ */

/*
 * io_service_get_matching_service - Find the first service matching
 *                                    the given properties.
 *
 * Walks the IOService plane looking for a registered service whose
 * property table matches all entries in match_props.
 *
 * Reference: XNU IOService::copyMatchingService()
 */
struct io_service *
io_service_get_matching_service(const struct io_prop_table *match_props);

/*
 * io_service_get_matching_services - Find all matching services.
 *
 * @match_props:  Properties to match
 * @out_services: Array to fill
 * @max_services: Size of array
 *
 * Returns count of matches found.
 */
uint32_t io_service_get_matching_services(
    const struct io_prop_table *match_props,
    struct io_service **out_services,
    uint32_t max_services);

/* ============================================================================
 * Class Metadata
 * ============================================================================ */

extern const struct io_class_meta io_service_meta;

/* ============================================================================
 * Static Pool
 * ============================================================================ */

#define IO_SERVICE_POOL_SIZE    256

/*
 * io_service_alloc - Allocate a service from the static pool.
 */
struct io_service *io_service_alloc(void);

/*
 * io_service_free_to_pool - Return service to pool.
 */
void io_service_free_to_pool(struct io_service *service);

#endif /* _IOKIT_IO_SERVICE_H */
