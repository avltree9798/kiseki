/*
 * Kiseki OS - IOKit User Client
 *
 * IOUserClient provides the userland-facing interface to IOKit services.
 * When a user process calls IOServiceOpen(), the target service's
 * newUserClient() creates an io_user_client that handles:
 *   - External method dispatch (IOConnectCallMethod)
 *   - Memory mapping (IOConnectMapMemory)
 *   - Notification delivery
 *
 * Inherits: io_object -> io_registry_entry -> io_service -> io_user_client
 *
 * Reference: XNU iokit/Kernel/IOUserClient.cpp
 */

#ifndef _IOKIT_IO_USER_CLIENT_H
#define _IOKIT_IO_USER_CLIENT_H

#include <iokit/io_service.h>
#include <iokit/io_memory_descriptor.h>

/* Maximum external methods per user client */
#define IO_USER_CLIENT_MAX_METHODS  32

/* Maximum memory mappings per user client */
#define IO_USER_CLIENT_MAX_MAPPINGS 16

/* ============================================================================
 * IOExternalMethodArguments
 *
 * Passed to external method dispatch functions. Contains scalar and
 * structure input/output parameters.
 *
 * Reference: XNU IOKit/IOUserClient.h (IOExternalMethodArguments)
 * ============================================================================ */

struct io_external_method_args {
    /* Scalar input */
    const uint64_t      *scalarInput;
    uint32_t            scalarInputCount;

    /* Structure input (raw bytes) */
    const void          *structureInput;
    uint32_t            structureInputSize;

    /* Scalar output */
    uint64_t            *scalarOutput;
    uint32_t            scalarOutputCount;

    /* Structure output (raw bytes) */
    void                *structureOutput;
    uint32_t            structureOutputSize;
};

/* ============================================================================
 * IOExternalMethodDispatch
 *
 * Describes one external method: its function pointer, and the expected
 * counts of scalar/structure input/output parameters.
 *
 * Reference: XNU IOKit/IOUserClient.h (IOExternalMethodDispatch)
 * ============================================================================ */

typedef IOReturn (*io_external_method_fn)(struct io_user_client *client,
                                          void *reference,
                                          struct io_external_method_args *args);

struct io_external_method_dispatch {
    io_external_method_fn   function;
    uint32_t                checkScalarInputCount;
    uint32_t                checkStructureInputSize;
    uint32_t                checkScalarOutputCount;
    uint32_t                checkStructureOutputSize;
};

/* ============================================================================
 * io_user_client_vtable
 *
 * Extends io_service_vtable with user client-specific methods.
 * ============================================================================ */

struct io_user_client_vtable {
    /* Parent vtable (must be first) */
    struct io_service_vtable    base;

    /*
     * externalMethod - Dispatch an external method call.
     *
     * @client:     This user client
     * @selector:   Method index
     * @args:       Input/output arguments
     *
     * Returns kIOReturnSuccess or error.
     *
     * Reference: XNU IOUserClient::externalMethod()
     */
    IOReturn (*externalMethod)(struct io_user_client *client,
                               uint32_t selector,
                               struct io_external_method_args *args);

    /*
     * clientMemoryForType - Get a memory descriptor for client mapping.
     *
     * Called by IOConnectMapMemory. The user client returns an
     * io_memory_descriptor for the requested memory type.
     *
     * @client:     This user client
     * @type:       Memory type (driver-defined, 0 = framebuffer, etc.)
     * @options:    Mapping options
     * @memory_out: On success, the memory descriptor
     *
     * Returns kIOReturnSuccess or error.
     *
     * Reference: XNU IOUserClient::clientMemoryForType()
     */
    IOReturn (*clientMemoryForType)(struct io_user_client *client,
                                    uint32_t type,
                                    IOOptionBits *options,
                                    struct io_memory_descriptor **memory_out);

    /*
     * clientClose - Called when the user client connection is closed.
     *
     * Reference: XNU IOUserClient::clientClose()
     */
    IOReturn (*clientClose)(struct io_user_client *client);
};

/* ============================================================================
 * io_user_client - User client connection object
 *
 * Reference: XNU IOUserClient
 * ============================================================================ */

struct io_user_client {
    /* Base service (MUST be first for upcast chain) */
    struct io_service       service;

    /* Owning task (the process that opened this connection) */
    struct task             *owning_task;

    /* The service this user client is connected to */
    struct io_service       *owner_service;

    /* External method dispatch table */
    const struct io_external_method_dispatch *dispatch_table;
    uint32_t                dispatch_table_count;

    /* Active memory mappings */
    struct io_memory_map    *mappings[IO_USER_CLIENT_MAX_MAPPINGS];
    uint32_t                mapping_count;

    /* Mach port for this connection (userland io_connect_t) */
    struct ipc_port         *connect_port;

    /* Connection type (passed by IOServiceOpen) */
    uint32_t                connect_type;

    /* Pool tracking */
    bool                    uc_pool_allocated;
    uint32_t                uc_pool_index;
};

/* ============================================================================
 * io_user_client API
 * ============================================================================ */

/*
 * io_user_client_init - Initialise a user client.
 *
 * @client:        User client to initialise
 * @vtable:        Vtable for concrete user client class
 * @meta:          Class metadata
 * @owner_service: The service this client connects to
 * @owning_task:   The task that opened the connection
 * @type:          Connection type
 *
 * Returns kIOReturnSuccess.
 */
IOReturn io_user_client_init(struct io_user_client *client,
                             const struct io_user_client_vtable *vtable,
                             const struct io_class_meta *meta,
                             struct io_service *owner_service,
                             struct task *owning_task,
                             uint32_t type);

/*
 * io_user_client_set_dispatch_table - Set the external method dispatch table.
 */
void io_user_client_set_dispatch_table(
    struct io_user_client *client,
    const struct io_external_method_dispatch *table,
    uint32_t count);

/*
 * io_user_client_call_method - Dispatch an external method.
 *
 * Validates argument counts against the dispatch table entry,
 * then calls the method function.
 *
 * Reference: XNU IOUserClient::externalMethod()
 */
IOReturn io_user_client_call_method(struct io_user_client *client,
                                    uint32_t selector,
                                    struct io_external_method_args *args);

/*
 * io_user_client_map_memory - Map memory into the owning task.
 *
 * Calls clientMemoryForType() on the user client to get a descriptor,
 * then maps it into the owning task.
 *
 * @client:     User client
 * @type:       Memory type (driver-defined)
 * @options:    Mapping options
 * @address:    Out — virtual address in owning task
 * @size:       Out — mapped size
 *
 * Returns kIOReturnSuccess or error.
 *
 * Reference: XNU is_io_connect_map_memory_into_task()
 */
IOReturn io_user_client_map_memory(struct io_user_client *client,
                                   uint32_t type,
                                   IOOptionBits options,
                                   uint64_t *address,
                                   uint64_t *size);

/*
 * io_user_client_close - Close the user client connection.
 *
 * Unmaps all mappings, calls clientClose(), and releases resources.
 */
IOReturn io_user_client_close(struct io_user_client *client);

/* ============================================================================
 * Class Metadata
 * ============================================================================ */

extern const struct io_class_meta io_user_client_meta;

/* ============================================================================
 * Static Pool
 * ============================================================================ */

#define IO_USER_CLIENT_POOL_SIZE    64

struct io_user_client *io_user_client_alloc(void);
void io_user_client_free_to_pool(struct io_user_client *client);

#endif /* _IOKIT_IO_USER_CLIENT_H */
