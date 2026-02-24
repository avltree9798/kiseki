/*
 * Kiseki OS - IOKit Client Library (IOKitLib)
 *
 * Public API for userland programs to interact with IOKit services.
 * Mirrors macOS IOKit.framework/Headers/IOKitLib.h.
 *
 * Usage:
 *   #include <IOKit/IOKitLib.h>
 *
 * Example (open IOFramebuffer and map VRAM):
 *   io_service_t fb = IOServiceGetMatchingService(
 *       kIOMasterPortDefault,
 *       IOServiceMatching("IOFramebuffer"));
 *   io_connect_t conn;
 *   IOServiceOpen(fb, mach_task_self(), 0, &conn);
 *   mach_vm_address_t addr;
 *   mach_vm_size_t size;
 *   IOConnectMapMemory64(conn, 0, mach_task_self(),
 *       &addr, &size, kIOMapAnywhere);
 *
 * Reference: XNU IOKitUser/IOKitLib.h
 */

#ifndef _IOKIT_IOKITLIB_H
#define _IOKIT_IOKITLIB_H

#include <IOKit/IOTypes.h>
#include <IOKit/IOReturn.h>
#include <mach/mach.h>

/* ============================================================================
 * IOKit Master Port
 *
 * kIOMasterPortDefault can be passed to functions that take a master port.
 * On macOS, passing 0 means "use the default master port".
 * ============================================================================ */

#define kIOMasterPortDefault    0

/* ============================================================================
 * IOFramebuffer External Method Selectors
 *
 * These selectors are used with IOConnectCallMethod/IOConnectCallScalarMethod
 * on an IOFramebuffer user client connection.
 * ============================================================================ */

#define kIOFBMethodGetInfo          0   /* Get fb info: 5 scalar outputs */
#define kIOFBMethodFlushRect        1   /* Flush rect: 4 scalar inputs */
#define kIOFBMethodFlushAll         2   /* Flush all: no args */
#define kIOFBMethodCount            3

/* IOFramebuffer memory types (for IOConnectMapMemory) */
#define kIOFBMemoryTypeVRAM         0   /* Framebuffer VRAM */

/* ============================================================================
 * IOMasterPort
 *
 * Obtains the IOKit master device port. This port is used to look up
 * IOKit services.
 *
 * @bootstrapPort  Bootstrap port (pass 0 for default)
 * @masterPort     Output: receives the master port
 * @return         kIOReturnSuccess on success
 * ============================================================================ */

kern_return_t IOMasterPort(
    mach_port_t         bootstrapPort,
    mach_port_t         *masterPort);

/* ============================================================================
 * IOServiceMatching
 *
 * Creates a matching dictionary for an IOService class name.
 * The returned value is passed to IOServiceGetMatchingService().
 *
 * On macOS this returns a CFMutableDictionaryRef. Here it returns the
 * class name string directly (no CoreFoundation dependency).
 *
 * The returned pointer is consumed by IOServiceGetMatchingService
 * (no deallocation needed).
 *
 * @name    IOService class name (e.g. "IOFramebuffer")
 * @return  Opaque matching dictionary (class name pointer)
 * ============================================================================ */

void *IOServiceMatching(const char *name);

/* ============================================================================
 * IOServiceGetMatchingService
 *
 * Looks up a single IOService matching the given dictionary. If multiple
 * services match, the first one found is returned.
 *
 * @masterPort  IOKit master port (or kIOMasterPortDefault)
 * @matching    Matching dictionary (from IOServiceMatching)
 * @return      Service port, or IO_OBJECT_NULL if not found
 * ============================================================================ */

io_service_t IOServiceGetMatchingService(
    mach_port_t         masterPort,
    void                *matching);

/* ============================================================================
 * IOServiceOpen
 *
 * Opens a connection to an IOService, creating a user client.
 *
 * @service     The IOService to connect to
 * @owningTask  The task requesting the connection (mach_task_self())
 * @type        Connection type (driver-specific, usually 0)
 * @connect     Output: receives the connection handle
 * @return      kIOReturnSuccess on success
 * ============================================================================ */

kern_return_t IOServiceOpen(
    io_service_t        service,
    task_port_t         owningTask,
    unsigned int        type,
    io_connect_t        *connect);

/* ============================================================================
 * IOServiceClose
 *
 * Closes a connection to an IOService.
 *
 * @connect     The connection to close
 * @return      kIOReturnSuccess on success
 * ============================================================================ */

kern_return_t IOServiceClose(
    io_connect_t        connect);

/* ============================================================================
 * IOConnectCallMethod
 *
 * Calls an external method on a user client connection.
 *
 * @connect              User client connection
 * @selector             Method selector (driver-defined)
 * @input                Scalar input array (uint64_t[])
 * @inputCnt             Number of scalar inputs
 * @inputStruct          Structure input buffer
 * @inputStructCnt       Size of structure input
 * @output               Scalar output array (uint64_t[])
 * @outputCnt            In: max outputs, Out: actual count
 * @outputStruct         Structure output buffer
 * @outputStructCnt      In: max size, Out: actual size
 * @return               kIOReturnSuccess on success
 * ============================================================================ */

kern_return_t IOConnectCallMethod(
    io_connect_t        connect,
    unsigned int        selector,
    const uint64_t      *input,
    unsigned int        inputCnt,
    const void          *inputStruct,
    size_t              inputStructCnt,
    uint64_t            *output,
    unsigned int        *outputCnt,
    void                *outputStruct,
    size_t              *outputStructCnt);

/* ============================================================================
 * IOConnectCallScalarMethod
 *
 * Convenience wrapper for scalar-only IOConnectCallMethod.
 * ============================================================================ */

kern_return_t IOConnectCallScalarMethod(
    io_connect_t        connect,
    unsigned int        selector,
    const uint64_t      *input,
    unsigned int        inputCnt,
    uint64_t            *output,
    unsigned int        *outputCnt);

/* ============================================================================
 * IOConnectCallStructMethod
 *
 * Convenience wrapper for structure-only IOConnectCallMethod.
 * ============================================================================ */

kern_return_t IOConnectCallStructMethod(
    io_connect_t        connect,
    unsigned int        selector,
    const void          *inputStruct,
    size_t              inputStructCnt,
    void                *outputStruct,
    size_t              *outputStructCnt);

/* ============================================================================
 * IOConnectMapMemory64 / IOConnectMapMemory
 *
 * Maps a memory region from a user client into the calling task.
 *
 * @connect      User client connection
 * @memoryType   Driver-defined memory type (e.g. kIOFBMemoryTypeVRAM)
 * @intoTask     Task to map into (mach_task_self())
 * @address      In/Out: address (0 to let kernel choose)
 * @size         Out: mapped region size
 * @options      Mapping options (kIOMapAnywhere, cache modes)
 * @return       kIOReturnSuccess on success
 * ============================================================================ */

kern_return_t IOConnectMapMemory64(
    io_connect_t            connect,
    unsigned int            memoryType,
    task_port_t             intoTask,
    mach_vm_address_t       *address,
    mach_vm_size_t          *size,
    IOOptionBits            options);

kern_return_t IOConnectMapMemory(
    io_connect_t            connect,
    unsigned int            memoryType,
    task_port_t             intoTask,
    mach_vm_address_t       *address,
    mach_vm_size_t          *size,
    IOOptionBits            options);

/* ============================================================================
 * IORegistryEntryGetProperty
 *
 * Gets a property value from an IOService registry entry.
 *
 * @entry       Service port (io_registry_entry_t)
 * @key         Property key string
 * @value       Output buffer for value data
 * @valueSize   In: buffer size, Out: actual value size
 * @return      kIOReturnSuccess on success
 * ============================================================================ */

kern_return_t IORegistryEntryGetProperty(
    io_registry_entry_t     entry,
    const char              *key,
    void                    *value,
    unsigned int            *valueSize);

/* ============================================================================
 * IOObjectRelease
 *
 * Releases (deallocates the send right to) an IOKit object.
 *
 * @object      The IOKit object to release
 * @return      kIOReturnSuccess on success
 * ============================================================================ */

kern_return_t IOObjectRelease(
    io_object_t             object);

#endif /* _IOKIT_IOKITLIB_H */
