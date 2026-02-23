/*
 * Kiseki OS - Userland bootstrap.h
 *
 * Bootstrap server interface for Mach service registration and lookup.
 * On macOS, these are MIG-generated stubs that send messages to launchd's
 * bootstrap port. On Kiseki, they invoke kernel traps that manage a
 * kernel-side service name registry.
 *
 * The API is identical to macOS: programs use bootstrap_look_up() to
 * find system services by name, and daemons use bootstrap_register()
 * to advertise their service ports.
 *
 * Reference: bootstrap.h from launchd/liblaunch
 */

#ifndef _MACH_BOOTSTRAP_H_
#define _MACH_BOOTSTRAP_H_

#include <mach/port.h>
#include <mach/kern_return.h>

/* Bootstrap return codes (compatible with macOS bootstrap.h) */
#define BOOTSTRAP_SUCCESS               0
#define BOOTSTRAP_NOT_PRIVILEGED        1100
#define BOOTSTRAP_NAME_IN_USE           1101
#define BOOTSTRAP_UNKNOWN_SERVICE       1102
#define BOOTSTRAP_SERVICE_ACTIVE        1103
#define BOOTSTRAP_BAD_COUNT             1104
#define BOOTSTRAP_NO_MEMORY             1105

/* Maximum service name length */
#define BOOTSTRAP_MAX_NAME_LEN          128

/*
 * bootstrap_register - Register a service port under a name
 *
 * @bp:           Bootstrap port (ignored on Kiseki, use MACH_PORT_NULL)
 * @service_name: Name to register (e.g., "uk.co.avltree9798.mDNSResponder")
 * @sp:           Port name (in caller's IPC space) to register as service
 *
 * Returns KERN_SUCCESS or error.
 */
extern kern_return_t bootstrap_register(
    mach_port_t         bp,
    const char          *service_name,
    mach_port_t         sp);

/*
 * bootstrap_look_up - Look up a service port by name
 *
 * @bp:           Bootstrap port (ignored on Kiseki, use MACH_PORT_NULL)
 * @service_name: Name to look up (e.g., "uk.co.avltree9798.mDNSResponder")
 * @sp:           Out: receives a send right to the service port
 *
 * Returns KERN_SUCCESS or BOOTSTRAP_UNKNOWN_SERVICE.
 */
extern kern_return_t bootstrap_look_up(
    mach_port_t         bp,
    const char          *service_name,
    mach_port_t         *sp);

/*
 * bootstrap_check_in - Daemon claims a pre-registered service port
 *
 * On macOS, launchd pre-creates service ports declared in the daemon's
 * launchd plist before the daemon process starts. The daemon calls
 * bootstrap_check_in() to receive the receive right for its service port.
 *
 * This eliminates race conditions: the port exists in the bootstrap
 * namespace before the daemon is running, so clients can look_up()
 * immediately.
 *
 * @bp:           Bootstrap port (ignored on Kiseki, use MACH_PORT_NULL)
 * @service_name: Name of service to check in to
 * @sp:           Out: receives port name with RECEIVE + SEND rights
 *
 * Returns KERN_SUCCESS or error.
 * Returns KERN_NOT_RECEIVER if another task already claimed this service.
 */
extern kern_return_t bootstrap_check_in(
    mach_port_t         bp,
    const char          *service_name,
    mach_port_t         *sp);

#endif /* _MACH_BOOTSTRAP_H_ */
