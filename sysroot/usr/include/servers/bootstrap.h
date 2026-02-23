/*
 * Kiseki OS - <servers/bootstrap.h>
 *
 * Compatibility header matching macOS layout. On macOS, bootstrap_register,
 * bootstrap_look_up, and bootstrap_check_in are declared here. We simply
 * include the Mach bootstrap header which has the same declarations.
 */

#ifndef _SERVERS_BOOTSTRAP_H_
#define _SERVERS_BOOTSTRAP_H_

#include <mach/bootstrap.h>

#endif /* _SERVERS_BOOTSTRAP_H_ */
