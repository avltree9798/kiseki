/*
 * Kiseki OS - IOKit Mach Message Handler
 *
 * Declares the IOKit kobject server function that intercepts Mach
 * messages destined for IOKit object ports.
 *
 * Reference: XNU osfmk/ipc/ipc_kobject.h
 */

#ifndef _IOKIT_IOKIT_MACH_H
#define _IOKIT_IOKIT_MACH_H

#include <kiseki/types.h>
#include <iokit/iokit_types.h>

/* Forward declarations */
struct ipc_port;
struct task;

/*
 * iokit_kobject_server - Handle an IOKit Mach message.
 *
 * Called from mach_msg_trap() when the destination port has a kobject_type
 * matching an IOKit type (IKOT_MASTER_DEVICE, IKOT_IOKIT_OBJECT, or
 * IKOT_IOKIT_CONNECT).
 *
 * This function processes the request synchronously and sends a reply
 * on the reply port via ipc_port_send_kernel().
 *
 * @dest_port:    Destination port (kobject port)
 * @user_msg:     Message data (already read from user buffer)
 * @send_size:    Message size in bytes
 * @reply_port:   Reply port (kernel object, may be NULL)
 * @reply_type:   Post-copyin type for reply port
 * @caller_task:  The calling task
 *
 * Returns true if the message was handled (caller should NOT queue it).
 * Returns false if the message should be queued normally.
 */
bool iokit_kobject_server(struct ipc_port *dest_port,
                          const void *user_msg,
                          uint32_t send_size,
                          struct ipc_port *reply_port,
                          uint32_t reply_type,
                          struct task *caller_task);

#endif /* _IOKIT_IOKIT_MACH_H */
