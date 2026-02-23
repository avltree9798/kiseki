/*
 * Kiseki OS - Userland Mach mach_port.h
 *
 * Port manipulation function prototypes.
 * On XNU this is MIG-generated from mach_port.defs.
 * We provide the prototypes directly.
 *
 * Reference: MIG-generated mach/mach_port.h
 */

#ifndef _MACH_MACH_PORT_H_
#define _MACH_MACH_PORT_H_

#include <mach/port.h>
#include <mach/kern_return.h>
#include <mach/message.h>

/* ============================================================================
 * Port Allocation and Deallocation
 * ============================================================================ */

/*
 * mach_port_allocate - Allocate a new port with the given right
 *
 * @task:  Target task (should be mach_task_self())
 * @right: Type of right (MACH_PORT_RIGHT_RECEIVE, etc.)
 * @name:  Out parameter: receives the new port name
 *
 * Returns KERN_SUCCESS or error.
 */
extern kern_return_t mach_port_allocate(
    mach_port_t         task,
    mach_port_right_t   right,
    mach_port_t         *name);

/*
 * mach_port_deallocate - Release a send right on a port
 *
 * @task: Target task (should be mach_task_self())
 * @name: Port name to deallocate
 *
 * Returns KERN_SUCCESS or error.
 */
extern kern_return_t mach_port_deallocate(
    mach_port_t         task,
    mach_port_name_t    name);

/*
 * mach_port_insert_right - Insert a port right into a task
 *
 * @task:        Target task
 * @name:        Port name in target task
 * @poly:        Port right to insert
 * @polyPoly:    Type of right (MACH_MSG_TYPE_MAKE_SEND, etc.)
 *
 * Returns KERN_SUCCESS or error.
 */
extern kern_return_t mach_port_insert_right(
    mach_port_t             task,
    mach_port_name_t        name,
    mach_port_t             poly,
    mach_msg_type_name_t    polyPoly);

/*
 * mach_port_mod_refs - Modify the user reference count for a port right
 *
 * @task:  Target task
 * @name:  Port name
 * @right: Right type
 * @delta: Amount to change reference count
 *
 * Returns KERN_SUCCESS or error.
 */
extern kern_return_t mach_port_mod_refs(
    mach_port_t         task,
    mach_port_name_t    name,
    mach_port_right_t   right,
    mach_port_delta_t   delta);

#endif /* _MACH_MACH_PORT_H_ */
