/*
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Kiseki OS - Userland Mach mach_types.h
 *
 * XNU-compatible Mach type definitions for userland.
 * In userland, all kernel object types (task_t, thread_t, etc.)
 * are represented as mach_port_t - opaque port names.
 *
 * Reference: osfmk/mach/mach_types.h
 */

#ifndef _MACH_MACH_TYPES_H_
#define _MACH_MACH_TYPES_H_

#include <mach/port.h>
#include <mach/message.h>

/* ============================================================================
 * Kernel Object Types (Userland View)
 *
 * In userland, all Mach kernel objects are referenced by mach_port_t.
 * The actual kernel object lives in kernel space; userland only holds
 * port names (send/receive rights).
 * ============================================================================ */

typedef mach_port_t     task_t;
typedef mach_port_t     task_name_t;
typedef mach_port_t     task_inspect_t;
typedef mach_port_t     task_read_t;
typedef mach_port_t     task_suspension_token_t;
typedef mach_port_t     thread_t;
typedef mach_port_t     thread_act_t;
typedef mach_port_t     thread_inspect_t;
typedef mach_port_t     thread_read_t;
typedef mach_port_t     ipc_space_t;
typedef mach_port_t     ipc_space_read_t;
typedef mach_port_t     ipc_space_inspect_t;
typedef mach_port_t     host_t;
typedef mach_port_t     host_priv_t;
typedef mach_port_t     host_security_t;
typedef mach_port_t     processor_t;
typedef mach_port_t     processor_set_t;
typedef mach_port_t     processor_set_control_t;
typedef mach_port_t     processor_set_name_t;
typedef mach_port_t     semaphore_t;
typedef mach_port_t     lock_set_t;
typedef mach_port_t     ledger_t;
typedef mach_port_t     alarm_t;
typedef mach_port_t     clock_serv_t;
typedef mach_port_t     clock_ctrl_t;
typedef mach_port_t     clock_reply_t;
typedef mach_port_t     bootstrap_t;
typedef mach_port_t     mem_entry_name_port_t;
typedef mach_port_t     exception_handler_t;
typedef mach_port_t     vm_task_entry_t;
typedef mach_port_t     mach_eventlink_t;

/* Null values for kernel object types */
#define TASK_NULL               ((task_t) 0)
#define TASK_NAME_NULL          ((task_name_t) 0)
#define THREAD_NULL             ((thread_t) 0)
#define HOST_NULL               ((host_t) 0)
#define HOST_PRIV_NULL          ((host_priv_t) 0)
#define HOST_SECURITY_NULL      ((host_security_t) 0)
#define PROCESSOR_SET_NULL      ((processor_set_t) 0)
#define PROCESSOR_NULL          ((processor_t) 0)
#define SEMAPHORE_NULL          ((semaphore_t) 0)
#define LOCK_SET_NULL           ((lock_set_t) 0)
#define LEDGER_NULL             ((ledger_t) 0)
#define ALARM_NULL              ((alarm_t) 0)
#define CLOCK_NULL              ((clock_serv_t) 0)

/* Task/Thread flavors */
#define TASK_FLAVOR_CONTROL     0
#define TASK_FLAVOR_READ        1
#define TASK_FLAVOR_INSPECT     2
#define TASK_FLAVOR_NAME        3

#define THREAD_FLAVOR_CONTROL   0
#define THREAD_FLAVOR_READ      1
#define THREAD_FLAVOR_INSPECT   2

/* Array types */
typedef task_t          *task_array_t;
typedef thread_t        *thread_array_t;
typedef processor_set_t *processor_set_array_t;
typedef processor_t     *processor_array_t;
typedef ledger_t        *ledger_array_t;

/* Legacy compatibility aliases */
typedef task_t          task_port_t;
typedef thread_t        thread_port_t;

/* Natural_t-based types */
typedef natural_t       ledger_item_t;      /* Deprecated */

#endif /* _MACH_MACH_TYPES_H_ */
