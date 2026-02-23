/*
 * Kiseki OS - Mach IPC Types and Definitions
 *
 * XNU-compatible Mach message passing primitives.
 * Provides port-based IPC: send/receive messages between tasks.
 *
 * Reference: osfmk/mach/message.h, osfmk/mach/port.h
 */

#ifndef _MACH_IPC_H
#define _MACH_IPC_H

#include <kiseki/types.h>
#include <kern/sync.h>

/* ============================================================================
 * Mach Port Types
 * ============================================================================ */

typedef uint32_t    mach_port_name_t;
typedef uint32_t    mach_port_right_t;
typedef uint32_t    mach_port_type_t;
typedef uint32_t    mach_msg_bits_t;
typedef uint32_t    mach_msg_size_t;
typedef uint32_t    mach_msg_id_t;
typedef uint32_t    mach_msg_option_t;
typedef uint32_t    mach_msg_type_name_t;
typedef int32_t     mach_msg_timeout_t;

/* Null port name */
#define MACH_PORT_NULL          ((mach_port_name_t)0)
#define MACH_PORT_DEAD          ((mach_port_name_t)~0U)

/* Port rights */
#define MACH_PORT_RIGHT_SEND        0
#define MACH_PORT_RIGHT_RECEIVE     1
#define MACH_PORT_RIGHT_SEND_ONCE   2
#define MACH_PORT_RIGHT_PORT_SET    3
#define MACH_PORT_RIGHT_DEAD_NAME   4

/* Port right type bits (bitmask in port type field) */
#define MACH_PORT_TYPE_SEND         (1u << (MACH_PORT_RIGHT_SEND + 16))
#define MACH_PORT_TYPE_RECEIVE      (1u << (MACH_PORT_RIGHT_RECEIVE + 16))
#define MACH_PORT_TYPE_SEND_ONCE    (1u << (MACH_PORT_RIGHT_SEND_ONCE + 16))
#define MACH_PORT_TYPE_PORT_SET     (1u << (MACH_PORT_RIGHT_PORT_SET + 16))
#define MACH_PORT_TYPE_DEAD_NAME    (1u << (MACH_PORT_RIGHT_DEAD_NAME + 16))

/* ============================================================================
 * Mach Message Header
 * ============================================================================ */

/*
 * msgh_bits encoding:
 *   bits [7:0]   = remote type name (send disposition)
 *   bits [15:8]  = local type name (receive disposition)
 *   bit  [31]    = MACH_MSGH_BITS_COMPLEX
 */
#define MACH_MSGH_BITS_REMOTE_MASK      0x000000FFu
#define MACH_MSGH_BITS_LOCAL_MASK       0x0000FF00u
#define MACH_MSGH_BITS_COMPLEX          0x80000000u

#define MACH_MSGH_BITS(remote, local) \
    ((mach_msg_bits_t)((remote) | ((local) << 8)))

#define MACH_MSGH_BITS_REMOTE(bits) \
    ((mach_msg_type_name_t)((bits) & MACH_MSGH_BITS_REMOTE_MASK))

#define MACH_MSGH_BITS_LOCAL(bits) \
    ((mach_msg_type_name_t)(((bits) & MACH_MSGH_BITS_LOCAL_MASK) >> 8))

/* Message type names (disposition of port rights transferred in header) */
#define MACH_MSG_TYPE_MOVE_RECEIVE      16
#define MACH_MSG_TYPE_MOVE_SEND         17
#define MACH_MSG_TYPE_MOVE_SEND_ONCE    18
#define MACH_MSG_TYPE_COPY_SEND         19
#define MACH_MSG_TYPE_MAKE_SEND         20
#define MACH_MSG_TYPE_MAKE_SEND_ONCE    21
#define MACH_MSG_TYPE_PORT_SEND         MACH_MSG_TYPE_MOVE_SEND

/*
 * Post-copyin port type names.
 *
 * On XNU, after ipc_kmsg_copyin_header(), the msgh_bits fields are
 * converted from "action" dispositions (COPY_SEND, MAKE_SEND_ONCE, etc.)
 * to "state" types using ipc_object_copyin_type(). These describe what
 * kind of right the kernel is holding in the in-flight message.
 *
 * See osfmk/ipc/ipc_object.c:ipc_object_copyin_type()
 */
#define MACH_MSG_TYPE_PORT_RECEIVE      MACH_MSG_TYPE_MOVE_RECEIVE      /* 16 */
#define MACH_MSG_TYPE_PORT_SEND_ONCE    MACH_MSG_TYPE_MOVE_SEND_ONCE    /* 18 */
/* MACH_MSG_TYPE_PORT_SEND is same as MACH_MSG_TYPE_MOVE_SEND = 17 */
#define MACH_MSG_TYPE_PORT_NONE         0

/*
 * mach_msg_header_t - Fixed header at the start of every Mach message
 */
typedef struct {
    mach_msg_bits_t     msgh_bits;          /* Message flags + port dispositions */
    mach_msg_size_t     msgh_size;          /* Total message size in bytes */
    mach_port_name_t    msgh_remote_port;   /* Destination port */
    mach_port_name_t    msgh_local_port;    /* Reply port */
    uint32_t            msgh_voucher_port;  /* Voucher port (unused, for compat) */
    mach_msg_id_t       msgh_id;            /* Message ID (user-defined) */
} mach_msg_header_t;

/*
 * mach_msg_body_t - Follows header in complex messages
 */
typedef struct {
    uint32_t            msgh_descriptor_count;
} mach_msg_body_t;

/*
 * mach_msg_trailer_t - Appended to received messages
 */
#define MACH_MSG_TRAILER_FORMAT_0       0

typedef struct {
    uint32_t            msgh_trailer_type;
    uint32_t            msgh_trailer_size;
} mach_msg_trailer_t;

#define MACH_MSG_TRAILER_MINIMUM_SIZE   sizeof(mach_msg_trailer_t)

/* ============================================================================
 * Mach Message Options
 * ============================================================================ */

#define MACH_MSG_OPTION_NONE        0x00000000u
#define MACH_SEND_MSG               0x00000001u
#define MACH_RCV_MSG                0x00000002u
#define MACH_SEND_TIMEOUT           0x00000010u
#define MACH_RCV_TIMEOUT            0x00000100u
#define MACH_RCV_LARGE              0x00000004u
#define MACH_SEND_INTERRUPT         0x00000040u
#define MACH_RCV_INTERRUPT          0x00000400u

/* ============================================================================
 * Mach Message Return Codes
 * ============================================================================ */

#define MACH_MSG_SUCCESS                0x00000000
#define MACH_SEND_INVALID_DEST          0x10000002
#define MACH_SEND_INVALID_RIGHT         0x10000007
#define MACH_SEND_INVALID_HEADER        0x10000010
#define MACH_SEND_NO_BUFFER             0x10000013
#define MACH_SEND_MSG_TOO_SMALL         0x10000008
#define MACH_RCV_INVALID_NAME           0x10004002
#define MACH_RCV_TOO_LARGE              0x10004004
#define MACH_RCV_TIMED_OUT              0x10004003
#define MACH_RCV_PORT_DIED              0x10004005
#define MACH_RCV_INVALID_TYPE           0x1000400F

/* ============================================================================
 * Kernel Port Structures
 * ============================================================================ */

/* Maximum message size (inline, no OOL data) */
#define MACH_MSG_SIZE_MAX           4096

/* Message queue capacity per port */
#define PORT_MSG_QUEUE_SIZE         16

/* Maximum ports per task name space */
#define TASK_PORT_TABLE_SIZE        256

/*
 * ipc_msg - Queued message in a port's ring buffer
 *
 * On XNU, ipc_kmsg stores the message inline and port header fields
 * (msgh_remote_port, msgh_local_port) are overwritten with kernel
 * ipc_port pointers after copyin. We store the raw user message bytes
 * separately and carry the translated kernel port pointers alongside.
 *
 * reply_port:  Kernel port object for the sender's reply port.
 *              During copyin, the sender's msgh_local_port name is
 *              translated to this kernel object. During copyout, it
 *              is inserted into the receiver's IPC space with a
 *              send-once right, becoming the receiver's msgh_remote_port.
 *
 * reply_type:  Post-copyin type for the reply port (e.g. PORT_SEND_ONCE).
 *              Corresponds to XNU's MACH_MSGH_BITS_LOCAL after copyin.
 *
 * dest_type:   Post-copyin type for the destination port (e.g. PORT_SEND).
 *              Used during copyout to determine how to handle the
 *              destination right for the receiver.
 */
struct ipc_msg {
    uint32_t            size;           /* Total message size including header */
    struct ipc_port     *reply_port;    /* Translated reply port (kernel obj) */
    mach_msg_type_name_t reply_type;    /* Post-copyin type: PORT_SEND_ONCE etc */
    mach_msg_type_name_t dest_type;     /* Post-copyin type: PORT_SEND etc */
    uint8_t             data[MACH_MSG_SIZE_MAX];
};

/*
 * ipc_port - Kernel-internal port object
 *
 * Each port has a single receive right holder and potentially
 * many send rights. Messages are queued in a fixed-size ring buffer.
 */
struct ipc_port {
    bool                active;             /* Port is alive */
    uint32_t            refs;               /* Reference count */
    struct task         *receiver;          /* Task holding receive right */

    /* Message ring buffer */
    struct ipc_msg      queue[PORT_MSG_QUEUE_SIZE];
    uint32_t            queue_head;         /* Next slot to dequeue from */
    uint32_t            queue_tail;         /* Next slot to enqueue to */
    uint32_t            queue_count;        /* Messages currently queued */

    spinlock_t          lock;
    semaphore_t         msg_available;      /* Signaled when msg enqueued */
};

/*
 * ipc_port_entry - Entry in a task's port name table
 *
 * Maps a port name (index) to a kernel port object + rights held.
 */
struct ipc_port_entry {
    struct ipc_port     *port;              /* Kernel port object (or NULL) */
    mach_port_type_t    type;               /* Rights held on this name */
};

/*
 * ipc_space - Per-task port name space
 *
 * Maps mach_port_name_t -> ipc_port_entry.
 * Name 0 (MACH_PORT_NULL) is reserved.
 */
struct ipc_space {
    struct ipc_port_entry   table[TASK_PORT_TABLE_SIZE];
    uint32_t                next_name;      /* Hint for next free slot */
    spinlock_t              lock;
};

/* Port set: a set of ports that can be received on together */
struct ipc_port_set {
    mach_port_name_t    members[TASK_PORT_TABLE_SIZE];
    uint32_t            count;
    spinlock_t          lock;
};

/* ============================================================================
 * Mach IPC API (kernel-internal)
 * ============================================================================ */

/* Initialize the IPC subsystem */
void ipc_init(void);

/* Allocate a new kernel port object */
struct ipc_port *ipc_port_alloc(void);

/* Deallocate a kernel port object */
void ipc_port_dealloc(struct ipc_port *port);

/* Initialize a task's IPC space (used internally by ipc_space_create) */
void ipc_space_init(struct ipc_space *space);

/*
 * ipc_space_create - Allocate a new per-task IPC space from pool
 *
 * On XNU, called from task_create_internal() to give each task its own
 * port name table. Every task must have its own ipc_space.
 *
 * Returns pointer to initialized ipc_space, or NULL on pool exhaustion.
 */
struct ipc_space *ipc_space_create(void);

/*
 * ipc_space_destroy - Release an IPC space and all port rights it holds
 *
 * On XNU, called from task_deallocate(). Releases all port rights held
 * in the space's name table and returns the space to the pool.
 */
void ipc_space_destroy(struct ipc_space *space);

/*
 * ipc_port_allocate_name - Insert a port into a task's name space
 *
 * @space:  Task's IPC space
 * @port:   Kernel port object
 * @type:   Rights to grant
 * @namep:  On success, receives the assigned name
 *
 * Returns KERN_SUCCESS or error.
 */
kern_return_t ipc_port_allocate_name(struct ipc_space *space,
                                     struct ipc_port *port,
                                     mach_port_type_t type,
                                     mach_port_name_t *namep);

/*
 * ipc_port_lookup - Look up a port by name in a task's space
 *
 * @space: Task's IPC space
 * @name:  Port name
 * @portp: On success, receives the kernel port object
 * @typep: On success, receives the rights held
 *
 * Returns KERN_SUCCESS or KERN_INVALID_ARGUMENT.
 */
kern_return_t ipc_port_lookup(struct ipc_space *space,
                              mach_port_name_t name,
                              struct ipc_port **portp,
                              mach_port_type_t *typep);

/*
 * ipc_port_deallocate_name - Remove a port from a task's name space
 *
 * @space: Task's IPC space
 * @name:  Port name to remove
 *
 * Returns KERN_SUCCESS or error.
 */
kern_return_t ipc_port_deallocate_name(struct ipc_space *space,
                                       mach_port_name_t name);

/* ============================================================================
 * Mach Trap Entrypoints (called from syscall dispatch)
 * ============================================================================ */

struct trap_frame;

/*
 * mach_msg_trap - Send and/or receive a message
 *
 * Trap args (from user x0-x5):
 *   x0 = pointer to mach_msg_header_t (user buffer)
 *   x1 = option (MACH_SEND_MSG, MACH_RCV_MSG, or both)
 *   x2 = send_size
 *   x3 = rcv_size
 *   x4 = rcv_name (port to receive on, if different from header)
 *   x5 = timeout
 *
 * Returns mach_msg_return_t in x0.
 */
mach_msg_return_t mach_msg_trap(struct trap_frame *tf);

/*
 * mach_port_allocate_trap - Allocate a new port with given right
 *
 * x0 = target task port (should be self)
 * x1 = right type (MACH_PORT_RIGHT_RECEIVE, etc.)
 * x2 = pointer to mach_port_name_t (out)
 *
 * Returns kern_return_t.
 */
kern_return_t mach_port_allocate_trap(struct trap_frame *tf);

/*
 * mach_port_deallocate_trap - Release a port right
 *
 * x0 = target task port
 * x1 = port name
 *
 * Returns kern_return_t.
 */
kern_return_t mach_port_deallocate_trap(struct trap_frame *tf);

/*
 * task_self_trap - Return the calling task's self port
 *
 * No arguments. Returns mach_port_t in x0.
 */
mach_port_t task_self_trap(void);

/*
 * mach_reply_port_trap - Allocate a reply port
 *
 * Returns mach_port_t in x0.
 */
mach_port_t mach_reply_port_trap(void);

/*
 * thread_self_trap - Return the calling thread's self port
 *
 * Returns mach_port_t in x0.
 */
mach_port_t thread_self_trap(void);

/* ============================================================================
 * Bootstrap Service Registry
 *
 * On XNU, service lookup (bootstrap_register / bootstrap_look_up) is
 * handled by launchd via Mach messages to the bootstrap port. Kiseki
 * implements this as kernel-managed traps for simplicity while maintaining
 * the same userland API semantics.
 *
 * Services register a name→port mapping. Clients look up a service by
 * name and receive a send right to the service port in their own IPC space.
 * ============================================================================ */

#define BOOTSTRAP_MAX_NAME_LEN      128
#define BOOTSTRAP_MAX_SERVICES      64

/* Trap numbers for bootstrap (Kiseki extensions in Mach trap space) */
#define MACH_TRAP_bootstrap_register    (-40)
#define MACH_TRAP_bootstrap_look_up     (-41)
#define MACH_TRAP_bootstrap_check_in    (-42)

/*
 * bootstrap_register_trap - Register a service port under a name
 *
 * x0 = bootstrap port (ignored, uses kernel registry)
 * x1 = pointer to service name string (user)
 * x2 = service port name (in caller's IPC space)
 *
 * Returns kern_return_t.
 */
kern_return_t bootstrap_register_trap(struct trap_frame *tf);

/*
 * bootstrap_look_up_trap - Look up a service port by name
 *
 * x0 = bootstrap port (ignored, uses kernel registry)
 * x1 = pointer to service name string (user)
 * x2 = pointer to mach_port_t (out, receives send right in caller's space)
 *
 * Returns kern_return_t.
 */
kern_return_t bootstrap_look_up_trap(struct trap_frame *tf);

/*
 * bootstrap_check_in_trap - Daemon checks in to claim a pre-registered service
 *
 * On macOS, launchd pre-creates the service port and registers it before
 * the daemon starts. The daemon calls bootstrap_check_in() to receive the
 * receive right for its service port. This eliminates race conditions:
 * clients can bootstrap_look_up() immediately because the port exists
 * before the daemon is even running.
 *
 * x0 = bootstrap port (ignored)
 * x1 = pointer to service name string (user)
 * x2 = pointer to mach_port_t (out, receives port name with receive+send right)
 *
 * Returns kern_return_t.
 */
kern_return_t bootstrap_check_in_trap(struct trap_frame *tf);

#endif /* _MACH_IPC_H */
