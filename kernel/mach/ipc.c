/*
 * Kiseki OS - Mach IPC Implementation
 *
 * Port-based message passing modeled after XNU's Mach IPC.
 *
 * Key concepts:
 *   - A port is a kernel-managed message queue with a single receiver
 *   - Tasks hold port rights (send, receive, send-once) via a per-task
 *     name space (ipc_space) that maps names -> kernel port objects
 *   - mach_msg_trap is the primary IPC primitive: send and/or receive
 *   - Messages are queued inline (no OOL descriptors in this implementation)
 *
 * This is a basic implementation sufficient for bootstrap IPC. Complex
 * descriptors, vouchers, and notification ports are not yet supported.
 */

#include <kiseki/types.h>
#include <mach/ipc.h>
#include <kern/thread.h>
#include <kern/kprintf.h>
#include <kern/sync.h>
#include <machine/trap.h>

/* ============================================================================
 * Port Object Pool
 *
 * Fixed pool of kernel port objects. A real implementation would use
 * a zone allocator, but a static pool is fine for bootstrap.
 * ============================================================================ */

#define IPC_PORT_POOL_SIZE  512

static struct ipc_port  port_pool[IPC_PORT_POOL_SIZE];
static spinlock_t       port_pool_lock = SPINLOCK_INIT;

/* Global kernel IPC space — fallback for tasks without their own */
struct ipc_space ipc_space_kernel;

/* ============================================================================
 * Initialization
 * ============================================================================ */

void ipc_init(void)
{
    for (uint32_t i = 0; i < IPC_PORT_POOL_SIZE; i++) {
        port_pool[i].active = false;
        port_pool[i].refs = 0;
        port_pool[i].receiver = NULL;
        port_pool[i].queue_head = 0;
        port_pool[i].queue_tail = 0;
        port_pool[i].queue_count = 0;
        spin_init(&port_pool[i].lock);
        semaphore_init(&port_pool[i].msg_available, 0);
    }

    /* Initialize the kernel IPC space */
    ipc_space_init(&ipc_space_kernel);

    kprintf("[ipc] Mach IPC initialized (%u port slots)\n", IPC_PORT_POOL_SIZE);
}

/* ============================================================================
 * Port Allocation / Deallocation
 * ============================================================================ */

struct ipc_port *ipc_port_alloc(void)
{
    uint64_t flags;
    spin_lock_irqsave(&port_pool_lock, &flags);

    for (uint32_t i = 0; i < IPC_PORT_POOL_SIZE; i++) {
        if (!port_pool[i].active) {
            struct ipc_port *port = &port_pool[i];
            port->active = true;
            port->refs = 1;
            port->receiver = NULL;
            port->queue_head = 0;
            port->queue_tail = 0;
            port->queue_count = 0;
            spin_init(&port->lock);
            semaphore_init(&port->msg_available, 0);

            spin_unlock_irqrestore(&port_pool_lock, flags);
            return port;
        }
    }

    spin_unlock_irqrestore(&port_pool_lock, flags);
    kprintf("[ipc] port_alloc: pool exhausted\n");
    return NULL;
}

void ipc_port_dealloc(struct ipc_port *port)
{
    if (port == NULL)
        return;

    uint64_t flags;
    spin_lock_irqsave(&port->lock, &flags);

    if (port->refs > 0)
        port->refs--;

    if (port->refs == 0) {
        port->active = false;
        port->receiver = NULL;
        port->queue_head = 0;
        port->queue_tail = 0;
        port->queue_count = 0;
    }

    spin_unlock_irqrestore(&port->lock, flags);
}

/* ============================================================================
 * IPC Space (per-task port name table)
 * ============================================================================ */

void ipc_space_init(struct ipc_space *space)
{
    spin_init(&space->lock);
    space->next_name = 1;   /* 0 = MACH_PORT_NULL, reserved */

    for (uint32_t i = 0; i < TASK_PORT_TABLE_SIZE; i++) {
        space->table[i].port = NULL;
        space->table[i].type = 0;
    }
}

kern_return_t ipc_port_allocate_name(struct ipc_space *space,
                                     struct ipc_port *port,
                                     mach_port_type_t type,
                                     mach_port_name_t *namep)
{
    if (space == NULL || port == NULL || namep == NULL)
        return KERN_INVALID_ARGUMENT;

    uint64_t flags;
    spin_lock_irqsave(&space->lock, &flags);

    /* Scan for a free slot starting from next_name hint */
    uint32_t start = space->next_name;
    uint32_t name = start;

    do {
        if (name == 0)
            name = 1;   /* Skip MACH_PORT_NULL */

        if (name < TASK_PORT_TABLE_SIZE && space->table[name].port == NULL) {
            space->table[name].port = port;
            space->table[name].type = type;
            space->next_name = (name + 1) % TASK_PORT_TABLE_SIZE;
            *namep = name;

            spin_unlock_irqrestore(&space->lock, flags);
            return KERN_SUCCESS;
        }

        name = (name + 1) % TASK_PORT_TABLE_SIZE;
    } while (name != start);

    spin_unlock_irqrestore(&space->lock, flags);
    return KERN_NO_SPACE;
}

kern_return_t ipc_port_lookup(struct ipc_space *space,
                              mach_port_name_t name,
                              struct ipc_port **portp,
                              mach_port_type_t *typep)
{
    if (space == NULL || name == MACH_PORT_NULL ||
        name >= TASK_PORT_TABLE_SIZE)
        return KERN_INVALID_ARGUMENT;

    uint64_t flags;
    spin_lock_irqsave(&space->lock, &flags);

    struct ipc_port_entry *entry = &space->table[name];
    if (entry->port == NULL || !entry->port->active) {
        spin_unlock_irqrestore(&space->lock, flags);
        return KERN_INVALID_ARGUMENT;
    }

    if (portp != NULL)
        *portp = entry->port;
    if (typep != NULL)
        *typep = entry->type;

    spin_unlock_irqrestore(&space->lock, flags);
    return KERN_SUCCESS;
}

kern_return_t ipc_port_deallocate_name(struct ipc_space *space,
                                       mach_port_name_t name)
{
    if (space == NULL || name == MACH_PORT_NULL ||
        name >= TASK_PORT_TABLE_SIZE)
        return KERN_INVALID_ARGUMENT;

    uint64_t flags;
    spin_lock_irqsave(&space->lock, &flags);

    struct ipc_port_entry *entry = &space->table[name];
    if (entry->port == NULL) {
        spin_unlock_irqrestore(&space->lock, flags);
        return KERN_INVALID_ARGUMENT;
    }

    struct ipc_port *port = entry->port;
    entry->port = NULL;
    entry->type = 0;

    spin_unlock_irqrestore(&space->lock, flags);

    /* Drop reference on the kernel port object */
    ipc_port_dealloc(port);

    return KERN_SUCCESS;
}

/* ============================================================================
 * Helper: memcpy (freestanding kernel, no libc)
 * ============================================================================ */

static void ipc_memcpy(void *dst, const void *src, uint64_t n)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    while (n--)
        *d++ = *s++;
}

/* ============================================================================
 * Message Enqueue / Dequeue
 * ============================================================================ */

/*
 * port_enqueue - Enqueue a message onto a port's ring buffer.
 *
 * Caller must NOT hold port->lock (semaphore_signal may sleep).
 * Returns MACH_MSG_SUCCESS or MACH_SEND_NO_BUFFER.
 */
static mach_msg_return_t port_enqueue(struct ipc_port *port,
                                      const void *msg_data,
                                      uint32_t msg_size)
{
    uint64_t flags;
    spin_lock_irqsave(&port->lock, &flags);

    if (port->queue_count >= PORT_MSG_QUEUE_SIZE) {
        spin_unlock_irqrestore(&port->lock, flags);
        return MACH_SEND_NO_BUFFER;
    }

    struct ipc_msg *slot = &port->queue[port->queue_tail];
    slot->size = msg_size;
    ipc_memcpy(slot->data, msg_data, msg_size);

    port->queue_tail = (port->queue_tail + 1) % PORT_MSG_QUEUE_SIZE;
    port->queue_count++;

    spin_unlock_irqrestore(&port->lock, flags);

    /* Wake any thread waiting in receive */
    semaphore_signal(&port->msg_available);

    return MACH_MSG_SUCCESS;
}

/*
 * port_dequeue - Dequeue a message from a port's ring buffer.
 *
 * Blocks if no messages available (via semaphore).
 * Returns MACH_MSG_SUCCESS or error. Copies into user buffer.
 */
static mach_msg_return_t port_dequeue(struct ipc_port *port,
                                      void *buf,
                                      uint32_t buf_size,
                                      uint32_t *actual_size)
{
    /* Block until a message is available */
    semaphore_wait(&port->msg_available);

    uint64_t flags;
    spin_lock_irqsave(&port->lock, &flags);

    if (port->queue_count == 0) {
        /* Spurious wakeup or port died */
        spin_unlock_irqrestore(&port->lock, flags);
        return MACH_RCV_PORT_DIED;
    }

    struct ipc_msg *slot = &port->queue[port->queue_head];

    if (slot->size > buf_size) {
        spin_unlock_irqrestore(&port->lock, flags);
        return MACH_RCV_TOO_LARGE;
    }

    ipc_memcpy(buf, slot->data, slot->size);
    *actual_size = slot->size;

    port->queue_head = (port->queue_head + 1) % PORT_MSG_QUEUE_SIZE;
    port->queue_count--;

    spin_unlock_irqrestore(&port->lock, flags);
    return MACH_MSG_SUCCESS;
}

/* ============================================================================
 * Mach Trap: mach_msg_trap
 *
 * This is the core IPC primitive. User calls svc #0x80 with x16 = -31.
 *
 * Arguments (via trap frame registers):
 *   x0 = user pointer to mach_msg_header_t buffer
 *   x1 = option flags (MACH_SEND_MSG | MACH_RCV_MSG)
 *   x2 = send_size (bytes)
 *   x3 = rcv_size (max bytes for receive buffer)
 *   x4 = rcv_name (port name to receive on, 0 = use msgh_local_port)
 *   x5 = timeout (unused in basic implementation)
 * ============================================================================ */

mach_msg_return_t mach_msg_trap(struct trap_frame *tf)
{
    mach_msg_header_t *user_msg = (mach_msg_header_t *)tf->regs[0];
    mach_msg_option_t option    = (mach_msg_option_t)tf->regs[1];
    mach_msg_size_t send_size   = (mach_msg_size_t)tf->regs[2];
    mach_msg_size_t rcv_size    = (mach_msg_size_t)tf->regs[3];
    mach_port_name_t rcv_name   = (mach_port_name_t)tf->regs[4];
    /* timeout in tf->regs[5] - unused for now */

    struct thread *cur = current_thread_get();
    if (cur == NULL || cur->task == NULL)
        return KERN_FAILURE;

    struct ipc_space *space = cur->task->ipc_space;
    if (space == NULL) {
        /* Lazily allocate a default IPC space if none exists.
         * Use the global IPC space as fallback. */
        space = &ipc_space_kernel;
    }

    mach_msg_return_t ret = MACH_MSG_SUCCESS;

    /* --- Send phase --- */
    if (option & MACH_SEND_MSG) {
        if (user_msg == NULL || send_size < sizeof(mach_msg_header_t))
            return MACH_SEND_MSG_TOO_SMALL;

        if (send_size > MACH_MSG_SIZE_MAX)
            return MACH_SEND_NO_BUFFER;

        /* Read header from user buffer */
        mach_msg_header_t hdr;
        ipc_memcpy(&hdr, user_msg, sizeof(hdr));

        /* Look up the destination port */
        mach_port_name_t dest_name = hdr.msgh_remote_port;
        struct ipc_port *dest_port = NULL;
        mach_port_type_t dest_type = 0;

        kern_return_t kr = ipc_port_lookup(space, dest_name,
                                           &dest_port, &dest_type);
        if (kr != KERN_SUCCESS)
            return MACH_SEND_INVALID_DEST;

        /* Must have send or send-once right */
        if (!(dest_type & (MACH_PORT_TYPE_SEND | MACH_PORT_TYPE_SEND_ONCE)))
            return MACH_SEND_INVALID_RIGHT;

        /* Enqueue the message */
        ret = port_enqueue(dest_port, (const void *)user_msg, send_size);
        if (ret != MACH_MSG_SUCCESS)
            return ret;
    }

    /* --- Receive phase --- */
    if (option & MACH_RCV_MSG) {
        if (user_msg == NULL || rcv_size < sizeof(mach_msg_header_t))
            return MACH_RCV_INVALID_TYPE;

        /* Determine which port to receive on */
        mach_port_name_t rname = rcv_name;
        if (rname == MACH_PORT_NULL && user_msg != NULL) {
            /* Use the local port from the header */
            mach_msg_header_t hdr;
            ipc_memcpy(&hdr, user_msg, sizeof(hdr));
            rname = hdr.msgh_local_port;
        }

        struct ipc_port *rcv_port = NULL;
        mach_port_type_t rcv_type = 0;

        kern_return_t kr = ipc_port_lookup(space, rname,
                                           &rcv_port, &rcv_type);
        if (kr != KERN_SUCCESS)
            return MACH_RCV_INVALID_NAME;

        /* Must have receive right */
        if (!(rcv_type & MACH_PORT_TYPE_RECEIVE))
            return MACH_RCV_INVALID_NAME;

        /* Dequeue (blocks if empty) */
        uint32_t actual = 0;
        ret = port_dequeue(rcv_port, (void *)user_msg, rcv_size, &actual);
        if (ret != MACH_MSG_SUCCESS)
            return ret;

        /* Append a minimal trailer */
        if (actual + sizeof(mach_msg_trailer_t) <= rcv_size) {
            mach_msg_trailer_t trailer;
            trailer.msgh_trailer_type = MACH_MSG_TRAILER_FORMAT_0;
            trailer.msgh_trailer_size = sizeof(mach_msg_trailer_t);
            ipc_memcpy((uint8_t *)user_msg + actual, &trailer, sizeof(trailer));
        }
    }

    return ret;
}

/* ============================================================================
 * Mach Trap: mach_port_allocate_trap
 *
 * Allocate a new port and insert it into the caller's name space.
 * x0 = target task port (must be task_self), x1 = right, x2 = out name ptr
 * ============================================================================ */

kern_return_t mach_port_allocate_trap(struct trap_frame *tf)
{
    /* mach_port_right_t right = (mach_port_right_t)tf->regs[1]; */
    mach_port_name_t *user_namep = (mach_port_name_t *)tf->regs[2];

    struct thread *cur = current_thread_get();
    if (cur == NULL || cur->task == NULL || user_namep == NULL)
        return KERN_INVALID_ARGUMENT;

    struct ipc_space *space = cur->task->ipc_space;
    if (space == NULL) space = &ipc_space_kernel;

    /* Allocate a new kernel port */
    struct ipc_port *port = ipc_port_alloc();
    if (port == NULL)
        return KERN_RESOURCE_SHORTAGE;

    /* The allocator gets the receive right */
    port->receiver = cur->task;

    mach_port_name_t name;
    kern_return_t kr = ipc_port_allocate_name(space, port,
                                              MACH_PORT_TYPE_RECEIVE |
                                              MACH_PORT_TYPE_SEND,
                                              &name);
    if (kr != KERN_SUCCESS) {
        ipc_port_dealloc(port);
        return kr;
    }

    /* Write the name back to userspace */
    *user_namep = name;

    return KERN_SUCCESS;
}

/* ============================================================================
 * Mach Trap: mach_port_deallocate_trap
 *
 * x0 = target task port, x1 = port name to deallocate
 * ============================================================================ */

kern_return_t mach_port_deallocate_trap(struct trap_frame *tf)
{
    mach_port_name_t name = (mach_port_name_t)tf->regs[1];

    struct thread *cur = current_thread_get();
    if (cur == NULL || cur->task == NULL)
        return KERN_INVALID_ARGUMENT;

    struct ipc_space *space = cur->task->ipc_space;
    if (space == NULL) space = &ipc_space_kernel;

    return ipc_port_deallocate_name(space, name);
}

/* ============================================================================
 * Mach Trap: task_self_trap
 *
 * Returns the caller's task self port. No arguments.
 * ============================================================================ */

mach_port_t task_self_trap(void)
{
    struct thread *cur = current_thread_get();
    if (cur == NULL || cur->task == NULL)
        return MACH_PORT_NULL;

    return cur->task->task_port;
}

/* ============================================================================
 * Mach Trap: mach_reply_port_trap
 *
 * Allocate a temporary receive port for use as a reply port.
 * Returns the new port name, or MACH_PORT_NULL on failure.
 * ============================================================================ */

mach_port_t mach_reply_port_trap(void)
{
    struct thread *cur = current_thread_get();
    if (cur == NULL || cur->task == NULL)
        return MACH_PORT_NULL;

    struct ipc_space *space = cur->task->ipc_space;
    if (space == NULL) space = &ipc_space_kernel;

    struct ipc_port *port = ipc_port_alloc();
    if (port == NULL)
        return MACH_PORT_NULL;

    port->receiver = cur->task;

    mach_port_name_t name;
    kern_return_t kr = ipc_port_allocate_name(space, port,
                                              MACH_PORT_TYPE_RECEIVE |
                                              MACH_PORT_TYPE_SEND_ONCE,
                                              &name);
    if (kr != KERN_SUCCESS) {
        ipc_port_dealloc(port);
        return MACH_PORT_NULL;
    }

    return name;
}

/* ============================================================================
 * Mach Trap: thread_self_trap
 *
 * Returns the calling thread's port. Stub: returns the task port for now.
 * ============================================================================ */

mach_port_t thread_self_trap(void)
{
    /* TODO: per-thread port. For now, return task port. */
    return task_self_trap();
}
