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
 *
 * On XNU, ipc_space objects are allocated from a zone allocator (ipc_space_zone).
 * Each task gets its own ipc_space at task creation. We use a static pool.
 * ============================================================================ */

#define IPC_SPACE_POOL_SIZE     64      /* Max concurrent tasks with IPC */

static struct ipc_space ipc_space_pool[IPC_SPACE_POOL_SIZE];
static bool             ipc_space_used[IPC_SPACE_POOL_SIZE];
static spinlock_t       ipc_space_pool_lock = SPINLOCK_INIT;

void ipc_space_init(struct ipc_space *space)
{
    spin_init(&space->lock);
    space->next_name = 1;   /* 0 = MACH_PORT_NULL, reserved */

    for (uint32_t i = 0; i < TASK_PORT_TABLE_SIZE; i++) {
        space->table[i].port = NULL;
        space->table[i].type = 0;
    }
}

/*
 * ipc_space_create - Allocate and initialize a new IPC space for a task.
 *
 * On XNU: ipc_space_create() in osfmk/ipc/ipc_space.c allocates from
 * ipc_space_zone and initializes the space table. Called from task_create_internal().
 *
 * Returns pointer to initialized space, or NULL on pool exhaustion.
 */
struct ipc_space *ipc_space_create(void)
{
    uint64_t flags;
    spin_lock_irqsave(&ipc_space_pool_lock, &flags);

    for (uint32_t i = 0; i < IPC_SPACE_POOL_SIZE; i++) {
        if (!ipc_space_used[i]) {
            ipc_space_used[i] = true;
            spin_unlock_irqrestore(&ipc_space_pool_lock, flags);

            struct ipc_space *space = &ipc_space_pool[i];
            ipc_space_init(space);
            return space;
        }
    }

    spin_unlock_irqrestore(&ipc_space_pool_lock, flags);
    kprintf("[ipc] ipc_space_create: pool exhausted\n");
    return NULL;
}

/*
 * ipc_space_destroy - Release an IPC space back to the pool.
 *
 * On XNU: ipc_space_destroy() in osfmk/ipc/ipc_space.c tears down the
 * space, releasing all port rights. Called from task_deallocate().
 */
void ipc_space_destroy(struct ipc_space *space)
{
    if (space == NULL)
        return;

    /* Release all port rights held in this space */
    for (uint32_t i = 0; i < TASK_PORT_TABLE_SIZE; i++) {
        if (space->table[i].port != NULL) {
            struct ipc_port *port = space->table[i].port;
            uint64_t pflags;
            spin_lock_irqsave(&port->lock, &pflags);
            if (port->refs > 0)
                port->refs--;
            if (port->refs == 0) {
                port->active = false;
                port->receiver = NULL;
            }
            spin_unlock_irqrestore(&port->lock, pflags);
            space->table[i].port = NULL;
            space->table[i].type = 0;
        }
    }

    /* Return to pool */
    uint64_t flags;
    spin_lock_irqsave(&ipc_space_pool_lock, &flags);

    for (uint32_t i = 0; i < IPC_SPACE_POOL_SIZE; i++) {
        if (&ipc_space_pool[i] == space) {
            ipc_space_used[i] = false;
            break;
        }
    }

    spin_unlock_irqrestore(&ipc_space_pool_lock, flags);
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

/* ============================================================================
 * ipc_object_copyin_type - Convert user disposition to kernel (post-copyin) type
 *
 * On XNU: osfmk/ipc/ipc_object.c:ipc_object_copyin_type()
 *
 * Translates from "action" dispositions (what the sender asked) to "state"
 * types (what kind of right the kernel holds in the message):
 *
 *   MOVE_RECEIVE    -> PORT_RECEIVE    (16)
 *   MOVE_SEND       -> PORT_SEND       (17)
 *   COPY_SEND       -> PORT_SEND       (17)
 *   MAKE_SEND       -> PORT_SEND       (17)
 *   MOVE_SEND_ONCE  -> PORT_SEND_ONCE  (18)
 *   MAKE_SEND_ONCE  -> PORT_SEND_ONCE  (18)
 * ============================================================================ */

static mach_msg_type_name_t ipc_object_copyin_type(mach_msg_type_name_t type)
{
    switch (type) {
    case MACH_MSG_TYPE_MOVE_RECEIVE:
        return MACH_MSG_TYPE_PORT_RECEIVE;
    case MACH_MSG_TYPE_MOVE_SEND:
    case MACH_MSG_TYPE_COPY_SEND:
    case MACH_MSG_TYPE_MAKE_SEND:
        return MACH_MSG_TYPE_PORT_SEND;
    case MACH_MSG_TYPE_MOVE_SEND_ONCE:
    case MACH_MSG_TYPE_MAKE_SEND_ONCE:
        return MACH_MSG_TYPE_PORT_SEND_ONCE;
    default:
        return MACH_MSG_TYPE_PORT_NONE;
    }
}

/*
 * port_enqueue - Enqueue a message onto a port's ring buffer.
 *
 * After copyin, the message data still contains the raw user bytes, but
 * the kernel port pointers and post-copyin type info are stored in the
 * ipc_msg slot alongside the data. This mirrors XNU's ipc_kmsg which
 * stores port pointers in the header fields.
 *
 * Caller must NOT hold port->lock (semaphore_signal may sleep).
 * Returns MACH_MSG_SUCCESS or MACH_SEND_NO_BUFFER.
 */
static mach_msg_return_t port_enqueue(struct ipc_port *port,
                                      const void *msg_data,
                                      uint32_t msg_size,
                                      struct ipc_port *reply_port,
                                      mach_msg_type_name_t reply_type,
                                      mach_msg_type_name_t dest_type)
{
    uint64_t flags;
    spin_lock_irqsave(&port->lock, &flags);

    if (port->queue_count >= PORT_MSG_QUEUE_SIZE) {
        spin_unlock_irqrestore(&port->lock, flags);
        return MACH_SEND_NO_BUFFER;
    }

    struct ipc_msg *slot = &port->queue[port->queue_tail];
    slot->size = msg_size;
    slot->reply_port = reply_port;
    slot->reply_type = reply_type;
    slot->dest_type = dest_type;
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
 * Returns MACH_MSG_SUCCESS or error. Copies raw message bytes into user
 * buffer and returns the kernel port pointers + types for copyout.
 */
static mach_msg_return_t port_dequeue(struct ipc_port *port,
                                      void *buf,
                                      uint32_t buf_size,
                                      uint32_t *actual_size,
                                      struct ipc_port **reply_port_out,
                                      mach_msg_type_name_t *reply_type_out,
                                      mach_msg_type_name_t *dest_type_out)
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

    /* Return the translated port info for copyout */
    *reply_port_out = slot->reply_port;
    *reply_type_out = slot->reply_type;
    *dest_type_out  = slot->dest_type;

    /* Clear the slot */
    slot->reply_port = NULL;
    slot->reply_type = MACH_MSG_TYPE_PORT_NONE;
    slot->dest_type  = MACH_MSG_TYPE_PORT_NONE;

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
    if (space == NULL)
        return MACH_SEND_INVALID_DEST;

    mach_msg_return_t ret = MACH_MSG_SUCCESS;

    /* ===================================================================
     * Send phase — ipc_kmsg_copyin_header() equivalent
     *
     * On XNU, ipc_kmsg_copyin_header() does the following:
     *   1. Extract dest_name, reply_name, and dispositions from msgh_bits
     *   2. Look up both port names in sender's IPC space
     *   3. Copyin rights per disposition (COPY_SEND, MAKE_SEND_ONCE, etc.)
     *   4. Convert dispositions to post-copyin types via ipc_object_copyin_type()
     *   5. Store kernel ipc_port pointers in the message header fields
     *   6. Queue the message on the destination port
     *
     * We translate port names to kernel objects and store them in the
     * ipc_msg queue slot alongside the raw message bytes. The raw bytes
     * keep the sender's original header (port names zeroed for safety).
     * =================================================================== */
    if (option & MACH_SEND_MSG) {
        if (user_msg == NULL || send_size < sizeof(mach_msg_header_t))
            return MACH_SEND_MSG_TOO_SMALL;

        if (send_size > MACH_MSG_SIZE_MAX)
            return MACH_SEND_NO_BUFFER;

        /* Read header from user buffer */
        mach_msg_header_t hdr;
        ipc_memcpy(&hdr, user_msg, sizeof(hdr));

        /* Extract port names and dispositions from msgh_bits */
        mach_port_name_t dest_name  = hdr.msgh_remote_port;
        mach_port_name_t reply_name = hdr.msgh_local_port;
        mach_msg_type_name_t dest_disp  = MACH_MSGH_BITS_REMOTE(hdr.msgh_bits);
        mach_msg_type_name_t reply_disp = MACH_MSGH_BITS_LOCAL(hdr.msgh_bits);

        /*
         * Step 1: Copyin the destination port
         *
         * Look up dest_name in the sender's IPC space. The sender must
         * hold a send or send-once right, matching the disposition.
         */
        struct ipc_port *dest_port = NULL;
        mach_port_type_t dest_right_type = 0;

        kern_return_t kr = ipc_port_lookup(space, dest_name,
                                           &dest_port, &dest_right_type);
        if (kr != KERN_SUCCESS) {
            kprintf("[ipc] send: dest port name %u not found in space %p\n",
                    dest_name, space);
            return MACH_SEND_INVALID_DEST;
        }

        /* Validate sender has appropriate right for the disposition */
        if (dest_disp == MACH_MSG_TYPE_MAKE_SEND ||
            dest_disp == MACH_MSG_TYPE_MAKE_SEND_ONCE) {
            /* MAKE_SEND/MAKE_SEND_ONCE require receive right */
            if (!(dest_right_type & MACH_PORT_TYPE_RECEIVE)) {
                kprintf("[ipc] send: MAKE_SEND* requires receive right\n");
                return MACH_SEND_INVALID_RIGHT;
            }
        } else {
            /* COPY_SEND, MOVE_SEND, MOVE_SEND_ONCE require send/send-once */
            if (!(dest_right_type & (MACH_PORT_TYPE_SEND |
                                     MACH_PORT_TYPE_SEND_ONCE))) {
                kprintf("[ipc] send: dest port name %u has no send right\n",
                        dest_name);
                return MACH_SEND_INVALID_RIGHT;
            }
        }

        /* Bump reference on dest port for the in-flight message */
        uint64_t dflags;
        spin_lock_irqsave(&dest_port->lock, &dflags);
        dest_port->refs++;
        spin_unlock_irqrestore(&dest_port->lock, dflags);

        /*
         * Step 2: Copyin the reply port (msgh_local_port)
         *
         * On XNU, the reply port is typically sent with MAKE_SEND_ONCE
         * disposition. The sender holds the receive right, and copyin
         * creates a send-once right (incrementing ip_sorights and taking
         * a reference) that travels with the message.
         *
         * The reply port is optional — MACH_PORT_NULL means no reply.
         */
        struct ipc_port *reply_port = NULL;
        mach_msg_type_name_t reply_copyin_type = MACH_MSG_TYPE_PORT_NONE;

        if (reply_name != MACH_PORT_NULL && reply_disp != 0) {
            mach_port_type_t reply_right_type = 0;

            kr = ipc_port_lookup(space, reply_name,
                                 &reply_port, &reply_right_type);
            if (kr != KERN_SUCCESS) {
                /* Release dest ref on failure */
                spin_lock_irqsave(&dest_port->lock, &dflags);
                dest_port->refs--;
                spin_unlock_irqrestore(&dest_port->lock, dflags);
                kprintf("[ipc] send: reply port name %u not found\n",
                        reply_name);
                return MACH_SEND_INVALID_DEST;
            }

            /* Validate reply disposition */
            if (reply_disp == MACH_MSG_TYPE_MAKE_SEND ||
                reply_disp == MACH_MSG_TYPE_MAKE_SEND_ONCE) {
                if (!(reply_right_type & MACH_PORT_TYPE_RECEIVE)) {
                    spin_lock_irqsave(&dest_port->lock, &dflags);
                    dest_port->refs--;
                    spin_unlock_irqrestore(&dest_port->lock, dflags);
                    return MACH_SEND_INVALID_RIGHT;
                }
            } else {
                if (!(reply_right_type & (MACH_PORT_TYPE_SEND |
                                          MACH_PORT_TYPE_SEND_ONCE))) {
                    spin_lock_irqsave(&dest_port->lock, &dflags);
                    dest_port->refs--;
                    spin_unlock_irqrestore(&dest_port->lock, dflags);
                    return MACH_SEND_INVALID_RIGHT;
                }
            }

            /* Take a reference for the in-flight reply port */
            uint64_t rflags;
            spin_lock_irqsave(&reply_port->lock, &rflags);
            reply_port->refs++;
            spin_unlock_irqrestore(&reply_port->lock, rflags);

            /* Convert disposition to post-copyin type */
            reply_copyin_type = ipc_object_copyin_type(reply_disp);
        }

        /*
         * Step 3: Convert dest disposition to post-copyin type
         */
        mach_msg_type_name_t dest_copyin_type = ipc_object_copyin_type(dest_disp);

        /*
         * Step 4: Enqueue the message with translated port rights
         *
         * The raw user message bytes are copied verbatim. The kernel
         * port pointers and post-copyin types travel in the ipc_msg
         * slot fields (reply_port, reply_type, dest_type).
         */
        ret = port_enqueue(dest_port, (const void *)user_msg, send_size,
                           reply_port, reply_copyin_type, dest_copyin_type);
        if (ret != MACH_MSG_SUCCESS) {
            /* Release references on failure */
            uint64_t pflags;
            spin_lock_irqsave(&dest_port->lock, &pflags);
            dest_port->refs--;
            spin_unlock_irqrestore(&dest_port->lock, pflags);
            if (reply_port != NULL) {
                spin_lock_irqsave(&reply_port->lock, &pflags);
                reply_port->refs--;
                spin_unlock_irqrestore(&reply_port->lock, pflags);
            }
            return ret;
        }

        /* Release the send-phase reference on dest (message is queued) */
        spin_lock_irqsave(&dest_port->lock, &dflags);
        dest_port->refs--;
        spin_unlock_irqrestore(&dest_port->lock, dflags);
    }

    /* ===================================================================
     * Receive phase — ipc_kmsg_copyout_header() equivalent
     *
     * On XNU, ipc_kmsg_copyout_header() does the following:
     *   1. Dequeue the message from the port
     *   2. Extract kernel port pointers from the message
     *   3. Copyout the reply port: insert a right (typically send-once)
     *      into the receiver's IPC space
     *   4. Copyout the dest port: consume the send right, return the
     *      receiver's name for the port (they hold the receive right)
     *   5. Swap remote/local: receiver's remote = reply, local = dest
     *   6. Update msgh_bits with the swapped post-copyin types
     * =================================================================== */
    if (option & MACH_RCV_MSG) {
        if (user_msg == NULL || rcv_size < sizeof(mach_msg_header_t))
            return MACH_RCV_INVALID_TYPE;

        /* Determine which port to receive on */
        mach_port_name_t rname = rcv_name;
        if (rname == MACH_PORT_NULL && user_msg != NULL) {
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

        if (!(rcv_type & MACH_PORT_TYPE_RECEIVE))
            return MACH_RCV_INVALID_NAME;

        /* Dequeue — blocks if empty. Returns raw bytes + translated ports. */
        uint32_t actual = 0;
        struct ipc_port *msg_reply_port = NULL;
        mach_msg_type_name_t msg_reply_type = MACH_MSG_TYPE_PORT_NONE;
        mach_msg_type_name_t msg_dest_type  = MACH_MSG_TYPE_PORT_NONE;

        ret = port_dequeue(rcv_port, (void *)user_msg, rcv_size, &actual,
                           &msg_reply_port, &msg_reply_type, &msg_dest_type);
        if (ret != MACH_MSG_SUCCESS)
            return ret;

        /*
         * Step 1: Copyout the reply port into receiver's IPC space
         *
         * On XNU, ipc_kmsg_copyout_header() calls ipc_right_copyout_any_send()
         * to insert the reply port (typically a send-once right) into the
         * receiver's namespace. This creates a NEW name in the receiver's
         * space pointing to the kernel reply port object.
         *
         * After copyout, this becomes the receiver's msgh_remote_port
         * (the port they'll send replies to).
         */
        mach_port_name_t reply_name_out = MACH_PORT_NULL;
        mach_msg_type_name_t reply_type_out = MACH_MSG_TYPE_PORT_NONE;

        if (msg_reply_port != NULL &&
            msg_reply_type != MACH_MSG_TYPE_PORT_NONE) {

            if (!msg_reply_port->active) {
                /* Reply port died — set to MACH_PORT_DEAD */
                reply_name_out = MACH_PORT_DEAD;
                reply_type_out = MACH_MSG_TYPE_PORT_NONE;
                /* Release the reference from copyin */
                uint64_t rpflags;
                spin_lock_irqsave(&msg_reply_port->lock, &rpflags);
                if (msg_reply_port->refs > 0)
                    msg_reply_port->refs--;
                spin_unlock_irqrestore(&msg_reply_port->lock, rpflags);
            } else {
                /*
                 * Insert the right into the receiver's IPC space.
                 *
                 * For SEND_ONCE: always allocate a fresh entry (XNU uses
                 *   ipc_entry_claim for send-once rights).
                 * For SEND: check if receiver already has an entry for this
                 *   port (ipc_right_reverse), reuse if so, else allocate new.
                 *
                 * We use ipc_port_allocate_name which always allocates a new
                 * entry. This is correct for SEND_ONCE (always fresh) and
                 * acceptable for SEND (a simplification — XNU would reuse
                 * an existing entry if the receiver already has a send right
                 * to this port, but allocating new is safe and correct).
                 */
                mach_port_type_t insert_type;
                if (msg_reply_type == MACH_MSG_TYPE_PORT_SEND_ONCE) {
                    insert_type = MACH_PORT_TYPE_SEND_ONCE;
                } else if (msg_reply_type == MACH_MSG_TYPE_PORT_SEND) {
                    insert_type = MACH_PORT_TYPE_SEND;
                } else {
                    /* PORT_RECEIVE — unusual for reply, but handle it */
                    insert_type = MACH_PORT_TYPE_RECEIVE;
                }

                mach_port_name_t new_name;
                kr = ipc_port_allocate_name(space, msg_reply_port,
                                            insert_type, &new_name);
                if (kr == KERN_SUCCESS) {
                    reply_name_out = new_name;
                    reply_type_out = msg_reply_type;
                    /* Reference transfers from message to entry — no change */
                } else {
                    /* Failed to insert — port becomes dead name */
                    reply_name_out = MACH_PORT_DEAD;
                    reply_type_out = MACH_MSG_TYPE_PORT_NONE;
                    /* Release the reference */
                    uint64_t rpflags;
                    spin_lock_irqsave(&msg_reply_port->lock, &rpflags);
                    if (msg_reply_port->refs > 0)
                        msg_reply_port->refs--;
                    spin_unlock_irqrestore(&msg_reply_port->lock, rpflags);
                }
            }
        }

        /*
         * Step 2: Copyout the destination port (ipc_object_copyout_dest)
         *
         * On XNU, ipc_object_copyout_dest() CONSUMES the destination right.
         * The receiver already holds the receive right for the destination
         * port (that's how they're receiving from it). The send right that
         * traveled with the message is consumed:
         *   - refs decremented
         *   - The receiver gets their existing name for the port
         *
         * If the receiver doesn't hold the receive right (shouldn't happen
         * normally), they get MACH_PORT_NULL or MACH_PORT_DEAD.
         */
        mach_port_name_t dest_name_out = rname;  /* The name receiver used to receive */
        mach_msg_type_name_t dest_type_out = msg_dest_type;

        /* Consume the in-flight destination right reference */
        /* (The message held one ref from copyin; receiver already has the port) */

        /*
         * Step 3: Swap remote/local per XNU convention
         *
         * On XNU, after copyout the header is rewritten:
         *   msgh_remote_port = reply port name (in receiver's space)
         *   msgh_local_port  = dest port name (receiver's own port)
         *   msgh_bits: remote = reply_type, local = dest_type (SWAPPED)
         *
         * This makes semantic sense: from the receiver's perspective,
         *   - "local" = the port they own (the destination they received on)
         *   - "remote" = the port to reply to (the sender's reply port)
         */
        mach_msg_header_t *rcv_hdr = user_msg;

        /* Build new msgh_bits with swapped types */
        mach_msg_bits_t new_bits = MACH_MSGH_BITS(reply_type_out, dest_type_out);
        /* Preserve complex bit and other flags from original */
        new_bits |= (rcv_hdr->msgh_bits & MACH_MSGH_BITS_COMPLEX);

        rcv_hdr->msgh_bits = new_bits;
        rcv_hdr->msgh_remote_port = reply_name_out;    /* Reply port */
        rcv_hdr->msgh_local_port  = dest_name_out;     /* Receiver's port */

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
    if (space == NULL)
        return KERN_INVALID_ARGUMENT;

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
    if (space == NULL)
        return KERN_INVALID_ARGUMENT;

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
    if (space == NULL)
        return MACH_PORT_NULL;

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
 * Returns the calling thread's port. Each thread gets a unique port that
 * can be used to send messages to that specific thread.
 * ============================================================================ */

mach_port_t thread_self_trap(void)
{
    struct thread *th = current_thread_get();
    if (th == NULL || th->task == NULL)
        return MACH_PORT_NULL;

    /* Lazily allocate thread port on first use */
    if (th->thread_port == MACH_PORT_NULL) {
        struct ipc_space *space = th->task->ipc_space;
        if (space == NULL)
            return MACH_PORT_NULL;

        struct ipc_port *port = ipc_port_alloc();
        if (port == NULL)
            return MACH_PORT_NULL;

        /* Thread port receiver is the task (thread control messages go there) */
        port->receiver = th->task;

        mach_port_name_t name;
        kern_return_t kr = ipc_port_allocate_name(space, port,
                                                  MACH_PORT_TYPE_SEND,
                                                  &name);
        if (kr != KERN_SUCCESS) {
            ipc_port_dealloc(port);
            return MACH_PORT_NULL;
        }

        th->thread_port = name;
    }

    return th->thread_port;
}

/* ============================================================================
 * Bootstrap Service Registry
 *
 * Kernel-managed name→port registry. On XNU, this is handled by launchd
 * via Mach messages to the bootstrap port. Kiseki implements it as kernel
 * traps to avoid the complexity of a full MIG/launchd bootstrap protocol
 * while maintaining the same userland API semantics.
 *
 * When a daemon calls bootstrap_register("uk.co.avltree9798.mDNSResponder", port),
 * the kernel stores the kernel port object under that name. When a client
 * calls bootstrap_look_up("uk.co.avltree9798.mDNSResponder", &port), the kernel
 * inserts a SEND right to that port into the client's IPC space.
 * ============================================================================ */

struct bootstrap_entry {
    char                name[BOOTSTRAP_MAX_NAME_LEN];
    struct ipc_port     *port;      /* Kernel port object */
    bool                active;
};

static struct bootstrap_entry bootstrap_registry[BOOTSTRAP_MAX_SERVICES];
static spinlock_t             bootstrap_lock = SPINLOCK_INIT;

/* Simple freestanding strcmp */
static int ipc_strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

/* Simple freestanding strncpy */
static void ipc_strncpy(char *dst, const char *src, uint32_t n)
{
    uint32_t i;
    for (i = 0; i < n - 1 && src[i] != '\0'; i++)
        dst[i] = src[i];
    dst[i] = '\0';
}

/* Simple freestanding strlen */
static uint32_t ipc_strlen(const char *s)
{
    uint32_t len = 0;
    while (s[len] != '\0') len++;
    return len;
}

/*
 * bootstrap_register_trap - Register a named service port
 *
 * x0 = bootstrap port (ignored)
 * x1 = user pointer to service name string
 * x2 = port name in caller's IPC space (must hold send or receive right)
 */
kern_return_t bootstrap_register_trap(struct trap_frame *tf)
{
    const char *user_name     = (const char *)tf->regs[1];
    mach_port_name_t port_name = (mach_port_name_t)tf->regs[2];

    struct thread *cur = current_thread_get();
    if (cur == NULL || cur->task == NULL || user_name == NULL)
        return KERN_INVALID_ARGUMENT;

    struct ipc_space *space = cur->task->ipc_space;
    if (space == NULL)
        return KERN_INVALID_ARGUMENT;

    /* Validate the service name from userspace */
    if (ipc_strlen(user_name) == 0 || ipc_strlen(user_name) >= BOOTSTRAP_MAX_NAME_LEN)
        return KERN_INVALID_ARGUMENT;

    /* Look up the port in the caller's namespace */
    struct ipc_port *port = NULL;
    mach_port_type_t type = 0;
    kern_return_t kr = ipc_port_lookup(space, port_name, &port, &type);
    if (kr != KERN_SUCCESS)
        return KERN_INVALID_RIGHT;

    /* Register in the bootstrap table */
    uint64_t flags;
    spin_lock_irqsave(&bootstrap_lock, &flags);

    /* Check for duplicate name */
    for (uint32_t i = 0; i < BOOTSTRAP_MAX_SERVICES; i++) {
        if (bootstrap_registry[i].active &&
            ipc_strcmp(bootstrap_registry[i].name, user_name) == 0) {
            /* Update existing entry */
            bootstrap_registry[i].port = port;
            port->refs++;
            spin_unlock_irqrestore(&bootstrap_lock, flags);
            kprintf("[bootstrap] updated service '%s' -> port %p\n",
                    user_name, port);
            return KERN_SUCCESS;
        }
    }

    /* Find a free slot */
    for (uint32_t i = 0; i < BOOTSTRAP_MAX_SERVICES; i++) {
        if (!bootstrap_registry[i].active) {
            ipc_strncpy(bootstrap_registry[i].name, user_name,
                        BOOTSTRAP_MAX_NAME_LEN);
            bootstrap_registry[i].port = port;
            bootstrap_registry[i].active = true;
            port->refs++;

            spin_unlock_irqrestore(&bootstrap_lock, flags);
            kprintf("[bootstrap] registered service '%s' -> port %p\n",
                    user_name, port);
            return KERN_SUCCESS;
        }
    }

    spin_unlock_irqrestore(&bootstrap_lock, flags);
    kprintf("[bootstrap] registry full, cannot register '%s'\n", user_name);
    return KERN_NO_SPACE;
}

/*
 * bootstrap_look_up_trap - Look up a named service and get a send right
 *
 * x0 = bootstrap port (ignored)
 * x1 = user pointer to service name string
 * x2 = user pointer to mach_port_t (out: receives port name with send right)
 *
 * This creates a SEND right to the service port in the caller's IPC space.
 * The port must have been previously registered via bootstrap_register.
 */
kern_return_t bootstrap_look_up_trap(struct trap_frame *tf)
{
    const char *user_name       = (const char *)tf->regs[1];
    mach_port_name_t *user_outp = (mach_port_name_t *)tf->regs[2];

    struct thread *cur = current_thread_get();
    if (cur == NULL || cur->task == NULL || user_name == NULL || user_outp == NULL)
        return KERN_INVALID_ARGUMENT;

    struct ipc_space *space = cur->task->ipc_space;
    if (space == NULL)
        return KERN_INVALID_ARGUMENT;

    /* Validate the name */
    if (ipc_strlen(user_name) == 0 || ipc_strlen(user_name) >= BOOTSTRAP_MAX_NAME_LEN)
        return KERN_INVALID_ARGUMENT;

    /* Look up in the registry */
    uint64_t flags;
    spin_lock_irqsave(&bootstrap_lock, &flags);

    struct ipc_port *service_port = NULL;
    for (uint32_t i = 0; i < BOOTSTRAP_MAX_SERVICES; i++) {
        if (bootstrap_registry[i].active &&
            ipc_strcmp(bootstrap_registry[i].name, user_name) == 0) {
            service_port = bootstrap_registry[i].port;
            break;
        }
    }

    spin_unlock_irqrestore(&bootstrap_lock, flags);

    if (service_port == NULL || !service_port->active)
        return KERN_FAILURE;    /* Service not registered */

    /*
     * Insert a SEND right to the service port into the client's IPC space.
     * This is the key cross-task port transfer: the daemon owns the receive
     * right, and each client gets a send right (new name in their space
     * pointing to the same kernel port object).
     */
    mach_port_name_t client_name;
    kern_return_t kr = ipc_port_allocate_name(space, service_port,
                                              MACH_PORT_TYPE_SEND,
                                              &client_name);
    if (kr != KERN_SUCCESS)
        return kr;

    /* Bump the port reference for the new send right */
    uint64_t pflags;
    spin_lock_irqsave(&service_port->lock, &pflags);
    service_port->refs++;
    spin_unlock_irqrestore(&service_port->lock, pflags);

    /* Write the port name back to userspace */
    *user_outp = client_name;

    return KERN_SUCCESS;
}

/*
 * bootstrap_check_in_trap - Daemon checks in to claim a pre-registered service
 *
 * On macOS, launchd pre-creates Mach service ports declared in the daemon's
 * plist before the daemon process starts. When the daemon starts, it calls
 * bootstrap_check_in() to receive the receive right for its service port.
 *
 * This is the mechanism that eliminates race conditions: the port is
 * registered in the bootstrap namespace before the daemon exists, so
 * clients can bootstrap_look_up() at any time. The daemon claims the
 * port when it's ready to process messages.
 *
 * x0 = bootstrap port (ignored)
 * x1 = user pointer to service name string
 * x2 = user pointer to mach_port_t (out: receives port name with
 *       RECEIVE + SEND rights in caller's IPC space)
 *
 * The key difference from bootstrap_look_up:
 *   - look_up grants a SEND right (for clients)
 *   - check_in grants RECEIVE + SEND rights (for the daemon)
 *   - check_in also sets the calling task as the port's receiver
 *   - check_in can only be called once per service (the receive right
 *     is exclusive — only one task can hold it)
 */
kern_return_t bootstrap_check_in_trap(struct trap_frame *tf)
{
    const char *user_name       = (const char *)tf->regs[1];
    mach_port_name_t *user_outp = (mach_port_name_t *)tf->regs[2];

    struct thread *cur = current_thread_get();
    if (cur == NULL || cur->task == NULL || user_name == NULL || user_outp == NULL)
        return KERN_INVALID_ARGUMENT;

    struct ipc_space *space = cur->task->ipc_space;
    if (space == NULL)
        return KERN_INVALID_ARGUMENT;

    /* Validate the name */
    if (ipc_strlen(user_name) == 0 || ipc_strlen(user_name) >= BOOTSTRAP_MAX_NAME_LEN)
        return KERN_INVALID_ARGUMENT;

    /* Find the service in the registry */
    uint64_t flags;
    spin_lock_irqsave(&bootstrap_lock, &flags);

    struct ipc_port *service_port = NULL;
    for (uint32_t i = 0; i < BOOTSTRAP_MAX_SERVICES; i++) {
        if (bootstrap_registry[i].active &&
            ipc_strcmp(bootstrap_registry[i].name, user_name) == 0) {
            service_port = bootstrap_registry[i].port;
            break;
        }
    }

    spin_unlock_irqrestore(&bootstrap_lock, flags);

    if (service_port == NULL || !service_port->active)
        return KERN_FAILURE;    /* Service not registered */

    /*
     * Check that no other task has already claimed the receive right.
     * On macOS, only one process can check in to a service. If the
     * port already has a receiver that isn't the kernel/init, fail.
     */
    uint64_t pflags;
    spin_lock_irqsave(&service_port->lock, &pflags);

    if (service_port->receiver != NULL &&
        service_port->receiver != cur->task) {
        /*
         * Another task already owns the receive right.
         * Allow re-check-in only if the receiver is init (the task
         * that pre-created it) or NULL.
         */
        /* Check if current receiver is PID 1 (init/launchd) */
        bool receiver_is_init = (service_port->receiver->pid == 1);

        if (!receiver_is_init) {
            spin_unlock_irqrestore(&service_port->lock, pflags);
            kprintf("[bootstrap] check_in '%s': already claimed by task %d\n",
                    user_name, service_port->receiver->pid);
            return KERN_NOT_RECEIVER;
        }
    }

    /* Transfer ownership: set the calling task as the receiver */
    service_port->receiver = cur->task;
    service_port->refs++;

    spin_unlock_irqrestore(&service_port->lock, pflags);

    /*
     * Insert RECEIVE + SEND rights into the daemon's IPC space.
     * The daemon needs the receive right to dequeue messages from
     * clients, and a send right so it can also send to itself or
     * pass the port to others.
     */
    mach_port_name_t daemon_name;
    kern_return_t kr = ipc_port_allocate_name(space, service_port,
                                              MACH_PORT_TYPE_RECEIVE |
                                              MACH_PORT_TYPE_SEND,
                                              &daemon_name);
    if (kr != KERN_SUCCESS) {
        /* Roll back receiver assignment */
        spin_lock_irqsave(&service_port->lock, &pflags);
        service_port->receiver = NULL;
        service_port->refs--;
        spin_unlock_irqrestore(&service_port->lock, pflags);
        return kr;
    }

    /* Write the port name back to userspace */
    *user_outp = daemon_name;

    kprintf("[bootstrap] check_in '%s': task %d claimed receive right (name %u)\n",
            user_name, cur->task->pid, daemon_name);

    return KERN_SUCCESS;
}
