/*
 * Kiseki OS - Mach IPC Implementation
 *
 * Port-based message passing modelled after XNU's Mach IPC.
 *
 * Key concepts:
 *   - A port is a kernel-managed message queue with a single receiver
 *   - Tasks hold port rights (send, receive, send-once) via a per-task
 *     name space (ipc_space) that maps names -> kernel port objects
 *   - mach_msg_trap is the primary IPC primitive: send and/or receive
 *   - Complex messages (MACH_MSGH_BITS_COMPLEX) support out-of-line (OOL)
 *     memory descriptors for transferring large data between tasks
 *
 * OOL descriptor flow (modelled on XNU ipc_kmsg_copyin/copyout):
 *   Send (copyin):
 *     1. Detect MACH_MSGH_BITS_COMPLEX in msgh_bits
 *     2. Parse mach_msg_body_t + descriptor array after header
 *     3. For each OOL descriptor: allocate kernel buffer (pmm_alloc_pages),
 *        copy sender's data into it, create vm_map_copy object
 *     4. Store vm_map_copy objects in ipc_msg.ool_descs[]
 *     5. If deallocate=true, unmap from sender
 *   Receive (copyout):
 *     1. For each OOL descriptor in the dequeued message:
 *        allocate pages in receiver's address space, map them,
 *        copy data from kernel buffer, update descriptor VA
 *     2. Free kernel buffer (vm_map_copy)
 *
 * Reference: XNU osfmk/ipc/ipc_kmsg.c — ipc_kmsg_copyin_ool_descriptor(),
 *            ipc_kmsg_copyout_ool_descriptor()
 */

#include <kiseki/types.h>
#include <mach/ipc.h>
#include <kern/thread.h>
#include <kern/kprintf.h>
#include <kern/sync.h>
#include <kern/pmm.h>
#include <kern/vmm.h>
#include <kern/proc.h>
#include <iokit/iokit_mach.h>
#include <machine/trap.h>

/* Forward declarations for functions used before their definition */
static void ipc_kmsg_clean_ool(struct ipc_msg *msg);
static void vm_map_copy_free(struct vm_map_copy *copy);

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
 * vm_map_copy Pool
 *
 * On XNU, vm_map_copy objects are allocated from a zone (vm_map_copy_zone).
 * We use a static pool since we have no general-purpose kernel heap.
 *
 * Each OOL descriptor in transit requires one vm_map_copy. With
 * MACH_MSG_OOL_MAX=16 descriptors per message and PORT_MSG_QUEUE_SIZE=16
 * queued messages, worst case is 256 concurrent copies. We provision
 * generously.
 *
 * Reference: XNU osfmk/vm/vm_map_xnu.h — struct vm_map_copy
 * ============================================================================ */

#define VM_MAP_COPY_POOL_SIZE   256

static struct vm_map_copy  vm_map_copy_pool[VM_MAP_COPY_POOL_SIZE];
static bool                vm_map_copy_used[VM_MAP_COPY_POOL_SIZE];
static spinlock_t          vm_map_copy_pool_lock = SPINLOCK_INIT;

/*
 * vm_map_copy_alloc - Allocate a vm_map_copy from the pool.
 *
 * On XNU: zalloc(vm_map_copy_zone)
 */
static struct vm_map_copy *vm_map_copy_alloc(void)
{
    uint64_t flags;
    spin_lock_irqsave(&vm_map_copy_pool_lock, &flags);

    for (uint32_t i = 0; i < VM_MAP_COPY_POOL_SIZE; i++) {
        if (!vm_map_copy_used[i]) {
            vm_map_copy_used[i] = true;
            spin_unlock_irqrestore(&vm_map_copy_pool_lock, flags);

            struct vm_map_copy *copy = &vm_map_copy_pool[i];
            copy->type = VM_MAP_COPY_NONE;
            copy->size = 0;
            copy->offset = 0;
            copy->kdata = NULL;
            return copy;
        }
    }

    spin_unlock_irqrestore(&vm_map_copy_pool_lock, flags);
    kprintf("[ipc] vm_map_copy_alloc: pool exhausted\n");
    return NULL;
}

/*
 * vm_map_copy_free - Free a vm_map_copy and its backing kernel buffer.
 *
 * On XNU: vm_map_copy_discard() in osfmk/vm/vm_map.c frees the copy
 * object and any kernel buffer it references.
 */
static void vm_map_copy_free(struct vm_map_copy *copy)
{
    if (copy == NULL)
        return;

    /* Free the kernel buffer if present */
    if (copy->type == VM_MAP_COPY_KERNEL_BUFFER && copy->kdata != NULL) {
        uint64_t npages = (copy->size + PAGE_SIZE - 1) / PAGE_SIZE;
        /* Determine the buddy order from page count */
        uint32_t order = 0;
        uint64_t p = 1;
        while (p < npages) {
            p <<= 1;
            order++;
        }
        pmm_free_pages((uint64_t)copy->kdata, order);
        copy->kdata = NULL;
    }

    copy->type = VM_MAP_COPY_NONE;
    copy->size = 0;
    copy->offset = 0;

    /* Return to pool */
    uint64_t flags;
    spin_lock_irqsave(&vm_map_copy_pool_lock, &flags);

    for (uint32_t i = 0; i < VM_MAP_COPY_POOL_SIZE; i++) {
        if (&vm_map_copy_pool[i] == copy) {
            vm_map_copy_used[i] = false;
            break;
        }
    }

    spin_unlock_irqrestore(&vm_map_copy_pool_lock, flags);
}

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

    kprintf("[ipc] Mach IPC initialised (%u port slots)\n", IPC_PORT_POOL_SIZE);
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
            port->kobject = NULL;
            port->kobject_type = 0;  /* IKOT_NONE */
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

        /*
         * Clean up any queued messages with OOL descriptors.
         *
         * On XNU, ipc_port_destroy() calls ipc_mqueue_changed() which
         * walks all queued kmsgs and calls ipc_kmsg_destroy() on each,
         * which in turn calls ipc_kmsg_clean_body() to free OOL copies.
         */
        while (port->queue_count > 0) {
            struct ipc_msg *slot = &port->queue[port->queue_head];
            ipc_kmsg_clean_ool(slot);
            slot->reply_port = NULL;
            port->queue_head = (port->queue_head + 1) % PORT_MSG_QUEUE_SIZE;
            port->queue_count--;
        }

        port->queue_head = 0;
        port->queue_tail = 0;
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
 * Returns pointer to initialised space, or NULL on pool exhaustion.
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
 * OOL Descriptor Copyin / Copyout
 *
 * On XNU, ipc_kmsg_copyin_body() iterates through the descriptor array
 * in a complex message, calling type-specific copyin functions:
 *   - ipc_kmsg_copyin_ool_descriptor() for OOL memory
 *   - ipc_kmsg_copyin_port_descriptor() for port rights
 *
 * Similarly, ipc_kmsg_copyout_body() calls:
 *   - ipc_kmsg_copyout_ool_descriptor() for OOL memory
 *   - ipc_kmsg_copyout_port_descriptor() for port rights
 *
 * Reference: XNU osfmk/ipc/ipc_kmsg.c
 * ============================================================================ */

/*
 * ipc_kmsg_copyin_ool_descriptor - Copy OOL data from sender to kernel buffer
 *
 * On XNU (osfmk/ipc/ipc_kmsg.c), this function:
 *   1. Validates the descriptor (address, size, alignment)
 *   2. Calls vm_map_copyin() to create a vm_map_copy from the sender's VA
 *   3. For small data (≤ msg_ool_size_small, typically 3 pages):
 *      Uses VM_MAP_COPY_KERNEL_BUFFER — physical copy into a kalloc'd buffer
 *   4. For large data: Uses VM_MAP_COPY_ENTRY_LIST — COW page references
 *   5. If deallocate=true: vm_map_remove() the source range from sender
 *   6. Overwrites the descriptor's address field with the vm_map_copy pointer
 *
 * We implement only the KERNEL_BUFFER path (physical copy) for now.
 * The ENTRY_LIST (COW) path is a future optimisation.
 *
 * @sender_space: Sender's vm_space (for reading user memory)
 * @desc:         Pointer to the OOL descriptor in the user message
 * @ool_out:      Kernel-side OOL storage to fill in
 *
 * Returns MACH_MSG_SUCCESS or error.
 */
static mach_msg_return_t
ipc_kmsg_copyin_ool_descriptor(struct vm_space *sender_space,
                               mach_msg_ool_descriptor_t *desc,
                               struct ipc_kmsg_ool *ool_out)
{
    uint64_t user_addr = desc->address;
    uint64_t size = desc->size;

    /* Zero-size OOL is valid (sends a NULL pointer to receiver) */
    if (size == 0) {
        ool_out->copy = VM_MAP_COPY_NULL;
        ool_out->size = 0;
        ool_out->deallocate = desc->deallocate;
        ool_out->copy_option = desc->copy;
        return MACH_MSG_SUCCESS;
    }

    /* Validate: address must be non-NULL for non-zero size */
    if (user_addr == 0) {
        kprintf("[ipc] copyin_ool: NULL address with size %lu\n", size);
        return MACH_SEND_INVALID_DEST;
    }

    /*
     * Allocate kernel buffer pages.
     *
     * On XNU, vm_map_copyin_kernel_buffer() does:
     *   kbuf = kalloc_data(len, Z_WAITOK)
     *   copyinmap(src_map, src_addr, kbuf, len)
     *
     * We use pmm_alloc_pages() since we have no kernel heap.
     * The buddy allocator gives us 2^order pages.
     */
    uint64_t npages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    uint32_t order = 0;
    uint64_t p = 1;
    while (p < npages) {
        p <<= 1;
        order++;
    }

    uint64_t kbuf_pa = pmm_alloc_pages(order);
    if (kbuf_pa == 0) {
        kprintf("[ipc] copyin_ool: failed to allocate %lu pages (order %u)\n",
                npages, order);
        return MACH_SEND_NO_BUFFER;
    }

    /*
     * Copy data from sender's address space into kernel buffer.
     *
     * The kernel buffer is identity-mapped (PA == kernel VA) since our
     * PMM allocates from the identity-mapped region. We can access it
     * directly from kernel context.
     *
     * For the sender's user VA, we need to translate through their page
     * tables to get the physical address, then access via identity mapping.
     * We copy page-by-page since user pages may not be contiguous physically.
     */
    /* Validate sender_space->pgd before walking page tables */
    if (sender_space->pgd == NULL) {
        pmm_free_pages(kbuf_pa, order);
        return MACH_SEND_INVALID_DEST;
    }

    uint64_t copied = 0;
    while (copied < size) {
        uint64_t src_va = user_addr + copied;
        uint64_t page_offset = src_va & (PAGE_SIZE - 1);
        uint64_t chunk = PAGE_SIZE - page_offset;
        if (chunk > size - copied)
            chunk = size - copied;

        /* Translate sender's VA to PA */
        uint64_t src_pa = vmm_translate(sender_space->pgd, src_va & PAGE_MASK);
        if (src_pa == 0) {
            kprintf("[ipc] copyin_ool: unmapped sender VA 0x%lx\n", src_va);
            pmm_free_pages(kbuf_pa, order);
            return MACH_SEND_INVALID_DEST;
        }

        /* Copy from sender's physical page to kernel buffer */
        uint8_t *src = (uint8_t *)(src_pa + page_offset);
        uint8_t *dst = (uint8_t *)(kbuf_pa + copied);
        ipc_memcpy(dst, src, chunk);

        copied += chunk;
    }

    /*
     * Create the vm_map_copy object.
     *
     * On XNU, vm_map_copyin_kernel_buffer() allocates a vm_map_copy,
     * sets type = VM_MAP_COPY_KERNEL_BUFFER, stores the buffer pointer
     * and size.
     */
    struct vm_map_copy *copy = vm_map_copy_alloc();
    if (copy == NULL) {
        pmm_free_pages(kbuf_pa, order);
        return MACH_SEND_NO_BUFFER;
    }

    copy->type = VM_MAP_COPY_KERNEL_BUFFER;
    copy->size = size;
    copy->offset = 0;
    copy->kdata = (void *)kbuf_pa;

    /*
     * If deallocate=true, unmap the source range from the sender.
     *
     * On XNU: if (deallocate), vm_map_remove(src_map, ...).
     * We unmap each page and free it.
     */
    if (desc->deallocate) {
        uint64_t va = user_addr & PAGE_MASK;
        uint64_t end = (user_addr + size + PAGE_SIZE - 1) & PAGE_MASK;
        while (va < end) {
            uint64_t pa = vmm_unmap_page(sender_space->pgd, va);
            if (pa != 0) {
                pmm_page_unref(pa);
            }
            va += PAGE_SIZE;
        }
        /* Also remove the vm_map entry if we have a map */
        if (sender_space->map != NULL) {
            vm_map_remove(sender_space->map,
                          user_addr & PAGE_MASK,
                          (user_addr + size + PAGE_SIZE - 1) & PAGE_MASK);
        }
    }

    /* Fill in the kernel-side OOL storage */
    ool_out->copy = copy;
    ool_out->size = size;
    ool_out->deallocate = desc->deallocate;
    ool_out->copy_option = desc->copy;

    return MACH_MSG_SUCCESS;
}

/*
 * ipc_kmsg_copyout_ool_descriptor - Map OOL data into receiver's address space
 *
 * On XNU (osfmk/ipc/ipc_kmsg.c), this function:
 *   1. Calls vm_map_copyout() to map the kernel buffer into the receiver
 *   2. For KERNEL_BUFFER: allocates VA in receiver, copies data, frees kbuf
 *   3. Writes the new user VA back into the descriptor's address field
 *   4. Clears the deallocate flag (receiver owns the memory now)
 *
 * @rcv_space: Receiver's vm_space
 * @desc:      Pointer to the OOL descriptor in the user message buffer
 * @ool:       Kernel-side OOL storage with vm_map_copy
 *
 * Returns MACH_MSG_SUCCESS or error.
 */
static mach_msg_return_t
ipc_kmsg_copyout_ool_descriptor(struct vm_space *rcv_space,
                                mach_msg_ool_descriptor_t *desc,
                                struct ipc_kmsg_ool *ool)
{
    struct vm_map_copy *copy = ool->copy;

    /* Zero-size OOL: receiver gets NULL */
    if (copy == VM_MAP_COPY_NULL || ool->size == 0) {
        desc->address = 0;
        desc->size = 0;
        desc->deallocate = 0;
        desc->copy = MACH_MSG_PHYSICAL_COPY;
        desc->type = MACH_MSG_OOL_DESCRIPTOR;
        return MACH_MSG_SUCCESS;
    }

    uint64_t size = copy->size;
    uint64_t npages = (size + PAGE_SIZE - 1) / PAGE_SIZE;

    /*
     * Allocate VA in the receiver's address space.
     *
     * On XNU, vm_map_copyout() calls vm_map_enter() to find free VA
     * in the destination map, then copies data from the kernel buffer
     * into newly allocated pages at that VA.
     *
     * We allocate physical pages, map them into the receiver's space,
     * copy the data from the kernel buffer, then free the kernel buffer.
     */
    uint64_t rcv_va = 0;

    if (rcv_space->map != NULL) {
        /* Use vm_map_enter to find free VA space */
        int err = vm_map_enter(rcv_space->map, &rcv_va, npages * PAGE_SIZE,
                               VM_PROT_READ | VM_PROT_WRITE,
                               VM_PROT_ALL,
                               VM_INHERIT_DEFAULT,
                               false, /* not shared */
                               -1, 0, NULL);
        if (err != 0) {
            kprintf("[ipc] copyout_ool: vm_map_enter failed (%d)\n", err);
            vm_map_copy_free(copy);
            ool->copy = VM_MAP_COPY_NULL;
            return MACH_SEND_NO_BUFFER;
        }
    } else {
        /* No vm_map — shouldn't happen for user tasks */
        kprintf("[ipc] copyout_ool: receiver has no vm_map\n");
        vm_map_copy_free(copy);
        ool->copy = VM_MAP_COPY_NULL;
        return MACH_SEND_NO_BUFFER;
    }

    /*
     * Allocate physical pages for the receiver and copy data.
     *
     * On XNU, vm_map_copyout() for KERNEL_BUFFER:
     *   1. Allocates pages in the destination map
     *   2. Copies from the kernel buffer to those pages
     *   3. Frees the kernel buffer (kfree_data)
     */
    uint8_t *kbuf = (uint8_t *)copy->kdata;
    uint64_t mapped = 0;

    for (uint64_t i = 0; i < npages; i++) {
        uint64_t page_pa = pmm_alloc_page();
        if (page_pa == 0) {
            /* OOM — unmap what we've already mapped */
            for (uint64_t j = 0; j < i; j++) {
                uint64_t va = rcv_va + j * PAGE_SIZE;
                uint64_t pa = vmm_unmap_page(rcv_space->pgd, va);
                if (pa != 0)
                    pmm_free_page(pa);
            }
            if (rcv_space->map != NULL) {
                vm_map_remove(rcv_space->map, rcv_va,
                              rcv_va + npages * PAGE_SIZE);
            }
            vm_map_copy_free(copy);
            ool->copy = VM_MAP_COPY_NULL;
            kprintf("[ipc] copyout_ool: OOM allocating receiver pages\n");
            return MACH_SEND_NO_BUFFER;
        }

        /* Map the page into the receiver's address space */
        uint64_t va = rcv_va + i * PAGE_SIZE;
        if (vmm_map_page(rcv_space->pgd, va, page_pa, PTE_USER_RW) != 0) {
            pmm_free_page(page_pa);
            /* Clean up previously mapped pages */
            for (uint64_t j = 0; j < i; j++) {
                uint64_t prev_va = rcv_va + j * PAGE_SIZE;
                uint64_t pa = vmm_unmap_page(rcv_space->pgd, prev_va);
                if (pa != 0)
                    pmm_free_page(pa);
            }
            if (rcv_space->map != NULL) {
                vm_map_remove(rcv_space->map, rcv_va,
                              rcv_va + npages * PAGE_SIZE);
            }
            vm_map_copy_free(copy);
            ool->copy = VM_MAP_COPY_NULL;
            return MACH_SEND_NO_BUFFER;
        }

        /* Copy data from kernel buffer to receiver's page */
        uint64_t chunk = PAGE_SIZE;
        if (mapped + chunk > size)
            chunk = size - mapped;

        ipc_memcpy((void *)page_pa, kbuf + mapped, chunk);

        /* Zero remainder of last page */
        if (chunk < PAGE_SIZE) {
            uint8_t *zp = (uint8_t *)page_pa + chunk;
            for (uint64_t z = chunk; z < PAGE_SIZE; z++)
                *zp++ = 0;
        }

        mapped += chunk;
    }

    /* Free the kernel buffer (the vm_map_copy and its backing pages) */
    vm_map_copy_free(copy);
    ool->copy = VM_MAP_COPY_NULL;

    /* Write the receiver's VA back into the descriptor */
    desc->address = rcv_va;
    desc->size = (mach_msg_size_t)size;
    desc->deallocate = 0;  /* Receiver now owns the memory */
    desc->copy = MACH_MSG_VIRTUAL_COPY;
    desc->type = MACH_MSG_OOL_DESCRIPTOR;

    return MACH_MSG_SUCCESS;
}

/*
 * ipc_kmsg_copyin_body - Process all descriptors in a complex message (send side)
 *
 * On XNU (osfmk/ipc/ipc_kmsg.c), ipc_kmsg_copyin_body() iterates through
 * the body's descriptor array, calling the appropriate copyin function for
 * each descriptor type.
 *
 * Layout of a complex message after the header:
 *   [header] [body: descriptor_count] [desc0] [desc1] ... [inline data]
 *
 * @sender_space:  Sender's vm_space
 * @msg_data:      Pointer to the full message (starting at header)
 * @msg_size:      Total message size in bytes
 * @ool_descs:     Array to fill with kernel-side OOL storage
 * @ool_count_out: Number of OOL descriptors processed
 *
 * Returns MACH_MSG_SUCCESS or error.
 */
static mach_msg_return_t
ipc_kmsg_copyin_body(struct vm_space *sender_space,
                     uint8_t *msg_data, uint32_t msg_size,
                     struct ipc_kmsg_ool *ool_descs,
                     uint32_t *ool_count_out)
{
    mach_msg_header_t *hdr = (mach_msg_header_t *)msg_data;

    /* Complex bit must be set (caller already checked) */
    if (!(hdr->msgh_bits & MACH_MSGH_BITS_COMPLEX)) {
        *ool_count_out = 0;
        return MACH_MSG_SUCCESS;
    }

    /* Body follows header */
    if (msg_size < sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t)) {
        kprintf("[ipc] copyin_body: message too small for body\n");
        return MACH_SEND_MSG_TOO_SMALL;
    }

    mach_msg_body_t *body = (mach_msg_body_t *)(msg_data + sizeof(mach_msg_header_t));
    uint32_t desc_count = body->msgh_descriptor_count;

    if (desc_count == 0) {
        *ool_count_out = 0;
        return MACH_MSG_SUCCESS;
    }

    if (desc_count > MACH_MSG_OOL_MAX) {
        kprintf("[ipc] copyin_body: too many descriptors (%u > %u)\n",
                desc_count, MACH_MSG_OOL_MAX);
        return MACH_SEND_INVALID_HEADER;
    }

    /* Validate that the message is large enough for all descriptors */
    uint64_t desc_area_size = (uint64_t)desc_count * sizeof(mach_msg_ool_descriptor_t);
    if (msg_size < sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t) + desc_area_size) {
        kprintf("[ipc] copyin_body: message too small for %u descriptors\n",
                desc_count);
        return MACH_SEND_MSG_TOO_SMALL;
    }

    /*
     * Iterate through descriptors.
     *
     * On XNU, descriptors are variable-sized (port=12, ool=16, ool_ports=16
     * on 64-bit). We iterate using the common type field to determine size.
     * For now we support OOL descriptors only (all 16 bytes).
     */
    uint8_t *desc_ptr = msg_data + sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t);
    uint32_t ool_idx = 0;

    for (uint32_t i = 0; i < desc_count; i++) {
        /* Check the type field — at byte offset 11 in every descriptor */
        mach_msg_type_descriptor_t *type_desc = (mach_msg_type_descriptor_t *)desc_ptr;
        mach_msg_descriptor_type_t dtype = type_desc->type;

        switch (dtype) {
        case MACH_MSG_OOL_DESCRIPTOR:
        case MACH_MSG_OOL_VOLATILE_DESCRIPTOR: {
            mach_msg_ool_descriptor_t *ool_desc =
                (mach_msg_ool_descriptor_t *)desc_ptr;

            mach_msg_return_t kr = ipc_kmsg_copyin_ool_descriptor(
                sender_space, ool_desc, &ool_descs[ool_idx]);
            if (kr != MACH_MSG_SUCCESS) {
                /* Clean up previously copied OOL descriptors */
                for (uint32_t j = 0; j < ool_idx; j++) {
                    if (ool_descs[j].copy != VM_MAP_COPY_NULL)
                        vm_map_copy_free(ool_descs[j].copy);
                }
                *ool_count_out = 0;
                return kr;
            }

            /*
             * Overwrite the descriptor's address with the vm_map_copy pointer.
             * On XNU, the descriptor in the kmsg is overwritten so that
             * the in-kernel message carries the copy object, not the
             * sender's VA. We do the same — the queued message data
             * will have the pointer in the address field.
             */
            ool_desc->address = (uint64_t)ool_descs[ool_idx].copy;

            ool_idx++;
            desc_ptr += sizeof(mach_msg_ool_descriptor_t);
            break;
        }

        case MACH_MSG_PORT_DESCRIPTOR: {
            /* Port descriptors: not yet implemented in copyin_body.
             * Port rights in header (remote/local) are already handled
             * by the existing copyin logic. In-body port descriptors
             * would need similar copyin logic. Skip for now. */
            kprintf("[ipc] copyin_body: port descriptor not yet supported\n");
            desc_ptr += sizeof(mach_msg_port_descriptor_t);
            break;
        }

        default:
            kprintf("[ipc] copyin_body: unknown descriptor type %u\n", dtype);
            /* Clean up */
            for (uint32_t j = 0; j < ool_idx; j++) {
                if (ool_descs[j].copy != VM_MAP_COPY_NULL)
                    vm_map_copy_free(ool_descs[j].copy);
            }
            *ool_count_out = 0;
            return MACH_SEND_INVALID_HEADER;
        }
    }

    *ool_count_out = ool_idx;
    return MACH_MSG_SUCCESS;
}

/*
 * ipc_kmsg_copyout_body - Process all descriptors in a complex message (receive side)
 *
 * On XNU, ipc_kmsg_copyout_body() iterates through the descriptor array
 * and maps OOL data into the receiver's address space.
 *
 * @rcv_space:  Receiver's vm_space
 * @msg_data:   Pointer to the full message (written into receiver's buffer)
 * @msg_size:   Total message size
 * @ool_descs:  Array of kernel-side OOL storage from the queued message
 * @ool_count:  Number of OOL descriptors
 *
 * Returns MACH_MSG_SUCCESS or error.
 */
static mach_msg_return_t
ipc_kmsg_copyout_body(struct vm_space *rcv_space,
                      uint8_t *msg_data, uint32_t msg_size __attribute__((unused)),
                      struct ipc_kmsg_ool *ool_descs,
                      uint32_t ool_count)
{
    mach_msg_header_t *hdr = (mach_msg_header_t *)msg_data;

    if (!(hdr->msgh_bits & MACH_MSGH_BITS_COMPLEX) || ool_count == 0)
        return MACH_MSG_SUCCESS;

    mach_msg_body_t *body = (mach_msg_body_t *)(msg_data + sizeof(mach_msg_header_t));
    uint32_t desc_count = body->msgh_descriptor_count;

    uint8_t *desc_ptr = msg_data + sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t);
    uint32_t ool_idx = 0;

    for (uint32_t i = 0; i < desc_count; i++) {
        mach_msg_type_descriptor_t *type_desc = (mach_msg_type_descriptor_t *)desc_ptr;
        mach_msg_descriptor_type_t dtype = type_desc->type;

        switch (dtype) {
        case MACH_MSG_OOL_DESCRIPTOR:
        case MACH_MSG_OOL_VOLATILE_DESCRIPTOR: {
            if (ool_idx >= ool_count) {
                kprintf("[ipc] copyout_body: OOL index mismatch\n");
                return MACH_RCV_INVALID_TYPE;
            }

            mach_msg_ool_descriptor_t *ool_desc =
                (mach_msg_ool_descriptor_t *)desc_ptr;

            mach_msg_return_t kr = ipc_kmsg_copyout_ool_descriptor(
                rcv_space, ool_desc, &ool_descs[ool_idx]);
            if (kr != MACH_MSG_SUCCESS) {
                /* Clean up remaining OOL descriptors */
                for (uint32_t j = ool_idx + 1; j < ool_count; j++) {
                    if (ool_descs[j].copy != VM_MAP_COPY_NULL)
                        vm_map_copy_free(ool_descs[j].copy);
                }
                return kr;
            }

            ool_idx++;
            desc_ptr += sizeof(mach_msg_ool_descriptor_t);
            break;
        }

        case MACH_MSG_PORT_DESCRIPTOR:
            /* Not yet implemented */
            desc_ptr += sizeof(mach_msg_port_descriptor_t);
            break;

        default:
            desc_ptr += sizeof(mach_msg_type_descriptor_t);
            break;
        }
    }

    return MACH_MSG_SUCCESS;
}

/* ============================================================================
 * OOL Descriptor Cleanup
 *
 * Free all OOL descriptors in an ipc_msg. Called when a message is
 * destroyed without being received (e.g., port destroyed with queued
 * messages), or on error paths.
 *
 * On XNU: ipc_kmsg_clean_body() in osfmk/ipc/ipc_kmsg.c
 * ============================================================================ */

static void ipc_kmsg_clean_ool(struct ipc_msg *msg)
{
    for (uint32_t i = 0; i < msg->ool_count; i++) {
        if (msg->ool_descs[i].copy != VM_MAP_COPY_NULL) {
            vm_map_copy_free(msg->ool_descs[i].copy);
            msg->ool_descs[i].copy = VM_MAP_COPY_NULL;
        }
    }
    msg->ool_count = 0;
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
 * After copyin, the message data still contains the raw user bytes
 * (with OOL descriptor address fields overwritten to vm_map_copy pointers),
 * and the kernel port pointers and post-copyin type info are stored in
 * the ipc_msg slot alongside the data. This mirrors XNU's ipc_kmsg which
 * stores port pointers in the header fields.
 *
 * OOL descriptors (vm_map_copy objects) travel with the message in
 * the ool_descs[] array. Ownership transfers from the copyin caller
 * to the queue slot, then to the receiver during copyout.
 *
 * Caller must NOT hold port->lock (semaphore_signal may sleep).
 * Returns MACH_MSG_SUCCESS or MACH_SEND_NO_BUFFER.
 */
static mach_msg_return_t port_enqueue(struct ipc_port *port,
                                       const void *msg_data,
                                       uint32_t msg_size,
                                       struct ipc_port *reply_port,
                                       mach_msg_type_name_t reply_type,
                                       mach_msg_type_name_t dest_type,
                                       struct ipc_kmsg_ool *ool_descs,
                                       uint32_t ool_count)
{
    uint64_t flags;
    spin_lock_irqsave(&port->lock, &flags);

    /*
     * Check if the port is still active. A port becomes inactive when
     * its receiver's IPC space is destroyed (process exit). On XNU,
     * ipc_kmsg_send() calls ipc_port_check_circularity() which detects
     * dead ports. We check port->active here — equivalent to XNU's
     * ip_active() check in ipc_mqueue_send().
     *
     * Return MACH_SEND_INVALID_DEST so the sender can detect dead clients
     * and clean up connection state.
     */
    if (!port->active) {
        spin_unlock_irqrestore(&port->lock, flags);
        return MACH_SEND_INVALID_DEST;
    }

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

    /* Transfer OOL descriptor ownership from copyin to queue slot */
    slot->ool_count = ool_count;
    for (uint32_t i = 0; i < ool_count; i++) {
        slot->ool_descs[i] = ool_descs[i];
    }
    /* Zero remaining slots for safety */
    for (uint32_t i = ool_count; i < MACH_MSG_OOL_MAX; i++) {
        slot->ool_descs[i].copy = VM_MAP_COPY_NULL;
        slot->ool_descs[i].size = 0;
        slot->ool_descs[i].deallocate = false;
        slot->ool_descs[i].copy_option = MACH_MSG_PHYSICAL_COPY;
    }

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
 * Blocks if no messages available (via semaphore). Supports timeout:
 *   timeout_ms < 0  → block indefinitely (semaphore_wait)
 *   timeout_ms == 0 → non-blocking (semaphore_trywait)
 *   timeout_ms > 0  → block with timeout (semaphore_timedwait)
 *
 * Returns MACH_MSG_SUCCESS or error. Copies raw message bytes into user
 * buffer and returns the kernel port pointers + types for copyout.
 * OOL descriptors are transferred from the queue slot to the caller's
 * arrays for subsequent copyout processing.
 */
static mach_msg_return_t port_dequeue(struct ipc_port *port,
                                      void *buf,
                                      uint32_t buf_size,
                                      uint32_t *actual_size,
                                      struct ipc_port **reply_port_out,
                                      mach_msg_type_name_t *reply_type_out,
                                      mach_msg_type_name_t *dest_type_out,
                                      struct ipc_kmsg_ool *ool_descs_out,
                                      uint32_t *ool_count_out,
                                      int32_t timeout_ms)
{
    /* Block until a message is available, with optional timeout */
    if (timeout_ms < 0) {
        /* Indefinite wait — original behaviour */
        semaphore_wait(&port->msg_available);
    } else if (timeout_ms == 0) {
        /* Non-blocking */
        if (!semaphore_trywait(&port->msg_available))
            return MACH_RCV_TIMED_OUT;
    } else {
        /* Timed wait */
        if (!semaphore_timedwait(&port->msg_available, (uint32_t)timeout_ms))
            return MACH_RCV_TIMED_OUT;
    }

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

    /* Transfer OOL descriptor ownership from queue slot to caller */
    *ool_count_out = slot->ool_count;
    for (uint32_t i = 0; i < slot->ool_count; i++) {
        ool_descs_out[i] = slot->ool_descs[i];
        /* Clear slot's reference — ownership transferred */
        slot->ool_descs[i].copy = VM_MAP_COPY_NULL;
    }

    /* Clear the slot */
    slot->reply_port = NULL;
    slot->reply_type = MACH_MSG_TYPE_PORT_NONE;
    slot->dest_type  = MACH_MSG_TYPE_PORT_NONE;
    slot->ool_count  = 0;

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
    mach_msg_timeout_t timeout = (mach_msg_timeout_t)tf->regs[5];

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
        bool is_complex = (hdr.msgh_bits & MACH_MSGH_BITS_COMPLEX) != 0;

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
         * Step 3a: IOKit kobject interception
         *
         * On XNU, ipc_kobject_server() intercepts messages to kernel
         * object ports before normal queuing. If the destination port
         * has a kobject_type matching an IOKit type, we dispatch the
         * message synchronously to iokit_kobject_server(), which
         * processes the request and sends the reply directly.
         *
         * This must happen before OOL copyin since kobject handlers
         * read the raw user message directly.
         *
         * Reference: XNU osfmk/ipc/ipc_kobject.c
         */
        if (dest_port->kobject_type != IKOT_NONE) {
            bool handled = iokit_kobject_server(
                dest_port, (const void *)user_msg, send_size,
                reply_port, reply_copyin_type, cur->task);

            if (handled) {
                /* Release the dest reference (message was not queued) */
                spin_lock_irqsave(&dest_port->lock, &dflags);
                dest_port->refs--;
                spin_unlock_irqrestore(&dest_port->lock, dflags);

                /* Reply port ref was consumed by kobject handler */
                if (reply_port != NULL) {
                    spin_lock_irqsave(&reply_port->lock, &dflags);
                    reply_port->refs--;
                    spin_unlock_irqrestore(&reply_port->lock, dflags);
                }

                goto send_done;
            }
            /* If not handled, fall through to normal queuing */
        }

        /*
         * Step 3.5: Copyin complex message body (OOL descriptors)
         *
         * On XNU, ipc_kmsg_copyin() calls ipc_kmsg_copyin_body() after
         * copyin_header(). This processes the descriptor array in a
         * complex message, creating vm_map_copy objects for OOL data.
         *
         * We process the user message bytes in-place. The OOL descriptor
         * address fields get overwritten with vm_map_copy pointers.
         * The modified message (with kernel pointers in descriptors)
         * is then queued along with the ool_descs array.
         */
        struct ipc_kmsg_ool ool_descs[MACH_MSG_OOL_MAX];
        uint32_t ool_count = 0;

        for (uint32_t i = 0; i < MACH_MSG_OOL_MAX; i++) {
            ool_descs[i].copy = VM_MAP_COPY_NULL;
            ool_descs[i].size = 0;
            ool_descs[i].deallocate = false;
            ool_descs[i].copy_option = MACH_MSG_PHYSICAL_COPY;
        }

        if (is_complex) {
            struct vm_space *sender_vm = cur->task->vm_space;
            if (sender_vm == NULL) {
                /* Release port refs on failure */
                uint64_t pflags;
                spin_lock_irqsave(&dest_port->lock, &pflags);
                dest_port->refs--;
                spin_unlock_irqrestore(&dest_port->lock, pflags);
                if (reply_port != NULL) {
                    spin_lock_irqsave(&reply_port->lock, &pflags);
                    reply_port->refs--;
                    spin_unlock_irqrestore(&reply_port->lock, pflags);
                }
                return MACH_SEND_INVALID_DEST;
            }

            mach_msg_return_t ool_ret = ipc_kmsg_copyin_body(
                sender_vm, (uint8_t *)user_msg, send_size,
                ool_descs, &ool_count);
            if (ool_ret != MACH_MSG_SUCCESS) {
                /* Release port refs on failure */
                uint64_t pflags;
                spin_lock_irqsave(&dest_port->lock, &pflags);
                dest_port->refs--;
                spin_unlock_irqrestore(&dest_port->lock, pflags);
                if (reply_port != NULL) {
                    spin_lock_irqsave(&reply_port->lock, &pflags);
                    reply_port->refs--;
                    spin_unlock_irqrestore(&reply_port->lock, pflags);
                }
                return ool_ret;
            }
        }

        /*
         * Step 4: Enqueue the message with translated port rights and OOL descs
         *
         * The raw user message bytes are copied verbatim (with OOL descriptor
         * address fields overwritten to vm_map_copy pointers for complex
         * messages). The kernel port pointers, post-copyin types, and OOL
         * descriptors travel in the ipc_msg slot fields.
         */
        ret = port_enqueue(dest_port, (const void *)user_msg, send_size,
                           reply_port, reply_copyin_type, dest_copyin_type,
                           ool_descs, ool_count);
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
            /* Clean up OOL descriptors on enqueue failure */
            for (uint32_t i = 0; i < ool_count; i++) {
                if (ool_descs[i].copy != VM_MAP_COPY_NULL)
                    vm_map_copy_free(ool_descs[i].copy);
            }
            return ret;
        }

        /* Release the send-phase reference on dest (message is queued) */
        spin_lock_irqsave(&dest_port->lock, &dflags);
        dest_port->refs--;
        spin_unlock_irqrestore(&dest_port->lock, dflags);

    send_done: ;  /* Kobject interception jumps here after handling */
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

        /* Dequeue — blocks if empty. Returns raw bytes + translated ports + OOL.
         * If MACH_RCV_TIMEOUT is set, pass the timeout (in ms) to port_dequeue.
         * Otherwise pass -1 for indefinite blocking (original behaviour). */
        int32_t dequeue_timeout = -1;  /* default: block forever */
        if (option & MACH_RCV_TIMEOUT) {
            dequeue_timeout = (int32_t)timeout;  /* timeout in ms from mach_msg */
        }

        uint32_t actual = 0;
        struct ipc_port *msg_reply_port = NULL;
        mach_msg_type_name_t msg_reply_type = MACH_MSG_TYPE_PORT_NONE;
        mach_msg_type_name_t msg_dest_type  = MACH_MSG_TYPE_PORT_NONE;
        struct ipc_kmsg_ool rcv_ool_descs[MACH_MSG_OOL_MAX];
        uint32_t rcv_ool_count = 0;

        ret = port_dequeue(rcv_port, (void *)user_msg, rcv_size, &actual,
                           &msg_reply_port, &msg_reply_type, &msg_dest_type,
                           rcv_ool_descs, &rcv_ool_count, dequeue_timeout);
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

        /*
         * Step 4: Copyout OOL descriptors into receiver's address space
         *
         * On XNU, ipc_kmsg_copyout_body() processes the descriptor array
         * after the header has been rewritten. For each OOL descriptor,
         * it maps the kernel buffer into the receiver's VM and writes the
         * new VA back into the descriptor.
         *
         * This must happen after the header is written to user_msg (since
         * copyout_body reads the complex bit and body from the message),
         * and before the trailer.
         */
        if (rcv_ool_count > 0) {
            struct vm_space *rcv_vm = cur->task->vm_space;
            if (rcv_vm != NULL) {
                mach_msg_return_t ool_ret = ipc_kmsg_copyout_body(
                    rcv_vm, (uint8_t *)user_msg, actual,
                    rcv_ool_descs, rcv_ool_count);
                if (ool_ret != MACH_MSG_SUCCESS) {
                    /* OOL copyout failed — message is already in user buffer
                     * with zero/invalid OOL addresses. Log but continue;
                     * the receiver will see NULL OOL pointers. */
                    kprintf("[ipc] recv: OOL copyout failed (%u)\n", ool_ret);
                }
            } else {
                /* No vm_space — clean up OOL descriptors */
                for (uint32_t i = 0; i < rcv_ool_count; i++) {
                    if (rcv_ool_descs[i].copy != VM_MAP_COPY_NULL)
                        vm_map_copy_free(rcv_ool_descs[i].copy);
                }
                kprintf("[ipc] recv: receiver has no vm_space, OOL dropped\n");
            }
        }

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
 * Mach Trap: mach_port_mod_refs_trap
 *
 * Modify the reference count on a port right.
 *
 * x0 = target task port (ignored, operates on current task)
 * x1 = port name
 * x2 = right type (MACH_PORT_RIGHT_SEND = 0, MACH_PORT_RIGHT_RECEIVE = 1)
 * x3 = delta (positive to add refs, negative to remove)
 *
 * On XNU, this adjusts the user-reference count for the specified right.
 * In Kiseki's simplified IPC model:
 *   - delta > 0: no-op success (we don't track per-right refcounts)
 *   - delta < 0 with |delta| >= 1: deallocate the port name
 *   - delta == 0: no-op success
 *
 * Reference: XNU osfmk/kern/ipc_mig.c _kernelrpc_mach_port_mod_refs_trap
 * ============================================================================ */

kern_return_t mach_port_mod_refs_trap(struct trap_frame *tf)
{
    mach_port_name_t name = (mach_port_name_t)tf->regs[1];
    /* uint32_t right = (uint32_t)tf->regs[2]; — unused for now */
    int32_t delta = (int32_t)tf->regs[3];

    struct thread *cur = current_thread_get();
    if (cur == NULL || cur->task == NULL)
        return KERN_INVALID_ARGUMENT;

    struct ipc_space *space = cur->task->ipc_space;
    if (space == NULL)
        return KERN_INVALID_ARGUMENT;

    if (name == MACH_PORT_NULL || name == MACH_PORT_DEAD)
        return KERN_INVALID_NAME;

    if (delta == 0)
        return KERN_SUCCESS;

    if (delta > 0) {
        /*
         * Adding references — in XNU this bumps the user-reference
         * count. Our simplified model doesn't track per-right refcounts
         * so this is a successful no-op. The port entry exists as long
         * as it's in the IPC space.
         */
        return KERN_SUCCESS;
    }

    /*
     * delta < 0 — removing references. In XNU, when the user-ref
     * count drops to zero the right is destroyed. Since we don't
     * track refcounts, any negative delta deallocates the name.
     */
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
         * Allow re-check-in if:
         *   1. The receiver is init/launchd (PID 1) — it pre-created the port
         *   2. The previous receiver task has exited (daemon crashed/restarted)
         *
         * On macOS, launchd revokes the receive right from a crashed daemon's
         * port and re-creates it for the relaunched instance. We achieve the
         * same effect by checking if the previous owner is still alive.
         */
        pid_t prev_pid = service_port->receiver->pid;
        bool receiver_is_init = (prev_pid == 1);
        bool receiver_is_dead = false;

        if (!receiver_is_init) {
            struct proc *prev_proc = proc_find(prev_pid);
            receiver_is_dead = (prev_proc == NULL || prev_proc->p_exited);
        }

        if (!receiver_is_init && !receiver_is_dead) {
            spin_unlock_irqrestore(&service_port->lock, pflags);
            kprintf("[bootstrap] check_in '%s': already claimed by task %d\n",
                    user_name, prev_pid);
            return KERN_NOT_RECEIVER;
        }

        if (receiver_is_dead) {
            kprintf("[bootstrap] check_in '%s': previous owner (pid %d) exited, "
                    "allowing re-claim by task %d\n",
                    user_name, prev_pid, cur->task->pid);
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

/* ============================================================================
 * bootstrap_register_kernel - Register a kernel service port in bootstrap
 *
 * Kernel-side equivalent of bootstrap_register_trap(). Used by kernel
 * subsystems (e.g., IOKit) to register service ports in the bootstrap
 * namespace so that userland processes can look them up.
 *
 * Unlike the trap version, this takes direct kernel pointers — no
 * user-space copyin, no IPC space lookup.
 *
 * Reference: XNU ipc_bootstrap.c, bootstrap_register()
 * ============================================================================ */

kern_return_t
bootstrap_register_kernel(const char *name, struct ipc_port *port)
{
    if (name == NULL || port == NULL)
        return KERN_INVALID_ARGUMENT;

    /* Validate name length */
    uint32_t len = ipc_strlen(name);
    if (len == 0 || len >= BOOTSTRAP_MAX_NAME_LEN)
        return KERN_INVALID_ARGUMENT;

    uint64_t flags;
    spin_lock_irqsave(&bootstrap_lock, &flags);

    /* Check for duplicate name — update existing entry */
    for (uint32_t i = 0; i < BOOTSTRAP_MAX_SERVICES; i++) {
        if (bootstrap_registry[i].active &&
            ipc_strcmp(bootstrap_registry[i].name, name) == 0) {
            /* Replace the port, drop old ref, take new ref */
            struct ipc_port *old = bootstrap_registry[i].port;
            bootstrap_registry[i].port = port;
            port->refs++;
            if (old != NULL && old != port)
                old->refs--;

            spin_unlock_irqrestore(&bootstrap_lock, flags);
            kprintf("[bootstrap] kernel updated service '%s' -> port %p\n",
                    name, port);
            return KERN_SUCCESS;
        }
    }

    /* Find a free slot */
    for (uint32_t i = 0; i < BOOTSTRAP_MAX_SERVICES; i++) {
        if (!bootstrap_registry[i].active) {
            ipc_strncpy(bootstrap_registry[i].name, name,
                        BOOTSTRAP_MAX_NAME_LEN);
            bootstrap_registry[i].port = port;
            bootstrap_registry[i].active = true;
            port->refs++;

            spin_unlock_irqrestore(&bootstrap_lock, flags);
            kprintf("[bootstrap] kernel registered service '%s' -> port %p\n",
                    name, port);
            return KERN_SUCCESS;
        }
    }

    spin_unlock_irqrestore(&bootstrap_lock, flags);
    kprintf("[bootstrap] registry full, cannot register kernel service '%s'\n",
            name);
    return KERN_NO_SPACE;
}

/* ============================================================================
 * ipc_port_send_kernel - Enqueue a message from kernel context
 *
 * Kernel-side equivalent of the send phase in mach_msg_trap(). Bypasses
 * all user-space copyin (port name resolution, disposition validation,
 * OOL copyin from user VA) since the message and port objects are
 * already in kernel memory.
 *
 * Used by IOKit's Mach message handler (iokit_mach.c) to send reply
 * messages back to userland clients after processing IOKit requests.
 *
 * Reference: XNU ipc_mqueue_send(), ipc_kmsg_send()
 * ============================================================================ */

mach_msg_return_t
ipc_port_send_kernel(struct ipc_port *port,
                     const void *msg_data,
                     uint32_t msg_size,
                     struct ipc_port *reply_port,
                     mach_msg_type_name_t reply_type,
                     mach_msg_type_name_t dest_type,
                     struct ipc_kmsg_ool *ool_descs,
                     uint32_t ool_count)
{
    if (port == NULL || msg_data == NULL || msg_size == 0)
        return MACH_SEND_INVALID_DEST;

    if (!port->active)
        return MACH_SEND_INVALID_DEST;

    if (msg_size > MACH_MSG_SIZE_MAX)
        return MACH_SEND_INVALID_HEADER;

    return port_enqueue(port, msg_data, msg_size,
                        reply_port, reply_type, dest_type,
                        ool_descs, ool_count);
}
