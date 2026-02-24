/*
 * Kiseki OS - IOKit Work Loop & Event Sources Implementation
 *
 * Implements IOWorkLoop (dedicated kernel thread), IOInterruptEventSource,
 * and IOCommandGate for serialised driver event processing.
 *
 * Reference: XNU iokit/Kernel/IOWorkLoop.cpp,
 *            iokit/Kernel/IOInterruptEventSource.cpp,
 *            iokit/Kernel/IOCommandGate.cpp
 */

#include <iokit/io_work_loop.h>
#include <iokit/io_service.h>
#include <kern/kprintf.h>

/* ============================================================================
 * Class Metadata
 * ============================================================================ */

const struct io_class_meta io_work_loop_meta = {
    .class_name     = "IOWorkLoop",
    .super_meta     = &io_object_meta,
    .instance_size  = sizeof(struct io_work_loop),
};

const struct io_class_meta io_event_source_meta = {
    .class_name     = "IOEventSource",
    .super_meta     = &io_object_meta,
    .instance_size  = sizeof(struct io_event_source),
};

const struct io_class_meta io_interrupt_event_source_meta = {
    .class_name     = "IOInterruptEventSource",
    .super_meta     = &io_event_source_meta,
    .instance_size  = sizeof(struct io_interrupt_event_source),
};

const struct io_class_meta io_command_gate_meta = {
    .class_name     = "IOCommandGate",
    .super_meta     = &io_event_source_meta,
    .instance_size  = sizeof(struct io_command_gate),
};

/* ============================================================================
 * Static Pools
 * ============================================================================ */

static struct io_work_loop wl_pool[IO_WORK_LOOP_POOL_SIZE];
static bool wl_pool_used[IO_WORK_LOOP_POOL_SIZE];
static spinlock_t wl_pool_lock = SPINLOCK_INIT;

static struct io_interrupt_event_source ies_pool[IO_INTERRUPT_EVENT_SOURCE_POOL_SIZE];
static bool ies_pool_used[IO_INTERRUPT_EVENT_SOURCE_POOL_SIZE];
static spinlock_t ies_pool_lock = SPINLOCK_INIT;

static struct io_command_gate cg_pool[IO_COMMAND_GATE_POOL_SIZE];
static bool cg_pool_used[IO_COMMAND_GATE_POOL_SIZE];
static spinlock_t cg_pool_lock = SPINLOCK_INIT;

/* ============================================================================
 * Pool allocation helpers
 * ============================================================================ */

static struct io_work_loop *
wl_pool_alloc(void)
{
    uint64_t flags;
    spin_lock_irqsave(&wl_pool_lock, &flags);
    for (uint32_t i = 0; i < IO_WORK_LOOP_POOL_SIZE; i++) {
        if (!wl_pool_used[i]) {
            wl_pool_used[i] = true;
            uint8_t *p = (uint8_t *)&wl_pool[i];
            for (uint32_t j = 0; j < sizeof(struct io_work_loop); j++)
                p[j] = 0;
            wl_pool[i].pool_allocated = true;
            wl_pool[i].pool_index = i;
            spin_unlock_irqrestore(&wl_pool_lock, flags);
            return &wl_pool[i];
        }
    }
    spin_unlock_irqrestore(&wl_pool_lock, flags);
    return NULL;
}

static void
wl_pool_free(struct io_work_loop *wl)
{
    if (!wl || !wl->pool_allocated) return;
    uint64_t flags;
    spin_lock_irqsave(&wl_pool_lock, &flags);
    if (wl->pool_index < IO_WORK_LOOP_POOL_SIZE)
        wl_pool_used[wl->pool_index] = false;
    spin_unlock_irqrestore(&wl_pool_lock, flags);
}

static struct io_interrupt_event_source *
ies_pool_alloc(void)
{
    uint64_t flags;
    spin_lock_irqsave(&ies_pool_lock, &flags);
    for (uint32_t i = 0; i < IO_INTERRUPT_EVENT_SOURCE_POOL_SIZE; i++) {
        if (!ies_pool_used[i]) {
            ies_pool_used[i] = true;
            uint8_t *p = (uint8_t *)&ies_pool[i];
            for (uint32_t j = 0; j < sizeof(struct io_interrupt_event_source); j++)
                p[j] = 0;
            ies_pool[i].base.pool_allocated = true;
            ies_pool[i].base.pool_index = i;
            spin_unlock_irqrestore(&ies_pool_lock, flags);
            return &ies_pool[i];
        }
    }
    spin_unlock_irqrestore(&ies_pool_lock, flags);
    return NULL;
}

static struct io_command_gate *
cg_pool_alloc(void)
{
    uint64_t flags;
    spin_lock_irqsave(&cg_pool_lock, &flags);
    for (uint32_t i = 0; i < IO_COMMAND_GATE_POOL_SIZE; i++) {
        if (!cg_pool_used[i]) {
            cg_pool_used[i] = true;
            uint8_t *p = (uint8_t *)&cg_pool[i];
            for (uint32_t j = 0; j < sizeof(struct io_command_gate); j++)
                p[j] = 0;
            cg_pool[i].base.pool_allocated = true;
            cg_pool[i].base.pool_index = i;
            spin_unlock_irqrestore(&cg_pool_lock, flags);
            return &cg_pool[i];
        }
    }
    spin_unlock_irqrestore(&cg_pool_lock, flags);
    return NULL;
}

/* ============================================================================
 * Vtables
 * ============================================================================ */

static void wl_free(struct io_object *obj)
{
    struct io_work_loop *wl = (struct io_work_loop *)obj;
    wl->running = false;
    wl_pool_free(wl);
}

static const struct io_object_vtable wl_vtable = {
    .free = wl_free,
};

/* ============================================================================
 * Work Loop Thread
 *
 * The main loop: acquire the gate lock, iterate event sources calling
 * checkForWork(), release lock, sleep until signalled.
 *
 * Reference: XNU IOWorkLoop::threadMain()
 * ============================================================================ */

static void
io_work_loop_thread_func(void *arg)
{
    struct io_work_loop *wl = (struct io_work_loop *)arg;

    kprintf("IOKit: work loop thread started\n");

    while (wl->running) {
        /* Acquire the gate lock for serialisation */
        mutex_lock(&wl->gate_lock);

        bool more_work;
        do {
            more_work = false;

            /* Iterate event source chain */
            struct io_event_source *src = wl->event_chain;
            while (src) {
                if (src->enabled && src->checkForWork) {
                    if (src->checkForWork(src))
                        more_work = true;
                }
                src = src->next;
            }
        } while (more_work);

        wl->work_pending = false;

        mutex_unlock(&wl->gate_lock);

        /* Sleep until signalled */
        thread_sleep_on(wl, "IOWorkLoop");
    }
}

/* ============================================================================
 * IOWorkLoop API
 * ============================================================================ */

struct io_work_loop *
io_work_loop_create(const char *name)
{
    struct io_work_loop *wl = wl_pool_alloc();
    if (!wl)
        return NULL;

    io_object_init(&wl->obj, &wl_vtable, &io_work_loop_meta);

    wl->event_chain = NULL;
    wl->event_source_count = 0;
    mutex_init(&wl->gate_lock);
    wl->work_pending = false;
    wl->running = true;

    /* Create the dedicated kernel thread */
    wl->thread = thread_create(name ? name : "IOWorkLoop",
                               io_work_loop_thread_func, wl,
                               PRI_DEFAULT + 4);
    if (!wl->thread) {
        kprintf("IOKit: failed to create work loop thread\n");
        wl->running = false;
        wl_pool_free(wl);
        return NULL;
    }

    return wl;
}

IOReturn
io_work_loop_add_event_source(struct io_work_loop *wl,
                              struct io_event_source *source)
{
    if (!wl || !source)
        return kIOReturnBadArgument;

    mutex_lock(&wl->gate_lock);

    /* Prepend to chain */
    source->work_loop = wl;
    source->next = wl->event_chain;
    wl->event_chain = source;
    wl->event_source_count++;
    source->enabled = true;

    mutex_unlock(&wl->gate_lock);

    return kIOReturnSuccess;
}

IOReturn
io_work_loop_remove_event_source(struct io_work_loop *wl,
                                 struct io_event_source *source)
{
    if (!wl || !source)
        return kIOReturnBadArgument;

    mutex_lock(&wl->gate_lock);

    struct io_event_source **pp = &wl->event_chain;
    while (*pp) {
        if (*pp == source) {
            *pp = source->next;
            source->next = NULL;
            source->work_loop = NULL;
            source->enabled = false;
            wl->event_source_count--;
            mutex_unlock(&wl->gate_lock);
            return kIOReturnSuccess;
        }
        pp = &(*pp)->next;
    }

    mutex_unlock(&wl->gate_lock);
    return kIOReturnNotFound;
}

void
io_work_loop_signal(struct io_work_loop *wl)
{
    if (!wl)
        return;
    wl->work_pending = true;
    thread_wakeup_on(wl);
}

/* ============================================================================
 * IOInterruptEventSource
 *
 * Reference: XNU iokit/Kernel/IOInterruptEventSource.cpp
 * ============================================================================ */

static bool
ies_check_for_work(struct io_event_source *source)
{
    struct io_interrupt_event_source *ies =
        (struct io_interrupt_event_source *)source;

    if (!ies->interrupt_pending)
        return false;

    ies->interrupt_pending = false;
    ies->interrupt_count++;

    if (ies->action)
        ies->action(source->owner, NULL);

    return true;  /* Did work */
}

struct io_interrupt_event_source *
io_interrupt_event_source_create(struct io_service *owner,
                                 io_event_action_t action,
                                 uint32_t irq)
{
    struct io_interrupt_event_source *ies = ies_pool_alloc();
    if (!ies)
        return NULL;

    io_object_init(&ies->base.obj, NULL, &io_interrupt_event_source_meta);

    ies->base.owner = owner;
    ies->base.checkForWork = ies_check_for_work;
    ies->base.enabled = false;
    ies->base.next = NULL;
    ies->base.work_loop = NULL;

    ies->irq = irq;
    ies->action = action;
    ies->interrupt_pending = false;
    ies->interrupt_count = 0;

    return ies;
}

void
io_interrupt_event_source_signal(struct io_interrupt_event_source *source)
{
    if (!source)
        return;
    source->interrupt_pending = true;
    if (source->base.work_loop)
        io_work_loop_signal(source->base.work_loop);
}

/* ============================================================================
 * IOCommandGate
 *
 * Reference: XNU iokit/Kernel/IOCommandGate.cpp
 * ============================================================================ */

static bool
cg_check_for_work(struct io_event_source *source)
{
    struct io_command_gate *gate = (struct io_command_gate *)source;

    if (!gate->command_pending)
        return false;

    gate->command_pending = false;

    if (gate->pending_action) {
        gate->command_result = gate->pending_action(
            source->owner,
            gate->pending_args[0], gate->pending_args[1],
            gate->pending_args[2], gate->pending_args[3]);
    }

    /* Wake up the caller waiting in runAction */
    if (gate->waiting)
        thread_wakeup_on(gate);

    return true;
}

struct io_command_gate *
io_command_gate_create(struct io_service *owner)
{
    struct io_command_gate *gate = cg_pool_alloc();
    if (!gate)
        return NULL;

    io_object_init(&gate->base.obj, NULL, &io_command_gate_meta);

    gate->base.owner = owner;
    gate->base.checkForWork = cg_check_for_work;
    gate->base.enabled = false;
    gate->base.next = NULL;
    gate->base.work_loop = NULL;

    gate->pending_action = NULL;
    gate->command_pending = false;
    gate->command_result = kIOReturnSuccess;
    gate->waiting = false;

    return gate;
}

IOReturn
io_command_gate_run_action(struct io_command_gate *gate,
                           io_command_gate_action_t action,
                           void *arg0, void *arg1,
                           void *arg2, void *arg3)
{
    if (!gate || !action)
        return kIOReturnBadArgument;

    /*
     * If we're already on the work loop thread, execute directly.
     * Otherwise, post the command and sleep.
     */
    struct io_work_loop *wl = gate->base.work_loop;
    if (!wl)
        return kIOReturnNotAttached;

    /* Check if current thread is the work loop thread */
    if (current_thread_get() == wl->thread) {
        /* Direct execution — already serialised */
        return action(gate->base.owner, arg0, arg1, arg2, arg3);
    }

    /* Post the command and wait */
    gate->pending_action = action;
    gate->pending_args[0] = arg0;
    gate->pending_args[1] = arg1;
    gate->pending_args[2] = arg2;
    gate->pending_args[3] = arg3;
    gate->waiting = true;
    gate->command_pending = true;

    /* Signal the work loop */
    io_work_loop_signal(wl);

    /* Sleep until the work loop executes our command */
    thread_sleep_on(gate, "IOCommandGate::runAction");

    gate->waiting = false;

    return gate->command_result;
}
