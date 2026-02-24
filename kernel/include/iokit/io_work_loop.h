/*
 * Kiseki OS - IOKit Work Loop & Event Sources
 *
 * IOWorkLoop provides a dedicated kernel thread for serialised driver
 * event processing. Event sources are chained onto the work loop and
 * polled/signalled when events occur.
 *
 * Event source hierarchy:
 *   io_event_source (abstract base)
 *     io_interrupt_event_source (hardware IRQ)
 *     io_command_gate (serialised method execution)
 *
 * Reference: XNU iokit/Kernel/IOWorkLoop.cpp,
 *            IOKit/IOEventSource.h, IOKit/IOInterruptEventSource.h,
 *            IOKit/IOCommandGate.h
 */

#ifndef _IOKIT_IO_WORK_LOOP_H
#define _IOKIT_IO_WORK_LOOP_H

#include <iokit/io_object.h>
#include <iokit/iokit_types.h>
#include <kern/thread.h>

/* Maximum event sources per work loop */
#define IO_WORK_LOOP_MAX_EVENT_SOURCES  16

/* ============================================================================
 * io_event_source - Abstract base for event sources
 *
 * Each event source is linked into a work loop's event chain.
 * When the work loop thread runs, it iterates the chain calling
 * checkForWork() on each source.
 *
 * Reference: XNU IOEventSource
 * ============================================================================ */

struct io_event_source;

/* Callback type for event source actions */
typedef void (*io_event_action_t)(struct io_service *owner, void *arg);

struct io_event_source {
    struct io_object        obj;

    /* Work loop this source is attached to */
    struct io_work_loop     *work_loop;

    /* Owning service */
    struct io_service       *owner;

    /* Chain linkage within work loop */
    struct io_event_source  *next;

    /* Enabled flag */
    bool                    enabled;

    /*
     * checkForWork - Called by the work loop thread.
     *
     * Returns true if work was done (loop should re-check all sources).
     */
    bool (*checkForWork)(struct io_event_source *source);

    /* Pool tracking */
    bool                    pool_allocated;
    uint32_t                pool_index;
};

/* ============================================================================
 * io_interrupt_event_source - Hardware interrupt event source
 *
 * Wraps a hardware IRQ. When the interrupt fires, it signals the
 * work loop thread. The work loop calls the action handler on its
 * dedicated thread (not in IRQ context).
 *
 * Reference: XNU IOInterruptEventSource
 * ============================================================================ */

struct io_interrupt_event_source {
    /* Base event source (MUST be first) */
    struct io_event_source  base;

    /* IRQ number (GIC) */
    uint32_t                irq;

    /* Action called when interrupt fires */
    io_event_action_t       action;

    /* Interrupt pending flag (set in IRQ handler, cleared by work loop) */
    volatile bool           interrupt_pending;

    /* Interrupt count (statistics) */
    uint64_t                interrupt_count;
};

/* ============================================================================
 * io_command_gate - Serialised method execution on work loop thread
 *
 * Allows arbitrary code to execute on the work loop thread, ensuring
 * serialisation with the driver's interrupt handlers.
 *
 * Reference: XNU IOCommandGate
 * ============================================================================ */

typedef IOReturn (*io_command_gate_action_t)(struct io_service *owner,
                                             void *arg0, void *arg1,
                                             void *arg2, void *arg3);

struct io_command_gate {
    /* Base event source (MUST be first) */
    struct io_event_source  base;

    /* Pending command */
    io_command_gate_action_t pending_action;
    void                    *pending_args[4];
    volatile bool           command_pending;
    volatile IOReturn       command_result;

    /* Signalling */
    bool                    waiting;
};

/* ============================================================================
 * io_work_loop - Dedicated driver thread
 *
 * Reference: XNU IOWorkLoop
 * ============================================================================ */

struct io_work_loop {
    struct io_object        obj;

    /* Event source chain (linked list) */
    struct io_event_source  *event_chain;
    uint32_t                event_source_count;

    /* Work loop thread */
    struct thread           *thread;

    /* Serialisation lock */
    mutex_t                 gate_lock;

    /* Thread signalling */
    volatile bool           work_pending;
    volatile bool           running;

    /* Pool tracking */
    bool                    pool_allocated;
    uint32_t                pool_index;
};

/* ============================================================================
 * IOWorkLoop API
 * ============================================================================ */

/*
 * io_work_loop_create - Create a new work loop with a dedicated thread.
 *
 * Reference: XNU IOWorkLoop::workLoop()
 */
struct io_work_loop *io_work_loop_create(const char *name);

/*
 * io_work_loop_add_event_source - Add an event source to the chain.
 *
 * Reference: XNU IOWorkLoop::addEventSource()
 */
IOReturn io_work_loop_add_event_source(struct io_work_loop *wl,
                                       struct io_event_source *source);

/*
 * io_work_loop_remove_event_source - Remove an event source.
 *
 * Reference: XNU IOWorkLoop::removeEventSource()
 */
IOReturn io_work_loop_remove_event_source(struct io_work_loop *wl,
                                          struct io_event_source *source);

/*
 * io_work_loop_signal - Signal the work loop thread to wake up.
 *
 * Called when new work is available (e.g., interrupt pending).
 */
void io_work_loop_signal(struct io_work_loop *wl);

/* ============================================================================
 * IOInterruptEventSource API
 * ============================================================================ */

/*
 * io_interrupt_event_source_create
 *
 * @owner:  Owning service
 * @action: Callback for interrupt handling (called on work loop thread)
 * @irq:    GIC IRQ number
 *
 * Reference: XNU IOInterruptEventSource::interruptEventSource()
 */
struct io_interrupt_event_source *
io_interrupt_event_source_create(struct io_service *owner,
                                 io_event_action_t action,
                                 uint32_t irq);

/*
 * io_interrupt_event_source_signal - Signal from IRQ handler.
 *
 * Called from the hardware interrupt handler (IRQ context).
 * Sets the pending flag and wakes the work loop.
 */
void io_interrupt_event_source_signal(struct io_interrupt_event_source *source);

/* ============================================================================
 * IOCommandGate API
 * ============================================================================ */

/*
 * io_command_gate_create
 *
 * @owner: Owning service
 *
 * Reference: XNU IOCommandGate::commandGate()
 */
struct io_command_gate *io_command_gate_create(struct io_service *owner);

/*
 * io_command_gate_run_action - Execute an action on the work loop thread.
 *
 * Blocks the caller until the action completes on the work loop thread.
 * This provides serialisation with interrupt handlers.
 *
 * @gate:   Command gate
 * @action: Function to execute
 * @arg0-3: Arguments passed to the action
 *
 * Returns the IOReturn from the action.
 *
 * Reference: XNU IOCommandGate::runAction()
 */
IOReturn io_command_gate_run_action(struct io_command_gate *gate,
                                    io_command_gate_action_t action,
                                    void *arg0, void *arg1,
                                    void *arg2, void *arg3);

/* ============================================================================
 * Class Metadata
 * ============================================================================ */

extern const struct io_class_meta io_work_loop_meta;
extern const struct io_class_meta io_event_source_meta;
extern const struct io_class_meta io_interrupt_event_source_meta;
extern const struct io_class_meta io_command_gate_meta;

/* ============================================================================
 * Static Pools
 * ============================================================================ */

#define IO_WORK_LOOP_POOL_SIZE                  32
#define IO_EVENT_SOURCE_POOL_SIZE               64
#define IO_INTERRUPT_EVENT_SOURCE_POOL_SIZE      32
#define IO_COMMAND_GATE_POOL_SIZE               32

#endif /* _IOKIT_IO_WORK_LOOP_H */
