/*
 * Kiseki OS - IOKit Base Object (io_object)
 *
 * Root of the IOKit class hierarchy, equivalent to XNU's OSObject.
 * Every IOKit object (IORegistryEntry, IOService, IOUserClient, etc.)
 * starts with an embedded io_object as its first field, enabling safe
 * upcasting via pointer cast.
 *
 * Virtual dispatch is achieved through vtable function pointer structs.
 * Each "class" has a corresponding vtable struct whose first field is
 * the parent's vtable, mirroring C++ single-inheritance vtables.
 *
 * Reference: XNU libkern/c++/OSObject.h, iokit/Kernel/IOService.cpp
 */

#ifndef _IOKIT_IO_OBJECT_H
#define _IOKIT_IO_OBJECT_H

#include <iokit/iokit_types.h>
#include <kern/sync.h>

/* Forward declaration for Mach port linkage */
struct ipc_port;

/* ============================================================================
 * IOKit Class Metadata
 *
 * Each IOKit "class" has a static metadata struct that describes it.
 * This replaces XNU's OSMetaClass. Used for RTTI-style casting and
 * the IOKit registry's class-based matching.
 *
 * Reference: XNU libkern/c++/OSMetaClass.h
 * ============================================================================ */

struct io_class_meta {
    const char              *class_name;    /* e.g. "IOService" */
    const struct io_class_meta *super_meta; /* Parent class metadata */
    uint32_t                instance_size;  /* sizeof(struct io_*) */
};

/* ============================================================================
 * io_object_vtable - Virtual method table for io_object
 *
 * Base vtable. Subclass vtables embed this as their first field.
 * ============================================================================ */

struct io_object_vtable {
    /*
     * free - Release resources when refcount reaches zero.
     *
     * Equivalent to OSObject::free(). Subclasses override to
     * clean up their own resources before calling the parent's free.
     */
    void (*free)(struct io_object *obj);
};

/* ============================================================================
 * io_object - Base IOKit object
 *
 * Equivalent to XNU's OSObject. Contains:
 *   - vtable pointer for virtual dispatch
 *   - class metadata for RTTI
 *   - reference count (atomic, not under lock)
 *   - retain count starts at 1 on allocation
 *
 * Reference: XNU libkern/c++/OSObject.h
 * ============================================================================ */

struct io_object {
    const struct io_object_vtable   *vtable;    /* Virtual method table */
    const struct io_class_meta      *meta;      /* Class metadata (RTTI) */
    volatile int32_t                retain_count; /* Reference count (starts at 1) */
    uint32_t                        _pad;
    struct ipc_port                 *iokit_port; /* Mach port for this object (kobject) */
};

/* ============================================================================
 * io_object API
 * ============================================================================ */

/*
 * io_object_init - Initialise base fields of an io_object.
 *
 * Called by subclass init functions. Sets vtable, meta, retain_count=1.
 *
 * @obj:    Object to initialise
 * @vtable: Vtable for this object's concrete class
 * @meta:   Class metadata
 */
void io_object_init(struct io_object *obj,
                    const struct io_object_vtable *vtable,
                    const struct io_class_meta *meta);

/*
 * io_object_retain - Increment reference count.
 *
 * Reference: XNU OSObject::retain()
 */
void io_object_retain(struct io_object *obj);

/*
 * io_object_release - Decrement reference count; free if zero.
 *
 * When the retain count reaches zero, calls obj->vtable->free(obj).
 *
 * Reference: XNU OSObject::release()
 */
void io_object_release(struct io_object *obj);

/*
 * io_object_get_retain_count - Return current retain count.
 *
 * Reference: XNU OSObject::getRetainCount()
 */
int32_t io_object_get_retain_count(struct io_object *obj);

/*
 * io_object_is_class - Check if an object is an instance of a class.
 *
 * Walks the class metadata chain (meta -> super_meta) looking for
 * a match. Equivalent to XNU's OSMetaClass::checkMetaCast().
 *
 * @obj:        Object to check
 * @target_meta: Target class metadata
 *
 * Returns true if obj is an instance of the target class or a subclass.
 */
bool io_object_is_class(struct io_object *obj,
                        const struct io_class_meta *target_meta);

/*
 * io_object_cast - Safe downcast.
 *
 * Returns obj if it is an instance of target_meta (or subclass),
 * NULL otherwise.
 */
void *io_object_cast(struct io_object *obj,
                     const struct io_class_meta *target_meta);

/* ============================================================================
 * Class Metadata Declarations
 *
 * Each IOKit class defines a global io_class_meta. These are used by
 * io_object_is_class() and the registry's matching algorithm.
 * ============================================================================ */

extern const struct io_class_meta io_object_meta;

/* ============================================================================
 * Static Pool Management
 *
 * IOKit objects are allocated from static pools (no kernel heap).
 * Each concrete class manages its own pool.
 * ============================================================================ */

#define IOKIT_OBJECT_POOL_SIZE  256

#endif /* _IOKIT_IO_OBJECT_H */
