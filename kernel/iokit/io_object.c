/*
 * Kiseki OS - IOKit Base Object Implementation
 *
 * Implements reference counting, RTTI-style casting, and base vtable
 * for all IOKit objects. Equivalent to XNU's OSObject.cpp.
 *
 * Reference: XNU libkern/c++/OSObject.cpp
 */

#include <iokit/io_object.h>
#include <kern/kprintf.h>

/* ============================================================================
 * Class Metadata
 * ============================================================================ */

const struct io_class_meta io_object_meta = {
    .class_name     = "IOObject",
    .super_meta     = NULL,         /* Root of the hierarchy */
    .instance_size  = sizeof(struct io_object),
};

/* ============================================================================
 * Default vtable
 *
 * The base io_object's free does nothing — subclasses override this.
 * ============================================================================ */

static void io_object_default_free(struct io_object *obj)
{
    (void)obj;
    /* Base class free is a no-op. Subclass vtables override this. */
}

static const struct io_object_vtable io_object_default_vtable = {
    .free = io_object_default_free,
};

/* ============================================================================
 * io_object_init
 * ============================================================================ */

void
io_object_init(struct io_object *obj,
               const struct io_object_vtable *vtable,
               const struct io_class_meta *meta)
{
    obj->vtable = vtable ? vtable : &io_object_default_vtable;
    obj->meta = meta ? meta : &io_object_meta;
    obj->retain_count = 1;
    obj->_pad = 0;
    obj->iokit_port = NULL;
}

/* ============================================================================
 * Reference Counting
 *
 * Uses GCC built-in atomics for thread-safe refcounting.
 * On XNU, OSObject uses OSIncrementAtomic / OSDecrementAtomic.
 * ============================================================================ */

void
io_object_retain(struct io_object *obj)
{
    if (!obj)
        return;
    __atomic_add_fetch(&obj->retain_count, 1, __ATOMIC_RELAXED);
}

void
io_object_release(struct io_object *obj)
{
    if (!obj)
        return;

    int32_t old = __atomic_sub_fetch(&obj->retain_count, 1, __ATOMIC_ACQ_REL);
    if (old == 0) {
        /* Retain count reached zero — invoke virtual free */
        if (obj->vtable && obj->vtable->free)
            obj->vtable->free(obj);
    } else if (old < 0) {
        /* Over-release detected — this is a bug */
        kprintf("IOKit: PANIC: over-release of %s object %p (retain_count=%d)\n",
                obj->meta ? obj->meta->class_name : "unknown", obj, old);
    }
}

int32_t
io_object_get_retain_count(struct io_object *obj)
{
    if (!obj)
        return 0;
    return __atomic_load_n(&obj->retain_count, __ATOMIC_RELAXED);
}

/* ============================================================================
 * RTTI / Class Casting
 *
 * Walks the metadata chain to determine if an object is an instance
 * of a given class (or any of its superclasses).
 *
 * On XNU, this is OSMetaClass::checkMetaCast() which walks the
 * OSMetaClass::superClassLink chain.
 *
 * Reference: XNU libkern/c++/OSMetaClass.cpp::checkMetaCast()
 * ============================================================================ */

bool
io_object_is_class(struct io_object *obj,
                   const struct io_class_meta *target_meta)
{
    if (!obj || !target_meta)
        return false;

    const struct io_class_meta *m = obj->meta;
    while (m) {
        if (m == target_meta)
            return true;
        m = m->super_meta;
    }
    return false;
}

void *
io_object_cast(struct io_object *obj,
               const struct io_class_meta *target_meta)
{
    if (io_object_is_class(obj, target_meta))
        return (void *)obj;
    return NULL;
}
