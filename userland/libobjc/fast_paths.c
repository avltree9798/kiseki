#include "objc/runtime.h"
#include "objc/message.h"
#include "class.h"
#include <stdio.h>

typedef struct _NSZone NSZone;

// Cached selectors for fast-path message sends
static SEL alloc_sel;
static SEL allocWithZone_sel;
static SEL init_sel;

static inline void fast_paths_init_sels(void)
{
	if (!alloc_sel)
	{
		alloc_sel = sel_registerName("alloc");
		allocWithZone_sel = sel_registerName("allocWithZone:");
		init_sel = sel_registerName("init");
	}
}

OBJC_PUBLIC
id
objc_alloc(Class cls)
{
	if (UNLIKELY(cls == nil))
	{
		return nil;
	}
	if (UNLIKELY(!objc_test_class_flag(cls->isa, objc_class_flag_initialized)))
	{
		objc_send_initialize(cls);
	}
	if (objc_test_class_flag(cls->isa, objc_class_flag_fast_alloc_init))
	{
		return class_createInstance(cls, 0);
	}
	fast_paths_init_sels();
	return ((id(*)(id, SEL))objc_msgSend)((id)cls, alloc_sel);
}

/**
 * Equivalent to [cls allocWithZone: null].  If there's a fast path opt-in, then this skips the message send.
 */
OBJC_PUBLIC
id
objc_allocWithZone(Class cls)
{
	if (UNLIKELY(cls == nil))
	{
		return nil;
	}
	if (UNLIKELY(!objc_test_class_flag(cls->isa, objc_class_flag_initialized)))
	{
		objc_send_initialize(cls);
	}
	if (objc_test_class_flag(cls->isa, objc_class_flag_fast_alloc_init))
	{
		return class_createInstance(cls, 0);
	}
	fast_paths_init_sels();
	return ((id(*)(id, SEL, NSZone*))objc_msgSend)((id)cls, allocWithZone_sel, NULL);
}

/**
 * Equivalent to [[cls alloc] init].  If there's a fast path opt-in, then this
 * skips the message send.
 */
OBJC_PUBLIC
id
objc_alloc_init(Class cls)
{
	if (UNLIKELY(cls == nil))
	{
		return nil;
	}
	id instance = objc_alloc(cls);
	// If +alloc was overwritten, it is not guaranteed that it returns
	// an instance of cls.
	cls = classForObject(instance);
	if (objc_test_class_flag(cls, objc_class_flag_fast_alloc_init))
	{
		return instance;
	}
	fast_paths_init_sels();
	return ((id(*)(id, SEL))objc_msgSend)(instance, init_sel);
}
