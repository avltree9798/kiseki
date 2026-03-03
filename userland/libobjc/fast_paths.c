#include "objc/runtime.h"
#include "objc/message.h"
#include "class.h"
#include <stdio.h>

typedef struct _NSZone NSZone;

/* ---- raw_write diagnostic for libobjc fast_paths ---- */
static void _fp_raw_write(const char *s)
{
	unsigned long len = 0;
	const char *p = s;
	while (*p++) len++;
	register long x16 __asm__("x16") = 4;
	register long x0  __asm__("x0")  = 2;
	register long x1  __asm__("x1")  = (long)s;
	register long x2  __asm__("x2")  = (long)len;
	__asm__ volatile("svc #0x80"
		: "+r"(x0)
		: "r"(x16), "r"(x1), "r"(x2)
		: "memory", "cc");
}
static void _fp_raw_hex(unsigned long val)
{
	char buf[19];
	buf[0] = '0'; buf[1] = 'x';
	for (int i = 15; i >= 0; i--) {
		int nibble = val & 0xf;
		buf[2 + i] = nibble < 10 ? '0' + nibble : 'a' + nibble - 10;
		val >>= 4;
	}
	buf[18] = '\0';
	_fp_raw_write(buf);
}
/* ---- end raw_write ---- */

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
		_fp_raw_write("[objc_alloc] INIT cls=");
		_fp_raw_write(cls->name ? cls->name : "(null)");
		_fp_raw_write("\n");
		objc_send_initialize(cls);
		_fp_raw_write("[objc_alloc] INIT done cls=");
		_fp_raw_write(cls->name ? cls->name : "(null)");
		_fp_raw_write("\n");
	}
	if (objc_test_class_flag(cls->isa, objc_class_flag_fast_alloc_init))
	{
		return class_createInstance(cls, 0);
	}
	fast_paths_init_sels();
	id result = ((id(*)(id, SEL))objc_msgSend)((id)cls, alloc_sel);
	return result;
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
