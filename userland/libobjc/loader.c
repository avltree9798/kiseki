#include <stdlib.h>
#include <assert.h>
#include "objc/runtime.h"
#include "objc/objc-auto.h"
#include "objc/objc-arc.h"
#include "lock.h"
#include "loader.h"
#include "visibility.h"
#include "legacy.h"
#ifdef ENABLE_GC
#include <gc/gc.h>
#endif
#include <stdio.h>
#include <string.h>

/**
 * Runtime lock.  This is exposed in 
 */
PRIVATE mutex_t runtime_mutex;
LEGACY void *__objc_runtime_mutex = &runtime_mutex;

void log_selector_memory_usage(void);

static void log_memory_stats(void)
{
	log_selector_memory_usage();
}

/* Number of threads that are alive.  */
int __objc_runtime_threads_alive = 1;			/* !T:MUTEX */

// libdispatch hooks for registering threads
__attribute__((weak)) void (*dispatch_begin_thread_4GC)(void);
__attribute__((weak)) void (*dispatch_end_thread_4GC)(void);
__attribute__((weak)) void *(*_dispatch_begin_NSAutoReleasePool)(void);
__attribute__((weak)) void (*_dispatch_end_NSAutoReleasePool)(void *);

static void init_runtime(void)
{
	static BOOL first_run = YES;
	if (first_run)
	{
		INIT_LOCK(runtime_mutex);
		init_selector_tables();
		init_dispatch_tables();
		init_protocol_table();
		init_class_tables();
		init_alias_table();
		init_early_blocks();
		init_arc();
#if defined(EMBEDDED_BLOCKS_RUNTIME)
		init_trampolines();
#endif
		init_builtin_classes();
		first_run = NO;
		if (getenv("LIBOBJC_MEMORY_PROFILE"))
		{
			atexit(log_memory_stats);
		}
		if (dispatch_begin_thread_4GC != 0) {
			dispatch_begin_thread_4GC = objc_registerThreadWithCollector;
		}
		if (dispatch_end_thread_4GC != 0) {
			dispatch_end_thread_4GC = objc_unregisterThreadWithCollector;
		}
		if (_dispatch_begin_NSAutoReleasePool != 0) {
			_dispatch_begin_NSAutoReleasePool = objc_autoreleasePoolPush;
		}
		if (_dispatch_end_NSAutoReleasePool != 0) {
			_dispatch_end_NSAutoReleasePool = objc_autoreleasePoolPop;
		}
	}
}

/**
 * Structure for a class alias.
 */
struct objc_alias
{
	/**
	 * The name by which this class is referenced.
	 */
	const char *alias_name;
	/**
	 * A pointer to the indirection variable for this class.
	 */
	Class *alias;
};

/**
 * Type of the NSConstantString structure.
 */
struct nsstr
{
	/** Class pointer. */
	id isa;
	/**
	 * Flags.  Low 2 bits store the encoding:
	 * 0: ASCII
	 * 1: UTF-8
	 * 2: UTF-16
	 * 3: UTF-32
	 *
	 * Low 16 bits are reserved for the compiler, high 32 bits are reserved for
	 * the Foundation framework.
	 */
	uint32_t flags;
	/**
	 * Number of UTF-16 code units in the string.
	 */
	uint32_t length;
	/**
	 * Number of bytes in the string.
	 */
	uint32_t size;
	/**
	 * Hash (Foundation framework defines the hash algorithm).
	 */
	uint32_t hash;
	/**
	 * Character data.
	 */
	const char *data;
};

// begin: objc_init
struct objc_init
{
	uint64_t version;
	SEL sel_begin;
	SEL sel_end;
	Class *cls_begin;
	Class *cls_end;
	Class *cls_ref_begin;
	Class *cls_ref_end;
	struct objc_category *cat_begin;
	struct objc_category *cat_end;
	struct objc_protocol *proto_begin;
	struct objc_protocol *proto_end;
	struct objc_protocol **proto_ref_begin;
	struct objc_protocol **proto_ref_end;
	struct objc_alias *alias_begin;
	struct objc_alias *alias_end;
	struct nsstr *strings_begin;
	struct nsstr *strings_end;
};
// end: objc_init

#ifdef DEBUG_LOADING
#include <dlfcn.h>
#endif

static enum {
	LegacyABI,
	NewABI,
	UnknownABI
} CurrentABI = UnknownABI;

void registerProtocol(Protocol *proto);

/*
 * The clang gnustep-1.9 ABI (v2) emits method lists with a different layout
 * than what the runtime expects:
 *
 * Compiler v2 method list (no 'size' field, different method entry order):
 *   struct v2_method_list {
 *       struct v2_method_list *next;   // offset 0
 *       int count;                      // offset 8
 *       // 4 bytes padding              // offset 12
 *       struct { const char *sel_name; const char *types; IMP imp; } methods[];
 *                                       // offset 16, each 24 bytes
 *   };
 *
 * Runtime method list (with 'size' field, different method entry order):
 *   struct objc_method_list {
 *       struct objc_method_list *next;  // offset 0
 *       int count;                      // offset 8
 *       // 4 bytes padding              // offset 12
 *       size_t size;                    // offset 16
 *       struct { IMP imp; SEL selector; const char *types; } methods[];
 *                                       // offset 24, each 24 bytes
 *   };
 *
 * This function converts a compiler-generated v2 method list to the runtime
 * format.  It allocates a new method list and registers each selector.
 */
struct v2_method
{
	const char *sel_name;
	const char *types;
	IMP         imp;
};

struct v2_method_list
{
	struct v2_method_list *next;
	int                    count;
	struct v2_method       methods[];
};

static struct objc_method_list *upgradeV2MethodList(struct v2_method_list *old)
{
	if (old == NULL)
	{
		return NULL;
	}
	if (old->count == 0)
	{
		return NULL;
	}
	struct objc_method_list *l = calloc(1,
		sizeof(struct objc_method_list) + old->count * sizeof(struct objc_method));
	if (!l)
	{
		return NULL;
	}
	l->count = old->count;
	l->size = sizeof(struct objc_method);
	if (old->next)
	{
		l->next = upgradeV2MethodList(old->next);
	}
	for (int i = 0 ; i < old->count ; i++)
	{
		l->methods[i].imp = old->methods[i].imp;
		/*
		 * Create a SEL from the name+types. We use sel_registerTypedName_np
		 * when types are available, otherwise sel_registerName.
		 */
		if (old->methods[i].types)
		{
			l->methods[i].selector = sel_registerTypedName_np(
				old->methods[i].sel_name, old->methods[i].types);
		}
		else
		{
			l->methods[i].selector = sel_registerName(old->methods[i].sel_name);
		}
		l->methods[i].types = old->methods[i].types;
	}
	return l;
}

/**
 * Upgrade method lists on a v2 ABI class (and its metaclass) from the
 * compiler-generated format to the runtime format.
 */
static void upgradeV2ClassMethodLists(Class cls)
{
	if (cls->methods)
	{
		cls->methods = upgradeV2MethodList(
			(struct v2_method_list *)cls->methods);
	}
	if (cls->isa && cls->isa->methods)
	{
		cls->isa->methods = upgradeV2MethodList(
			(struct v2_method_list *)cls->isa->methods);
	}
}

OBJC_PUBLIC void __objc_load(struct objc_init *init)
{
	init_runtime();
#ifdef DEBUG_LOADING
	Dl_info info;
	if (dladdr(init, &info))
	{
		fprintf(stderr, "Loading %p from object: %s (%p)\n", init, info.dli_fname, __builtin_return_address(0));
	}
	else
	{
		fprintf(stderr, "Loading %p from unknown object\n", init);
	}
#endif
	LOCK_RUNTIME_FOR_SCOPE();
	BOOL isFirstLoad = NO;
	switch (CurrentABI)
	{
		case LegacyABI:
			fprintf(stderr, "Version 2 Objective-C ABI may not be mixed with earlier versions.\n");
			abort();
		case UnknownABI:
			isFirstLoad = YES;
			CurrentABI = NewABI;
			break;
		case NewABI:
			break;
	}

	// If we've already loaded this module, don't load it again.
	if (init->version == ULONG_MAX)
	{
		return;
	}

	assert(init->version == 0);
	assert((((uintptr_t)init->sel_end-(uintptr_t)init->sel_begin) % sizeof(*init->sel_begin)) == 0);
	assert((((uintptr_t)init->cls_end-(uintptr_t)init->cls_begin) % sizeof(*init->cls_begin)) == 0);
	assert((((uintptr_t)init->cat_end-(uintptr_t)init->cat_begin) % sizeof(*init->cat_begin)) == 0);
	for (SEL sel = init->sel_begin ; sel < init->sel_end ; sel++)
	{
		if (sel->name == 0)
		{
			continue;
		}
		objc_register_selector(sel);
	}
	for (struct objc_protocol *proto = init->proto_begin ; proto < init->proto_end ;
	     proto++)
	{
		if (proto->name == NULL)
		{
			continue;
		}
		registerProtocol((struct objc_protocol*)proto);
	}
	for (struct objc_protocol **proto = init->proto_ref_begin ; proto < init->proto_ref_end ;
	     proto++)
	{
		if (*proto == NULL)
		{
			continue;
		}
		struct objc_protocol *p = objc_getProtocol((*proto)->name);
		assert(p);
		*proto = p;
	}
	int classesLoaded = 0;
	for (Class *cls = init->cls_begin ; cls < init->cls_end ; cls++)
	{
		if (*cls == NULL)
		{
			continue;
		}
#ifdef DEBUG_LOADING
		fprintf(stderr, "Loading class %s\n", (*cls)->name);
#endif
		/* Convert v2 ABI method lists to runtime format */
		upgradeV2ClassMethodLists(*cls);
		objc_load_class(*cls);
	}
	if (isFirstLoad && (classesLoaded == 0))
	{
		// As a special case, allow using legacy ABI code with a new runtime.
		CurrentABI = UnknownABI;
	}
#if 0
	// We currently don't do anything with these pointers.  They exist to
	// provide a level of indirection that will permit us to completely change
	// the `objc_class` struct without breaking the ABI (again)
	for (Class *cls = init->cls_ref_begin ; cls < init->cls_ref_end ; cls++)
	{
	}
#endif
	for (struct objc_category *cat = init->cat_begin ; cat < init->cat_end ;
	     cat++)
	{
		if ((cat == NULL) || (cat->class_name == NULL))
		{
			continue;
		}
		/* Convert v2 ABI category method lists to runtime format */
		if (cat->instance_methods)
		{
			cat->instance_methods = upgradeV2MethodList(
				(struct v2_method_list *)cat->instance_methods);
		}
		if (cat->class_methods)
		{
			cat->class_methods = upgradeV2MethodList(
				(struct v2_method_list *)cat->class_methods);
		}
		objc_try_load_category(cat);
#ifdef DEBUG_LOADING
		fprintf(stderr, "Loading category %s (%s)\n", cat->class_name, cat->name);
#endif
	}
	// Load categories and statics that were deferred.
	objc_load_buffered_categories();
	// Fix up the class links for loaded classes.
	objc_resolve_class_links();
	for (struct objc_category *cat = init->cat_begin ; cat < init->cat_end ;
	     cat++)
	{
		Class class = (Class)objc_getClass(cat->class_name);
		if ((Nil != class) && 
		    objc_test_class_flag(class, objc_class_flag_resolved))
		{
			objc_send_load_message(class);
		}
	}
	// Register aliases
	for (struct objc_alias *alias = init->alias_begin ; alias < init->alias_end ;
	     alias++)
	{
		if (alias->alias_name)
		{
			class_registerAlias_np(*alias->alias, alias->alias_name);
		}
	}
#if 0
	// If future versions of the ABI need to do anything with constant strings,
	// they may do so here.
	for (struct nsstr *string = init->strings_begin ; string < init->strings_end ;
	     string++)
	{
		if (string->isa)
		{
		}
	}
#endif
	init->version = ULONG_MAX;
}

#ifdef OLDABI_COMPAT
OBJC_PUBLIC void __objc_exec_class(struct objc_module_abi_8 *module)
{
	/* Bug 17b: Check class name strings BEFORE any runtime operations.
	 * If corruption is already present at entry, it happened BEFORE
	 * this function was called (i.e., before the constructor ran).
	 * If not, the corruption happens inside objc_upgrade_class/calloc. */
	{
		struct objc_symbol_table_abi_8 *_syms = module->symbol_table;
		if (_syms && _syms->class_count > 4) {
			/* Check class[4] (NSArray in Foundation) */
			struct objc_class_gsv1 *_cls4 = 
				(struct objc_class_gsv1 *)_syms->definitions[4];
			if (_cls4 && _cls4->name) {
				const char *n = _cls4->name;
			}
		}
	}

	init_runtime();

	switch (CurrentABI)
	{
		case UnknownABI:
			CurrentABI = LegacyABI;
			break;
		case LegacyABI:
			break;
		case NewABI:
			fprintf(stderr, "Version 2 Objective-C ABI may not be mixed with earlier versions.\n");
			abort();
	}

	// Check that this module uses an ABI version that we recognise.  
	if (!objc_check_abi_version(module)) {
		abort();
	}

	LOCK_RUNTIME_FOR_SCOPE();

	struct objc_symbol_table_abi_8 *symbols = module->symbol_table;

	// Register all of the selectors used in this module.
	if (symbols->selectors)
	{
		objc_register_selector_array(symbols->selectors,
				symbols->selector_count);
	}

	/* Bug 17b: Check class[4] after selector registration */
	if (symbols->class_count > 4) {
		struct objc_class_gsv1 *_cls4b = 
			(struct objc_class_gsv1 *)symbols->definitions[4];
		if (_cls4b && _cls4b->name) {
			const char *n = _cls4b->name;
		}
	}

	unsigned short defs = 0;
	// Load the classes from this module
	for (unsigned short i=0 ; i<symbols->class_count ; i++)
	{
		void *raw_def = symbols->definitions[defs];
		struct objc_class_gsv1 *raw_cls = (struct objc_class_gsv1 *)raw_def;
		Class upgraded = objc_upgrade_class(raw_def);
		objc_load_class(upgraded);
		defs++;
	}
	unsigned int category_start = defs;
	// Load the categories from this module
	for (unsigned short i=0 ; i<symbols->category_count; i++)
	{
		objc_try_load_category(objc_upgrade_category(symbols->definitions[defs++]));
	}
	// Load the static instances
	struct objc_static_instance_list **statics = (void*)symbols->definitions[defs];
	while (NULL != statics && NULL != *statics)
	{
		objc_init_statics(*(statics++));
	}

	// Load categories and statics that were deferred.
	objc_load_buffered_categories();
	objc_init_buffered_statics();
	// Fix up the class links for loaded classes.
	objc_resolve_class_links();
	for (unsigned short i=0 ; i<symbols->category_count; i++)
	{
		struct objc_category *cat = (struct objc_category*)
			symbols->definitions[category_start++];
		Class class = (Class)objc_getClass(cat->class_name);
		if ((Nil != class) && 
		    objc_test_class_flag(class, objc_class_flag_resolved))
		{
			objc_send_load_message(class);
		}
	}
}
#endif
