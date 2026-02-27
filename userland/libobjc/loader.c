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
		fprintf(stderr, "[libobjc] init_runtime: begin\n");
		// Create the main runtime lock.  This is not safe in theory, but in
		// practice the first time that this function is called will be in the
		// loader, from the main thread.  Future loaders may run concurrently,
		// but that is likely to break the semantics of a lot of languages, so
		// we don't have to worry about it for a long time.
		//
		// The only case when this can potentially go badly wrong is when a
		// pure-C main() function spawns two threads which then, concurrently,
		// call dlopen() or equivalent, and the platform's implementation of
		// this does not perform any synchronization.
		INIT_LOCK(runtime_mutex);
		fprintf(stderr, "[libobjc] init_runtime: INIT_LOCK done\n");
		// Create the various tables that the runtime needs.
		init_selector_tables();
		fprintf(stderr, "[libobjc] init_runtime: init_selector_tables done\n");
		init_dispatch_tables();
		fprintf(stderr, "[libobjc] init_runtime: init_dispatch_tables done\n");
		init_protocol_table();
		fprintf(stderr, "[libobjc] init_runtime: init_protocol_table done\n");
		init_class_tables();
		fprintf(stderr, "[libobjc] init_runtime: init_class_tables done\n");
		init_alias_table();
		fprintf(stderr, "[libobjc] init_runtime: init_alias_table done\n");
		init_early_blocks();
		fprintf(stderr, "[libobjc] init_runtime: init_early_blocks done\n");
		init_arc();
		fprintf(stderr, "[libobjc] init_runtime: init_arc done\n");
#if defined(EMBEDDED_BLOCKS_RUNTIME)
		init_trampolines();
		fprintf(stderr, "[libobjc] init_runtime: init_trampolines done\n");
#endif
		init_builtin_classes();
		fprintf(stderr, "[libobjc] init_runtime: init_builtin_classes done\n");
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
		fprintf(stderr, "[libobjc] init_runtime: complete\n");
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
	fprintf(stderr, "[libobjc] __objc_exec_class: enter, module=%p\n", (void*)module);
	if (module) {
		fprintf(stderr, "[libobjc]   module version=%lu size=%lu name=%s symtab=%p\n",
			module->version, module->size,
			module->name ? module->name : "(null)",
			(void*)module->symbol_table);
	}

	init_runtime();
	fprintf(stderr, "[libobjc] __objc_exec_class: init_runtime done\n");

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
	fprintf(stderr, "[libobjc] __objc_exec_class: ABI check done (ABI=%d)\n", (int)CurrentABI);

	// Check that this module uses an ABI version that we recognise.  
	// In future, we should pass the ABI version to the class / category load
	// functions so that we can change various structures more easily.
	if (!objc_check_abi_version(module)) {
		fprintf(stderr, "[libobjc] __objc_exec_class: ABI version check FAILED!\n");
		abort();
	}
	fprintf(stderr, "[libobjc] __objc_exec_class: ABI version OK\n");


	// The runtime mutex is held for the entire duration of a load.  It does
	// not need to be acquired or released in any of the called load functions.
	fprintf(stderr, "[libobjc] __objc_exec_class: about to LOCK_RUNTIME_FOR_SCOPE\n");
	LOCK_RUNTIME_FOR_SCOPE();
	fprintf(stderr, "[libobjc] __objc_exec_class: runtime lock acquired\n");

	struct objc_symbol_table_abi_8 *symbols = module->symbol_table;
	fprintf(stderr, "[libobjc] __objc_exec_class: symbols=%p sel_count=%lu class_count=%u cat_count=%u\n",
		(void*)symbols, symbols->selector_count, symbols->class_count, symbols->category_count);

	// Register all of the selectors used in this module.
	if (symbols->selectors)
	{
		fprintf(stderr, "[libobjc] __objc_exec_class: registering %lu selectors at %p\n",
			symbols->selector_count, (void*)symbols->selectors);
		objc_register_selector_array(symbols->selectors,
				symbols->selector_count);
		fprintf(stderr, "[libobjc] __objc_exec_class: selectors registered\n");
	}

	unsigned short defs = 0;
	// Load the classes from this module
	for (unsigned short i=0 ; i<symbols->class_count ; i++)
	{
		void *raw_def = symbols->definitions[defs];
		fprintf(stderr, "[libobjc] __objc_exec_class: loading class %u/%u def=%p\n",
			i, symbols->class_count, raw_def);
		Class upgraded = objc_upgrade_class(raw_def);
		fprintf(stderr, "[libobjc] __objc_exec_class: class upgraded to %p name=%s\n",
			(void*)upgraded, upgraded ? upgraded->name : "(null)");
		objc_load_class(upgraded);
		fprintf(stderr, "[libobjc] __objc_exec_class: class loaded\n");
		defs++;
	}
	unsigned int category_start = defs;
	// Load the categories from this module
	for (unsigned short i=0 ; i<symbols->category_count; i++)
	{
		fprintf(stderr, "[libobjc] __objc_exec_class: loading category %u/%u\n",
			i, symbols->category_count);
		objc_try_load_category(objc_upgrade_category(symbols->definitions[defs++]));
		fprintf(stderr, "[libobjc] __objc_exec_class: category loaded\n");
	}
	// Load the static instances
	fprintf(stderr, "[libobjc] __objc_exec_class: loading statics, defs=%u\n", defs);
	struct objc_static_instance_list **statics = (void*)symbols->definitions[defs];
	while (NULL != statics && NULL != *statics)
	{
		objc_init_statics(*(statics++));
	}
	fprintf(stderr, "[libobjc] __objc_exec_class: statics done\n");

	// Load categories and statics that were deferred.
	objc_load_buffered_categories();
	fprintf(stderr, "[libobjc] __objc_exec_class: buffered categories done\n");
	objc_init_buffered_statics();
	fprintf(stderr, "[libobjc] __objc_exec_class: buffered statics done\n");
	// Fix up the class links for loaded classes.
	objc_resolve_class_links();
	fprintf(stderr, "[libobjc] __objc_exec_class: class links resolved\n");
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
	fprintf(stderr, "[libobjc] __objc_exec_class: COMPLETE for module %s\n",
		module->name ? module->name : "(null)");
}
#endif
