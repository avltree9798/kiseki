/*
 * Kiseki OS - CoreFoundation.framework
 *
 * Freestanding implementation of Apple's CoreFoundation library.
 * This file is completely freestanding — it does NOT #include any
 * headers. All types are defined inline. Exported function signatures
 * match real macOS CoreFoundation exactly.
 *
 * Reference: apple-oss-distributions/CF (CF-1153.18)
 *            apple/swift-corelibs-foundation
 */

/* ============================================================================
 * Section 1: Visibility & Compiler Helpers
 * ============================================================================ */

#define EXPORT  __attribute__((visibility("default")))
#define HIDDEN  __attribute__((visibility("hidden")))

#define CF_INLINE static inline __attribute__((always_inline))

typedef _Bool bool;
#define true  1
#define false 0
#define NULL  ((void *)0)

/* ============================================================================
 * Section 2: Freestanding Type Definitions
 * ============================================================================ */

typedef unsigned char       uint8_t;
typedef unsigned short      uint16_t;
typedef unsigned int        uint32_t;
typedef unsigned long       uint64_t;
typedef signed char         int8_t;
typedef signed short        int16_t;
typedef signed int          int32_t;
typedef signed long         int64_t;
typedef unsigned long       size_t;
typedef signed long         ssize_t;
typedef unsigned long       uintptr_t;
typedef signed long         intptr_t;

/* Variadic arguments */
typedef __builtin_va_list   va_list;
#define va_start(ap, last)  __builtin_va_start(ap, last)
#define va_end(ap)          __builtin_va_end(ap)
#define va_arg(ap, type)    __builtin_va_arg(ap, type)
#define va_copy(dst, src)   __builtin_va_copy(dst, src)

/* ============================================================================
 * Section 3: Imported Functions from libSystem.B.dylib
 * ============================================================================ */

extern void *malloc(size_t size);
extern void *calloc(size_t count, size_t size);
extern void *realloc(void *ptr, size_t size);
extern void  free(void *ptr);
extern void  abort(void) __attribute__((noreturn));

extern void *memcpy(void *dst, const void *src, size_t n);
extern void *memmove(void *dst, const void *src, size_t n);
extern void *memset(void *s, int c, size_t n);
extern int   memcmp(const void *s1, const void *s2, size_t n);
extern void *memchr(const void *s, int c, size_t n);

extern size_t strlen(const char *s);
extern int    strcmp(const char *s1, const char *s2);
extern int    strncmp(const char *s1, const char *s2, size_t n);
extern char  *strcpy(char *dst, const char *src);
extern char  *strncpy(char *dst, const char *src, size_t n);
extern char  *strdup(const char *s);
extern char  *strstr(const char *haystack, const char *needle);
extern char  *strchr(const char *s, int c);
extern char  *strrchr(const char *s, int c);

extern long   strtol(const char *str, char **endptr, int base);
extern double strtod(const char *str, char **endptr);
extern int    atoi(const char *str);
extern double atof(const char *str);

extern int    snprintf(char *buf, size_t size, const char *fmt, ...);
extern int    vsnprintf(char *buf, size_t size, const char *fmt, va_list ap);
extern int    fprintf(void *stream, const char *fmt, ...);
extern size_t fwrite(const void *ptr, size_t size, size_t nmemb, void *stream);

extern void **__stderrp;
extern void **__stdoutp;
#define stderr (*__stderrp)
#define stdout (*__stdoutp)

extern void qsort(void *base, size_t nmemb, size_t size,
                   int (*compar)(const void *, const void *));

extern int gettimeofday(void *tv, void *tz);

/* pthread mutex — simplified signatures */
extern int pthread_mutex_init(void *mutex, const void *attr);
extern int pthread_mutex_lock(void *mutex);
extern int pthread_mutex_unlock(void *mutex);
extern int pthread_mutex_destroy(void *mutex);

/*
 * Bug 14 fix: pthread_mutex_t must be properly aligned for ARM64 exclusive
 * instructions (ldaxr/stlxr). Matches libSystem's definition.
 */
typedef struct {
    int             type;
    int             locked;
    unsigned long   owner;
    int             recursion;
    volatile int    spinlock;
} pthread_mutex_t;
extern int pthread_once(int *once_control, void (*init_routine)(void));

/* pthread TLS (thread-local storage) */
extern int   pthread_key_create(unsigned int *key, void (*destructor)(void *));
extern void *pthread_getspecific(unsigned int key);
extern int   pthread_setspecific(unsigned int key, const void *value);
extern unsigned long pthread_self(void);

/* Mach IPC — for CFRunLoop wakeup port */
typedef unsigned int mach_port_t;
typedef unsigned int mach_port_name_t;
typedef int          kern_return_t;
typedef unsigned int mach_msg_option_t;
typedef unsigned int mach_msg_size_t;
typedef unsigned int mach_msg_bits_t;
typedef int          mach_msg_id_t;
typedef int          mach_msg_return_t;
typedef int          mach_msg_timeout_t;

#define KERN_SUCCESS            0
#define MACH_PORT_NULL          0
#define MACH_PORT_RIGHT_RECEIVE 1
#define MACH_SEND_MSG           0x00000001u
#define MACH_RCV_MSG            0x00000002u
#define MACH_RCV_TIMEOUT        0x00000100u
#define MACH_RCV_TIMED_OUT      0x10004003
#define MACH_MSG_SUCCESS        0
#define MACH_MSGH_BITS(remote, local) ((remote) | ((local) << 8))
#define MACH_MSG_TYPE_MAKE_SEND 20

/* mach_msg_header_t — must match kernel layout exactly */
typedef struct {
    mach_msg_bits_t   msgh_bits;
    mach_msg_size_t   msgh_size;
    mach_port_name_t  msgh_remote_port;
    mach_port_name_t  msgh_local_port;
    mach_port_name_t  msgh_voucher_port;
    mach_msg_id_t     msgh_id;
} mach_msg_header_t;

extern mach_msg_return_t mach_msg(mach_msg_header_t *msg,
                                   mach_msg_option_t option,
                                   mach_msg_size_t send_size,
                                   mach_msg_size_t rcv_size,
                                   mach_port_name_t rcv_name,
                                   mach_msg_timeout_t timeout,
                                   mach_port_name_t notify);
extern kern_return_t mach_port_allocate(unsigned int task,
                                         unsigned int right,
                                         mach_port_t *name);
extern unsigned int mach_task_self(void);

/* nanosleep — for fallback timing */
struct timespec_cf {
    long tv_sec;
    long tv_nsec;
};
extern int nanosleep(const struct timespec_cf *req, struct timespec_cf *rem);


/* ============================================================================
 * Section 4: CoreFoundation Public Type Definitions
 *
 * These match the exact types from Apple's CFBase.h on LP64 (macOS arm64).
 * ============================================================================ */

typedef unsigned long   CFTypeID;
typedef unsigned long   CFOptionFlags;
typedef unsigned long   CFHashCode;
typedef signed long     CFIndex;

typedef const void *    CFTypeRef;

/* CFRange */
typedef struct {
    CFIndex location;
    CFIndex length;
} CFRange;

CF_INLINE CFRange CFRangeMake(CFIndex loc, CFIndex len) {
    CFRange r; r.location = loc; r.length = len; return r;
}

static const CFIndex kCFNotFound = -1;

/* CFComparisonResult */
typedef CFIndex CFComparisonResult;
#define kCFCompareLessThan    (-1L)
#define kCFCompareEqualTo     0L
#define kCFCompareGreaterThan 1L

typedef CFComparisonResult (*CFComparatorFunction)(const void *val1,
                                                    const void *val2,
                                                    void *context);

/* Mac-compatibility scalar types */
typedef bool                Boolean;
typedef unsigned char       UInt8;
typedef signed char         SInt8;
typedef unsigned short      UInt16;
typedef signed short        SInt16;
typedef unsigned int        UInt32;
typedef signed int          SInt32;
typedef uint64_t            UInt64;
typedef int64_t             SInt64;
typedef SInt32              OSStatus;
typedef float               Float32;
typedef double              Float64;
typedef unsigned short      UniChar;
typedef unsigned long       UniCharCount;
typedef UInt32              FourCharCode;
typedef FourCharCode        OSType;
typedef UInt8               Byte;
typedef SInt8               SignedByte;
typedef UInt32              UTF32Char;
typedef UInt16              UTF16Char;
typedef UInt8               UTF8Char;

/* ============================================================================
 * Section 5: Opaque Type Forward Declarations
 * ============================================================================ */

typedef const struct __CFAllocator * CFAllocatorRef;
typedef const struct __CFString *    CFStringRef;
typedef struct __CFString *          CFMutableStringRef;
typedef const struct __CFArray *     CFArrayRef;
typedef struct __CFArray *           CFMutableArrayRef;
typedef const struct __CFDictionary *CFDictionaryRef;
typedef struct __CFDictionary *      CFMutableDictionaryRef;
typedef const struct __CFSet *       CFSetRef;
typedef struct __CFSet *             CFMutableSetRef;
typedef const struct __CFNumber *    CFNumberRef;
typedef const struct __CFData *      CFDataRef;
typedef struct __CFData *            CFMutableDataRef;
typedef const struct __CFBoolean *   CFBooleanRef;
typedef const struct __CFNull *      CFNullRef;
typedef const struct __CFDate *      CFDateRef;
typedef const struct __CFAttributedString *   CFAttributedStringRef;
typedef struct __CFAttributedString *         CFMutableAttributedStringRef;
typedef CFTypeRef                    CFPropertyListRef;

/* Forward declare for callback signatures */
typedef const struct __CFRunLoop *       CFRunLoopRef;
typedef const struct __CFRunLoopSource * CFRunLoopSourceRef;
typedef const struct __CFRunLoopTimer *  CFRunLoopTimerRef;
typedef const struct __CFRunLoopObserver *CFRunLoopObserverRef;
typedef CFStringRef                      CFRunLoopMode;

/* ============================================================================
 * Section 6: CFStringEncoding (exact Apple values)
 * ============================================================================ */

typedef UInt32 CFStringEncoding;

#define kCFStringEncodingInvalidId       ((CFStringEncoding)0xFFFFFFFFU)
#define kCFStringEncodingMacRoman        ((CFStringEncoding)0)
#define kCFStringEncodingWindowsLatin1   ((CFStringEncoding)0x0500)
#define kCFStringEncodingISOLatin1       ((CFStringEncoding)0x0201)
#define kCFStringEncodingNextStepLatin   ((CFStringEncoding)0x0B01)
#define kCFStringEncodingASCII           ((CFStringEncoding)0x0600)
#define kCFStringEncodingUnicode         ((CFStringEncoding)0x0100)
#define kCFStringEncodingUTF8            ((CFStringEncoding)0x08000100)
#define kCFStringEncodingNonLossyASCII   ((CFStringEncoding)0x0BFF)
#define kCFStringEncodingUTF16           ((CFStringEncoding)0x0100)
#define kCFStringEncodingUTF16BE         ((CFStringEncoding)0x10000100)
#define kCFStringEncodingUTF16LE         ((CFStringEncoding)0x14000100)
#define kCFStringEncodingUTF32           ((CFStringEncoding)0x0c000100)
#define kCFStringEncodingUTF32BE         ((CFStringEncoding)0x18000100)
#define kCFStringEncodingUTF32LE         ((CFStringEncoding)0x1c000100)

/* ============================================================================
 * Section 7: CFStringCompareFlags
 * ============================================================================ */

typedef CFOptionFlags CFStringCompareFlags;
#define kCFCompareCaseInsensitive       1UL
#define kCFCompareBackwards             4UL
#define kCFCompareAnchored              8UL
#define kCFCompareNonliteral            16UL
#define kCFCompareLocalized             32UL
#define kCFCompareNumerically           64UL
#define kCFCompareDiacriticInsensitive  128UL
#define kCFCompareWidthInsensitive      256UL
#define kCFCompareForcedOrdering        512UL

/* ============================================================================
 * Section 8: CFNumberType (exact Apple values 1-16)
 * ============================================================================ */

typedef CFIndex CFNumberType;
#define kCFNumberSInt8Type      1
#define kCFNumberSInt16Type     2
#define kCFNumberSInt32Type     3
#define kCFNumberSInt64Type     4
#define kCFNumberFloat32Type    5
#define kCFNumberFloat64Type    6
#define kCFNumberCharType       7
#define kCFNumberShortType      8
#define kCFNumberIntType        9
#define kCFNumberLongType       10
#define kCFNumberLongLongType   11
#define kCFNumberFloatType      12
#define kCFNumberDoubleType     13
#define kCFNumberCFIndexType    14
#define kCFNumberNSIntegerType  15
#define kCFNumberCGFloatType    16
#define kCFNumberMaxType        16

/* ============================================================================
 * Section 9: Callback Structures
 * ============================================================================ */

/* CFAllocator callbacks */
typedef const void *(*CFAllocatorRetainCallBack)(const void *info);
typedef void (*CFAllocatorReleaseCallBack)(const void *info);
typedef CFStringRef (*CFAllocatorCopyDescriptionCallBack)(const void *info);
typedef void *(*CFAllocatorAllocateCallBack)(CFIndex allocSize, CFOptionFlags hint, void *info);
typedef void *(*CFAllocatorReallocateCallBack)(void *ptr, CFIndex newsize, CFOptionFlags hint, void *info);
typedef void (*CFAllocatorDeallocateCallBack)(void *ptr, void *info);
typedef CFIndex (*CFAllocatorPreferredSizeCallBack)(CFIndex size, CFOptionFlags hint, void *info);

typedef struct {
    CFIndex                             version;
    void *                              info;
    CFAllocatorRetainCallBack           retain;
    CFAllocatorReleaseCallBack          release;
    CFAllocatorCopyDescriptionCallBack  copyDescription;
    CFAllocatorAllocateCallBack         allocate;
    CFAllocatorReallocateCallBack       reallocate;
    CFAllocatorDeallocateCallBack       deallocate;
    CFAllocatorPreferredSizeCallBack    preferredSize;
} CFAllocatorContext;

/* CFArray callbacks */
typedef const void *(*CFArrayRetainCallBack)(CFAllocatorRef allocator, const void *value);
typedef void (*CFArrayReleaseCallBack)(CFAllocatorRef allocator, const void *value);
typedef CFStringRef (*CFArrayCopyDescriptionCallBack)(const void *value);
typedef Boolean (*CFArrayEqualCallBack)(const void *value1, const void *value2);

typedef struct {
    CFIndex                         version;
    CFArrayRetainCallBack           retain;
    CFArrayReleaseCallBack          release;
    CFArrayCopyDescriptionCallBack  copyDescription;
    CFArrayEqualCallBack            equal;
} CFArrayCallBacks;

typedef void (*CFArrayApplierFunction)(const void *value, void *context);

/* CFDictionary callbacks */
typedef const void *(*CFDictionaryRetainCallBack)(CFAllocatorRef allocator, const void *value);
typedef void (*CFDictionaryReleaseCallBack)(CFAllocatorRef allocator, const void *value);
typedef CFStringRef (*CFDictionaryCopyDescriptionCallBack)(const void *value);
typedef Boolean (*CFDictionaryEqualCallBack)(const void *value1, const void *value2);
typedef CFHashCode (*CFDictionaryHashCallBack)(const void *value);

typedef struct {
    CFIndex                              version;
    CFDictionaryRetainCallBack           retain;
    CFDictionaryReleaseCallBack          release;
    CFDictionaryCopyDescriptionCallBack  copyDescription;
    CFDictionaryEqualCallBack            equal;
    CFDictionaryHashCallBack             hash;
} CFDictionaryKeyCallBacks;

typedef struct {
    CFIndex                              version;
    CFDictionaryRetainCallBack           retain;
    CFDictionaryReleaseCallBack          release;
    CFDictionaryCopyDescriptionCallBack  copyDescription;
    CFDictionaryEqualCallBack            equal;
} CFDictionaryValueCallBacks;

typedef void (*CFDictionaryApplierFunction)(const void *key, const void *value, void *context);

/* CFSet callbacks */
typedef const void *(*CFSetRetainCallBack)(CFAllocatorRef allocator, const void *value);
typedef void (*CFSetReleaseCallBack)(CFAllocatorRef allocator, const void *value);
typedef CFStringRef (*CFSetCopyDescriptionCallBack)(const void *value);
typedef Boolean (*CFSetEqualCallBack)(const void *value1, const void *value2);
typedef CFHashCode (*CFSetHashCallBack)(const void *value);

typedef struct {
    CFIndex                      version;
    CFSetRetainCallBack          retain;
    CFSetReleaseCallBack         release;
    CFSetCopyDescriptionCallBack copyDescription;
    CFSetEqualCallBack           equal;
    CFSetHashCallBack            hash;
} CFSetCallBacks;

typedef void (*CFSetApplierFunction)(const void *value, void *context);


/* ============================================================================
 * Section 10: CFRuntime — Type Registration & Instance Management
 *
 * Every CF object starts with a CFRuntimeBase header at the pointer
 * returned by _CFRuntimeCreateInstance. Additionally, a hidden intptr_t
 * refcount word is stored at offset -8 (before the object pointer),
 * matching GNUstep libobjc2's object layout for toll-free bridging.
 *
 * Memory layout of a dynamically-allocated CF object:
 *
 *   addr[-1]:  intptr_t  — hidden refcount (same as libobjc obj[-1])
 *   addr[ 0]:  uintptr_t _cfisa   — ObjC isa pointer (for toll-free bridging)
 *   addr[ 8]:  uint64_t  _cfinfoa — packed type ID + marker flags
 *   addr[16+]: CF type-specific fields
 *
 * The _cfinfoa field packs:
 *   Bits 0-7:   info flags (bit 7 = "is CF object" marker = 0x80)
 *   Bits 8-23:  type ID (supports up to 65535 types)
 *   Bits 24-63: reserved (no longer used for refcount)
 *
 * The refcount is stored in the hidden word at ((intptr_t *)cf)[-1].
 * This is identical to GNUstep libobjc2's refcount location, enabling
 * objc_retain/objc_release to work directly on CF objects.
 *
 * Reference: CFRuntime.h, CFRuntime.c in apple/swift-corelibs-foundation
 * ============================================================================ */

typedef struct __CFRuntimeBase {
    uintptr_t _cfisa;
    uint64_t  _cfinfoa;
} CFRuntimeBase;

/* Bit layout helpers for _cfinfoa (refcount NO LONGER stored here) */
#define __CF_INFO_MARKER        0x80ULL             /* bit 7: "is CF object" */
#define __CF_TYPEID_SHIFT       8
#define __CF_TYPEID_MASK        0xFFFF00ULL         /* bits 8-23 */

/* Legacy defines kept for source compatibility — NOT used for refcount */
#define __CF_RC_SHIFT           24
#define __CF_RC_ONE             (1ULL << __CF_RC_SHIFT)

#define _kCFRuntimeNotATypeID   0

/* Hidden refcount sentinel for immortal/static objects */
#define __CF_RC_IMMORTAL        ((intptr_t)0x7FFFFFFFFFFFFFFLL)

/* Static initialiser for singletons. Static objects use a wrapper struct
 * with __CFStaticRC that prepends the hidden refcount word. The INIT macro
 * still initialises just the CFRuntimeBase part (isa=0, infoa=marker). */
#define INIT_CFRUNTIME_BASE()   { 0, __CF_INFO_MARKER }

/* Wrapper for static CF instances — prepends the hidden refcount word */
#define __CF_STATIC_INSTANCE_DECL(type, name, ...) \
    static struct { intptr_t _hiddenRC; type _instance; } name##_storage = \
        { __CF_RC_IMMORTAL, __VA_ARGS__ }

/* Get the CFTypeRef pointer from a static instance storage */
#define __CF_STATIC_INSTANCE_PTR(name) \
    ((void *)&(name##_storage._instance))

CF_INLINE CFTypeID __CFTypeIDFromInfo(uint64_t info) {
    return (CFTypeID)((info & __CF_TYPEID_MASK) >> __CF_TYPEID_SHIFT);
}

/* Read the hidden refcount at obj[-1] */
CF_INLINE intptr_t __CFGetRC(const void *cf) {
    return ((const intptr_t *)cf)[-1];
}

CF_INLINE uint64_t __CFInfoMake(CFTypeID typeID, uint64_t reserved) {
    (void)reserved;
    return __CF_INFO_MARKER
         | ((uint64_t)typeID << __CF_TYPEID_SHIFT);
}

/* Toll-free bridging: Foundation can register ObjC class pointers per CF type.
 * When set, _CFRuntimeCreateInstance sets _cfisa to the ObjC class. */
typedef uintptr_t (*__CFBridgeISALookupFn)(CFTypeID typeID);
static __CFBridgeISALookupFn __CFBridgeISALookup = NULL;

EXPORT void _CFRuntimeBridgeSetISALookup(__CFBridgeISALookupFn fn) {
    __CFBridgeISALookup = fn;
}

/* CFRuntimeClass — class descriptor registered per CF type */
typedef struct __CFRuntimeClass {
    CFIndex     version;
    const char *className;
    void       (*init)(CFTypeRef cf);
    CFTypeRef  (*copy)(CFAllocatorRef allocator, CFTypeRef cf);
    void       (*finalize)(CFTypeRef cf);
    Boolean    (*equal)(CFTypeRef cf1, CFTypeRef cf2);
    CFHashCode (*hash)(CFTypeRef cf);
    CFStringRef(*copyFormattingDesc)(CFTypeRef cf, CFDictionaryRef formatOptions);
    CFStringRef(*copyDebugDesc)(CFTypeRef cf);
} CFRuntimeClass;

/* Class registry — supports up to 256 registered types */
#define __CF_MAX_TYPES 256

static const CFRuntimeClass *__CFRuntimeClassTable[__CF_MAX_TYPES];
static CFTypeID __CFRuntimeNextTypeID = 1; /* 0 = _kCFRuntimeNotATypeID */

/* Mutex for thread-safe registration.
 * Bug 14 fix: Must be pthread_mutex_t (not uint8_t[]) for proper alignment.
 * ARM64 exclusive instructions (ldaxr/stlxr) in pthread_mutex_lock require
 * 4-byte aligned addresses — a uint8_t array may be placed at an odd offset
 * by the linker, causing alignment faults (DFSC=0x21).
 */
static pthread_mutex_t __CFRuntimeLock;
static int     __CFRuntimeLockInit = 0;

HIDDEN void __CFRuntimeLockAcquire(void) {
    if (!__CFRuntimeLockInit) {
        pthread_mutex_init(&__CFRuntimeLock, NULL);
        __CFRuntimeLockInit = 1;
    }
    pthread_mutex_lock(&__CFRuntimeLock);
}

HIDDEN void __CFRuntimeLockRelease(void) {
    pthread_mutex_unlock(&__CFRuntimeLock);
}

EXPORT CFTypeID _CFRuntimeRegisterClass(const CFRuntimeClass *cls) {
    if (!cls) return _kCFRuntimeNotATypeID;
    __CFRuntimeLockAcquire();
    if (__CFRuntimeNextTypeID >= __CF_MAX_TYPES) {
        __CFRuntimeLockRelease();
        return _kCFRuntimeNotATypeID;
    }
    CFTypeID typeID = __CFRuntimeNextTypeID++;
    __CFRuntimeClassTable[typeID] = cls;
    __CFRuntimeLockRelease();
    return typeID;
}

EXPORT const CFRuntimeClass *_CFRuntimeGetClassWithTypeID(CFTypeID typeID) {
    if (typeID == 0 || typeID >= __CFRuntimeNextTypeID) return NULL;
    return __CFRuntimeClassTable[typeID];
}

EXPORT CFTypeRef _CFRuntimeCreateInstance(CFAllocatorRef allocator,
                                           CFTypeID typeID,
                                           CFIndex extraBytes,
                                           unsigned char *category) {
    (void)category;
    /* Allocate: hidden intptr_t refcount + CFRuntimeBase + type-specific data.
     * The returned pointer is past the hidden word, matching libobjc2 layout. */
    size_t total = sizeof(intptr_t) + sizeof(CFRuntimeBase) + (size_t)extraBytes;
    intptr_t *raw = (intptr_t *)calloc(1, total);
    if (!raw) return NULL;

    /* Hidden refcount word at raw[0], initialised to 1 */
    raw[0] = 1;

    /* Object pointer starts after the hidden word */
    CFRuntimeBase *obj = (CFRuntimeBase *)(raw + 1);

    /* Set up _cfinfoa: marker + typeID (refcount is in hidden word now) */
    obj->_cfinfoa = __CFInfoMake(typeID, 0);

    /* Set isa for toll-free bridging if Foundation has registered a lookup */
    if (__CFBridgeISALookup) {
        uintptr_t isa = __CFBridgeISALookup(typeID);
        if (isa) obj->_cfisa = isa;
    }

    /* Call init if provided */
    const CFRuntimeClass *cls = _CFRuntimeGetClassWithTypeID(typeID);
    if (cls && cls->init) {
        cls->init((CFTypeRef)obj);
    }

    return (CFTypeRef)obj;
}

EXPORT void _CFRuntimeInitStaticInstance(void *memory, CFTypeID typeID) {
    if (!memory) return;
    CFRuntimeBase *base = (CFRuntimeBase *)memory;
    /* Set the type ID in _cfinfoa (refcount is in the hidden word at [-1]) */
    base->_cfinfoa = __CFInfoMake(typeID, 0);
    /* The hidden refcount word must be set to immortal by the caller
     * (handled via __CF_STATIC_INSTANCE_DECL or manually). */

    /* Set isa for toll-free bridging if Foundation has registered a lookup */
    if (__CFBridgeISALookup) {
        uintptr_t isa = __CFBridgeISALookup(typeID);
        if (isa) base->_cfisa = isa;
    }
}

EXPORT void _CFRuntimeSetInstanceTypeID(CFTypeRef cf, CFTypeID typeID) {
    if (!cf) return;
    CFRuntimeBase *base = (CFRuntimeBase *)cf;
    base->_cfinfoa = __CFInfoMake(typeID, 0);
}

/* ============================================================================
 * Section 11: CFBase — Polymorphic Functions
 * ============================================================================ */

EXPORT double kCFCoreFoundationVersionNumber = 1153.18;

EXPORT CFTypeID CFGetTypeID(CFTypeRef cf) {
    if (!cf) return _kCFRuntimeNotATypeID;
    const CFRuntimeBase *base = (const CFRuntimeBase *)cf;
    return __CFTypeIDFromInfo(base->_cfinfoa);
}

EXPORT CFTypeRef CFRetain(CFTypeRef cf) {
    if (!cf) return NULL;
    /* Refcount is the hidden intptr_t at ((intptr_t *)cf)[-1] */
    intptr_t *rcPtr = ((intptr_t *)cf) - 1;
    intptr_t rc = __atomic_load_n(rcPtr, __ATOMIC_RELAXED);
    /* Don't increment immortal objects (static singletons) */
    if (rc >= __CF_RC_IMMORTAL) return cf;
    __atomic_add_fetch(rcPtr, 1, __ATOMIC_RELAXED);
    return cf;
}

EXPORT void CFRelease(CFTypeRef cf) {
    if (!cf) return;
    intptr_t *rcPtr = ((intptr_t *)cf) - 1;
    intptr_t rc = __atomic_load_n(rcPtr, __ATOMIC_RELAXED);
    /* Don't release immortal objects */
    if (rc >= __CF_RC_IMMORTAL) return;
    intptr_t old = __atomic_fetch_sub(rcPtr, 1, __ATOMIC_ACQ_REL);
    if (old <= 1) {
        /* Refcount hit zero — finalize and free */
        const CFRuntimeBase *base = (const CFRuntimeBase *)cf;
        CFTypeID tid = __CFTypeIDFromInfo(base->_cfinfoa);
        const CFRuntimeClass *cls = _CFRuntimeGetClassWithTypeID(tid);
        if (cls && cls->finalize) {
            cls->finalize(cf);
        }
        /* Free from the hidden refcount word (the actual allocation start) */
        free(rcPtr);
    }
}

EXPORT CFTypeRef CFAutorelease(CFTypeRef cf) {
    /* No autorelease pool in freestanding CF — just return.
     * When Foundation is loaded, objc_autorelease handles this. */
    return cf;
}

EXPORT CFIndex CFGetRetainCount(CFTypeRef cf) {
    if (!cf) return 0;
    intptr_t rc = __CFGetRC(cf);
    if (rc >= __CF_RC_IMMORTAL) return 9999999; /* immortal */
    return (CFIndex)rc;
}

EXPORT Boolean CFEqual(CFTypeRef cf1, CFTypeRef cf2) {
    if (cf1 == cf2) return true;
    if (!cf1 || !cf2) return false;
    CFTypeID t1 = CFGetTypeID(cf1);
    CFTypeID t2 = CFGetTypeID(cf2);
    if (t1 != t2) return false;
    const CFRuntimeClass *cls = _CFRuntimeGetClassWithTypeID(t1);
    if (cls && cls->equal) return cls->equal(cf1, cf2);
    return false;
}

EXPORT CFHashCode CFHash(CFTypeRef cf) {
    if (!cf) return 0;
    CFTypeID tid = CFGetTypeID(cf);
    const CFRuntimeClass *cls = _CFRuntimeGetClassWithTypeID(tid);
    if (cls && cls->hash) return cls->hash(cf);
    /* Default: pointer hash */
    return (CFHashCode)(uintptr_t)cf;
}

EXPORT CFStringRef CFCopyDescription(CFTypeRef cf) {
    if (!cf) return NULL;
    CFTypeID tid = CFGetTypeID(cf);
    const CFRuntimeClass *cls = _CFRuntimeGetClassWithTypeID(tid);
    if (cls && cls->copyFormattingDesc) return cls->copyFormattingDesc(cf, NULL);
    if (cls && cls->copyDebugDesc) return cls->copyDebugDesc(cf);
    return NULL;
}

EXPORT CFStringRef CFCopyTypeIDDescription(CFTypeID type_id) {
    const CFRuntimeClass *cls = _CFRuntimeGetClassWithTypeID(type_id);
    if (!cls || !cls->className) return NULL;
    /* We'll create a CFString — but CFString isn't initialised yet during early
     * bootstrap, so this returns NULL if called too early. It'll work once
     * __CFStringTypeID is set up. Forward-declared; implemented later. */
    return NULL; /* Placeholder — updated after CFString init */
}

EXPORT CFAllocatorRef CFGetAllocator(CFTypeRef cf) {
    /* We don't track per-object allocators in this implementation.
     * Always return NULL (= kCFAllocatorDefault = system default). */
    (void)cf;
    return NULL;
}

EXPORT CFTypeRef CFMakeCollectable(CFTypeRef cf) {
    /* No-op — GC is not supported */
    return cf;
}


/* ============================================================================
 * Section 12: CFAllocator
 *
 * kCFAllocatorDefault is NULL — it means "use the current default allocator",
 * which is kCFAllocatorSystemDefault unless changed by CFAllocatorSetDefault().
 *
 * Reference: CFBase.c in apple/swift-corelibs-foundation
 * ============================================================================ */

struct __CFAllocator {
    CFRuntimeBase    _base;
    CFAllocatorContext _context;
};

static CFTypeID __CFAllocatorTypeID = _kCFRuntimeNotATypeID;
static CFAllocatorRef __CFDefaultAllocator = NULL; /* NULL = system default */

/* --- System default allocator: uses malloc/realloc/free --- */
static void *__CFAllocatorSystemAllocate(CFIndex size, CFOptionFlags hint, void *info) {
    (void)hint; (void)info;
    return malloc((size_t)size);
}
static void *__CFAllocatorSystemReallocate(void *ptr, CFIndex newsize, CFOptionFlags hint, void *info) {
    (void)hint; (void)info;
    return realloc(ptr, (size_t)newsize);
}
static void __CFAllocatorSystemDeallocate(void *ptr, void *info) {
    (void)info;
    free(ptr);
}

/* Static allocator singletons — each prefixed with hidden intptr_t refcount
 * for toll-free bridging compatibility with libobjc2's object layout. */
__CF_STATIC_INSTANCE_DECL(struct __CFAllocator, __kCFAllocatorSystemDefault, {
    INIT_CFRUNTIME_BASE(),
    { 0, NULL, NULL, NULL, NULL,
      __CFAllocatorSystemAllocate,
      __CFAllocatorSystemReallocate,
      __CFAllocatorSystemDeallocate,
      NULL }
});
#define __kCFAllocatorSystemDefaultInstance (*(struct __CFAllocator *)__CF_STATIC_INSTANCE_PTR(__kCFAllocatorSystemDefault))

/* --- Malloc allocator: identical to system default --- */
__CF_STATIC_INSTANCE_DECL(struct __CFAllocator, __kCFAllocatorMalloc, {
    INIT_CFRUNTIME_BASE(),
    { 0, NULL, NULL, NULL, NULL,
      __CFAllocatorSystemAllocate,
      __CFAllocatorSystemReallocate,
      __CFAllocatorSystemDeallocate,
      NULL }
});
#define __kCFAllocatorMallocInstance (*(struct __CFAllocator *)__CF_STATIC_INSTANCE_PTR(__kCFAllocatorMalloc))

/* --- Null allocator: does nothing --- */
static void *__CFAllocatorNullAllocate(CFIndex size, CFOptionFlags hint, void *info) {
    (void)size; (void)hint; (void)info;
    return NULL;
}
static void *__CFAllocatorNullReallocate(void *ptr, CFIndex newsize, CFOptionFlags hint, void *info) {
    (void)ptr; (void)newsize; (void)hint; (void)info;
    return NULL;
}
static void __CFAllocatorNullDeallocate(void *ptr, void *info) {
    (void)ptr; (void)info;
}

__CF_STATIC_INSTANCE_DECL(struct __CFAllocator, __kCFAllocatorNull, {
    INIT_CFRUNTIME_BASE(),
    { 0, NULL, NULL, NULL, NULL,
      __CFAllocatorNullAllocate,
      __CFAllocatorNullReallocate,
      __CFAllocatorNullDeallocate,
      NULL }
});
#define __kCFAllocatorNullInstance (*(struct __CFAllocator *)__CF_STATIC_INSTANCE_PTR(__kCFAllocatorNull))

/* Exported constants */
EXPORT const CFAllocatorRef kCFAllocatorDefault       = NULL;
EXPORT const CFAllocatorRef kCFAllocatorSystemDefault  = (CFAllocatorRef)__CF_STATIC_INSTANCE_PTR(__kCFAllocatorSystemDefault);
EXPORT const CFAllocatorRef kCFAllocatorMalloc         = (CFAllocatorRef)__CF_STATIC_INSTANCE_PTR(__kCFAllocatorMalloc);
EXPORT const CFAllocatorRef kCFAllocatorMallocZone     = (CFAllocatorRef)__CF_STATIC_INSTANCE_PTR(__kCFAllocatorMalloc);
EXPORT const CFAllocatorRef kCFAllocatorNull           = (CFAllocatorRef)__CF_STATIC_INSTANCE_PTR(__kCFAllocatorNull);
EXPORT const CFAllocatorRef kCFAllocatorUseContext      = (CFAllocatorRef)0x1; /* sentinel, never dereferenced */

/* Resolve NULL → system default */
CF_INLINE const struct __CFAllocator *__CFAllocatorResolve(CFAllocatorRef alloc) {
    if (alloc == NULL || alloc == kCFAllocatorDefault) {
        if (__CFDefaultAllocator)
            return (const struct __CFAllocator *)__CFDefaultAllocator;
        return &__kCFAllocatorSystemDefaultInstance;
    }
    return (const struct __CFAllocator *)alloc;
}

static Boolean __CFAllocatorEqual(CFTypeRef cf1, CFTypeRef cf2) {
    return cf1 == cf2;
}

static CFHashCode __CFAllocatorHash(CFTypeRef cf) {
    return (CFHashCode)(uintptr_t)cf;
}

static const CFRuntimeClass __CFAllocatorClass = {
    0, "CFAllocator", NULL, NULL, NULL,
    __CFAllocatorEqual, __CFAllocatorHash, NULL, NULL
};

EXPORT CFTypeID CFAllocatorGetTypeID(void) {
    return __CFAllocatorTypeID;
}

EXPORT CFAllocatorRef CFAllocatorGetDefault(void) {
    if (__CFDefaultAllocator) return __CFDefaultAllocator;
    return kCFAllocatorSystemDefault;
}

EXPORT void CFAllocatorSetDefault(CFAllocatorRef allocator) {
    /* Cannot set the null allocator as default */
    if (allocator == kCFAllocatorNull) return;
    __CFDefaultAllocator = allocator;
}

EXPORT CFAllocatorRef CFAllocatorCreate(CFAllocatorRef allocator, CFAllocatorContext *context) {
    if (!context) return NULL;
    struct __CFAllocator *newAlloc = (struct __CFAllocator *)calloc(1, sizeof(struct __CFAllocator));
    if (!newAlloc) return NULL;
    newAlloc->_base._cfinfoa = __CFInfoMake(__CFAllocatorTypeID, 1);
    memcpy(&newAlloc->_context, context, sizeof(CFAllocatorContext));
    if (context->retain && context->info) {
        newAlloc->_context.info = (void *)context->retain(context->info);
    }
    return (CFAllocatorRef)newAlloc;
}

EXPORT void *CFAllocatorAllocate(CFAllocatorRef allocator, CFIndex size, CFOptionFlags hint) {
    const struct __CFAllocator *alloc = __CFAllocatorResolve(allocator);
    if (alloc->_context.allocate)
        return alloc->_context.allocate(size, hint, alloc->_context.info);
    return NULL;
}

EXPORT void *CFAllocatorReallocate(CFAllocatorRef allocator, void *ptr, CFIndex newsize, CFOptionFlags hint) {
    const struct __CFAllocator *alloc = __CFAllocatorResolve(allocator);
    if (newsize <= 0 && ptr) {
        if (alloc->_context.deallocate)
            alloc->_context.deallocate(ptr, alloc->_context.info);
        return NULL;
    }
    if (alloc->_context.reallocate)
        return alloc->_context.reallocate(ptr, newsize, hint, alloc->_context.info);
    return NULL;
}

EXPORT void CFAllocatorDeallocate(CFAllocatorRef allocator, void *ptr) {
    if (!ptr) return;
    const struct __CFAllocator *alloc = __CFAllocatorResolve(allocator);
    if (alloc->_context.deallocate)
        alloc->_context.deallocate(ptr, alloc->_context.info);
}

EXPORT CFIndex CFAllocatorGetPreferredSizeForSize(CFAllocatorRef allocator, CFIndex size, CFOptionFlags hint) {
    const struct __CFAllocator *alloc = __CFAllocatorResolve(allocator);
    if (alloc->_context.preferredSize)
        return alloc->_context.preferredSize(size, hint, alloc->_context.info);
    return size;
}

EXPORT void CFAllocatorGetContext(CFAllocatorRef allocator, CFAllocatorContext *context) {
    if (!context) return;
    const struct __CFAllocator *alloc = __CFAllocatorResolve(allocator);
    memcpy(context, &alloc->_context, sizeof(CFAllocatorContext));
}


/* ============================================================================
 * Section 13: CFNull
 * ============================================================================ */

struct __CFNull {
    CFRuntimeBase _base;
};

static CFTypeID __CFNullTypeID = _kCFRuntimeNotATypeID;

static Boolean __CFNullEqual(CFTypeRef cf1, CFTypeRef cf2) { return cf1 == cf2; }
static CFHashCode __CFNullHash(CFTypeRef cf) { (void)cf; return 0; }

static const CFRuntimeClass __CFNullClass = {
    0, "CFNull", NULL, NULL, NULL,
    __CFNullEqual, __CFNullHash, NULL, NULL
};

__CF_STATIC_INSTANCE_DECL(struct __CFNull, __kCFNull, { INIT_CFRUNTIME_BASE() });
#define __kCFNullInstance (*(struct __CFNull *)__CF_STATIC_INSTANCE_PTR(__kCFNull))
EXPORT const CFNullRef kCFNull = (CFNullRef)__CF_STATIC_INSTANCE_PTR(__kCFNull);

EXPORT CFTypeID CFNullGetTypeID(void) { return __CFNullTypeID; }

/* ============================================================================
 * Section 14: CFBoolean
 * ============================================================================ */

struct __CFBoolean {
    CFRuntimeBase _base;
    Boolean       _value;
};

static CFTypeID __CFBooleanTypeID = _kCFRuntimeNotATypeID;

static Boolean __CFBooleanEqual(CFTypeRef cf1, CFTypeRef cf2) {
    return ((const struct __CFBoolean *)cf1)->_value ==
           ((const struct __CFBoolean *)cf2)->_value;
}
static CFHashCode __CFBooleanHash(CFTypeRef cf) {
    return ((const struct __CFBoolean *)cf)->_value ? 1 : 0;
}

static const CFRuntimeClass __CFBooleanClass = {
    0, "CFBoolean", NULL, NULL, NULL,
    __CFBooleanEqual, __CFBooleanHash, NULL, NULL
};

__CF_STATIC_INSTANCE_DECL(struct __CFBoolean, __kCFBooleanTrue,  { INIT_CFRUNTIME_BASE(), true });
__CF_STATIC_INSTANCE_DECL(struct __CFBoolean, __kCFBooleanFalse, { INIT_CFRUNTIME_BASE(), false });
#define __kCFBooleanTrueInstance  (*(struct __CFBoolean *)__CF_STATIC_INSTANCE_PTR(__kCFBooleanTrue))
#define __kCFBooleanFalseInstance (*(struct __CFBoolean *)__CF_STATIC_INSTANCE_PTR(__kCFBooleanFalse))

EXPORT const CFBooleanRef kCFBooleanTrue  = (CFBooleanRef)__CF_STATIC_INSTANCE_PTR(__kCFBooleanTrue);
EXPORT const CFBooleanRef kCFBooleanFalse = (CFBooleanRef)__CF_STATIC_INSTANCE_PTR(__kCFBooleanFalse);

EXPORT CFTypeID CFBooleanGetTypeID(void) { return __CFBooleanTypeID; }

EXPORT Boolean CFBooleanGetValue(CFBooleanRef boolean) {
    if (!boolean) return false;
    return ((const struct __CFBoolean *)boolean)->_value;
}

/* ============================================================================
 * Section 15: CFNumber
 *
 * Internal storage: always stored as the largest type that can represent
 * the value (int64_t for integers, double for floats).
 * ============================================================================ */

struct __CFNumber {
    CFRuntimeBase _base;
    CFNumberType  _type;
    union {
        int64_t _sint64;
        double  _float64;
    } _value;
};

static CFTypeID __CFNumberTypeID = _kCFRuntimeNotATypeID;

/* Return the byte size of a CFNumberType */
HIDDEN CFIndex __CFNumberTypeSize(CFNumberType type) {
    switch (type) {
    case kCFNumberSInt8Type:  case kCFNumberCharType:   return 1;
    case kCFNumberSInt16Type: case kCFNumberShortType:  return 2;
    case kCFNumberSInt32Type: case kCFNumberIntType:    return 4;
    case kCFNumberSInt64Type: case kCFNumberLongLongType: return 8;
    case kCFNumberFloat32Type: case kCFNumberFloatType: return 4;
    case kCFNumberFloat64Type: case kCFNumberDoubleType: return 8;
    case kCFNumberLongType:   case kCFNumberCFIndexType:
    case kCFNumberNSIntegerType: return sizeof(long);
    case kCFNumberCGFloatType: return sizeof(double);
    default: return 0;
    }
}

HIDDEN Boolean __CFNumberTypeIsFloat(CFNumberType type) {
    return (type == kCFNumberFloat32Type || type == kCFNumberFloat64Type ||
            type == kCFNumberFloatType || type == kCFNumberDoubleType ||
            type == kCFNumberCGFloatType);
}

static Boolean __CFNumberEqual(CFTypeRef cf1, CFTypeRef cf2) {
    const struct __CFNumber *n1 = (const struct __CFNumber *)cf1;
    const struct __CFNumber *n2 = (const struct __CFNumber *)cf2;
    Boolean f1 = __CFNumberTypeIsFloat(n1->_type);
    Boolean f2 = __CFNumberTypeIsFloat(n2->_type);
    if (f1 || f2) return n1->_value._float64 == n2->_value._float64;
    return n1->_value._sint64 == n2->_value._sint64;
}

static CFHashCode __CFNumberHash(CFTypeRef cf) {
    const struct __CFNumber *n = (const struct __CFNumber *)cf;
    if (__CFNumberTypeIsFloat(n->_type)) {
        /* Hash the double bits */
        uint64_t bits;
        memcpy(&bits, &n->_value._float64, 8);
        return (CFHashCode)(bits ^ (bits >> 32));
    }
    return (CFHashCode)(n->_value._sint64 ^ (n->_value._sint64 >> 32));
}

static const CFRuntimeClass __CFNumberClass = {
    0, "CFNumber", NULL, NULL, NULL,
    __CFNumberEqual, __CFNumberHash, NULL, NULL
};

EXPORT CFTypeID CFNumberGetTypeID(void) { return __CFNumberTypeID; }

EXPORT CFNumberRef CFNumberCreate(CFAllocatorRef allocator, CFNumberType theType, const void *valuePtr) {
    if (!valuePtr || theType < 1 || theType > kCFNumberMaxType) return NULL;
    struct __CFNumber *num = (struct __CFNumber *)_CFRuntimeCreateInstance(
        allocator, __CFNumberTypeID,
        sizeof(struct __CFNumber) - sizeof(CFRuntimeBase), NULL);
    if (!num) return NULL;
    num->_type = theType;

    Boolean isFloat = __CFNumberTypeIsFloat(theType);
    if (isFloat) {
        switch (theType) {
        case kCFNumberFloat32Type: case kCFNumberFloatType: {
            float f; memcpy(&f, valuePtr, sizeof(float));
            num->_value._float64 = (double)f;
            break;
        }
        default: /* Float64, Double, CGFloat */
            memcpy(&num->_value._float64, valuePtr, sizeof(double));
            break;
        }
    } else {
        num->_value._sint64 = 0;
        CFIndex sz = __CFNumberTypeSize(theType);
        /* Sign-extend from source */
        switch (sz) {
        case 1: { int8_t v; memcpy(&v, valuePtr, 1); num->_value._sint64 = v; break; }
        case 2: { int16_t v; memcpy(&v, valuePtr, 2); num->_value._sint64 = v; break; }
        case 4: { int32_t v; memcpy(&v, valuePtr, 4); num->_value._sint64 = v; break; }
        case 8: { memcpy(&num->_value._sint64, valuePtr, 8); break; }
        default: break;
        }
    }
    return (CFNumberRef)num;
}

EXPORT CFNumberType CFNumberGetType(CFNumberRef number) {
    if (!number) return 0;
    return ((const struct __CFNumber *)number)->_type;
}

EXPORT CFIndex CFNumberGetByteSize(CFNumberRef number) {
    if (!number) return 0;
    return __CFNumberTypeSize(((const struct __CFNumber *)number)->_type);
}

EXPORT Boolean CFNumberIsFloatType(CFNumberRef number) {
    if (!number) return false;
    return __CFNumberTypeIsFloat(((const struct __CFNumber *)number)->_type);
}

EXPORT Boolean CFNumberGetValue(CFNumberRef number, CFNumberType theType, void *valuePtr) {
    if (!number || !valuePtr) return false;
    const struct __CFNumber *n = (const struct __CFNumber *)number;
    Boolean srcFloat = __CFNumberTypeIsFloat(n->_type);
    Boolean dstFloat = __CFNumberTypeIsFloat(theType);

    if (dstFloat) {
        double val;
        if (srcFloat) val = n->_value._float64;
        else val = (double)n->_value._sint64;
        switch (theType) {
        case kCFNumberFloat32Type: case kCFNumberFloatType: {
            float f = (float)val; memcpy(valuePtr, &f, sizeof(float));
            return true;
        }
        default:
            memcpy(valuePtr, &val, sizeof(double));
            return true;
        }
    } else {
        int64_t val;
        if (srcFloat) val = (int64_t)n->_value._float64;
        else val = n->_value._sint64;
        CFIndex sz = __CFNumberTypeSize(theType);
        switch (sz) {
        case 1: { int8_t v = (int8_t)val; memcpy(valuePtr, &v, 1); break; }
        case 2: { int16_t v = (int16_t)val; memcpy(valuePtr, &v, 2); break; }
        case 4: { int32_t v = (int32_t)val; memcpy(valuePtr, &v, 4); break; }
        case 8: { memcpy(valuePtr, &val, 8); break; }
        default: return false;
        }
        return true;
    }
}

EXPORT CFComparisonResult CFNumberCompare(CFNumberRef number, CFNumberRef otherNumber, void *context) {
    (void)context;
    if (!number || !otherNumber) return kCFCompareEqualTo;
    const struct __CFNumber *n1 = (const struct __CFNumber *)number;
    const struct __CFNumber *n2 = (const struct __CFNumber *)otherNumber;
    Boolean f1 = __CFNumberTypeIsFloat(n1->_type);
    Boolean f2 = __CFNumberTypeIsFloat(n2->_type);

    if (f1 || f2) {
        double v1 = f1 ? n1->_value._float64 : (double)n1->_value._sint64;
        double v2 = f2 ? n2->_value._float64 : (double)n2->_value._sint64;
        if (v1 < v2) return kCFCompareLessThan;
        if (v1 > v2) return kCFCompareGreaterThan;
        return kCFCompareEqualTo;
    }
    if (n1->_value._sint64 < n2->_value._sint64) return kCFCompareLessThan;
    if (n1->_value._sint64 > n2->_value._sint64) return kCFCompareGreaterThan;
    return kCFCompareEqualTo;
}

/* Special constant numbers: +Inf, -Inf, NaN */
/* These will be initialised in the constructor */
/* CFNumber special constants — need hidden refcount prefix for toll-free bridging.
 * Fields are initialised at runtime in __CFInitSpecialNumbers(). */
static struct { intptr_t _hiddenRC; struct __CFNumber _instance; } __kCFNumberPosInf_storage = { __CF_RC_IMMORTAL, { INIT_CFRUNTIME_BASE(), 0, { 0 } } };
static struct { intptr_t _hiddenRC; struct __CFNumber _instance; } __kCFNumberNegInf_storage = { __CF_RC_IMMORTAL, { INIT_CFRUNTIME_BASE(), 0, { 0 } } };
static struct { intptr_t _hiddenRC; struct __CFNumber _instance; } __kCFNumberNaN_storage    = { __CF_RC_IMMORTAL, { INIT_CFRUNTIME_BASE(), 0, { 0 } } };
#define __kCFNumberPosInfInstance (__kCFNumberPosInf_storage._instance)
#define __kCFNumberNegInfInstance (__kCFNumberNegInf_storage._instance)
#define __kCFNumberNaNInstance    (__kCFNumberNaN_storage._instance)

EXPORT const CFNumberRef kCFNumberPositiveInfinity = (CFNumberRef)&(__kCFNumberPosInf_storage._instance);
EXPORT const CFNumberRef kCFNumberNegativeInfinity = (CFNumberRef)&(__kCFNumberNegInf_storage._instance);
EXPORT const CFNumberRef kCFNumberNaN              = (CFNumberRef)&(__kCFNumberNaN_storage._instance);


/* ============================================================================
 * Section 16: CFData
 * ============================================================================ */

struct __CFData {
    CFRuntimeBase _base;
    CFIndex       _length;
    CFIndex       _capacity;
    uint8_t      *_bytes;
    Boolean       _mutable;
    Boolean       _ownsBuf;     /* whether we should free _bytes */
    CFAllocatorRef _deallocator; /* for NoCopy variants */
};

static CFTypeID __CFDataTypeID = _kCFRuntimeNotATypeID;

static void __CFDataFinalize(CFTypeRef cf) {
    struct __CFData *data = (struct __CFData *)cf;
    if (data->_bytes && data->_ownsBuf) {
        if (data->_deallocator && data->_deallocator != kCFAllocatorNull) {
            CFAllocatorDeallocate(data->_deallocator, data->_bytes);
        } else {
            free(data->_bytes);
        }
    }
}

static Boolean __CFDataEqual(CFTypeRef cf1, CFTypeRef cf2) {
    const struct __CFData *d1 = (const struct __CFData *)cf1;
    const struct __CFData *d2 = (const struct __CFData *)cf2;
    if (d1->_length != d2->_length) return false;
    if (d1->_length == 0) return true;
    return memcmp(d1->_bytes, d2->_bytes, (size_t)d1->_length) == 0;
}

static CFHashCode __CFDataHash(CFTypeRef cf) {
    const struct __CFData *d = (const struct __CFData *)cf;
    /* FNV-1a hash over first 80 bytes */
    CFHashCode hash = 14695981039346656037ULL;
    CFIndex len = d->_length < 80 ? d->_length : 80;
    for (CFIndex i = 0; i < len; i++) {
        hash ^= d->_bytes[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static const CFRuntimeClass __CFDataClass = {
    0, "CFData", NULL, NULL, __CFDataFinalize,
    __CFDataEqual, __CFDataHash, NULL, NULL
};

EXPORT CFTypeID CFDataGetTypeID(void) { return __CFDataTypeID; }

EXPORT CFDataRef CFDataCreate(CFAllocatorRef allocator, const UInt8 *bytes, CFIndex length) {
    struct __CFData *d = (struct __CFData *)_CFRuntimeCreateInstance(
        allocator, __CFDataTypeID,
        sizeof(struct __CFData) - sizeof(CFRuntimeBase), NULL);
    if (!d) return NULL;
    d->_mutable = false;
    d->_ownsBuf = true;
    d->_deallocator = NULL;
    d->_length = length;
    d->_capacity = length;
    if (length > 0 && bytes) {
        d->_bytes = (uint8_t *)malloc((size_t)length);
        if (!d->_bytes) { free(d); return NULL; }
        memcpy(d->_bytes, bytes, (size_t)length);
    } else {
        d->_bytes = NULL;
    }
    return (CFDataRef)d;
}

EXPORT CFDataRef CFDataCreateCopy(CFAllocatorRef allocator, CFDataRef theData) {
    if (!theData) return NULL;
    const struct __CFData *src = (const struct __CFData *)theData;
    return CFDataCreate(allocator, src->_bytes, src->_length);
}

EXPORT CFDataRef CFDataCreateWithBytesNoCopy(CFAllocatorRef allocator,
    const UInt8 *bytes, CFIndex length, CFAllocatorRef bytesDeallocator) {
    struct __CFData *d = (struct __CFData *)_CFRuntimeCreateInstance(
        allocator, __CFDataTypeID,
        sizeof(struct __CFData) - sizeof(CFRuntimeBase), NULL);
    if (!d) return NULL;
    d->_mutable = false;
    d->_ownsBuf = (bytesDeallocator != kCFAllocatorNull);
    d->_deallocator = bytesDeallocator;
    d->_length = length;
    d->_capacity = length;
    d->_bytes = (uint8_t *)bytes; /* const cast — immutable, so safe */
    return (CFDataRef)d;
}

EXPORT CFMutableDataRef CFDataCreateMutable(CFAllocatorRef allocator, CFIndex capacity) {
    struct __CFData *d = (struct __CFData *)_CFRuntimeCreateInstance(
        allocator, __CFDataTypeID,
        sizeof(struct __CFData) - sizeof(CFRuntimeBase), NULL);
    if (!d) return NULL;
    d->_mutable = true;
    d->_ownsBuf = true;
    d->_deallocator = NULL;
    d->_length = 0;
    d->_capacity = capacity > 0 ? capacity : 16;
    d->_bytes = (uint8_t *)calloc(1, (size_t)d->_capacity);
    return (CFMutableDataRef)d;
}

EXPORT CFMutableDataRef CFDataCreateMutableCopy(CFAllocatorRef allocator, CFIndex capacity, CFDataRef theData) {
    if (!theData) return CFDataCreateMutable(allocator, capacity);
    const struct __CFData *src = (const struct __CFData *)theData;
    CFIndex cap = capacity > src->_length ? capacity : src->_length;
    CFMutableDataRef md = CFDataCreateMutable(allocator, cap);
    if (!md) return NULL;
    struct __CFData *d = (struct __CFData *)md;
    if (src->_length > 0 && src->_bytes) {
        memcpy(d->_bytes, src->_bytes, (size_t)src->_length);
        d->_length = src->_length;
    }
    return md;
}

EXPORT CFIndex CFDataGetLength(CFDataRef theData) {
    if (!theData) return 0;
    return ((const struct __CFData *)theData)->_length;
}

EXPORT const UInt8 *CFDataGetBytePtr(CFDataRef theData) {
    if (!theData) return NULL;
    return ((const struct __CFData *)theData)->_bytes;
}

EXPORT void CFDataGetBytes(CFDataRef theData, CFRange range, UInt8 *buffer) {
    if (!theData || !buffer) return;
    const struct __CFData *d = (const struct __CFData *)theData;
    if (range.location < 0 || range.location + range.length > d->_length) return;
    memcpy(buffer, d->_bytes + range.location, (size_t)range.length);
}

EXPORT UInt8 *CFDataGetMutableBytePtr(CFMutableDataRef theData) {
    if (!theData) return NULL;
    struct __CFData *d = (struct __CFData *)theData;
    if (!d->_mutable) return NULL;
    return d->_bytes;
}

HIDDEN void __CFDataGrow(struct __CFData *d, CFIndex needed) {
    CFIndex newCap = d->_capacity;
    while (newCap < needed) newCap = newCap < 16 ? 16 : newCap * 2;
    d->_bytes = (uint8_t *)realloc(d->_bytes, (size_t)newCap);
    d->_capacity = newCap;
}

EXPORT void CFDataSetLength(CFMutableDataRef theData, CFIndex length) {
    if (!theData) return;
    struct __CFData *d = (struct __CFData *)theData;
    if (!d->_mutable) return;
    if (length > d->_capacity) __CFDataGrow(d, length);
    if (length > d->_length) {
        memset(d->_bytes + d->_length, 0, (size_t)(length - d->_length));
    }
    d->_length = length;
}

EXPORT void CFDataAppendBytes(CFMutableDataRef theData, const UInt8 *bytes, CFIndex length) {
    if (!theData || !bytes || length <= 0) return;
    struct __CFData *d = (struct __CFData *)theData;
    if (!d->_mutable) return;
    CFIndex newLen = d->_length + length;
    if (newLen > d->_capacity) __CFDataGrow(d, newLen);
    memcpy(d->_bytes + d->_length, bytes, (size_t)length);
    d->_length = newLen;
}

EXPORT void CFDataReplaceBytes(CFMutableDataRef theData, CFRange range,
                                const UInt8 *newBytes, CFIndex newLength) {
    if (!theData) return;
    struct __CFData *d = (struct __CFData *)theData;
    if (!d->_mutable) return;
    if (range.location < 0 || range.location > d->_length) return;
    if (range.location + range.length > d->_length)
        range.length = d->_length - range.location;

    CFIndex delta = newLength - range.length;
    CFIndex newTotal = d->_length + delta;
    if (newTotal > d->_capacity) __CFDataGrow(d, newTotal);

    /* Shift tail */
    CFIndex tailStart = range.location + range.length;
    CFIndex tailLen = d->_length - tailStart;
    if (tailLen > 0 && delta != 0) {
        memmove(d->_bytes + range.location + newLength,
                d->_bytes + tailStart, (size_t)tailLen);
    }
    /* Copy new bytes */
    if (newLength > 0 && newBytes) {
        memcpy(d->_bytes + range.location, newBytes, (size_t)newLength);
    }
    d->_length = newTotal;
}

EXPORT void CFDataDeleteBytes(CFMutableDataRef theData, CFRange range) {
    CFDataReplaceBytes(theData, range, NULL, 0);
}

EXPORT void CFDataIncreaseLength(CFMutableDataRef theData, CFIndex extraLength) {
    if (!theData || extraLength <= 0) return;
    struct __CFData *d = (struct __CFData *)theData;
    CFDataSetLength(theData, d->_length + extraLength);
}


/* ============================================================================
 * Section 17: CFString
 *
 * Internal storage is UTF-8. CFStringGetCStringPtr() returns a direct
 * pointer for kCFStringEncodingUTF8 and kCFStringEncodingASCII requests.
 * UniChar (UTF-16) access converts on the fly.
 *
 * The CFSTR() macro calls __CFStringMakeConstantString() which maintains
 * a hash table of interned constant strings.
 * ============================================================================ */

#define __CF_STRING_INLINE_BUF 0  /* no inline buffer — always heap */

struct __CFString {
    CFRuntimeBase _base;
    CFIndex       _length;    /* number of UTF-16 code units (for compatibility) */
    CFIndex       _byteLen;   /* number of bytes in _buf (not counting NUL) */
    CFIndex       _capacity;  /* allocated capacity of _buf */
    char         *_buf;       /* UTF-8 NUL-terminated */
    Boolean       _mutable;
    Boolean       _isConstant; /* interned via CFSTR() — never freed */
    Boolean       _ownsBuf;
};

static CFTypeID __CFStringTypeID = _kCFRuntimeNotATypeID;

/* Count UTF-16 code units from a UTF-8 string (for CFStringGetLength).
 * ASCII bytes = 1 code unit. Multi-byte sequences = 1 or 2 code units
 * depending on whether the codepoint is in the BMP or supplementary. */
HIDDEN CFIndex __CFStringUTF16Length(const char *utf8, CFIndex byteLen) {
    CFIndex u16len = 0;
    CFIndex i = 0;
    while (i < byteLen) {
        unsigned char c = (unsigned char)utf8[i];
        if (c < 0x80) {
            u16len++; i++;
        } else if ((c & 0xE0) == 0xC0) {
            u16len++; i += 2;
        } else if ((c & 0xF0) == 0xE0) {
            u16len++; i += 3;
        } else if ((c & 0xF8) == 0xF0) {
            u16len += 2; i += 4; /* surrogate pair */
        } else {
            u16len++; i++; /* invalid byte — count as 1 */
        }
    }
    return u16len;
}

static void __CFStringFinalize(CFTypeRef cf) {
    struct __CFString *s = (struct __CFString *)cf;
    if (s->_isConstant) return; /* never free constant strings */
    if (s->_buf && s->_ownsBuf) free(s->_buf);
}

static Boolean __CFStringEqual(CFTypeRef cf1, CFTypeRef cf2) {
    const struct __CFString *s1 = (const struct __CFString *)cf1;
    const struct __CFString *s2 = (const struct __CFString *)cf2;
    if (s1->_byteLen != s2->_byteLen) return false;
    if (s1->_byteLen == 0) return true;
    return memcmp(s1->_buf, s2->_buf, (size_t)s1->_byteLen) == 0;
}

static CFHashCode __CFStringHash(CFTypeRef cf) {
    const struct __CFString *s = (const struct __CFString *)cf;
    /* DJB2 hash */
    CFHashCode hash = 5381;
    for (CFIndex i = 0; i < s->_byteLen; i++) {
        hash = ((hash << 5) + hash) + (unsigned char)s->_buf[i];
    }
    return hash;
}

static const CFRuntimeClass __CFStringClass = {
    0, "CFString", NULL, NULL, __CFStringFinalize,
    __CFStringEqual, __CFStringHash, NULL, NULL
};

EXPORT CFTypeID CFStringGetTypeID(void) { return __CFStringTypeID; }

/* Internal: create a CFString from a UTF-8 C string (copies) */
HIDDEN CFStringRef __CFStringCreateWithUTF8(CFAllocatorRef alloc, const char *cStr, CFIndex len, Boolean isMutable) {
    struct __CFString *s = (struct __CFString *)_CFRuntimeCreateInstance(
        alloc, __CFStringTypeID,
        sizeof(struct __CFString) - sizeof(CFRuntimeBase), NULL);
    if (!s) return NULL;
    s->_mutable = isMutable;
    s->_isConstant = false;
    s->_ownsBuf = true;
    s->_byteLen = len;
    s->_capacity = len + 1;
    s->_buf = (char *)malloc((size_t)(len + 1));
    if (!s->_buf) { free(s); return NULL; }
    if (len > 0 && cStr) memcpy(s->_buf, cStr, (size_t)len);
    s->_buf[len] = '\0';
    s->_length = __CFStringUTF16Length(s->_buf, s->_byteLen);
    return (CFStringRef)s;
}

EXPORT CFStringRef CFStringCreateWithCString(CFAllocatorRef alloc, const char *cStr, CFStringEncoding encoding) {
    if (!cStr) return NULL;
    /* We store everything as UTF-8 internally. For ASCII and UTF-8, just copy. */
    (void)encoding; /* TODO: handle other encodings */
    CFIndex len = (CFIndex)strlen(cStr);
    return __CFStringCreateWithUTF8(alloc, cStr, len, false);
}

EXPORT CFStringRef CFStringCreateWithBytes(CFAllocatorRef alloc, const UInt8 *bytes,
    CFIndex numBytes, CFStringEncoding encoding, Boolean isExternalRepresentation) {
    (void)encoding; (void)isExternalRepresentation;
    if (!bytes || numBytes <= 0) return __CFStringCreateWithUTF8(alloc, "", 0, false);
    return __CFStringCreateWithUTF8(alloc, (const char *)bytes, numBytes, false);
}

EXPORT CFStringRef CFStringCreateWithCharacters(CFAllocatorRef alloc, const UniChar *chars, CFIndex numChars) {
    if (!chars || numChars <= 0) return __CFStringCreateWithUTF8(alloc, "", 0, false);
    /* Convert UTF-16 to UTF-8 */
    CFIndex maxBytes = numChars * 4; /* worst case */
    char *buf = (char *)malloc((size_t)(maxBytes + 1));
    if (!buf) return NULL;
    CFIndex out = 0;
    for (CFIndex i = 0; i < numChars; i++) {
        uint32_t cp = chars[i];
        /* Check for surrogate pair */
        if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < numChars) {
            uint32_t lo = chars[i + 1];
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                cp = ((cp - 0xD800) << 10) + (lo - 0xDC00) + 0x10000;
                i++;
            }
        }
        if (cp < 0x80) {
            buf[out++] = (char)cp;
        } else if (cp < 0x800) {
            buf[out++] = (char)(0xC0 | (cp >> 6));
            buf[out++] = (char)(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            buf[out++] = (char)(0xE0 | (cp >> 12));
            buf[out++] = (char)(0x80 | ((cp >> 6) & 0x3F));
            buf[out++] = (char)(0x80 | (cp & 0x3F));
        } else {
            buf[out++] = (char)(0xF0 | (cp >> 18));
            buf[out++] = (char)(0x80 | ((cp >> 12) & 0x3F));
            buf[out++] = (char)(0x80 | ((cp >> 6) & 0x3F));
            buf[out++] = (char)(0x80 | (cp & 0x3F));
        }
    }
    buf[out] = '\0';
    CFStringRef result = __CFStringCreateWithUTF8(alloc, buf, out, false);
    free(buf);
    return result;
}

EXPORT CFStringRef CFStringCreateCopy(CFAllocatorRef alloc, CFStringRef theString) {
    if (!theString) return NULL;
    const struct __CFString *src = (const struct __CFString *)theString;
    return __CFStringCreateWithUTF8(alloc, src->_buf, src->_byteLen, false);
}

EXPORT CFStringRef CFStringCreateWithSubstring(CFAllocatorRef alloc, CFStringRef str, CFRange range) {
    if (!str) return NULL;
    const struct __CFString *s = (const struct __CFString *)str;
    /* range is in UTF-16 code units — we need to convert to byte offsets */
    CFIndex byteStart = 0, byteEnd = 0, u16idx = 0, i = 0;
    while (i < s->_byteLen && u16idx < range.location) {
        unsigned char c = (unsigned char)s->_buf[i];
        if (c < 0x80) { i++; u16idx++; }
        else if ((c & 0xE0) == 0xC0) { i += 2; u16idx++; }
        else if ((c & 0xF0) == 0xE0) { i += 3; u16idx++; }
        else if ((c & 0xF8) == 0xF0) { i += 4; u16idx += 2; }
        else { i++; u16idx++; }
    }
    byteStart = i;
    CFIndex endTarget = range.location + range.length;
    while (i < s->_byteLen && u16idx < endTarget) {
        unsigned char c = (unsigned char)s->_buf[i];
        if (c < 0x80) { i++; u16idx++; }
        else if ((c & 0xE0) == 0xC0) { i += 2; u16idx++; }
        else if ((c & 0xF0) == 0xE0) { i += 3; u16idx++; }
        else if ((c & 0xF8) == 0xF0) { i += 4; u16idx += 2; }
        else { i++; u16idx++; }
    }
    byteEnd = i;
    return __CFStringCreateWithUTF8(alloc, s->_buf + byteStart, byteEnd - byteStart, false);
}

EXPORT CFMutableStringRef CFStringCreateMutable(CFAllocatorRef alloc, CFIndex maxLength) {
    (void)maxLength;
    return (CFMutableStringRef)__CFStringCreateWithUTF8(alloc, "", 0, true);
}

EXPORT CFMutableStringRef CFStringCreateMutableCopy(CFAllocatorRef alloc, CFIndex maxLength, CFStringRef theString) {
    (void)maxLength;
    if (!theString) return CFStringCreateMutable(alloc, 0);
    const struct __CFString *src = (const struct __CFString *)theString;
    return (CFMutableStringRef)__CFStringCreateWithUTF8(alloc, src->_buf, src->_byteLen, true);
}

/* --- Accessors --- */

EXPORT CFIndex CFStringGetLength(CFStringRef theString) {
    if (!theString) return 0;
    return ((const struct __CFString *)theString)->_length;
}

EXPORT UniChar CFStringGetCharacterAtIndex(CFStringRef theString, CFIndex idx) {
    if (!theString) return 0;
    const struct __CFString *s = (const struct __CFString *)theString;
    /* Walk UTF-8 to find the idx-th UTF-16 code unit */
    CFIndex u16idx = 0, i = 0;
    while (i < s->_byteLen && u16idx < idx) {
        unsigned char c = (unsigned char)s->_buf[i];
        if (c < 0x80) { i++; u16idx++; }
        else if ((c & 0xE0) == 0xC0) { i += 2; u16idx++; }
        else if ((c & 0xF0) == 0xE0) { i += 3; u16idx++; }
        else if ((c & 0xF8) == 0xF0) {
            if (u16idx + 1 == idx) {
                /* Want the low surrogate */
                uint32_t cp = ((s->_buf[i] & 0x07) << 18)
                            | ((s->_buf[i+1] & 0x3F) << 12)
                            | ((s->_buf[i+2] & 0x3F) << 6)
                            | (s->_buf[i+3] & 0x3F);
                return (UniChar)((cp - 0x10000) & 0x3FF) + 0xDC00;
            }
            i += 4; u16idx += 2;
        }
        else { i++; u16idx++; }
    }
    if (i >= s->_byteLen) return 0;
    unsigned char c = (unsigned char)s->_buf[i];
    if (c < 0x80) return (UniChar)c;
    uint32_t cp = 0;
    if ((c & 0xE0) == 0xC0) {
        cp = ((c & 0x1F) << 6) | (s->_buf[i+1] & 0x3F);
    } else if ((c & 0xF0) == 0xE0) {
        cp = ((c & 0x0F) << 12) | ((s->_buf[i+1] & 0x3F) << 6) | (s->_buf[i+2] & 0x3F);
    } else if ((c & 0xF8) == 0xF0) {
        cp = ((c & 0x07) << 18) | ((s->_buf[i+1] & 0x3F) << 12)
           | ((s->_buf[i+2] & 0x3F) << 6) | (s->_buf[i+3] & 0x3F);
        /* Return high surrogate */
        return (UniChar)((cp - 0x10000) >> 10) + 0xD800;
    }
    return (UniChar)cp;
}

EXPORT void CFStringGetCharacters(CFStringRef theString, CFRange range, UniChar *buffer) {
    if (!theString || !buffer) return;
    for (CFIndex i = 0; i < range.length; i++) {
        buffer[i] = CFStringGetCharacterAtIndex(theString, range.location + i);
    }
}

EXPORT const char *CFStringGetCStringPtr(CFStringRef theString, CFStringEncoding encoding) {
    if (!theString) return NULL;
    /* Direct pointer only available for UTF-8 and ASCII */
    if (encoding != kCFStringEncodingUTF8 && encoding != kCFStringEncodingASCII) return NULL;
    return ((const struct __CFString *)theString)->_buf;
}

EXPORT Boolean CFStringGetCString(CFStringRef theString, char *buffer, CFIndex bufferSize, CFStringEncoding encoding) {
    if (!theString || !buffer || bufferSize <= 0) return false;
    (void)encoding;
    const struct __CFString *s = (const struct __CFString *)theString;
    if (s->_byteLen + 1 > bufferSize) return false;
    memcpy(buffer, s->_buf, (size_t)s->_byteLen);
    buffer[s->_byteLen] = '\0';
    return true;
}

EXPORT const UniChar *CFStringGetCharactersPtr(CFStringRef theString) {
    /* We store UTF-8, so no direct UniChar buffer */
    (void)theString;
    return NULL;
}

EXPORT CFIndex CFStringGetBytes(CFStringRef theString, CFRange range,
    CFStringEncoding encoding, UInt8 lossByte, Boolean isExternalRepresentation,
    UInt8 *buffer, CFIndex maxBufLen, CFIndex *usedBufLen) {
    (void)encoding; (void)lossByte; (void)isExternalRepresentation;
    if (!theString) return 0;
    /* For UTF-8, extract the byte range corresponding to the UTF-16 range */
    const struct __CFString *s = (const struct __CFString *)theString;
    CFIndex byteStart = 0, u16idx = 0, i = 0;
    while (i < s->_byteLen && u16idx < range.location) {
        unsigned char c = (unsigned char)s->_buf[i];
        if (c < 0x80) { i++; u16idx++; }
        else if ((c & 0xE0) == 0xC0) { i += 2; u16idx++; }
        else if ((c & 0xF0) == 0xE0) { i += 3; u16idx++; }
        else if ((c & 0xF8) == 0xF0) { i += 4; u16idx += 2; }
        else { i++; u16idx++; }
    }
    byteStart = i;
    CFIndex endTarget = range.location + range.length;
    while (i < s->_byteLen && u16idx < endTarget) {
        unsigned char c = (unsigned char)s->_buf[i];
        if (c < 0x80) { i++; u16idx++; }
        else if ((c & 0xE0) == 0xC0) { i += 2; u16idx++; }
        else if ((c & 0xF0) == 0xE0) { i += 3; u16idx++; }
        else if ((c & 0xF8) == 0xF0) { i += 4; u16idx += 2; }
        else { i++; u16idx++; }
    }
    CFIndex byteLen = i - byteStart;
    CFIndex toCopy = byteLen;
    if (buffer) {
        if (toCopy > maxBufLen) toCopy = maxBufLen;
        memcpy(buffer, s->_buf + byteStart, (size_t)toCopy);
    }
    if (usedBufLen) *usedBufLen = toCopy;
    return u16idx - range.location; /* number of UTF-16 chars converted */
}

/* --- Comparison --- */

/* Forward declaration */
EXPORT CFComparisonResult CFStringCompareWithOptions(CFStringRef s1, CFStringRef s2,
    CFRange rangeToCompare, CFStringCompareFlags compareOptions);

EXPORT CFComparisonResult CFStringCompare(CFStringRef s1, CFStringRef s2, CFStringCompareFlags compareOptions) {
    return CFStringCompareWithOptions(s1, s2,
        CFRangeMake(0, s1 ? CFStringGetLength(s1) : 0), compareOptions);
}

EXPORT CFComparisonResult CFStringCompareWithOptions(CFStringRef s1, CFStringRef s2,
    CFRange rangeToCompare, CFStringCompareFlags compareOptions) {
    if (!s1 || !s2) return kCFCompareEqualTo;
    const struct __CFString *str1 = (const struct __CFString *)s1;
    const struct __CFString *str2 = (const struct __CFString *)s2;

    /* For simplicity, do byte-level comparison of the UTF-8.
     * This is correct for case-sensitive, non-localised comparison.
     * TODO: handle kCFCompareCaseInsensitive properly */
    const char *p1 = str1->_buf;
    const char *p2 = str2->_buf;
    CFIndex len1 = str1->_byteLen;
    CFIndex len2 = str2->_byteLen;

    /* Adjust p1 for rangeToCompare (convert UTF-16 offset to byte offset) */
    CFIndex u16idx = 0, byteOff = 0;
    while (byteOff < len1 && u16idx < rangeToCompare.location) {
        unsigned char c = (unsigned char)p1[byteOff];
        if (c < 0x80) { byteOff++; u16idx++; }
        else if ((c & 0xE0) == 0xC0) { byteOff += 2; u16idx++; }
        else if ((c & 0xF0) == 0xE0) { byteOff += 3; u16idx++; }
        else if ((c & 0xF8) == 0xF0) { byteOff += 4; u16idx += 2; }
        else { byteOff++; u16idx++; }
    }
    p1 += byteOff;
    len1 -= byteOff;

    /* Find byte length of rangeToCompare.length UTF-16 units */
    CFIndex endU16 = rangeToCompare.location + rangeToCompare.length;
    CFIndex byteEnd = byteOff;
    while (byteEnd < str1->_byteLen && u16idx < endU16) {
        unsigned char c = (unsigned char)str1->_buf[byteEnd];
        if (c < 0x80) { byteEnd++; u16idx++; }
        else if ((c & 0xE0) == 0xC0) { byteEnd += 2; u16idx++; }
        else if ((c & 0xF0) == 0xE0) { byteEnd += 3; u16idx++; }
        else if ((c & 0xF8) == 0xF0) { byteEnd += 4; u16idx += 2; }
        else { byteEnd++; u16idx++; }
    }
    len1 = byteEnd - byteOff;

    if (compareOptions & kCFCompareCaseInsensitive) {
        /* ASCII case-insensitive comparison */
        CFIndex minLen = len1 < len2 ? len1 : len2;
        for (CFIndex i = 0; i < minLen; i++) {
            unsigned char a = (unsigned char)p1[i];
            unsigned char b = (unsigned char)p2[i];
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a < b) return kCFCompareLessThan;
            if (a > b) return kCFCompareGreaterThan;
        }
    } else {
        CFIndex minLen = len1 < len2 ? len1 : len2;
        int r = memcmp(p1, p2, (size_t)minLen);
        if (r < 0) return kCFCompareLessThan;
        if (r > 0) return kCFCompareGreaterThan;
    }
    if (len1 < len2) return kCFCompareLessThan;
    if (len1 > len2) return kCFCompareGreaterThan;
    return kCFCompareEqualTo;
}

EXPORT Boolean CFStringHasPrefix(CFStringRef theString, CFStringRef prefix) {
    if (!theString || !prefix) return false;
    const struct __CFString *s = (const struct __CFString *)theString;
    const struct __CFString *p = (const struct __CFString *)prefix;
    if (p->_byteLen > s->_byteLen) return false;
    return memcmp(s->_buf, p->_buf, (size_t)p->_byteLen) == 0;
}

EXPORT Boolean CFStringHasSuffix(CFStringRef theString, CFStringRef suffix) {
    if (!theString || !suffix) return false;
    const struct __CFString *s = (const struct __CFString *)theString;
    const struct __CFString *x = (const struct __CFString *)suffix;
    if (x->_byteLen > s->_byteLen) return false;
    return memcmp(s->_buf + s->_byteLen - x->_byteLen, x->_buf, (size_t)x->_byteLen) == 0;
}

EXPORT CFRange CFStringFind(CFStringRef theString, CFStringRef stringToFind, CFStringCompareFlags compareOptions) {
    CFRange result = { kCFNotFound, 0 };
    if (!theString || !stringToFind) return result;
    const struct __CFString *s = (const struct __CFString *)theString;
    const struct __CFString *f = (const struct __CFString *)stringToFind;
    if (f->_byteLen == 0) { result.location = 0; return result; }
    if (f->_byteLen > s->_byteLen) return result;

    /* Simple byte-level search (correct for case-sensitive) */
    for (CFIndex i = 0; i <= s->_byteLen - f->_byteLen; i++) {
        if (memcmp(s->_buf + i, f->_buf, (size_t)f->_byteLen) == 0) {
            /* Convert byte offset to UTF-16 offset */
            result.location = __CFStringUTF16Length(s->_buf, i);
            result.length = f->_length;
            return result;
        }
    }
    return result;
}

EXPORT Boolean CFStringFindWithOptions(CFStringRef theString, CFStringRef stringToFind,
    CFRange rangeToSearch, CFStringCompareFlags searchOptions, CFRange *result) {
    (void)rangeToSearch; (void)searchOptions;
    CFRange found = CFStringFind(theString, stringToFind, searchOptions);
    if (found.location == kCFNotFound) return false;
    if (result) *result = found;
    return true;
}


/* --- CFString Mutation --- */

HIDDEN void __CFStringGrow(struct __CFString *s, CFIndex needed) {
    CFIndex newCap = s->_capacity;
    while (newCap < needed + 1) newCap = newCap < 16 ? 16 : newCap * 2;
    s->_buf = (char *)realloc(s->_buf, (size_t)newCap);
    s->_capacity = newCap;
}

EXPORT void CFStringAppend(CFMutableStringRef theString, CFStringRef appendedString) {
    if (!theString || !appendedString) return;
    struct __CFString *s = (struct __CFString *)theString;
    if (!s->_mutable) return;
    const struct __CFString *a = (const struct __CFString *)appendedString;
    if (a->_byteLen == 0) return;
    CFIndex newLen = s->_byteLen + a->_byteLen;
    if (newLen + 1 > s->_capacity) __CFStringGrow(s, newLen);
    memcpy(s->_buf + s->_byteLen, a->_buf, (size_t)a->_byteLen);
    s->_byteLen = newLen;
    s->_buf[newLen] = '\0';
    s->_length = __CFStringUTF16Length(s->_buf, s->_byteLen);
}

EXPORT void CFStringAppendCString(CFMutableStringRef theString, const char *cStr, CFStringEncoding encoding) {
    (void)encoding;
    if (!theString || !cStr) return;
    struct __CFString *s = (struct __CFString *)theString;
    if (!s->_mutable) return;
    CFIndex appendLen = (CFIndex)strlen(cStr);
    if (appendLen == 0) return;
    CFIndex newLen = s->_byteLen + appendLen;
    if (newLen + 1 > s->_capacity) __CFStringGrow(s, newLen);
    memcpy(s->_buf + s->_byteLen, cStr, (size_t)appendLen);
    s->_byteLen = newLen;
    s->_buf[newLen] = '\0';
    s->_length = __CFStringUTF16Length(s->_buf, s->_byteLen);
}

EXPORT void CFStringAppendCharacters(CFMutableStringRef theString, const UniChar *chars, CFIndex numChars) {
    if (!theString || !chars || numChars <= 0) return;
    /* Create a temporary CFString from the UniChars and append */
    CFStringRef tmp = CFStringCreateWithCharacters(NULL, chars, numChars);
    if (tmp) {
        CFStringAppend(theString, tmp);
        CFRelease(tmp);
    }
}

EXPORT void CFStringInsert(CFMutableStringRef str, CFIndex idx, CFStringRef insertedStr) {
    if (!str || !insertedStr) return;
    struct __CFString *s = (struct __CFString *)str;
    if (!s->_mutable) return;
    const struct __CFString *ins = (const struct __CFString *)insertedStr;
    if (ins->_byteLen == 0) return;

    /* Convert UTF-16 index to byte offset */
    CFIndex byteOff = 0, u16idx = 0;
    while (byteOff < s->_byteLen && u16idx < idx) {
        unsigned char c = (unsigned char)s->_buf[byteOff];
        if (c < 0x80) { byteOff++; u16idx++; }
        else if ((c & 0xE0) == 0xC0) { byteOff += 2; u16idx++; }
        else if ((c & 0xF0) == 0xE0) { byteOff += 3; u16idx++; }
        else if ((c & 0xF8) == 0xF0) { byteOff += 4; u16idx += 2; }
        else { byteOff++; u16idx++; }
    }

    CFIndex newLen = s->_byteLen + ins->_byteLen;
    if (newLen + 1 > s->_capacity) __CFStringGrow(s, newLen);
    memmove(s->_buf + byteOff + ins->_byteLen, s->_buf + byteOff, (size_t)(s->_byteLen - byteOff));
    memcpy(s->_buf + byteOff, ins->_buf, (size_t)ins->_byteLen);
    s->_byteLen = newLen;
    s->_buf[newLen] = '\0';
    s->_length = __CFStringUTF16Length(s->_buf, s->_byteLen);
}

EXPORT void CFStringDelete(CFMutableStringRef theString, CFRange range) {
    if (!theString) return;
    struct __CFString *s = (struct __CFString *)theString;
    if (!s->_mutable) return;

    /* Convert UTF-16 range to byte range */
    CFIndex byteStart = 0, byteEnd = 0, u16idx = 0, i = 0;
    while (i < s->_byteLen && u16idx < range.location) {
        unsigned char c = (unsigned char)s->_buf[i];
        if (c < 0x80) { i++; u16idx++; }
        else if ((c & 0xE0) == 0xC0) { i += 2; u16idx++; }
        else if ((c & 0xF0) == 0xE0) { i += 3; u16idx++; }
        else if ((c & 0xF8) == 0xF0) { i += 4; u16idx += 2; }
        else { i++; u16idx++; }
    }
    byteStart = i;
    CFIndex endTarget = range.location + range.length;
    while (i < s->_byteLen && u16idx < endTarget) {
        unsigned char c = (unsigned char)s->_buf[i];
        if (c < 0x80) { i++; u16idx++; }
        else if ((c & 0xE0) == 0xC0) { i += 2; u16idx++; }
        else if ((c & 0xF0) == 0xE0) { i += 3; u16idx++; }
        else if ((c & 0xF8) == 0xF0) { i += 4; u16idx += 2; }
        else { i++; u16idx++; }
    }
    byteEnd = i;
    CFIndex byteRange = byteEnd - byteStart;
    if (byteRange <= 0) return;

    memmove(s->_buf + byteStart, s->_buf + byteEnd, (size_t)(s->_byteLen - byteEnd));
    s->_byteLen -= byteRange;
    s->_buf[s->_byteLen] = '\0';
    s->_length = __CFStringUTF16Length(s->_buf, s->_byteLen);
}

EXPORT void CFStringReplace(CFMutableStringRef theString, CFRange range, CFStringRef replacement) {
    if (!theString) return;
    CFStringDelete(theString, range);
    CFStringInsert(theString, range.location, replacement);
}

EXPORT void CFStringReplaceAll(CFMutableStringRef theString, CFStringRef replacement) {
    if (!theString) return;
    struct __CFString *s = (struct __CFString *)theString;
    if (!s->_mutable) return;
    if (!replacement) {
        s->_byteLen = 0;
        s->_length = 0;
        if (s->_buf) s->_buf[0] = '\0';
        return;
    }
    const struct __CFString *r = (const struct __CFString *)replacement;
    if (r->_byteLen + 1 > s->_capacity) __CFStringGrow(s, r->_byteLen);
    memcpy(s->_buf, r->_buf, (size_t)r->_byteLen);
    s->_byteLen = r->_byteLen;
    s->_buf[s->_byteLen] = '\0';
    s->_length = r->_length;
}

EXPORT void CFStringTrimWhitespace(CFMutableStringRef theString) {
    if (!theString) return;
    struct __CFString *s = (struct __CFString *)theString;
    if (!s->_mutable || s->_byteLen == 0) return;
    CFIndex start = 0, end = s->_byteLen;
    while (start < end) {
        char c = s->_buf[start];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') start++;
        else break;
    }
    while (end > start) {
        char c = s->_buf[end - 1];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') end--;
        else break;
    }
    if (start > 0 || end < s->_byteLen) {
        CFIndex newLen = end - start;
        memmove(s->_buf, s->_buf + start, (size_t)newLen);
        s->_byteLen = newLen;
        s->_buf[newLen] = '\0';
        s->_length = __CFStringUTF16Length(s->_buf, s->_byteLen);
    }
}

EXPORT void CFStringLowercase(CFMutableStringRef theString, CFTypeRef locale) {
    (void)locale;
    if (!theString) return;
    struct __CFString *s = (struct __CFString *)theString;
    if (!s->_mutable) return;
    for (CFIndex i = 0; i < s->_byteLen; i++) {
        if (s->_buf[i] >= 'A' && s->_buf[i] <= 'Z')
            s->_buf[i] += 32;
    }
}

EXPORT void CFStringUppercase(CFMutableStringRef theString, CFTypeRef locale) {
    (void)locale;
    if (!theString) return;
    struct __CFString *s = (struct __CFString *)theString;
    if (!s->_mutable) return;
    for (CFIndex i = 0; i < s->_byteLen; i++) {
        if (s->_buf[i] >= 'a' && s->_buf[i] <= 'z')
            s->_buf[i] -= 32;
    }
}

EXPORT void CFStringCapitalize(CFMutableStringRef theString, CFTypeRef locale) {
    (void)locale;
    if (!theString) return;
    struct __CFString *s = (struct __CFString *)theString;
    if (!s->_mutable || s->_byteLen == 0) return;
    Boolean nextCap = true;
    for (CFIndex i = 0; i < s->_byteLen; i++) {
        char c = s->_buf[i];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            nextCap = true;
        } else if (nextCap) {
            if (c >= 'a' && c <= 'z') s->_buf[i] -= 32;
            nextCap = false;
        } else {
            if (c >= 'A' && c <= 'Z') s->_buf[i] += 32;
        }
    }
}

/* --- Encoding utilities --- */

EXPORT CFStringEncoding CFStringGetSystemEncoding(void) {
    return kCFStringEncodingUTF8;
}

EXPORT CFStringEncoding CFStringGetFastestEncoding(CFStringRef theString) {
    (void)theString;
    return kCFStringEncodingUTF8; /* our internal encoding */
}

EXPORT CFStringEncoding CFStringGetSmallestEncoding(CFStringRef theString) {
    if (!theString) return kCFStringEncodingASCII;
    const struct __CFString *s = (const struct __CFString *)theString;
    /* Check if pure ASCII */
    for (CFIndex i = 0; i < s->_byteLen; i++) {
        if ((unsigned char)s->_buf[i] > 127) return kCFStringEncodingUTF8;
    }
    return kCFStringEncodingASCII;
}

EXPORT Boolean CFStringIsEncodingAvailable(CFStringEncoding encoding) {
    return (encoding == kCFStringEncodingUTF8 ||
            encoding == kCFStringEncodingASCII ||
            encoding == kCFStringEncodingMacRoman ||
            encoding == kCFStringEncodingISOLatin1);
}

EXPORT CFIndex CFStringGetMaximumSizeForEncoding(CFIndex length, CFStringEncoding encoding) {
    (void)encoding;
    return length * 4; /* worst case: 4 bytes per UTF-16 code unit */
}

EXPORT CFIndex CFStringGetMaximumSizeOfFileSystemRepresentation(CFStringRef string) {
    if (!string) return 0;
    return CFStringGetLength(string) * 4 + 1;
}

EXPORT Boolean CFStringGetFileSystemRepresentation(CFStringRef string, char *buffer, CFIndex maxBufLen) {
    return CFStringGetCString(string, buffer, maxBufLen, kCFStringEncodingUTF8);
}

EXPORT CFStringRef CFStringCreateWithFileSystemRepresentation(CFAllocatorRef alloc, const char *buffer) {
    return CFStringCreateWithCString(alloc, buffer, kCFStringEncodingUTF8);
}

/* --- Numeric parsing --- */

EXPORT SInt32 CFStringGetIntValue(CFStringRef str) {
    if (!str) return 0;
    const struct __CFString *s = (const struct __CFString *)str;
    return (SInt32)strtol(s->_buf, NULL, 10);
}

EXPORT double CFStringGetDoubleValue(CFStringRef str) {
    if (!str) return 0.0;
    const struct __CFString *s = (const struct __CFString *)str;
    return strtod(s->_buf, NULL);
}

/* --- Format strings --- */

EXPORT CFStringRef CFStringCreateWithFormat(CFAllocatorRef alloc, CFDictionaryRef formatOptions,
    CFStringRef format, ...) {
    (void)formatOptions;
    if (!format) return NULL;
    const struct __CFString *fmt = (const struct __CFString *)format;
    va_list ap;
    va_start(ap, format);
    char buf[2048];
    int n = vsnprintf(buf, sizeof(buf), fmt->_buf, ap);
    va_end(ap);
    if (n < 0) n = 0;
    return __CFStringCreateWithUTF8(alloc, buf, n < 2048 ? n : 2047, false);
}

EXPORT CFStringRef CFStringCreateWithFormatAndArguments(CFAllocatorRef alloc,
    CFDictionaryRef formatOptions, CFStringRef format, va_list arguments) {
    (void)formatOptions;
    if (!format) return NULL;
    const struct __CFString *fmt = (const struct __CFString *)format;
    char buf[2048];
    int n = vsnprintf(buf, sizeof(buf), fmt->_buf, arguments);
    if (n < 0) n = 0;
    return __CFStringCreateWithUTF8(alloc, buf, n < 2048 ? n : 2047, false);
}

EXPORT void CFStringAppendFormat(CFMutableStringRef theString, CFDictionaryRef formatOptions,
    CFStringRef format, ...) {
    (void)formatOptions;
    if (!theString || !format) return;
    va_list ap;
    va_start(ap, format);
    CFStringRef tmp = CFStringCreateWithFormatAndArguments(NULL, NULL, format, ap);
    va_end(ap);
    if (tmp) {
        CFStringAppend(theString, tmp);
        CFRelease(tmp);
    }
}

EXPORT void CFStringAppendFormatAndArguments(CFMutableStringRef theString,
    CFDictionaryRef formatOptions, CFStringRef format, va_list arguments) {
    (void)formatOptions;
    if (!theString || !format) return;
    CFStringRef tmp = CFStringCreateWithFormatAndArguments(NULL, NULL, format, arguments);
    if (tmp) {
        CFStringAppend(theString, tmp);
        CFRelease(tmp);
    }
}

/* --- String join/split --- */

EXPORT CFStringRef CFStringCreateByCombiningStrings(CFAllocatorRef alloc,
    CFArrayRef theArray, CFStringRef separatorString);
/* Forward declaration — implemented after CFArray */

EXPORT CFArrayRef CFStringCreateArrayBySeparatingStrings(CFAllocatorRef alloc,
    CFStringRef theString, CFStringRef separatorString);
/* Forward declaration — implemented after CFArray */

/* --- CFShow --- */

EXPORT void CFShow(CFTypeRef obj) {
    if (!obj) {
        fprintf(stderr, "(null)\n");
        return;
    }
    CFStringRef desc = CFCopyDescription(obj);
    if (desc) {
        const struct __CFString *s = (const struct __CFString *)desc;
        fprintf(stderr, "%s\n", s->_buf);
        CFRelease(desc);
    } else {
        CFTypeID tid = CFGetTypeID(obj);
        const CFRuntimeClass *cls = _CFRuntimeGetClassWithTypeID(tid);
        fprintf(stderr, "<%s %p>\n", cls ? cls->className : "CFType", obj);
    }
}

EXPORT void CFShowStr(CFStringRef str) {
    CFShow((CFTypeRef)str);
}

/* --- CFSTR() interning hash table --- */

#define __CFSTR_TABLE_SIZE 1024

static struct {
    const char  *key;       /* C string (not owned — points into __CFString._buf) */
    CFStringRef  value;
} __CFConstantStringTable[__CFSTR_TABLE_SIZE];

/* Bug 14 fix: proper alignment for ARM64 exclusive instructions */
static pthread_mutex_t __CFStrTableLock;
static int     __CFStrTableLockInit = 0;

EXPORT CFStringRef __CFStringMakeConstantString(const char *cStr) {
    if (!cStr) return NULL;

    /* Hash the C string to find a slot */
    CFHashCode hash = 5381;
    for (const char *p = cStr; *p; p++)
        hash = ((hash << 5) + hash) + (unsigned char)*p;
    CFIndex idx = (CFIndex)(hash % __CFSTR_TABLE_SIZE);

    /* Lock */
    if (!__CFStrTableLockInit) {
        pthread_mutex_init(&__CFStrTableLock, NULL);
        __CFStrTableLockInit = 1;
    }
    pthread_mutex_lock(&__CFStrTableLock);

    /* Linear probe for existing entry */
    CFIndex startIdx = idx;
    while (__CFConstantStringTable[idx].key) {
        if (strcmp(__CFConstantStringTable[idx].key, cStr) == 0) {
            CFStringRef result = __CFConstantStringTable[idx].value;
            pthread_mutex_unlock(&__CFStrTableLock);
            return result;
        }
        idx = (idx + 1) % __CFSTR_TABLE_SIZE;
        if (idx == startIdx) break; /* table full */
    }

    /* Create new constant string */
    CFIndex len = (CFIndex)strlen(cStr);
    struct __CFString *s = (struct __CFString *)_CFRuntimeCreateInstance(
        NULL, __CFStringTypeID,
        sizeof(struct __CFString) - sizeof(CFRuntimeBase), NULL);
    if (!s) { pthread_mutex_unlock(&__CFStrTableLock); return NULL; }
    s->_mutable = false;
    s->_isConstant = true;
    s->_ownsBuf = true;
    s->_byteLen = len;
    s->_capacity = len + 1;
    s->_buf = (char *)malloc((size_t)(len + 1));
    memcpy(s->_buf, cStr, (size_t)(len + 1));
    s->_length = __CFStringUTF16Length(s->_buf, s->_byteLen);

    /* Make it immortal */
    s->_base._cfinfoa = __CFInfoMake(__CFStringTypeID, 0xFFFFFFFFFFULL);

    __CFConstantStringTable[idx].key = s->_buf;
    __CFConstantStringTable[idx].value = (CFStringRef)s;

    pthread_mutex_unlock(&__CFStrTableLock);
    return (CFStringRef)s;
}


/* ============================================================================
 * Section 18: CFArray
 * ============================================================================ */

struct __CFArray {
    CFRuntimeBase    _base;
    CFIndex          _count;
    CFIndex          _capacity;
    const void     **_values;
    CFArrayCallBacks _callbacks;
    Boolean          _mutable;
};

static CFTypeID __CFArrayTypeID = _kCFRuntimeNotATypeID;

/* Default callbacks for CF types */
static const void *__CFTypeArrayRetain(CFAllocatorRef alloc, const void *value) {
    (void)alloc;
    if (value) CFRetain(value);
    return value;
}
static void __CFTypeArrayRelease(CFAllocatorRef alloc, const void *value) {
    (void)alloc;
    if (value) CFRelease(value);
}
static Boolean __CFTypeArrayEqual(const void *v1, const void *v2) {
    return CFEqual(v1, v2);
}

EXPORT const CFArrayCallBacks kCFTypeArrayCallBacks = {
    0, __CFTypeArrayRetain, __CFTypeArrayRelease, NULL, __CFTypeArrayEqual
};

static void __CFArrayFinalize(CFTypeRef cf) {
    struct __CFArray *a = (struct __CFArray *)cf;
    if (a->_callbacks.release) {
        for (CFIndex i = 0; i < a->_count; i++) {
            if (a->_values[i]) a->_callbacks.release(NULL, a->_values[i]);
        }
    }
    if (a->_values) free(a->_values);
}

static Boolean __CFArrayEqual(CFTypeRef cf1, CFTypeRef cf2) {
    const struct __CFArray *a1 = (const struct __CFArray *)cf1;
    const struct __CFArray *a2 = (const struct __CFArray *)cf2;
    if (a1->_count != a2->_count) return false;
    for (CFIndex i = 0; i < a1->_count; i++) {
        if (a1->_callbacks.equal) {
            if (!a1->_callbacks.equal(a1->_values[i], a2->_values[i])) return false;
        } else {
            if (a1->_values[i] != a2->_values[i]) return false;
        }
    }
    return true;
}

static CFHashCode __CFArrayHash(CFTypeRef cf) {
    const struct __CFArray *a = (const struct __CFArray *)cf;
    return (CFHashCode)a->_count;
}

static const CFRuntimeClass __CFArrayClass = {
    0, "CFArray", NULL, NULL, __CFArrayFinalize,
    __CFArrayEqual, __CFArrayHash, NULL, NULL
};

EXPORT CFTypeID CFArrayGetTypeID(void) { return __CFArrayTypeID; }

HIDDEN void __CFArrayGrow(struct __CFArray *a, CFIndex needed) {
    CFIndex newCap = a->_capacity;
    while (newCap < needed) newCap = newCap < 4 ? 4 : newCap * 2;
    a->_values = (const void **)realloc(a->_values, (size_t)newCap * sizeof(const void *));
    a->_capacity = newCap;
}

EXPORT CFArrayRef CFArrayCreate(CFAllocatorRef allocator, const void **values,
    CFIndex numValues, const CFArrayCallBacks *callBacks) {
    struct __CFArray *a = (struct __CFArray *)_CFRuntimeCreateInstance(
        allocator, __CFArrayTypeID,
        sizeof(struct __CFArray) - sizeof(CFRuntimeBase), NULL);
    if (!a) return NULL;
    a->_mutable = false;
    if (callBacks) a->_callbacks = *callBacks; else memset(&a->_callbacks, 0, sizeof(a->_callbacks));
    a->_count = numValues;
    a->_capacity = numValues > 0 ? numValues : 1;
    a->_values = (const void **)calloc((size_t)a->_capacity, sizeof(const void *));
    if (values && numValues > 0) {
        for (CFIndex i = 0; i < numValues; i++) {
            a->_values[i] = (a->_callbacks.retain) ? a->_callbacks.retain(NULL, values[i]) : values[i];
        }
    }
    return (CFArrayRef)a;
}

EXPORT CFArrayRef CFArrayCreateCopy(CFAllocatorRef allocator, CFArrayRef theArray) {
    if (!theArray) return CFArrayCreate(allocator, NULL, 0, &kCFTypeArrayCallBacks);
    const struct __CFArray *src = (const struct __CFArray *)theArray;
    return CFArrayCreate(allocator, src->_values, src->_count, &src->_callbacks);
}

EXPORT CFMutableArrayRef CFArrayCreateMutable(CFAllocatorRef allocator, CFIndex capacity,
    const CFArrayCallBacks *callBacks) {
    struct __CFArray *a = (struct __CFArray *)_CFRuntimeCreateInstance(
        allocator, __CFArrayTypeID,
        sizeof(struct __CFArray) - sizeof(CFRuntimeBase), NULL);
    if (!a) return NULL;
    a->_mutable = true;
    if (callBacks) a->_callbacks = *callBacks; else memset(&a->_callbacks, 0, sizeof(a->_callbacks));
    a->_count = 0;
    a->_capacity = capacity > 0 ? capacity : 4;
    a->_values = (const void **)calloc((size_t)a->_capacity, sizeof(const void *));
    return (CFMutableArrayRef)a;
}

EXPORT CFMutableArrayRef CFArrayCreateMutableCopy(CFAllocatorRef allocator, CFIndex capacity, CFArrayRef theArray) {
    if (!theArray) return CFArrayCreateMutable(allocator, capacity, &kCFTypeArrayCallBacks);
    const struct __CFArray *src = (const struct __CFArray *)theArray;
    CFIndex cap = capacity > src->_count ? capacity : src->_count;
    CFMutableArrayRef ma = CFArrayCreateMutable(allocator, cap, &src->_callbacks);
    if (!ma) return NULL;
    struct __CFArray *a = (struct __CFArray *)ma;
    for (CFIndex i = 0; i < src->_count; i++) {
        a->_values[i] = (a->_callbacks.retain) ? a->_callbacks.retain(NULL, src->_values[i]) : src->_values[i];
    }
    a->_count = src->_count;
    return ma;
}

EXPORT CFIndex CFArrayGetCount(CFArrayRef theArray) {
    if (!theArray) return 0;
    return ((const struct __CFArray *)theArray)->_count;
}

EXPORT const void *CFArrayGetValueAtIndex(CFArrayRef theArray, CFIndex idx) {
    if (!theArray) return NULL;
    const struct __CFArray *a = (const struct __CFArray *)theArray;
    if (idx < 0 || idx >= a->_count) return NULL;
    return a->_values[idx];
}

EXPORT void CFArrayGetValues(CFArrayRef theArray, CFRange range, const void **values) {
    if (!theArray || !values) return;
    const struct __CFArray *a = (const struct __CFArray *)theArray;
    for (CFIndex i = 0; i < range.length; i++) {
        CFIndex idx = range.location + i;
        values[i] = (idx >= 0 && idx < a->_count) ? a->_values[idx] : NULL;
    }
}

/* Forward declaration */
EXPORT CFIndex CFArrayGetFirstIndexOfValue(CFArrayRef theArray, CFRange range, const void *value);

EXPORT Boolean CFArrayContainsValue(CFArrayRef theArray, CFRange range, const void *value) {
    return CFArrayGetFirstIndexOfValue(theArray, range, value) != kCFNotFound;
}

EXPORT CFIndex CFArrayGetFirstIndexOfValue(CFArrayRef theArray, CFRange range, const void *value) {
    if (!theArray) return kCFNotFound;
    const struct __CFArray *a = (const struct __CFArray *)theArray;
    for (CFIndex i = range.location; i < range.location + range.length && i < a->_count; i++) {
        if (a->_callbacks.equal) {
            if (a->_callbacks.equal(a->_values[i], value)) return i;
        } else {
            if (a->_values[i] == value) return i;
        }
    }
    return kCFNotFound;
}

EXPORT CFIndex CFArrayGetLastIndexOfValue(CFArrayRef theArray, CFRange range, const void *value) {
    if (!theArray) return kCFNotFound;
    const struct __CFArray *a = (const struct __CFArray *)theArray;
    CFIndex last = kCFNotFound;
    for (CFIndex i = range.location; i < range.location + range.length && i < a->_count; i++) {
        if (a->_callbacks.equal) {
            if (a->_callbacks.equal(a->_values[i], value)) last = i;
        } else {
            if (a->_values[i] == value) last = i;
        }
    }
    return last;
}

EXPORT CFIndex CFArrayGetCountOfValue(CFArrayRef theArray, CFRange range, const void *value) {
    if (!theArray) return 0;
    const struct __CFArray *a = (const struct __CFArray *)theArray;
    CFIndex count = 0;
    for (CFIndex i = range.location; i < range.location + range.length && i < a->_count; i++) {
        if (a->_callbacks.equal) {
            if (a->_callbacks.equal(a->_values[i], value)) count++;
        } else {
            if (a->_values[i] == value) count++;
        }
    }
    return count;
}

EXPORT void CFArrayApplyFunction(CFArrayRef theArray, CFRange range,
    CFArrayApplierFunction applier, void *context) {
    if (!theArray || !applier) return;
    const struct __CFArray *a = (const struct __CFArray *)theArray;
    for (CFIndex i = range.location; i < range.location + range.length && i < a->_count; i++) {
        applier(a->_values[i], context);
    }
}

EXPORT void CFArrayAppendValue(CFMutableArrayRef theArray, const void *value) {
    if (!theArray) return;
    struct __CFArray *a = (struct __CFArray *)theArray;
    if (!a->_mutable) return;
    if (a->_count >= a->_capacity) __CFArrayGrow(a, a->_count + 1);
    a->_values[a->_count] = (a->_callbacks.retain) ? a->_callbacks.retain(NULL, value) : value;
    a->_count++;
}

EXPORT void CFArrayInsertValueAtIndex(CFMutableArrayRef theArray, CFIndex idx, const void *value) {
    if (!theArray) return;
    struct __CFArray *a = (struct __CFArray *)theArray;
    if (!a->_mutable || idx < 0 || idx > a->_count) return;
    if (a->_count >= a->_capacity) __CFArrayGrow(a, a->_count + 1);
    memmove(&a->_values[idx + 1], &a->_values[idx], (size_t)(a->_count - idx) * sizeof(const void *));
    a->_values[idx] = (a->_callbacks.retain) ? a->_callbacks.retain(NULL, value) : value;
    a->_count++;
}

EXPORT void CFArraySetValueAtIndex(CFMutableArrayRef theArray, CFIndex idx, const void *value) {
    if (!theArray) return;
    struct __CFArray *a = (struct __CFArray *)theArray;
    if (!a->_mutable || idx < 0 || idx >= a->_count) return;
    const void *old = a->_values[idx];
    a->_values[idx] = (a->_callbacks.retain) ? a->_callbacks.retain(NULL, value) : value;
    if (a->_callbacks.release && old) a->_callbacks.release(NULL, old);
}

EXPORT void CFArrayRemoveValueAtIndex(CFMutableArrayRef theArray, CFIndex idx) {
    if (!theArray) return;
    struct __CFArray *a = (struct __CFArray *)theArray;
    if (!a->_mutable || idx < 0 || idx >= a->_count) return;
    if (a->_callbacks.release && a->_values[idx]) a->_callbacks.release(NULL, a->_values[idx]);
    memmove(&a->_values[idx], &a->_values[idx + 1], (size_t)(a->_count - idx - 1) * sizeof(const void *));
    a->_count--;
}

EXPORT void CFArrayRemoveAllValues(CFMutableArrayRef theArray) {
    if (!theArray) return;
    struct __CFArray *a = (struct __CFArray *)theArray;
    if (!a->_mutable) return;
    if (a->_callbacks.release) {
        for (CFIndex i = 0; i < a->_count; i++) {
            if (a->_values[i]) a->_callbacks.release(NULL, a->_values[i]);
        }
    }
    a->_count = 0;
}

EXPORT void CFArrayReplaceValues(CFMutableArrayRef theArray, CFRange range,
    const void **newValues, CFIndex newCount) {
    if (!theArray) return;
    struct __CFArray *a = (struct __CFArray *)theArray;
    if (!a->_mutable) return;
    /* Remove old values */
    if (a->_callbacks.release) {
        for (CFIndex i = range.location; i < range.location + range.length && i < a->_count; i++) {
            if (a->_values[i]) a->_callbacks.release(NULL, a->_values[i]);
        }
    }
    CFIndex delta = newCount - range.length;
    CFIndex newTotal = a->_count + delta;
    if (newTotal > a->_capacity) __CFArrayGrow(a, newTotal);
    /* Shift tail */
    CFIndex tailStart = range.location + range.length;
    if (tailStart < a->_count && delta != 0) {
        memmove(&a->_values[range.location + newCount], &a->_values[tailStart],
                (size_t)(a->_count - tailStart) * sizeof(const void *));
    }
    /* Insert new values */
    for (CFIndex i = 0; i < newCount; i++) {
        a->_values[range.location + i] = (a->_callbacks.retain && newValues)
            ? a->_callbacks.retain(NULL, newValues[i])
            : (newValues ? newValues[i] : NULL);
    }
    a->_count = newTotal;
}

EXPORT void CFArrayExchangeValuesAtIndices(CFMutableArrayRef theArray, CFIndex idx1, CFIndex idx2) {
    if (!theArray) return;
    struct __CFArray *a = (struct __CFArray *)theArray;
    if (!a->_mutable || idx1 < 0 || idx2 < 0 || idx1 >= a->_count || idx2 >= a->_count) return;
    const void *tmp = a->_values[idx1];
    a->_values[idx1] = a->_values[idx2];
    a->_values[idx2] = tmp;
}

EXPORT void CFArraySortValues(CFMutableArrayRef theArray, CFRange range,
    CFComparatorFunction comparator, void *context) {
    if (!theArray || !comparator) return;
    struct __CFArray *a = (struct __CFArray *)theArray;
    if (!a->_mutable) return;
    if (range.location < 0 || range.location + range.length > a->_count) return;
    /* Simple wrapper — qsort doesn't pass context, so we do insertion sort */
    for (CFIndex i = range.location + 1; i < range.location + range.length; i++) {
        const void *key = a->_values[i];
        CFIndex j = i - 1;
        while (j >= range.location && comparator(a->_values[j], key, context) == kCFCompareGreaterThan) {
            a->_values[j + 1] = a->_values[j];
            j--;
        }
        a->_values[j + 1] = key;
    }
}

EXPORT void CFArrayAppendArray(CFMutableArrayRef theArray, CFArrayRef otherArray, CFRange otherRange) {
    if (!theArray || !otherArray) return;
    const struct __CFArray *src = (const struct __CFArray *)otherArray;
    for (CFIndex i = otherRange.location; i < otherRange.location + otherRange.length && i < src->_count; i++) {
        CFArrayAppendValue(theArray, src->_values[i]);
    }
}

EXPORT CFIndex CFArrayBSearchValues(CFArrayRef theArray, CFRange range, const void *value,
    CFComparatorFunction comparator, void *context) {
    if (!theArray || !comparator) return kCFNotFound;
    const struct __CFArray *a = (const struct __CFArray *)theArray;
    CFIndex lo = range.location;
    CFIndex hi = range.location + range.length;
    while (lo < hi) {
        CFIndex mid = lo + (hi - lo) / 2;
        CFComparisonResult r = comparator(a->_values[mid], value, context);
        if (r == kCFCompareLessThan) lo = mid + 1;
        else hi = mid;
    }
    return lo;
}

/* Now implement the CFString join/split that were forward-declared */

/* CFStringCreateByCombiningStrings — joins an array of CFStrings with a separator */
CFStringRef CFStringCreateByCombiningStrings(CFAllocatorRef alloc,
    CFArrayRef theArray, CFStringRef separatorString) {
    if (!theArray) return __CFStringCreateWithUTF8(alloc, "", 0, false);
    CFIndex count = CFArrayGetCount(theArray);
    if (count == 0) return __CFStringCreateWithUTF8(alloc, "", 0, false);
    CFMutableStringRef result = CFStringCreateMutable(alloc, 0);
    for (CFIndex i = 0; i < count; i++) {
        if (i > 0 && separatorString) CFStringAppend(result, separatorString);
        CFStringRef s = (CFStringRef)CFArrayGetValueAtIndex(theArray, i);
        if (s) CFStringAppend(result, s);
    }
    /* Make immutable copy and release mutable */
    CFStringRef immutable = CFStringCreateCopy(alloc, (CFStringRef)result);
    CFRelease(result);
    return immutable;
}

/* CFStringCreateArrayBySeparatingStrings — splits a CFString by separator */
CFArrayRef CFStringCreateArrayBySeparatingStrings(CFAllocatorRef alloc,
    CFStringRef theString, CFStringRef separatorString) {
    if (!theString) return CFArrayCreate(alloc, NULL, 0, &kCFTypeArrayCallBacks);
    if (!separatorString) {
        const void *vals[1] = { theString };
        return CFArrayCreate(alloc, vals, 1, &kCFTypeArrayCallBacks);
    }
    CFMutableArrayRef parts = CFArrayCreateMutable(alloc, 0, &kCFTypeArrayCallBacks);
    const struct __CFString *s = (const struct __CFString *)theString;
    const struct __CFString *sep = (const struct __CFString *)separatorString;
    if (sep->_byteLen == 0) {
        CFArrayAppendValue(parts, theString);
        return (CFArrayRef)parts;
    }
    CFIndex start = 0;
    for (CFIndex i = 0; i <= s->_byteLen - sep->_byteLen; i++) {
        if (memcmp(s->_buf + i, sep->_buf, (size_t)sep->_byteLen) == 0) {
            CFStringRef piece = __CFStringCreateWithUTF8(alloc, s->_buf + start, i - start, false);
            CFArrayAppendValue(parts, piece);
            CFRelease(piece);
            i += sep->_byteLen - 1;
            start = i + 1;
        }
    }
    /* Last piece */
    CFStringRef last = __CFStringCreateWithUTF8(alloc, s->_buf + start, s->_byteLen - start, false);
    CFArrayAppendValue(parts, last);
    CFRelease(last);
    return (CFArrayRef)parts;
}


/* ============================================================================
 * Section 19: CFDictionary
 *
 * Open-addressing hash table with linear probing.
 * Sentinel values: EMPTY = NULL, DELETED = special pointer.
 * ============================================================================ */

/* Sentinel for deleted slots */
static const int __CFDictDeletedMarker = 0xDEAD;
#define __CF_DICT_EMPTY   NULL
#define __CF_DICT_DELETED ((const void *)&__CFDictDeletedMarker)

struct __CFDictionary {
    CFRuntimeBase              _base;
    CFIndex                    _count;
    CFIndex                    _capacity;  /* always power of 2 */
    const void               **_keys;
    const void               **_values;
    CFDictionaryKeyCallBacks   _keyCallBacks;
    CFDictionaryValueCallBacks _valueCallBacks;
    Boolean                    _mutable;
};

static CFTypeID __CFDictionaryTypeID = _kCFRuntimeNotATypeID;

/* Default callbacks for CF types */
static const void *__CFTypeDictRetain(CFAllocatorRef alloc, const void *value) {
    (void)alloc;
    if (value) CFRetain(value);
    return value;
}
static void __CFTypeDictRelease(CFAllocatorRef alloc, const void *value) {
    (void)alloc;
    if (value) CFRelease(value);
}
static Boolean __CFTypeDictEqual(const void *v1, const void *v2) {
    return CFEqual(v1, v2);
}
static CFHashCode __CFTypeDictHash(const void *value) {
    return CFHash(value);
}

EXPORT const CFDictionaryKeyCallBacks kCFTypeDictionaryKeyCallBacks = {
    0, __CFTypeDictRetain, __CFTypeDictRelease, NULL, __CFTypeDictEqual, __CFTypeDictHash
};

EXPORT const CFDictionaryValueCallBacks kCFTypeDictionaryValueCallBacks = {
    0, __CFTypeDictRetain, __CFTypeDictRelease, NULL, __CFTypeDictEqual
};

/* Copy-string key callbacks: keys are CFStrings, copied on insert */
static const void *__CFCopyStringRetain(CFAllocatorRef alloc, const void *value) {
    (void)alloc;
    if (value) return CFStringCreateCopy(NULL, (CFStringRef)value);
    return NULL;
}

EXPORT const CFDictionaryKeyCallBacks kCFCopyStringDictionaryKeyCallBacks = {
    0, __CFCopyStringRetain, __CFTypeDictRelease, NULL, __CFTypeDictEqual, __CFTypeDictHash
};

/* Forward declarations for functions used in callbacks */
EXPORT const void *CFDictionaryGetValue(CFDictionaryRef theDict, const void *key);
EXPORT void CFDictionarySetValue(CFMutableDictionaryRef theDict, const void *key, const void *value);

static void __CFDictionaryFinalize(CFTypeRef cf) {
    struct __CFDictionary *d = (struct __CFDictionary *)cf;
    for (CFIndex i = 0; i < d->_capacity; i++) {
        if (d->_keys[i] && d->_keys[i] != __CF_DICT_DELETED) {
            if (d->_keyCallBacks.release) d->_keyCallBacks.release(NULL, d->_keys[i]);
            if (d->_valueCallBacks.release && d->_values[i]) d->_valueCallBacks.release(NULL, d->_values[i]);
        }
    }
    if (d->_keys) free(d->_keys);
    if (d->_values) free(d->_values);
}

static Boolean __CFDictionaryEqual(CFTypeRef cf1, CFTypeRef cf2) {
    const struct __CFDictionary *d1 = (const struct __CFDictionary *)cf1;
    const struct __CFDictionary *d2 = (const struct __CFDictionary *)cf2;
    if (d1->_count != d2->_count) return false;
    for (CFIndex i = 0; i < d1->_capacity; i++) {
        if (d1->_keys[i] && d1->_keys[i] != __CF_DICT_DELETED) {
            const void *val2 = CFDictionaryGetValue((CFDictionaryRef)d2, d1->_keys[i]);
            if (!val2) return false;
            if (d1->_valueCallBacks.equal) {
                if (!d1->_valueCallBacks.equal(d1->_values[i], val2)) return false;
            } else {
                if (d1->_values[i] != val2) return false;
            }
        }
    }
    return true;
}

static CFHashCode __CFDictionaryHash(CFTypeRef cf) {
    return (CFHashCode)((const struct __CFDictionary *)cf)->_count;
}

static const CFRuntimeClass __CFDictionaryClass = {
    0, "CFDictionary", NULL, NULL, __CFDictionaryFinalize,
    __CFDictionaryEqual, __CFDictionaryHash, NULL, NULL
};

EXPORT CFTypeID CFDictionaryGetTypeID(void) { return __CFDictionaryTypeID; }

CF_INLINE CFIndex __CFDictFindSlot(const struct __CFDictionary *d, const void *key) {
    CFHashCode hash;
    if (d->_keyCallBacks.hash) hash = d->_keyCallBacks.hash(key);
    else hash = (CFHashCode)(uintptr_t)key;
    CFIndex mask = d->_capacity - 1;
    CFIndex idx = (CFIndex)(hash & (CFHashCode)mask);
    CFIndex firstDeleted = -1;
    for (CFIndex i = 0; i < d->_capacity; i++) {
        CFIndex probe = (idx + i) & mask;
        if (d->_keys[probe] == __CF_DICT_EMPTY) {
            return firstDeleted >= 0 ? firstDeleted : probe;
        }
        if (d->_keys[probe] == __CF_DICT_DELETED) {
            if (firstDeleted < 0) firstDeleted = probe;
            continue;
        }
        Boolean eq;
        if (d->_keyCallBacks.equal) eq = d->_keyCallBacks.equal(d->_keys[probe], key);
        else eq = (d->_keys[probe] == key);
        if (eq) return probe;
    }
    return firstDeleted >= 0 ? firstDeleted : -1;
}

CF_INLINE CFIndex __CFDictFindKey(const struct __CFDictionary *d, const void *key) {
    CFHashCode hash;
    if (d->_keyCallBacks.hash) hash = d->_keyCallBacks.hash(key);
    else hash = (CFHashCode)(uintptr_t)key;
    CFIndex mask = d->_capacity - 1;
    CFIndex idx = (CFIndex)(hash & (CFHashCode)mask);
    for (CFIndex i = 0; i < d->_capacity; i++) {
        CFIndex probe = (idx + i) & mask;
        if (d->_keys[probe] == __CF_DICT_EMPTY) return -1;
        if (d->_keys[probe] == __CF_DICT_DELETED) continue;
        Boolean eq;
        if (d->_keyCallBacks.equal) eq = d->_keyCallBacks.equal(d->_keys[probe], key);
        else eq = (d->_keys[probe] == key);
        if (eq) return probe;
    }
    return -1;
}

HIDDEN void __CFDictRehash(struct __CFDictionary *d, CFIndex newCap) {
    const void **oldKeys = d->_keys;
    const void **oldValues = d->_values;
    CFIndex oldCap = d->_capacity;

    d->_capacity = newCap;
    d->_keys = (const void **)calloc((size_t)newCap, sizeof(const void *));
    d->_values = (const void **)calloc((size_t)newCap, sizeof(const void *));
    d->_count = 0;

    for (CFIndex i = 0; i < oldCap; i++) {
        if (oldKeys[i] && oldKeys[i] != __CF_DICT_DELETED) {
            CFIndex slot = __CFDictFindSlot(d, oldKeys[i]);
            d->_keys[slot] = oldKeys[i];
            d->_values[slot] = oldValues[i];
            d->_count++;
        }
    }
    if (oldKeys) free(oldKeys);
    if (oldValues) free(oldValues);
}

EXPORT CFDictionaryRef CFDictionaryCreate(CFAllocatorRef allocator,
    const void **keys, const void **values, CFIndex numValues,
    const CFDictionaryKeyCallBacks *keyCallBacks,
    const CFDictionaryValueCallBacks *valueCallBacks) {

    struct __CFDictionary *d = (struct __CFDictionary *)_CFRuntimeCreateInstance(
        allocator, __CFDictionaryTypeID,
        sizeof(struct __CFDictionary) - sizeof(CFRuntimeBase), NULL);
    if (!d) return NULL;
    d->_mutable = false;
    if (keyCallBacks) d->_keyCallBacks = *keyCallBacks; else memset(&d->_keyCallBacks, 0, sizeof(d->_keyCallBacks));
    if (valueCallBacks) d->_valueCallBacks = *valueCallBacks; else memset(&d->_valueCallBacks, 0, sizeof(d->_valueCallBacks));

    /* Capacity must be power of 2, at least 2x the count */
    CFIndex cap = 8;
    while (cap < numValues * 2) cap *= 2;
    d->_capacity = cap;
    d->_count = 0;
    d->_keys = (const void **)calloc((size_t)cap, sizeof(const void *));
    d->_values = (const void **)calloc((size_t)cap, sizeof(const void *));

    for (CFIndex i = 0; i < numValues; i++) {
        CFIndex slot = __CFDictFindSlot(d, keys[i]);
        if (slot < 0) continue;
        d->_keys[slot] = (d->_keyCallBacks.retain) ? d->_keyCallBacks.retain(NULL, keys[i]) : keys[i];
        d->_values[slot] = (d->_valueCallBacks.retain) ? d->_valueCallBacks.retain(NULL, values[i]) : values[i];
        d->_count++;
    }
    return (CFDictionaryRef)d;
}

EXPORT CFDictionaryRef CFDictionaryCreateCopy(CFAllocatorRef allocator, CFDictionaryRef theDict) {
    if (!theDict) return CFDictionaryCreate(allocator, NULL, NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    const struct __CFDictionary *src = (const struct __CFDictionary *)theDict;
    /* Collect keys and values */
    const void **keys = (const void **)malloc((size_t)src->_count * sizeof(const void *));
    const void **vals = (const void **)malloc((size_t)src->_count * sizeof(const void *));
    CFIndex n = 0;
    for (CFIndex i = 0; i < src->_capacity; i++) {
        if (src->_keys[i] && src->_keys[i] != __CF_DICT_DELETED) {
            keys[n] = src->_keys[i];
            vals[n] = src->_values[i];
            n++;
        }
    }
    CFDictionaryRef result = CFDictionaryCreate(allocator, keys, vals, n,
        &src->_keyCallBacks, &src->_valueCallBacks);
    free(keys);
    free(vals);
    return result;
}

EXPORT CFMutableDictionaryRef CFDictionaryCreateMutable(CFAllocatorRef allocator, CFIndex capacity,
    const CFDictionaryKeyCallBacks *keyCallBacks,
    const CFDictionaryValueCallBacks *valueCallBacks) {

    struct __CFDictionary *d = (struct __CFDictionary *)_CFRuntimeCreateInstance(
        allocator, __CFDictionaryTypeID,
        sizeof(struct __CFDictionary) - sizeof(CFRuntimeBase), NULL);
    if (!d) return NULL;
    d->_mutable = true;
    if (keyCallBacks) d->_keyCallBacks = *keyCallBacks; else memset(&d->_keyCallBacks, 0, sizeof(d->_keyCallBacks));
    if (valueCallBacks) d->_valueCallBacks = *valueCallBacks; else memset(&d->_valueCallBacks, 0, sizeof(d->_valueCallBacks));

    CFIndex cap = 8;
    while (cap < capacity * 2) cap *= 2;
    d->_capacity = cap;
    d->_count = 0;
    d->_keys = (const void **)calloc((size_t)cap, sizeof(const void *));
    d->_values = (const void **)calloc((size_t)cap, sizeof(const void *));
    return (CFMutableDictionaryRef)d;
}

EXPORT CFMutableDictionaryRef CFDictionaryCreateMutableCopy(CFAllocatorRef allocator,
    CFIndex capacity, CFDictionaryRef theDict) {
    const struct __CFDictionary *src = theDict ? (const struct __CFDictionary *)theDict : NULL;
    CFIndex cap = capacity;
    if (src && src->_count > cap) cap = src->_count;
    CFMutableDictionaryRef md = CFDictionaryCreateMutable(allocator, cap,
        src ? &src->_keyCallBacks : &kCFTypeDictionaryKeyCallBacks,
        src ? &src->_valueCallBacks : &kCFTypeDictionaryValueCallBacks);
    if (!md || !src) return md;
    for (CFIndex i = 0; i < src->_capacity; i++) {
        if (src->_keys[i] && src->_keys[i] != __CF_DICT_DELETED) {
            CFDictionarySetValue(md, src->_keys[i], src->_values[i]);
        }
    }
    return md;
}

EXPORT CFIndex CFDictionaryGetCount(CFDictionaryRef theDict) {
    if (!theDict) return 0;
    return ((const struct __CFDictionary *)theDict)->_count;
}

EXPORT const void *CFDictionaryGetValue(CFDictionaryRef theDict, const void *key) {
    if (!theDict) return NULL;
    const struct __CFDictionary *d = (const struct __CFDictionary *)theDict;
    CFIndex slot = __CFDictFindKey(d, key);
    if (slot < 0) return NULL;
    return d->_values[slot];
}

EXPORT Boolean CFDictionaryGetValueIfPresent(CFDictionaryRef theDict, const void *key, const void **value) {
    if (!theDict) return false;
    const struct __CFDictionary *d = (const struct __CFDictionary *)theDict;
    CFIndex slot = __CFDictFindKey(d, key);
    if (slot < 0) return false;
    if (value) *value = d->_values[slot];
    return true;
}

EXPORT Boolean CFDictionaryContainsKey(CFDictionaryRef theDict, const void *key) {
    if (!theDict) return false;
    return __CFDictFindKey((const struct __CFDictionary *)theDict, key) >= 0;
}

EXPORT Boolean CFDictionaryContainsValue(CFDictionaryRef theDict, const void *value) {
    if (!theDict) return false;
    const struct __CFDictionary *d = (const struct __CFDictionary *)theDict;
    for (CFIndex i = 0; i < d->_capacity; i++) {
        if (d->_keys[i] && d->_keys[i] != __CF_DICT_DELETED) {
            if (d->_valueCallBacks.equal) {
                if (d->_valueCallBacks.equal(d->_values[i], value)) return true;
            } else {
                if (d->_values[i] == value) return true;
            }
        }
    }
    return false;
}

EXPORT CFIndex CFDictionaryGetCountOfKey(CFDictionaryRef theDict, const void *key) {
    return CFDictionaryContainsKey(theDict, key) ? 1 : 0;
}

EXPORT CFIndex CFDictionaryGetCountOfValue(CFDictionaryRef theDict, const void *value) {
    if (!theDict) return 0;
    const struct __CFDictionary *d = (const struct __CFDictionary *)theDict;
    CFIndex count = 0;
    for (CFIndex i = 0; i < d->_capacity; i++) {
        if (d->_keys[i] && d->_keys[i] != __CF_DICT_DELETED) {
            if (d->_valueCallBacks.equal) {
                if (d->_valueCallBacks.equal(d->_values[i], value)) count++;
            } else {
                if (d->_values[i] == value) count++;
            }
        }
    }
    return count;
}

EXPORT void CFDictionaryGetKeysAndValues(CFDictionaryRef theDict, const void **keys, const void **values) {
    if (!theDict) return;
    const struct __CFDictionary *d = (const struct __CFDictionary *)theDict;
    CFIndex n = 0;
    for (CFIndex i = 0; i < d->_capacity; i++) {
        if (d->_keys[i] && d->_keys[i] != __CF_DICT_DELETED) {
            if (keys) keys[n] = d->_keys[i];
            if (values) values[n] = d->_values[i];
            n++;
        }
    }
}

EXPORT void CFDictionaryApplyFunction(CFDictionaryRef theDict,
    CFDictionaryApplierFunction applier, void *context) {
    if (!theDict || !applier) return;
    const struct __CFDictionary *d = (const struct __CFDictionary *)theDict;
    for (CFIndex i = 0; i < d->_capacity; i++) {
        if (d->_keys[i] && d->_keys[i] != __CF_DICT_DELETED) {
            applier(d->_keys[i], d->_values[i], context);
        }
    }
}

/* --- Mutation --- */

EXPORT void CFDictionarySetValue(CFMutableDictionaryRef theDict, const void *key, const void *value) {
    if (!theDict) return;
    struct __CFDictionary *d = (struct __CFDictionary *)theDict;
    if (!d->_mutable) return;

    /* Rehash at 70% load */
    if ((d->_count + 1) * 10 > d->_capacity * 7) {
        __CFDictRehash(d, d->_capacity * 2);
    }

    CFIndex slot = __CFDictFindSlot(d, key);
    if (slot < 0) return;

    if (d->_keys[slot] && d->_keys[slot] != __CF_DICT_DELETED) {
        /* Replace existing value */
        const void *oldVal = d->_values[slot];
        d->_values[slot] = (d->_valueCallBacks.retain) ? d->_valueCallBacks.retain(NULL, value) : value;
        if (d->_valueCallBacks.release && oldVal) d->_valueCallBacks.release(NULL, oldVal);
    } else {
        /* New entry */
        d->_keys[slot] = (d->_keyCallBacks.retain) ? d->_keyCallBacks.retain(NULL, key) : key;
        d->_values[slot] = (d->_valueCallBacks.retain) ? d->_valueCallBacks.retain(NULL, value) : value;
        d->_count++;
    }
}

EXPORT void CFDictionaryAddValue(CFMutableDictionaryRef theDict, const void *key, const void *value) {
    if (!theDict) return;
    struct __CFDictionary *d = (struct __CFDictionary *)theDict;
    if (!d->_mutable) return;
    /* Only add if key doesn't exist */
    if (__CFDictFindKey(d, key) >= 0) return;
    CFDictionarySetValue(theDict, key, value);
}

EXPORT void CFDictionaryReplaceValue(CFMutableDictionaryRef theDict, const void *key, const void *value) {
    if (!theDict) return;
    struct __CFDictionary *d = (struct __CFDictionary *)theDict;
    if (!d->_mutable) return;
    CFIndex slot = __CFDictFindKey(d, key);
    if (slot < 0) return; /* no-op if key absent */
    const void *oldVal = d->_values[slot];
    d->_values[slot] = (d->_valueCallBacks.retain) ? d->_valueCallBacks.retain(NULL, value) : value;
    if (d->_valueCallBacks.release && oldVal) d->_valueCallBacks.release(NULL, oldVal);
}

EXPORT void CFDictionaryRemoveValue(CFMutableDictionaryRef theDict, const void *key) {
    if (!theDict) return;
    struct __CFDictionary *d = (struct __CFDictionary *)theDict;
    if (!d->_mutable) return;
    CFIndex slot = __CFDictFindKey(d, key);
    if (slot < 0) return;
    if (d->_keyCallBacks.release) d->_keyCallBacks.release(NULL, d->_keys[slot]);
    if (d->_valueCallBacks.release && d->_values[slot]) d->_valueCallBacks.release(NULL, d->_values[slot]);
    d->_keys[slot] = __CF_DICT_DELETED;
    d->_values[slot] = NULL;
    d->_count--;
}

EXPORT void CFDictionaryRemoveAllValues(CFMutableDictionaryRef theDict) {
    if (!theDict) return;
    struct __CFDictionary *d = (struct __CFDictionary *)theDict;
    if (!d->_mutable) return;
    for (CFIndex i = 0; i < d->_capacity; i++) {
        if (d->_keys[i] && d->_keys[i] != __CF_DICT_DELETED) {
            if (d->_keyCallBacks.release) d->_keyCallBacks.release(NULL, d->_keys[i]);
            if (d->_valueCallBacks.release && d->_values[i]) d->_valueCallBacks.release(NULL, d->_values[i]);
            d->_keys[i] = NULL;
            d->_values[i] = NULL;
        }
    }
    d->_count = 0;
}


/* ============================================================================
 * Section 20: CFSet
 *
 * Open-addressing hash table, keys-only (no values).
 * Same sentinel approach as CFDictionary.
 * ============================================================================ */

static const int __CFSetDeletedMarker = 0xBEEF;
#define __CF_SET_EMPTY   NULL
#define __CF_SET_DELETED ((const void *)&__CFSetDeletedMarker)

struct __CFSet {
    CFRuntimeBase    _base;
    CFIndex          _count;
    CFIndex          _capacity;  /* power of 2 */
    const void     **_values;
    CFSetCallBacks   _callBacks;
    Boolean          _mutable;
};

static CFTypeID __CFSetTypeID = _kCFRuntimeNotATypeID;

EXPORT const CFSetCallBacks kCFTypeSetCallBacks = {
    0,
    (CFSetRetainCallBack)__CFTypeDictRetain,
    (CFSetReleaseCallBack)__CFTypeDictRelease,
    NULL,
    (CFSetEqualCallBack)__CFTypeDictEqual,
    (CFSetHashCallBack)__CFTypeDictHash
};

/* Forward declarations for functions used in callbacks */
EXPORT Boolean CFSetContainsValue(CFSetRef theSet, const void *value);
EXPORT void CFSetAddValue(CFMutableSetRef theSet, const void *value);

static void __CFSetFinalize(CFTypeRef cf) {
    struct __CFSet *s = (struct __CFSet *)cf;
    if (s->_callBacks.release) {
        for (CFIndex i = 0; i < s->_capacity; i++) {
            if (s->_values[i] && s->_values[i] != __CF_SET_DELETED)
                s->_callBacks.release(NULL, s->_values[i]);
        }
    }
    if (s->_values) free(s->_values);
}

static Boolean __CFSetEqual(CFTypeRef cf1, CFTypeRef cf2) {
    const struct __CFSet *s1 = (const struct __CFSet *)cf1;
    const struct __CFSet *s2 = (const struct __CFSet *)cf2;
    if (s1->_count != s2->_count) return false;
    for (CFIndex i = 0; i < s1->_capacity; i++) {
        if (s1->_values[i] && s1->_values[i] != __CF_SET_DELETED) {
            if (!CFSetContainsValue((CFSetRef)s2, s1->_values[i])) return false;
        }
    }
    return true;
}

static CFHashCode __CFSetHash(CFTypeRef cf) {
    return (CFHashCode)((const struct __CFSet *)cf)->_count;
}

static const CFRuntimeClass __CFSetClass = {
    0, "CFSet", NULL, NULL, __CFSetFinalize,
    __CFSetEqual, __CFSetHash, NULL, NULL
};

EXPORT CFTypeID CFSetGetTypeID(void) { return __CFSetTypeID; }

CF_INLINE CFIndex __CFSetFindSlot(const struct __CFSet *s, const void *value) {
    CFHashCode hash;
    if (s->_callBacks.hash) hash = s->_callBacks.hash(value);
    else hash = (CFHashCode)(uintptr_t)value;
    CFIndex mask = s->_capacity - 1;
    CFIndex idx = (CFIndex)(hash & (CFHashCode)mask);
    CFIndex firstDeleted = -1;
    for (CFIndex i = 0; i < s->_capacity; i++) {
        CFIndex probe = (idx + i) & mask;
        if (s->_values[probe] == __CF_SET_EMPTY)
            return firstDeleted >= 0 ? firstDeleted : probe;
        if (s->_values[probe] == __CF_SET_DELETED) {
            if (firstDeleted < 0) firstDeleted = probe;
            continue;
        }
        Boolean eq;
        if (s->_callBacks.equal) eq = s->_callBacks.equal(s->_values[probe], value);
        else eq = (s->_values[probe] == value);
        if (eq) return probe;
    }
    return firstDeleted >= 0 ? firstDeleted : -1;
}

CF_INLINE CFIndex __CFSetFindValue(const struct __CFSet *s, const void *value) {
    CFHashCode hash;
    if (s->_callBacks.hash) hash = s->_callBacks.hash(value);
    else hash = (CFHashCode)(uintptr_t)value;
    CFIndex mask = s->_capacity - 1;
    CFIndex idx = (CFIndex)(hash & (CFHashCode)mask);
    for (CFIndex i = 0; i < s->_capacity; i++) {
        CFIndex probe = (idx + i) & mask;
        if (s->_values[probe] == __CF_SET_EMPTY) return -1;
        if (s->_values[probe] == __CF_SET_DELETED) continue;
        Boolean eq;
        if (s->_callBacks.equal) eq = s->_callBacks.equal(s->_values[probe], value);
        else eq = (s->_values[probe] == value);
        if (eq) return probe;
    }
    return -1;
}

HIDDEN void __CFSetRehash(struct __CFSet *s, CFIndex newCap) {
    const void **oldValues = s->_values;
    CFIndex oldCap = s->_capacity;
    s->_capacity = newCap;
    s->_values = (const void **)calloc((size_t)newCap, sizeof(const void *));
    s->_count = 0;
    for (CFIndex i = 0; i < oldCap; i++) {
        if (oldValues[i] && oldValues[i] != __CF_SET_DELETED) {
            CFIndex slot = __CFSetFindSlot(s, oldValues[i]);
            s->_values[slot] = oldValues[i];
            s->_count++;
        }
    }
    if (oldValues) free(oldValues);
}

EXPORT CFSetRef CFSetCreate(CFAllocatorRef allocator, const void **values, CFIndex numValues,
    const CFSetCallBacks *callBacks) {
    struct __CFSet *s = (struct __CFSet *)_CFRuntimeCreateInstance(
        allocator, __CFSetTypeID,
        sizeof(struct __CFSet) - sizeof(CFRuntimeBase), NULL);
    if (!s) return NULL;
    s->_mutable = false;
    if (callBacks) s->_callBacks = *callBacks; else memset(&s->_callBacks, 0, sizeof(s->_callBacks));
    CFIndex cap = 8;
    while (cap < numValues * 2) cap *= 2;
    s->_capacity = cap;
    s->_count = 0;
    s->_values = (const void **)calloc((size_t)cap, sizeof(const void *));
    for (CFIndex i = 0; i < numValues; i++) {
        CFIndex slot = __CFSetFindSlot(s, values[i]);
        if (slot >= 0 && (s->_values[slot] == __CF_SET_EMPTY || s->_values[slot] == __CF_SET_DELETED)) {
            s->_values[slot] = (s->_callBacks.retain) ? s->_callBacks.retain(NULL, values[i]) : values[i];
            s->_count++;
        }
    }
    return (CFSetRef)s;
}

EXPORT CFSetRef CFSetCreateCopy(CFAllocatorRef allocator, CFSetRef theSet) {
    if (!theSet) return CFSetCreate(allocator, NULL, 0, &kCFTypeSetCallBacks);
    const struct __CFSet *src = (const struct __CFSet *)theSet;
    const void **vals = (const void **)malloc((size_t)src->_count * sizeof(const void *));
    CFIndex n = 0;
    for (CFIndex i = 0; i < src->_capacity; i++) {
        if (src->_values[i] && src->_values[i] != __CF_SET_DELETED)
            vals[n++] = src->_values[i];
    }
    CFSetRef result = CFSetCreate(allocator, vals, n, &src->_callBacks);
    free(vals);
    return result;
}

EXPORT CFMutableSetRef CFSetCreateMutable(CFAllocatorRef allocator, CFIndex capacity,
    const CFSetCallBacks *callBacks) {
    struct __CFSet *s = (struct __CFSet *)_CFRuntimeCreateInstance(
        allocator, __CFSetTypeID,
        sizeof(struct __CFSet) - sizeof(CFRuntimeBase), NULL);
    if (!s) return NULL;
    s->_mutable = true;
    if (callBacks) s->_callBacks = *callBacks; else memset(&s->_callBacks, 0, sizeof(s->_callBacks));
    CFIndex cap = 8;
    while (cap < capacity * 2) cap *= 2;
    s->_capacity = cap;
    s->_count = 0;
    s->_values = (const void **)calloc((size_t)cap, sizeof(const void *));
    return (CFMutableSetRef)s;
}

EXPORT CFMutableSetRef CFSetCreateMutableCopy(CFAllocatorRef allocator, CFIndex capacity, CFSetRef theSet) {
    const struct __CFSet *src = theSet ? (const struct __CFSet *)theSet : NULL;
    CFIndex cap = capacity;
    if (src && src->_count > cap) cap = src->_count;
    CFMutableSetRef ms = CFSetCreateMutable(allocator, cap,
        src ? &src->_callBacks : &kCFTypeSetCallBacks);
    if (!ms || !src) return ms;
    for (CFIndex i = 0; i < src->_capacity; i++) {
        if (src->_values[i] && src->_values[i] != __CF_SET_DELETED)
            CFSetAddValue(ms, src->_values[i]);
    }
    return ms;
}

EXPORT CFIndex CFSetGetCount(CFSetRef theSet) {
    if (!theSet) return 0;
    return ((const struct __CFSet *)theSet)->_count;
}

EXPORT Boolean CFSetContainsValue(CFSetRef theSet, const void *value) {
    if (!theSet) return false;
    return __CFSetFindValue((const struct __CFSet *)theSet, value) >= 0;
}

EXPORT const void *CFSetGetValue(CFSetRef theSet, const void *value) {
    if (!theSet) return NULL;
    const struct __CFSet *s = (const struct __CFSet *)theSet;
    CFIndex slot = __CFSetFindValue(s, value);
    if (slot < 0) return NULL;
    return s->_values[slot];
}

EXPORT Boolean CFSetGetValueIfPresent(CFSetRef theSet, const void *candidate, const void **value) {
    if (!theSet) return false;
    const struct __CFSet *s = (const struct __CFSet *)theSet;
    CFIndex slot = __CFSetFindValue(s, candidate);
    if (slot < 0) return false;
    if (value) *value = s->_values[slot];
    return true;
}

EXPORT CFIndex CFSetGetCountOfValue(CFSetRef theSet, const void *value) {
    return CFSetContainsValue(theSet, value) ? 1 : 0;
}

EXPORT void CFSetGetValues(CFSetRef theSet, const void **values) {
    if (!theSet || !values) return;
    const struct __CFSet *s = (const struct __CFSet *)theSet;
    CFIndex n = 0;
    for (CFIndex i = 0; i < s->_capacity; i++) {
        if (s->_values[i] && s->_values[i] != __CF_SET_DELETED)
            values[n++] = s->_values[i];
    }
}

EXPORT void CFSetApplyFunction(CFSetRef theSet, CFSetApplierFunction applier, void *context) {
    if (!theSet || !applier) return;
    const struct __CFSet *s = (const struct __CFSet *)theSet;
    for (CFIndex i = 0; i < s->_capacity; i++) {
        if (s->_values[i] && s->_values[i] != __CF_SET_DELETED)
            applier(s->_values[i], context);
    }
}

EXPORT void CFSetAddValue(CFMutableSetRef theSet, const void *value) {
    if (!theSet) return;
    struct __CFSet *s = (struct __CFSet *)theSet;
    if (!s->_mutable) return;
    if (__CFSetFindValue(s, value) >= 0) return; /* already exists */
    if ((s->_count + 1) * 10 > s->_capacity * 7) __CFSetRehash(s, s->_capacity * 2);
    CFIndex slot = __CFSetFindSlot(s, value);
    if (slot < 0) return;
    s->_values[slot] = (s->_callBacks.retain) ? s->_callBacks.retain(NULL, value) : value;
    s->_count++;
}

EXPORT void CFSetSetValue(CFMutableSetRef theSet, const void *value) {
    if (!theSet) return;
    struct __CFSet *s = (struct __CFSet *)theSet;
    if (!s->_mutable) return;
    CFIndex slot = __CFSetFindValue(s, value);
    if (slot >= 0) {
        /* Replace */
        const void *old = s->_values[slot];
        s->_values[slot] = (s->_callBacks.retain) ? s->_callBacks.retain(NULL, value) : value;
        if (s->_callBacks.release && old) s->_callBacks.release(NULL, old);
    } else {
        CFSetAddValue(theSet, value);
    }
}

EXPORT void CFSetReplaceValue(CFMutableSetRef theSet, const void *value) {
    if (!theSet) return;
    struct __CFSet *s = (struct __CFSet *)theSet;
    if (!s->_mutable) return;
    CFIndex slot = __CFSetFindValue(s, value);
    if (slot < 0) return;
    const void *old = s->_values[slot];
    s->_values[slot] = (s->_callBacks.retain) ? s->_callBacks.retain(NULL, value) : value;
    if (s->_callBacks.release && old) s->_callBacks.release(NULL, old);
}

EXPORT void CFSetRemoveValue(CFMutableSetRef theSet, const void *value) {
    if (!theSet) return;
    struct __CFSet *s = (struct __CFSet *)theSet;
    if (!s->_mutable) return;
    CFIndex slot = __CFSetFindValue(s, value);
    if (slot < 0) return;
    if (s->_callBacks.release) s->_callBacks.release(NULL, s->_values[slot]);
    s->_values[slot] = __CF_SET_DELETED;
    s->_count--;
}

EXPORT void CFSetRemoveAllValues(CFMutableSetRef theSet) {
    if (!theSet) return;
    struct __CFSet *s = (struct __CFSet *)theSet;
    if (!s->_mutable) return;
    for (CFIndex i = 0; i < s->_capacity; i++) {
        if (s->_values[i] && s->_values[i] != __CF_SET_DELETED) {
            if (s->_callBacks.release) s->_callBacks.release(NULL, s->_values[i]);
            s->_values[i] = NULL;
        }
    }
    s->_count = 0;
}


/* ============================================================================
 * Section 21: CFDate
 *
 * CFAbsoluteTime is a double representing seconds since the reference date
 * 2001-01-01 00:00:00 UTC (= Unix epoch + 978307200 seconds).
 * ============================================================================ */

typedef double CFAbsoluteTime;
typedef double CFTimeInterval;

#define kCFAbsoluteTimeIntervalSince1970  978307200.0
#define kCFAbsoluteTimeIntervalSince1904  3061152000.0

struct __CFDate {
    CFRuntimeBase  _base;
    CFAbsoluteTime _time;
};

static CFTypeID __CFDateTypeID = _kCFRuntimeNotATypeID;

static Boolean __CFDateEqual(CFTypeRef cf1, CFTypeRef cf2) {
    return ((const struct __CFDate *)cf1)->_time == ((const struct __CFDate *)cf2)->_time;
}

static CFHashCode __CFDateHash(CFTypeRef cf) {
    double t = ((const struct __CFDate *)cf)->_time;
    uint64_t bits;
    memcpy(&bits, &t, 8);
    return (CFHashCode)(bits ^ (bits >> 32));
}

static const CFRuntimeClass __CFDateClass = {
    0, "CFDate", NULL, NULL, NULL,
    __CFDateEqual, __CFDateHash, NULL, NULL
};

EXPORT CFTypeID CFDateGetTypeID(void) { return __CFDateTypeID; }

/* gettimeofday structure — defined inline since freestanding */
struct __cf_timeval {
    int64_t  tv_sec;
    int32_t  tv_usec;
    int32_t  _pad;
};

EXPORT CFAbsoluteTime CFAbsoluteTimeGetCurrent(void) {
    struct __cf_timeval tv;
    memset(&tv, 0, sizeof(tv));
    gettimeofday(&tv, NULL);
    double unix_time = (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
    return unix_time - kCFAbsoluteTimeIntervalSince1970;
}

EXPORT CFDateRef CFDateCreate(CFAllocatorRef allocator, CFAbsoluteTime at) {
    struct __CFDate *d = (struct __CFDate *)_CFRuntimeCreateInstance(
        allocator, __CFDateTypeID,
        sizeof(struct __CFDate) - sizeof(CFRuntimeBase), NULL);
    if (!d) return NULL;
    d->_time = at;
    return (CFDateRef)d;
}

EXPORT CFAbsoluteTime CFDateGetAbsoluteTime(CFDateRef theDate) {
    if (!theDate) return 0.0;
    return ((const struct __CFDate *)theDate)->_time;
}

EXPORT CFComparisonResult CFDateCompare(CFDateRef theDate, CFDateRef otherDate, void *context) {
    (void)context;
    if (!theDate || !otherDate) return kCFCompareEqualTo;
    CFAbsoluteTime t1 = ((const struct __CFDate *)theDate)->_time;
    CFAbsoluteTime t2 = ((const struct __CFDate *)otherDate)->_time;
    if (t1 < t2) return kCFCompareLessThan;
    if (t1 > t2) return kCFCompareGreaterThan;
    return kCFCompareEqualTo;
}

EXPORT CFTimeInterval CFDateGetTimeIntervalSinceDate(CFDateRef theDate, CFDateRef otherDate) {
    if (!theDate || !otherDate) return 0.0;
    return ((const struct __CFDate *)theDate)->_time - ((const struct __CFDate *)otherDate)->_time;
}

/* ============================================================================
 * Section 21b: CFAttributedString
 *
 * A string with associated attributes (key/value pairs) over ranges.
 * Used primarily by CoreText for text layout and rendering.
 *
 * Simplified implementation: stores a single attribute dictionary that
 * applies to the entire string. Real macOS uses a run-length-encoded
 * array of attribute dictionaries, but for our bitmap font renderer
 * whole-string attributes are sufficient.
 *
 * Reference: apple/swift-corelibs-foundation (CFAttributedString.c)
 * ============================================================================ */

/* --- CFAttributedString struct --- */
struct __CFAttributedString {
    CFRuntimeBase      _base;
    CFStringRef        _string;
    CFDictionaryRef    _attributes;  /* single run covering entire string */
    bool               _isMutable;
};

/* --- Type ID storage --- */
static CFTypeID __CFAttributedStringTypeID = 0;

static void __CFAttributedStringDealloc(CFTypeRef cf) {
    struct __CFAttributedString *as = (struct __CFAttributedString *)cf;
    if (as->_string)     CFRelease((CFTypeRef)as->_string);
    if (as->_attributes) CFRelease((CFTypeRef)as->_attributes);
}

static const CFRuntimeClass __CFAttributedStringClass = {
    0, "CFAttributedString", NULL, NULL,
    __CFAttributedStringDealloc, NULL, NULL, NULL, NULL
};

EXPORT CFAttributedStringRef CFAttributedStringCreate(
    CFAllocatorRef alloc, CFStringRef str, CFDictionaryRef attributes)
{
    if (!str) return NULL;
    struct __CFAttributedString *as = (struct __CFAttributedString *)
        _CFRuntimeCreateInstance(alloc, __CFAttributedStringTypeID,
            sizeof(struct __CFAttributedString) - sizeof(CFRuntimeBase), NULL);
    if (!as) return NULL;
    as->_string = (CFStringRef)CFRetain((CFTypeRef)str);
    as->_attributes = attributes ? (CFDictionaryRef)CFRetain((CFTypeRef)attributes) : NULL;
    as->_isMutable = false;
    return (CFAttributedStringRef)as;
}

EXPORT CFIndex CFAttributedStringGetLength(CFAttributedStringRef aStr) {
    if (!aStr) return 0;
    return CFStringGetLength(((const struct __CFAttributedString *)aStr)->_string);
}

EXPORT CFStringRef CFAttributedStringGetString(CFAttributedStringRef aStr) {
    if (!aStr) return NULL;
    return ((const struct __CFAttributedString *)aStr)->_string;
}

EXPORT CFDictionaryRef CFAttributedStringGetAttributes(
    CFAttributedStringRef aStr, CFIndex loc, CFRange *effectiveRange)
{
    if (!aStr) return NULL;
    const struct __CFAttributedString *as = (const struct __CFAttributedString *)aStr;
    /* Single-run model: attributes cover entire string */
    if (effectiveRange) {
        effectiveRange->location = 0;
        effectiveRange->length = CFStringGetLength(as->_string);
    }
    (void)loc;
    return as->_attributes;
}

EXPORT CFTypeID CFAttributedStringGetTypeID(void) {
    return __CFAttributedStringTypeID;
}

/* ============================================================================
 * Section 22: CFRunLoop — Full Implementation
 *
 * XNU-faithful CFRunLoop using mach_msg(MACH_RCV_MSG | MACH_RCV_TIMEOUT)
 * for the blocking wait phase. Each run loop owns a wakeup Mach port; 
 * CFRunLoopWakeUp() sends a message to this port to unblock the loop.
 *
 * Reference: apple-oss-distributions/CF (CFRunLoop.c, CF-1153.18)
 *            apple/swift-corelibs-foundation (CFRunLoop.c)
 * ============================================================================ */

/* --- CFRunLoop constants --- */
EXPORT const CFRunLoopMode kCFRunLoopDefaultMode = NULL; /* initialised in constructor */
EXPORT const CFRunLoopMode kCFRunLoopCommonModes = NULL;  /* initialised in constructor */

/* --- CFRunLoopActivity flags (exact Apple values) --- */
typedef CFOptionFlags CFRunLoopActivity;
#define kCFRunLoopEntry         (1UL << 0)
#define kCFRunLoopBeforeTimers  (1UL << 1)
#define kCFRunLoopBeforeSources (1UL << 2)
#define kCFRunLoopBeforeWaiting (1UL << 5)
#define kCFRunLoopAfterWaiting  (1UL << 6)
#define kCFRunLoopExit          (1UL << 7)
#define kCFRunLoopAllActivities 0x0FFFFFFFU

/* --- CFRunLoopRunResult (exact Apple return values from CFRunLoopRunInMode) --- */
#define kCFRunLoopRunFinished       1
#define kCFRunLoopRunStopped        2
#define kCFRunLoopRunTimedOut       3
#define kCFRunLoopRunHandledSource  4

/* --- Callback typedefs --- */
typedef void (*CFRunLoopTimerCallBack)(CFRunLoopTimerRef timer, void *info);
typedef void (*CFRunLoopObserverCallBack)(CFRunLoopObserverRef observer, CFRunLoopActivity activity, void *info);

/* --- CFRunLoopSourceContext (version 0 — callback-based) --- */
typedef struct {
    CFIndex version;
    void   *info;
    const void *(*retain)(const void *info);
    void        (*release)(const void *info);
    CFStringRef (*copyDescription)(const void *info);
    Boolean     (*equal)(const void *info1, const void *info2);
    CFHashCode  (*hash)(const void *info);
    void        (*schedule)(void *info, CFRunLoopRef rl, CFRunLoopMode mode);
    void        (*cancel)(void *info, CFRunLoopRef rl, CFRunLoopMode mode);
    void        (*perform)(void *info);
} CFRunLoopSourceContext;

/* --- CFRunLoopTimerContext --- */
typedef struct {
    CFIndex version;
    void   *info;
    const void *(*retain)(const void *info);
    void        (*release)(const void *info);
    CFStringRef (*copyDescription)(const void *info);
} CFRunLoopTimerContext;

/* --- CFRunLoopObserverContext --- */
typedef struct {
    CFIndex version;
    void   *info;
    const void *(*retain)(const void *info);
    void        (*release)(const void *info);
    CFStringRef (*copyDescription)(const void *info);
} CFRunLoopObserverContext;

/* --- Type IDs for run loop objects --- */
static CFTypeID __CFRunLoopTypeID       = _kCFRuntimeNotATypeID;
static CFTypeID __CFRunLoopSourceTypeID = _kCFRuntimeNotATypeID;
static CFTypeID __CFRunLoopTimerTypeID  = _kCFRuntimeNotATypeID;
static CFTypeID __CFRunLoopObserverTypeID = _kCFRuntimeNotATypeID;

/* --- Internal Limits --- */
#define __CF_RL_MAX_SOURCES     64
#define __CF_RL_MAX_TIMERS      32
#define __CF_RL_MAX_OBSERVERS   32
#define __CF_RL_MAX_MODES       8
#define __CF_RL_MAX_COMMON      4

/* ============================================================================
 * Internal Structures
 * ============================================================================ */

struct __CFRunLoopSource {
    CFRuntimeBase           _base;
    CFIndex                 _order;
    Boolean                 _valid;
    Boolean                 _signaled;
    CFRunLoopSourceContext  _context;
};

struct __CFRunLoopTimer {
    CFRuntimeBase           _base;
    Boolean                 _valid;
    CFAbsoluteTime          _nextFireDate;
    CFTimeInterval          _interval;
    CFOptionFlags           _flags;
    CFIndex                 _order;
    CFRunLoopTimerCallBack  _callout;
    CFRunLoopTimerContext   _context;
};

struct __CFRunLoopObserver {
    CFRuntimeBase             _base;
    Boolean                   _valid;
    Boolean                   _repeats;
    CFRunLoopActivity         _activities;
    CFIndex                   _order;
    CFRunLoopObserverCallBack _callout;
    CFRunLoopObserverContext  _context;
};

/* Per-mode storage */
typedef struct __CFRunLoopMode {
    CFStringRef         _name;

    /* Version-0 sources (callback-based) */
    struct __CFRunLoopSource *_sources[__CF_RL_MAX_SOURCES];
    CFIndex             _sourceCount;

    /* Timers */
    struct __CFRunLoopTimer *_timers[__CF_RL_MAX_TIMERS];
    CFIndex             _timerCount;

    /* Observers */
    struct __CFRunLoopObserver *_observers[__CF_RL_MAX_OBSERVERS];
    CFIndex             _observerCount;

    Boolean             _stopped;
} __CFRunLoopMode;

struct __CFRunLoop {
    CFRuntimeBase       _base;

    /* Per-thread identity */
    unsigned long       _pthread;           /* pthread_self() value */

    /* Wakeup Mach port — mach_msg receive on this to sleep,
     * send to it to wake up (CFRunLoopWakeUp). */
    mach_port_t         _wakeUpPort;

    /* Lock for thread safety */
    /* Bug 14 fix: proper type for ARM64 alignment */
    pthread_mutex_t     _lock;

    /* Modes */
    __CFRunLoopMode     _modes[__CF_RL_MAX_MODES];
    CFIndex             _modeCount;

    /* Common modes set */
    CFStringRef         _commonModes[__CF_RL_MAX_COMMON];
    CFIndex             _commonModeCount;

    /* State */
    Boolean             _stopped;
    Boolean             _sleeping;
    CFRunLoopMode       _currentMode;       /* name of the mode currently running */
};


/* ============================================================================
 * Thread-to-RunLoop Mapping (pthread TLS)
 * ============================================================================ */

static unsigned int __CFRunLoopTLSKey = 0;
static Boolean __CFRunLoopTLSKeyCreated = false;
static struct __CFRunLoop *__CFMainRunLoop = NULL;

/* Ensure the TLS key is created exactly once */
HIDDEN void __CFRunLoopEnsureTLS(void) {
    if (!__CFRunLoopTLSKeyCreated) {
        pthread_key_create(&__CFRunLoopTLSKey, NULL);
        __CFRunLoopTLSKeyCreated = true;
    }
}

/* ============================================================================
 * CFRuntime Class Descriptors
 * ============================================================================ */

static void __CFRunLoopFinalize(CFTypeRef cf) {
    struct __CFRunLoop *rl = (struct __CFRunLoop *)cf;
    if (rl->_wakeUpPort != MACH_PORT_NULL) {
        /* On real macOS, mach_port_deallocate — we'll leave the port
         * for now as process exit will reclaim it. */
    }
    pthread_mutex_destroy(&rl->_lock);
}

static Boolean __CFRunLoopEqual(CFTypeRef cf1, CFTypeRef cf2) {
    return cf1 == cf2; /* identity */
}

static CFHashCode __CFRunLoopHash(CFTypeRef cf) {
    const struct __CFRunLoop *rl = (const struct __CFRunLoop *)cf;
    return (CFHashCode)rl->_pthread;
}

static const CFRuntimeClass __CFRunLoopClass = {
    0, "CFRunLoop", NULL, NULL, __CFRunLoopFinalize,
    __CFRunLoopEqual, __CFRunLoopHash, NULL, NULL
};

/* --- Source --- */
static void __CFRunLoopSourceFinalize(CFTypeRef cf) {
    struct __CFRunLoopSource *s = (struct __CFRunLoopSource *)cf;
    if (s->_context.release && s->_context.info)
        s->_context.release(s->_context.info);
}

static Boolean __CFRunLoopSourceEqual(CFTypeRef cf1, CFTypeRef cf2) {
    if (cf1 == cf2) return true;
    const struct __CFRunLoopSource *s1 = (const struct __CFRunLoopSource *)cf1;
    const struct __CFRunLoopSource *s2 = (const struct __CFRunLoopSource *)cf2;
    if (s1->_context.equal)
        return s1->_context.equal(s1->_context.info, s2->_context.info);
    return false;
}

static CFHashCode __CFRunLoopSourceHash(CFTypeRef cf) {
    const struct __CFRunLoopSource *s = (const struct __CFRunLoopSource *)cf;
    if (s->_context.hash) return s->_context.hash(s->_context.info);
    return (CFHashCode)(uintptr_t)cf;
}

static const CFRuntimeClass __CFRunLoopSourceClass = {
    0, "CFRunLoopSource", NULL, NULL, __CFRunLoopSourceFinalize,
    __CFRunLoopSourceEqual, __CFRunLoopSourceHash, NULL, NULL
};

/* --- Timer --- */
static void __CFRunLoopTimerFinalize(CFTypeRef cf) {
    struct __CFRunLoopTimer *t = (struct __CFRunLoopTimer *)cf;
    if (t->_context.release && t->_context.info)
        t->_context.release(t->_context.info);
}

static const CFRuntimeClass __CFRunLoopTimerClass = {
    0, "CFRunLoopTimer", NULL, NULL, __CFRunLoopTimerFinalize,
    NULL, NULL, NULL, NULL
};

/* --- Observer --- */
static void __CFRunLoopObserverFinalize(CFTypeRef cf) {
    struct __CFRunLoopObserver *o = (struct __CFRunLoopObserver *)cf;
    if (o->_context.release && o->_context.info)
        o->_context.release(o->_context.info);
}

static const CFRuntimeClass __CFRunLoopObserverClass = {
    0, "CFRunLoopObserver", NULL, NULL, __CFRunLoopObserverFinalize,
    NULL, NULL, NULL, NULL
};


/* ============================================================================
 * Type ID Accessors
 * ============================================================================ */

EXPORT CFTypeID CFRunLoopGetTypeID(void)         { return __CFRunLoopTypeID; }
EXPORT CFTypeID CFRunLoopSourceGetTypeID(void)   { return __CFRunLoopSourceTypeID; }
EXPORT CFTypeID CFRunLoopTimerGetTypeID(void)    { return __CFRunLoopTimerTypeID; }
EXPORT CFTypeID CFRunLoopObserverGetTypeID(void) { return __CFRunLoopObserverTypeID; }


/* ============================================================================
 * Internal: Mode Lookup / Creation
 * ============================================================================ */

HIDDEN __CFRunLoopMode *__CFRunLoopFindMode(struct __CFRunLoop *rl,
                                             CFRunLoopMode modeName,
                                             Boolean create) {
    if (!modeName) modeName = kCFRunLoopDefaultMode;

    /* Search existing modes */
    for (CFIndex i = 0; i < rl->_modeCount; i++) {
        if (CFEqual(rl->_modes[i]._name, modeName))
            return &rl->_modes[i];
    }

    if (!create) return NULL;

    /* Create new mode */
    if (rl->_modeCount >= __CF_RL_MAX_MODES) return NULL;

    __CFRunLoopMode *m = &rl->_modes[rl->_modeCount++];
    memset(m, 0, sizeof(*m));
    m->_name = (CFStringRef)CFRetain(modeName);
    return m;
}


/* ============================================================================
 * Internal: Create a new CFRunLoop for the current thread
 * ============================================================================ */

HIDDEN struct __CFRunLoop *__CFRunLoopCreate(void) {
    struct __CFRunLoop *rl = (struct __CFRunLoop *)_CFRuntimeCreateInstance(
        NULL, __CFRunLoopTypeID,
        sizeof(struct __CFRunLoop) - sizeof(CFRuntimeBase), NULL);
    if (!rl) return NULL;

    rl->_pthread = pthread_self();
    pthread_mutex_init(&rl->_lock, NULL);
    rl->_modeCount = 0;
    rl->_commonModeCount = 0;
    rl->_stopped = false;
    rl->_sleeping = false;
    rl->_currentMode = NULL;

    /* Allocate the wakeup Mach port */
    rl->_wakeUpPort = MACH_PORT_NULL;
    kern_return_t kr = mach_port_allocate(mach_task_self(),
                                           MACH_PORT_RIGHT_RECEIVE,
                                           &rl->_wakeUpPort);
    if (kr != KERN_SUCCESS) {
        rl->_wakeUpPort = MACH_PORT_NULL;
        /* Non-fatal: run loop will use nanosleep fallback */
    }

    /* Pre-create the default mode */
    __CFRunLoopFindMode(rl, kCFRunLoopDefaultMode, true);

    /* kCFRunLoopCommonModes: register default mode as a common mode */
    rl->_commonModes[0] = kCFRunLoopDefaultMode;
    rl->_commonModeCount = 1;

    return rl;
}


/* ============================================================================
 * CFRunLoopGetCurrent / CFRunLoopGetMain
 * ============================================================================ */

EXPORT CFRunLoopRef CFRunLoopGetCurrent(void) {
    __CFRunLoopEnsureTLS();

    struct __CFRunLoop *rl = (struct __CFRunLoop *)pthread_getspecific(__CFRunLoopTLSKey);
    if (rl) return (CFRunLoopRef)rl;

    /* Create a new run loop for this thread */
    rl = __CFRunLoopCreate();
    if (!rl) return NULL;

    pthread_setspecific(__CFRunLoopTLSKey, rl);

    /* First run loop created becomes the main run loop */
    if (__CFMainRunLoop == NULL)
        __CFMainRunLoop = rl;

    return (CFRunLoopRef)rl;
}

EXPORT CFRunLoopRef CFRunLoopGetMain(void) {
    if (__CFMainRunLoop) return (CFRunLoopRef)__CFMainRunLoop;

    /* Force creation via GetCurrent on the calling thread.
     * On real macOS this would always return the main thread's RL,
     * but in a single-threaded app this is equivalent. */
    return CFRunLoopGetCurrent();
}

EXPORT CFStringRef CFRunLoopCopyCurrentMode(CFRunLoopRef rl) {
    if (!rl) return NULL;
    const struct __CFRunLoop *loop = (const struct __CFRunLoop *)rl;
    if (loop->_currentMode) return (CFStringRef)CFRetain(loop->_currentMode);
    return NULL;
}

EXPORT CFArrayRef CFRunLoopCopyAllModes(CFRunLoopRef rl) {
    if (!rl) return NULL;
    const struct __CFRunLoop *loop = (const struct __CFRunLoop *)rl;
    /* Build an array of mode name strings */
    const void **values = (const void **)malloc((size_t)loop->_modeCount * sizeof(void *));
    if (!values) return NULL;
    for (CFIndex i = 0; i < loop->_modeCount; i++)
        values[i] = loop->_modes[i]._name;
    CFArrayRef arr = CFArrayCreate(NULL, values, loop->_modeCount, NULL);
    free(values);
    return arr;
}


/* ============================================================================
 * Internal: Observer Notification
 * ============================================================================ */

HIDDEN void __CFRunLoopNotifyObservers(struct __CFRunLoop *rl,
                                        __CFRunLoopMode *mode,
                                        CFRunLoopActivity activity) {
    for (CFIndex i = 0; i < mode->_observerCount; i++) {
        struct __CFRunLoopObserver *obs = mode->_observers[i];
        if (!obs || !obs->_valid) continue;
        if (!(obs->_activities & activity)) continue;

        if (obs->_callout)
            obs->_callout((CFRunLoopObserverRef)obs, activity,
                          obs->_context.info);

        /* Non-repeating observers are invalidated after first fire */
        if (!obs->_repeats)
            obs->_valid = false;
    }
}


/* ============================================================================
 * Internal: Fire Timers
 * ============================================================================ */

HIDDEN Boolean __CFRunLoopFireTimers(struct __CFRunLoop *rl,
                                      __CFRunLoopMode *mode) {
    CFAbsoluteTime now = CFAbsoluteTimeGetCurrent();
    Boolean fired = false;

    for (CFIndex i = 0; i < mode->_timerCount; i++) {
        struct __CFRunLoopTimer *t = mode->_timers[i];
        if (!t || !t->_valid) continue;
        if (t->_nextFireDate > now) continue;

        /* Fire the timer */
        if (t->_callout)
            t->_callout((CFRunLoopTimerRef)t, t->_context.info);
        fired = true;

        /* Reschedule repeating timer */
        if (t->_interval > 0.0) {
            /* Advance fire date. If we've fallen behind, skip forward
             * to the next future fire date (matching XNU behaviour). */
            while (t->_nextFireDate <= now)
                t->_nextFireDate += t->_interval;
        } else {
            /* One-shot timer: invalidate */
            t->_valid = false;
        }
    }

    return fired;
}


/* ============================================================================
 * Internal: Fire Signaled Sources
 * ============================================================================ */

HIDDEN Boolean __CFRunLoopFireSources0(struct __CFRunLoop *rl,
                                        __CFRunLoopMode *mode) {
    Boolean fired = false;

    for (CFIndex i = 0; i < mode->_sourceCount; i++) {
        struct __CFRunLoopSource *s = mode->_sources[i];
        if (!s || !s->_valid || !s->_signaled) continue;

        s->_signaled = false;
        if (s->_context.perform)
            s->_context.perform(s->_context.info);
        fired = true;
    }

    return fired;
}


/* ============================================================================
 * Internal: Compute Next Timer Fire Date
 * ============================================================================ */

HIDDEN CFTimeInterval __CFRunLoopNextTimerFireInterval(__CFRunLoopMode *mode) {
    CFAbsoluteTime now = CFAbsoluteTimeGetCurrent();
    CFTimeInterval earliest = 1.0e30;  /* very large sentinel */

    for (CFIndex i = 0; i < mode->_timerCount; i++) {
        struct __CFRunLoopTimer *t = mode->_timers[i];
        if (!t || !t->_valid) continue;
        CFTimeInterval delta = t->_nextFireDate - now;
        if (delta < earliest) earliest = delta;
    }

    return earliest;
}


/* ============================================================================
 * Internal: Check if Mode Has Sources/Timers
 * ============================================================================ */

HIDDEN Boolean __CFRunLoopModeIsEmpty(__CFRunLoopMode *mode) {
    for (CFIndex i = 0; i < mode->_sourceCount; i++) {
        if (mode->_sources[i] && mode->_sources[i]->_valid)
            return false;
    }
    for (CFIndex i = 0; i < mode->_timerCount; i++) {
        if (mode->_timers[i] && mode->_timers[i]->_valid)
            return false;
    }
    return true;
}


/* ============================================================================
 * Core Run Loop Implementation: __CFRunLoopRun
 *
 * This is the heart of CFRunLoop — the inner event processing loop.
 * On real macOS, this blocks on mach_msg(MACH_RCV_MSG | MACH_RCV_TIMEOUT).
 *
 * Reference: CFRunLoop.c __CFRunLoopRun() in apple/swift-corelibs-foundation
 *
 * Returns: kCFRunLoopRunFinished, kCFRunLoopRunStopped,
 *          kCFRunLoopRunTimedOut, kCFRunLoopRunHandledSource
 * ============================================================================ */

HIDDEN SInt32 __CFRunLoopRun(struct __CFRunLoop *rl,
                              __CFRunLoopMode *mode,
                              CFTimeInterval seconds,
                              Boolean returnAfterSourceHandled) {
    /* If the mode is empty (no sources, no timers), return immediately.
     * This matches XNU: "A run loop with no sources returns immediately." */
    if (__CFRunLoopModeIsEmpty(mode))
        return kCFRunLoopRunFinished;

    rl->_stopped = false;
    mode->_stopped = false;

    /* Entry notification */
    __CFRunLoopNotifyObservers(rl, mode, kCFRunLoopEntry);

    /* Calculate deadline */
    CFAbsoluteTime deadline = 0.0;
    if (seconds <= 0.0) {
        deadline = CFAbsoluteTimeGetCurrent(); /* immediate timeout */
    } else if (seconds >= 1.0e10) {
        deadline = 1.0e30; /* effectively infinite */
    } else {
        deadline = CFAbsoluteTimeGetCurrent() + seconds;
    }

    SInt32 retVal = 0;

    /* ---- Main loop ---- */
    do {
        /* Step 2: Notify observers — about to process timers */
        __CFRunLoopNotifyObservers(rl, mode, kCFRunLoopBeforeTimers);

        /* Step 3: Notify observers — about to process sources */
        __CFRunLoopNotifyObservers(rl, mode, kCFRunLoopBeforeSources);

        /* Step 4: Fire version 0 (callback-based) sources that are signaled */
        Boolean sourceHandled = __CFRunLoopFireSources0(rl, mode);

        if (sourceHandled && returnAfterSourceHandled) {
            retVal = kCFRunLoopRunHandledSource;
            break;
        }

        /* Step 5: Check if we've been stopped */
        if (rl->_stopped || mode->_stopped) {
            retVal = kCFRunLoopRunStopped;
            break;
        }

        /* Step 6: Compute how long to sleep.
         * Sleep duration = min(time until next timer, time until deadline). */
        CFTimeInterval sleepDuration;
        {
            CFTimeInterval timerInterval = __CFRunLoopNextTimerFireInterval(mode);
            CFTimeInterval untilDeadline = deadline - CFAbsoluteTimeGetCurrent();

            if (timerInterval < 0.0) timerInterval = 0.0;
            if (untilDeadline < 0.0) untilDeadline = 0.0;

            sleepDuration = timerInterval < untilDeadline ? timerInterval : untilDeadline;
            if (sleepDuration < 0.0) sleepDuration = 0.0;
        }

        /* Step 7: Notify observers — about to wait */
        __CFRunLoopNotifyObservers(rl, mode, kCFRunLoopBeforeWaiting);
        rl->_sleeping = true;

        /* Step 8: Sleep — block on wakeup Mach port with timeout.
         *
         * On XNU, CFRunLoop sleeps via:
         *   mk_timer_arm() + mach_msg(MACH_RCV_MSG | MACH_RCV_TIMEOUT)
         *
         * When CFRunLoopWakeUp() is called, a message is sent to the
         * wakeup port, which unblocks the mach_msg receive.
         */
        if (rl->_wakeUpPort != MACH_PORT_NULL) {
            /* Convert seconds to milliseconds for mach_msg timeout */
            mach_msg_timeout_t timeout_ms;
            if (sleepDuration >= 1.0e10) {
                timeout_ms = 0; /* 0 = infinite for mach_msg with no TIMEOUT flag */
            } else {
                timeout_ms = (mach_msg_timeout_t)(sleepDuration * 1000.0);
                if (timeout_ms == 0 && sleepDuration > 0.0)
                    timeout_ms = 1; /* minimum 1ms to avoid busy-loop */
            }

            mach_msg_header_t rcv_msg;
            memset(&rcv_msg, 0, sizeof(rcv_msg));

            mach_msg_option_t opts = MACH_RCV_MSG;
            if (sleepDuration < 1.0e10) {
                opts |= MACH_RCV_TIMEOUT;
            }

            /* This blocks until either:
             *   a) A message arrives (CFRunLoopWakeUp sent one)
             *   b) The timeout expires
             * Both cases are handled by the kernel's mach_msg_trap. */
            mach_msg(&rcv_msg, opts,
                     0,                     /* send_size */
                     sizeof(rcv_msg),       /* rcv_size */
                     rl->_wakeUpPort,       /* rcv_name */
                     timeout_ms,            /* timeout */
                     MACH_PORT_NULL);       /* notify */
            /* We don't check the return — MACH_RCV_TIMED_OUT is expected */
        } else {
            /* Fallback: no Mach port available, use nanosleep.
             * This is less faithful but functional. */
            if (sleepDuration > 0.0 && sleepDuration < 1.0e10) {
                struct timespec_cf ts;
                ts.tv_sec = (long)sleepDuration;
                ts.tv_nsec = (long)((sleepDuration - (double)ts.tv_sec) * 1.0e9);
                nanosleep(&ts, NULL);
            }
        }

        rl->_sleeping = false;

        /* Step 9: Notify observers — done waiting */
        __CFRunLoopNotifyObservers(rl, mode, kCFRunLoopAfterWaiting);

        /* Step 10: Fire timers */
        Boolean timerFired = __CFRunLoopFireTimers(rl, mode);
        (void)timerFired;

        /* Step 11: Fire any newly-signaled sources */
        sourceHandled = __CFRunLoopFireSources0(rl, mode);

        if (sourceHandled && returnAfterSourceHandled) {
            retVal = kCFRunLoopRunHandledSource;
            break;
        }

        /* Step 12: Check termination conditions */
        if (rl->_stopped || mode->_stopped) {
            retVal = kCFRunLoopRunStopped;
            break;
        }

        if (CFAbsoluteTimeGetCurrent() >= deadline) {
            retVal = kCFRunLoopRunTimedOut;
            break;
        }

        /* If the mode became empty, exit */
        if (__CFRunLoopModeIsEmpty(mode)) {
            retVal = kCFRunLoopRunFinished;
            break;
        }

    } while (1);

    /* Exit notification */
    __CFRunLoopNotifyObservers(rl, mode, kCFRunLoopExit);

    rl->_currentMode = NULL;
    return retVal;
}


/* ============================================================================
 * Public API: CFRunLoopRun / CFRunLoopRunInMode
 * ============================================================================ */

/* Forward declarations for mutual references */
EXPORT SInt32 CFRunLoopRunInMode(CFRunLoopMode modeName, CFTimeInterval seconds, Boolean returnAfterSourceHandled);
EXPORT void CFRunLoopWakeUp(CFRunLoopRef rl);

EXPORT void CFRunLoopRun(void) {
    /* CFRunLoopRun() runs in kCFRunLoopDefaultMode until stopped or
     * until all sources are removed. It re-enters repeatedly if
     * kCFRunLoopRunTimedOut or kCFRunLoopRunHandledSource. */
    SInt32 result;
    do {
        result = CFRunLoopRunInMode(kCFRunLoopDefaultMode, 1.0e10, false);
    } while (result != kCFRunLoopRunStopped && result != kCFRunLoopRunFinished);
}

EXPORT SInt32 CFRunLoopRunInMode(CFRunLoopMode modeName,
                                  CFTimeInterval seconds,
                                  Boolean returnAfterSourceHandled) {
    struct __CFRunLoop *rl = (struct __CFRunLoop *)CFRunLoopGetCurrent();
    if (!rl) return kCFRunLoopRunFinished;

    if (!modeName) modeName = kCFRunLoopDefaultMode;

    pthread_mutex_lock(&rl->_lock);
    __CFRunLoopMode *mode = __CFRunLoopFindMode(rl, modeName, false);
    pthread_mutex_unlock(&rl->_lock);

    if (!mode) return kCFRunLoopRunFinished;

    rl->_currentMode = modeName;
    return __CFRunLoopRun(rl, mode, seconds, returnAfterSourceHandled);
}


/* ============================================================================
 * Public API: CFRunLoopStop / CFRunLoopWakeUp / CFRunLoopIsWaiting
 * ============================================================================ */

EXPORT void CFRunLoopStop(CFRunLoopRef rl) {
    if (!rl) return;
    struct __CFRunLoop *loop = (struct __CFRunLoop *)rl;
    loop->_stopped = true;
    CFRunLoopWakeUp(rl);
}

EXPORT void CFRunLoopWakeUp(CFRunLoopRef rl) {
    if (!rl) return;
    struct __CFRunLoop *loop = (struct __CFRunLoop *)rl;

    if (loop->_wakeUpPort != MACH_PORT_NULL) {
        /* Send a zero-size message to the wakeup port.
         * This unblocks the mach_msg(MACH_RCV_MSG) in __CFRunLoopRun. */
        mach_msg_header_t msg;
        memset(&msg, 0, sizeof(msg));
        msg.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
        msg.msgh_size = sizeof(msg);
        msg.msgh_remote_port = loop->_wakeUpPort;
        msg.msgh_local_port = MACH_PORT_NULL;
        msg.msgh_id = 0;

        /* Non-blocking send — if the port is already full, that's fine,
         * the loop will wake up regardless. */
        mach_msg(&msg, MACH_SEND_MSG,
                 sizeof(msg), 0,
                 MACH_PORT_NULL, 0, MACH_PORT_NULL);
    }
}

EXPORT Boolean CFRunLoopIsWaiting(CFRunLoopRef rl) {
    if (!rl) return false;
    return ((const struct __CFRunLoop *)rl)->_sleeping;
}


/* ============================================================================
 * Public API: CFRunLoopAddCommonMode
 * ============================================================================ */

EXPORT void CFRunLoopAddCommonMode(CFRunLoopRef rl, CFRunLoopMode mode) {
    if (!rl || !mode) return;
    struct __CFRunLoop *loop = (struct __CFRunLoop *)rl;
    pthread_mutex_lock(&loop->_lock);

    /* Check if already registered */
    for (CFIndex i = 0; i < loop->_commonModeCount; i++) {
        if (CFEqual(loop->_commonModes[i], mode)) {
            pthread_mutex_unlock(&loop->_lock);
            return;
        }
    }

    if (loop->_commonModeCount < __CF_RL_MAX_COMMON) {
        loop->_commonModes[loop->_commonModeCount++] = mode;
        /* Ensure the mode object exists */
        __CFRunLoopFindMode(loop, mode, true);
    }

    pthread_mutex_unlock(&loop->_lock);
}


/* ============================================================================
 * Internal: Check if modeName is in the common modes set
 * ============================================================================ */

HIDDEN Boolean __CFRunLoopModeIsCommon(struct __CFRunLoop *rl,
                                        CFRunLoopMode modeName) {
    for (CFIndex i = 0; i < rl->_commonModeCount; i++) {
        if (CFEqual(rl->_commonModes[i], modeName))
            return true;
    }
    return false;
}


/* ============================================================================
 * Public API: Source Management
 * ============================================================================ */

EXPORT CFRunLoopSourceRef CFRunLoopSourceCreate(CFAllocatorRef allocator,
                                                 CFIndex order,
                                                 CFRunLoopSourceContext *context) {
    if (!context) return NULL;

    struct __CFRunLoopSource *s = (struct __CFRunLoopSource *)_CFRuntimeCreateInstance(
        allocator, __CFRunLoopSourceTypeID,
        sizeof(struct __CFRunLoopSource) - sizeof(CFRuntimeBase), NULL);
    if (!s) return NULL;

    s->_order = order;
    s->_valid = true;
    s->_signaled = false;
    memcpy(&s->_context, context, sizeof(CFRunLoopSourceContext));

    if (s->_context.retain && s->_context.info)
        s->_context.info = (void *)s->_context.retain(s->_context.info);

    return (CFRunLoopSourceRef)s;
}

EXPORT void CFRunLoopAddSource(CFRunLoopRef rl, CFRunLoopSourceRef source,
                                CFRunLoopMode modeName) {
    if (!rl || !source) return;
    struct __CFRunLoop *loop = (struct __CFRunLoop *)rl;
    struct __CFRunLoopSource *src = (struct __CFRunLoopSource *)source;

    pthread_mutex_lock(&loop->_lock);

    /* If modeName is kCFRunLoopCommonModes, add to all common modes */
    if (modeName == kCFRunLoopCommonModes || CFEqual(modeName, kCFRunLoopCommonModes)) {
        for (CFIndex ci = 0; ci < loop->_commonModeCount; ci++) {
            __CFRunLoopMode *m = __CFRunLoopFindMode(loop, loop->_commonModes[ci], true);
            if (!m) continue;
            if (m->_sourceCount < __CF_RL_MAX_SOURCES) {
                /* Check for duplicates */
                Boolean found = false;
                for (CFIndex j = 0; j < m->_sourceCount; j++) {
                    if (m->_sources[j] == src) { found = true; break; }
                }
                if (!found) {
                    m->_sources[m->_sourceCount++] = src;
                    if (src->_context.schedule)
                        src->_context.schedule(src->_context.info,
                                               (CFRunLoopRef)loop,
                                               m->_name);
                }
            }
        }
    } else {
        __CFRunLoopMode *m = __CFRunLoopFindMode(loop, modeName, true);
        if (m && m->_sourceCount < __CF_RL_MAX_SOURCES) {
            /* Check for duplicates */
            Boolean found = false;
            for (CFIndex j = 0; j < m->_sourceCount; j++) {
                if (m->_sources[j] == src) { found = true; break; }
            }
            if (!found) {
                m->_sources[m->_sourceCount++] = src;
                if (src->_context.schedule)
                    src->_context.schedule(src->_context.info,
                                           (CFRunLoopRef)loop, modeName);
            }
        }
    }

    pthread_mutex_unlock(&loop->_lock);
}

EXPORT void CFRunLoopRemoveSource(CFRunLoopRef rl, CFRunLoopSourceRef source,
                                   CFRunLoopMode modeName) {
    if (!rl || !source) return;
    struct __CFRunLoop *loop = (struct __CFRunLoop *)rl;
    struct __CFRunLoopSource *src = (struct __CFRunLoopSource *)source;

    pthread_mutex_lock(&loop->_lock);

    /* Helper: remove from a single mode */
    #define __REMOVE_SOURCE_FROM_MODE(m) do { \
        for (CFIndex j = 0; j < (m)->_sourceCount; j++) { \
            if ((m)->_sources[j] == src) { \
                if (src->_context.cancel) \
                    src->_context.cancel(src->_context.info, \
                                          (CFRunLoopRef)loop, (m)->_name); \
                (m)->_sources[j] = (m)->_sources[--(m)->_sourceCount]; \
                break; \
            } \
        } \
    } while (0)

    if (modeName == kCFRunLoopCommonModes || CFEqual(modeName, kCFRunLoopCommonModes)) {
        for (CFIndex ci = 0; ci < loop->_commonModeCount; ci++) {
            __CFRunLoopMode *m = __CFRunLoopFindMode(loop, loop->_commonModes[ci], false);
            if (m) __REMOVE_SOURCE_FROM_MODE(m);
        }
    } else {
        __CFRunLoopMode *m = __CFRunLoopFindMode(loop, modeName, false);
        if (m) __REMOVE_SOURCE_FROM_MODE(m);
    }

    #undef __REMOVE_SOURCE_FROM_MODE

    pthread_mutex_unlock(&loop->_lock);
}

EXPORT Boolean CFRunLoopContainsSource(CFRunLoopRef rl, CFRunLoopSourceRef source,
                                        CFRunLoopMode modeName) {
    if (!rl || !source) return false;
    struct __CFRunLoop *loop = (struct __CFRunLoop *)rl;
    struct __CFRunLoopSource *src = (struct __CFRunLoopSource *)source;

    pthread_mutex_lock(&loop->_lock);
    __CFRunLoopMode *m = __CFRunLoopFindMode(loop, modeName, false);
    Boolean found = false;
    if (m) {
        for (CFIndex j = 0; j < m->_sourceCount; j++) {
            if (m->_sources[j] == src) { found = true; break; }
        }
    }
    pthread_mutex_unlock(&loop->_lock);
    return found;
}

EXPORT void CFRunLoopSourceSignal(CFRunLoopSourceRef source) {
    if (!source) return;
    struct __CFRunLoopSource *src = (struct __CFRunLoopSource *)source;
    src->_signaled = true;
}

EXPORT void CFRunLoopSourceInvalidate(CFRunLoopSourceRef source) {
    if (!source) return;
    struct __CFRunLoopSource *src = (struct __CFRunLoopSource *)source;
    src->_valid = false;
    src->_signaled = false;
}

EXPORT Boolean CFRunLoopSourceIsValid(CFRunLoopSourceRef source) {
    if (!source) return false;
    return ((const struct __CFRunLoopSource *)source)->_valid;
}

EXPORT CFIndex CFRunLoopSourceGetOrder(CFRunLoopSourceRef source) {
    if (!source) return 0;
    return ((const struct __CFRunLoopSource *)source)->_order;
}

EXPORT void CFRunLoopSourceGetContext(CFRunLoopSourceRef source,
                                       CFRunLoopSourceContext *context) {
    if (!source || !context) return;
    const struct __CFRunLoopSource *s = (const struct __CFRunLoopSource *)source;
    memcpy(context, &s->_context, sizeof(CFRunLoopSourceContext));
}


/* ============================================================================
 * Public API: Timer Management
 * ============================================================================ */

EXPORT CFRunLoopTimerRef CFRunLoopTimerCreate(CFAllocatorRef allocator,
                                               CFAbsoluteTime fireDate,
                                               CFTimeInterval interval,
                                               CFOptionFlags flags,
                                               CFIndex order,
                                               CFRunLoopTimerCallBack callout) {
    struct __CFRunLoopTimer *t = (struct __CFRunLoopTimer *)_CFRuntimeCreateInstance(
        allocator, __CFRunLoopTimerTypeID,
        sizeof(struct __CFRunLoopTimer) - sizeof(CFRuntimeBase), NULL);
    if (!t) return NULL;

    t->_valid = true;
    t->_nextFireDate = fireDate;
    t->_interval = interval;
    t->_flags = flags;
    t->_order = order;
    t->_callout = callout;
    memset(&t->_context, 0, sizeof(t->_context));

    return (CFRunLoopTimerRef)t;
}

EXPORT CFRunLoopTimerRef CFRunLoopTimerCreateWithHandler(CFAllocatorRef allocator,
                                                          CFAbsoluteTime fireDate,
                                                          CFTimeInterval interval,
                                                          CFOptionFlags flags,
                                                          CFIndex order,
                                                          void *block) {
    /* Block-based timer — treat block pointer as info, callout invokes block.
     * For now, store block in context.info. The block calling convention
     * on ARM64 is: invoke = ((void **)block)[3], so we can't directly
     * call it without ObjC blocks runtime. Stub for API compatibility. */
    (void)block;
    return CFRunLoopTimerCreate(allocator, fireDate, interval, flags, order, NULL);
}

EXPORT void CFRunLoopAddTimer(CFRunLoopRef rl, CFRunLoopTimerRef timer,
                               CFRunLoopMode modeName) {
    if (!rl || !timer) return;
    struct __CFRunLoop *loop = (struct __CFRunLoop *)rl;
    struct __CFRunLoopTimer *t = (struct __CFRunLoopTimer *)timer;

    pthread_mutex_lock(&loop->_lock);

    if (modeName == kCFRunLoopCommonModes || CFEqual(modeName, kCFRunLoopCommonModes)) {
        for (CFIndex ci = 0; ci < loop->_commonModeCount; ci++) {
            __CFRunLoopMode *m = __CFRunLoopFindMode(loop, loop->_commonModes[ci], true);
            if (m && m->_timerCount < __CF_RL_MAX_TIMERS) {
                Boolean found = false;
                for (CFIndex j = 0; j < m->_timerCount; j++) {
                    if (m->_timers[j] == t) { found = true; break; }
                }
                if (!found) m->_timers[m->_timerCount++] = t;
            }
        }
    } else {
        __CFRunLoopMode *m = __CFRunLoopFindMode(loop, modeName, true);
        if (m && m->_timerCount < __CF_RL_MAX_TIMERS) {
            Boolean found = false;
            for (CFIndex j = 0; j < m->_timerCount; j++) {
                if (m->_timers[j] == t) { found = true; break; }
            }
            if (!found) m->_timers[m->_timerCount++] = t;
        }
    }

    pthread_mutex_unlock(&loop->_lock);
}

EXPORT void CFRunLoopRemoveTimer(CFRunLoopRef rl, CFRunLoopTimerRef timer,
                                  CFRunLoopMode modeName) {
    if (!rl || !timer) return;
    struct __CFRunLoop *loop = (struct __CFRunLoop *)rl;
    struct __CFRunLoopTimer *t = (struct __CFRunLoopTimer *)timer;

    pthread_mutex_lock(&loop->_lock);

    #define __REMOVE_TIMER_FROM_MODE(m) do { \
        for (CFIndex j = 0; j < (m)->_timerCount; j++) { \
            if ((m)->_timers[j] == t) { \
                (m)->_timers[j] = (m)->_timers[--(m)->_timerCount]; \
                break; \
            } \
        } \
    } while (0)

    if (modeName == kCFRunLoopCommonModes || CFEqual(modeName, kCFRunLoopCommonModes)) {
        for (CFIndex ci = 0; ci < loop->_commonModeCount; ci++) {
            __CFRunLoopMode *m = __CFRunLoopFindMode(loop, loop->_commonModes[ci], false);
            if (m) __REMOVE_TIMER_FROM_MODE(m);
        }
    } else {
        __CFRunLoopMode *m = __CFRunLoopFindMode(loop, modeName, false);
        if (m) __REMOVE_TIMER_FROM_MODE(m);
    }

    #undef __REMOVE_TIMER_FROM_MODE

    pthread_mutex_unlock(&loop->_lock);
}

EXPORT Boolean CFRunLoopContainsTimer(CFRunLoopRef rl, CFRunLoopTimerRef timer,
                                       CFRunLoopMode modeName) {
    if (!rl || !timer) return false;
    struct __CFRunLoop *loop = (struct __CFRunLoop *)rl;
    struct __CFRunLoopTimer *t = (struct __CFRunLoopTimer *)timer;

    pthread_mutex_lock(&loop->_lock);
    __CFRunLoopMode *m = __CFRunLoopFindMode(loop, modeName, false);
    Boolean found = false;
    if (m) {
        for (CFIndex j = 0; j < m->_timerCount; j++) {
            if (m->_timers[j] == t) { found = true; break; }
        }
    }
    pthread_mutex_unlock(&loop->_lock);
    return found;
}

EXPORT void CFRunLoopTimerInvalidate(CFRunLoopTimerRef timer) {
    if (!timer) return;
    ((struct __CFRunLoopTimer *)timer)->_valid = false;
}

EXPORT Boolean CFRunLoopTimerIsValid(CFRunLoopTimerRef timer) {
    if (!timer) return false;
    return ((const struct __CFRunLoopTimer *)timer)->_valid;
}

EXPORT CFAbsoluteTime CFRunLoopTimerGetNextFireDate(CFRunLoopTimerRef timer) {
    if (!timer) return 0.0;
    return ((const struct __CFRunLoopTimer *)timer)->_nextFireDate;
}

EXPORT void CFRunLoopTimerSetNextFireDate(CFRunLoopTimerRef timer, CFAbsoluteTime fireDate) {
    if (!timer) return;
    ((struct __CFRunLoopTimer *)timer)->_nextFireDate = fireDate;
}

EXPORT CFTimeInterval CFRunLoopTimerGetInterval(CFRunLoopTimerRef timer) {
    if (!timer) return 0.0;
    return ((const struct __CFRunLoopTimer *)timer)->_interval;
}

EXPORT CFIndex CFRunLoopTimerGetOrder(CFRunLoopTimerRef timer) {
    if (!timer) return 0;
    return ((const struct __CFRunLoopTimer *)timer)->_order;
}

EXPORT void CFRunLoopTimerGetContext(CFRunLoopTimerRef timer,
                                      CFRunLoopTimerContext *context) {
    if (!timer || !context) return;
    memcpy(context, &((const struct __CFRunLoopTimer *)timer)->_context,
           sizeof(CFRunLoopTimerContext));
}

EXPORT Boolean CFRunLoopTimerDoesRepeat(CFRunLoopTimerRef timer) {
    if (!timer) return false;
    return ((const struct __CFRunLoopTimer *)timer)->_interval > 0.0;
}


/* ============================================================================
 * Public API: Observer Management
 * ============================================================================ */

EXPORT CFRunLoopObserverRef CFRunLoopObserverCreate(CFAllocatorRef allocator,
                                                     CFRunLoopActivity activities,
                                                     Boolean repeats,
                                                     CFIndex order,
                                                     CFRunLoopObserverCallBack callout,
                                                     CFRunLoopObserverContext *context) {
    struct __CFRunLoopObserver *o = (struct __CFRunLoopObserver *)_CFRuntimeCreateInstance(
        allocator, __CFRunLoopObserverTypeID,
        sizeof(struct __CFRunLoopObserver) - sizeof(CFRuntimeBase), NULL);
    if (!o) return NULL;

    o->_valid = true;
    o->_repeats = repeats;
    o->_activities = activities;
    o->_order = order;
    o->_callout = callout;

    if (context) {
        memcpy(&o->_context, context, sizeof(CFRunLoopObserverContext));
        if (o->_context.retain && o->_context.info)
            o->_context.info = (void *)o->_context.retain(o->_context.info);
    } else {
        memset(&o->_context, 0, sizeof(o->_context));
    }

    return (CFRunLoopObserverRef)o;
}

EXPORT CFRunLoopObserverRef CFRunLoopObserverCreateWithHandler(CFAllocatorRef allocator,
                                                                CFRunLoopActivity activities,
                                                                Boolean repeats,
                                                                CFIndex order,
                                                                void *block) {
    /* Block-based observer — stub for API compatibility. */
    (void)block;
    return CFRunLoopObserverCreate(allocator, activities, repeats, order, NULL, NULL);
}

EXPORT void CFRunLoopAddObserver(CFRunLoopRef rl, CFRunLoopObserverRef observer,
                                  CFRunLoopMode modeName) {
    if (!rl || !observer) return;
    struct __CFRunLoop *loop = (struct __CFRunLoop *)rl;
    struct __CFRunLoopObserver *obs = (struct __CFRunLoopObserver *)observer;

    pthread_mutex_lock(&loop->_lock);

    if (modeName == kCFRunLoopCommonModes || CFEqual(modeName, kCFRunLoopCommonModes)) {
        for (CFIndex ci = 0; ci < loop->_commonModeCount; ci++) {
            __CFRunLoopMode *m = __CFRunLoopFindMode(loop, loop->_commonModes[ci], true);
            if (m && m->_observerCount < __CF_RL_MAX_OBSERVERS) {
                Boolean found = false;
                for (CFIndex j = 0; j < m->_observerCount; j++) {
                    if (m->_observers[j] == obs) { found = true; break; }
                }
                if (!found) m->_observers[m->_observerCount++] = obs;
            }
        }
    } else {
        __CFRunLoopMode *m = __CFRunLoopFindMode(loop, modeName, true);
        if (m && m->_observerCount < __CF_RL_MAX_OBSERVERS) {
            Boolean found = false;
            for (CFIndex j = 0; j < m->_observerCount; j++) {
                if (m->_observers[j] == obs) { found = true; break; }
            }
            if (!found) m->_observers[m->_observerCount++] = obs;
        }
    }

    pthread_mutex_unlock(&loop->_lock);
}

EXPORT void CFRunLoopRemoveObserver(CFRunLoopRef rl, CFRunLoopObserverRef observer,
                                     CFRunLoopMode modeName) {
    if (!rl || !observer) return;
    struct __CFRunLoop *loop = (struct __CFRunLoop *)rl;
    struct __CFRunLoopObserver *obs = (struct __CFRunLoopObserver *)observer;

    pthread_mutex_lock(&loop->_lock);

    #define __REMOVE_OBSERVER_FROM_MODE(m) do { \
        for (CFIndex j = 0; j < (m)->_observerCount; j++) { \
            if ((m)->_observers[j] == obs) { \
                (m)->_observers[j] = (m)->_observers[--(m)->_observerCount]; \
                break; \
            } \
        } \
    } while (0)

    if (modeName == kCFRunLoopCommonModes || CFEqual(modeName, kCFRunLoopCommonModes)) {
        for (CFIndex ci = 0; ci < loop->_commonModeCount; ci++) {
            __CFRunLoopMode *m = __CFRunLoopFindMode(loop, loop->_commonModes[ci], false);
            if (m) __REMOVE_OBSERVER_FROM_MODE(m);
        }
    } else {
        __CFRunLoopMode *m = __CFRunLoopFindMode(loop, modeName, false);
        if (m) __REMOVE_OBSERVER_FROM_MODE(m);
    }

    #undef __REMOVE_OBSERVER_FROM_MODE

    pthread_mutex_unlock(&loop->_lock);
}

EXPORT Boolean CFRunLoopContainsObserver(CFRunLoopRef rl, CFRunLoopObserverRef observer,
                                          CFRunLoopMode modeName) {
    if (!rl || !observer) return false;
    struct __CFRunLoop *loop = (struct __CFRunLoop *)rl;
    struct __CFRunLoopObserver *obs = (struct __CFRunLoopObserver *)observer;

    pthread_mutex_lock(&loop->_lock);
    __CFRunLoopMode *m = __CFRunLoopFindMode(loop, modeName, false);
    Boolean found = false;
    if (m) {
        for (CFIndex j = 0; j < m->_observerCount; j++) {
            if (m->_observers[j] == obs) { found = true; break; }
        }
    }
    pthread_mutex_unlock(&loop->_lock);
    return found;
}

EXPORT void CFRunLoopObserverInvalidate(CFRunLoopObserverRef observer) {
    if (!observer) return;
    ((struct __CFRunLoopObserver *)observer)->_valid = false;
}

EXPORT Boolean CFRunLoopObserverIsValid(CFRunLoopObserverRef observer) {
    if (!observer) return false;
    return ((const struct __CFRunLoopObserver *)observer)->_valid;
}

EXPORT CFRunLoopActivity CFRunLoopObserverGetActivities(CFRunLoopObserverRef observer) {
    if (!observer) return 0;
    return ((const struct __CFRunLoopObserver *)observer)->_activities;
}

EXPORT Boolean CFRunLoopObserverDoesRepeat(CFRunLoopObserverRef observer) {
    if (!observer) return false;
    return ((const struct __CFRunLoopObserver *)observer)->_repeats;
}

EXPORT CFIndex CFRunLoopObserverGetOrder(CFRunLoopObserverRef observer) {
    if (!observer) return 0;
    return ((const struct __CFRunLoopObserver *)observer)->_order;
}

EXPORT void CFRunLoopObserverGetContext(CFRunLoopObserverRef observer,
                                         CFRunLoopObserverContext *context) {
    if (!observer || !context) return;
    memcpy(context, &((const struct __CFRunLoopObserver *)observer)->_context,
           sizeof(CFRunLoopObserverContext));
}

/* ============================================================================
 * Public API: CFRunLoopPerformBlock (GCD-less version)
 *
 * On real macOS this dispatches a block on the run loop. Without GCD,
 * we implement it as a one-shot source that fires the block.
 * For now, a no-op stub — blocks require the ObjC blocks runtime.
 * ============================================================================ */

EXPORT void CFRunLoopPerformBlock(CFRunLoopRef rl, CFTypeRef mode, void *block) {
    (void)rl; (void)mode; (void)block;
    /* No-op until blocks runtime is available */
}


/* ============================================================================
 * Section 23: Framework Initialisation
 *
 * __attribute__((constructor)) runs when the dylib is loaded by dyld.
 * Registers all built-in CF types and initialises singleton instances.
 * ============================================================================ */

static void __CFInitSpecialNumbers(void) {
    /* +Infinity — hidden refcount already set to immortal in storage */
    __kCFNumberPosInfInstance._base._cfinfoa = __CFInfoMake(__CFNumberTypeID, 0);
    __kCFNumberPosInfInstance._type = kCFNumberFloat64Type;
    __kCFNumberPosInfInstance._value._float64 = __builtin_inf();

    /* -Infinity */
    __kCFNumberNegInfInstance._base._cfinfoa = __CFInfoMake(__CFNumberTypeID, 0);
    __kCFNumberNegInfInstance._type = kCFNumberFloat64Type;
    __kCFNumberNegInfInstance._value._float64 = -__builtin_inf();

    /* NaN */
    __kCFNumberNaNInstance._base._cfinfoa = __CFInfoMake(__CFNumberTypeID, 0);
    __kCFNumberNaNInstance._type = kCFNumberFloat64Type;
    __kCFNumberNaNInstance._value._float64 = __builtin_nan("");
}

__attribute__((constructor, used))
static void __CFInitialize(void) {
    /* Initialise runtime mutex */
    pthread_mutex_init(&__CFRuntimeLock, NULL);
    __CFRuntimeLockInit = 1;

    /* Register all built-in types.
     * Type IDs are assigned sequentially starting from 1:
     *   1 = CFAllocator
     *   2 = CFNull
     *   3 = CFBoolean
     *   4 = CFNumber
     *   5 = CFData
     *   6 = CFString
     *   7 = CFArray
     *   8 = CFDictionary
     *   9 = CFSet
     *  10 = CFDate
     *  11 = CFRunLoop
     *  12 = CFRunLoopSource
     *  13 = CFRunLoopTimer
     *  14 = CFRunLoopObserver
     *  15 = CFAttributedString
     */
    __CFAllocatorTypeID       = _CFRuntimeRegisterClass(&__CFAllocatorClass);
    __CFNullTypeID            = _CFRuntimeRegisterClass(&__CFNullClass);
    __CFBooleanTypeID         = _CFRuntimeRegisterClass(&__CFBooleanClass);
    __CFNumberTypeID          = _CFRuntimeRegisterClass(&__CFNumberClass);
    __CFDataTypeID            = _CFRuntimeRegisterClass(&__CFDataClass);
    __CFStringTypeID          = _CFRuntimeRegisterClass(&__CFStringClass);
    __CFArrayTypeID           = _CFRuntimeRegisterClass(&__CFArrayClass);
    __CFDictionaryTypeID      = _CFRuntimeRegisterClass(&__CFDictionaryClass);
    __CFSetTypeID             = _CFRuntimeRegisterClass(&__CFSetClass);
    __CFDateTypeID            = _CFRuntimeRegisterClass(&__CFDateClass);
    __CFRunLoopTypeID         = _CFRuntimeRegisterClass(&__CFRunLoopClass);
    __CFRunLoopSourceTypeID   = _CFRuntimeRegisterClass(&__CFRunLoopSourceClass);
    __CFRunLoopTimerTypeID    = _CFRuntimeRegisterClass(&__CFRunLoopTimerClass);
    __CFRunLoopObserverTypeID = _CFRuntimeRegisterClass(&__CFRunLoopObserverClass);
    __CFAttributedStringTypeID = _CFRuntimeRegisterClass(&__CFAttributedStringClass);

    /* Initialise static singleton instances with correct type IDs */
    _CFRuntimeInitStaticInstance(&__kCFAllocatorSystemDefaultInstance, __CFAllocatorTypeID);
    _CFRuntimeInitStaticInstance(&__kCFAllocatorMallocInstance, __CFAllocatorTypeID);
    _CFRuntimeInitStaticInstance(&__kCFAllocatorNullInstance, __CFAllocatorTypeID);
    _CFRuntimeInitStaticInstance(&__kCFNullInstance, __CFNullTypeID);
    _CFRuntimeInitStaticInstance(&__kCFBooleanTrueInstance, __CFBooleanTypeID);
    _CFRuntimeInitStaticInstance(&__kCFBooleanFalseInstance, __CFBooleanTypeID);

    /* Initialise special CFNumber constants */
    __CFInitSpecialNumbers();

    /* Initialise CFRunLoop mode string constants */
    /* These are interned constant strings — use __CFStringMakeConstantString
     * which is safe now that __CFStringTypeID is set */
    *(CFRunLoopMode *)&kCFRunLoopDefaultMode = __CFStringMakeConstantString("kCFRunLoopDefaultMode");
    *(CFRunLoopMode *)&kCFRunLoopCommonModes = __CFStringMakeConstantString("kCFRunLoopCommonModes");
}

/* ============================================================================
 * End of CoreFoundation.framework
 * ============================================================================ */
