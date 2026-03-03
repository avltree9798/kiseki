/*
 * Kiseki OS - Foundation.framework
 *
 * Objective-C bridge over CoreFoundation. Classes are toll-free bridged
 * to their CF counterparts — NSString IS CFString, NSDictionary IS
 * CFDictionary, etc. The same pointer is valid as both types.
 *
 * Toll-free bridging works because:
 *   1. GNUstep libobjc2 stores the refcount at obj[-1] (intptr_t before
 *      the object pointer), matching CoreFoundation's hidden refcount word.
 *   2. CFRuntimeBase._cfisa (offset 0) is the ObjC isa pointer.
 *   3. Foundation classes set the _cfisa field via _CFRuntimeBridgeSetISALookup
 *      so CF objects get the correct ObjC class.
 *
 * This file is compiled with the COMDAT-stripping pipeline:
 *   clang -fobjc-runtime=gnustep-1.9 -S -emit-llvm → sed → llc
 *
 * Reference: Apple Foundation framework, GNUstep Base
 */

/* ============================================================================
 * Section 1: Freestanding Type Definitions
 *
 * We cannot #include anything — all types defined inline, matching the
 * freestanding pattern established by CoreFoundation.c and CoreGraphics.c.
 * ============================================================================ */

typedef _Bool BOOL;
#define YES ((BOOL)1)
#define NO  ((BOOL)0)
#define nil ((id)0)
#define NULL ((void *)0)

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
typedef uint16_t            UniChar;
typedef double              CGFloat;
typedef signed long         NSInteger;
typedef unsigned long       NSUInteger;
typedef double              NSTimeInterval;

/* ============================================================================
 * Section 2: ObjC Runtime Declarations
 *
 * Minimal subset of the ObjC runtime API we need. These are provided
 * by libobjc.A.dylib at runtime.
 * ============================================================================ */

typedef struct objc_class    *Class;
typedef struct objc_object   *id;
typedef struct objc_selector *SEL;
typedef id (*IMP)(id, SEL, ...);
typedef struct objc_method   *Method;

struct objc_super {
    id    receiver;
    Class super_class;
};

extern id   objc_msgSend(id self, SEL _cmd, ...);
extern id   objc_msgSendSuper2(struct objc_super *super, SEL _cmd, ...);
extern id   objc_alloc(Class cls);
extern id   objc_alloc_init(Class cls);
extern id   objc_retain(id obj);
extern void objc_release(id obj);
extern id   objc_autorelease(id obj);
extern id   objc_autoreleaseReturnValue(id obj);
extern id   objc_retainAutoreleasedReturnValue(id obj);
extern void objc_storeStrong(id *location, id obj);
extern void *objc_autoreleasePoolPush(void);
extern void  objc_autoreleasePoolPop(void *pool);

extern Class  objc_getClass(const char *name);
extern Class  objc_allocateClassPair(Class superclass, const char *name, size_t extraBytes);
extern void   objc_registerClassPair(Class cls);
extern BOOL   class_addMethod(Class cls, SEL name, IMP imp, const char *types);
extern BOOL   class_addIvar(Class cls, const char *name, size_t size, uint8_t alignment, const char *types);
extern const char *class_getName(Class cls);
extern Class  class_getSuperclass(Class cls);
extern size_t class_getInstanceSize(Class cls);
extern BOOL   class_respondsToSelector(Class cls, SEL sel);
extern Class  object_getClass(id obj);
extern void  *object_getIndexedIvars(id obj);
extern SEL    sel_registerName(const char *str);
extern const char *sel_getName(SEL sel);
extern void   objc_enumerationMutation(id obj);

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

extern size_t strlen(const char *s);
extern int    strcmp(const char *s1, const char *s2);
extern int    strncmp(const char *s1, const char *s2, size_t n);
extern char  *strcpy(char *dst, const char *src);
extern char  *strncpy(char *dst, const char *src, size_t n);
extern char  *strdup(const char *s);
extern int    snprintf(char *buf, size_t size, const char *fmt, ...);
extern int    printf(const char *fmt, ...);
extern size_t fwrite(const void *ptr, size_t size, size_t nmemb, void *stream);

extern void *__stdoutp;
#define stdout __stdoutp

/* Safe stderr write — bypasses broken FILE* pointer (Bug 21 fix) */
static void _fnd_stderr_write(const char *s) {
    if (!s) return;
    unsigned long len = 0;
    while (s[len]) len++;
    if (len == 0) return;
    long r;
    __asm__ volatile(
        "mov x0, #2\n"
        "mov x1, %1\n"
        "mov x2, %2\n"
        "mov x16, #4\n"
        "svc #0x80\n"
        "mov %0, x0"
        : "=r"(r) : "r"(s), "r"(len) : "x0","x1","x2","x16","memory");
}

/* ============================================================================
 * Section 4: CoreFoundation Imported Types & Functions
 *
 * These match the exact layout in CoreFoundation.c so toll-free bridging
 * works — an NSString* and CFStringRef point to the same memory.
 * ============================================================================ */

typedef unsigned long CFTypeID;
typedef signed long   CFIndex;
typedef unsigned long CFHashCode;
typedef unsigned int  UInt32;
typedef unsigned long CFOptionFlags;
typedef double        CFTimeInterval;
typedef double        CFAbsoluteTime;

typedef const void   *CFTypeRef;
typedef const void   *CFAllocatorRef;
typedef const void   *CFStringRef;
typedef const void   *CFMutableStringRef;
typedef const void   *CFArrayRef;
typedef const void   *CFMutableArrayRef;
typedef const void   *CFDictionaryRef;
typedef const void   *CFMutableDictionaryRef;
typedef const void   *CFDataRef;
typedef const void   *CFNumberRef;
typedef const void   *CFDateRef;
typedef const void   *CFAttributedStringRef;
typedef const void   *CFRunLoopRef;
typedef const void   *CFRunLoopSourceRef;
typedef const void   *CFRunLoopTimerRef;
typedef const void   *CFRunLoopObserverRef;
typedef CFStringRef   CFRunLoopMode;

extern const CFAllocatorRef kCFAllocatorDefault;
extern const CFRunLoopMode  kCFRunLoopDefaultMode;
extern const CFRunLoopMode  kCFRunLoopCommonModes;
extern const void *kCFTypeDictionaryKeyCallBacks;
extern const void *kCFTypeDictionaryValueCallBacks;

/* CFRuntime — must match CoreFoundation.c layout exactly */
typedef struct {
    uintptr_t _cfisa;
    uint64_t  _cfinfoa;
} CFRuntimeBase;

typedef struct {
    CFIndex        version;
    const char    *className;
    void (*init)(CFTypeRef cf);
    void *copy;
    void (*finalize)(CFTypeRef cf);
    BOOL (*equal)(CFTypeRef cf1, CFTypeRef cf2);
    CFHashCode (*hash)(CFTypeRef cf);
    void *copyFormattingDesc;
    void *copyDebugDesc;
} CFRuntimeClass;

extern CFTypeID _CFRuntimeRegisterClass(const CFRuntimeClass *cls);
extern CFTypeRef _CFRuntimeCreateInstance(CFAllocatorRef alloc, CFTypeID typeID,
                                           CFIndex extraBytes, void *category);
extern void _CFRuntimeInitStaticInstance(void *memory, CFTypeID typeID);

/* CF functions we call */
extern CFTypeRef   CFRetain(CFTypeRef cf);
extern void        CFRelease(CFTypeRef cf);
extern CFTypeID    CFGetTypeID(CFTypeRef cf);

/* Individual type ID getters — needed for toll-free bridging ISA lookup */
extern CFTypeID CFStringGetTypeID(void);
extern CFTypeID CFArrayGetTypeID(void);
extern CFTypeID CFDictionaryGetTypeID(void);
extern CFTypeID CFNumberGetTypeID(void);
extern CFTypeID CFDataGetTypeID(void);
extern CFTypeID CFDateGetTypeID(void);
extern CFTypeID CFSetGetTypeID(void);
extern CFTypeID CFBooleanGetTypeID(void);
extern CFTypeID CFNullGetTypeID(void);

/* Bridge ISA lookup registration */
typedef uintptr_t (*__CFBridgeISALookupFn)(CFTypeID typeID);
extern void _CFRuntimeBridgeSetISALookup(__CFBridgeISALookupFn fn);

extern CFStringRef CFStringCreateWithCString(CFAllocatorRef alloc, const char *cStr, UInt32 encoding);
extern const char *CFStringGetCStringPtr(CFStringRef theString, UInt32 encoding);
extern CFIndex     CFStringGetLength(CFStringRef theString);
extern UniChar     CFStringGetCharacterAtIndex(CFStringRef theString, CFIndex idx);
extern BOOL        CFStringGetCString(CFStringRef theString, char *buffer, CFIndex bufferSize, UInt32 encoding);
extern CFIndex     CFStringGetMaximumSizeForEncoding(CFIndex length, UInt32 encoding);
extern CFStringRef __CFStringMakeConstantString(const char *cStr);
#define CFSTR(s) __CFStringMakeConstantString(s)

#define kCFStringEncodingUTF8       ((UInt32)0x08000100)
#define kCFStringEncodingASCII      ((UInt32)0x0600)

extern CFArrayRef       CFArrayCreate(CFAllocatorRef alloc, const void **values, CFIndex numValues, const void *callBacks);
extern CFIndex          CFArrayGetCount(CFArrayRef theArray);
extern const void      *CFArrayGetValueAtIndex(CFArrayRef theArray, CFIndex idx);
extern CFMutableArrayRef CFArrayCreateMutable(CFAllocatorRef alloc, CFIndex capacity, const void *callBacks);
extern void             CFArrayAppendValue(CFMutableArrayRef theArray, const void *value);

extern CFDictionaryRef  CFDictionaryCreate(CFAllocatorRef alloc, const void **keys, const void **values,
                                            CFIndex numValues, const void *keyCallBacks, const void *valueCallBacks);
extern const void      *CFDictionaryGetValue(CFDictionaryRef theDict, const void *key);
extern CFIndex          CFDictionaryGetCount(CFDictionaryRef theDict);
extern CFMutableDictionaryRef CFDictionaryCreateMutable(CFAllocatorRef alloc, CFIndex capacity,
                                                         const void *keyCallBacks, const void *valueCallBacks);
extern void             CFDictionarySetValue(CFMutableDictionaryRef theDict, const void *key, const void *value);
extern void             CFDictionaryRemoveValue(CFMutableDictionaryRef theDict, const void *key);
extern BOOL             CFDictionaryContainsKey(CFDictionaryRef theDict, const void *key);

extern CFNumberRef      CFNumberCreate(CFAllocatorRef alloc, CFIndex theType, const void *valuePtr);
extern BOOL             CFNumberGetValue(CFNumberRef number, CFIndex theType, void *valuePtr);
#define kCFNumberIntType     9
#define kCFNumberFloat64Type 13
#define kCFNumberNSIntegerType kCFNumberIntType

extern CFRunLoopRef     CFRunLoopGetCurrent(void);
extern CFRunLoopRef     CFRunLoopGetMain(void);
extern void             CFRunLoopRun(void);
extern int32_t          CFRunLoopRunInMode(CFRunLoopMode mode, CFTimeInterval seconds, BOOL returnAfterSourceHandled);
extern void             CFRunLoopStop(CFRunLoopRef rl);
extern void             CFRunLoopWakeUp(CFRunLoopRef rl);

extern CFAbsoluteTime   CFAbsoluteTimeGetCurrent(void);

/* Comparison results — matching CF */
typedef CFIndex CFComparisonResult;
#define NSOrderedAscending  ((NSInteger)-1)
#define NSOrderedSame       ((NSInteger)0)
#define NSOrderedDescending ((NSInteger)1)

/* NSRange */
typedef struct _NSRange {
    NSUInteger location;
    NSUInteger length;
} NSRange;

static inline NSRange NSMakeRange(NSUInteger loc, NSUInteger len) {
    NSRange r = { loc, len };
    return r;
}

#define NSNotFound ((NSInteger)0x7fffffffffffffffL)

/* ============================================================================
 * Section 5: NSObject — Root Class
 *
 * NSObject is the root of the Objective-C class hierarchy. Every method
 * call in Foundation ultimately goes through NSObject's retain/release
 * mechanism, which delegates to CFRetain/CFRelease for toll-free bridged
 * objects.
 *
 * The isa pointer for toll-free bridged objects is set by CFRuntimeBase._cfisa.
 * ============================================================================ */

__attribute__((objc_root_class))
@interface NSObject {
    Class isa;
}
+ (id)alloc;
+ (id)new;
+ (id)allocWithZone:(void *)zone;
+ (Class)class;
+ (Class)superclass;
+ (BOOL)instancesRespondToSelector:(SEL)aSelector;
+ (BOOL)conformsToProtocol:(void *)protocol;
+ (NSUInteger)hash;
+ (BOOL)isEqual:(id)object;
- (id)init;
- (void)dealloc;
- (id)retain;
- (void)release;
- (id)autorelease;
- (NSUInteger)retainCount;
- (Class)class;
- (Class)superclass;
- (BOOL)isKindOfClass:(Class)aClass;
- (BOOL)isMemberOfClass:(Class)aClass;
- (BOOL)respondsToSelector:(SEL)aSelector;
- (BOOL)conformsToProtocol:(void *)protocol;
- (NSUInteger)hash;
- (BOOL)isEqual:(id)object;
- (id)description;
- (id)debugDescription;
- (id)performSelector:(SEL)aSelector;
- (id)performSelector:(SEL)aSelector withObject:(id)object;
- (id)self;
- (BOOL)isProxy;
@end



@implementation NSObject

+ (id)alloc {
    size_t size = class_getInstanceSize(self);

    /* Allocate with hidden refcount word at obj[-1] for toll-free bridging */
    intptr_t *raw = (intptr_t *)calloc(1, sizeof(intptr_t) + size);
    if (!raw) return nil;
    *raw = 1; /* initial refcount */
    id obj = (id)(raw + 1);
    /* Set isa — for GNUstep runtime, isa is at offset 0 */
    ((struct { Class isa; } *)obj)->isa = self;
    return obj;
}

+ (id)new {
    return [[self alloc] init];
}

+ (id)allocWithZone:(void *)zone {
    (void)zone;
    return [self alloc];
}

+ (Class)class {
    return self;
}

+ (Class)superclass {
    return class_getSuperclass(self);
}

+ (BOOL)instancesRespondToSelector:(SEL)aSelector {
    return class_respondsToSelector(self, aSelector);
}

+ (BOOL)conformsToProtocol:(void *)protocol {
    (void)protocol;
    return NO; /* simplified */
}

+ (NSUInteger)hash {
    return (NSUInteger)(uintptr_t)self;
}

+ (BOOL)isEqual:(id)object {
    return (id)self == object;
}

- (id)init {
    return self;
}

- (void)dealloc {
    /* Free the object, accounting for the hidden refcount word */
    intptr_t *raw = ((intptr_t *)self) - 1;
    free(raw);
}

- (id)retain {
    intptr_t *rc = ((intptr_t *)self) - 1;
    (*rc)++;
    return self;
}

- (void)release {
    intptr_t *rc = ((intptr_t *)self) - 1;
    if (--(*rc) <= 0) {
        [self dealloc];
    }
}

- (id)autorelease {
    return objc_autorelease(self);
}

- (NSUInteger)retainCount {
    intptr_t *rc = ((intptr_t *)self) - 1;
    return (NSUInteger)(*rc);
}

- (Class)class {
    return object_getClass(self);
}

- (Class)superclass {
    return class_getSuperclass(object_getClass(self));
}

- (BOOL)isKindOfClass:(Class)aClass {
    Class cls = object_getClass(self);
    while (cls) {
        if (cls == aClass) return YES;
        cls = class_getSuperclass(cls);
    }
    return NO;
}

- (BOOL)isMemberOfClass:(Class)aClass {
    return object_getClass(self) == aClass;
}

- (BOOL)respondsToSelector:(SEL)aSelector {
    return class_respondsToSelector(object_getClass(self), aSelector);
}

- (BOOL)conformsToProtocol:(void *)protocol {
    (void)protocol;
    return NO;
}

- (NSUInteger)hash {
    return (NSUInteger)(uintptr_t)self;
}

- (BOOL)isEqual:(id)object {
    return self == object;
}

- (id)description {
    /* Return a CFString describing the object — "<ClassName: 0xaddress>" */
    const char *name = class_getName(object_getClass(self));
    char buf[128];
    snprintf(buf, sizeof(buf), "<%s: %p>", name, (void *)self);
    return (id)CFStringCreateWithCString(kCFAllocatorDefault, buf, kCFStringEncodingUTF8);
}

- (id)debugDescription {
    return [self description];
}

- (id)performSelector:(SEL)aSelector {
    return ((id (*)(id, SEL))objc_msgSend)(self, aSelector);
}

- (id)performSelector:(SEL)aSelector withObject:(id)object {
    return ((id (*)(id, SEL, id))objc_msgSend)(self, aSelector, object);
}

- (id)self {
    return self;
}

- (BOOL)isProxy {
    return NO;
}

@end

/* ============================================================================
 * Section 6: NSString — Toll-Free Bridged to CFString
 *
 * NSString is an ObjC class whose instances ARE CFString objects.
 * The isa pointer at offset 0 of every CFString is set to the NSString
 * class. All methods delegate to CFString functions.
 * ============================================================================ */

@interface NSString : NSObject
+ (id)string;
+ (id)stringWithUTF8String:(const char *)nullTerminatedCString;
+ (id)stringWithCString:(const char *)cString encoding:(NSUInteger)enc;
+ (id)stringWithFormat:(id)format, ...;
- (NSUInteger)length;
- (UniChar)characterAtIndex:(NSUInteger)index;
- (const char *)UTF8String;
- (BOOL)isEqualToString:(id)aString;
- (id)substringFromIndex:(NSUInteger)from;
- (id)substringToIndex:(NSUInteger)to;
- (id)substringWithRange:(NSRange)range;
- (NSRange)rangeOfString:(id)searchString;
- (BOOL)hasPrefix:(id)str;
- (BOOL)hasSuffix:(id)str;
- (NSInteger)integerValue;
- (double)doubleValue;
- (id)stringByAppendingString:(id)aString;
- (id)description;
- (NSUInteger)hash;
- (BOOL)isEqual:(id)object;
@end

@implementation NSString

+ (id)string {
    return (id)CFStringCreateWithCString(kCFAllocatorDefault, "", kCFStringEncodingUTF8);
}

+ (id)stringWithUTF8String:(const char *)nullTerminatedCString {
    if (!nullTerminatedCString) return nil;
    return (id)CFStringCreateWithCString(kCFAllocatorDefault, nullTerminatedCString, kCFStringEncodingUTF8);
}

+ (id)stringWithCString:(const char *)cString encoding:(NSUInteger)enc {
    (void)enc; /* treat everything as UTF-8 */
    if (!cString) return nil;
    return (id)CFStringCreateWithCString(kCFAllocatorDefault, cString, kCFStringEncodingUTF8);
}

+ (id)stringWithFormat:(id)format, ... {
    /* Simplified: just return the format string itself */
    /* A real implementation would do va_list formatting */
    if (!format) return nil;
    return (id)CFRetain((CFTypeRef)format);
}

- (NSUInteger)length {
    return (NSUInteger)CFStringGetLength((CFStringRef)self);
}

- (UniChar)characterAtIndex:(NSUInteger)index {
    return CFStringGetCharacterAtIndex((CFStringRef)self, (CFIndex)index);
}

- (const char *)UTF8String {
    return CFStringGetCStringPtr((CFStringRef)self, kCFStringEncodingUTF8);
}

- (BOOL)isEqualToString:(id)aString {
    if (!aString) return NO;
    if (self == aString) return YES;
    NSUInteger myLen = [self length];
    NSUInteger otherLen = [(NSString *)aString length];
    if (myLen != otherLen) return NO;
    for (NSUInteger i = 0; i < myLen; i++) {
        if ([self characterAtIndex:i] != [(NSString *)aString characterAtIndex:i])
            return NO;
    }
    return YES;
}

- (id)substringFromIndex:(NSUInteger)from {
    const char *s = [self UTF8String];
    if (!s || from >= strlen(s)) return [NSString string];
    return [NSString stringWithUTF8String:s + from];
}

- (id)substringToIndex:(NSUInteger)to {
    const char *s = [self UTF8String];
    if (!s) return [NSString string];
    size_t len = strlen(s);
    if (to > len) to = (NSUInteger)len;
    char *buf = (char *)malloc(to + 1);
    if (!buf) return [NSString string];
    memcpy(buf, s, to);
    buf[to] = '\0';
    id result = [NSString stringWithUTF8String:buf];
    free(buf);
    return result;
}

- (id)substringWithRange:(NSRange)range {
    const char *s = [self UTF8String];
    if (!s) return [NSString string];
    size_t len = strlen(s);
    if (range.location >= len) return [NSString string];
    NSUInteger end = range.location + range.length;
    if (end > len) end = (NSUInteger)len;
    NSUInteger subLen = end - range.location;
    char *buf = (char *)malloc(subLen + 1);
    if (!buf) return [NSString string];
    memcpy(buf, s + range.location, subLen);
    buf[subLen] = '\0';
    id result = [NSString stringWithUTF8String:buf];
    free(buf);
    return result;
}

- (NSRange)rangeOfString:(id)searchString {
    if (!searchString) return NSMakeRange((NSUInteger)NSNotFound, 0);
    const char *haystack = [self UTF8String];
    const char *needle = [(NSString *)searchString UTF8String];
    if (!haystack || !needle) return NSMakeRange((NSUInteger)NSNotFound, 0);
    const char *found = NULL;
    /* Simple strstr */
    size_t nlen = strlen(needle);
    size_t hlen = strlen(haystack);
    for (size_t i = 0; i + nlen <= hlen; i++) {
        if (memcmp(haystack + i, needle, nlen) == 0) {
            found = haystack + i;
            break;
        }
    }
    if (!found) return NSMakeRange((NSUInteger)NSNotFound, 0);
    return NSMakeRange((NSUInteger)(found - haystack), (NSUInteger)nlen);
}

- (BOOL)hasPrefix:(id)str {
    if (!str) return NO;
    const char *s = [self UTF8String];
    const char *p = [(NSString *)str UTF8String];
    if (!s || !p) return NO;
    return strncmp(s, p, strlen(p)) == 0;
}

- (BOOL)hasSuffix:(id)str {
    if (!str) return NO;
    const char *s = [self UTF8String];
    const char *p = [(NSString *)str UTF8String];
    if (!s || !p) return NO;
    size_t slen = strlen(s);
    size_t plen = strlen(p);
    if (plen > slen) return NO;
    return strcmp(s + slen - plen, p) == 0;
}

- (NSInteger)integerValue {
    const char *s = [self UTF8String];
    if (!s) return 0;
    NSInteger result = 0;
    BOOL negative = NO;
    while (*s == ' ' || *s == '\t') s++;
    if (*s == '-') { negative = YES; s++; }
    else if (*s == '+') { s++; }
    while (*s >= '0' && *s <= '9') {
        result = result * 10 + (*s - '0');
        s++;
    }
    return negative ? -result : result;
}

- (double)doubleValue {
    const char *s = [self UTF8String];
    if (!s) return 0.0;
    /* Simple atof — parse integer.fraction */
    double result = 0.0;
    BOOL negative = NO;
    while (*s == ' ' || *s == '\t') s++;
    if (*s == '-') { negative = YES; s++; }
    else if (*s == '+') { s++; }
    while (*s >= '0' && *s <= '9') {
        result = result * 10.0 + (*s - '0');
        s++;
    }
    if (*s == '.') {
        s++;
        double frac = 0.1;
        while (*s >= '0' && *s <= '9') {
            result += (*s - '0') * frac;
            frac *= 0.1;
            s++;
        }
    }
    return negative ? -result : result;
}

- (id)stringByAppendingString:(id)aString {
    const char *s1 = [self UTF8String];
    const char *s2 = [(NSString *)aString UTF8String];
    if (!s1) s1 = "";
    if (!s2) s2 = "";
    size_t l1 = strlen(s1);
    size_t l2 = strlen(s2);
    char *buf = (char *)malloc(l1 + l2 + 1);
    if (!buf) return [NSString string];
    memcpy(buf, s1, l1);
    memcpy(buf + l1, s2, l2);
    buf[l1 + l2] = '\0';
    id result = [NSString stringWithUTF8String:buf];
    free(buf);
    return result;
}

- (id)description {
    return (id)CFRetain((CFTypeRef)self);
}

- (NSUInteger)hash {
    const char *s = [self UTF8String];
    if (!s) return 0;
    /* DJB2 hash */
    NSUInteger h = 5381;
    int c;
    while ((c = *s++)) {
        h = ((h << 5) + h) + (NSUInteger)c;
    }
    return h;
}

- (BOOL)isEqual:(id)object {
    if (self == object) return YES;
    if (!object) return NO;
    if (![object isKindOfClass:[NSString class]]) return NO;
    return [self isEqualToString:object];
}

@end

/* ============================================================================
 * Section 7: NSMutableString
 * ============================================================================ */

@interface NSMutableString : NSString
- (void)appendString:(id)aString;
- (void)appendFormat:(id)format, ...;
- (void)setString:(id)aString;
@end

@implementation NSMutableString

- (void)appendString:(id)aString {
    /* Simplified: NSMutableString as standalone is limited.
     * For toll-free bridging, this delegates to CFStringAppend. */
    (void)aString;
    /* TODO: implement via CFStringAppend when available */
}

- (void)appendFormat:(id)format, ... {
    (void)format;
}

- (void)setString:(id)aString {
    (void)aString;
}

@end

/* ============================================================================
 * Section 8: NSNumber — Toll-Free Bridged to CFNumber
 * ============================================================================ */

@interface NSNumber : NSObject
+ (id)numberWithInt:(int)value;
+ (id)numberWithInteger:(NSInteger)value;
+ (id)numberWithFloat:(float)value;
+ (id)numberWithDouble:(double)value;
+ (id)numberWithBool:(BOOL)value;
- (int)intValue;
- (NSInteger)integerValue;
- (float)floatValue;
- (double)doubleValue;
- (BOOL)boolValue;
- (id)description;
@end

@implementation NSNumber

+ (id)numberWithInt:(int)value {
    return (id)CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &value);
}

+ (id)numberWithInteger:(NSInteger)value {
    return (id)CFNumberCreate(kCFAllocatorDefault, kCFNumberNSIntegerType, &value);
}

+ (id)numberWithFloat:(float)value {
    double d = (double)value;
    return (id)CFNumberCreate(kCFAllocatorDefault, kCFNumberFloat64Type, &d);
}

+ (id)numberWithDouble:(double)value {
    return (id)CFNumberCreate(kCFAllocatorDefault, kCFNumberFloat64Type, &value);
}

+ (id)numberWithBool:(BOOL)value {
    int v = value ? 1 : 0;
    return (id)CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &v);
}

- (int)intValue {
    int v = 0;
    CFNumberGetValue((CFNumberRef)self, kCFNumberIntType, &v);
    return v;
}

- (NSInteger)integerValue {
    NSInteger v = 0;
    CFNumberGetValue((CFNumberRef)self, kCFNumberNSIntegerType, &v);
    return v;
}

- (float)floatValue {
    double d = 0.0;
    CFNumberGetValue((CFNumberRef)self, kCFNumberFloat64Type, &d);
    return (float)d;
}

- (double)doubleValue {
    double d = 0.0;
    CFNumberGetValue((CFNumberRef)self, kCFNumberFloat64Type, &d);
    return d;
}

- (BOOL)boolValue {
    int v = 0;
    CFNumberGetValue((CFNumberRef)self, kCFNumberIntType, &v);
    return v != 0;
}

- (id)description {
    double d = [self doubleValue];
    char buf[64];
    snprintf(buf, sizeof(buf), "%g", d);
    return (id)CFStringCreateWithCString(kCFAllocatorDefault, buf, kCFStringEncodingUTF8);
}

@end

/* ============================================================================
 * Section 9: NSArray — Toll-Free Bridged to CFArray
 * ============================================================================ */

@interface NSArray : NSObject
+ (id)array;
+ (id)arrayWithObject:(id)anObject;
+ (id)arrayWithObjects:(const id *)objects count:(NSUInteger)cnt;
- (NSUInteger)count;
- (id)objectAtIndex:(NSUInteger)index;
- (id)firstObject;
- (id)lastObject;
- (BOOL)containsObject:(id)anObject;
- (NSUInteger)indexOfObject:(id)anObject;
- (id)description;
@end

@implementation NSArray

+ (id)array {
    return (id)CFArrayCreate(kCFAllocatorDefault, NULL, 0, NULL);
}

+ (id)arrayWithObject:(id)anObject {
    const void *values[1] = { (const void *)anObject };
    return (id)CFArrayCreate(kCFAllocatorDefault, values, 1, NULL);
}

+ (id)arrayWithObjects:(const id *)objects count:(NSUInteger)cnt {
    return (id)CFArrayCreate(kCFAllocatorDefault, (const void **)objects, (CFIndex)cnt, NULL);
}

- (NSUInteger)count {
    return (NSUInteger)CFArrayGetCount((CFArrayRef)self);
}

- (id)objectAtIndex:(NSUInteger)index {
    return (id)CFArrayGetValueAtIndex((CFArrayRef)self, (CFIndex)index);
}

- (id)firstObject {
    if ([self count] == 0) return nil;
    return [self objectAtIndex:0];
}

- (id)lastObject {
    NSUInteger c = [self count];
    if (c == 0) return nil;
    return [self objectAtIndex:c - 1];
}

- (BOOL)containsObject:(id)anObject {
    return [self indexOfObject:anObject] != (NSUInteger)NSNotFound;
}

- (NSUInteger)indexOfObject:(id)anObject {
    NSUInteger c = [self count];
    for (NSUInteger i = 0; i < c; i++) {
        if ([[self objectAtIndex:i] isEqual:anObject]) return i;
    }
    return (NSUInteger)NSNotFound;
}

- (id)description {
    return (id)CFSTR("(NSArray)");
}

@end

/* ============================================================================
 * Section 10: NSMutableArray — Toll-Free Bridged to CFMutableArray
 * ============================================================================ */

@interface NSMutableArray : NSArray
+ (id)array;
+ (id)arrayWithCapacity:(NSUInteger)numItems;
- (void)addObject:(id)anObject;
- (void)insertObject:(id)anObject atIndex:(NSUInteger)index;
- (void)removeObjectAtIndex:(NSUInteger)index;
- (void)removeLastObject;
- (void)removeAllObjects;
- (void)replaceObjectAtIndex:(NSUInteger)index withObject:(id)anObject;
@end

@implementation NSMutableArray

+ (id)array {
    return (id)CFArrayCreateMutable(kCFAllocatorDefault, 0, NULL);
}

+ (id)arrayWithCapacity:(NSUInteger)numItems {
    return (id)CFArrayCreateMutable(kCFAllocatorDefault, (CFIndex)numItems, NULL);
}

- (void)addObject:(id)anObject {
    CFArrayAppendValue((CFMutableArrayRef)self, (const void *)anObject);
}

- (void)insertObject:(id)anObject atIndex:(NSUInteger)index {
    (void)anObject; (void)index;
    /* TODO: CFArrayInsertValueAtIndex */
}

- (void)removeObjectAtIndex:(NSUInteger)index {
    (void)index;
    /* TODO: CFArrayRemoveValueAtIndex */
}

- (void)removeLastObject {
    NSUInteger c = [self count];
    if (c > 0) [self removeObjectAtIndex:c - 1];
}

- (void)removeAllObjects {
    /* TODO: CFArrayRemoveAllValues */
}

- (void)replaceObjectAtIndex:(NSUInteger)index withObject:(id)anObject {
    (void)index; (void)anObject;
    /* TODO: CFArraySetValueAtIndex */
}

@end

/* ============================================================================
 * Section 11: NSDictionary — Toll-Free Bridged to CFDictionary
 * ============================================================================ */

@interface NSDictionary : NSObject
+ (id)dictionary;
+ (id)dictionaryWithObject:(id)object forKey:(id)key;
+ (id)dictionaryWithObjects:(const id *)objects forKeys:(const id *)keys count:(NSUInteger)cnt;
- (NSUInteger)count;
- (id)objectForKey:(id)aKey;
- (id)allKeys;
- (id)allValues;
- (id)description;
@end

@implementation NSDictionary

+ (id)dictionary {
    return (id)CFDictionaryCreate(kCFAllocatorDefault, NULL, NULL, 0,
                                   &kCFTypeDictionaryKeyCallBacks,
                                   &kCFTypeDictionaryValueCallBacks);
}

+ (id)dictionaryWithObject:(id)object forKey:(id)key {
    const void *keys[1] = { (const void *)key };
    const void *vals[1] = { (const void *)object };
    return (id)CFDictionaryCreate(kCFAllocatorDefault, keys, vals, 1,
                                   &kCFTypeDictionaryKeyCallBacks,
                                   &kCFTypeDictionaryValueCallBacks);
}

+ (id)dictionaryWithObjects:(const id *)objects forKeys:(const id *)keys count:(NSUInteger)cnt {
    return (id)CFDictionaryCreate(kCFAllocatorDefault, (const void **)keys,
                                   (const void **)objects, (CFIndex)cnt,
                                   &kCFTypeDictionaryKeyCallBacks,
                                   &kCFTypeDictionaryValueCallBacks);
}

- (NSUInteger)count {
    return (NSUInteger)CFDictionaryGetCount((CFDictionaryRef)self);
}

- (id)objectForKey:(id)aKey {
    return (id)CFDictionaryGetValue((CFDictionaryRef)self, (const void *)aKey);
}

- (id)allKeys {
    return nil; /* TODO */
}

- (id)allValues {
    return nil; /* TODO */
}

- (id)description {
    return (id)CFSTR("(NSDictionary)");
}

@end

/* ============================================================================
 * Section 12: NSMutableDictionary — Toll-Free Bridged to CFMutableDictionary
 * ============================================================================ */

@interface NSMutableDictionary : NSDictionary
+ (id)dictionary;
+ (id)dictionaryWithCapacity:(NSUInteger)numItems;
- (void)setObject:(id)anObject forKey:(id)aKey;
- (void)removeObjectForKey:(id)aKey;
- (void)removeAllObjects;
@end

@implementation NSMutableDictionary

+ (id)dictionary {
    return (id)CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                                          &kCFTypeDictionaryKeyCallBacks,
                                          &kCFTypeDictionaryValueCallBacks);
}

+ (id)dictionaryWithCapacity:(NSUInteger)numItems {
    return (id)CFDictionaryCreateMutable(kCFAllocatorDefault, (CFIndex)numItems,
                                          &kCFTypeDictionaryKeyCallBacks,
                                          &kCFTypeDictionaryValueCallBacks);
}

- (void)setObject:(id)anObject forKey:(id)aKey {
    CFDictionarySetValue((CFMutableDictionaryRef)self, (const void *)aKey, (const void *)anObject);
}

- (void)removeObjectForKey:(id)aKey {
    CFDictionaryRemoveValue((CFMutableDictionaryRef)self, (const void *)aKey);
}

- (void)removeAllObjects {
    /* TODO: iterate and remove */
}

@end

/* ============================================================================
 * Section 13: NSData
 * ============================================================================ */

@interface NSData : NSObject
+ (id)data;
+ (id)dataWithBytes:(const void *)bytes length:(NSUInteger)length;
- (NSUInteger)length;
- (const void *)bytes;
- (id)description;
@end

@implementation NSData

+ (id)data {
    return (id)CFRetain((CFTypeRef)(id)nil); /* empty data TODO */
}

+ (id)dataWithBytes:(const void *)bytes length:(NSUInteger)length {
    return (id)((void *)CFRetain((CFTypeRef)(id)nil)); /* TODO: CFDataCreate */
}

- (NSUInteger)length {
    return 0; /* TODO: CFDataGetLength */
}

- (const void *)bytes {
    return NULL; /* TODO: CFDataGetBytePtr */
}

- (id)description {
    return (id)CFSTR("(NSData)");
}

@end

/* ============================================================================
 * Section 14: NSRunLoop — Toll-Free Bridged to CFRunLoop
 *
 * NSRunLoop wraps CFRunLoop. [NSRunLoop currentRunLoop] returns
 * the CFRunLoop for the current thread, cast to NSRunLoop.
 * ============================================================================ */

@interface NSRunLoop : NSObject
+ (id)currentRunLoop;
+ (id)mainRunLoop;
- (void)run;
- (void)runUntilDate:(id)limitDate;
- (BOOL)runMode:(id)mode beforeDate:(id)limitDate;
- (id)currentMode;
- (void)performSelector:(SEL)aSelector target:(id)target argument:(id)arg order:(NSUInteger)order modes:(id)modes;
@end

@implementation NSRunLoop

+ (id)currentRunLoop {
    return (id)CFRunLoopGetCurrent();
}

+ (id)mainRunLoop {
    return (id)CFRunLoopGetMain();
}

- (void)run {
    CFRunLoopRun();
}

- (void)runUntilDate:(id)limitDate {
    /* Simplified: run until stopped */
    (void)limitDate;
    CFRunLoopRunInMode(kCFRunLoopDefaultMode, 1.0e10, NO);
}

- (BOOL)runMode:(id)mode beforeDate:(id)limitDate {
    (void)limitDate;
    CFRunLoopMode cfMode = kCFRunLoopDefaultMode;
    if (mode) cfMode = (CFRunLoopMode)mode;
    int32_t result = CFRunLoopRunInMode(cfMode, 1.0e10, YES);
    return result != 1; /* kCFRunLoopRunFinished = 1 */
}

- (id)currentMode {
    return (id)kCFRunLoopDefaultMode;
}

- (void)performSelector:(SEL)aSelector target:(id)target argument:(id)arg
                  order:(NSUInteger)order modes:(id)modes {
    (void)order; (void)modes;
    ((id (*)(id, SEL, id))objc_msgSend)(target, aSelector, arg);
}

@end

/* ============================================================================
 * Section 15: NSAutoreleasePool
 *
 * Wraps objc_autoreleasePoolPush/Pop from libobjc.
 * ============================================================================ */

@interface NSAutoreleasePool : NSObject {
    void *_pool;
}
+ (BOOL)_ARCCompatibleAutoreleasePool;
- (id)init;
- (void)drain;
- (void)dealloc;
@end

@implementation NSAutoreleasePool

/*
 * +_ARCCompatibleAutoreleasePool
 *
 * GNUstep libobjc2 checks for this method in initAutorelease() to decide
 * whether to use its built-in ARC-style autorelease pool.  If this method
 * exists, the runtime sets useARCAutoreleasePool = YES and manages pools
 * internally via arc_tls, avoiding the creation of NSAutoreleasePool
 * instances (which would cause infinite recursion: -init calling
 * objc_autoreleasePoolPush -> [NSAutoreleasePool new] -> -init -> ...).
 */
+ (BOOL)_ARCCompatibleAutoreleasePool {
    return YES;
}

- (id)init {
    self = [super init];
    /* Do NOT call objc_autoreleasePoolPush() here.
     * The runtime's built-in ARC pool handles push/pop.
     * This class exists for compatibility but the runtime
     * bypasses it when +_ARCCompatibleAutoreleasePool returns YES. */
    return self;
}

- (void)drain {
    /* No-op: the runtime manages the pool internally. */
}

- (void)dealloc {
    [super dealloc];
}

@end

/* ============================================================================
 * Section 16: NSNotificationCenter (minimal)
 *
 * Simplified notification center — stores observers in an array and
 * dispatches synchronously. Enough for AppKit's NSApplication.
 * ============================================================================ */

/* NSNotification names used by AppKit */
__attribute__((visibility("default")))
CFStringRef NSApplicationDidFinishLaunchingNotification = NULL;
__attribute__((visibility("default")))
CFStringRef NSApplicationWillTerminateNotification = NULL;
__attribute__((visibility("default")))
CFStringRef NSWindowDidBecomeKeyNotification = NULL;
__attribute__((visibility("default")))
CFStringRef NSWindowDidResignKeyNotification = NULL;

typedef struct __NSObserver {
    id          observer;
    SEL         selector;
    CFStringRef name;
    id          object;
    struct __NSObserver *next;
} __NSObserver;

@interface NSNotificationCenter : NSObject {
    __NSObserver *_observers;
}
+ (id)defaultCenter;
- (void)addObserver:(id)observer selector:(SEL)aSelector name:(id)aName object:(id)anObject;
- (void)removeObserver:(id)observer;
- (void)postNotificationName:(id)aName object:(id)anObject;
- (void)postNotificationName:(id)aName object:(id)anObject userInfo:(id)aUserInfo;
@end

static NSNotificationCenter *__defaultCenter = nil;

@implementation NSNotificationCenter

+ (id)defaultCenter {
    if (!__defaultCenter) {
        __defaultCenter = [[NSNotificationCenter alloc] init];
    }
    return __defaultCenter;
}

- (id)init {
    self = [super init];
    if (self) {
        _observers = NULL;
    }
    return self;
}

- (void)addObserver:(id)observer selector:(SEL)aSelector name:(id)aName object:(id)anObject {
    __NSObserver *obs = (__NSObserver *)malloc(sizeof(__NSObserver));
    if (!obs) return;
    obs->observer = observer;
    obs->selector = aSelector;
    obs->name = aName ? (CFStringRef)CFRetain((CFTypeRef)aName) : NULL;
    obs->object = anObject;
    obs->next = _observers;
    _observers = obs;
}

- (void)removeObserver:(id)observer {
    __NSObserver **pp = &_observers;
    while (*pp) {
        if ((*pp)->observer == observer) {
            __NSObserver *tmp = *pp;
            *pp = tmp->next;
            if (tmp->name) CFRelease((CFTypeRef)tmp->name);
            free(tmp);
        } else {
            pp = &(*pp)->next;
        }
    }
}

- (void)postNotificationName:(id)aName object:(id)anObject {
    [self postNotificationName:aName object:anObject userInfo:nil];
}

- (void)postNotificationName:(id)aName object:(id)anObject userInfo:(id)aUserInfo {
    (void)aUserInfo;
    __NSObserver *obs = _observers;
    while (obs) {
        BOOL nameMatch = (!obs->name && !aName) ||
                          (obs->name && aName && CFStringGetCStringPtr(obs->name, kCFStringEncodingUTF8) &&
                           CFStringGetCStringPtr((CFStringRef)aName, kCFStringEncodingUTF8) &&
                           strcmp(CFStringGetCStringPtr(obs->name, kCFStringEncodingUTF8),
                                  CFStringGetCStringPtr((CFStringRef)aName, kCFStringEncodingUTF8)) == 0);
        BOOL objectMatch = !obs->object || obs->object == anObject;
        if (nameMatch && objectMatch) {
            /* Send the selector with a nil notification for now */
            ((void (*)(id, SEL, id))objc_msgSend)(obs->observer, obs->selector, nil);
        }
        obs = obs->next;
    }
}

@end

/* ============================================================================
 * Section 17: NSLog
 *
 * Standard Foundation logging function.
 * ============================================================================ */

__attribute__((visibility("default")))
void NSLog(id format, ...) {
    if (!format) return;
    const char *s = CFStringGetCStringPtr((CFStringRef)format, kCFStringEncodingUTF8);
    if (s) {
        _fnd_stderr_write(s);
        _fnd_stderr_write("\n");
    }
}

/* ============================================================================
 * Section 18: NSProcessInfo (minimal)
 * ============================================================================ */

@interface NSProcessInfo : NSObject
+ (id)processInfo;
- (id)processName;
- (id)arguments;
- (id)environment;
- (NSUInteger)processorCount;
@end

static NSProcessInfo *__processInfo = nil;

@implementation NSProcessInfo

+ (id)processInfo {
    if (!__processInfo) {
        __processInfo = [[NSProcessInfo alloc] init];
    }
    return __processInfo;
}

- (id)processName {
    return (id)CFSTR("Kiseki");
}

- (id)arguments {
    return [NSArray array];
}

- (id)environment {
    return [NSDictionary dictionary];
}

- (NSUInteger)processorCount {
    return 4; /* Kiseki QEMU config: -smp 4 */
}

@end

/* ============================================================================
 * Section 19: NSThread (minimal)
 * ============================================================================ */

@interface NSThread : NSObject
+ (id)currentThread;
+ (id)mainThread;
+ (BOOL)isMainThread;
+ (void)sleepForTimeInterval:(NSTimeInterval)ti;
@end

extern unsigned int sleep(unsigned int seconds);

@implementation NSThread

+ (id)currentThread {
    return nil; /* simplified */
}

+ (id)mainThread {
    return nil;
}

+ (BOOL)isMainThread {
    return YES; /* simplified — single-threaded GUI for now */
}

+ (void)sleepForTimeInterval:(NSTimeInterval)ti {
    if (ti > 0) sleep((unsigned int)ti);
}

@end

/* ============================================================================
 * Section 20: NSDate (minimal)
 * ============================================================================ */

@interface NSDate : NSObject
+ (id)date;
+ (id)dateWithTimeIntervalSinceNow:(NSTimeInterval)secs;
+ (id)distantFuture;
+ (id)distantPast;
- (NSTimeInterval)timeIntervalSinceNow;
- (NSTimeInterval)timeIntervalSinceReferenceDate;
- (NSTimeInterval)timeIntervalSince1970;
@end

@implementation NSDate

+ (id)date {
    /* Returns current date — just a thin wrapper over CFAbsoluteTimeGetCurrent */
    return [[NSDate alloc] init];
}

+ (id)dateWithTimeIntervalSinceNow:(NSTimeInterval)secs {
    (void)secs;
    return [NSDate date];
}

+ (id)distantFuture {
    return [NSDate date]; /* simplified */
}

+ (id)distantPast {
    return [NSDate date]; /* simplified */
}

- (NSTimeInterval)timeIntervalSinceNow {
    return 0.0;
}

- (NSTimeInterval)timeIntervalSinceReferenceDate {
    return CFAbsoluteTimeGetCurrent();
}

- (NSTimeInterval)timeIntervalSince1970 {
    return CFAbsoluteTimeGetCurrent() + 978307200.0; /* CF epoch offset */
}

@end

/* ============================================================================
 * Section 21: NSBundle (minimal)
 * ============================================================================ */

@interface NSBundle : NSObject
+ (id)mainBundle;
- (id)bundlePath;
- (id)bundleIdentifier;
- (id)infoDictionary;
- (id)objectForInfoDictionaryKey:(id)key;
@end

static NSBundle *__mainBundle = nil;

@implementation NSBundle

+ (id)mainBundle {
    if (!__mainBundle) {
        __mainBundle = [[NSBundle alloc] init];
    }
    return __mainBundle;
}

- (id)bundlePath {
    return (id)CFSTR("/");
}

- (id)bundleIdentifier {
    return (id)CFSTR("uk.co.avltree9798.kiseki");
}

- (id)infoDictionary {
    return [NSDictionary dictionary];
}

- (id)objectForInfoDictionaryKey:(id)key {
    (void)key;
    return nil;
}

@end

/* ============================================================================
 * Section 22: NSTimer — Toll-Free Bridged to CFRunLoopTimer
 * ============================================================================ */

@interface NSTimer : NSObject
+ (id)scheduledTimerWithTimeInterval:(NSTimeInterval)ti
                              target:(id)aTarget
                            selector:(SEL)aSelector
                            userInfo:(id)userInfo
                             repeats:(BOOL)yesOrNo;
+ (id)timerWithTimeInterval:(NSTimeInterval)ti
                     target:(id)aTarget
                   selector:(SEL)aSelector
                   userInfo:(id)userInfo
                    repeats:(BOOL)yesOrNo;
- (void)invalidate;
- (BOOL)isValid;
- (void)fire;
- (id)userInfo;
- (NSTimeInterval)timeInterval;
@end

@implementation NSTimer

+ (id)scheduledTimerWithTimeInterval:(NSTimeInterval)ti
                              target:(id)aTarget
                            selector:(SEL)aSelector
                            userInfo:(id)userInfo
                             repeats:(BOOL)yesOrNo
{
    (void)ti; (void)aTarget; (void)aSelector; (void)userInfo; (void)yesOrNo;
    /* TODO: create CFRunLoopTimer and add to current run loop */
    return nil;
}

+ (id)timerWithTimeInterval:(NSTimeInterval)ti
                     target:(id)aTarget
                   selector:(SEL)aSelector
                   userInfo:(id)userInfo
                    repeats:(BOOL)yesOrNo
{
    (void)ti; (void)aTarget; (void)aSelector; (void)userInfo; (void)yesOrNo;
    return nil;
}

- (void)invalidate { }
- (BOOL)isValid { return NO; }
- (void)fire { }
- (id)userInfo { return nil; }
- (NSTimeInterval)timeInterval { return 0.0; }

@end

/* ============================================================================
 * Section 23: Framework Initialisation
 * ============================================================================ */

/*
 * __FoundationBridgeISALookup — Toll-free bridging callback.
 *
 * Called by CoreFoundation's _CFRuntimeCreateInstance to set the ObjC
 * isa pointer on newly created CF objects.  Without this, CFString etc.
 * have isa == NULL and any ObjC message send to them crashes.
 */
/*
 * Cached class pointers for toll-free bridging.
 * Resolved lazily via objc_getClass() (a C function, no ObjC messages).
 * We retry on each call until resolved because the ObjC runtime may not
 * have loaded Foundation's classes yet during early constructor execution.
 */
static Class __bridge_NSString     = NULL;
static Class __bridge_NSArray      = NULL;
static Class __bridge_NSDictionary = NULL;
static Class __bridge_NSNumber     = NULL;
static Class __bridge_NSData       = NULL;
static Class __bridge_NSDate       = NULL;

static void __FoundationResolveBridgeClasses(void) {
    if (!__bridge_NSString)     __bridge_NSString     = objc_getClass("NSString");
    if (!__bridge_NSArray)      __bridge_NSArray      = objc_getClass("NSArray");
    if (!__bridge_NSDictionary) __bridge_NSDictionary = objc_getClass("NSDictionary");
    if (!__bridge_NSNumber)     __bridge_NSNumber     = objc_getClass("NSNumber");
    if (!__bridge_NSData)       __bridge_NSData       = objc_getClass("NSData");
    if (!__bridge_NSDate)       __bridge_NSDate       = objc_getClass("NSDate");
}

static uintptr_t __FoundationBridgeISALookup(CFTypeID typeID) {
    /* Resolve classes on every call until all are found.
     * During early construction objc_getClass may return NULL;
     * we simply return 0 (no isa) for those objects and they
     * will work fine as long as they are only used via C APIs
     * (which is true for CFSTR constants). */
    __FoundationResolveBridgeClasses();
    if (typeID == CFStringGetTypeID())     return (uintptr_t)__bridge_NSString;
    if (typeID == CFArrayGetTypeID())      return (uintptr_t)__bridge_NSArray;
    if (typeID == CFDictionaryGetTypeID()) return (uintptr_t)__bridge_NSDictionary;
    if (typeID == CFNumberGetTypeID())     return (uintptr_t)__bridge_NSNumber;
    if (typeID == CFDataGetTypeID())       return (uintptr_t)__bridge_NSData;
    if (typeID == CFDateGetTypeID())       return (uintptr_t)__bridge_NSDate;
    return 0;
}

static BOOL __foundation_inited = NO;

/*
 * _FoundationEnsureInitialized — Called lazily to finish Foundation setup.
 *
 * We split initialization: the bridge ISA lookup is registered in the
 * constructor (safe — just sets a function pointer), but the notification
 * name constants are created later (they call CFSTR which triggers the
 * ISA lookup, which needs objc_getClass to work, which requires all
 * ObjC classes to be loaded).
 *
 * Called from [NSApplication sharedApplication] — by that point all
 * images are loaded and ObjC classes are registered.
 */
__attribute__((visibility("default")))
void _FoundationEnsureInitialized(void) {
    if (__foundation_inited) return;
    __foundation_inited = YES;
    NSApplicationDidFinishLaunchingNotification = CFSTR("NSApplicationDidFinishLaunchingNotification");
    NSApplicationWillTerminateNotification = CFSTR("NSApplicationWillTerminateNotification");
    NSWindowDidBecomeKeyNotification = CFSTR("NSWindowDidBecomeKeyNotification");
    NSWindowDidResignKeyNotification = CFSTR("NSWindowDidResignKeyNotification");
}

__attribute__((constructor, used))
static void __FoundationInitialize(void) {
    /* Register toll-free bridging ISA lookup so CF objects get ObjC isa pointers.
     * This just sets a function pointer — safe during early construction. */
    _CFRuntimeBridgeSetISALookup(__FoundationBridgeISALookup);
}

/* ============================================================================
 * End of Foundation.framework
 * ============================================================================ */
