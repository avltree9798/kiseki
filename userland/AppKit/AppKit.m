/*
 * Kiseki OS - AppKit.framework
 *
 * Objective-C application framework providing the GUI toolkit for Kiseki.
 * Connects to WindowServer via Mach IPC (matching macOS CGSConnection)
 * and provides NSApplication, NSWindow, NSView, NSEvent, NSMenu, NSColor,
 * NSFont, NSGraphicsContext, NSTextField, NSButton.
 *
 * Architecture (matching macOS):
 *   NSApplication  → main event loop, WindowServer connection
 *   NSWindow       → wraps WS_MSG_CREATE_WINDOW / WS_MSG_DESTROY_WINDOW
 *   NSView         → drawing hierarchy, drawRect: dispatches to CGContext
 *   NSEvent        → wraps WS_EVENT_* from WindowServer
 *   NSGraphicsContext → wraps CGBitmapContext for window backing store
 *   NSColor        → wraps CGColor
 *   NSFont         → wraps CTFont
 *   NSMenu/NSMenuItem → wraps WS_MSG_SET_MENU
 *
 * Compiled with COMDAT-stripping pipeline:
 *   clang -fobjc-runtime=gnustep-1.9 -S -emit-llvm → sed → llc
 *
 * Reference: macOS AppKit headers, GNUstep GUI
 */

/* ============================================================================
 * Section 1: Visibility & Compiler Helpers
 * ============================================================================ */

#define EXPORT  __attribute__((visibility("default")))
#define HIDDEN  __attribute__((visibility("hidden")))

typedef _Bool BOOL;
#define YES ((BOOL)1)
#define NO  ((BOOL)0)
#define nil ((id)0)
#define NULL ((void *)0)

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
typedef uint16_t            UniChar;
typedef double              CGFloat;
typedef signed long         NSInteger;
typedef unsigned long       NSUInteger;
typedef double              NSTimeInterval;

/* CoreGraphics geometry — must match CoreGraphics.c layout */
struct CGPoint { CGFloat x; CGFloat y; };
typedef struct CGPoint CGPoint;

struct CGSize { CGFloat width; CGFloat height; };
typedef struct CGSize CGSize;

struct CGRect { CGPoint origin; CGSize size; };
typedef struct CGRect CGRect;

struct CGAffineTransform {
    CGFloat a, b, c, d;
    CGFloat tx, ty;
};
typedef struct CGAffineTransform CGAffineTransform;

static inline CGPoint CGPointMake(CGFloat x, CGFloat y) {
    CGPoint p = { x, y };
    return p;
}

static inline CGSize CGSizeMake(CGFloat w, CGFloat h) {
    CGSize s = { w, h };
    return s;
}

static inline CGRect CGRectMake(CGFloat x, CGFloat y, CGFloat w, CGFloat h) {
    CGRect r = { { x, y }, { w, h } };
    return r;
}

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
 * Section 3: ObjC Runtime Declarations
 * ============================================================================ */

typedef struct objc_class    *Class;
typedef struct objc_object   *id;
typedef struct objc_selector *SEL;
typedef id (*IMP)(id, SEL, ...);

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
 * Section 4: Imported Functions — libSystem.B.dylib
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

/*
 * IMPORTANT: Do NOT use fprintf(stderr, ...) from AppKit!
 *
 * AppKit is compiled with macOS SDK headers (for ObjC runtime), but links
 * against Kiseki's libSystem at runtime.  The __stderrp indirection produces
 * a FILE* with bit 36 set (0x00000013000540e0 instead of 0x00000003000540e0),
 * and fprintf writing through that corrupted pointer trashes heap memory
 * (specifically the ObjC runtime's reference_list->lock mutexes, causing
 * Bug 21 deadlock in objc_sync_enter).
 *
 * Instead we redirect all fprintf(stderr,...) to snprintf + raw write(2,...).
 */
static int _appkit_fprintf_stderr(const char *fmt, ...) __attribute__((format(printf,1,2)));
static int _appkit_fprintf_stderr(const char *fmt, ...) {
    char _buf[256];
    __builtin_va_list ap;
    __builtin_va_start(ap, fmt);
    extern int vsnprintf(char *, size_t, const char *, __builtin_va_list);
    int n = vsnprintf(_buf, sizeof(_buf), fmt, ap);
    __builtin_va_end(ap);
    if (n > 0) {
        size_t len = (size_t)n;
        if (len > sizeof(_buf) - 1) len = sizeof(_buf) - 1;
        /* direct syscall write to fd 2 */
        long r;
        __asm__ volatile(
            "mov x0, #2\n"
            "mov x1, %1\n"
            "mov x2, %2\n"
            "mov x16, #4\n"
            "svc #0x80\n"
            "mov %0, x0"
            : "=r"(r) : "r"(_buf), "r"(len) : "x0","x1","x2","x16","memory");
    }
    return n;
}

/* Shadow fprintf: all calls to fprintf(stderr, ...) become safe */
#define fprintf(stream, ...) _appkit_fprintf_stderr(__VA_ARGS__)

/* Mach IPC primitives */
typedef unsigned int mach_port_t;
typedef unsigned int mach_port_name_t;
typedef unsigned int mach_msg_bits_t;
typedef unsigned int mach_msg_size_t;
typedef int          mach_msg_id_t;
typedef unsigned int mach_msg_timeout_t;
typedef int          mach_msg_option_t;
typedef int          mach_msg_return_t;
typedef int          kern_return_t;
typedef unsigned int mach_msg_type_name_t;
typedef unsigned int mach_msg_copy_options_t;
typedef unsigned int mach_msg_descriptor_type_t;

#define MACH_PORT_NULL          ((mach_port_t)0)
#define MACH_PORT_RIGHT_RECEIVE 1
#define MACH_MSG_SUCCESS        0x00000000
#define MACH_SEND_MSG           0x00000001
#define MACH_RCV_MSG            0x00000002
#define MACH_SEND_TIMEOUT       0x00000010
#define MACH_RCV_TIMEOUT        0x00000100
#define MACH_RCV_TIMED_OUT      0x10004003
#define MACH_MSG_TIMEOUT_NONE   ((mach_msg_timeout_t)0)
#define MACH_MSGH_BITS_COMPLEX  0x80000000u
#define MACH_MSG_OOL_DESCRIPTOR 1
#define MACH_MSG_VIRTUAL_COPY   1

#define MACH_MSG_TYPE_MOVE_SEND      17
#define MACH_MSG_TYPE_COPY_SEND      19
#define MACH_MSG_TYPE_MAKE_SEND      20
#define MACH_MSG_TYPE_MAKE_SEND_ONCE 21

#define MACH_MSGH_BITS(remote, local) \
    ((mach_msg_bits_t)((remote) | ((local) << 8)))

typedef struct {
    mach_msg_bits_t     msgh_bits;
    mach_msg_size_t     msgh_size;
    mach_port_t         msgh_remote_port;
    mach_port_t         msgh_local_port;
    mach_port_name_t    msgh_voucher_port;
    mach_msg_id_t       msgh_id;
} mach_msg_header_t;

typedef struct {
    mach_msg_size_t     msgh_descriptor_count;
} mach_msg_body_t;

/*
 * Mach IPC descriptor structs must use #pragma pack(4) to match the
 * macOS/XNU ABI. Without this, the compiler inserts 4 bytes of padding
 * after mach_msg_body_t (4 bytes) to align the void* address field to
 * 8 bytes, making sizeof(ws_msg_draw_rect_t) = 80 instead of 72.
 * XNU's mach/message.h uses #pragma pack(push, 4) for all descriptor
 * types. See osfmk/mach/message.h.
 */
#pragma pack(push, 4)

typedef struct {
    void                    *address;
    unsigned int            deallocate : 8;
    mach_msg_copy_options_t copy : 8;
    unsigned int            pad1 : 8;
    mach_msg_descriptor_type_t type : 8;
    mach_msg_size_t         size;
} mach_msg_ool_descriptor_t;

#pragma pack(pop)

extern mach_msg_return_t mach_msg(
    mach_msg_header_t   *msg,
    mach_msg_option_t   option,
    mach_msg_size_t     send_size,
    mach_msg_size_t     rcv_size,
    mach_port_name_t    rcv_name,
    mach_msg_timeout_t  timeout,
    mach_port_name_t    notify);

extern uint32_t mach_task_self(void);
extern uint32_t mach_task_self_;
extern int mach_port_allocate(unsigned int task, unsigned int right, void *name);
extern int bootstrap_look_up(unsigned int bp, const void *service_name, void *sp);

/* ============================================================================
 * Section 5: Imported Functions — CoreFoundation
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
typedef const void   *CFAttributedStringRef;
typedef const void   *CFRunLoopRef;
typedef const void   *CFRunLoopSourceRef;
typedef CFStringRef   CFRunLoopMode;

extern const CFAllocatorRef kCFAllocatorDefault;
extern const CFRunLoopMode  kCFRunLoopDefaultMode;

extern CFTypeRef   CFRetain(CFTypeRef cf);
extern void        CFRelease(CFTypeRef cf);
extern CFTypeID    CFGetTypeID(CFTypeRef cf);

extern CFStringRef CFStringCreateWithCString(CFAllocatorRef alloc, const char *cStr, UInt32 encoding);
extern const char *CFStringGetCStringPtr(CFStringRef theString, UInt32 encoding);
extern CFIndex     CFStringGetLength(CFStringRef theString);
extern CFStringRef __CFStringMakeConstantString(const char *cStr);
#define CFSTR(s) __CFStringMakeConstantString(s)

#define kCFStringEncodingUTF8   ((UInt32)0x08000100)
#define kCFStringEncodingASCII  ((UInt32)0x0600)

extern CFArrayRef        CFArrayCreate(CFAllocatorRef alloc, const void **values, CFIndex numValues, const void *callBacks);
extern CFIndex           CFArrayGetCount(CFArrayRef theArray);
extern const void       *CFArrayGetValueAtIndex(CFArrayRef theArray, CFIndex idx);
extern CFMutableArrayRef CFArrayCreateMutable(CFAllocatorRef alloc, CFIndex capacity, const void *callBacks);
extern void              CFArrayAppendValue(CFMutableArrayRef theArray, const void *value);

extern CFDictionaryRef         CFDictionaryCreate(CFAllocatorRef alloc, const void **keys, const void **values,
                                                   CFIndex numValues, const void *keyCallBacks, const void *valueCallBacks);
extern const void             *CFDictionaryGetValue(CFDictionaryRef theDict, const void *key);
extern CFMutableDictionaryRef  CFDictionaryCreateMutable(CFAllocatorRef alloc, CFIndex capacity,
                                                          const void *keyCallBacks, const void *valueCallBacks);
extern void                    CFDictionarySetValue(CFMutableDictionaryRef theDict, const void *key, const void *value);

extern CFRunLoopRef CFRunLoopGetCurrent(void);
extern CFRunLoopRef CFRunLoopGetMain(void);
extern void         CFRunLoopRun(void);
extern int32_t      CFRunLoopRunInMode(CFRunLoopMode mode, CFTimeInterval seconds, BOOL returnAfterSourceHandled);
extern void         CFRunLoopStop(CFRunLoopRef rl);
extern void         CFRunLoopWakeUp(CFRunLoopRef rl);

extern CFAbsoluteTime CFAbsoluteTimeGetCurrent(void);

extern void NSLog(id format, ...);

/* ============================================================================
 * Section 6: Imported Functions — CoreGraphics
 * ============================================================================ */

typedef struct CGContext *CGContextRef;
typedef struct CGColor  *CGColorRef;
typedef struct CGColorSpace *CGColorSpaceRef;
typedef struct CGImage  *CGImageRef;
typedef const struct CGPath *CGPathRef;
typedef struct CGPath   *CGMutablePathRef;

typedef uint32_t CGBitmapInfo;
typedef int32_t  CGBlendMode;
typedef int32_t  CGLineCap;
typedef int32_t  CGLineJoin;

/* Bitmap info constants */
#define kCGImageAlphaPremultipliedFirst  2
#define kCGBitmapByteOrder32Little       0x2000

extern CGColorSpaceRef CGColorSpaceCreateDeviceRGB(void);
extern void            CGColorSpaceRelease(CGColorSpaceRef space);

extern CGColorRef CGColorCreateGenericRGB(CGFloat red, CGFloat green, CGFloat blue, CGFloat alpha);
extern CGColorRef CGColorCreateSRGB(CGFloat red, CGFloat green, CGFloat blue, CGFloat alpha);
extern CGColorRef CGColorRetain(CGColorRef color);
extern void       CGColorRelease(CGColorRef color);
extern const CGFloat *CGColorGetComponents(CGColorRef color);
extern CGFloat    CGColorGetAlpha(CGColorRef color);

extern CGContextRef CGBitmapContextCreate(
    void *data, size_t width, size_t height,
    size_t bitsPerComponent, size_t bytesPerRow,
    CGColorSpaceRef space, uint32_t bitmapInfo);
extern void       *CGBitmapContextGetData(CGContextRef c);
extern size_t      CGBitmapContextGetWidth(CGContextRef c);
extern size_t      CGBitmapContextGetHeight(CGContextRef c);
extern size_t      CGBitmapContextGetBytesPerRow(CGContextRef c);
extern CGImageRef  CGBitmapContextCreateImage(CGContextRef c);

extern CGContextRef CGContextRetain(CGContextRef c);
extern void         CGContextRelease(CGContextRef c);
extern void         CGContextSaveGState(CGContextRef c);
extern void         CGContextRestoreGState(CGContextRef c);

extern void CGContextSetRGBFillColor(CGContextRef c, CGFloat r, CGFloat g, CGFloat b, CGFloat a);
extern void CGContextSetRGBStrokeColor(CGContextRef c, CGFloat r, CGFloat g, CGFloat b, CGFloat a);
extern void CGContextSetFillColorWithColor(CGContextRef c, CGColorRef color);
extern void CGContextSetStrokeColorWithColor(CGContextRef c, CGColorRef color);
extern void CGContextSetAlpha(CGContextRef c, CGFloat alpha);
extern void CGContextSetLineWidth(CGContextRef c, CGFloat width);

extern void CGContextFillRect(CGContextRef c, CGRect rect);
extern void CGContextStrokeRect(CGContextRef c, CGRect rect);
extern void CGContextClearRect(CGContextRef c, CGRect rect);

extern void CGContextBeginPath(CGContextRef c);
extern void CGContextMoveToPoint(CGContextRef c, CGFloat x, CGFloat y);
extern void CGContextAddLineToPoint(CGContextRef c, CGFloat x, CGFloat y);
extern void CGContextAddRect(CGContextRef c, CGRect rect);
extern void CGContextClosePath(CGContextRef c);
extern void CGContextFillPath(CGContextRef c);
extern void CGContextStrokePath(CGContextRef c);

extern void CGContextSetTextPosition(CGContextRef c, CGFloat x, CGFloat y);
extern CGPoint CGContextGetTextPosition(CGContextRef c);
extern void CGContextShowTextAtPoint(CGContextRef c, CGFloat x, CGFloat y, const char *string, size_t length);

extern void CGContextDrawImage(CGContextRef c, CGRect rect, CGImageRef image);
extern void CGImageRelease(CGImageRef image);

extern void CGContextClipToRect(CGContextRef c, CGRect rect);
extern void CGContextFlush(CGContextRef c);

/* ============================================================================
 * Section 7: Imported Functions — CoreText
 * ============================================================================ */

typedef const void *CTFontRef;
typedef const void *CTLineRef;

extern CTFontRef CTFontCreateWithName(CFStringRef name, CGFloat size, const CGAffineTransform *matrix);
extern CGFloat   CTFontGetSize(CTFontRef font);
extern CGFloat   CTFontGetAscent(CTFontRef font);
extern CGFloat   CTFontGetDescent(CTFontRef font);
extern CGFloat   CTFontGetLeading(CTFontRef font);
extern void      CTFontRelease(CTFontRef font);

extern CTLineRef CTLineCreateWithAttributedString(CFAttributedStringRef attrString);
extern void      CTLineDraw(CTLineRef line, CGContextRef context);
extern double    CTLineGetTypographicBounds(CTLineRef line, CGFloat *ascent, CGFloat *descent, CGFloat *leading);
extern void      CTLineRelease(CTLineRef line);

extern CFAttributedStringRef CFAttributedStringCreate(CFAllocatorRef alloc, CFStringRef str, CFDictionaryRef attributes);

/* ============================================================================
 * Section 8: WindowServer IPC Protocol Constants
 *
 * These must match WindowServer.c exactly.
 * ============================================================================ */

#define WS_SERVICE_NAME             "uk.co.avltree9798.WindowServer"

/* Request message IDs (client → WindowServer) */
#define WS_MSG_CONNECT              1000
#define WS_MSG_DISCONNECT           1001
#define WS_MSG_CREATE_WINDOW        1010
#define WS_MSG_DESTROY_WINDOW       1011
#define WS_MSG_ORDER_WINDOW         1012
#define WS_MSG_SET_TITLE            1013
#define WS_MSG_SET_FRAME            1014
#define WS_MSG_DRAW_RECT            1020
#define WS_MSG_SET_MENU             1030

/* Reply message IDs (WindowServer → client) */
#define WS_REPLY_CONNECT            2000
#define WS_REPLY_CREATE_WINDOW      2010
#define WS_REPLY_GENERIC            2099

/* Event message IDs (WindowServer → client, async) */
#define WS_EVENT_KEY_DOWN           3000
#define WS_EVENT_KEY_UP             3001
#define WS_EVENT_MOUSE_DOWN         3010
#define WS_EVENT_MOUSE_UP           3011
#define WS_EVENT_MOUSE_MOVED        3012
#define WS_EVENT_MOUSE_DRAGGED      3013
#define WS_EVENT_WINDOW_ACTIVATE    3020
#define WS_EVENT_WINDOW_DEACTIVATE  3021
#define WS_EVENT_WINDOW_CLOSE       3022
#define WS_EVENT_WINDOW_RESIZE      3023

/* Window ordering */
#define WS_ORDER_OUT                0
#define WS_ORDER_FRONT              1
#define WS_ORDER_BACK               2

/* Menu limits */
#define WS_MAX_MENU_ITEMS           16
#define WS_MENU_TITLE_MAX           32

/* ============================================================================
 * Section 9: WindowServer IPC Message Structures
 *
 * Must match WindowServer.c layout exactly.
 * ============================================================================ */

typedef struct {
    mach_msg_header_t   header;
    char                app_name[64];
    int32_t             pid;
} ws_msg_connect_t;

typedef struct {
    mach_msg_header_t   header;
    int32_t             conn_id;
    kern_return_t       result;
} ws_reply_connect_t;

typedef struct {
    mach_msg_header_t   header;
    int32_t             conn_id;
    int32_t             x, y;
    uint32_t            width, height;
    uint32_t            style_mask;
    char                title[64];
} ws_msg_create_window_t;

typedef struct {
    mach_msg_header_t   header;
    int32_t             window_id;
    kern_return_t       result;
} ws_reply_create_window_t;

typedef struct {
    mach_msg_header_t   header;
    int32_t             conn_id;
    int32_t             window_id;
} ws_msg_destroy_window_t;

typedef struct {
    mach_msg_header_t   header;
    int32_t             conn_id;
    int32_t             window_id;
    int32_t             order;
} ws_msg_order_window_t;

typedef struct {
    mach_msg_header_t   header;
    int32_t             conn_id;
    int32_t             window_id;
    char                title[64];
} ws_msg_set_title_t;

typedef struct {
    mach_msg_header_t   header;
    int32_t             conn_id;
    int32_t             window_id;
    int32_t             x, y;
    uint32_t            width, height;
} ws_msg_set_frame_t;

#pragma pack(push, 4)
typedef struct {
    mach_msg_header_t           header;
    mach_msg_body_t             body;
    mach_msg_ool_descriptor_t   surface_desc;
    int32_t                     conn_id;
    int32_t                     window_id;
    uint32_t                    dst_x, dst_y;
    uint32_t                    width, height;
    uint32_t                    src_rowbytes;
} ws_msg_draw_rect_t;
#pragma pack(pop)

typedef struct {
    mach_msg_header_t   header;
    int32_t             conn_id;
    uint32_t            item_count;
    struct {
        char            title[WS_MENU_TITLE_MAX];
        int32_t         tag;
        int32_t         enabled;
    } items[WS_MAX_MENU_ITEMS];
} ws_msg_set_menu_t;

typedef struct {
    mach_msg_header_t   header;
    kern_return_t       result;
} ws_reply_generic_t;

/* Event messages (WindowServer → client) */
typedef struct {
    mach_msg_header_t   header;
    int32_t             window_id;
    uint32_t            keycode;
    uint32_t            characters;
    uint32_t            modifiers;
    uint16_t            is_repeat;
    uint16_t            _pad;
} ws_event_key_t;

typedef struct {
    mach_msg_header_t   header;
    int32_t             window_id;
    int32_t             x, y;
    int32_t             screen_x, screen_y;
    uint32_t            button;
    uint32_t            modifiers;
    uint32_t            click_count;
} ws_event_mouse_t;

typedef struct {
    mach_msg_header_t   header;
    int32_t             window_id;
} ws_event_window_t;

typedef struct {
    mach_msg_header_t   header;
    int32_t             window_id;
    uint32_t            new_width;
    uint32_t            new_height;
} ws_event_resize_t;

/* Receive buffer */
typedef union {
    mach_msg_header_t   header;
    uint8_t             _pad[4096 + 256];
} ws_msg_buffer_t;

/* ============================================================================
 * Section 10: Forward Declarations
 * ============================================================================ */

@class NSApplication;
@class NSWindow;
@class NSView;
@class NSEvent;
@class NSColor;
@class NSFont;
@class NSMenu;
@class NSMenuItem;
@class NSGraphicsContext;
@class NSResponder;
@class NSControl;
@class NSTextField;
@class NSButton;
@class NSCell;

/*
 * NSObject root class declaration.
 *
 * AppKit is compiled freestanding (no #include), so we need to declare
 * NSObject here. The actual implementation lives in Foundation.framework;
 * at link time, the class is resolved by the ObjC runtime when both
 * frameworks are loaded into the same process.
 */
__attribute__((objc_root_class))
@interface NSObject {
    Class isa;
}
+ (id)alloc;
+ (id)new;
- (id)init;
- (void)dealloc;
- (id)retain;
- (void)release;
- (id)autorelease;
- (NSUInteger)retainCount;
- (Class)class;
- (Class)superclass;
- (BOOL)isKindOfClass:(Class)aClass;
- (BOOL)respondsToSelector:(SEL)aSelector;
- (NSUInteger)hash;
- (BOOL)isEqual:(id)object;
@end

/* Global shared application instance (matching macOS NSApp) */
EXPORT id NSApp = nil;

/* Notification name constants — defined and initialised by Foundation.
 * AppKit merely references them via extern. */
extern CFStringRef NSApplicationDidFinishLaunchingNotification;
extern CFStringRef NSApplicationWillTerminateNotification;
extern CFStringRef NSWindowDidBecomeKeyNotification;
extern CFStringRef NSWindowDidResignKeyNotification;

/* Deferred Foundation initialisation (safe to call after class loading) */
extern void _FoundationEnsureInitialized(void);

/* ============================================================================
 * Section 11: NSGraphicsContext
 *
 * Wraps CGContextRef, providing the current drawing context for NSView's
 * drawRect: method. On macOS, NSGraphicsContext manages a stack of
 * contexts on a per-thread basis. We simplify to a single-thread model.
 *
 * Reference: macOS NSGraphicsContext.h
 * ============================================================================ */

static NSGraphicsContext *__currentGraphicsContext = nil;

@interface NSGraphicsContext : NSObject {
@public
    CGContextRef _cgContext;
    BOOL         _flipped;
}
+ (id)graphicsContextWithCGContext:(CGContextRef)cgContext flipped:(BOOL)flipped;
+ (id)currentContext;
+ (void)setCurrentContext:(id)context;
+ (void)saveGraphicsState;
+ (void)restoreGraphicsState;
- (CGContextRef)CGContext;
- (BOOL)isFlipped;
- (void)flushGraphics;
@end

@implementation NSGraphicsContext

+ (id)graphicsContextWithCGContext:(CGContextRef)cgContext flipped:(BOOL)flipped {
    NSGraphicsContext *ctx = [[NSGraphicsContext alloc] init];
    if (ctx) {
        ctx->_cgContext = CGContextRetain(cgContext);
        ctx->_flipped = flipped;
    }
    return ctx;
}

+ (id)currentContext {
    return __currentGraphicsContext;
}

+ (void)setCurrentContext:(id)context {
    __currentGraphicsContext = (NSGraphicsContext *)context;
}

+ (void)saveGraphicsState {
    if (__currentGraphicsContext && __currentGraphicsContext->_cgContext) {
        CGContextSaveGState(__currentGraphicsContext->_cgContext);
    }
}

+ (void)restoreGraphicsState {
    if (__currentGraphicsContext && __currentGraphicsContext->_cgContext) {
        CGContextRestoreGState(__currentGraphicsContext->_cgContext);
    }
}

- (CGContextRef)CGContext {
    return _cgContext;
}

- (BOOL)isFlipped {
    return _flipped;
}

- (void)flushGraphics {
    if (_cgContext) {
        CGContextFlush(_cgContext);
    }
}

- (void)dealloc {
    if (_cgContext) {
        CGContextRelease(_cgContext);
        _cgContext = NULL;
    }
    struct objc_super sup = { self, objc_getClass("NSObject") };
    objc_msgSendSuper2(&sup, sel_registerName("dealloc"));
}

@end

/* ============================================================================
 * Section 12: NSColor
 *
 * Wraps CGColor. Provides named colour constructors matching macOS API.
 * Colours are stored as RGBA CGFloat components.
 *
 * Reference: macOS NSColor.h
 * ============================================================================ */

@interface NSColor : NSObject {
@public
    CGFloat _red;
    CGFloat _green;
    CGFloat _blue;
    CGFloat _alpha;
}
+ (id)colorWithCalibratedRed:(CGFloat)red green:(CGFloat)green blue:(CGFloat)blue alpha:(CGFloat)alpha;
+ (id)colorWithSRGBRed:(CGFloat)red green:(CGFloat)green blue:(CGFloat)blue alpha:(CGFloat)alpha;
+ (id)blackColor;
+ (id)whiteColor;
+ (id)redColor;
+ (id)greenColor;
+ (id)blueColor;
+ (id)grayColor;
+ (id)lightGrayColor;
+ (id)darkGrayColor;
+ (id)clearColor;
+ (id)yellowColor;
+ (id)cyanColor;
+ (id)magentaColor;
+ (id)orangeColor;
+ (id)windowBackgroundColor;
+ (id)controlBackgroundColor;
+ (id)textColor;
+ (id)textBackgroundColor;
+ (id)selectedTextColor;
+ (id)selectedTextBackgroundColor;
+ (id)controlColor;
+ (id)labelColor;
+ (id)secondaryLabelColor;
+ (id)separatorColor;
- (CGFloat)redComponent;
- (CGFloat)greenComponent;
- (CGFloat)blueComponent;
- (CGFloat)alphaComponent;
- (void)set;
- (void)setFill;
- (void)setStroke;
- (CGColorRef)CGColor;
@end

@implementation NSColor

+ (id)colorWithCalibratedRed:(CGFloat)red green:(CGFloat)green blue:(CGFloat)blue alpha:(CGFloat)alpha {
    NSColor *c = [[NSColor alloc] init];
    if (c) {
        c->_red = red;
        c->_green = green;
        c->_blue = blue;
        c->_alpha = alpha;
    }
    return c;
}

+ (id)colorWithSRGBRed:(CGFloat)red green:(CGFloat)green blue:(CGFloat)blue alpha:(CGFloat)alpha {
    return [NSColor colorWithCalibratedRed:red green:green blue:blue alpha:alpha];
}

+ (id)blackColor    { return [NSColor colorWithCalibratedRed:0.0 green:0.0 blue:0.0 alpha:1.0]; }
+ (id)whiteColor    { return [NSColor colorWithCalibratedRed:1.0 green:1.0 blue:1.0 alpha:1.0]; }
+ (id)redColor      { return [NSColor colorWithCalibratedRed:1.0 green:0.0 blue:0.0 alpha:1.0]; }
+ (id)greenColor    { return [NSColor colorWithCalibratedRed:0.0 green:1.0 blue:0.0 alpha:1.0]; }
+ (id)blueColor     { return [NSColor colorWithCalibratedRed:0.0 green:0.0 blue:1.0 alpha:1.0]; }
+ (id)grayColor     { return [NSColor colorWithCalibratedRed:0.5 green:0.5 blue:0.5 alpha:1.0]; }
+ (id)lightGrayColor{ return [NSColor colorWithCalibratedRed:0.75 green:0.75 blue:0.75 alpha:1.0]; }
+ (id)darkGrayColor { return [NSColor colorWithCalibratedRed:0.33 green:0.33 blue:0.33 alpha:1.0]; }
+ (id)clearColor    { return [NSColor colorWithCalibratedRed:0.0 green:0.0 blue:0.0 alpha:0.0]; }
+ (id)yellowColor   { return [NSColor colorWithCalibratedRed:1.0 green:1.0 blue:0.0 alpha:1.0]; }
+ (id)cyanColor     { return [NSColor colorWithCalibratedRed:0.0 green:1.0 blue:1.0 alpha:1.0]; }
+ (id)magentaColor  { return [NSColor colorWithCalibratedRed:1.0 green:0.0 blue:1.0 alpha:1.0]; }
+ (id)orangeColor   { return [NSColor colorWithCalibratedRed:1.0 green:0.5 blue:0.0 alpha:1.0]; }

/* System colours — matching macOS Aqua theme (approximate) */
+ (id)windowBackgroundColor   { return [NSColor colorWithCalibratedRed:0.93 green:0.93 blue:0.93 alpha:1.0]; }
+ (id)controlBackgroundColor  { return [NSColor colorWithCalibratedRed:1.0 green:1.0 blue:1.0 alpha:1.0]; }
+ (id)textColor               { return [NSColor colorWithCalibratedRed:0.0 green:0.0 blue:0.0 alpha:1.0]; }
+ (id)textBackgroundColor     { return [NSColor colorWithCalibratedRed:1.0 green:1.0 blue:1.0 alpha:1.0]; }
+ (id)selectedTextColor       { return [NSColor colorWithCalibratedRed:1.0 green:1.0 blue:1.0 alpha:1.0]; }
+ (id)selectedTextBackgroundColor { return [NSColor colorWithCalibratedRed:0.25 green:0.5 blue:0.9 alpha:1.0]; }
+ (id)controlColor            { return [NSColor colorWithCalibratedRed:1.0 green:1.0 blue:1.0 alpha:1.0]; }
+ (id)labelColor              { return [NSColor colorWithCalibratedRed:0.0 green:0.0 blue:0.0 alpha:1.0]; }
+ (id)secondaryLabelColor     { return [NSColor colorWithCalibratedRed:0.5 green:0.5 blue:0.5 alpha:1.0]; }
+ (id)separatorColor          { return [NSColor colorWithCalibratedRed:0.8 green:0.8 blue:0.8 alpha:1.0]; }

- (CGFloat)redComponent   { return _red; }
- (CGFloat)greenComponent { return _green; }
- (CGFloat)blueComponent  { return _blue; }
- (CGFloat)alphaComponent { return _alpha; }

- (void)set {
    [self setFill];
    [self setStroke];
}

- (void)setFill {
    NSGraphicsContext *ctx = [NSGraphicsContext currentContext];
    if (ctx) {
        CGContextSetRGBFillColor([ctx CGContext], _red, _green, _blue, _alpha);
    }
}

- (void)setStroke {
    NSGraphicsContext *ctx = [NSGraphicsContext currentContext];
    if (ctx) {
        CGContextSetRGBStrokeColor([ctx CGContext], _red, _green, _blue, _alpha);
    }
}

- (CGColorRef)CGColor {
    return CGColorCreateGenericRGB(_red, _green, _blue, _alpha);
}

@end

/* ============================================================================
 * Section 13: NSFont
 *
 * Wraps CTFont from CoreText. Since we only have the embedded 8×16 bitmap
 * font, all font creation resolves to the same underlying CTFont with
 * varying logical size (though rendering uses fixed 8×16 glyphs).
 *
 * Reference: macOS NSFont.h
 * ============================================================================ */

@interface NSFont : NSObject {
@public
    CTFontRef   _ctFont;
    CGFloat     _pointSize;
    char        _name[64];
}
+ (id)fontWithName:(id)fontName size:(CGFloat)fontSize;
+ (id)systemFontOfSize:(CGFloat)fontSize;
+ (id)boldSystemFontOfSize:(CGFloat)fontSize;
+ (id)monospacedSystemFontOfSize:(CGFloat)fontSize weight:(CGFloat)weight;
+ (id)userFixedPitchFontOfSize:(CGFloat)fontSize;
+ (id)labelFontOfSize:(CGFloat)fontSize;
+ (id)menuFontOfSize:(CGFloat)fontSize;
+ (CGFloat)systemFontSize;
+ (CGFloat)smallSystemFontSize;
+ (CGFloat)labelFontSize;
- (id)fontName;
- (CGFloat)pointSize;
- (CGFloat)ascender;
- (CGFloat)descender;
- (CGFloat)leading;
- (CTFontRef)CTFont;
@end

@implementation NSFont

+ (id)fontWithName:(id)fontName size:(CGFloat)fontSize {
    NSFont *f = [[NSFont alloc] init];
    if (f) {
        if (fontSize <= 0.0) fontSize = 13.0;
        f->_pointSize = fontSize;
        /* All fonts resolve to the embedded bitmap font */
        f->_ctFont = CTFontCreateWithName(CFSTR("System"), fontSize, NULL);
        /* Store name */
        const char *cname = fontName ? CFStringGetCStringPtr((CFStringRef)fontName, kCFStringEncodingUTF8) : "System";
        if (!cname) cname = "System";
        size_t len = strlen(cname);
        if (len > 63) len = 63;
        memcpy(f->_name, cname, len);
        f->_name[len] = '\0';
    }
    return f;
}

+ (id)systemFontOfSize:(CGFloat)fontSize {
    return [NSFont fontWithName:(id)CFSTR("System") size:fontSize];
}

+ (id)boldSystemFontOfSize:(CGFloat)fontSize {
    return [NSFont fontWithName:(id)CFSTR("System Bold") size:fontSize];
}

+ (id)monospacedSystemFontOfSize:(CGFloat)fontSize weight:(CGFloat)weight {
    (void)weight;
    return [NSFont fontWithName:(id)CFSTR("Menlo") size:fontSize];
}

+ (id)userFixedPitchFontOfSize:(CGFloat)fontSize {
    return [NSFont fontWithName:(id)CFSTR("Menlo") size:fontSize];
}

+ (id)labelFontOfSize:(CGFloat)fontSize {
    return [NSFont systemFontOfSize:fontSize];
}

+ (id)menuFontOfSize:(CGFloat)fontSize {
    return [NSFont systemFontOfSize:fontSize];
}

+ (CGFloat)systemFontSize      { return 13.0; }
+ (CGFloat)smallSystemFontSize { return 11.0; }
+ (CGFloat)labelFontSize       { return 10.0; }

- (id)fontName {
    return (id)CFStringCreateWithCString(kCFAllocatorDefault, _name, kCFStringEncodingUTF8);
}

- (CGFloat)pointSize { return _pointSize; }

- (CGFloat)ascender {
    return _ctFont ? CTFontGetAscent(_ctFont) : 12.0;
}

- (CGFloat)descender {
    return _ctFont ? -CTFontGetDescent(_ctFont) : -3.0;
}

- (CGFloat)leading {
    return _ctFont ? CTFontGetLeading(_ctFont) : 1.0;
}

- (CTFontRef)CTFont {
    return _ctFont;
}

- (void)dealloc {
    if (_ctFont) {
        CTFontRelease(_ctFont);
        _ctFont = NULL;
    }
    struct objc_super sup = { self, objc_getClass("NSObject") };
    objc_msgSendSuper2(&sup, sel_registerName("dealloc"));
}

@end

/* ============================================================================
 * Section 14: NSEvent
 *
 * Wraps WindowServer events (WS_EVENT_*). Each NSEvent carries:
 *   - type (NSEventType enum matching macOS)
 *   - window reference
 *   - location in window coordinates
 *   - modifier flags
 *   - key/mouse specifics
 *
 * On macOS, NSEvent is created internally by AppKit's event loop when
 * CGEvents arrive from the WindowServer. We do the same, but from
 * Mach IPC messages instead of CGEventTap.
 *
 * Reference: macOS NSEvent.h
 * ============================================================================ */

/* NSEventType — matching macOS values */
typedef enum {
    NSEventTypeLeftMouseDown      = 1,
    NSEventTypeLeftMouseUp        = 2,
    NSEventTypeRightMouseDown     = 3,
    NSEventTypeRightMouseUp       = 4,
    NSEventTypeMouseMoved         = 5,
    NSEventTypeLeftMouseDragged   = 6,
    NSEventTypeRightMouseDragged  = 7,
    NSEventTypeMouseEntered       = 8,
    NSEventTypeMouseExited        = 9,
    NSEventTypeKeyDown            = 10,
    NSEventTypeKeyUp              = 11,
    NSEventTypeFlagsChanged       = 12,
    NSEventTypeScrollWheel        = 22,
    NSEventTypeOtherMouseDown     = 25,
    NSEventTypeOtherMouseUp       = 26,
    NSEventTypeOtherMouseDragged  = 27,
} NSEventType;

/* NSEventModifierFlags — matching macOS */
typedef enum {
    NSEventModifierFlagCapsLock   = 1 << 16,
    NSEventModifierFlagShift      = 1 << 17,
    NSEventModifierFlagControl    = 1 << 18,
    NSEventModifierFlagOption     = 1 << 19,
    NSEventModifierFlagCommand    = 1 << 20,
} NSEventModifierFlags;

/* Window style mask — matching macOS NSWindow.StyleMask */
typedef enum {
    NSWindowStyleMaskBorderless             = 0,
    NSWindowStyleMaskTitled                 = 1 << 0,
    NSWindowStyleMaskClosable               = 1 << 1,
    NSWindowStyleMaskMiniaturizable         = 1 << 2,
    NSWindowStyleMaskResizable              = 1 << 3,
    NSWindowStyleMaskFullScreen             = 1 << 14,
} NSWindowStyleMask;

/* NSBackingStoreType */
typedef enum {
    NSBackingStoreRetained    = 0,
    NSBackingStoreNonretained = 1,
    NSBackingStoreBuffered    = 2,
} NSBackingStoreType;

@interface NSEvent : NSObject {
@public
    NSEventType          _type;
    NSUInteger           _modifierFlags;
    NSTimeInterval       _timestamp;
    int32_t              _windowNumber;
    CGPoint              _locationInWindow;
    /* Key event fields */
    uint32_t             _keyCode;
    uint32_t             _characters;   /* ASCII char or 0 */
    BOOL                 _isARepeat;
    /* Mouse event fields */
    uint32_t             _buttonNumber;
    NSInteger            _clickCount;
    CGPoint              _screenLocation;
}
+ (id)_eventWithType:(NSEventType)type
              window:(int32_t)windowNumber
            location:(CGPoint)location
       modifierFlags:(NSUInteger)flags
           timestamp:(NSTimeInterval)timestamp;
- (NSEventType)type;
- (NSUInteger)modifierFlags;
- (NSTimeInterval)timestamp;
- (int32_t)windowNumber;
- (CGPoint)locationInWindow;
- (uint16_t)keyCode;
- (id)characters;
- (id)charactersIgnoringModifiers;
- (BOOL)isARepeat;
- (NSInteger)buttonNumber;
- (NSInteger)clickCount;
@end

@implementation NSEvent

+ (id)_eventWithType:(NSEventType)type
              window:(int32_t)windowNumber
            location:(CGPoint)location
       modifierFlags:(NSUInteger)flags
           timestamp:(NSTimeInterval)timestamp
{
    /* Reuse a single cached event to avoid per-event heap alloc (Bug 28 fix).
     * Safe because events are consumed synchronously before the next one is created. */
    static NSEvent *__cachedEvent = nil;
    if (!__cachedEvent) {
        __cachedEvent = [[NSEvent alloc] init];
    }
    NSEvent *e = __cachedEvent;
    if (e) {
        e->_type = type;
        e->_windowNumber = windowNumber;
        e->_locationInWindow = location;
        e->_modifierFlags = flags;
        e->_timestamp = timestamp;
        e->_keyCode = 0;
        e->_characters = 0;
        e->_isARepeat = NO;
        e->_buttonNumber = 0;
        e->_clickCount = 0;
        e->_screenLocation = CGPointMake(0.0, 0.0);
    }
    return e;
}

- (NSEventType)type           { return _type; }
- (NSUInteger)modifierFlags   { return _modifierFlags; }
- (NSTimeInterval)timestamp   { return _timestamp; }
- (int32_t)windowNumber       { return _windowNumber; }
- (CGPoint)locationInWindow   { return _locationInWindow; }
- (uint16_t)keyCode           { return (uint16_t)_keyCode; }

- (id)characters {
    if (_characters == 0) return (id)CFSTR("");
    char buf[2] = { (char)_characters, '\0' };
    return (id)CFStringCreateWithCString(kCFAllocatorDefault, buf, kCFStringEncodingUTF8);
}

- (id)charactersIgnoringModifiers {
    return [self characters];
}

- (BOOL)isARepeat       { return _isARepeat; }
- (NSInteger)buttonNumber { return (NSInteger)_buttonNumber; }
- (NSInteger)clickCount   { return _clickCount; }

@end

/* Helper: convert WS HID modifier flags → NSEventModifierFlags */
static NSUInteger _ws_modifiers_to_ns(uint32_t ws_mods) {
    NSUInteger flags = 0;
    if (ws_mods & (1 << 0)) flags |= NSEventModifierFlagShift;
    if (ws_mods & (1 << 1)) flags |= NSEventModifierFlagControl;
    if (ws_mods & (1 << 2)) flags |= NSEventModifierFlagOption;
    if (ws_mods & (1 << 3)) flags |= NSEventModifierFlagCapsLock;
    return flags;
}

/* Helper: create NSEvent from a WindowServer key event message */
static NSEvent *_NSEventFromWSKeyEvent(ws_event_key_t *msg, NSEventType type) {
    CGPoint loc = CGPointMake(0.0, 0.0);
    NSEvent *e = [NSEvent _eventWithType:type
                                  window:msg->window_id
                                location:loc
                           modifierFlags:_ws_modifiers_to_ns(msg->modifiers)
                               timestamp:CFAbsoluteTimeGetCurrent()];
    if (e) {
        e->_keyCode = msg->keycode;
        e->_characters = msg->characters;
        e->_isARepeat = msg->is_repeat ? YES : NO;
    }
    return e;
}

/* Helper: create NSEvent from a WindowServer mouse event message */
static NSEvent *_NSEventFromWSMouseEvent(ws_event_mouse_t *msg, NSEventType type) {
    CGPoint loc = CGPointMake((CGFloat)msg->x, (CGFloat)msg->y);
    NSEvent *e = [NSEvent _eventWithType:type
                                  window:msg->window_id
                                location:loc
                           modifierFlags:_ws_modifiers_to_ns(msg->modifiers)
                               timestamp:CFAbsoluteTimeGetCurrent()];
    if (e) {
        e->_buttonNumber = msg->button;
        e->_clickCount = (NSInteger)msg->click_count;
        e->_screenLocation = CGPointMake((CGFloat)msg->screen_x, (CGFloat)msg->screen_y);
    }
    return e;
}

/* ============================================================================
 * Section 15: WindowServer IPC Client (_CGSConnection equivalent)
 *
 * This is the C-level connection to WindowServer. On macOS, this is
 * CGSConnection (private SPI in SkyLight/CoreGraphics). AppKit's
 * NSApplication calls _CGSDefaultConnection() to get a connection ID.
 *
 * Our equivalent:
 *   _
 *   _
 *   _
 * ============================================================================ */

/* Global connection state — one per process (like CGSDefaultConnection) */
static struct {
    mach_port_t     service_port;   /* WindowServer's service port */
    mach_port_t     event_port;     /* Our port for receiving events */
    int32_t         conn_id;        /* Connection ID assigned by WS */
    BOOL            connected;
} _ws_conn = { MACH_PORT_NULL, MACH_PORT_NULL, -1, NO };

/*
 * _WSConnect — Establish connection to WindowServer.
 *
 * 1. bootstrap_look_up(WS_SERVICE_NAME) to find service port
 * 2. mach_port_allocate() to create our event receive port
 * 3. Send WS_MSG_CONNECT with our event port as reply port
 * 4. Receive WS_REPLY_CONNECT with conn_id
 */
static BOOL _WSConnect(const char *app_name) {
    if (_ws_conn.connected) return YES;

    /* Look up WindowServer service */
    kern_return_t kr = bootstrap_look_up(
        MACH_PORT_NULL, WS_SERVICE_NAME, &_ws_conn.service_port);
    if (kr != 0) {
        fprintf(stderr, "[AppKit] bootstrap_look_up(%s) failed: %d\n",
                WS_SERVICE_NAME, kr);
        return NO;
    }
    /* Allocate our event port (receive right) */
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
                            &_ws_conn.event_port);
    if (kr != 0) {
        fprintf(stderr, "[AppKit] mach_port_allocate failed: %d\n", kr);
        return NO;
    }
    /* Send CONNECT request */
    ws_msg_connect_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND,
                                            MACH_MSG_TYPE_MAKE_SEND);
    msg.header.msgh_size = sizeof(msg);
    msg.header.msgh_remote_port = _ws_conn.service_port;
    msg.header.msgh_local_port = _ws_conn.event_port;
    msg.header.msgh_id = WS_MSG_CONNECT;
    msg.pid = 0; /* TODO: getpid() */
    if (app_name) {
        size_t len = strlen(app_name);
        if (len > 63) len = 63;
        memcpy(msg.app_name, app_name, len);
        msg.app_name[len] = '\0';
    }

    kr = mach_msg(&msg.header, MACH_SEND_MSG | MACH_RCV_MSG,
                  sizeof(msg), sizeof(ws_reply_connect_t),
                  _ws_conn.event_port, MACH_MSG_TIMEOUT_NONE,
                  MACH_PORT_NULL);
    if (kr != MACH_MSG_SUCCESS) {
        fprintf(stderr, "[AppKit] WS_MSG_CONNECT mach_msg failed: %d\n", kr);
        return NO;
    }

    /* Parse reply */
    ws_reply_connect_t *reply = (ws_reply_connect_t *)&msg;
    if (reply->result != 0 || reply->conn_id < 0) {
        fprintf(stderr, "[AppKit] WS_MSG_CONNECT rejected: result=%d conn_id=%d\n",
                reply->result, reply->conn_id);
        return NO;
    }

    _ws_conn.conn_id = reply->conn_id;
    _ws_conn.connected = YES;
    return YES;
}

/*
 * _WSDisconnect — Disconnect from WindowServer.
 */
static void _WSDisconnect(void) {
    if (!_ws_conn.connected) return;

    ws_msg_destroy_window_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    msg.header.msgh_size = sizeof(mach_msg_header_t) + sizeof(int32_t);
    msg.header.msgh_remote_port = _ws_conn.service_port;
    msg.header.msgh_id = WS_MSG_DISCONNECT;
    msg.conn_id = _ws_conn.conn_id;

    mach_msg(&msg.header, MACH_SEND_MSG, msg.header.msgh_size, 0,
             MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);

    _ws_conn.connected = NO;
    _ws_conn.conn_id = -1;
}

/*
 * _WSCreateWindow — Create a window on WindowServer.
 * Returns window_id or -1 on error.
 */
static int32_t _WSCreateWindow(int32_t x, int32_t y, uint32_t width,
                                uint32_t height, uint32_t style_mask,
                                const char *title) {
    if (!_ws_conn.connected) {
        fprintf(stderr, "[AppKit] _WSCreateWindow: NOT CONNECTED, returning -1\n");
        return -1;
    }

    /* We need a buffer large enough for the reply too */
    union {
        ws_msg_create_window_t  req;
        ws_reply_create_window_t reply;
    } buf;
    memset(&buf, 0, sizeof(buf));

    buf.req.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND,
                                                MACH_MSG_TYPE_MAKE_SEND);
    buf.req.header.msgh_size = sizeof(ws_msg_create_window_t);
    buf.req.header.msgh_remote_port = _ws_conn.service_port;
    buf.req.header.msgh_local_port = _ws_conn.event_port;
    buf.req.header.msgh_id = WS_MSG_CREATE_WINDOW;
    buf.req.conn_id = _ws_conn.conn_id;
    buf.req.x = x;
    buf.req.y = y;
    buf.req.width = width;
    buf.req.height = height;
    buf.req.style_mask = style_mask;
    if (title) {
        size_t len = strlen(title);
        if (len > 63) len = 63;
        memcpy(buf.req.title, title, len);
        buf.req.title[len] = '\0';
    }

    /* First call: SEND the request AND RCV the first reply/event */
    kern_return_t kr = mach_msg(&buf.req.header, MACH_SEND_MSG | MACH_RCV_MSG,
                                sizeof(ws_msg_create_window_t),
                                sizeof(buf),
                                _ws_conn.event_port, MACH_MSG_TIMEOUT_NONE,
                                MACH_PORT_NULL);
    if (kr != MACH_MSG_SUCCESS)
        return -1;

    /* Loop: if we received an event instead of the reply, discard and re-receive */
    for (int attempts = 0; attempts < 32; attempts++) {
        if (buf.reply.header.msgh_id == WS_REPLY_CREATE_WINDOW)
            break; /* got the reply we want */
        /* Receive again (RCV only, no SEND) */
        kr = mach_msg(&buf.reply.header, MACH_RCV_MSG,
                       0, sizeof(buf),
                       _ws_conn.event_port, MACH_MSG_TIMEOUT_NONE,
                       MACH_PORT_NULL);
        if (kr != MACH_MSG_SUCCESS)
            return -1;
    }

    if (buf.reply.header.msgh_id != WS_REPLY_CREATE_WINDOW)
        return -1;
    if (buf.reply.result != 0 || buf.reply.window_id < 0)
        return -1;

    return buf.reply.window_id;
}

/*
 * _WSDestroyWindow — Destroy a window.
 */
static void _WSDestroyWindow(int32_t window_id) {
    if (!_ws_conn.connected) return;

    ws_msg_destroy_window_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    msg.header.msgh_size = sizeof(msg);
    msg.header.msgh_remote_port = _ws_conn.service_port;
    msg.header.msgh_id = WS_MSG_DESTROY_WINDOW;
    msg.conn_id = _ws_conn.conn_id;
    msg.window_id = window_id;

    mach_msg(&msg.header, MACH_SEND_MSG, sizeof(msg), 0,
             MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
}

/*
 * _WSOrderWindow — Order (show/hide/front) a window.
 */
static void _WSOrderWindow(int32_t window_id, int32_t order) {
    if (!_ws_conn.connected) return;

    ws_msg_order_window_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    msg.header.msgh_size = sizeof(msg);
    msg.header.msgh_remote_port = _ws_conn.service_port;
    msg.header.msgh_id = WS_MSG_ORDER_WINDOW;
    msg.conn_id = _ws_conn.conn_id;
    msg.window_id = window_id;
    msg.order = order;

    mach_msg(&msg.header, MACH_SEND_MSG, sizeof(msg), 0,
             MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
}

/*
 * _WSSetTitle — Set window title.
 */
static void _WSSetTitle(int32_t window_id, const char *title) {
    if (!_ws_conn.connected) return;

    ws_msg_set_title_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    msg.header.msgh_size = sizeof(msg);
    msg.header.msgh_remote_port = _ws_conn.service_port;
    msg.header.msgh_id = WS_MSG_SET_TITLE;
    msg.conn_id = _ws_conn.conn_id;
    msg.window_id = window_id;
    if (title) {
        size_t len = strlen(title);
        if (len > 63) len = 63;
        memcpy(msg.title, title, len);
        msg.title[len] = '\0';
    }

    mach_msg(&msg.header, MACH_SEND_MSG, sizeof(msg), 0,
             MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
}

/*
 * _WSSetFrame — Move/resize a window.
 */
static void _WSSetFrame(int32_t window_id, int32_t x, int32_t y,
                         uint32_t width, uint32_t height) {
    if (!_ws_conn.connected) return;

    ws_msg_set_frame_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    msg.header.msgh_size = sizeof(msg);
    msg.header.msgh_remote_port = _ws_conn.service_port;
    msg.header.msgh_id = WS_MSG_SET_FRAME;
    msg.conn_id = _ws_conn.conn_id;
    msg.window_id = window_id;
    msg.x = x;
    msg.y = y;
    msg.width = width;
    msg.height = height;

    mach_msg(&msg.header, MACH_SEND_MSG, sizeof(msg), 0,
             MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
}

/*
 * _WSDrawRect — Blit pixel data to a window via OOL Mach message.
 *
 * This sends the backing store pixel data to WindowServer using
 * MACH_MSG_OOL_DESCRIPTOR for zero-copy transfer.
 */
static void _WSDrawRect(int32_t window_id, uint32_t dst_x, uint32_t dst_y,
                         uint32_t width, uint32_t height,
                         const void *pixels, uint32_t rowbytes) {
    if (!_ws_conn.connected || !pixels) return;

    ws_msg_draw_rect_t msg;
    memset(&msg, 0, sizeof(msg));

    msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0)
                           | MACH_MSGH_BITS_COMPLEX;
    msg.header.msgh_size = sizeof(msg);
    msg.header.msgh_remote_port = _ws_conn.service_port;
    msg.header.msgh_id = WS_MSG_DRAW_RECT;

    msg.body.msgh_descriptor_count = 1;

    msg.surface_desc.address = (void *)pixels;
    msg.surface_desc.size = rowbytes * height;
    msg.surface_desc.deallocate = 0;
    msg.surface_desc.copy = MACH_MSG_VIRTUAL_COPY;
    msg.surface_desc.type = MACH_MSG_OOL_DESCRIPTOR;

    msg.conn_id = _ws_conn.conn_id;
    msg.window_id = window_id;
    msg.dst_x = dst_x;
    msg.dst_y = dst_y;
    msg.width = width;
    msg.height = height;
    msg.src_rowbytes = rowbytes;

    mach_msg_return_t kr = mach_msg(&msg.header, MACH_SEND_MSG, sizeof(msg), 0,
             MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != MACH_MSG_SUCCESS) {
        static int draw_fail_count = 0;
        draw_fail_count++;
        if (draw_fail_count <= 3)
            fprintf(stderr, "[AppKit] _WSDrawRect: mach_msg SEND FAILED: kr=%d (wid=%d %ux%u)\n",
                    kr, window_id, width, height);
    }
}

/*
 * _WSSetMenu — Set application menu bar items.
 */
static void _WSSetMenu(const char *titles[], int32_t tags[], int count) {
    if (!_ws_conn.connected || count <= 0) return;
    if (count > WS_MAX_MENU_ITEMS) count = WS_MAX_MENU_ITEMS;

    ws_msg_set_menu_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    msg.header.msgh_size = sizeof(msg);
    msg.header.msgh_remote_port = _ws_conn.service_port;
    msg.header.msgh_id = WS_MSG_SET_MENU;
    msg.conn_id = _ws_conn.conn_id;
    msg.item_count = (uint32_t)count;

    for (int i = 0; i < count; i++) {
        if (titles[i]) {
            size_t len = strlen(titles[i]);
            if (len > WS_MENU_TITLE_MAX - 1) len = WS_MENU_TITLE_MAX - 1;
            memcpy(msg.items[i].title, titles[i], len);
            msg.items[i].title[len] = '\0';
        }
        msg.items[i].tag = tags ? tags[i] : i;
        msg.items[i].enabled = 1;
    }

    mach_msg(&msg.header, MACH_SEND_MSG, sizeof(msg), 0,
             MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
}

/*
 * _WSPollEvent — Non-blocking poll for an event from WindowServer.
 * Returns YES if an event was received, NO if timed out.
 */
static BOOL _WSPollEvent(ws_msg_buffer_t *buf, mach_msg_timeout_t timeout_ms) {
    if (!_ws_conn.connected) return NO;

    memset(buf, 0, sizeof(*buf));
    mach_msg_return_t kr = mach_msg(
        &buf->header,
        MACH_RCV_MSG | MACH_RCV_TIMEOUT,
        0,
        sizeof(*buf),
        _ws_conn.event_port,
        timeout_ms,
        MACH_PORT_NULL);

    if (kr == MACH_MSG_SUCCESS) return YES;
    return NO; /* MACH_RCV_TIMED_OUT or other error */
}

/* ============================================================================
 * Section 16: NSResponder
 *
 * Abstract base class for the responder chain. NSView, NSWindow, and
 * NSApplication all inherit from NSResponder. Events propagate up the
 * chain: view → superview → ... → window → application.
 *
 * Reference: macOS NSResponder.h
 * ============================================================================ */

@interface NSResponder : NSObject {
@public
    id _nextResponder;
}
- (id)nextResponder;
- (void)setNextResponder:(id)responder;
- (void)keyDown:(id)event;
- (void)keyUp:(id)event;
- (void)mouseDown:(id)event;
- (void)mouseUp:(id)event;
- (void)mouseMoved:(id)event;
- (void)mouseDragged:(id)event;
- (void)rightMouseDown:(id)event;
- (void)rightMouseUp:(id)event;
- (BOOL)acceptsFirstResponder;
- (BOOL)becomeFirstResponder;
- (BOOL)resignFirstResponder;
@end

@implementation NSResponder

- (id)nextResponder           { return _nextResponder; }
- (void)setNextResponder:(id)r { _nextResponder = r; }

- (void)keyDown:(id)event {
    if (_nextResponder)
        ((void (*)(id, SEL, id))objc_msgSend)(_nextResponder, sel_registerName("keyDown:"), event);
}

- (void)keyUp:(id)event {
    if (_nextResponder)
        ((void (*)(id, SEL, id))objc_msgSend)(_nextResponder, sel_registerName("keyUp:"), event);
}

- (void)mouseDown:(id)event {
    if (_nextResponder)
        ((void (*)(id, SEL, id))objc_msgSend)(_nextResponder, sel_registerName("mouseDown:"), event);
}

- (void)mouseUp:(id)event {
    if (_nextResponder)
        ((void (*)(id, SEL, id))objc_msgSend)(_nextResponder, sel_registerName("mouseUp:"), event);
}

- (void)mouseMoved:(id)event {
    if (_nextResponder)
        ((void (*)(id, SEL, id))objc_msgSend)(_nextResponder, sel_registerName("mouseMoved:"), event);
}

- (void)mouseDragged:(id)event {
    if (_nextResponder)
        ((void (*)(id, SEL, id))objc_msgSend)(_nextResponder, sel_registerName("mouseDragged:"), event);
}

- (void)rightMouseDown:(id)event {
    if (_nextResponder)
        ((void (*)(id, SEL, id))objc_msgSend)(_nextResponder, sel_registerName("rightMouseDown:"), event);
}

- (void)rightMouseUp:(id)event {
    if (_nextResponder)
        ((void (*)(id, SEL, id))objc_msgSend)(_nextResponder, sel_registerName("rightMouseUp:"), event);
}

- (BOOL)acceptsFirstResponder { return NO; }
- (BOOL)becomeFirstResponder  { return YES; }
- (BOOL)resignFirstResponder  { return YES; }

@end

/* ============================================================================
 * Section 17: NSView
 *
 * The base class for all visual elements. Each NSView has:
 *   - A frame (position/size in superview coordinates)
 *   - A bounds (internal coordinate system)
 *   - An array of subviews
 *   - A reference to its window
 *
 * Drawing: NSWindow calls displayIfNeeded → setNeedsDisplay: propagates
 * through the view tree. The window's backing CGContext is set as the
 * current NSGraphicsContext before drawRect: is called.
 *
 * Reference: macOS NSView.h
 * ============================================================================ */

#define NS_MAX_SUBVIEWS 32

@interface NSView : NSResponder {
@public
    CGRect      _frame;
    CGRect      _bounds;
    id          _window;        /* weak — NSWindow* */
    id          _superview;     /* weak — NSView* */
    id          _subviews[NS_MAX_SUBVIEWS];
    int         _subviewCount;
    BOOL        _needsDisplay;
    BOOL        _hidden;
    BOOL        _autoresizesSubviews;
    id          _backgroundColor;  /* NSColor* */
}
- (id)initWithFrame:(CGRect)frameRect;
- (CGRect)frame;
- (void)setFrame:(CGRect)frame;
- (CGRect)bounds;
- (void)setBounds:(CGRect)bounds;
- (id)window;
- (id)superview;
- (id)subviews;
- (void)addSubview:(id)view;
- (void)removeFromSuperview;
- (void)setNeedsDisplay:(BOOL)flag;
- (BOOL)needsDisplay;
- (void)display;
- (void)drawRect:(CGRect)dirtyRect;
- (BOOL)isFlipped;
- (BOOL)isHidden;
- (void)setHidden:(BOOL)flag;
- (id)hitTest:(CGPoint)point;
- (BOOL)mouse:(CGPoint)point inRect:(CGRect)rect;
- (void)setBackgroundColor:(id)color;
- (id)backgroundColor;
@end

@implementation NSView

- (id)initWithFrame:(CGRect)frameRect {
    self = [super init];
    if (self) {
        _frame = frameRect;
        _bounds = CGRectMake(0, 0, frameRect.size.width, frameRect.size.height);
        _window = nil;
        _superview = nil;
        _subviewCount = 0;
        _needsDisplay = YES;
        _hidden = NO;
        _autoresizesSubviews = YES;
        _backgroundColor = nil;
        memset(_subviews, 0, sizeof(_subviews));
    }
    return self;
}

- (CGRect)frame   { return _frame; }

- (void)setFrame:(CGRect)frame {
    _frame = frame;
    _bounds = CGRectMake(0, 0, frame.size.width, frame.size.height);
    [self setNeedsDisplay:YES];
}

- (CGRect)bounds  { return _bounds; }
- (void)setBounds:(CGRect)bounds { _bounds = bounds; }

- (id)window      { return _window; }
- (id)superview   { return _superview; }

- (id)subviews {
    /* Return a simple array — apps typically just iterate */
    return nil; /* simplified; real macOS returns NSArray */
}

- (void)addSubview:(id)view {
    if (!view || _subviewCount >= NS_MAX_SUBVIEWS) return;
    NSView *v = (NSView *)view;

    /* Remove from old superview first */
    if (v->_superview) {
        [v removeFromSuperview];
    }

    _subviews[_subviewCount++] = view;
    v->_superview = self;
    v->_window = _window;

    /* Propagate window reference to all sub-subviews */
    for (int i = 0; i < v->_subviewCount; i++) {
        ((NSView *)v->_subviews[i])->_window = _window;
    }

    [self setNeedsDisplay:YES];
}

- (void)removeFromSuperview {
    if (!_superview) return;
    NSView *sv = (NSView *)_superview;
    for (int i = 0; i < sv->_subviewCount; i++) {
        if (sv->_subviews[i] == self) {
            /* Shift remaining subviews down */
            for (int j = i; j < sv->_subviewCount - 1; j++) {
                sv->_subviews[j] = sv->_subviews[j + 1];
            }
            sv->_subviews[sv->_subviewCount - 1] = nil;
            sv->_subviewCount--;
            break;
        }
    }
    _superview = nil;
    _window = nil;
}

- (void)setNeedsDisplay:(BOOL)flag {
    _needsDisplay = flag;
    /* Propagate up to window for display coalescing */
}

- (BOOL)needsDisplay { return _needsDisplay; }

- (void)display {
    if (_hidden) return;

    /* Get current graphics context */
    NSGraphicsContext *gctx = [NSGraphicsContext currentContext];
    if (!gctx) return;
    CGContextRef ctx = [gctx CGContext];
    if (!ctx) return;

    /* Save state, translate to our frame origin */
    CGContextSaveGState(ctx);

    /* Clip to our frame within the superview coordinate system */
    if (_superview) {
        CGContextClipToRect(ctx, _frame);
    }

    /* Draw background if set */
    if (_backgroundColor) {
        NSColor *bg = (NSColor *)_backgroundColor;
        CGContextSetRGBFillColor(ctx, bg->_red, bg->_green, bg->_blue, bg->_alpha);
        CGContextFillRect(ctx, _frame);
    }

    /* Call drawRect: with bounds */
    [self drawRect:_bounds];
    _needsDisplay = NO;

    /* Draw subviews (back to front) */
    for (int i = 0; i < _subviewCount; i++) {
        NSView *sv = (NSView *)_subviews[i];
        if (sv && ![sv isHidden]) {
            [sv display];
        }
    }

    CGContextRestoreGState(ctx);
}

- (void)drawRect:(CGRect)dirtyRect {
    /* Subclasses override this to draw custom content */
    (void)dirtyRect;
}

- (BOOL)isFlipped { return YES; } /* Kiseki uses flipped coordinates (top-left origin) */
- (BOOL)isHidden  { return _hidden; }
- (void)setHidden:(BOOL)flag { _hidden = flag; }

- (id)hitTest:(CGPoint)point {
    if (_hidden) return nil;
    if (![self mouse:point inRect:_frame]) return nil;

    /* Check subviews in reverse (front to back) */
    for (int i = _subviewCount - 1; i >= 0; i--) {
        NSView *sv = (NSView *)_subviews[i];
        /* Convert point to subview coordinates */
        CGPoint subPoint = CGPointMake(point.x - _frame.origin.x,
                                        point.y - _frame.origin.y);
        id hit = [sv hitTest:subPoint];
        if (hit) return hit;
    }
    return self;
}

- (BOOL)mouse:(CGPoint)point inRect:(CGRect)rect {
    return (point.x >= rect.origin.x &&
            point.x < rect.origin.x + rect.size.width &&
            point.y >= rect.origin.y &&
            point.y < rect.origin.y + rect.size.height);
}

- (void)setBackgroundColor:(id)color { _backgroundColor = color; }
- (id)backgroundColor { return _backgroundColor; }

@end

/* ============================================================================
 * Section 18: NSWindow
 *
 * Each NSWindow owns a WindowServer window (via _WSCreateWindow), a
 * backing store CGBitmapContext, and a content view hierarchy.
 *
 * Display cycle (matching macOS
 *   1. Something calls setNeedsDisplay: on a view
 *   2. NSWindow.displayIfNeeded creates NSGraphicsContext from backing store
 *   3. Content view tree draws into the backing CGContext
 *   4. NSWindow calls _WSDrawRect to blit pixels to WindowServer
 *
 * Reference: macOS NSWindow.h
 * ============================================================================ */

/* Global window tracking — NSApplication iterates these */
#define NS_MAX_WINDOWS 16
static NSWindow *__allWindows[NS_MAX_WINDOWS];
static int       __windowCount = 0;

@interface NSWindow : NSResponder {
@public
    int32_t         _windowNumber;      /* WindowServer window ID */
    CGRect          _frame;             /* Screen coordinates */
    uint32_t        _styleMask;
    NSBackingStoreType _backingType;
    id              _title;             /* NSString* */
    id              _contentView;       /* NSView* */
    id              _firstResponder;    /* id */
    id              _delegate;          /* id<NSWindowDelegate> */
    BOOL            _isVisible;
    BOOL            _isKeyWindow;
    BOOL            _isMainWindow;

    /* Backing store */
    CGContextRef    _backingContext;
    CGColorSpaceRef _backingColorSpace;
    void           *_backingData;
    size_t          _backingWidth;
    size_t          _backingHeight;
    size_t          _backingBytesPerRow;

    /* Cached graphics context to avoid per-frame allocation (Bug 28 fix) */
    id              _cachedGfxCtx;      /* NSGraphicsContext* */
}
- (id)initWithContentRect:(CGRect)contentRect
                styleMask:(NSUInteger)style
                  backing:(NSBackingStoreType)backingStoreType
                    defer:(BOOL)flag;
- (int32_t)windowNumber;
- (CGRect)frame;
- (void)setFrame:(CGRect)frame display:(BOOL)displayFlag;
- (CGRect)contentRectForFrameRect:(CGRect)frameRect;
- (id)contentView;
- (void)setContentView:(id)view;
- (id)title;
- (void)setTitle:(id)title;
- (NSUInteger)styleMask;
- (void)makeKeyAndOrderFront:(id)sender;
- (void)orderFront:(id)sender;
- (void)orderBack:(id)sender;
- (void)orderOut:(id)sender;
- (void)close;
- (BOOL)isVisible;
- (BOOL)isKeyWindow;
- (BOOL)isMainWindow;
- (id)firstResponder;
- (BOOL)makeFirstResponder:(id)responder;
- (id)delegate;
- (void)setDelegate:(id)delegate;
- (void)displayIfNeeded;
- (void)display;
- (void)flushWindow;
- (void)setNeedsDisplay:(BOOL)flag;
- (void)sendEvent:(id)event;
- (void)_createBackingStore;
- (void)_destroyBackingStore;
@end

@implementation NSWindow

- (id)initWithContentRect:(CGRect)contentRect
                styleMask:(NSUInteger)style
                  backing:(NSBackingStoreType)backingStoreType
                    defer:(BOOL)flag
{
    self = [super init];
    if (!self) return nil;

    (void)flag;
    _frame = contentRect;
    _styleMask = (uint32_t)style;
    _backingType = backingStoreType;
    _title = nil;
    _contentView = nil;
    _firstResponder = nil;
    _delegate = nil;
    _isVisible = NO;
    _isKeyWindow = NO;
    _isMainWindow = NO;
    _backingContext = NULL;
    _backingColorSpace = NULL;
    _backingData = NULL;
    _backingWidth = 0;
    _backingHeight = 0;
    _backingBytesPerRow = 0;
    _windowNumber = -1;

    /* Create the WindowServer window */
    _windowNumber = _WSCreateWindow(
        (int32_t)contentRect.origin.x,
        (int32_t)contentRect.origin.y,
        (uint32_t)contentRect.size.width,
        (uint32_t)contentRect.size.height,
        _styleMask,
        "Untitled");

    /* Create default content view filling the window */
    NSView *cv = [[NSView alloc] initWithFrame:
        CGRectMake(0, 0, contentRect.size.width, contentRect.size.height)];
    [self setContentView:(id)cv];

    /* Create backing store */
    [self _createBackingStore];

    /* Register in global window list */
    if (__windowCount < NS_MAX_WINDOWS) {
        __allWindows[__windowCount++] = self;
    }

    return self;
}

- (int32_t)windowNumber { return _windowNumber; }
- (CGRect)frame         { return _frame; }

- (void)setFrame:(CGRect)frame display:(BOOL)displayFlag {
    _frame = frame;

    /* Resize backing store */
    [self _destroyBackingStore];
    [self _createBackingStore];

    /* Update content view frame */
    if (_contentView) {
        ((NSView *)_contentView)->_frame =
            CGRectMake(0, 0, frame.size.width, frame.size.height);
        ((NSView *)_contentView)->_bounds =
            CGRectMake(0, 0, frame.size.width, frame.size.height);
    }

    /* Tell WindowServer */
    if (_windowNumber >= 0) {
        _WSSetFrame(_windowNumber,
                    (int32_t)frame.origin.x, (int32_t)frame.origin.y,
                    (uint32_t)frame.size.width, (uint32_t)frame.size.height);
    }

    if (displayFlag) [self display];
}

- (CGRect)contentRectForFrameRect:(CGRect)frameRect {
    /* For now, content rect = frame rect (no title bar inset on client side) */
    return frameRect;
}

- (id)contentView { return _contentView; }

- (void)setContentView:(id)view {
    if (_contentView) {
        ((NSView *)_contentView)->_window = nil;
    }
    _contentView = view;
    if (view) {
        ((NSView *)view)->_window = (id)self;
        [(NSView *)view setNextResponder:(id)self];
    }
}

- (id)title { return _title; }

- (void)setTitle:(id)title {
    _title = title;
    if (_windowNumber >= 0 && title) {
        const char *cstr = CFStringGetCStringPtr((CFStringRef)title, kCFStringEncodingUTF8);
        if (cstr) _WSSetTitle(_windowNumber, cstr);
    }
}

- (NSUInteger)styleMask { return (NSUInteger)_styleMask; }

- (void)makeKeyAndOrderFront:(id)sender {
    (void)sender;
    _isVisible = YES;
    _isKeyWindow = YES;
    _isMainWindow = YES;
    if (_windowNumber >= 0) {
        _WSOrderWindow(_windowNumber, WS_ORDER_FRONT);
    }
    [self display];
}

- (void)orderFront:(id)sender {
    (void)sender;
    _isVisible = YES;
    if (_windowNumber >= 0) {
        _WSOrderWindow(_windowNumber, WS_ORDER_FRONT);
    }
    [self display];
}

- (void)orderBack:(id)sender {
    (void)sender;
    _isVisible = YES;
    if (_windowNumber >= 0) {
        _WSOrderWindow(_windowNumber, WS_ORDER_BACK);
    }
    [self display];
}

- (void)orderOut:(id)sender {
    (void)sender;
    _isVisible = NO;
    if (_windowNumber >= 0) {
        _WSOrderWindow(_windowNumber, WS_ORDER_OUT);
    }
}

- (void)close {
    [self orderOut:nil];

    /* Notify delegate */
    if (_delegate && class_respondsToSelector(object_getClass(_delegate),
            sel_registerName("windowWillClose:"))) {
        ((void (*)(id, SEL, id))objc_msgSend)(
            _delegate, sel_registerName("windowWillClose:"), (id)self);
    }

    /* Remove from global list */
    for (int i = 0; i < __windowCount; i++) {
        if (__allWindows[i] == self) {
            for (int j = i; j < __windowCount - 1; j++)
                __allWindows[j] = __allWindows[j + 1];
            __allWindows[--__windowCount] = nil;
            break;
        }
    }

    if (_windowNumber >= 0) {
        _WSDestroyWindow(_windowNumber);
        _windowNumber = -1;
    }
}

- (BOOL)isVisible    { return _isVisible; }
- (BOOL)isKeyWindow  { return _isKeyWindow; }
- (BOOL)isMainWindow { return _isMainWindow; }

- (id)firstResponder { return _firstResponder; }

- (BOOL)makeFirstResponder:(id)responder {
    if (_firstResponder == responder) return YES;

    if (_firstResponder) {
        BOOL resigned = ((BOOL (*)(id, SEL))objc_msgSend)(
            _firstResponder, sel_registerName("resignFirstResponder"));
        if (!resigned) return NO;
    }

    _firstResponder = responder;
    if (responder) {
        ((BOOL (*)(id, SEL))objc_msgSend)(
            responder, sel_registerName("becomeFirstResponder"));
    }
    return YES;
}

- (id)delegate { return _delegate; }
- (void)setDelegate:(id)delegate { _delegate = delegate; }

- (void)displayIfNeeded {
    if (!_isVisible) return;
    if (_contentView && ((NSView *)_contentView)->_needsDisplay) {
        [self display];
    }
}

- (void)display {
    if (!_backingContext || !_contentView) {
        return;
    }

    /* Reuse cached graphics context to avoid per-frame alloc (Bug 28 fix) */
    if (!_cachedGfxCtx) {
        _cachedGfxCtx = [NSGraphicsContext
            graphicsContextWithCGContext:_backingContext flipped:YES];
    }
    [NSGraphicsContext setCurrentContext:_cachedGfxCtx];

    /* Clear backing store to window background */
    CGContextSetRGBFillColor(_backingContext, 0.93, 0.93, 0.93, 1.0);
    CGContextFillRect(_backingContext,
        CGRectMake(0, 0, (CGFloat)_backingWidth, (CGFloat)_backingHeight));

    /* Draw content view tree */
    [(NSView *)_contentView display];

    [NSGraphicsContext setCurrentContext:nil];

    /* Flush to WindowServer */
    [self flushWindow];
}

- (void)flushWindow {
    if (!_backingData || _windowNumber < 0) return;

    /* Blit entire backing store to WindowServer */
    _WSDrawRect(_windowNumber, 0, 0,
                (uint32_t)_backingWidth, (uint32_t)_backingHeight,
                _backingData, (uint32_t)_backingBytesPerRow);
}

- (void)setNeedsDisplay:(BOOL)flag {
    if (_contentView) {
        [(NSView *)_contentView setNeedsDisplay:flag];
    }
}

- (void)sendEvent:(id)event {
    NSEvent *e = (NSEvent *)event;
    NSEventType type = [e type];

    switch (type) {
        case NSEventTypeKeyDown:
            if (_firstResponder) {
                [(NSResponder *)_firstResponder keyDown:event];
            }
            break;
        case NSEventTypeKeyUp:
            if (_firstResponder) {
                [(NSResponder *)_firstResponder keyUp:event];
            }
            break;
        case NSEventTypeLeftMouseDown:
        case NSEventTypeRightMouseDown: {
            /* Hit test to find which view was clicked */
            CGPoint loc = [e locationInWindow];
            id hitView = [(NSView *)_contentView hitTest:loc];
            if (hitView) {
                /* Make first responder if it accepts */
                if (((BOOL (*)(id, SEL))objc_msgSend)(hitView,
                        sel_registerName("acceptsFirstResponder"))) {
                    [self makeFirstResponder:hitView];
                }
                if (type == NSEventTypeLeftMouseDown) {
                    [(NSResponder *)hitView mouseDown:event];
                } else {
                    [(NSResponder *)hitView rightMouseDown:event];
                }
            }
            break;
        }
        case NSEventTypeLeftMouseUp:
            if (_firstResponder) {
                [(NSResponder *)_firstResponder mouseUp:event];
            }
            break;
        case NSEventTypeMouseMoved:
            if (_firstResponder) {
                [(NSResponder *)_firstResponder mouseMoved:event];
            }
            break;
        case NSEventTypeLeftMouseDragged:
            if (_firstResponder) {
                [(NSResponder *)_firstResponder mouseDragged:event];
            }
            break;
        default:
            break;
    }
}

- (void)_createBackingStore {
    _backingWidth = (size_t)_frame.size.width;
    _backingHeight = (size_t)_frame.size.height;
    if (_backingWidth == 0) _backingWidth = 1;
    if (_backingHeight == 0) _backingHeight = 1;
    _backingBytesPerRow = _backingWidth * 4;

    _backingData = calloc(_backingHeight, _backingBytesPerRow);
    if (!_backingData)
        return;

    _backingColorSpace = CGColorSpaceCreateDeviceRGB();
    _backingContext = CGBitmapContextCreate(
        _backingData, _backingWidth, _backingHeight,
        8, _backingBytesPerRow, _backingColorSpace,
        kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little);

    if (!_backingContext) {
        free(_backingData);
        _backingData = NULL;
    }
}

- (void)_destroyBackingStore {
    /* Invalidate cached graphics context (Bug 28 fix) */
    _cachedGfxCtx = nil;

    if (_backingContext) {
        CGContextRelease(_backingContext);
        _backingContext = NULL;
    }
    if (_backingColorSpace) {
        CGColorSpaceRelease(_backingColorSpace);
        _backingColorSpace = NULL;
    }
    if (_backingData) {
        free(_backingData);
        _backingData = NULL;
    }
}

- (void)dealloc {
    [self _destroyBackingStore];
    if (_windowNumber >= 0) {
        _WSDestroyWindow(_windowNumber);
    }
    struct objc_super sup = { self, objc_getClass("NSResponder") };
    objc_msgSendSuper2(&sup, sel_registerName("dealloc"));
}

@end

/* ============================================================================
 * Section 19: NSMenuItem
 *
 * Represents a single menu item. Stores title, action selector, target,
 * keyboard equivalent, and enabled state.
 *
 * Reference: macOS NSMenuItem.h
 * ============================================================================ */

@interface NSMenuItem : NSObject {
@public
    id      _title;             /* NSString* */
    SEL     _action;
    id      _target;
    id      _keyEquivalent;     /* NSString* */
    int32_t _tag;
    BOOL    _enabled;
    BOOL    _isSeparator;
    id      _submenu;           /* NSMenu* */
}
+ (id)separatorItem;
- (id)initWithTitle:(id)title action:(SEL)action keyEquivalent:(id)keyEquivalent;
- (id)title;
- (void)setTitle:(id)title;
- (SEL)action;
- (void)setAction:(SEL)action;
- (id)target;
- (void)setTarget:(id)target;
- (int32_t)tag;
- (void)setTag:(int32_t)tag;
- (BOOL)isEnabled;
- (void)setEnabled:(BOOL)enabled;
- (id)keyEquivalent;
- (void)setKeyEquivalent:(id)keyEquiv;
- (id)submenu;
- (void)setSubmenu:(id)submenu;
- (BOOL)isSeparatorItem;
@end

@implementation NSMenuItem

+ (id)separatorItem {
    NSMenuItem *item = [[NSMenuItem alloc] init];
    if (item) {
        item->_isSeparator = YES;
        item->_title = (id)CFSTR("-");
        item->_enabled = NO;
    }
    return item;
}

- (id)initWithTitle:(id)title action:(SEL)action keyEquivalent:(id)keyEquivalent {
    self = [super init];
    if (self) {
        _title = title;
        _action = action;
        _target = nil;
        _keyEquivalent = keyEquivalent ? keyEquivalent : (id)CFSTR("");
        _tag = 0;
        _enabled = YES;
        _isSeparator = NO;
        _submenu = nil;
    }
    return self;
}

- (id)title              { return _title; }
- (void)setTitle:(id)t   { _title = t; }
- (SEL)action            { return _action; }
- (void)setAction:(SEL)a { _action = a; }
- (id)target             { return _target; }
- (void)setTarget:(id)t  { _target = t; }
- (int32_t)tag           { return _tag; }
- (void)setTag:(int32_t)t { _tag = t; }
- (BOOL)isEnabled        { return _enabled; }
- (void)setEnabled:(BOOL)e { _enabled = e; }
- (id)keyEquivalent      { return _keyEquivalent; }
- (void)setKeyEquivalent:(id)k { _keyEquivalent = k; }
- (id)submenu            { return _submenu; }
- (void)setSubmenu:(id)m { _submenu = m; }
- (BOOL)isSeparatorItem  { return _isSeparator; }

@end

/* ============================================================================
 * Section 20: NSMenu
 *
 * Represents a menu (menu bar or dropdown). Stores an array of NSMenuItems.
 * When set as NSApplication.mainMenu, the top-level items are sent to
 * WindowServer via WS_MSG_SET_MENU.
 *
 * Reference: macOS NSMenu.h
 * ============================================================================ */

#define NS_MAX_MENU_ITEMS 32

@interface NSMenu : NSObject {
@public
    id      _title;
    id      _items[NS_MAX_MENU_ITEMS];
    int     _itemCount;
    id      _supermenu;     /* weak — parent NSMenu */
}
- (id)initWithTitle:(id)title;
- (id)title;
- (void)setTitle:(id)title;
- (void)addItem:(id)item;
- (id)addItemWithTitle:(id)title action:(SEL)action keyEquivalent:(id)keyEquiv;
- (void)insertItem:(id)item atIndex:(NSInteger)index;
- (void)removeItemAtIndex:(NSInteger)index;
- (id)itemAtIndex:(NSInteger)index;
- (id)itemWithTag:(int32_t)tag;
- (NSInteger)numberOfItems;
- (id)itemArray;
- (void)_syncToWindowServer;
@end

@implementation NSMenu

- (id)initWithTitle:(id)title {
    self = [super init];
    if (self) {
        _title = title;
        _itemCount = 0;
        _supermenu = nil;
        memset(_items, 0, sizeof(_items));
    }
    return self;
}

- (id)title { return _title; }
- (void)setTitle:(id)t { _title = t; }

- (void)addItem:(id)item {
    if (!item || _itemCount >= NS_MAX_MENU_ITEMS) return;
    _items[_itemCount++] = item;
}

- (id)addItemWithTitle:(id)title action:(SEL)action keyEquivalent:(id)keyEquiv {
    NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:title action:action
                                          keyEquivalent:keyEquiv];
    [self addItem:(id)item];
    return (id)item;
}

- (void)insertItem:(id)item atIndex:(NSInteger)index {
    if (!item || _itemCount >= NS_MAX_MENU_ITEMS) return;
    if (index < 0) index = 0;
    if (index > _itemCount) index = _itemCount;
    /* Shift items up */
    for (int i = _itemCount; i > (int)index; i--) {
        _items[i] = _items[i - 1];
    }
    _items[index] = item;
    _itemCount++;
}

- (void)removeItemAtIndex:(NSInteger)index {
    if (index < 0 || index >= _itemCount) return;
    for (int i = (int)index; i < _itemCount - 1; i++) {
        _items[i] = _items[i + 1];
    }
    _items[--_itemCount] = nil;
}

- (id)itemAtIndex:(NSInteger)index {
    if (index < 0 || index >= _itemCount) return nil;
    return _items[index];
}

- (id)itemWithTag:(int32_t)tag {
    for (int i = 0; i < _itemCount; i++) {
        NSMenuItem *item = (NSMenuItem *)_items[i];
        if (item->_tag == tag) return (id)item;
    }
    return nil;
}

- (NSInteger)numberOfItems { return (NSInteger)_itemCount; }
- (id)itemArray { return nil; /* simplified */ }

/*
 * _syncToWindowServer — Send menu items to WindowServer via WS_MSG_SET_MENU.
 *
 * This flattens the top-level menu items (each of which may have a submenu)
 * into the flat array that WindowServer expects for the menu bar.
 */
- (void)_syncToWindowServer {
    const char *titles[WS_MAX_MENU_ITEMS];
    int32_t tags[WS_MAX_MENU_ITEMS];
    int count = 0;

    for (int i = 0; i < _itemCount && count < WS_MAX_MENU_ITEMS; i++) {
        NSMenuItem *item = (NSMenuItem *)_items[i];
        if (!item || item->_isSeparator) continue;

        const char *t = item->_title ?
            CFStringGetCStringPtr((CFStringRef)item->_title, kCFStringEncodingUTF8) : "?";
        if (!t) t = "?";
        titles[count] = t;
        tags[count] = item->_tag;
        count++;
    }

    if (count > 0) {
        _WSSetMenu(titles, tags, count);
    }
}

@end

/* ============================================================================
 * Section 21: NSApplication
 *
 * The singleton application object. Manages:
 *   - Connection to WindowServer (via _WSConnect)
 *   - Main event loop (run → nextEventMatchingMask: → sendEvent:)
 *   - Window list
 *   - Main menu → WindowServer
 *   - Application delegate lifecycle
 *
 * On macOS, NSApplication is created by [NSApplication sharedApplication]
 * (which also sets the global NSApp). The run method enters the main event
 * loop, polling for Mach IPC events from WindowServer and dispatching them
 * to the appropriate NSWindow.
 *
 * Reference: macOS NSApplication.h
 * ============================================================================ */

/* NSApplicationActivationPolicy — matching macOS */
typedef enum {
    NSApplicationActivationPolicyRegular    = 0,
    NSApplicationActivationPolicyAccessory  = 1,
    NSApplicationActivationPolicyProhibited = 2,
} NSApplicationActivationPolicy;

@interface NSApplication : NSResponder {
@public
    id      _delegate;
    id      _mainMenu;          /* NSMenu* */
    id      _keyWindow;         /* NSWindow* */
    id      _mainWindow;        /* NSWindow* */
    BOOL    _isRunning;
    NSApplicationActivationPolicy _activationPolicy;
}
+ (id)sharedApplication;
- (void)setDelegate:(id)delegate;
- (id)delegate;
- (void)run;
- (void)stop:(id)sender;
- (void)terminate:(id)sender;
- (id)nextEventMatchingMask:(NSUInteger)mask
                  untilDate:(id)expiration
                     inMode:(id)mode
                    dequeue:(BOOL)deqFlag;
- (void)sendEvent:(id)event;
- (void)setMainMenu:(id)menu;
- (id)mainMenu;
- (id)keyWindow;
- (id)mainWindow;
- (id)windows;
- (void)setActivationPolicy:(NSApplicationActivationPolicy)policy;
- (void)activateIgnoringOtherApps:(BOOL)flag;
- (void)finishLaunching;
- (void)_processWSEvent:(ws_msg_buffer_t *)buf;
@end

@implementation NSApplication

+ (id)sharedApplication {
    if (!NSApp) {
        /* Finish deferred Foundation setup (notification name constants etc.).
         * Safe here because all images are loaded and ObjC classes registered. */
        _FoundationEnsureInitialized();
        NSApp = [[NSApplication alloc] init];
    }
    return NSApp;
}

- (id)init {
    self = [super init];
    if (self) {
        _delegate = nil;
        _mainMenu = nil;
        _keyWindow = nil;
        _mainWindow = nil;
        _isRunning = NO;
        _activationPolicy = NSApplicationActivationPolicyRegular;
    }
    return self;
}

- (void)setDelegate:(id)delegate { _delegate = delegate; }
- (id)delegate                   { return _delegate; }

- (void)setMainMenu:(id)menu {
    _mainMenu = menu;
    /* Sync to WindowServer */
    if (menu) {
        [(NSMenu *)menu _syncToWindowServer];
    }
}

- (id)mainMenu    { return _mainMenu; }
- (id)keyWindow   { return _keyWindow; }
- (id)mainWindow  { return _mainWindow; }

- (id)windows {
    /* Return the global window list — simplified */
    return nil;
}

- (void)setActivationPolicy:(NSApplicationActivationPolicy)policy {
    _activationPolicy = policy;
}

- (void)activateIgnoringOtherApps:(BOOL)flag {
    (void)flag;
    /* On macOS this brings the app to the foreground.
       For us, the WindowServer connection already makes us foreground. */
}

- (void)finishLaunching {
    /* Connect to WindowServer */
    const char *appName = "Application";
    if (_mainMenu) {
        NSMenu *menu = (NSMenu *)_mainMenu;
        if (menu->_title) {
            const char *t = CFStringGetCStringPtr((CFStringRef)menu->_title,
                                                   kCFStringEncodingUTF8);
            if (t) appName = t;
        }
    }

    if (!_WSConnect(appName)) {
        /* Continue anyway — allows running without WS for testing */
    }

    /* Sync menu to WindowServer */
    if (_mainMenu) {
        [(NSMenu *)_mainMenu _syncToWindowServer];
    }

    /* Notify delegate */
    if (_delegate && class_respondsToSelector(object_getClass(_delegate),
            sel_registerName("applicationDidFinishLaunching:"))) {
        ((void (*)(id, SEL, id))objc_msgSend)(
            _delegate, sel_registerName("applicationDidFinishLaunching:"), nil);
    }

    /* Post notification */
    /* NSNotificationCenter would post NSApplicationDidFinishLaunchingNotification here */
}

/*
 * run — Main event loop.
 *
 * On macOS, this is:
 *   1. finishLaunching
 *   2. Loop: nextEvent → sendEvent → updateWindows
 *
 * We poll WindowServer's event port with a 10ms timeout (matching the
 * kernel's 100 Hz timer tick), process any events, then let run loops
 * fire timers.
 */
- (void)run {
    [self finishLaunching];
    _isRunning = YES;

    ws_msg_buffer_t buf;

    while (_isRunning) {
        /* Poll for WindowServer events with 100ms timeout */
        if (_WSPollEvent(&buf, 100)) {
            [self _processWSEvent:&buf];
        }

        /* Display any windows that need updating */
        for (int i = 0; i < __windowCount; i++) {
            if (__allWindows[i]) {
                [__allWindows[i] displayIfNeeded];
            }
        }

        /* Let CFRunLoop process timers and sources */
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.0, YES);
    }

    /* Notify delegate of termination */
    if (_delegate && class_respondsToSelector(object_getClass(_delegate),
            sel_registerName("applicationWillTerminate:"))) {
        ((void (*)(id, SEL, id))objc_msgSend)(
            _delegate, sel_registerName("applicationWillTerminate:"), nil);
    }

    _WSDisconnect();
}

- (void)stop:(id)sender {
    (void)sender;
    _isRunning = NO;
}

- (void)terminate:(id)sender {
    (void)sender;
    _isRunning = NO;
}

/*
 * nextEventMatchingMask:untilDate:inMode:dequeue:
 *
 * On macOS, this pulls the next event from the event queue.
 * We implement a simplified version that polls WindowServer.
 */
- (id)nextEventMatchingMask:(NSUInteger)mask
                  untilDate:(id)expiration
                     inMode:(id)mode
                    dequeue:(BOOL)deqFlag
{
    (void)mask; (void)expiration; (void)mode; (void)deqFlag;

    ws_msg_buffer_t buf;
    if (_WSPollEvent(&buf, 100)) {
        /* Convert to NSEvent based on message ID */
        mach_msg_id_t mid = buf.header.msgh_id;
        NSEvent *event = nil;

        if (mid == WS_EVENT_KEY_DOWN) {
            event = _NSEventFromWSKeyEvent((ws_event_key_t *)&buf, NSEventTypeKeyDown);
        } else if (mid == WS_EVENT_KEY_UP) {
            event = _NSEventFromWSKeyEvent((ws_event_key_t *)&buf, NSEventTypeKeyUp);
        } else if (mid == WS_EVENT_MOUSE_DOWN) {
            ws_event_mouse_t *me = (ws_event_mouse_t *)&buf;
            NSEventType type = (me->button == 1) ? NSEventTypeRightMouseDown
                                                  : NSEventTypeLeftMouseDown;
            event = _NSEventFromWSMouseEvent(me, type);
        } else if (mid == WS_EVENT_MOUSE_UP) {
            ws_event_mouse_t *me = (ws_event_mouse_t *)&buf;
            NSEventType type = (me->button == 1) ? NSEventTypeRightMouseUp
                                                  : NSEventTypeLeftMouseUp;
            event = _NSEventFromWSMouseEvent(me, type);
        } else if (mid == WS_EVENT_MOUSE_MOVED) {
            event = _NSEventFromWSMouseEvent((ws_event_mouse_t *)&buf, NSEventTypeMouseMoved);
        } else if (mid == WS_EVENT_MOUSE_DRAGGED) {
            event = _NSEventFromWSMouseEvent((ws_event_mouse_t *)&buf, NSEventTypeLeftMouseDragged);
        }
        /* Window events handled in _processWSEvent */

        return (id)event;
    }
    return nil;
}

- (void)sendEvent:(id)event {
    if (!event) return;
    NSEvent *e = (NSEvent *)event;

    /* Find the target window */
    int32_t wnum = [e windowNumber];
    NSWindow *targetWindow = nil;
    for (int i = 0; i < __windowCount; i++) {
        if (__allWindows[i] && __allWindows[i]->_windowNumber == wnum) {
            targetWindow = __allWindows[i];
            break;
        }
    }

    if (targetWindow) {
        [targetWindow sendEvent:event];
    }
}

/*
 * _processWSEvent — Process a raw WindowServer IPC message.
 *
 * Converts WS events to NSEvents and dispatches them.
 * Also handles window lifecycle events (activate/deactivate/close/resize).
 */
- (void)_processWSEvent:(ws_msg_buffer_t *)buf {
    mach_msg_id_t mid = buf->header.msgh_id;

    switch (mid) {
        case WS_EVENT_KEY_DOWN: {
            NSEvent *e = _NSEventFromWSKeyEvent((ws_event_key_t *)buf,
                                                 NSEventTypeKeyDown);
            if (e) [self sendEvent:(id)e];
            break;
        }
        case WS_EVENT_KEY_UP: {
            NSEvent *e = _NSEventFromWSKeyEvent((ws_event_key_t *)buf,
                                                 NSEventTypeKeyUp);
            if (e) [self sendEvent:(id)e];
            break;
        }
        case WS_EVENT_MOUSE_DOWN: {
            ws_event_mouse_t *me = (ws_event_mouse_t *)buf;
            NSEventType type = (me->button == 1) ? NSEventTypeRightMouseDown
                                                  : NSEventTypeLeftMouseDown;
            NSEvent *e = _NSEventFromWSMouseEvent(me, type);
            if (e) [self sendEvent:(id)e];
            break;
        }
        case WS_EVENT_MOUSE_UP: {
            ws_event_mouse_t *me = (ws_event_mouse_t *)buf;
            NSEventType type = (me->button == 1) ? NSEventTypeRightMouseUp
                                                  : NSEventTypeLeftMouseUp;
            NSEvent *e = _NSEventFromWSMouseEvent(me, type);
            if (e) [self sendEvent:(id)e];
            break;
        }
        case WS_EVENT_MOUSE_MOVED: {
            NSEvent *e = _NSEventFromWSMouseEvent((ws_event_mouse_t *)buf,
                                                   NSEventTypeMouseMoved);
            if (e) [self sendEvent:(id)e];
            break;
        }
        case WS_EVENT_MOUSE_DRAGGED: {
            NSEvent *e = _NSEventFromWSMouseEvent((ws_event_mouse_t *)buf,
                                                   NSEventTypeLeftMouseDragged);
            if (e) [self sendEvent:(id)e];
            break;
        }
        case WS_EVENT_WINDOW_ACTIVATE: {
            ws_event_window_t *we = (ws_event_window_t *)buf;
            for (int i = 0; i < __windowCount; i++) {
                if (__allWindows[i] && __allWindows[i]->_windowNumber == we->window_id) {
                    __allWindows[i]->_isKeyWindow = YES;
                    __allWindows[i]->_isMainWindow = YES;
                    _keyWindow = (id)__allWindows[i];
                    _mainWindow = (id)__allWindows[i];
                    break;
                }
            }
            break;
        }
        case WS_EVENT_WINDOW_DEACTIVATE: {
            ws_event_window_t *we = (ws_event_window_t *)buf;
            for (int i = 0; i < __windowCount; i++) {
                if (__allWindows[i] && __allWindows[i]->_windowNumber == we->window_id) {
                    __allWindows[i]->_isKeyWindow = NO;
                    __allWindows[i]->_isMainWindow = NO;
                    break;
                }
            }
            break;
        }
        case WS_EVENT_WINDOW_CLOSE: {
            ws_event_window_t *we = (ws_event_window_t *)buf;
            for (int i = 0; i < __windowCount; i++) {
                if (__allWindows[i] && __allWindows[i]->_windowNumber == we->window_id) {
                    [__allWindows[i] close];
                    break;
                }
            }
            break;
        }
        case WS_EVENT_WINDOW_RESIZE: {
            ws_event_resize_t *re = (ws_event_resize_t *)buf;
            for (int i = 0; i < __windowCount; i++) {
                if (__allWindows[i] && __allWindows[i]->_windowNumber == re->window_id) {
                    CGRect newFrame = __allWindows[i]->_frame;
                    newFrame.size.width = (CGFloat)re->new_width;
                    newFrame.size.height = (CGFloat)re->new_height;
                    [__allWindows[i] setFrame:newFrame display:YES];
                    break;
                }
            }
            break;
        }
        default:
            /* Unknown event — ignore */
            break;
    }
}

@end

/* ============================================================================
 * NSApplicationMain — Standard entry point for AppKit applications.
 *
 * On macOS: NSApplicationMain(argc, argv) creates the shared NSApplication,
 * loads the main nib, and calls [NSApp run]. Since we have no nib loading,
 * we just create the app and run.
 * ============================================================================ */

EXPORT int NSApplicationMain(int argc, const char *argv[]) {
    (void)argc; (void)argv;
    void *pool = objc_autoreleasePoolPush();
    [NSApplication sharedApplication];
    [NSApp run];
    objc_autoreleasePoolPop(pool);
    return 0;
}

/* ============================================================================
 * Section 22: NSCell (minimal)
 *
 * NSCell is the lightweight data/drawing object used by NSControl subclasses
 * on macOS. We provide a minimal implementation since NSTextField and
 * NSButton reference it.
 *
 * Reference: macOS NSCell.h
 * ============================================================================ */

@interface NSCell : NSObject {
@public
    id      _stringValue;   /* NSString* */
    id      _font;          /* NSFont* */
    id      _target;
    SEL     _action;
    BOOL    _enabled;
    BOOL    _editable;
}
- (id)stringValue;
- (void)setStringValue:(id)value;
- (id)font;
- (void)setFont:(id)font;
- (id)target;
- (void)setTarget:(id)target;
- (SEL)action;
- (void)setAction:(SEL)action;
- (BOOL)isEnabled;
- (void)setEnabled:(BOOL)flag;
- (BOOL)isEditable;
- (void)setEditable:(BOOL)flag;
@end

@implementation NSCell

- (id)init {
    self = [super init];
    if (self) {
        _stringValue = (id)CFSTR("");
        _font = nil;
        _target = nil;
        _action = NULL;
        _enabled = YES;
        _editable = NO;
    }
    return self;
}

- (id)stringValue         { return _stringValue; }
- (void)setStringValue:(id)v { _stringValue = v; }
- (id)font                { return _font; }
- (void)setFont:(id)f     { _font = f; }
- (id)target              { return _target; }
- (void)setTarget:(id)t   { _target = t; }
- (SEL)action             { return _action; }
- (void)setAction:(SEL)a  { _action = a; }
- (BOOL)isEnabled         { return _enabled; }
- (void)setEnabled:(BOOL)f { _enabled = f; }
- (BOOL)isEditable        { return _editable; }
- (void)setEditable:(BOOL)f { _editable = f; }

@end

/* ============================================================================
 * Section 23: NSControl
 *
 * Base class for interactive views (NSTextField, NSButton, etc.).
 * Wraps a target/action pattern and a string value.
 *
 * Reference: macOS NSControl.h
 * ============================================================================ */

@interface NSControl : NSView {
@public
    id      _cell;          /* NSCell* */
    id      _target;
    SEL     _action;
    BOOL    _enabled;
}
- (id)initWithFrame:(CGRect)frameRect;
- (id)stringValue;
- (void)setStringValue:(id)value;
- (id)font;
- (void)setFont:(id)font;
- (id)target;
- (void)setTarget:(id)target;
- (SEL)action;
- (void)setAction:(SEL)action;
- (BOOL)isEnabled;
- (void)setEnabled:(BOOL)flag;
- (void)sendAction:(SEL)action to:(id)target;
@end

@implementation NSControl

- (id)initWithFrame:(CGRect)frameRect {
    struct objc_super sup = { self, objc_getClass("NSView") };
    self = objc_msgSendSuper2(&sup, sel_registerName("initWithFrame:"),
                               frameRect);
    if (self) {
        _cell = [[NSCell alloc] init];
        _target = nil;
        _action = NULL;
        _enabled = YES;
    }
    return self;
}

- (id)stringValue {
    return _cell ? [(NSCell *)_cell stringValue] : (id)CFSTR("");
}

- (void)setStringValue:(id)value {
    if (_cell) [(NSCell *)_cell setStringValue:value];
    [self setNeedsDisplay:YES];
}

- (id)font {
    return _cell ? [(NSCell *)_cell font] : nil;
}

- (void)setFont:(id)font {
    if (_cell) [(NSCell *)_cell setFont:font];
    [self setNeedsDisplay:YES];
}

- (id)target         { return _target; }
- (void)setTarget:(id)t { _target = t; }
- (SEL)action        { return _action; }
- (void)setAction:(SEL)a { _action = a; }
- (BOOL)isEnabled    { return _enabled; }
- (void)setEnabled:(BOOL)f { _enabled = f; }

- (void)sendAction:(SEL)action to:(id)target {
    if (action && target) {
        ((void (*)(id, SEL, id))objc_msgSend)(target, action, self);
    }
}

@end

/* ============================================================================
 * Section 24: NSTextField
 *
 * Displays static or editable text. Draws text using CoreText (CTLine)
 * into the view's region of the window backing store.
 *
 * Reference: macOS NSTextField.h
 * ============================================================================ */

@interface NSTextField : NSControl {
@public
    id      _textColor;     /* NSColor* */
    id      _bgColor;       /* NSColor* */
    BOOL    _bordered;
    BOOL    _bezeled;
    BOOL    _drawsBackground;
    BOOL    _selectable;
}
+ (id)labelWithString:(id)stringValue;
- (id)initWithFrame:(CGRect)frameRect;
- (id)textColor;
- (void)setTextColor:(id)color;
- (void)setBackgroundColor:(id)color;
- (BOOL)isBordered;
- (void)setBordered:(BOOL)flag;
- (BOOL)isBezeled;
- (void)setBezeled:(BOOL)flag;
- (BOOL)drawsBackground;
- (void)setDrawsBackground:(BOOL)flag;
- (BOOL)isSelectable;
- (void)setSelectable:(BOOL)flag;
- (BOOL)isEditable;
- (void)setEditable:(BOOL)flag;
- (void)drawRect:(CGRect)dirtyRect;
@end

@implementation NSTextField

+ (id)labelWithString:(id)stringValue {
    NSTextField *tf = [[NSTextField alloc] initWithFrame:CGRectMake(0, 0, 200, 20)];
    if (tf) {
        [tf setStringValue:stringValue];
        [tf setBordered:NO];
        [tf setBezeled:NO];
        [tf setDrawsBackground:NO];
        [tf setEditable:NO];
        [tf setSelectable:NO];
    }
    return (id)tf;
}

- (id)initWithFrame:(CGRect)frameRect {
    struct objc_super sup = { self, objc_getClass("NSControl") };
    self = objc_msgSendSuper2(&sup, sel_registerName("initWithFrame:"),
                               frameRect);
    if (self) {
        _textColor = [NSColor textColor];
        _bgColor = [NSColor controlBackgroundColor];
        _bordered = YES;
        _bezeled = NO;
        _drawsBackground = YES;
        _selectable = YES;
    }
    return self;
}

- (id)textColor            { return _textColor; }
- (void)setTextColor:(id)c { _textColor = c; }
- (void)setBackgroundColor:(id)c { _bgColor = c; }
- (BOOL)isBordered         { return _bordered; }
- (void)setBordered:(BOOL)f { _bordered = f; }
- (BOOL)isBezeled          { return _bezeled; }
- (void)setBezeled:(BOOL)f { _bezeled = f; }
- (BOOL)drawsBackground    { return _drawsBackground; }
- (void)setDrawsBackground:(BOOL)f { _drawsBackground = f; }
- (BOOL)isSelectable       { return _selectable; }
- (void)setSelectable:(BOOL)f { _selectable = f; }

- (BOOL)isEditable {
    return _cell ? [(NSCell *)_cell isEditable] : NO;
}

- (void)setEditable:(BOOL)flag {
    if (_cell) [(NSCell *)_cell setEditable:flag];
}

- (void)drawRect:(CGRect)dirtyRect {
    (void)dirtyRect;
    NSGraphicsContext *gctx = [NSGraphicsContext currentContext];
    if (!gctx) return;
    CGContextRef ctx = [gctx CGContext];
    if (!ctx) return;

    CGRect frame = _frame;

    /* Draw background */
    if (_drawsBackground && _bgColor) {
        NSColor *bg = (NSColor *)_bgColor;
        CGContextSetRGBFillColor(ctx, bg->_red, bg->_green, bg->_blue, bg->_alpha);
        CGContextFillRect(ctx, frame);
    }

    /* Draw border */
    if (_bordered) {
        CGContextSetRGBStrokeColor(ctx, 0.7, 0.7, 0.7, 1.0);
        CGContextSetLineWidth(ctx, 1.0);
        CGContextStrokeRect(ctx, frame);
    }

    /* Draw text */
    id strVal = [self stringValue];
    if (strVal) {
        const char *cstr = CFStringGetCStringPtr((CFStringRef)strVal, kCFStringEncodingUTF8);
        if (cstr && strlen(cstr) > 0) {
            /* Use CoreText CTLine for text rendering */
            NSColor *tc = (NSColor *)_textColor;
            if (!tc) tc = (NSColor *)[NSColor textColor];
            CGContextSetRGBFillColor(ctx, tc->_red, tc->_green, tc->_blue, tc->_alpha);

            /* Position text with 2px inset, vertically centred (8×16 font) */
            CGFloat textY = frame.origin.y + (frame.size.height - 16.0) / 2.0;
            if (textY < frame.origin.y) textY = frame.origin.y;
            CGContextSetTextPosition(ctx, frame.origin.x + 3.0, textY);
            CGContextShowTextAtPoint(ctx, frame.origin.x + 3.0, textY,
                                     cstr, strlen(cstr));
        }
    }
}

- (BOOL)acceptsFirstResponder { return [self isEditable]; }

@end

/* ============================================================================
 * Section 25: NSButton
 *
 * Push button control. Draws a rounded rectangle with centred title text.
 * Sends target/action on mouseUp.
 *
 * Reference: macOS NSButton.h
 * ============================================================================ */

/* NSButtonType — matching macOS */
typedef enum {
    NSButtonTypeMomentaryLight     = 0,
    NSButtonTypeMomentaryPushIn    = 7,
    NSButtonTypeToggle             = 2,
    NSButtonTypeSwitch             = 3,    /* Checkbox */
    NSButtonTypeRadio              = 4,
    NSButtonTypeOnOff              = 6,
} NSButtonType;

/* NSBezelStyle — matching macOS */
typedef enum {
    NSBezelStyleRounded            = 1,
    NSBezelStyleRegularSquare      = 2,
    NSBezelStyleSmallSquare        = 6,
    NSBezelStyleInline             = 15,
} NSBezelStyle;

@interface NSButton : NSControl {
@public
    id          _title;         /* NSString* */
    NSButtonType _buttonType;
    NSBezelStyle _bezelStyle;
    BOOL        _isHighlighted;
    NSInteger   _state;         /* NSOnState=1, NSOffState=0 */
}
+ (id)buttonWithTitle:(id)title target:(id)target action:(SEL)action;
- (id)initWithFrame:(CGRect)frameRect;
- (id)title;
- (void)setTitle:(id)title;
- (void)setButtonType:(NSButtonType)type;
- (void)setBezelStyle:(NSBezelStyle)style;
- (NSInteger)state;
- (void)setState:(NSInteger)state;
- (BOOL)isHighlighted;
- (void)setHighlighted:(BOOL)flag;
- (void)drawRect:(CGRect)dirtyRect;
- (void)mouseDown:(id)event;
- (void)mouseUp:(id)event;
@end

@implementation NSButton

+ (id)buttonWithTitle:(id)title target:(id)target action:(SEL)action {
    NSButton *btn = [[NSButton alloc] initWithFrame:CGRectMake(0, 0, 80, 24)];
    if (btn) {
        [btn setTitle:title];
        [btn setTarget:target];
        [btn setAction:action];
    }
    return (id)btn;
}

- (id)initWithFrame:(CGRect)frameRect {
    struct objc_super sup = { self, objc_getClass("NSControl") };
    self = objc_msgSendSuper2(&sup, sel_registerName("initWithFrame:"),
                               frameRect);
    if (self) {
        _title = (id)CFSTR("Button");
        _buttonType = NSButtonTypeMomentaryLight;
        _bezelStyle = NSBezelStyleRounded;
        _isHighlighted = NO;
        _state = 0;
    }
    return self;
}

- (id)title               { return _title; }
- (void)setTitle:(id)t    { _title = t; [self setNeedsDisplay:YES]; }
- (void)setButtonType:(NSButtonType)t { _buttonType = t; }
- (void)setBezelStyle:(NSBezelStyle)s { _bezelStyle = s; }
- (NSInteger)state        { return _state; }
- (void)setState:(NSInteger)s { _state = s; [self setNeedsDisplay:YES]; }
- (BOOL)isHighlighted     { return _isHighlighted; }
- (void)setHighlighted:(BOOL)f { _isHighlighted = f; }

- (void)drawRect:(CGRect)dirtyRect {
    (void)dirtyRect;
    NSGraphicsContext *gctx = [NSGraphicsContext currentContext];
    if (!gctx) return;
    CGContextRef ctx = [gctx CGContext];
    if (!ctx) return;

    CGRect frame = _frame;

    /* Button background */
    if (_isHighlighted) {
        CGContextSetRGBFillColor(ctx, 0.3, 0.55, 0.95, 1.0);
    } else {
        CGContextSetRGBFillColor(ctx, 1.0, 1.0, 1.0, 1.0);
    }
    CGContextFillRect(ctx, frame);

    /* Border */
    CGContextSetRGBStrokeColor(ctx, 0.6, 0.6, 0.6, 1.0);
    CGContextSetLineWidth(ctx, 1.0);
    CGContextStrokeRect(ctx, frame);

    /* Title text — centred */
    if (_title) {
        const char *cstr = CFStringGetCStringPtr((CFStringRef)_title, kCFStringEncodingUTF8);
        if (cstr && strlen(cstr) > 0) {
            if (_isHighlighted) {
                CGContextSetRGBFillColor(ctx, 1.0, 1.0, 1.0, 1.0);
            } else {
                CGContextSetRGBFillColor(ctx, 0.0, 0.0, 0.0, 1.0);
            }
            /* Centre text: each char is 8px wide, 16px tall */
            size_t textLen = strlen(cstr);
            CGFloat textWidth = (CGFloat)(textLen * 8);
            CGFloat textX = frame.origin.x + (frame.size.width - textWidth) / 2.0;
            CGFloat textY = frame.origin.y + (frame.size.height - 16.0) / 2.0;
            if (textX < frame.origin.x + 2) textX = frame.origin.x + 2;
            CGContextShowTextAtPoint(ctx, textX, textY, cstr, textLen);
        }
    }
}

- (void)mouseDown:(id)event {
    (void)event;
    if (!_enabled) return;
    _isHighlighted = YES;
    [self setNeedsDisplay:YES];
    /* Request immediate redraw */
    if (_window) {
        [(NSWindow *)_window display];
    }
}

- (void)mouseUp:(id)event {
    (void)event;
    if (!_enabled) return;
    _isHighlighted = NO;
    [self setNeedsDisplay:YES];

    /* Toggle state for toggle/switch buttons */
    if (_buttonType == NSButtonTypeToggle || _buttonType == NSButtonTypeSwitch) {
        _state = _state ? 0 : 1;
    }

    /* Send action */
    if (_action && _target) {
        [self sendAction:_action to:_target];
    }

    if (_window) {
        [(NSWindow *)_window display];
    }
}

- (BOOL)acceptsFirstResponder { return YES; }

@end

/* ============================================================================
 * Section 26: Framework Initialisation
 *
 * __AppKitInitialize runs when the framework is loaded (dyld constructor).
 * Sets up notification name constants and any global state.
 * ============================================================================ */

/* AppKit constructor — currently a no-op.
 * Notification name constants are initialised by Foundation via
 * _FoundationEnsureInitialized(), called from +[NSApplication sharedApplication].
 * CFSTR must NOT be called in constructors because ObjC classes may not
 * be loaded yet, causing toll-free bridged objects to get NULL isa. */

/* ============================================================================
 * End of AppKit.framework
 * ============================================================================ */
