/*
 * Kiseki OS - CoreText.framework
 *
 * Freestanding implementation of Apple's CoreText library.
 * Provides text layout and font management using an embedded 8×16 bitmap
 * font (CP437/IBM PC VGA). Renders glyphs into CGContexts via direct
 * pixel-level blitting.
 *
 * Public API:
 *   CTFont       — font object wrapping the embedded bitmap font
 *   CTLine       — single line of laid-out glyphs
 *   CTFramesetter — lays out text into frames (paragraphs)
 *   CTRun        — contiguous run of glyphs with uniform attributes
 *   CTFrame      — laid-out text within a rectangular path
 *
 * Reference: macOS SDK CoreText headers (CTFont.h, CTLine.h, CTRun.h,
 *            CTFramesetter.h, CTStringAttributes.h)
 */

/* ============================================================================
 * Section 1: Visibility & Compiler Helpers
 * ============================================================================ */

#define EXPORT  __attribute__((visibility("default")))
#define HIDDEN  __attribute__((visibility("hidden")))
#define CT_INLINE static inline __attribute__((always_inline))

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
typedef uint16_t            UniChar;

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
extern int    fprintf(void *stream, const char *fmt, ...);
extern size_t fwrite(const void *ptr, size_t size, size_t nmemb, void *stream);

extern void **__stderrp;
extern void **__stdoutp;
#define stderr (*__stderrp)
#define stdout (*__stdoutp)

/* ============================================================================
 * Section 4: CoreFoundation Imported Types & Functions
 * ============================================================================ */

typedef double             CGFloat;
typedef signed long        CFIndex;
typedef unsigned long      CFTypeID;
typedef unsigned long      CFHashCode;
typedef unsigned int       UInt32;
typedef unsigned long      CFOptionFlags;

typedef const void        *CFTypeRef;
typedef const void        *CFAllocatorRef;
typedef const void        *CFStringRef;
typedef const void        *CFDictionaryRef;
typedef const void        *CFArrayRef;
typedef const void        *CFMutableArrayRef;
typedef const void        *CFDataRef;
typedef const void        *CFNumberRef;
typedef const void        *CFAttributedStringRef;

extern const CFAllocatorRef kCFAllocatorDefault;

/* CFRuntime base — must match CoreFoundation's layout exactly */
typedef struct {
    uintptr_t _cfisa;
    uint64_t  _cfinfoa;
} CFRuntimeBase;

/* CFRetain/CFRelease */
extern CFTypeRef  CFRetain(CFTypeRef cf);
extern void       CFRelease(CFTypeRef cf);
extern CFTypeID   CFGetTypeID(CFTypeRef cf);

/* CFString */
extern CFStringRef CFStringCreateWithCString(CFAllocatorRef alloc, const char *cStr, UInt32 encoding);
extern const char *CFStringGetCStringPtr(CFStringRef theString, UInt32 encoding);
extern CFIndex     CFStringGetLength(CFStringRef theString);
extern UniChar     CFStringGetCharacterAtIndex(CFStringRef theString, CFIndex idx);
extern bool        CFStringGetCString(CFStringRef theString, char *buffer, CFIndex bufferSize, UInt32 encoding);
extern CFIndex     CFStringGetMaximumSizeForEncoding(CFIndex length, UInt32 encoding);
extern CFStringRef __CFStringMakeConstantString(const char *cStr);
#define CFSTR(s) __CFStringMakeConstantString(s)

#define kCFStringEncodingUTF8 0x08000100

/* CFArray */
extern CFArrayRef  CFArrayCreate(CFAllocatorRef alloc, const void **values, CFIndex numValues,
                                 const void *callBacks);
extern CFIndex     CFArrayGetCount(CFArrayRef theArray);
extern const void *CFArrayGetValueAtIndex(CFArrayRef theArray, CFIndex idx);
extern CFMutableArrayRef CFArrayCreateMutable(CFAllocatorRef alloc, CFIndex capacity, const void *callBacks);
extern void        CFArrayAppendValue(CFMutableArrayRef theArray, const void *value);

/* CFDictionary */
extern CFDictionaryRef CFDictionaryCreate(CFAllocatorRef alloc, const void **keys, const void **values,
                                          CFIndex numValues, const void *keyCallBacks, const void *valueCallBacks);
extern const void *CFDictionaryGetValue(CFDictionaryRef theDict, const void *key);

extern const void *kCFTypeDictionaryKeyCallBacks;
extern const void *kCFTypeDictionaryValueCallBacks;

/* CFData */
extern CFDataRef       CFDataCreate(CFAllocatorRef alloc, const uint8_t *bytes, CFIndex length);
extern const uint8_t  *CFDataGetBytePtr(CFDataRef theData);
extern CFIndex         CFDataGetLength(CFDataRef theData);

/* CFNumber */
extern CFNumberRef CFNumberCreate(CFAllocatorRef alloc, CFIndex theType, const void *valuePtr);
extern bool        CFNumberGetValue(CFNumberRef number, CFIndex theType, void *valuePtr);
#define kCFNumberFloat64Type 13
#define kCFNumberCGFloatType kCFNumberFloat64Type

/* CFAttributedString */
extern CFAttributedStringRef CFAttributedStringCreate(CFAllocatorRef alloc, CFStringRef str, CFDictionaryRef attributes);
extern CFIndex        CFAttributedStringGetLength(CFAttributedStringRef aStr);
extern CFStringRef    CFAttributedStringGetString(CFAttributedStringRef aStr);

typedef struct { CFIndex location; CFIndex length; } CFRange;
CT_INLINE CFRange CFRangeMake(CFIndex loc, CFIndex len) {
    CFRange r = { loc, len };
    return r;
}

extern CFDictionaryRef CFAttributedStringGetAttributes(CFAttributedStringRef aStr, CFIndex loc, CFRange *effectiveRange);

/* ============================================================================
 * Section 5: CoreGraphics Imported Types & Functions
 * ============================================================================ */

struct CGPoint { CGFloat x; CGFloat y; };
typedef struct CGPoint CGPoint;

struct CGSize { CGFloat width; CGFloat height; };
typedef struct CGSize CGSize;

struct CGRect { CGPoint origin; CGSize size; };
typedef struct CGRect CGRect;

CT_INLINE CGPoint CGPointMake(CGFloat x, CGFloat y) {
    CGPoint p = { x, y };
    return p;
}

CT_INLINE CGSize CGSizeMake(CGFloat w, CGFloat h) {
    CGSize s = { w, h };
    return s;
}

CT_INLINE CGRect CGRectMake(CGFloat x, CGFloat y, CGFloat w, CGFloat h) {
    CGRect r = { { x, y }, { w, h } };
    return r;
}

#define CGPointZero ((CGPoint){ 0.0, 0.0 })
#define CGSizeZero  ((CGSize){ 0.0, 0.0 })
#define CGRectZero  ((CGRect){ { 0.0, 0.0 }, { 0.0, 0.0 } })

typedef struct CGAffineTransform {
    CGFloat a, b, c, d, tx, ty;
} CGAffineTransform;

extern const CGAffineTransform CGAffineTransformIdentity;

/* CGContext — we need the struct layout to blit pixels directly.
 * This MUST match CoreGraphics.c's struct CGContext exactly. */

typedef int32_t CGBlendMode;
typedef int32_t CGLineCap;
typedef int32_t CGLineJoin;
typedef int32_t CGTextDrawingMode;
typedef int32_t CGInterpolationQuality;
typedef uint32_t CGBitmapInfo;

/* Internal refcount header — matches CoreGraphics */
typedef struct { int32_t _refCount; } __CGRefCounted;
typedef int32_t __CGContextType;

/* GState — matches CoreGraphics __CGGState exactly */
typedef struct __CGGState {
    CGFloat fillColor[4];
    CGFloat strokeColor[4];
    CGAffineTransform ctm;
    CGRect clipRect;
    CGFloat lineWidth;
    CGLineCap lineCap;
    CGLineJoin lineJoin;
    CGFloat miterLimit;
    CGFloat flatness;
    CGBlendMode blendMode;
    CGFloat alpha;
    bool shouldAntialias;
    CGTextDrawingMode textDrawingMode;
    CGFloat characterSpacing;
    CGPoint textPosition;
    CGInterpolationQuality interpolationQuality;
    CGSize shadowOffset;
    CGFloat shadowBlur;
    struct __CGGState *_prev;
} __CGGState;

/* CGPath forward declaration */
typedef void *CGMutablePathRef;
typedef const void *CGColorSpaceRef;

/* CGContext struct — must match CoreGraphics.c layout exactly */
struct CGContext {
    __CGRefCounted   _rc;
    __CGContextType  _type;
    __CGGState      *_gstate;
    CGMutablePathRef _path;
    void            *_data;
    size_t           _width;
    size_t           _height;
    size_t           _bitsPerComponent;
    size_t           _bytesPerRow;
    CGColorSpaceRef  _colorSpace;
    CGBitmapInfo     _bitmapInfo;
    bool             _ownsData;
};
typedef struct CGContext *CGContextRef;

/* CGColor */
extern void *CGColorCreate(CGColorSpaceRef space, const CGFloat *components);
extern void  CGColorRelease(void *color);
extern const CGFloat *CGColorGetComponents(void *color);
extern void *CGColorSpaceCreateDeviceRGB(void);
extern void  CGColorSpaceRelease(void *colorSpace);

/* CGContext drawing functions we call */
extern void CGContextSetRGBFillColor(CGContextRef c, CGFloat r, CGFloat g, CGFloat b, CGFloat a);
extern void CGContextFillRect(CGContextRef c, CGRect rect);
extern void CGContextSetFillColorWithColor(CGContextRef c, void *color);

/* CGPath */
extern void *CGPathCreateMutable(void);
extern void  CGPathRelease(void *path);

/* ============================================================================
 * Section 6: Embedded 8×16 Bitmap Font (CP437 / IBM PC VGA)
 *
 * Identical data to kernel/kern/font8x16.c but as a userspace copy.
 * 256 glyphs × 16 rows × 1 byte per row = 4096 bytes.
 * MSB = leftmost pixel. Row-major, top-to-bottom.
 * ============================================================================ */

static const uint8_t __CTBitmapFontData[256][16] = {
    /* 0x00 */ { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0x01 */ { 0x00,0x00,0x7e,0x81,0xa5,0x81,0x81,0xbd,0x99,0x81,0x81,0x7e,0x00,0x00,0x00,0x00 },
    /* 0x02 */ { 0x00,0x00,0x7e,0xff,0xdb,0xff,0xff,0xc3,0xe7,0xff,0xff,0x7e,0x00,0x00,0x00,0x00 },
    /* 0x03 */ { 0x00,0x00,0x00,0x00,0x6c,0xfe,0xfe,0xfe,0xfe,0x7c,0x38,0x10,0x00,0x00,0x00,0x00 },
    /* 0x04 */ { 0x00,0x00,0x00,0x00,0x10,0x38,0x7c,0xfe,0x7c,0x38,0x10,0x00,0x00,0x00,0x00,0x00 },
    /* 0x05 */ { 0x00,0x00,0x00,0x18,0x3c,0x3c,0xe7,0xe7,0xe7,0x18,0x18,0x3c,0x00,0x00,0x00,0x00 },
    /* 0x06 */ { 0x00,0x00,0x00,0x18,0x3c,0x7e,0xff,0xff,0x7e,0x18,0x18,0x3c,0x00,0x00,0x00,0x00 },
    /* 0x07 */ { 0x00,0x00,0x00,0x00,0x00,0x00,0x18,0x3c,0x3c,0x18,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0x08 */ { 0xff,0xff,0xff,0xff,0xff,0xff,0xe7,0xc3,0xc3,0xe7,0xff,0xff,0xff,0xff,0xff,0xff },
    /* 0x09 */ { 0x00,0x00,0x00,0x00,0x00,0x3c,0x66,0x42,0x42,0x66,0x3c,0x00,0x00,0x00,0x00,0x00 },
    /* 0x0A */ { 0xff,0xff,0xff,0xff,0xff,0xc3,0x99,0xbd,0xbd,0x99,0xc3,0xff,0xff,0xff,0xff,0xff },
    /* 0x0B */ { 0x00,0x00,0x1e,0x0e,0x1a,0x32,0x78,0xcc,0xcc,0xcc,0xcc,0x78,0x00,0x00,0x00,0x00 },
    /* 0x0C */ { 0x00,0x00,0x3c,0x66,0x66,0x66,0x66,0x3c,0x18,0x7e,0x18,0x18,0x00,0x00,0x00,0x00 },
    /* 0x0D */ { 0x00,0x00,0x3f,0x33,0x3f,0x30,0x30,0x30,0x30,0x70,0xf0,0xe0,0x00,0x00,0x00,0x00 },
    /* 0x0E */ { 0x00,0x00,0x7f,0x63,0x7f,0x63,0x63,0x63,0x63,0x67,0xe7,0xe6,0xc0,0x00,0x00,0x00 },
    /* 0x0F */ { 0x00,0x00,0x00,0x18,0x18,0xdb,0x3c,0xe7,0x3c,0xdb,0x18,0x18,0x00,0x00,0x00,0x00 },
    /* 0x10 */ { 0x00,0x80,0xc0,0xe0,0xf0,0xf8,0xfe,0xf8,0xf0,0xe0,0xc0,0x80,0x00,0x00,0x00,0x00 },
    /* 0x11 */ { 0x00,0x02,0x06,0x0e,0x1e,0x3e,0xfe,0x3e,0x1e,0x0e,0x06,0x02,0x00,0x00,0x00,0x00 },
    /* 0x12 */ { 0x00,0x00,0x18,0x3c,0x7e,0x18,0x18,0x18,0x7e,0x3c,0x18,0x00,0x00,0x00,0x00,0x00 },
    /* 0x13 */ { 0x00,0x00,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x00,0x66,0x66,0x00,0x00,0x00,0x00 },
    /* 0x14 */ { 0x00,0x00,0x7f,0xdb,0xdb,0xdb,0x7b,0x1b,0x1b,0x1b,0x1b,0x1b,0x00,0x00,0x00,0x00 },
    /* 0x15 */ { 0x00,0x7c,0xc6,0x60,0x38,0x6c,0xc6,0xc6,0x6c,0x38,0x0c,0xc6,0x7c,0x00,0x00,0x00 },
    /* 0x16 */ { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xfe,0xfe,0xfe,0xfe,0x00,0x00,0x00,0x00 },
    /* 0x17 */ { 0x00,0x00,0x18,0x3c,0x7e,0x18,0x18,0x18,0x7e,0x3c,0x18,0x7e,0x00,0x00,0x00,0x00 },
    /* 0x18 */ { 0x00,0x00,0x18,0x3c,0x7e,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x00,0x00,0x00,0x00 },
    /* 0x19 */ { 0x00,0x00,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x7e,0x3c,0x18,0x00,0x00,0x00,0x00 },
    /* 0x1A */ { 0x00,0x00,0x00,0x00,0x00,0x18,0x0c,0xfe,0x0c,0x18,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0x1B */ { 0x00,0x00,0x00,0x00,0x00,0x30,0x60,0xfe,0x60,0x30,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0x1C */ { 0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0xc0,0xc0,0xfe,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0x1D */ { 0x00,0x00,0x00,0x00,0x00,0x24,0x66,0xff,0x66,0x24,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0x1E */ { 0x00,0x00,0x00,0x00,0x10,0x38,0x38,0x7c,0x7c,0xfe,0xfe,0x00,0x00,0x00,0x00,0x00 },
    /* 0x1F */ { 0x00,0x00,0x00,0x00,0xfe,0xfe,0x7c,0x7c,0x38,0x38,0x10,0x00,0x00,0x00,0x00,0x00 },
    /* 0x20 */ { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0x21 */ { 0x00,0x00,0x18,0x3c,0x3c,0x3c,0x18,0x18,0x18,0x00,0x18,0x18,0x00,0x00,0x00,0x00 },
    /* 0x22 */ { 0x00,0x66,0x66,0x66,0x24,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0x23 */ { 0x00,0x00,0x00,0x6c,0x6c,0xfe,0x6c,0x6c,0x6c,0xfe,0x6c,0x6c,0x00,0x00,0x00,0x00 },
    /* 0x24 */ { 0x18,0x18,0x7c,0xc6,0xc2,0xc0,0x7c,0x06,0x06,0x86,0xc6,0x7c,0x18,0x18,0x00,0x00 },
    /* 0x25 */ { 0x00,0x00,0x00,0x00,0xc2,0xc6,0x0c,0x18,0x30,0x60,0xc6,0x86,0x00,0x00,0x00,0x00 },
    /* 0x26 */ { 0x00,0x00,0x38,0x6c,0x6c,0x38,0x76,0xdc,0xcc,0xcc,0xcc,0x76,0x00,0x00,0x00,0x00 },
    /* 0x27 */ { 0x00,0x30,0x30,0x30,0x60,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0x28 */ { 0x00,0x00,0x0c,0x18,0x30,0x30,0x30,0x30,0x30,0x30,0x18,0x0c,0x00,0x00,0x00,0x00 },
    /* 0x29 */ { 0x00,0x00,0x30,0x18,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x18,0x30,0x00,0x00,0x00,0x00 },
    /* 0x2A */ { 0x00,0x00,0x00,0x00,0x00,0x66,0x3c,0xff,0x3c,0x66,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0x2B */ { 0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x7e,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0x2C */ { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x18,0x30,0x00,0x00,0x00 },
    /* 0x2D */ { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xfe,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0x2E */ { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x00,0x00,0x00,0x00 },
    /* 0x2F */ { 0x00,0x00,0x00,0x00,0x02,0x06,0x0c,0x18,0x30,0x60,0xc0,0x80,0x00,0x00,0x00,0x00 },
    /* 0x30 */ { 0x00,0x00,0x7c,0xc6,0xc6,0xce,0xde,0xf6,0xe6,0xc6,0xc6,0x7c,0x00,0x00,0x00,0x00 },
    /* 0x31 */ { 0x00,0x00,0x18,0x38,0x78,0x18,0x18,0x18,0x18,0x18,0x18,0x7e,0x00,0x00,0x00,0x00 },
    /* 0x32 */ { 0x00,0x00,0x7c,0xc6,0x06,0x0c,0x18,0x30,0x60,0xc0,0xc6,0xfe,0x00,0x00,0x00,0x00 },
    /* 0x33 */ { 0x00,0x00,0x7c,0xc6,0x06,0x06,0x3c,0x06,0x06,0x06,0xc6,0x7c,0x00,0x00,0x00,0x00 },
    /* 0x34 */ { 0x00,0x00,0x0c,0x1c,0x3c,0x6c,0xcc,0xfe,0x0c,0x0c,0x0c,0x1e,0x00,0x00,0x00,0x00 },
    /* 0x35 */ { 0x00,0x00,0xfe,0xc0,0xc0,0xc0,0xfc,0x06,0x06,0x06,0xc6,0x7c,0x00,0x00,0x00,0x00 },
    /* 0x36 */ { 0x00,0x00,0x38,0x60,0xc0,0xc0,0xfc,0xc6,0xc6,0xc6,0xc6,0x7c,0x00,0x00,0x00,0x00 },
    /* 0x37 */ { 0x00,0x00,0xfe,0xc6,0x06,0x06,0x0c,0x18,0x30,0x30,0x30,0x30,0x00,0x00,0x00,0x00 },
    /* 0x38 */ { 0x00,0x00,0x7c,0xc6,0xc6,0xc6,0x7c,0xc6,0xc6,0xc6,0xc6,0x7c,0x00,0x00,0x00,0x00 },
    /* 0x39 */ { 0x00,0x00,0x7c,0xc6,0xc6,0xc6,0x7e,0x06,0x06,0x06,0x0c,0x78,0x00,0x00,0x00,0x00 },
    /* 0x3A */ { 0x00,0x00,0x00,0x00,0x18,0x18,0x00,0x00,0x00,0x18,0x18,0x00,0x00,0x00,0x00,0x00 },
    /* 0x3B */ { 0x00,0x00,0x00,0x00,0x18,0x18,0x00,0x00,0x00,0x18,0x18,0x30,0x00,0x00,0x00,0x00 },
    /* 0x3C */ { 0x00,0x00,0x00,0x06,0x0c,0x18,0x30,0x60,0x30,0x18,0x0c,0x06,0x00,0x00,0x00,0x00 },
    /* 0x3D */ { 0x00,0x00,0x00,0x00,0x00,0x7e,0x00,0x00,0x7e,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0x3E */ { 0x00,0x00,0x00,0x60,0x30,0x18,0x0c,0x06,0x0c,0x18,0x30,0x60,0x00,0x00,0x00,0x00 },
    /* 0x3F */ { 0x00,0x00,0x7c,0xc6,0xc6,0x0c,0x18,0x18,0x18,0x00,0x18,0x18,0x00,0x00,0x00,0x00 },
    /* 0x40 */ { 0x00,0x00,0x00,0x7c,0xc6,0xc6,0xde,0xde,0xde,0xdc,0xc0,0x7c,0x00,0x00,0x00,0x00 },
    /* 0x41 */ { 0x00,0x00,0x10,0x38,0x6c,0xc6,0xc6,0xfe,0xc6,0xc6,0xc6,0xc6,0x00,0x00,0x00,0x00 },
    /* 0x42 */ { 0x00,0x00,0xfc,0x66,0x66,0x66,0x7c,0x66,0x66,0x66,0x66,0xfc,0x00,0x00,0x00,0x00 },
    /* 0x43 */ { 0x00,0x00,0x3c,0x66,0xc2,0xc0,0xc0,0xc0,0xc0,0xc2,0x66,0x3c,0x00,0x00,0x00,0x00 },
    /* 0x44 */ { 0x00,0x00,0xf8,0x6c,0x66,0x66,0x66,0x66,0x66,0x66,0x6c,0xf8,0x00,0x00,0x00,0x00 },
    /* 0x45 */ { 0x00,0x00,0xfe,0x66,0x62,0x68,0x78,0x68,0x60,0x62,0x66,0xfe,0x00,0x00,0x00,0x00 },
    /* 0x46 */ { 0x00,0x00,0xfe,0x66,0x62,0x68,0x78,0x68,0x60,0x60,0x60,0xf0,0x00,0x00,0x00,0x00 },
    /* 0x47 */ { 0x00,0x00,0x3c,0x66,0xc2,0xc0,0xc0,0xde,0xc6,0xc6,0x66,0x3a,0x00,0x00,0x00,0x00 },
    /* 0x48 */ { 0x00,0x00,0xc6,0xc6,0xc6,0xc6,0xfe,0xc6,0xc6,0xc6,0xc6,0xc6,0x00,0x00,0x00,0x00 },
    /* 0x49 */ { 0x00,0x00,0x3c,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x3c,0x00,0x00,0x00,0x00 },
    /* 0x4A */ { 0x00,0x00,0x1e,0x0c,0x0c,0x0c,0x0c,0x0c,0xcc,0xcc,0xcc,0x78,0x00,0x00,0x00,0x00 },
    /* 0x4B */ { 0x00,0x00,0xe6,0x66,0x66,0x6c,0x78,0x78,0x6c,0x66,0x66,0xe6,0x00,0x00,0x00,0x00 },
    /* 0x4C */ { 0x00,0x00,0xf0,0x60,0x60,0x60,0x60,0x60,0x60,0x62,0x66,0xfe,0x00,0x00,0x00,0x00 },
    /* 0x4D */ { 0x00,0x00,0xc6,0xee,0xfe,0xfe,0xd6,0xc6,0xc6,0xc6,0xc6,0xc6,0x00,0x00,0x00,0x00 },
    /* 0x4E */ { 0x00,0x00,0xc6,0xe6,0xf6,0xfe,0xde,0xce,0xc6,0xc6,0xc6,0xc6,0x00,0x00,0x00,0x00 },
    /* 0x4F */ { 0x00,0x00,0x7c,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0x7c,0x00,0x00,0x00,0x00 },
    /* 0x50 */ { 0x00,0x00,0xfc,0x66,0x66,0x66,0x7c,0x60,0x60,0x60,0x60,0xf0,0x00,0x00,0x00,0x00 },
    /* 0x51 */ { 0x00,0x00,0x7c,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0xd6,0xde,0x7c,0x0c,0x0e,0x00,0x00 },
    /* 0x52 */ { 0x00,0x00,0xfc,0x66,0x66,0x66,0x7c,0x6c,0x66,0x66,0x66,0xe6,0x00,0x00,0x00,0x00 },
    /* 0x53 */ { 0x00,0x00,0x7c,0xc6,0xc6,0x60,0x38,0x0c,0x06,0xc6,0xc6,0x7c,0x00,0x00,0x00,0x00 },
    /* 0x54 */ { 0x00,0x00,0xff,0xdb,0x99,0x18,0x18,0x18,0x18,0x18,0x18,0x3c,0x00,0x00,0x00,0x00 },
    /* 0x55 */ { 0x00,0x00,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0x7c,0x00,0x00,0x00,0x00 },
    /* 0x56 */ { 0x00,0x00,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0x6c,0x38,0x10,0x00,0x00,0x00,0x00 },
    /* 0x57 */ { 0x00,0x00,0xc6,0xc6,0xc6,0xc6,0xd6,0xd6,0xd6,0xfe,0xee,0x6c,0x00,0x00,0x00,0x00 },
    /* 0x58 */ { 0x00,0x00,0xc6,0xc6,0x6c,0x7c,0x38,0x38,0x7c,0x6c,0xc6,0xc6,0x00,0x00,0x00,0x00 },
    /* 0x59 */ { 0x00,0x00,0xc6,0xc6,0xc6,0x6c,0x38,0x18,0x18,0x18,0x18,0x3c,0x00,0x00,0x00,0x00 },
    /* 0x5A */ { 0x00,0x00,0xfe,0xc6,0x86,0x0c,0x18,0x30,0x60,0xc2,0xc6,0xfe,0x00,0x00,0x00,0x00 },
    /* 0x5B */ { 0x00,0x00,0x3c,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x3c,0x00,0x00,0x00,0x00 },
    /* 0x5C */ { 0x00,0x00,0x00,0x80,0xc0,0xe0,0x70,0x38,0x1c,0x0e,0x06,0x02,0x00,0x00,0x00,0x00 },
    /* 0x5D */ { 0x00,0x00,0x3c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x3c,0x00,0x00,0x00,0x00 },
    /* 0x5E */ { 0x10,0x38,0x6c,0xc6,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0x5F */ { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0x00,0x00,0x00 },
    /* 0x60 */ { 0x30,0x30,0x18,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0x61 */ { 0x00,0x00,0x00,0x00,0x00,0x78,0x0c,0x7c,0xcc,0xcc,0xcc,0x76,0x00,0x00,0x00,0x00 },
    /* 0x62 */ { 0x00,0x00,0xe0,0x60,0x60,0x78,0x6c,0x66,0x66,0x66,0x66,0x7c,0x00,0x00,0x00,0x00 },
    /* 0x63 */ { 0x00,0x00,0x00,0x00,0x00,0x7c,0xc6,0xc0,0xc0,0xc0,0xc6,0x7c,0x00,0x00,0x00,0x00 },
    /* 0x64 */ { 0x00,0x00,0x1c,0x0c,0x0c,0x3c,0x6c,0xcc,0xcc,0xcc,0xcc,0x76,0x00,0x00,0x00,0x00 },
    /* 0x65 */ { 0x00,0x00,0x00,0x00,0x00,0x7c,0xc6,0xfe,0xc0,0xc0,0xc6,0x7c,0x00,0x00,0x00,0x00 },
    /* 0x66 */ { 0x00,0x00,0x38,0x6c,0x64,0x60,0xf0,0x60,0x60,0x60,0x60,0xf0,0x00,0x00,0x00,0x00 },
    /* 0x67 */ { 0x00,0x00,0x00,0x00,0x00,0x76,0xcc,0xcc,0xcc,0xcc,0xcc,0x7c,0x0c,0xcc,0x78,0x00 },
    /* 0x68 */ { 0x00,0x00,0xe0,0x60,0x60,0x6c,0x76,0x66,0x66,0x66,0x66,0xe6,0x00,0x00,0x00,0x00 },
    /* 0x69 */ { 0x00,0x00,0x18,0x18,0x00,0x38,0x18,0x18,0x18,0x18,0x18,0x3c,0x00,0x00,0x00,0x00 },
    /* 0x6A */ { 0x00,0x00,0x06,0x06,0x00,0x0e,0x06,0x06,0x06,0x06,0x06,0x06,0x66,0x66,0x3c,0x00 },
    /* 0x6B */ { 0x00,0x00,0xe0,0x60,0x60,0x66,0x6c,0x78,0x78,0x6c,0x66,0xe6,0x00,0x00,0x00,0x00 },
    /* 0x6C */ { 0x00,0x00,0x38,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x3c,0x00,0x00,0x00,0x00 },
    /* 0x6D */ { 0x00,0x00,0x00,0x00,0x00,0xec,0xfe,0xd6,0xd6,0xd6,0xd6,0xc6,0x00,0x00,0x00,0x00 },
    /* 0x6E */ { 0x00,0x00,0x00,0x00,0x00,0xdc,0x66,0x66,0x66,0x66,0x66,0x66,0x00,0x00,0x00,0x00 },
    /* 0x6F */ { 0x00,0x00,0x00,0x00,0x00,0x7c,0xc6,0xc6,0xc6,0xc6,0xc6,0x7c,0x00,0x00,0x00,0x00 },
    /* 0x70 */ { 0x00,0x00,0x00,0x00,0x00,0xdc,0x66,0x66,0x66,0x66,0x66,0x7c,0x60,0x60,0xf0,0x00 },
    /* 0x71 */ { 0x00,0x00,0x00,0x00,0x00,0x76,0xcc,0xcc,0xcc,0xcc,0xcc,0x7c,0x0c,0x0c,0x1e,0x00 },
    /* 0x72 */ { 0x00,0x00,0x00,0x00,0x00,0xdc,0x76,0x66,0x60,0x60,0x60,0xf0,0x00,0x00,0x00,0x00 },
    /* 0x73 */ { 0x00,0x00,0x00,0x00,0x00,0x7c,0xc6,0x60,0x38,0x0c,0xc6,0x7c,0x00,0x00,0x00,0x00 },
    /* 0x74 */ { 0x00,0x00,0x10,0x30,0x30,0xfc,0x30,0x30,0x30,0x30,0x36,0x1c,0x00,0x00,0x00,0x00 },
    /* 0x75 */ { 0x00,0x00,0x00,0x00,0x00,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0x76,0x00,0x00,0x00,0x00 },
    /* 0x76 */ { 0x00,0x00,0x00,0x00,0x00,0xc6,0xc6,0xc6,0xc6,0xc6,0x6c,0x38,0x00,0x00,0x00,0x00 },
    /* 0x77 */ { 0x00,0x00,0x00,0x00,0x00,0xc6,0xc6,0xd6,0xd6,0xd6,0xfe,0x6c,0x00,0x00,0x00,0x00 },
    /* 0x78 */ { 0x00,0x00,0x00,0x00,0x00,0xc6,0x6c,0x38,0x38,0x38,0x6c,0xc6,0x00,0x00,0x00,0x00 },
    /* 0x79 */ { 0x00,0x00,0x00,0x00,0x00,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0x7e,0x06,0x0c,0xf8,0x00 },
    /* 0x7A */ { 0x00,0x00,0x00,0x00,0x00,0xfe,0xcc,0x18,0x30,0x60,0xc6,0xfe,0x00,0x00,0x00,0x00 },
    /* 0x7B */ { 0x00,0x00,0x0e,0x18,0x18,0x18,0x70,0x18,0x18,0x18,0x18,0x0e,0x00,0x00,0x00,0x00 },
    /* 0x7C */ { 0x00,0x00,0x18,0x18,0x18,0x18,0x00,0x18,0x18,0x18,0x18,0x18,0x00,0x00,0x00,0x00 },
    /* 0x7D */ { 0x00,0x00,0x70,0x18,0x18,0x18,0x0e,0x18,0x18,0x18,0x18,0x70,0x00,0x00,0x00,0x00 },
    /* 0x7E */ { 0x00,0x00,0x76,0xdc,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0x7F */ { 0x00,0x00,0x00,0x00,0x10,0x38,0x6c,0xc6,0xc6,0xfe,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0x80 */ { 0x00,0x00,0x3c,0x66,0xc2,0xc0,0xc0,0xc0,0xc2,0x66,0x3c,0x0c,0x06,0x7c,0x00,0x00 },
    /* 0x81 */ { 0x00,0x00,0xcc,0x00,0x00,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0x76,0x00,0x00,0x00,0x00 },
    /* 0x82 */ { 0x00,0x0c,0x18,0x30,0x00,0x7c,0xc6,0xfe,0xc0,0xc0,0xc6,0x7c,0x00,0x00,0x00,0x00 },
    /* 0x83 */ { 0x00,0x10,0x38,0x6c,0x00,0x78,0x0c,0x7c,0xcc,0xcc,0xcc,0x76,0x00,0x00,0x00,0x00 },
    /* 0x84 */ { 0x00,0x00,0xcc,0x00,0x00,0x78,0x0c,0x7c,0xcc,0xcc,0xcc,0x76,0x00,0x00,0x00,0x00 },
    /* 0x85 */ { 0x00,0x60,0x30,0x18,0x00,0x78,0x0c,0x7c,0xcc,0xcc,0xcc,0x76,0x00,0x00,0x00,0x00 },
    /* 0x86 */ { 0x00,0x38,0x6c,0x38,0x00,0x78,0x0c,0x7c,0xcc,0xcc,0xcc,0x76,0x00,0x00,0x00,0x00 },
    /* 0x87 */ { 0x00,0x00,0x00,0x00,0x00,0x7c,0xc6,0xc0,0xc0,0xc0,0xc6,0x7c,0x18,0x70,0x00,0x00 },
    /* 0x88 */ { 0x00,0x10,0x38,0x6c,0x00,0x7c,0xc6,0xfe,0xc0,0xc0,0xc6,0x7c,0x00,0x00,0x00,0x00 },
    /* 0x89 */ { 0x00,0x00,0xc6,0x00,0x00,0x7c,0xc6,0xfe,0xc0,0xc0,0xc6,0x7c,0x00,0x00,0x00,0x00 },
    /* 0x8A */ { 0x00,0x60,0x30,0x18,0x00,0x7c,0xc6,0xfe,0xc0,0xc0,0xc6,0x7c,0x00,0x00,0x00,0x00 },
    /* 0x8B */ { 0x00,0x00,0x66,0x00,0x00,0x38,0x18,0x18,0x18,0x18,0x18,0x3c,0x00,0x00,0x00,0x00 },
    /* 0x8C */ { 0x00,0x18,0x3c,0x66,0x00,0x38,0x18,0x18,0x18,0x18,0x18,0x3c,0x00,0x00,0x00,0x00 },
    /* 0x8D */ { 0x00,0x60,0x30,0x18,0x00,0x38,0x18,0x18,0x18,0x18,0x18,0x3c,0x00,0x00,0x00,0x00 },
    /* 0x8E */ { 0x00,0xc6,0x00,0x10,0x38,0x6c,0xc6,0xc6,0xfe,0xc6,0xc6,0xc6,0x00,0x00,0x00,0x00 },
    /* 0x8F */ { 0x38,0x6c,0x38,0x10,0x38,0x6c,0xc6,0xfe,0xc6,0xc6,0xc6,0xc6,0x00,0x00,0x00,0x00 },
    /* 0x90 */ { 0x0c,0x18,0x00,0xfe,0x66,0x62,0x68,0x78,0x68,0x62,0x66,0xfe,0x00,0x00,0x00,0x00 },
    /* 0x91 */ { 0x00,0x00,0x00,0x00,0x00,0x6e,0x3b,0x1b,0x7e,0xd8,0xdc,0x77,0x00,0x00,0x00,0x00 },
    /* 0x92 */ { 0x00,0x00,0x3e,0x6c,0xcc,0xcc,0xfe,0xcc,0xcc,0xcc,0xcc,0xce,0x00,0x00,0x00,0x00 },
    /* 0x93 */ { 0x00,0x10,0x38,0x6c,0x00,0x7c,0xc6,0xc6,0xc6,0xc6,0xc6,0x7c,0x00,0x00,0x00,0x00 },
    /* 0x94 */ { 0x00,0x00,0xc6,0x00,0x00,0x7c,0xc6,0xc6,0xc6,0xc6,0xc6,0x7c,0x00,0x00,0x00,0x00 },
    /* 0x95 */ { 0x00,0x60,0x30,0x18,0x00,0x7c,0xc6,0xc6,0xc6,0xc6,0xc6,0x7c,0x00,0x00,0x00,0x00 },
    /* 0x96 */ { 0x00,0x30,0x78,0xcc,0x00,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0x76,0x00,0x00,0x00,0x00 },
    /* 0x97 */ { 0x00,0x60,0x30,0x18,0x00,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0x76,0x00,0x00,0x00,0x00 },
    /* 0x98 */ { 0x00,0x00,0xc6,0x00,0x00,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0x7e,0x06,0x0c,0x78,0x00 },
    /* 0x99 */ { 0x00,0xc6,0x00,0x7c,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0x7c,0x00,0x00,0x00,0x00 },
    /* 0x9A */ { 0x00,0xc6,0x00,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0x7c,0x00,0x00,0x00,0x00 },
    /* 0x9B */ { 0x00,0x18,0x18,0x7c,0xc6,0xc0,0xc0,0xc0,0xc6,0x7c,0x18,0x18,0x00,0x00,0x00,0x00 },
    /* 0x9C */ { 0x00,0x38,0x6c,0x64,0x60,0xf0,0x60,0x60,0x60,0x60,0xe6,0xfc,0x00,0x00,0x00,0x00 },
    /* 0x9D */ { 0x00,0x00,0xc6,0xc6,0x6c,0x6c,0x38,0xfe,0x38,0xfe,0x38,0x38,0x00,0x00,0x00,0x00 },
    /* 0x9E */ { 0x00,0xf8,0xcc,0xcc,0xf8,0xc4,0xcc,0xde,0xcc,0xcc,0xcc,0xc6,0x00,0x00,0x00,0x00 },
    /* 0x9F */ { 0x00,0x0e,0x1b,0x18,0x18,0x18,0x7e,0x18,0x18,0x18,0xd8,0x70,0x00,0x00,0x00,0x00 },
    /* 0xA0 */ { 0x00,0x18,0x30,0x60,0x00,0x78,0x0c,0x7c,0xcc,0xcc,0xcc,0x76,0x00,0x00,0x00,0x00 },
    /* 0xA1 */ { 0x00,0x0c,0x18,0x30,0x00,0x38,0x18,0x18,0x18,0x18,0x18,0x3c,0x00,0x00,0x00,0x00 },
    /* 0xA2 */ { 0x00,0x18,0x30,0x60,0x00,0x7c,0xc6,0xc6,0xc6,0xc6,0xc6,0x7c,0x00,0x00,0x00,0x00 },
    /* 0xA3 */ { 0x00,0x18,0x30,0x60,0x00,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0x76,0x00,0x00,0x00,0x00 },
    /* 0xA4 */ { 0x00,0x00,0x76,0xdc,0x00,0xdc,0x66,0x66,0x66,0x66,0x66,0x66,0x00,0x00,0x00,0x00 },
    /* 0xA5 */ { 0x76,0xdc,0x00,0xc6,0xe6,0xf6,0xfe,0xde,0xce,0xc6,0xc6,0xc6,0x00,0x00,0x00,0x00 },
    /* 0xA6 */ { 0x00,0x3c,0x6c,0x6c,0x3e,0x00,0x7e,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0xA7 */ { 0x00,0x38,0x6c,0x6c,0x38,0x00,0x7c,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0xA8 */ { 0x00,0x00,0x30,0x30,0x00,0x30,0x30,0x60,0xc0,0xc6,0xc6,0x7c,0x00,0x00,0x00,0x00 },
    /* 0xA9 */ { 0x00,0x00,0x00,0x00,0x00,0x00,0xfe,0xc0,0xc0,0xc0,0xc0,0x00,0x00,0x00,0x00,0x00 },
    /* 0xAA */ { 0x00,0x00,0x00,0x00,0x00,0x00,0xfe,0x06,0x06,0x06,0x06,0x00,0x00,0x00,0x00,0x00 },
    /* 0xAB */ { 0x00,0xc0,0xc0,0xc2,0xc6,0xcc,0x18,0x30,0x60,0xce,0x9b,0x06,0x0c,0x1f,0x00,0x00 },
    /* 0xAC */ { 0x00,0xc0,0xc0,0xc2,0xc6,0xcc,0x18,0x30,0x66,0xce,0x96,0x3e,0x06,0x06,0x00,0x00 },
    /* 0xAD */ { 0x00,0x00,0x18,0x18,0x00,0x18,0x18,0x18,0x3c,0x3c,0x3c,0x18,0x00,0x00,0x00,0x00 },
    /* 0xAE */ { 0x00,0x00,0x00,0x00,0x00,0x36,0x6c,0xd8,0x6c,0x36,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0xAF */ { 0x00,0x00,0x00,0x00,0x00,0xd8,0x6c,0x36,0x6c,0xd8,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0xB0 */ { 0x11,0x44,0x11,0x44,0x11,0x44,0x11,0x44,0x11,0x44,0x11,0x44,0x11,0x44,0x11,0x44 },
    /* 0xB1 */ { 0x55,0xaa,0x55,0xaa,0x55,0xaa,0x55,0xaa,0x55,0xaa,0x55,0xaa,0x55,0xaa,0x55,0xaa },
    /* 0xB2 */ { 0xdd,0x77,0xdd,0x77,0xdd,0x77,0xdd,0x77,0xdd,0x77,0xdd,0x77,0xdd,0x77,0xdd,0x77 },
    /* 0xB3 */ { 0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18 },
    /* 0xB4 */ { 0x18,0x18,0x18,0x18,0x18,0x18,0x18,0xf8,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18 },
    /* 0xB5 */ { 0x18,0x18,0x18,0x18,0x18,0xf8,0x18,0xf8,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18 },
    /* 0xB6 */ { 0x36,0x36,0x36,0x36,0x36,0x36,0x36,0xf6,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36 },
    /* 0xB7 */ { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xfe,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36 },
    /* 0xB8 */ { 0x00,0x00,0x00,0x00,0x00,0xf8,0x18,0xf8,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18 },
    /* 0xB9 */ { 0x36,0x36,0x36,0x36,0x36,0xf6,0x06,0xf6,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36 },
    /* 0xBA */ { 0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36 },
    /* 0xBB */ { 0x00,0x00,0x00,0x00,0x00,0xfe,0x06,0xf6,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36 },
    /* 0xBC */ { 0x36,0x36,0x36,0x36,0x36,0xf6,0x06,0xfe,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0xBD */ { 0x36,0x36,0x36,0x36,0x36,0x36,0x36,0xfe,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0xBE */ { 0x18,0x18,0x18,0x18,0x18,0xf8,0x18,0xf8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0xBF */ { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xf8,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18 },
    /* 0xC0 */ { 0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x1f,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0xC1 */ { 0x18,0x18,0x18,0x18,0x18,0x18,0x18,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0xC2 */ { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18 },
    /* 0xC3 */ { 0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x1f,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18 },
    /* 0xC4 */ { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0xC5 */ { 0x18,0x18,0x18,0x18,0x18,0x18,0x18,0xff,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18 },
    /* 0xC6 */ { 0x18,0x18,0x18,0x18,0x18,0x1f,0x18,0x1f,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18 },
    /* 0xC7 */ { 0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x37,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36 },
    /* 0xC8 */ { 0x36,0x36,0x36,0x36,0x36,0x37,0x30,0x3f,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0xC9 */ { 0x00,0x00,0x00,0x00,0x00,0x3f,0x30,0x37,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36 },
    /* 0xCA */ { 0x36,0x36,0x36,0x36,0x36,0xf7,0x00,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0xCB */ { 0x00,0x00,0x00,0x00,0x00,0xff,0x00,0xf7,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36 },
    /* 0xCC */ { 0x36,0x36,0x36,0x36,0x36,0x37,0x30,0x37,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36 },
    /* 0xCD */ { 0x00,0x00,0x00,0x00,0x00,0xff,0x00,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0xCE */ { 0x36,0x36,0x36,0x36,0x36,0xf7,0x00,0xf7,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36 },
    /* 0xCF */ { 0x18,0x18,0x18,0x18,0x18,0xff,0x00,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0xD0 */ { 0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x3f,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0xD1 */ { 0x00,0x00,0x00,0x00,0x00,0xff,0x00,0xff,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18 },
    /* 0xD2 */ { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x3f,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36 },
    /* 0xD3 */ { 0x36,0x36,0x36,0x36,0x36,0x36,0x36,0xf7,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0xD4 */ { 0x18,0x18,0x18,0x18,0x18,0x1f,0x18,0x1f,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0xD5 */ { 0x00,0x00,0x00,0x00,0x00,0x1f,0x18,0x1f,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18 },
    /* 0xD6 */ { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xf7,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36 },
    /* 0xD7 */ { 0x36,0x36,0x36,0x36,0x36,0x36,0x36,0xff,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36 },
    /* 0xD8 */ { 0x18,0x18,0x18,0x18,0x18,0xff,0x18,0xff,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18 },
    /* 0xD9 */ { 0x18,0x18,0x18,0x18,0x18,0x18,0x18,0xf8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0xDA */ { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x1f,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18 },
    /* 0xDB */ { 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff },
    /* 0xDC */ { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff },
    /* 0xDD */ { 0xf0,0xf0,0xf0,0xf0,0xf0,0xf0,0xf0,0xf0,0xf0,0xf0,0xf0,0xf0,0xf0,0xf0,0xf0,0xf0 },
    /* 0xDE */ { 0x0f,0x0f,0x0f,0x0f,0x0f,0x0f,0x0f,0x0f,0x0f,0x0f,0x0f,0x0f,0x0f,0x0f,0x0f,0x0f },
    /* 0xDF */ { 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0xE0 */ { 0x00,0x00,0x00,0x00,0x00,0x76,0xdc,0xd8,0xd8,0xd8,0xdc,0x76,0x00,0x00,0x00,0x00 },
    /* 0xE1 */ { 0x00,0x00,0x78,0xcc,0xcc,0xcc,0xd8,0xcc,0xc6,0xc6,0xc6,0xcc,0x00,0x00,0x00,0x00 },
    /* 0xE2 */ { 0x00,0x00,0xfe,0xc6,0xc6,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0x00,0x00,0x00,0x00 },
    /* 0xE3 */ { 0x00,0x00,0x00,0x00,0xfe,0x6c,0x6c,0x6c,0x6c,0x6c,0x6c,0x6c,0x00,0x00,0x00,0x00 },
    /* 0xE4 */ { 0x00,0x00,0x00,0xfe,0xc6,0x60,0x30,0x18,0x30,0x60,0xc6,0xfe,0x00,0x00,0x00,0x00 },
    /* 0xE5 */ { 0x00,0x00,0x00,0x00,0x00,0x7e,0xd8,0xd8,0xd8,0xd8,0xd8,0x70,0x00,0x00,0x00,0x00 },
    /* 0xE6 */ { 0x00,0x00,0x00,0x00,0x66,0x66,0x66,0x66,0x66,0x7c,0x60,0x60,0xc0,0x00,0x00,0x00 },
    /* 0xE7 */ { 0x00,0x00,0x00,0x00,0x76,0xdc,0x18,0x18,0x18,0x18,0x18,0x18,0x00,0x00,0x00,0x00 },
    /* 0xE8 */ { 0x00,0x00,0x00,0x7e,0x18,0x3c,0x66,0x66,0x66,0x3c,0x18,0x7e,0x00,0x00,0x00,0x00 },
    /* 0xE9 */ { 0x00,0x00,0x00,0x38,0x6c,0xc6,0xc6,0xfe,0xc6,0xc6,0x6c,0x38,0x00,0x00,0x00,0x00 },
    /* 0xEA */ { 0x00,0x00,0x38,0x6c,0xc6,0xc6,0xc6,0xc6,0x6c,0x6c,0x6c,0xee,0x00,0x00,0x00,0x00 },
    /* 0xEB */ { 0x00,0x00,0x1e,0x30,0x18,0x0c,0x3e,0x66,0x66,0x66,0x66,0x3c,0x00,0x00,0x00,0x00 },
    /* 0xEC */ { 0x00,0x00,0x00,0x00,0x00,0x76,0xdb,0xdb,0xdb,0xdb,0x76,0x00,0x00,0x00,0x00,0x00 },
    /* 0xED */ { 0x00,0x00,0x00,0x02,0x06,0x7c,0xce,0xd6,0xe6,0x7c,0xc0,0x80,0x00,0x00,0x00,0x00 },
    /* 0xEE */ { 0x00,0x00,0x1c,0x30,0x60,0x60,0x7c,0x60,0x60,0x60,0x30,0x1c,0x00,0x00,0x00,0x00 },
    /* 0xEF */ { 0x00,0x00,0x00,0x7c,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0x00,0x00,0x00,0x00 },
    /* 0xF0 */ { 0x00,0x00,0x00,0x00,0xfe,0x00,0x00,0xfe,0x00,0x00,0xfe,0x00,0x00,0x00,0x00,0x00 },
    /* 0xF1 */ { 0x00,0x00,0x00,0x00,0x18,0x18,0x7e,0x18,0x18,0x00,0x00,0xff,0x00,0x00,0x00,0x00 },
    /* 0xF2 */ { 0x00,0x00,0x00,0x30,0x18,0x0c,0x06,0x0c,0x18,0x30,0x00,0x7e,0x00,0x00,0x00,0x00 },
    /* 0xF3 */ { 0x00,0x00,0x00,0x0c,0x18,0x30,0x60,0x30,0x18,0x0c,0x00,0x7e,0x00,0x00,0x00,0x00 },
    /* 0xF4 */ { 0x00,0x00,0x0e,0x1b,0x1b,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18 },
    /* 0xF5 */ { 0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0xd8,0xd8,0xd8,0x70,0x00,0x00,0x00,0x00 },
    /* 0xF6 */ { 0x00,0x00,0x00,0x00,0x18,0x18,0x00,0x7e,0x00,0x18,0x18,0x00,0x00,0x00,0x00,0x00 },
    /* 0xF7 */ { 0x00,0x00,0x00,0x00,0x00,0x76,0xdc,0x00,0x76,0xdc,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0xF8 */ { 0x00,0x38,0x6c,0x6c,0x38,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0xF9 */ { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0xFA */ { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x18,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0xFB */ { 0x00,0x0f,0x0c,0x0c,0x0c,0x0c,0x0c,0xec,0x6c,0x6c,0x3c,0x1c,0x00,0x00,0x00,0x00 },
    /* 0xFC */ { 0x00,0xd8,0x6c,0x6c,0x6c,0x6c,0x6c,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0xFD */ { 0x00,0x70,0xd8,0x30,0x60,0xc8,0xf8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
    /* 0xFE */ { 0x00,0x00,0x00,0x00,0x7c,0x7c,0x7c,0x7c,0x7c,0x7c,0x7c,0x00,0x00,0x00,0x00,0x00 },
    /* 0xFF */ { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
};

#define BITMAP_FONT_WIDTH  8
#define BITMAP_FONT_HEIGHT 16

/* ============================================================================
 * Section 7: CoreText String Attribute Keys
 *
 * These are the well-known attribute keys used in CFAttributedStrings
 * passed to CoreText. Matching macOS CTStringAttributes.h constants.
 * ============================================================================ */

/* Exported as global CFStringRef constants — created in __CTInitialize() */
EXPORT CFStringRef kCTFontAttributeName          = NULL;
EXPORT CFStringRef kCTForegroundColorAttributeName = NULL;
EXPORT CFStringRef kCTBackgroundColorAttributeName = NULL;
EXPORT CFStringRef kCTFontSizeAttribute          = NULL;
EXPORT CFStringRef kCTKernAttributeName          = NULL;
EXPORT CFStringRef kCTLigatureAttributeName      = NULL;
EXPORT CFStringRef kCTParagraphStyleAttributeName = NULL;
EXPORT CFStringRef kCTUnderlineStyleAttributeName = NULL;
EXPORT CFStringRef kCTStrokeWidthAttributeName   = NULL;
EXPORT CFStringRef kCTStrokeColorAttributeName   = NULL;
EXPORT CFStringRef kCTSuperscriptAttributeName   = NULL;

/* ============================================================================
 * Section 8: CTFont — Font Object
 *
 * Wraps the embedded 8×16 bitmap font. Supports integer scaling (1×, 2×, etc.)
 * so a "16pt" font uses the raw bitmap and a "32pt" font scales 2×.
 *
 * On real macOS, CTFont wraps CGFont and uses TrueType/OpenType outlines.
 * Here we use the bitmap font for all sizes. The "size" parameter controls
 * the integer scale factor: scale = max(1, round(size / 16.0)).
 *
 * Reference: macOS SDK CTFont.h
 * ============================================================================ */

typedef const struct __CTFont *CTFontRef;

struct __CTFont {
    intptr_t       _refCount;   /* simple refcount at offset -0 (not CF runtime) */
    CGFloat        _size;       /* requested point size */
    int            _scale;      /* integer scale factor (1=8×16, 2=16×32, etc.) */
    int            _glyphWidth; /* _scale * 8 */
    int            _glyphHeight;/* _scale * 16 */
    CGFloat        _ascent;     /* typographic ascent  = _glyphHeight * 0.75 */
    CGFloat        _descent;    /* typographic descent = _glyphHeight * 0.25 */
    CGFloat        _leading;    /* inter-line leading  = 0 */
    char           _name[64];   /* postscript name */
};

/* --- Internal: create a CTFont --- */
static CTFontRef __CTFontCreate(CGFloat size, const char *name) {
    struct __CTFont *f = (struct __CTFont *)calloc(1, sizeof(struct __CTFont));
    if (!f) return NULL;
    f->_refCount = 1;
    f->_size = size;
    /* Compute integer scale factor */
    int scale = (int)(size / 16.0 + 0.5);
    if (scale < 1) scale = 1;
    f->_scale = scale;
    f->_glyphWidth  = scale * BITMAP_FONT_WIDTH;
    f->_glyphHeight = scale * BITMAP_FONT_HEIGHT;
    /* Typographic metrics — standard VGA font has ~12px ascent, 4px descent
     * out of 16px total. We scale these proportionally. */
    f->_ascent  = (CGFloat)(scale * 12);
    f->_descent = (CGFloat)(scale * 4);
    f->_leading = 0.0;
    if (name) {
        size_t len = strlen(name);
        if (len >= 64) len = 63;
        memcpy(f->_name, name, len);
        f->_name[len] = '\0';
    } else {
        strcpy(f->_name, "KisekiSystemFont");
    }
    return (CTFontRef)f;
}

/* --- Public API --- */

EXPORT CTFontRef CTFontCreateWithName(CFStringRef name, CGFloat size,
                                       const CGAffineTransform *matrix)
{
    (void)matrix; /* transform ignored for bitmap font */
    const char *cname = NULL;
    if (name) cname = CFStringGetCStringPtr(name, kCFStringEncodingUTF8);
    if (!cname) cname = "KisekiSystemFont";
    return __CTFontCreate(size, cname);
}

EXPORT CTFontRef CTFontCreateWithFontDescriptor(const void *descriptor,
                                                 CGFloat size,
                                                 const CGAffineTransform *matrix)
{
    (void)descriptor; (void)matrix;
    return __CTFontCreate(size, "KisekiSystemFont");
}

EXPORT CTFontRef CTFontCreateCopyWithAttributes(CTFontRef font, CGFloat size,
                                                 const CGAffineTransform *matrix,
                                                 const void *attributes)
{
    (void)matrix; (void)attributes;
    if (!font) return __CTFontCreate(size, "KisekiSystemFont");
    const struct __CTFont *f = (const struct __CTFont *)font;
    return __CTFontCreate(size > 0 ? size : f->_size, f->_name);
}

EXPORT CTFontRef CTFontCreateCopyWithSymbolicTraits(CTFontRef font, CGFloat size,
                                                     const CGAffineTransform *matrix,
                                                     uint32_t symTraitValue,
                                                     uint32_t symTraitMask)
{
    (void)matrix; (void)symTraitValue; (void)symTraitMask;
    if (!font) return __CTFontCreate(size, "KisekiSystemFont");
    const struct __CTFont *f = (const struct __CTFont *)font;
    return __CTFontCreate(size > 0 ? size : f->_size, f->_name);
}

EXPORT CTFontRef CTFontRetain(CTFontRef font) {
    if (!font) return NULL;
    struct __CTFont *f = (struct __CTFont *)font;
    f->_refCount++;
    return font;
}

EXPORT void CTFontRelease(CTFontRef font) {
    if (!font) return;
    struct __CTFont *f = (struct __CTFont *)font;
    if (--f->_refCount <= 0) free(f);
}

EXPORT CGFloat CTFontGetSize(CTFontRef font) {
    if (!font) return 0.0;
    return ((const struct __CTFont *)font)->_size;
}

EXPORT CGFloat CTFontGetAscent(CTFontRef font) {
    if (!font) return 0.0;
    return ((const struct __CTFont *)font)->_ascent;
}

EXPORT CGFloat CTFontGetDescent(CTFontRef font) {
    if (!font) return 0.0;
    return ((const struct __CTFont *)font)->_descent;
}

EXPORT CGFloat CTFontGetLeading(CTFontRef font) {
    if (!font) return 0.0;
    return ((const struct __CTFont *)font)->_leading;
}

EXPORT CGFloat CTFontGetUnderlinePosition(CTFontRef font) {
    if (!font) return 0.0;
    /* Position below baseline — roughly 1/8 of glyph height */
    return -((const struct __CTFont *)font)->_descent * 0.5;
}

EXPORT CGFloat CTFontGetUnderlineThickness(CTFontRef font) {
    if (!font) return 1.0;
    return (CGFloat)((const struct __CTFont *)font)->_scale;
}

EXPORT CGRect CTFontGetBoundingBox(CTFontRef font) {
    if (!font) return CGRectZero;
    const struct __CTFont *f = (const struct __CTFont *)font;
    return CGRectMake(0.0, -(f->_descent), (CGFloat)f->_glyphWidth, (CGFloat)f->_glyphHeight);
}

EXPORT unsigned CTFontGetUnitsPerEm(CTFontRef font) {
    (void)font;
    return 2048; /* standard UPM for compatibility */
}

EXPORT CFStringRef CTFontCopyPostScriptName(CTFontRef font) {
    if (!font) return CFSTR("KisekiSystemFont");
    const struct __CTFont *f = (const struct __CTFont *)font;
    return CFStringCreateWithCString(kCFAllocatorDefault, f->_name, kCFStringEncodingUTF8);
}

EXPORT CFStringRef CTFontCopyFamilyName(CTFontRef font) {
    (void)font;
    return CFStringCreateWithCString(kCFAllocatorDefault, "Kiseki System", kCFStringEncodingUTF8);
}

EXPORT CFStringRef CTFontCopyDisplayName(CTFontRef font) {
    return CTFontCopyPostScriptName(font);
}

EXPORT CFStringRef CTFontCopyFullName(CTFontRef font) {
    return CTFontCopyPostScriptName(font);
}

/* CGFont interop — returns NULL (no CGFont in our implementation) */
EXPORT void *CTFontCopyGraphicsFont(CTFontRef font, void *descriptorOut) {
    (void)font; (void)descriptorOut;
    return NULL;
}

EXPORT CTFontRef CTFontCreateWithGraphicsFont(void *graphicsFont, CGFloat size,
                                               const CGAffineTransform *matrix,
                                               const void *attributes)
{
    (void)graphicsFont; (void)matrix; (void)attributes;
    return __CTFontCreate(size > 0 ? size : 16.0, "KisekiSystemFont");
}

/* Glyph for character — direct identity mapping (byte value = glyph index) */
EXPORT bool CTFontGetGlyphsForCharacters(CTFontRef font, const UniChar *characters,
                                          uint16_t *glyphs, CFIndex count)
{
    (void)font;
    if (!characters || !glyphs) return false;
    for (CFIndex i = 0; i < count; i++) {
        /* Map Unicode to CP437-compatible byte. For ASCII range (0x20-0x7E)
         * this is identity. Characters outside the bitmap range map to 0x00. */
        UniChar ch = characters[i];
        if (ch < 256) {
            glyphs[i] = (uint16_t)ch;
        } else {
            glyphs[i] = 0; /* unmapped → NUL glyph (blank) */
        }
    }
    return true;
}

EXPORT CGFloat CTFontGetAdvancesForGlyphs(CTFontRef font, int orientation,
                                           const uint16_t *glyphs, CGSize *advances,
                                           CFIndex count)
{
    (void)orientation;
    if (!font) return 0.0;
    const struct __CTFont *f = (const struct __CTFont *)font;
    CGFloat totalAdvance = 0.0;
    CGFloat glyphAdvance = (CGFloat)f->_glyphWidth;
    for (CFIndex i = 0; i < count; i++) {
        if (advances) advances[i] = CGSizeMake(glyphAdvance, 0.0);
        totalAdvance += glyphAdvance;
        (void)glyphs;
    }
    return totalAdvance;
}

/* ============================================================================
 * Section 9: CTRun — Glyph Run
 *
 * A contiguous sequence of glyphs with uniform attributes (same font,
 * same colour, etc.). CTLine contains one or more CTRuns.
 *
 * Reference: macOS SDK CTRun.h
 * ============================================================================ */

typedef const struct __CTRun *CTRunRef;

typedef enum {
    kCTRunStatusNoStatus    = 0,
    kCTRunStatusRightToLeft = (1 << 0),
    kCTRunStatusNonMonotonic = (1 << 1),
    kCTRunStatusHasNonIdentityMatrix = (1 << 2),
} CTRunStatus;

struct __CTRun {
    intptr_t        _refCount;
    CFIndex         _glyphCount;
    uint16_t       *_glyphs;      /* glyph indices (into bitmap font) */
    CGPoint        *_positions;    /* position of each glyph relative to run origin */
    CGSize         *_advances;     /* advance width/height per glyph */
    CFIndex        *_stringIndices;/* map glyph index → source string index */
    CFRange         _stringRange;  /* range in the source CFAttributedString */
    CTRunStatus     _status;
    CGAffineTransform _textMatrix;
    CTFontRef       _font;         /* retained */
    CGFloat         _ascent;
    CGFloat         _descent;
    CGFloat         _leading;
    CGFloat         _width;        /* total typographic width */
    /* Foreground colour (RGBA) — extracted from attributes */
    CGFloat         _fgColor[4];   /* default: black opaque */
};

static struct __CTRun *__CTRunCreate(CFIndex glyphCount) {
    struct __CTRun *r = (struct __CTRun *)calloc(1, sizeof(struct __CTRun));
    if (!r) return NULL;
    r->_refCount = 1;
    r->_glyphCount = glyphCount;
    if (glyphCount > 0) {
        r->_glyphs       = (uint16_t *)calloc((size_t)glyphCount, sizeof(uint16_t));
        r->_positions     = (CGPoint *)calloc((size_t)glyphCount, sizeof(CGPoint));
        r->_advances      = (CGSize *)calloc((size_t)glyphCount, sizeof(CGSize));
        r->_stringIndices = (CFIndex *)calloc((size_t)glyphCount, sizeof(CFIndex));
    }
    r->_status = kCTRunStatusNoStatus;
    r->_textMatrix = CGAffineTransformIdentity;
    /* Default foreground: black opaque */
    r->_fgColor[0] = 0.0; r->_fgColor[1] = 0.0;
    r->_fgColor[2] = 0.0; r->_fgColor[3] = 1.0;
    return r;
}

static void __CTRunDestroy(struct __CTRun *r) {
    if (!r) return;
    free(r->_glyphs);
    free(r->_positions);
    free(r->_advances);
    free(r->_stringIndices);
    if (r->_font) CTFontRelease(r->_font);
    free(r);
}

EXPORT CFIndex CTRunGetGlyphCount(CTRunRef run) {
    if (!run) return 0;
    return ((const struct __CTRun *)run)->_glyphCount;
}

EXPORT const uint16_t *CTRunGetGlyphsPtr(CTRunRef run) {
    if (!run) return NULL;
    return ((const struct __CTRun *)run)->_glyphs;
}

EXPORT void CTRunGetGlyphs(CTRunRef run, CFRange range, uint16_t *buffer) {
    if (!run || !buffer) return;
    const struct __CTRun *r = (const struct __CTRun *)run;
    if (range.length == 0) { range.location = 0; range.length = r->_glyphCount; }
    memcpy(buffer, r->_glyphs + range.location, (size_t)range.length * sizeof(uint16_t));
}

EXPORT const CGPoint *CTRunGetPositionsPtr(CTRunRef run) {
    if (!run) return NULL;
    return ((const struct __CTRun *)run)->_positions;
}

EXPORT void CTRunGetPositions(CTRunRef run, CFRange range, CGPoint *buffer) {
    if (!run || !buffer) return;
    const struct __CTRun *r = (const struct __CTRun *)run;
    if (range.length == 0) { range.location = 0; range.length = r->_glyphCount; }
    memcpy(buffer, r->_positions + range.location, (size_t)range.length * sizeof(CGPoint));
}

EXPORT const CGSize *CTRunGetAdvancesPtr(CTRunRef run) {
    if (!run) return NULL;
    return ((const struct __CTRun *)run)->_advances;
}

EXPORT void CTRunGetAdvances(CTRunRef run, CFRange range, CGSize *buffer) {
    if (!run || !buffer) return;
    const struct __CTRun *r = (const struct __CTRun *)run;
    if (range.length == 0) { range.location = 0; range.length = r->_glyphCount; }
    memcpy(buffer, r->_advances + range.location, (size_t)range.length * sizeof(CGSize));
}

EXPORT const CFIndex *CTRunGetStringIndicesPtr(CTRunRef run) {
    if (!run) return NULL;
    return ((const struct __CTRun *)run)->_stringIndices;
}

EXPORT void CTRunGetStringIndices(CTRunRef run, CFRange range, CFIndex *buffer) {
    if (!run || !buffer) return;
    const struct __CTRun *r = (const struct __CTRun *)run;
    if (range.length == 0) { range.location = 0; range.length = r->_glyphCount; }
    memcpy(buffer, r->_stringIndices + range.location, (size_t)range.length * sizeof(CFIndex));
}

EXPORT CFRange CTRunGetStringRange(CTRunRef run) {
    if (!run) return CFRangeMake(0, 0);
    return ((const struct __CTRun *)run)->_stringRange;
}

EXPORT CTRunStatus CTRunGetStatus(CTRunRef run) {
    if (!run) return kCTRunStatusNoStatus;
    return ((const struct __CTRun *)run)->_status;
}

EXPORT CFDictionaryRef CTRunGetAttributes(CTRunRef run) {
    (void)run;
    return NULL; /* Simplified — attributes are baked into the run */
}

EXPORT double CTRunGetTypographicBounds(CTRunRef run, CFRange range,
                                         CGFloat *ascent, CGFloat *descent,
                                         CGFloat *leading)
{
    if (!run) return 0.0;
    const struct __CTRun *r = (const struct __CTRun *)run;
    if (ascent)  *ascent  = r->_ascent;
    if (descent) *descent = r->_descent;
    if (leading) *leading = r->_leading;
    if (range.length == 0) return (double)r->_width;
    /* Partial range width */
    CGFloat w = 0;
    CFIndex end = range.location + range.length;
    if (end > r->_glyphCount) end = r->_glyphCount;
    for (CFIndex i = range.location; i < end; i++) {
        w += r->_advances[i].width;
    }
    return (double)w;
}

EXPORT CGRect CTRunGetImageBounds(CTRunRef run, CGContextRef context, CFRange range) {
    (void)context;
    if (!run) return CGRectZero;
    const struct __CTRun *r = (const struct __CTRun *)run;
    CGFloat width = (CGFloat)CTRunGetTypographicBounds(run, range, NULL, NULL, NULL);
    return CGRectMake(0, -(r->_descent), width, r->_ascent + r->_descent);
}

EXPORT CGAffineTransform CTRunGetTextMatrix(CTRunRef run) {
    if (!run) return CGAffineTransformIdentity;
    return ((const struct __CTRun *)run)->_textMatrix;
}

/* --- CTRunDraw: render a glyph run into a CGContext --- */

static void __CTRunDrawGlyph(CGContextRef ctx, uint16_t glyph, int scale,
                              int px, int py, const CGFloat fgColor[4])
{
    if (!ctx || !ctx->_data) return;
    if (glyph >= 256) return;

    uint8_t *fb = (uint8_t *)ctx->_data;
    size_t fbw = ctx->_width;
    size_t fbh = ctx->_height;
    size_t bpr = ctx->_bytesPerRow;
    CGBitmapInfo info = ctx->_bitmapInfo;

    /* Determine pixel format: BGRA (little-endian premultiplied first) or RGBA */
    /* kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little = 0x2002 → BGRA */
    bool isBGRA = ((info & 0x7000) == 0x2000); /* kCGBitmapByteOrder32Little */

    /* Convert float colour to bytes */
    uint8_t cr = (uint8_t)(fgColor[0] * 255.0 + 0.5);
    uint8_t cg = (uint8_t)(fgColor[1] * 255.0 + 0.5);
    uint8_t cb = (uint8_t)(fgColor[2] * 255.0 + 0.5);
    uint8_t ca = (uint8_t)(fgColor[3] * 255.0 + 0.5);

    const uint8_t *bitmap = __CTBitmapFontData[glyph];

    for (int row = 0; row < BITMAP_FONT_HEIGHT; row++) {
        uint8_t bits = bitmap[row];
        for (int col = 0; col < BITMAP_FONT_WIDTH; col++) {
            if (!(bits & (0x80 >> col))) continue; /* pixel not set */

            /* Scale the pixel */
            for (int sy = 0; sy < scale; sy++) {
                int fy = py + row * scale + sy;
                if (fy < 0 || (size_t)fy >= fbh) continue;
                for (int sx = 0; sx < scale; sx++) {
                    int fx = px + col * scale + sx;
                    if (fx < 0 || (size_t)fx >= fbw) continue;

                    uint8_t *pixel = fb + (size_t)fy * bpr + (size_t)fx * 4;
                    if (isBGRA) {
                        pixel[0] = cb; pixel[1] = cg; pixel[2] = cr; pixel[3] = ca;
                    } else {
                        pixel[0] = cr; pixel[1] = cg; pixel[2] = cb; pixel[3] = ca;
                    }
                }
            }
        }
    }
}

EXPORT void CTRunDraw(CTRunRef run, CGContextRef context, CFRange range) {
    if (!run || !context) return;
    const struct __CTRun *r = (const struct __CTRun *)run;
    if (!r->_font) return;
    const struct __CTFont *font = (const struct __CTFont *)r->_font;

    CFIndex start = range.location;
    CFIndex count = range.length;
    if (count == 0) { start = 0; count = r->_glyphCount; }
    CFIndex end = start + count;
    if (end > r->_glyphCount) end = r->_glyphCount;

    /* Get the text position from the context's gstate */
    CGPoint origin = CGPointZero;
    if (context->_gstate) {
        origin = context->_gstate->textPosition;
    }

    for (CFIndex i = start; i < end; i++) {
        int px = (int)(origin.x + r->_positions[i].x);
        /* CoreText uses a bottom-up coordinate system.
         * Bitmap context also uses bottom-up (row 0 = bottom).
         * The glyph position .y is the baseline y. We render the glyph
         * from (baseline - descent) to (baseline + ascent), i.e. from
         * top-of-glyph down. But in our framebuffer, y=0 is top,
         * so we flip: screen_y = height - 1 - ct_y.
         * Actually, our WindowServer uses top-down framebuffer coordinates
         * (y=0 = top of screen), so we need: screen_y = origin.y - ascent + pos.y
         * for the top of the glyph. */
        int py = (int)(origin.y + r->_positions[i].y - r->_ascent);

        __CTRunDrawGlyph(context, r->_glyphs[i], font->_scale,
                          px, py, r->_fgColor);
    }
}

/* ============================================================================
 * Section 10: CTLine — Line of Text
 *
 * Represents a single line of laid-out text. Contains one or more CTRuns.
 * Created from a CFAttributedString via CTLineCreateWithAttributedString().
 *
 * Layout algorithm:
 *   1. Extract the plain string from the attributed string.
 *   2. Get the font (from attributes, or default 16pt system font).
 *   3. Map each character to a glyph index and compute positions.
 *   4. Create a single CTRun containing all glyphs.
 *
 * Reference: macOS SDK CTLine.h
 * ============================================================================ */

typedef const struct __CTLine *CTLineRef;

typedef enum {
    kCTLineTruncationStart  = 0,
    kCTLineTruncationEnd    = 1,
    kCTLineTruncationMiddle = 2,
} CTLineTruncationType;

struct __CTLine {
    intptr_t        _refCount;
    CFIndex         _runCount;
    struct __CTRun **_runs;        /* array of runs (owned) */
    CFIndex         _stringLength; /* total characters in source string */
    CGFloat         _width;        /* total typographic width */
    CGFloat         _ascent;
    CGFloat         _descent;
    CGFloat         _leading;
    CGFloat         _penOffset;    /* for flush alignment */
};

static void __CTLineDestroy(struct __CTLine *line) {
    if (!line) return;
    for (CFIndex i = 0; i < line->_runCount; i++) {
        __CTRunDestroy(line->_runs[i]);
    }
    free(line->_runs);
    free(line);
}

/* Internal: lay out a single run from a string with uniform attributes */
static struct __CTRun *__CTLayoutRun(CFStringRef string, CFIndex start, CFIndex length,
                                      CTFontRef font, const CGFloat fgColor[4])
{
    struct __CTRun *run = __CTRunCreate(length);
    if (!run) return NULL;

    const struct __CTFont *f = (const struct __CTFont *)font;
    run->_font = CTFontRetain(font);
    run->_ascent  = f->_ascent;
    run->_descent = f->_descent;
    run->_leading = f->_leading;
    run->_stringRange = CFRangeMake(start, length);

    if (fgColor) {
        run->_fgColor[0] = fgColor[0]; run->_fgColor[1] = fgColor[1];
        run->_fgColor[2] = fgColor[2]; run->_fgColor[3] = fgColor[3];
    }

    CGFloat advance = (CGFloat)f->_glyphWidth;
    CGFloat x = 0.0;

    for (CFIndex i = 0; i < length; i++) {
        UniChar ch = CFStringGetCharacterAtIndex(string, start + i);
        /* Map to glyph — identity for CP437 range */
        run->_glyphs[i] = (ch < 256) ? (uint16_t)ch : 0;
        run->_positions[i] = CGPointMake(x, 0.0);
        run->_advances[i]  = CGSizeMake(advance, 0.0);
        run->_stringIndices[i] = start + i;
        x += advance;
    }

    run->_width = x;
    return run;
}

EXPORT CTLineRef CTLineCreateWithAttributedString(CFAttributedStringRef attrString) {
    if (!attrString) return NULL;

    CFStringRef string = CFAttributedStringGetString(attrString);
    if (!string) return NULL;
    CFIndex len = CFStringGetLength(string);
    if (len == 0) return NULL;

    /* Get attributes for the string (single-run model) */
    CFRange effectiveRange;
    CFDictionaryRef attrs = CFAttributedStringGetAttributes(attrString, 0, &effectiveRange);

    /* Extract font from attributes, or use default */
    CTFontRef font = NULL;
    if (attrs && kCTFontAttributeName) {
        font = (CTFontRef)CFDictionaryGetValue(attrs, kCTFontAttributeName);
    }
    bool ownsFont = false;
    if (!font) {
        font = __CTFontCreate(16.0, "KisekiSystemFont");
        ownsFont = true;
    }

    /* Extract foreground colour */
    CGFloat fgColor[4] = { 0.0, 0.0, 0.0, 1.0 }; /* black */
    if (attrs && kCTForegroundColorAttributeName) {
        void *color = (void *)CFDictionaryGetValue(attrs, kCTForegroundColorAttributeName);
        if (color) {
            const CGFloat *comps = CGColorGetComponents(color);
            if (comps) {
                fgColor[0] = comps[0]; fgColor[1] = comps[1];
                fgColor[2] = comps[2]; fgColor[3] = comps[3];
            }
        }
    }

    /* Create a single run for the entire string */
    struct __CTRun *run = __CTLayoutRun(string, 0, len, font, fgColor);
    if (ownsFont) CTFontRelease(font);
    if (!run) return NULL;

    /* Create the line */
    struct __CTLine *line = (struct __CTLine *)calloc(1, sizeof(struct __CTLine));
    if (!line) { __CTRunDestroy(run); return NULL; }
    line->_refCount = 1;
    line->_runCount = 1;
    line->_runs = (struct __CTRun **)malloc(sizeof(struct __CTRun *));
    if (!line->_runs) { __CTRunDestroy(run); free(line); return NULL; }
    line->_runs[0] = run;
    line->_stringLength = len;
    line->_width   = run->_width;
    line->_ascent  = run->_ascent;
    line->_descent = run->_descent;
    line->_leading = run->_leading;
    return (CTLineRef)line;
}

EXPORT CTLineRef CTLineRetain(CTLineRef line) {
    if (!line) return NULL;
    ((struct __CTLine *)line)->_refCount++;
    return line;
}

EXPORT void CTLineRelease(CTLineRef line) {
    if (!line) return;
    struct __CTLine *l = (struct __CTLine *)line;
    if (--l->_refCount <= 0) __CTLineDestroy(l);
}

/* Convenience: create a line directly from a CFString + attributes dict */
EXPORT CTLineRef CTLineCreateWithString(CFStringRef string, CFDictionaryRef attributes) {
    if (!string) return NULL;
    CFAttributedStringRef attrStr = CFAttributedStringCreate(kCFAllocatorDefault, string, attributes);
    if (!attrStr) return NULL;
    CTLineRef line = CTLineCreateWithAttributedString(attrStr);
    CFRelease((CFTypeRef)attrStr);
    return line;
}

EXPORT CFArrayRef CTLineGetGlyphRuns(CTLineRef line) {
    if (!line) return NULL;
    const struct __CTLine *l = (const struct __CTLine *)line;
    /* Create a CFArray containing our runs */
    return CFArrayCreate(kCFAllocatorDefault, (const void **)l->_runs,
                          l->_runCount, NULL);
}

EXPORT CFIndex CTLineGetGlyphCount(CTLineRef line) {
    if (!line) return 0;
    const struct __CTLine *l = (const struct __CTLine *)line;
    CFIndex total = 0;
    for (CFIndex i = 0; i < l->_runCount; i++) {
        total += l->_runs[i]->_glyphCount;
    }
    return total;
}

EXPORT CFRange CTLineGetStringRange(CTLineRef line) {
    if (!line) return CFRangeMake(0, 0);
    return CFRangeMake(0, ((const struct __CTLine *)line)->_stringLength);
}

EXPORT double CTLineGetTypographicBounds(CTLineRef line,
                                          CGFloat *ascent, CGFloat *descent,
                                          CGFloat *leading)
{
    if (!line) return 0.0;
    const struct __CTLine *l = (const struct __CTLine *)line;
    if (ascent)  *ascent  = l->_ascent;
    if (descent) *descent = l->_descent;
    if (leading) *leading = l->_leading;
    return (double)l->_width;
}

EXPORT CGRect CTLineGetImageBounds(CTLineRef line, CGContextRef context) {
    (void)context;
    if (!line) return CGRectZero;
    const struct __CTLine *l = (const struct __CTLine *)line;
    return CGRectMake(0.0, -(l->_descent), l->_width, l->_ascent + l->_descent);
}

EXPORT double CTLineGetTrailingWhitespaceWidth(CTLineRef line) {
    if (!line) return 0.0;
    const struct __CTLine *l = (const struct __CTLine *)line;
    /* Count trailing spaces */
    if (l->_runCount == 0) return 0.0;
    struct __CTRun *lastRun = l->_runs[l->_runCount - 1];
    CGFloat trailing = 0.0;
    for (CFIndex i = lastRun->_glyphCount - 1; i >= 0; i--) {
        if (lastRun->_glyphs[i] == 0x20) { /* space */
            trailing += lastRun->_advances[i].width;
        } else {
            break;
        }
    }
    return (double)trailing;
}

EXPORT double CTLineGetPenOffsetForFlush(CTLineRef line, CGFloat flushFactor,
                                          double flushWidth)
{
    if (!line) return 0.0;
    const struct __CTLine *l = (const struct __CTLine *)line;
    double lineWidth = (double)l->_width;
    double slack = flushWidth - lineWidth;
    if (slack < 0.0) slack = 0.0;
    return slack * (double)flushFactor;
}

EXPORT CFIndex CTLineGetStringIndexForPosition(CTLineRef line, CGPoint position) {
    if (!line) return 0;
    const struct __CTLine *l = (const struct __CTLine *)line;
    CGFloat x = position.x;
    for (CFIndex r = 0; r < l->_runCount; r++) {
        struct __CTRun *run = l->_runs[r];
        for (CFIndex i = 0; i < run->_glyphCount; i++) {
            CGFloat glyphStart = run->_positions[i].x;
            CGFloat glyphEnd   = glyphStart + run->_advances[i].width;
            if (x >= glyphStart && x < glyphEnd) {
                return run->_stringIndices[i];
            }
        }
    }
    return l->_stringLength; /* past end */
}

EXPORT CGFloat CTLineGetOffsetForStringIndex(CTLineRef line, CFIndex charIndex,
                                              CGFloat *secondaryOffset)
{
    if (secondaryOffset) *secondaryOffset = 0.0;
    if (!line) return 0.0;
    const struct __CTLine *l = (const struct __CTLine *)line;
    for (CFIndex r = 0; r < l->_runCount; r++) {
        struct __CTRun *run = l->_runs[r];
        for (CFIndex i = 0; i < run->_glyphCount; i++) {
            if (run->_stringIndices[i] == charIndex) {
                return run->_positions[i].x;
            }
        }
    }
    return l->_width; /* past end */
}

EXPORT CTLineRef CTLineCreateTruncatedLine(CTLineRef line, double width,
                                            CTLineTruncationType truncationType,
                                            CTLineRef truncationToken)
{
    (void)truncationType; (void)truncationToken;
    if (!line) return NULL;
    /* Simplified: just retain the original line if it fits */
    const struct __CTLine *l = (const struct __CTLine *)line;
    if ((double)l->_width <= width) {
        return CTLineRetain(line);
    }
    /* Truncate to fit — find how many glyphs fit */
    /* For now, just return the line as-is (proper truncation TODO) */
    return CTLineRetain(line);
}

EXPORT CTLineRef CTLineCreateJustifiedLine(CTLineRef line,
                                            CGFloat justificationFactor,
                                            double justificationWidth)
{
    (void)justificationFactor; (void)justificationWidth;
    if (!line) return NULL;
    return CTLineRetain(line); /* simplified — no justification */
}

/* --- CTLineDraw: render a line into a CGContext --- */

EXPORT void CTLineDraw(CTLineRef line, CGContextRef context) {
    if (!line || !context) return;
    const struct __CTLine *l = (const struct __CTLine *)line;
    for (CFIndex i = 0; i < l->_runCount; i++) {
        CTRunDraw((CTRunRef)l->_runs[i], context, CFRangeMake(0, 0));
    }
}

/* ============================================================================
 * Section 11: CTFramesetter & CTFrame — Paragraph Layout
 *
 * CTFramesetter takes a CFAttributedString and lays it out into a
 * rectangular path as multiple CTLines, handling word-wrapping.
 *
 * Reference: macOS SDK CTFramesetter.h, CTFrame.h
 * ============================================================================ */

typedef const struct __CTFramesetter *CTFramesetterRef;
typedef const struct __CTFrame       *CTFrameRef;

struct __CTFramesetter {
    intptr_t                  _refCount;
    CFAttributedStringRef     _attrString; /* retained */
};

struct __CTFrame {
    intptr_t        _refCount;
    CFIndex         _lineCount;
    struct __CTLine **_lines;      /* array of lines (owned) */
    CGPoint         *_lineOrigins; /* baseline origin of each line */
    CGRect           _frameRect;   /* bounding rectangle */
    CFRange          _visibleRange;/* range of source string that was laid out */
};

static void __CTFrameDestroy(struct __CTFrame *frame) {
    if (!frame) return;
    for (CFIndex i = 0; i < frame->_lineCount; i++) {
        __CTLineDestroy(frame->_lines[i]);
    }
    free(frame->_lines);
    free(frame->_lineOrigins);
    free(frame);
}

EXPORT CTFramesetterRef CTFramesetterCreateWithAttributedString(
    CFAttributedStringRef attrString)
{
    if (!attrString) return NULL;
    struct __CTFramesetter *fs = (struct __CTFramesetter *)calloc(1, sizeof(struct __CTFramesetter));
    if (!fs) return NULL;
    fs->_refCount = 1;
    fs->_attrString = (CFAttributedStringRef)CFRetain((CFTypeRef)attrString);
    return (CTFramesetterRef)fs;
}

EXPORT CTFramesetterRef CTFramesetterRetain(CTFramesetterRef framesetter) {
    if (!framesetter) return NULL;
    ((struct __CTFramesetter *)framesetter)->_refCount++;
    return framesetter;
}

EXPORT void CTFramesetterRelease(CTFramesetterRef framesetter) {
    if (!framesetter) return;
    struct __CTFramesetter *fs = (struct __CTFramesetter *)framesetter;
    if (--fs->_refCount <= 0) {
        if (fs->_attrString) CFRelease((CFTypeRef)fs->_attrString);
        free(fs);
    }
}

/* --- CTFramesetterCreateFrame: lay out text into a rectangular area --- */

EXPORT CTFrameRef CTFramesetterCreateFrame(CTFramesetterRef framesetter,
                                            CFRange stringRange,
                                            void *path,
                                            CFDictionaryRef frameAttributes)
{
    (void)frameAttributes;
    if (!framesetter) return NULL;
    const struct __CTFramesetter *fs = (const struct __CTFramesetter *)framesetter;
    CFAttributedStringRef attrStr = fs->_attrString;

    CFStringRef string = CFAttributedStringGetString(attrStr);
    if (!string) return NULL;
    CFIndex totalLen = CFStringGetLength(string);
    if (stringRange.length == 0) {
        stringRange.location = 0;
        stringRange.length = totalLen;
    }

    /* Get the frame rectangle from the path.
     * We accept a CGPathRef but just use the path's bounding box.
     * For simplicity, if path is NULL, assume infinite width. */
    CGFloat frameWidth  = 1e30;
    CGFloat frameHeight = 1e30;
    CGFloat frameX = 0, frameY = 0;
    (void)path; /* TODO: extract bounding box from CGPath */

    /* Get font and colour from attributes */
    CFRange effectiveRange;
    CFDictionaryRef attrs = CFAttributedStringGetAttributes(attrStr, 0, &effectiveRange);
    CTFontRef font = NULL;
    if (attrs && kCTFontAttributeName) {
        font = (CTFontRef)CFDictionaryGetValue(attrs, kCTFontAttributeName);
    }
    bool ownsFont = false;
    if (!font) {
        font = __CTFontCreate(16.0, "KisekiSystemFont");
        ownsFont = true;
    }
    const struct __CTFont *f = (const struct __CTFont *)font;

    CGFloat fgColor[4] = { 0.0, 0.0, 0.0, 1.0 };
    if (attrs && kCTForegroundColorAttributeName) {
        void *color = (void *)CFDictionaryGetValue(attrs, kCTForegroundColorAttributeName);
        if (color) {
            const CGFloat *comps = CGColorGetComponents(color);
            if (comps) {
                fgColor[0] = comps[0]; fgColor[1] = comps[1];
                fgColor[2] = comps[2]; fgColor[3] = comps[3];
            }
        }
    }

    CGFloat glyphAdvance = (CGFloat)f->_glyphWidth;
    CGFloat lineHeight = f->_ascent + f->_descent + f->_leading;
    int maxGlyphsPerLine = (int)(frameWidth / glyphAdvance);
    if (maxGlyphsPerLine < 1) maxGlyphsPerLine = 1;

    /* Allocate lines array (grow dynamically) */
    CFIndex lineCapacity = 64;
    CFIndex lineCount = 0;
    struct __CTLine **lines = (struct __CTLine **)malloc((size_t)lineCapacity * sizeof(struct __CTLine *));
    CGPoint *origins = (CGPoint *)malloc((size_t)lineCapacity * sizeof(CGPoint));
    if (!lines || !origins) {
        free(lines); free(origins);
        if (ownsFont) CTFontRelease(font);
        return NULL;
    }

    /* Word-wrapping line break algorithm:
     * Iterate through the string, breaking at newlines and when the line
     * exceeds frameWidth. For simplicity, we break at character boundaries
     * (the bitmap font is monospaced so word-wrap at spaces is a refinement). */

    CFIndex pos = stringRange.location;
    CFIndex end = stringRange.location + stringRange.length;
    CGFloat yPos = frameY;

    while (pos < end && yPos + lineHeight <= frameY + frameHeight) {
        /* Find the end of this line */
        CFIndex lineStart = pos;
        CFIndex lineEnd = pos;
        CFIndex lastSpace = -1;

        while (lineEnd < end) {
            UniChar ch = CFStringGetCharacterAtIndex(string, lineEnd);
            if (ch == '\n') {
                lineEnd++; /* consume the newline */
                break;
            }
            if ((lineEnd - lineStart) >= maxGlyphsPerLine) {
                /* Need to break — try at last space */
                if (lastSpace > lineStart) {
                    lineEnd = lastSpace + 1;
                }
                break;
            }
            if (ch == ' ') lastSpace = lineEnd;
            lineEnd++;
        }

        CFIndex lineLen = lineEnd - lineStart;
        /* Strip trailing newline from the run */
        CFIndex runLen = lineLen;
        if (runLen > 0) {
            UniChar lastCh = CFStringGetCharacterAtIndex(string, lineStart + runLen - 1);
            if (lastCh == '\n') runLen--;
        }

        if (runLen > 0) {
            struct __CTRun *run = __CTLayoutRun(string, lineStart, runLen, font, fgColor);
            if (run) {
                struct __CTLine *line = (struct __CTLine *)calloc(1, sizeof(struct __CTLine));
                if (line) {
                    line->_refCount = 1;
                    line->_runCount = 1;
                    line->_runs = (struct __CTRun **)malloc(sizeof(struct __CTRun *));
                    line->_runs[0] = run;
                    line->_stringLength = runLen;
                    line->_width   = run->_width;
                    line->_ascent  = run->_ascent;
                    line->_descent = run->_descent;
                    line->_leading = run->_leading;

                    /* Grow arrays if needed */
                    if (lineCount >= lineCapacity) {
                        lineCapacity *= 2;
                        lines = (struct __CTLine **)realloc(lines, (size_t)lineCapacity * sizeof(struct __CTLine *));
                        origins = (CGPoint *)realloc(origins, (size_t)lineCapacity * sizeof(CGPoint));
                    }

                    lines[lineCount] = line;
                    origins[lineCount] = CGPointMake(frameX, yPos + f->_ascent);
                    lineCount++;
                }
            }
        } else {
            /* Empty line (just a newline) — still advance y */
            /* Grow arrays if needed */
            if (lineCount >= lineCapacity) {
                lineCapacity *= 2;
                lines = (struct __CTLine **)realloc(lines, (size_t)lineCapacity * sizeof(struct __CTLine *));
                origins = (CGPoint *)realloc(origins, (size_t)lineCapacity * sizeof(CGPoint));
            }
            /* Insert a zero-width line */
            struct __CTLine *emptyLine = (struct __CTLine *)calloc(1, sizeof(struct __CTLine));
            if (emptyLine) {
                emptyLine->_refCount = 1;
                emptyLine->_ascent  = f->_ascent;
                emptyLine->_descent = f->_descent;
                emptyLine->_leading = f->_leading;
                lines[lineCount] = emptyLine;
                origins[lineCount] = CGPointMake(frameX, yPos + f->_ascent);
                lineCount++;
            }
        }

        yPos += lineHeight;
        pos = lineEnd;
    }

    if (ownsFont) CTFontRelease(font);

    /* Build the frame */
    struct __CTFrame *frame = (struct __CTFrame *)calloc(1, sizeof(struct __CTFrame));
    if (!frame) {
        for (CFIndex i = 0; i < lineCount; i++) __CTLineDestroy(lines[i]);
        free(lines); free(origins);
        return NULL;
    }
    frame->_refCount = 1;
    frame->_lineCount = lineCount;
    frame->_lines = lines;
    frame->_lineOrigins = origins;
    frame->_frameRect = CGRectMake(frameX, frameY, frameWidth, frameHeight);
    frame->_visibleRange = CFRangeMake(stringRange.location, pos - stringRange.location);
    return (CTFrameRef)frame;
}

EXPORT CGSize CTFramesetterSuggestFrameSizeWithConstraints(
    CTFramesetterRef framesetter, CFRange stringRange,
    CFDictionaryRef frameAttributes, CGSize constraints,
    CFRange *fitRange)
{
    (void)frameAttributes;
    if (!framesetter) {
        if (fitRange) *fitRange = CFRangeMake(0, 0);
        return CGSizeZero;
    }
    const struct __CTFramesetter *fs = (const struct __CTFramesetter *)framesetter;
    CFAttributedStringRef attrStr = fs->_attrString;
    CFStringRef string = CFAttributedStringGetString(attrStr);
    if (!string) {
        if (fitRange) *fitRange = CFRangeMake(0, 0);
        return CGSizeZero;
    }
    CFIndex totalLen = CFStringGetLength(string);
    if (stringRange.length == 0) {
        stringRange.location = 0;
        stringRange.length = totalLen;
    }

    /* Get font */
    CFRange effectiveRange;
    CFDictionaryRef attrs = CFAttributedStringGetAttributes(attrStr, 0, &effectiveRange);
    CTFontRef font = NULL;
    if (attrs && kCTFontAttributeName) {
        font = (CTFontRef)CFDictionaryGetValue(attrs, kCTFontAttributeName);
    }
    const struct __CTFont *f = font ? (const struct __CTFont *)font : NULL;
    CGFloat glyphW = f ? (CGFloat)f->_glyphWidth  : 8.0;
    CGFloat lineH  = f ? (f->_ascent + f->_descent + f->_leading) : 16.0;

    CGFloat maxWidth = constraints.width > 0 ? constraints.width : 1e30;
    int charsPerLine = (int)(maxWidth / glyphW);
    if (charsPerLine < 1) charsPerLine = 1;

    /* Count lines needed */
    CFIndex pos = stringRange.location;
    CFIndex end = stringRange.location + stringRange.length;
    CFIndex lines = 0;
    CGFloat widest = 0;

    while (pos < end) {
        CFIndex lineStart = pos;
        CFIndex lineEnd = pos;
        while (lineEnd < end && (lineEnd - lineStart) < charsPerLine) {
            UniChar ch = CFStringGetCharacterAtIndex(string, lineEnd);
            if (ch == '\n') { lineEnd++; break; }
            lineEnd++;
        }
        CFIndex lineLen = lineEnd - lineStart;
        /* Strip trailing newline */
        if (lineLen > 0 && CFStringGetCharacterAtIndex(string, lineStart + lineLen - 1) == '\n')
            lineLen--;
        CGFloat w = (CGFloat)lineLen * glyphW;
        if (w > widest) widest = w;
        lines++;
        pos = lineEnd;
    }

    if (fitRange) *fitRange = CFRangeMake(stringRange.location, pos - stringRange.location);
    return CGSizeMake(widest, (CGFloat)lines * lineH);
}

/* --- CTFrame accessors --- */

EXPORT CTFrameRef CTFrameRetain(CTFrameRef frame) {
    if (!frame) return NULL;
    ((struct __CTFrame *)frame)->_refCount++;
    return frame;
}

EXPORT void CTFrameRelease(CTFrameRef frame) {
    if (!frame) return;
    struct __CTFrame *f = (struct __CTFrame *)frame;
    if (--f->_refCount <= 0) __CTFrameDestroy(f);
}

EXPORT CFArrayRef CTFrameGetLines(CTFrameRef frame) {
    if (!frame) return NULL;
    const struct __CTFrame *f = (const struct __CTFrame *)frame;
    return CFArrayCreate(kCFAllocatorDefault, (const void **)f->_lines,
                          f->_lineCount, NULL);
}

EXPORT void CTFrameGetLineOrigins(CTFrameRef frame, CFRange range,
                                   CGPoint *origins)
{
    if (!frame || !origins) return;
    const struct __CTFrame *f = (const struct __CTFrame *)frame;
    if (range.length == 0) { range.location = 0; range.length = f->_lineCount; }
    CFIndex end = range.location + range.length;
    if (end > f->_lineCount) end = f->_lineCount;
    memcpy(origins, f->_lineOrigins + range.location,
           (size_t)(end - range.location) * sizeof(CGPoint));
}

EXPORT CFRange CTFrameGetVisibleStringRange(CTFrameRef frame) {
    if (!frame) return CFRangeMake(0, 0);
    return ((const struct __CTFrame *)frame)->_visibleRange;
}

EXPORT void *CTFrameGetPath(CTFrameRef frame) {
    (void)frame;
    return NULL; /* simplified */
}

EXPORT CFDictionaryRef CTFrameGetFrameAttributes(CTFrameRef frame) {
    (void)frame;
    return NULL;
}

/* --- CTFrameDraw: render all lines of a frame --- */

EXPORT void CTFrameDraw(CTFrameRef frame, CGContextRef context) {
    if (!frame || !context) return;
    const struct __CTFrame *f = (const struct __CTFrame *)frame;
    for (CFIndex i = 0; i < f->_lineCount; i++) {
        /* Set the text position for each line */
        if (context->_gstate) {
            context->_gstate->textPosition = f->_lineOrigins[i];
        }
        CTLineDraw((CTLineRef)f->_lines[i], context);
    }
}

/* ============================================================================
 * Section 12: CTFontDescriptor (minimal stubs)
 *
 * Font descriptors are used to query and match fonts. Since we have exactly
 * one font (the bitmap system font), these are mostly stubs.
 * ============================================================================ */

typedef const void *CTFontDescriptorRef;

EXPORT CTFontDescriptorRef CTFontDescriptorCreateWithAttributes(CFDictionaryRef attributes) {
    (void)attributes;
    return NULL; /* stub — single font system */
}

EXPORT CTFontDescriptorRef CTFontDescriptorCreateWithNameAndSize(CFStringRef name, CGFloat size) {
    (void)name; (void)size;
    return NULL;
}

EXPORT CTFontDescriptorRef CTFontDescriptorCreateCopyWithAttributes(
    CTFontDescriptorRef original, CFDictionaryRef attributes) {
    (void)original; (void)attributes;
    return NULL;
}

EXPORT CFTypeRef CTFontDescriptorCopyAttribute(CTFontDescriptorRef descriptor, CFStringRef attribute) {
    (void)descriptor; (void)attribute;
    return NULL;
}

EXPORT CFDictionaryRef CTFontDescriptorCopyAttributes(CTFontDescriptorRef descriptor) {
    (void)descriptor;
    return NULL;
}

EXPORT CFArrayRef CTFontDescriptorCreateMatchingFontDescriptors(
    CTFontDescriptorRef descriptor, CFArrayRef mandatoryAttributes) {
    (void)descriptor; (void)mandatoryAttributes;
    return NULL;
}

EXPORT CTFontDescriptorRef CTFontDescriptorCreateMatchingFontDescriptor(
    CTFontDescriptorRef descriptor, CFArrayRef mandatoryAttributes) {
    (void)descriptor; (void)mandatoryAttributes;
    return NULL;
}

/* ============================================================================
 * Section 13: CTFontCollection (minimal stubs)
 *
 * Font collections for querying available fonts. Since we only have one
 * font, these return empty/NULL.
 * ============================================================================ */

typedef const void *CTFontCollectionRef;

EXPORT CTFontCollectionRef CTFontCollectionCreateFromAvailableFonts(CFDictionaryRef options) {
    (void)options;
    return NULL;
}

EXPORT CFArrayRef CTFontCollectionCreateMatchingFontDescriptors(CTFontCollectionRef collection) {
    (void)collection;
    return NULL;
}

/* ============================================================================
 * Section 14: CTParagraphStyle (minimal)
 *
 * Paragraph-level formatting (alignment, line spacing, etc.).
 * Simplified: stores alignment only.
 * ============================================================================ */

typedef const struct __CTParagraphStyle *CTParagraphStyleRef;

typedef enum {
    kCTTextAlignmentLeft      = 0,
    kCTTextAlignmentRight     = 1,
    kCTTextAlignmentCenter    = 2,
    kCTTextAlignmentJustified = 3,
    kCTTextAlignmentNatural   = 4,
} CTTextAlignment;

typedef enum {
    kCTLineBreakByWordWrapping     = 0,
    kCTLineBreakByCharWrapping     = 1,
    kCTLineBreakByClipping         = 2,
    kCTLineBreakByTruncatingHead   = 3,
    kCTLineBreakByTruncatingTail   = 4,
    kCTLineBreakByTruncatingMiddle = 5,
} CTLineBreakMode;

typedef enum {
    kCTParagraphStyleSpecifierAlignment            = 0,
    kCTParagraphStyleSpecifierFirstLineHeadIndent   = 1,
    kCTParagraphStyleSpecifierHeadIndent             = 2,
    kCTParagraphStyleSpecifierTailIndent             = 3,
    kCTParagraphStyleSpecifierTabStops               = 4,
    kCTParagraphStyleSpecifierDefaultTabInterval     = 5,
    kCTParagraphStyleSpecifierLineBreakMode          = 6,
    kCTParagraphStyleSpecifierLineHeightMultiple      = 7,
    kCTParagraphStyleSpecifierMaximumLineHeight       = 8,
    kCTParagraphStyleSpecifierMinimumLineHeight       = 9,
    kCTParagraphStyleSpecifierLineSpacing             = 10,
    kCTParagraphStyleSpecifierParagraphSpacing        = 11,
    kCTParagraphStyleSpecifierParagraphSpacingBefore  = 12,
    kCTParagraphStyleSpecifierBaseWritingDirection    = 13,
    kCTParagraphStyleSpecifierMaximumLineSpacing      = 14,
    kCTParagraphStyleSpecifierMinimumLineSpacing      = 15,
    kCTParagraphStyleSpecifierLineSpacingAdjustment   = 16,
    kCTParagraphStyleSpecifierCount                   = 17,
} CTParagraphStyleSpecifier;

typedef struct {
    CTParagraphStyleSpecifier  spec;
    size_t                     valueSize;
    const void                *value;
} CTParagraphStyleSetting;

struct __CTParagraphStyle {
    intptr_t        _refCount;
    CTTextAlignment _alignment;
    CTLineBreakMode _lineBreakMode;
    CGFloat         _lineSpacing;
    CGFloat         _paragraphSpacing;
    CGFloat         _firstLineHeadIndent;
    CGFloat         _headIndent;
    CGFloat         _tailIndent;
};

EXPORT CTParagraphStyleRef CTParagraphStyleCreate(
    const CTParagraphStyleSetting *settings, size_t settingCount)
{
    struct __CTParagraphStyle *ps = (struct __CTParagraphStyle *)
        calloc(1, sizeof(struct __CTParagraphStyle));
    if (!ps) return NULL;
    ps->_refCount = 1;
    ps->_alignment = kCTTextAlignmentNatural;
    ps->_lineBreakMode = kCTLineBreakByWordWrapping;

    for (size_t i = 0; i < settingCount; i++) {
        const CTParagraphStyleSetting *s = &settings[i];
        switch (s->spec) {
        case kCTParagraphStyleSpecifierAlignment:
            if (s->value && s->valueSize >= sizeof(CTTextAlignment))
                ps->_alignment = *(const CTTextAlignment *)s->value;
            break;
        case kCTParagraphStyleSpecifierLineBreakMode:
            if (s->value && s->valueSize >= sizeof(CTLineBreakMode))
                ps->_lineBreakMode = *(const CTLineBreakMode *)s->value;
            break;
        case kCTParagraphStyleSpecifierLineSpacing:
            if (s->value && s->valueSize >= sizeof(CGFloat))
                ps->_lineSpacing = *(const CGFloat *)s->value;
            break;
        case kCTParagraphStyleSpecifierParagraphSpacing:
            if (s->value && s->valueSize >= sizeof(CGFloat))
                ps->_paragraphSpacing = *(const CGFloat *)s->value;
            break;
        case kCTParagraphStyleSpecifierFirstLineHeadIndent:
            if (s->value && s->valueSize >= sizeof(CGFloat))
                ps->_firstLineHeadIndent = *(const CGFloat *)s->value;
            break;
        case kCTParagraphStyleSpecifierHeadIndent:
            if (s->value && s->valueSize >= sizeof(CGFloat))
                ps->_headIndent = *(const CGFloat *)s->value;
            break;
        case kCTParagraphStyleSpecifierTailIndent:
            if (s->value && s->valueSize >= sizeof(CGFloat))
                ps->_tailIndent = *(const CGFloat *)s->value;
            break;
        default:
            break;
        }
    }
    return (CTParagraphStyleRef)ps;
}

EXPORT bool CTParagraphStyleGetValueForSpecifier(CTParagraphStyleRef paragraphStyle,
    CTParagraphStyleSpecifier spec, size_t valueBufferSize, void *valueBuffer)
{
    if (!paragraphStyle || !valueBuffer) return false;
    const struct __CTParagraphStyle *ps = (const struct __CTParagraphStyle *)paragraphStyle;
    switch (spec) {
    case kCTParagraphStyleSpecifierAlignment:
        if (valueBufferSize >= sizeof(CTTextAlignment)) {
            *(CTTextAlignment *)valueBuffer = ps->_alignment;
            return true;
        }
        break;
    case kCTParagraphStyleSpecifierLineBreakMode:
        if (valueBufferSize >= sizeof(CTLineBreakMode)) {
            *(CTLineBreakMode *)valueBuffer = ps->_lineBreakMode;
            return true;
        }
        break;
    default:
        break;
    }
    return false;
}

EXPORT CTParagraphStyleRef CTParagraphStyleRetain(CTParagraphStyleRef style) {
    if (!style) return NULL;
    ((struct __CTParagraphStyle *)style)->_refCount++;
    return style;
}

EXPORT void CTParagraphStyleRelease(CTParagraphStyleRef style) {
    if (!style) return;
    struct __CTParagraphStyle *ps = (struct __CTParagraphStyle *)style;
    if (--ps->_refCount <= 0) free(ps);
}

/* ============================================================================
 * Section 15: CTStringAttributes Constants & Helpers
 * ============================================================================ */

/* kCTFontAttributeName value helper: extract CTFontRef from attributes */
EXPORT CTFontRef CTFontCreateWithAttributes(CFDictionaryRef attributes) {
    if (!attributes || !kCTFontAttributeName) return NULL;
    CTFontRef font = (CTFontRef)CFDictionaryGetValue(attributes, kCTFontAttributeName);
    if (font) return CTFontRetain(font);
    return NULL;
}

/* ============================================================================
 * Section 16: Framework Initialisation
 *
 * Constructor function to initialise string constants.
 * ============================================================================ */

__attribute__((constructor, used))
static void __CTInitialize(void) {
    kCTFontAttributeName            = CFSTR("NSFont");
    kCTForegroundColorAttributeName = CFSTR("NSColor");
    kCTBackgroundColorAttributeName = CFSTR("NSBackgroundColor");
    kCTFontSizeAttribute            = CFSTR("NSFontSize");
    kCTKernAttributeName            = CFSTR("NSKern");
    kCTLigatureAttributeName        = CFSTR("NSLigature");
    kCTParagraphStyleAttributeName  = CFSTR("NSParagraphStyle");
    kCTUnderlineStyleAttributeName  = CFSTR("NSUnderline");
    kCTStrokeWidthAttributeName     = CFSTR("NSStrokeWidth");
    kCTStrokeColorAttributeName     = CFSTR("NSStrokeColor");
    kCTSuperscriptAttributeName     = CFSTR("NSSuperScript");
}

/* ============================================================================
 * End of CoreText.framework
 * ============================================================================ */

