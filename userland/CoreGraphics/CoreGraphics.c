/*
 * Kiseki OS - CoreGraphics.framework
 *
 * Freestanding implementation of Apple's CoreGraphics (Quartz 2D) library.
 * Provides 2D rendering into bitmap contexts. No GPU acceleration — pure
 * software rasterisation suitable for a framebuffer-based display.
 *
 * Reference: macOS SDK CoreGraphics headers (CGContext.h, CGBitmapContext.h,
 *            CGColorSpace.h, CGColor.h, CGPath.h, CGImage.h, CGGeometry.h,
 *            CGAffineTransform.h, CGDataProvider.h)
 */

/* ============================================================================
 * Section 1: Visibility & Compiler Helpers
 * ============================================================================ */

#define EXPORT  __attribute__((visibility("default")))
#define HIDDEN  __attribute__((visibility("hidden")))
#define CG_INLINE static inline __attribute__((always_inline))

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

/* ============================================================================
 * Section 3: Imported Functions
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
extern char  *strcpy(char *dst, const char *src);
extern char  *strdup(const char *s);
extern int    snprintf(char *buf, size_t size, const char *fmt, ...);
extern int    fprintf(void *stream, const char *fmt, ...);

extern void *__stderrp;
#define stderr __stderrp

/* CoreFoundation imports */
typedef const void *CFTypeRef;
typedef const struct __CFString *CFStringRef;
typedef const struct __CFAllocator *CFAllocatorRef;
typedef const struct __CFData *CFDataRef;
typedef unsigned long CFTypeID;
typedef signed long CFIndex;
typedef unsigned long CFHashCode;

extern CFTypeRef  CFRetain(CFTypeRef cf);
extern void       CFRelease(CFTypeRef cf);
extern CFTypeID   CFGetTypeID(CFTypeRef cf);
extern CFStringRef CFStringCreateWithCString(CFAllocatorRef alloc, const char *cStr, uint32_t encoding);
extern const char *CFStringGetCStringPtr(CFStringRef theString, uint32_t encoding);
extern CFStringRef __CFStringMakeConstantString(const char *cStr);
extern CFDataRef   CFDataCreate(CFAllocatorRef alloc, const uint8_t *bytes, CFIndex length);
extern const uint8_t *CFDataGetBytePtr(CFDataRef theData);
extern CFIndex     CFDataGetLength(CFDataRef theData);

#define kCFStringEncodingUTF8 0x08000100

/* ============================================================================
 * Section 4: CGFloat & Geometry Types
 * ============================================================================ */

typedef double CGFloat;
#define CGFLOAT_IS_DOUBLE 1

struct CGPoint { CGFloat x; CGFloat y; };
typedef struct CGPoint CGPoint;

struct CGSize { CGFloat width; CGFloat height; };
typedef struct CGSize CGSize;

struct CGVector { CGFloat dx; CGFloat dy; };
typedef struct CGVector CGVector;

struct CGRect { CGPoint origin; CGSize size; };
typedef struct CGRect CGRect;

typedef uint32_t CGRectEdge;
#define CGRectMinXEdge 0
#define CGRectMinYEdge 1
#define CGRectMaxXEdge 2
#define CGRectMaxYEdge 3

EXPORT const CGPoint CGPointZero = {0, 0};
EXPORT const CGSize  CGSizeZero  = {0, 0};
EXPORT const CGRect  CGRectZero  = {{0, 0}, {0, 0}};
/* CGRectNull: a rect that represents "no rectangle" — uses infinity */
EXPORT const CGRect  CGRectNull  = {{__builtin_inf(), __builtin_inf()}, {0, 0}};
EXPORT const CGRect  CGRectInfinite = {{-__builtin_inf()/2, -__builtin_inf()/2},
                                        {__builtin_inf(), __builtin_inf()}};

CG_INLINE CGPoint CGPointMake(CGFloat x, CGFloat y) {
    CGPoint p; p.x = x; p.y = y; return p;
}
CG_INLINE CGSize CGSizeMake(CGFloat w, CGFloat h) {
    CGSize s; s.width = w; s.height = h; return s;
}
CG_INLINE CGVector CGVectorMake(CGFloat dx, CGFloat dy) {
    CGVector v; v.dx = dx; v.dy = dy; return v;
}
CG_INLINE CGRect CGRectMake(CGFloat x, CGFloat y, CGFloat w, CGFloat h) {
    CGRect r; r.origin.x = x; r.origin.y = y; r.size.width = w; r.size.height = h; return r;
}

EXPORT CGFloat CGRectGetMinX(CGRect r) { return r.origin.x < r.origin.x + r.size.width ? r.origin.x : r.origin.x + r.size.width; }
EXPORT CGFloat CGRectGetMidX(CGRect r) { return r.origin.x + r.size.width * 0.5; }
EXPORT CGFloat CGRectGetMaxX(CGRect r) { return r.origin.x > r.origin.x + r.size.width ? r.origin.x : r.origin.x + r.size.width; }
EXPORT CGFloat CGRectGetMinY(CGRect r) { return r.origin.y < r.origin.y + r.size.height ? r.origin.y : r.origin.y + r.size.height; }
EXPORT CGFloat CGRectGetMidY(CGRect r) { return r.origin.y + r.size.height * 0.5; }
EXPORT CGFloat CGRectGetMaxY(CGRect r) { return r.origin.y > r.origin.y + r.size.height ? r.origin.y : r.origin.y + r.size.height; }
EXPORT CGFloat CGRectGetWidth(CGRect r)  { return r.size.width < 0 ? -r.size.width : r.size.width; }
EXPORT CGFloat CGRectGetHeight(CGRect r) { return r.size.height < 0 ? -r.size.height : r.size.height; }

EXPORT bool CGPointEqualToPoint(CGPoint p1, CGPoint p2) { return p1.x == p2.x && p1.y == p2.y; }
EXPORT bool CGSizeEqualToSize(CGSize s1, CGSize s2) { return s1.width == s2.width && s1.height == s2.height; }
EXPORT bool CGRectEqualToRect(CGRect r1, CGRect r2) {
    return CGPointEqualToPoint(r1.origin, r2.origin) && CGSizeEqualToSize(r1.size, r2.size);
}

EXPORT CGRect CGRectStandardize(CGRect r) {
    if (r.size.width < 0) { r.origin.x += r.size.width; r.size.width = -r.size.width; }
    if (r.size.height < 0) { r.origin.y += r.size.height; r.size.height = -r.size.height; }
    return r;
}

EXPORT bool CGRectIsEmpty(CGRect r) {
    CGRect s = CGRectStandardize(r);
    return s.size.width <= 0 || s.size.height <= 0;
}

EXPORT bool CGRectIsNull(CGRect r) {
    return r.origin.x == __builtin_inf() && r.origin.y == __builtin_inf();
}

EXPORT bool CGRectIsInfinite(CGRect r) {
    return r.size.width >= __builtin_inf() || r.size.height >= __builtin_inf();
}

EXPORT CGRect CGRectInset(CGRect r, CGFloat dx, CGFloat dy) {
    r = CGRectStandardize(r);
    r.origin.x += dx; r.origin.y += dy;
    r.size.width -= dx * 2; r.size.height -= dy * 2;
    return r;
}

EXPORT CGRect CGRectOffset(CGRect r, CGFloat dx, CGFloat dy) {
    r.origin.x += dx; r.origin.y += dy; return r;
}

CG_INLINE CGFloat __cg_min(CGFloat a, CGFloat b) { return a < b ? a : b; }
CG_INLINE CGFloat __cg_max(CGFloat a, CGFloat b) { return a > b ? a : b; }
CG_INLINE CGFloat __cg_floor(CGFloat x) { return (CGFloat)(int64_t)x - (x < 0 && x != (int64_t)x ? 1 : 0); }
CG_INLINE CGFloat __cg_ceil(CGFloat x) { return (CGFloat)(int64_t)x + (x > 0 && x != (int64_t)x ? 1 : 0); }
CG_INLINE CGFloat __cg_fabs(CGFloat x) { return x < 0 ? -x : x; }

EXPORT CGRect CGRectIntegral(CGRect r) {
    r = CGRectStandardize(r);
    CGFloat x2 = __cg_ceil(r.origin.x + r.size.width);
    CGFloat y2 = __cg_ceil(r.origin.y + r.size.height);
    r.origin.x = __cg_floor(r.origin.x);
    r.origin.y = __cg_floor(r.origin.y);
    r.size.width = x2 - r.origin.x;
    r.size.height = y2 - r.origin.y;
    return r;
}

EXPORT CGRect CGRectUnion(CGRect r1, CGRect r2) {
    if (CGRectIsNull(r1)) return r2;
    if (CGRectIsNull(r2)) return r1;
    r1 = CGRectStandardize(r1); r2 = CGRectStandardize(r2);
    CGFloat x1 = __cg_min(r1.origin.x, r2.origin.x);
    CGFloat y1 = __cg_min(r1.origin.y, r2.origin.y);
    CGFloat x2 = __cg_max(r1.origin.x + r1.size.width, r2.origin.x + r2.size.width);
    CGFloat y2 = __cg_max(r1.origin.y + r1.size.height, r2.origin.y + r2.size.height);
    return CGRectMake(x1, y1, x2 - x1, y2 - y1);
}

EXPORT CGRect CGRectIntersection(CGRect r1, CGRect r2) {
    r1 = CGRectStandardize(r1); r2 = CGRectStandardize(r2);
    CGFloat x1 = __cg_max(r1.origin.x, r2.origin.x);
    CGFloat y1 = __cg_max(r1.origin.y, r2.origin.y);
    CGFloat x2 = __cg_min(r1.origin.x + r1.size.width, r2.origin.x + r2.size.width);
    CGFloat y2 = __cg_min(r1.origin.y + r1.size.height, r2.origin.y + r2.size.height);
    if (x2 <= x1 || y2 <= y1) return CGRectNull;
    return CGRectMake(x1, y1, x2 - x1, y2 - y1);
}

EXPORT bool CGRectContainsPoint(CGRect r, CGPoint p) {
    r = CGRectStandardize(r);
    return p.x >= r.origin.x && p.x < r.origin.x + r.size.width &&
           p.y >= r.origin.y && p.y < r.origin.y + r.size.height;
}

EXPORT bool CGRectContainsRect(CGRect r1, CGRect r2) {
    r1 = CGRectStandardize(r1); r2 = CGRectStandardize(r2);
    return r2.origin.x >= r1.origin.x &&
           r2.origin.y >= r1.origin.y &&
           r2.origin.x + r2.size.width <= r1.origin.x + r1.size.width &&
           r2.origin.y + r2.size.height <= r1.origin.y + r1.size.height;
}

EXPORT bool CGRectIntersectsRect(CGRect r1, CGRect r2) {
    return !CGRectIsNull(CGRectIntersection(r1, r2));
}

EXPORT void CGRectDivide(CGRect rect, CGRect *slice, CGRect *remainder,
                          CGFloat amount, CGRectEdge edge) {
    rect = CGRectStandardize(rect);
    if (!slice || !remainder) return;
    switch (edge) {
    case CGRectMinXEdge:
        *slice = CGRectMake(rect.origin.x, rect.origin.y, amount, rect.size.height);
        *remainder = CGRectMake(rect.origin.x + amount, rect.origin.y,
                                 rect.size.width - amount, rect.size.height);
        break;
    case CGRectMaxXEdge:
        *slice = CGRectMake(rect.origin.x + rect.size.width - amount, rect.origin.y,
                             amount, rect.size.height);
        *remainder = CGRectMake(rect.origin.x, rect.origin.y,
                                 rect.size.width - amount, rect.size.height);
        break;
    case CGRectMinYEdge:
        *slice = CGRectMake(rect.origin.x, rect.origin.y, rect.size.width, amount);
        *remainder = CGRectMake(rect.origin.x, rect.origin.y + amount,
                                 rect.size.width, rect.size.height - amount);
        break;
    case CGRectMaxYEdge:
        *slice = CGRectMake(rect.origin.x, rect.origin.y + rect.size.height - amount,
                             rect.size.width, amount);
        *remainder = CGRectMake(rect.origin.x, rect.origin.y,
                                 rect.size.width, rect.size.height - amount);
        break;
    }
}


/* ============================================================================
 * Section 5: CGAffineTransform
 * ============================================================================ */

struct CGAffineTransform {
    CGFloat a, b, c, d;
    CGFloat tx, ty;
};
typedef struct CGAffineTransform CGAffineTransform;

EXPORT const CGAffineTransform CGAffineTransformIdentity = {1, 0, 0, 1, 0, 0};

EXPORT CGAffineTransform CGAffineTransformMake(CGFloat a, CGFloat b, CGFloat c, CGFloat d, CGFloat tx, CGFloat ty) {
    CGAffineTransform t; t.a = a; t.b = b; t.c = c; t.d = d; t.tx = tx; t.ty = ty; return t;
}

EXPORT CGAffineTransform CGAffineTransformMakeTranslation(CGFloat tx, CGFloat ty) {
    return CGAffineTransformMake(1, 0, 0, 1, tx, ty);
}

EXPORT CGAffineTransform CGAffineTransformMakeScale(CGFloat sx, CGFloat sy) {
    return CGAffineTransformMake(sx, 0, 0, sy, 0, 0);
}

/* sin/cos builtins for freestanding */
static double __cg_sin(double x) { return __builtin_sin(x); }
static double __cg_cos(double x) { return __builtin_cos(x); }
static double __cg_sqrt(double x) { return __builtin_sqrt(x); }

EXPORT CGAffineTransform CGAffineTransformMakeRotation(CGFloat angle) {
    CGFloat s = __cg_sin(angle), c = __cg_cos(angle);
    return CGAffineTransformMake(c, s, -s, c, 0, 0);
}

EXPORT bool CGAffineTransformIsIdentity(CGAffineTransform t) {
    return t.a == 1 && t.b == 0 && t.c == 0 && t.d == 1 && t.tx == 0 && t.ty == 0;
}

EXPORT CGAffineTransform CGAffineTransformConcat(CGAffineTransform t1, CGAffineTransform t2) {
    CGAffineTransform r;
    r.a  = t1.a * t2.a  + t1.b * t2.c;
    r.b  = t1.a * t2.b  + t1.b * t2.d;
    r.c  = t1.c * t2.a  + t1.d * t2.c;
    r.d  = t1.c * t2.b  + t1.d * t2.d;
    r.tx = t1.tx * t2.a  + t1.ty * t2.c + t2.tx;
    r.ty = t1.tx * t2.b  + t1.ty * t2.d + t2.ty;
    return r;
}

EXPORT CGAffineTransform CGAffineTransformTranslate(CGAffineTransform t, CGFloat tx, CGFloat ty) {
    return CGAffineTransformConcat(CGAffineTransformMakeTranslation(tx, ty), t);
}

EXPORT CGAffineTransform CGAffineTransformScale(CGAffineTransform t, CGFloat sx, CGFloat sy) {
    return CGAffineTransformConcat(CGAffineTransformMakeScale(sx, sy), t);
}

EXPORT CGAffineTransform CGAffineTransformRotate(CGAffineTransform t, CGFloat angle) {
    return CGAffineTransformConcat(CGAffineTransformMakeRotation(angle), t);
}

EXPORT CGAffineTransform CGAffineTransformInvert(CGAffineTransform t) {
    CGFloat det = t.a * t.d - t.b * t.c;
    if (det == 0) return t; /* singular */
    CGFloat inv = 1.0 / det;
    CGAffineTransform r;
    r.a  =  t.d * inv;
    r.b  = -t.b * inv;
    r.c  = -t.c * inv;
    r.d  =  t.a * inv;
    r.tx = (t.c * t.ty - t.d * t.tx) * inv;
    r.ty = (t.b * t.tx - t.a * t.ty) * inv;
    return r;
}

EXPORT bool CGAffineTransformEqualToTransform(CGAffineTransform t1, CGAffineTransform t2) {
    return t1.a == t2.a && t1.b == t2.b && t1.c == t2.c &&
           t1.d == t2.d && t1.tx == t2.tx && t1.ty == t2.ty;
}

EXPORT CGPoint CGPointApplyAffineTransform(CGPoint p, CGAffineTransform t) {
    CGPoint r;
    r.x = t.a * p.x + t.c * p.y + t.tx;
    r.y = t.b * p.x + t.d * p.y + t.ty;
    return r;
}

EXPORT CGSize CGSizeApplyAffineTransform(CGSize s, CGAffineTransform t) {
    CGSize r;
    r.width  = t.a * s.width + t.c * s.height;
    r.height = t.b * s.width + t.d * s.height;
    return r;
}

EXPORT CGRect CGRectApplyAffineTransform(CGRect rect, CGAffineTransform t) {
    CGPoint p0 = CGPointApplyAffineTransform(rect.origin, t);
    CGPoint p1 = CGPointApplyAffineTransform(CGPointMake(rect.origin.x + rect.size.width, rect.origin.y), t);
    CGPoint p2 = CGPointApplyAffineTransform(CGPointMake(rect.origin.x, rect.origin.y + rect.size.height), t);
    CGPoint p3 = CGPointApplyAffineTransform(CGPointMake(rect.origin.x + rect.size.width, rect.origin.y + rect.size.height), t);
    CGFloat minX = __cg_min(__cg_min(p0.x, p1.x), __cg_min(p2.x, p3.x));
    CGFloat minY = __cg_min(__cg_min(p0.y, p1.y), __cg_min(p2.y, p3.y));
    CGFloat maxX = __cg_max(__cg_max(p0.x, p1.x), __cg_max(p2.x, p3.x));
    CGFloat maxY = __cg_max(__cg_max(p0.y, p1.y), __cg_max(p2.y, p3.y));
    return CGRectMake(minX, minY, maxX - minX, maxY - minY);
}


/* ============================================================================
 * Section 6: Enumerations
 * ============================================================================ */

/* CGImageAlphaInfo */
typedef uint32_t CGImageAlphaInfo;
#define kCGImageAlphaNone               0
#define kCGImageAlphaPremultipliedLast   1
#define kCGImageAlphaPremultipliedFirst  2
#define kCGImageAlphaLast                3
#define kCGImageAlphaFirst               4
#define kCGImageAlphaNoneSkipLast        5
#define kCGImageAlphaNoneSkipFirst       6
#define kCGImageAlphaOnly                7

/* CGImageByteOrderInfo */
typedef uint32_t CGImageByteOrderInfo;
#define kCGImageByteOrderMask     0x7000
#define kCGImageByteOrderDefault  (0 << 12)
#define kCGImageByteOrder16Little (1 << 12)
#define kCGImageByteOrder32Little (2 << 12)
#define kCGImageByteOrder16Big    (3 << 12)
#define kCGImageByteOrder32Big    (4 << 12)
/* arm64 is little-endian */
#define kCGImageByteOrder16Host   kCGImageByteOrder16Little
#define kCGImageByteOrder32Host   kCGImageByteOrder32Little

/* CGBitmapInfo */
typedef uint32_t CGBitmapInfo;
#define kCGBitmapAlphaInfoMask        0x1F
#define kCGBitmapByteOrderMask        0x7000
#define kCGBitmapByteOrderDefault     kCGImageByteOrderDefault
#define kCGBitmapByteOrder16Little    kCGImageByteOrder16Little
#define kCGBitmapByteOrder32Little    kCGImageByteOrder32Little
#define kCGBitmapByteOrder16Big       kCGImageByteOrder16Big
#define kCGBitmapByteOrder32Big       kCGImageByteOrder32Big
#define kCGBitmapByteOrder16Host      kCGImageByteOrder16Host
#define kCGBitmapByteOrder32Host      kCGImageByteOrder32Host
#define kCGBitmapFloatComponents      (1 << 8)

/* CGColorRenderingIntent */
typedef int32_t CGColorRenderingIntent;
#define kCGRenderingIntentDefault               0
#define kCGRenderingIntentAbsoluteColorimetric  1
#define kCGRenderingIntentRelativeColorimetric  2
#define kCGRenderingIntentPerceptual            3
#define kCGRenderingIntentSaturation            4

/* CGColorSpaceModel */
typedef int32_t CGColorSpaceModel;
#define kCGColorSpaceModelUnknown    (-1)
#define kCGColorSpaceModelMonochrome 0
#define kCGColorSpaceModelRGB        1
#define kCGColorSpaceModelCMYK       2
#define kCGColorSpaceModelLab        3
#define kCGColorSpaceModelDeviceN    4
#define kCGColorSpaceModelIndexed    5
#define kCGColorSpaceModelPattern    6
#define kCGColorSpaceModelXYZ        7

/* CGLineCap */
typedef int32_t CGLineCap;
#define kCGLineCapButt   0
#define kCGLineCapRound  1
#define kCGLineCapSquare 2

/* CGLineJoin */
typedef int32_t CGLineJoin;
#define kCGLineJoinMiter 0
#define kCGLineJoinRound 1
#define kCGLineJoinBevel 2

/* CGPathDrawingMode */
typedef int32_t CGPathDrawingMode;
#define kCGPathFill         0
#define kCGPathEOFill       1
#define kCGPathStroke       2
#define kCGPathFillStroke   3
#define kCGPathEOFillStroke 4

/* CGBlendMode */
typedef int32_t CGBlendMode;
#define kCGBlendModeNormal          0
#define kCGBlendModeMultiply        1
#define kCGBlendModeScreen          2
#define kCGBlendModeOverlay         3
#define kCGBlendModeDarken          4
#define kCGBlendModeLighten         5
#define kCGBlendModeColorDodge      6
#define kCGBlendModeColorBurn       7
#define kCGBlendModeSoftLight       8
#define kCGBlendModeHardLight       9
#define kCGBlendModeDifference      10
#define kCGBlendModeExclusion       11
#define kCGBlendModeHue             12
#define kCGBlendModeSaturation      13
#define kCGBlendModeColor           14
#define kCGBlendModeLuminosity      15
#define kCGBlendModeClear           16
#define kCGBlendModeCopy            17
#define kCGBlendModeSourceIn        18
#define kCGBlendModeSourceOut       19
#define kCGBlendModeSourceAtop      20
#define kCGBlendModeDestinationOver 21
#define kCGBlendModeDestinationIn   22
#define kCGBlendModeDestinationOut  23
#define kCGBlendModeDestinationAtop 24
#define kCGBlendModeXOR             25
#define kCGBlendModePlusDarker      26
#define kCGBlendModePlusLighter     27

/* CGTextDrawingMode */
typedef int32_t CGTextDrawingMode;
#define kCGTextFill           0
#define kCGTextStroke         1
#define kCGTextFillStroke     2
#define kCGTextInvisible      3

/* CGInterpolationQuality */
typedef int32_t CGInterpolationQuality;
#define kCGInterpolationDefault 0
#define kCGInterpolationNone    1
#define kCGInterpolationLow     2
#define kCGInterpolationHigh    3
#define kCGInterpolationMedium  4

/* CGPathElementType */
typedef int32_t CGPathElementType;
#define kCGPathElementMoveToPoint         0
#define kCGPathElementAddLineToPoint      1
#define kCGPathElementAddQuadCurveToPoint 2
#define kCGPathElementAddCurveToPoint     3
#define kCGPathElementCloseSubpath        4

/* Forward declarations for opaque CG types */
typedef const struct CGPath    *CGPathRef;
typedef       struct CGContext *CGContextRef;
typedef const struct CFArray   *CFArrayRef;
typedef const struct __CFDictionary *CFDictionaryRef;

/* CGPathElement (forward — full definition in Section 12) */
struct __CGPathElement;
typedef void (*CGPathApplierFunction)(void *info, const struct __CGPathElement *element);


/* ============================================================================
 * Section 7: Internal Reference Counting Helpers
 *
 * CG objects use a simple refcount scheme (not CFRuntime — CG objects are
 * NOT CF types on real macOS either, except via toll-free bridging which
 * we don't need yet).
 * ============================================================================ */

typedef struct __CGRefCounted {
    int32_t _refCount;
} __CGRefCounted;

CG_INLINE void __CGRetainInit(__CGRefCounted *obj) { obj->_refCount = 1; }
CG_INLINE void __CGRetain(__CGRefCounted *obj) { if (obj) __atomic_add_fetch(&obj->_refCount, 1, __ATOMIC_RELAXED); }
CG_INLINE bool __CGRelease(__CGRefCounted *obj) {
    if (!obj) return false;
    int32_t old = __atomic_fetch_sub(&obj->_refCount, 1, __ATOMIC_ACQ_REL);
    return old <= 1; /* true if should free */
}

/* ============================================================================
 * Section 8: CGColorSpace
 * ============================================================================ */

struct CGColorSpace {
    __CGRefCounted _rc;
    CGColorSpaceModel _model;
    size_t _numberOfComponents;
    char _name[64];
};
typedef struct CGColorSpace *CGColorSpaceRef;

/* Singleton device color spaces */
static struct CGColorSpace __CGColorSpaceDeviceRGB  = { {0x7FFFFFFF}, kCGColorSpaceModelRGB,  3, "kCGColorSpaceDeviceRGB" };
static struct CGColorSpace __CGColorSpaceDeviceGray = { {0x7FFFFFFF}, kCGColorSpaceModelMonochrome, 1, "kCGColorSpaceDeviceGray" };
static struct CGColorSpace __CGColorSpaceDeviceCMYK = { {0x7FFFFFFF}, kCGColorSpaceModelCMYK, 4, "kCGColorSpaceDeviceCMYK" };
static struct CGColorSpace __CGColorSpaceSRGB       = { {0x7FFFFFFF}, kCGColorSpaceModelRGB,  3, "kCGColorSpaceSRGB" };

EXPORT CGColorSpaceRef CGColorSpaceCreateDeviceRGB(void)  { return &__CGColorSpaceDeviceRGB; }
EXPORT CGColorSpaceRef CGColorSpaceCreateDeviceGray(void) { return &__CGColorSpaceDeviceGray; }
EXPORT CGColorSpaceRef CGColorSpaceCreateDeviceCMYK(void) { return &__CGColorSpaceDeviceCMYK; }

EXPORT CGColorSpaceRef CGColorSpaceCreateWithName(CFStringRef name) {
    if (!name) return NULL;
    const char *cstr = CFStringGetCStringPtr(name, kCFStringEncodingUTF8);
    if (!cstr) return &__CGColorSpaceSRGB;
    if (strcmp(cstr, "kCGColorSpaceSRGB") == 0 ||
        strcmp(cstr, "kCGColorSpaceGenericRGB") == 0 ||
        strcmp(cstr, "kCGColorSpaceLinearSRGB") == 0 ||
        strcmp(cstr, "kCGColorSpaceExtendedSRGB") == 0)
        return &__CGColorSpaceSRGB;
    if (strcmp(cstr, "kCGColorSpaceGenericGray") == 0 ||
        strcmp(cstr, "kCGColorSpaceGenericGrayGamma2_2") == 0)
        return &__CGColorSpaceDeviceGray;
    if (strcmp(cstr, "kCGColorSpaceGenericCMYK") == 0)
        return &__CGColorSpaceDeviceCMYK;
    /* Default to sRGB */
    return &__CGColorSpaceSRGB;
}

EXPORT CGColorSpaceRef CGColorSpaceRetain(CGColorSpaceRef space) {
    if (space) __CGRetain(&space->_rc);
    return space;
}

EXPORT void CGColorSpaceRelease(CGColorSpaceRef space) {
    if (!space) return;
    /* Don't free singletons */
    if (space == &__CGColorSpaceDeviceRGB || space == &__CGColorSpaceDeviceGray ||
        space == &__CGColorSpaceDeviceCMYK || space == &__CGColorSpaceSRGB) return;
    if (__CGRelease(&space->_rc)) free(space);
}

EXPORT size_t CGColorSpaceGetNumberOfComponents(CGColorSpaceRef space) {
    return space ? space->_numberOfComponents : 0;
}

EXPORT CGColorSpaceModel CGColorSpaceGetModel(CGColorSpaceRef space) {
    return space ? space->_model : kCGColorSpaceModelUnknown;
}

EXPORT CFStringRef CGColorSpaceCopyName(CGColorSpaceRef space) {
    if (!space) return NULL;
    return CFStringCreateWithCString(NULL, space->_name, kCFStringEncodingUTF8);
}

EXPORT CFStringRef CGColorSpaceGetName(CGColorSpaceRef space) {
    /* Returns a non-retained reference — use the interned constant */
    if (!space) return NULL;
    return __CFStringMakeConstantString(space->_name);
}

EXPORT CFTypeID CGColorSpaceGetTypeID(void) { return 0; /* Not a CF type */ }
EXPORT bool CGColorSpaceIsWideGamutRGB(CGColorSpaceRef s) { (void)s; return false; }
EXPORT bool CGColorSpaceIsHDR(CGColorSpaceRef s) { (void)s; return false; }
EXPORT bool CGColorSpaceUsesExtendedRange(CGColorSpaceRef s) { (void)s; return false; }
EXPORT bool CGColorSpaceSupportsOutput(CGColorSpaceRef s) { (void)s; return true; }

/* Color space name constants */
EXPORT const CFStringRef kCGColorSpaceGenericGray = NULL;  /* Set in constructor */
EXPORT const CFStringRef kCGColorSpaceGenericRGB  = NULL;
EXPORT const CFStringRef kCGColorSpaceSRGB        = NULL;
EXPORT const CFStringRef kCGColorSpaceGenericGrayGamma2_2 = NULL;
EXPORT const CFStringRef kCGColorSpaceGenericRGBLinear = NULL;
EXPORT const CFStringRef kCGColorSpaceDisplayP3   = NULL;
EXPORT const CFStringRef kCGColorSpaceLinearSRGB  = NULL;
EXPORT const CFStringRef kCGColorSpaceExtendedSRGB = NULL;

/* ============================================================================
 * Section 9: CGColor
 * ============================================================================ */

#define __CG_COLOR_MAX_COMPONENTS 5  /* CMYK+alpha */

struct CGColor {
    __CGRefCounted _rc;
    CGColorSpaceRef _space;
    size_t _numComponents;  /* including alpha */
    CGFloat _components[__CG_COLOR_MAX_COMPONENTS];
};
typedef struct CGColor *CGColorRef;

EXPORT CGColorRef CGColorCreate(CGColorSpaceRef space, const CGFloat *components) {
    if (!space || !components) return NULL;
    struct CGColor *c = (struct CGColor *)calloc(1, sizeof(struct CGColor));
    if (!c) return NULL;
    __CGRetainInit(&c->_rc);
    c->_space = space;
    c->_numComponents = CGColorSpaceGetNumberOfComponents(space) + 1; /* +1 for alpha */
    for (size_t i = 0; i < c->_numComponents && i < __CG_COLOR_MAX_COMPONENTS; i++)
        c->_components[i] = components[i];
    return c;
}

EXPORT CGColorRef CGColorCreateGenericRGB(CGFloat red, CGFloat green, CGFloat blue, CGFloat alpha) {
    CGFloat comps[4] = {red, green, blue, alpha};
    return CGColorCreate(&__CGColorSpaceSRGB, comps);
}

EXPORT CGColorRef CGColorCreateGenericGray(CGFloat gray, CGFloat alpha) {
    CGFloat comps[2] = {gray, alpha};
    return CGColorCreate(&__CGColorSpaceDeviceGray, comps);
}

EXPORT CGColorRef CGColorCreateSRGB(CGFloat red, CGFloat green, CGFloat blue, CGFloat alpha) {
    CGFloat comps[4] = {red, green, blue, alpha};
    return CGColorCreate(&__CGColorSpaceSRGB, comps);
}

EXPORT CGColorRef CGColorCreateCopy(CGColorRef color) {
    if (!color) return NULL;
    return CGColorCreate(color->_space, color->_components);
}

EXPORT CGColorRef CGColorCreateCopyWithAlpha(CGColorRef color, CGFloat alpha) {
    if (!color) return NULL;
    struct CGColor *c = (struct CGColor *)calloc(1, sizeof(struct CGColor));
    if (!c) return NULL;
    *c = *color;
    __CGRetainInit(&c->_rc);
    c->_components[c->_numComponents - 1] = alpha;
    return c;
}

EXPORT CGColorRef CGColorRetain(CGColorRef color) {
    if (color) __CGRetain(&color->_rc);
    return color;
}

EXPORT void CGColorRelease(CGColorRef color) {
    if (!color) return;
    if (__CGRelease(&color->_rc)) free(color);
}

EXPORT bool CGColorEqualToColor(CGColorRef c1, CGColorRef c2) {
    if (c1 == c2) return true;
    if (!c1 || !c2) return false;
    if (c1->_numComponents != c2->_numComponents) return false;
    for (size_t i = 0; i < c1->_numComponents; i++)
        if (c1->_components[i] != c2->_components[i]) return false;
    return true;
}

EXPORT size_t CGColorGetNumberOfComponents(CGColorRef color) {
    return color ? color->_numComponents : 0;
}

EXPORT const CGFloat *CGColorGetComponents(CGColorRef color) {
    return color ? color->_components : NULL;
}

EXPORT CGFloat CGColorGetAlpha(CGColorRef color) {
    if (!color || color->_numComponents == 0) return 0;
    return color->_components[color->_numComponents - 1];
}

EXPORT CGColorSpaceRef CGColorGetColorSpace(CGColorRef color) {
    return color ? color->_space : NULL;
}

EXPORT CFTypeID CGColorGetTypeID(void) { return 0; }

/* Constant color names */
EXPORT const CFStringRef kCGColorWhite = NULL;
EXPORT const CFStringRef kCGColorBlack = NULL;
EXPORT const CFStringRef kCGColorClear = NULL;

static struct CGColor __kCGColorWhiteInstance;
static struct CGColor __kCGColorBlackInstance;
static struct CGColor __kCGColorClearInstance;

EXPORT CGColorRef CGColorGetConstantColor(CFStringRef colorName) {
    if (!colorName) return NULL;
    const char *name = CFStringGetCStringPtr(colorName, kCFStringEncodingUTF8);
    if (!name) return NULL;
    if (strcmp(name, "kCGColorWhite") == 0) return &__kCGColorWhiteInstance;
    if (strcmp(name, "kCGColorBlack") == 0) return &__kCGColorBlackInstance;
    if (strcmp(name, "kCGColorClear") == 0) return &__kCGColorClearInstance;
    return NULL;
}


/* ============================================================================
 * Section 10: CGDataProvider
 * ============================================================================ */

typedef void (*CGDataProviderReleaseDataCallback)(void *info, const void *data, size_t size);

struct CGDataProvider {
    __CGRefCounted _rc;
    const void *_data;
    size_t      _size;
    void       *_info;
    CGDataProviderReleaseDataCallback _releaseCallback;
};
typedef struct CGDataProvider *CGDataProviderRef;

EXPORT CGDataProviderRef CGDataProviderCreateWithData(void *info, const void *data,
    size_t size, CGDataProviderReleaseDataCallback releaseData) {
    struct CGDataProvider *p = (struct CGDataProvider *)calloc(1, sizeof(struct CGDataProvider));
    if (!p) return NULL;
    __CGRetainInit(&p->_rc);
    p->_data = data;
    p->_size = size;
    p->_info = info;
    p->_releaseCallback = releaseData;
    return p;
}

EXPORT CGDataProviderRef CGDataProviderCreateWithCFData(CFDataRef data) {
    if (!data) return NULL;
    const uint8_t *bytes = CFDataGetBytePtr(data);
    CFIndex len = CFDataGetLength(data);
    /* We retain the CFData to keep the bytes alive */
    CFRetain(data);
    /* No release callback — the data is owned by the CFData */
    struct CGDataProvider *p = (struct CGDataProvider *)calloc(1, sizeof(struct CGDataProvider));
    if (!p) { CFRelease(data); return NULL; }
    __CGRetainInit(&p->_rc);
    p->_data = bytes;
    p->_size = (size_t)len;
    p->_info = (void *)data;
    p->_releaseCallback = NULL; /* TODO: release CFData on provider release */
    return p;
}

EXPORT CGDataProviderRef CGDataProviderRetain(CGDataProviderRef provider) {
    if (provider) __CGRetain(&provider->_rc);
    return provider;
}

EXPORT void CGDataProviderRelease(CGDataProviderRef provider) {
    if (!provider) return;
    if (__CGRelease(&provider->_rc)) {
        if (provider->_releaseCallback)
            provider->_releaseCallback(provider->_info, provider->_data, provider->_size);
        free(provider);
    }
}

EXPORT CFDataRef CGDataProviderCopyData(CGDataProviderRef provider) {
    if (!provider || !provider->_data) return NULL;
    return CFDataCreate(NULL, (const uint8_t *)provider->_data, (CFIndex)provider->_size);
}

EXPORT void *CGDataProviderGetInfo(CGDataProviderRef provider) {
    return provider ? provider->_info : NULL;
}

EXPORT CFTypeID CGDataProviderGetTypeID(void) { return 0; }

/* ============================================================================
 * Section 11: CGImage
 * ============================================================================ */

struct CGImage {
    __CGRefCounted _rc;
    size_t _width;
    size_t _height;
    size_t _bitsPerComponent;
    size_t _bitsPerPixel;
    size_t _bytesPerRow;
    CGColorSpaceRef _colorSpace;
    CGBitmapInfo _bitmapInfo;
    CGDataProviderRef _provider;
    bool _shouldInterpolate;
    CGColorRenderingIntent _intent;
};
typedef struct CGImage *CGImageRef;

EXPORT CGImageRef CGImageCreate(size_t width, size_t height,
    size_t bitsPerComponent, size_t bitsPerPixel, size_t bytesPerRow,
    CGColorSpaceRef space, CGBitmapInfo bitmapInfo,
    CGDataProviderRef provider, const CGFloat *decode,
    bool shouldInterpolate, CGColorRenderingIntent intent) {
    (void)decode;
    struct CGImage *img = (struct CGImage *)calloc(1, sizeof(struct CGImage));
    if (!img) return NULL;
    __CGRetainInit(&img->_rc);
    img->_width = width;
    img->_height = height;
    img->_bitsPerComponent = bitsPerComponent;
    img->_bitsPerPixel = bitsPerPixel;
    img->_bytesPerRow = bytesPerRow;
    img->_colorSpace = space;
    img->_bitmapInfo = bitmapInfo;
    img->_provider = provider;
    if (provider) CGDataProviderRetain(provider);
    img->_shouldInterpolate = shouldInterpolate;
    img->_intent = intent;
    return img;
}

EXPORT CGImageRef CGImageCreateCopy(CGImageRef image) {
    if (!image) return NULL;
    return CGImageCreate(image->_width, image->_height,
        image->_bitsPerComponent, image->_bitsPerPixel, image->_bytesPerRow,
        image->_colorSpace, image->_bitmapInfo, image->_provider,
        NULL, image->_shouldInterpolate, image->_intent);
}

EXPORT CGImageRef CGImageRetain(CGImageRef image) {
    if (image) __CGRetain(&image->_rc);
    return image;
}

EXPORT void CGImageRelease(CGImageRef image) {
    if (!image) return;
    if (__CGRelease(&image->_rc)) {
        if (image->_provider) CGDataProviderRelease(image->_provider);
        free(image);
    }
}

EXPORT size_t CGImageGetWidth(CGImageRef image)  { return image ? image->_width : 0; }
EXPORT size_t CGImageGetHeight(CGImageRef image) { return image ? image->_height : 0; }
EXPORT size_t CGImageGetBitsPerComponent(CGImageRef image) { return image ? image->_bitsPerComponent : 0; }
EXPORT size_t CGImageGetBitsPerPixel(CGImageRef image) { return image ? image->_bitsPerPixel : 0; }
EXPORT size_t CGImageGetBytesPerRow(CGImageRef image) { return image ? image->_bytesPerRow : 0; }
EXPORT CGColorSpaceRef CGImageGetColorSpace(CGImageRef image) { return image ? image->_colorSpace : NULL; }
EXPORT CGImageAlphaInfo CGImageGetAlphaInfo(CGImageRef image) {
    return image ? (image->_bitmapInfo & kCGBitmapAlphaInfoMask) : kCGImageAlphaNone;
}
EXPORT CGBitmapInfo CGImageGetBitmapInfo(CGImageRef image) { return image ? image->_bitmapInfo : 0; }
EXPORT CGDataProviderRef CGImageGetDataProvider(CGImageRef image) { return image ? image->_provider : NULL; }
EXPORT bool CGImageGetShouldInterpolate(CGImageRef image) { return image ? image->_shouldInterpolate : false; }
EXPORT CGColorRenderingIntent CGImageGetRenderingIntent(CGImageRef image) {
    return image ? image->_intent : kCGRenderingIntentDefault;
}
EXPORT bool CGImageIsMask(CGImageRef image) { (void)image; return false; }
EXPORT CFTypeID CGImageGetTypeID(void) { return 0; }


/* ====================================================================
 * Section 12 — CGPath
 * ====================================================================
 * CGPath stores an array of path elements. Each element has a type
 * (move, line, quad curve, cubic curve, close) and up to 3 points.
 * CGMutablePathRef is a typedef to the same struct — mutability is
 * a convention, not a different type (matching real CG).
 * ==================================================================== */

/* CGPathElement uses CGPathElementType already defined as #define macros in Section 6 */

typedef struct __CGPathElement {
    CGPathElementType type;
    CGPoint           points[3]; /* move/line: [0]; quad: [0..1]; cubic: [0..2]; close: unused */
} CGPathElement;

struct CGPath {
    __CGRefCounted  _rc;
    CGPathElement  *_elements;
    size_t          _count;
    size_t          _capacity;
    CGRect          _boundingBox;       /* cached, recomputed on mutation */
    CGPoint         _currentPoint;
    bool            _boundingBoxValid;
};

typedef struct CGPath *CGMutablePathRef;

/* --- helpers --- */

static void __CGPathGrow(struct CGPath *p) {
    size_t newCap = p->_capacity ? p->_capacity * 2 : 16;
    CGPathElement *newBuf = (CGPathElement *)realloc(p->_elements,
        newCap * sizeof(CGPathElement));
    if (!newBuf) return;
    p->_elements = newBuf;
    p->_capacity = newCap;
}

static void __CGPathAppend(struct CGPath *p, CGPathElementType type,
                           const CGPoint *pts, size_t npts) {
    if (p->_count >= p->_capacity) __CGPathGrow(p);
    if (p->_count >= p->_capacity) return; /* OOM */
    CGPathElement *e = &p->_elements[p->_count++];
    e->type = type;
    for (size_t i = 0; i < npts && i < 3; i++) e->points[i] = pts[i];
    p->_boundingBoxValid = false;
}

static void __CGPathUpdateBBox(struct CGPath *p) {
    if (p->_boundingBoxValid) return;
    if (p->_count == 0) {
        p->_boundingBox = CGRectNull;
        p->_boundingBoxValid = true;
        return;
    }
    CGFloat minX = 1e30, minY = 1e30, maxX = -1e30, maxY = -1e30;
    for (size_t i = 0; i < p->_count; i++) {
        CGPathElement *e = &p->_elements[i];
        size_t np = 0;
        switch (e->type) {
            case kCGPathElementMoveToPoint:       np = 1; break;
            case kCGPathElementAddLineToPoint:    np = 1; break;
            case kCGPathElementAddQuadCurveToPoint: np = 2; break;
            case kCGPathElementAddCurveToPoint:   np = 3; break;
            case kCGPathElementCloseSubpath:       np = 0; break;
        }
        for (size_t j = 0; j < np; j++) {
            if (e->points[j].x < minX) minX = e->points[j].x;
            if (e->points[j].x > maxX) maxX = e->points[j].x;
            if (e->points[j].y < minY) minY = e->points[j].y;
            if (e->points[j].y > maxY) maxY = e->points[j].y;
        }
    }
    p->_boundingBox = CGRectMake(minX, minY, maxX - minX, maxY - minY);
    p->_boundingBoxValid = true;
}

/* --- creation --- */

EXPORT CGMutablePathRef CGPathCreateMutable(void) {
    struct CGPath *p = (struct CGPath *)calloc(1, sizeof(struct CGPath));
    if (!p) return NULL;
    __CGRetainInit(&p->_rc);
    p->_boundingBox = CGRectNull;
    return p;
}

EXPORT CGPathRef CGPathCreateCopy(CGPathRef path) {
    if (!path) return NULL;
    struct CGPath *p = CGPathCreateMutable();
    if (!p) return NULL;
    if (path->_count > 0) {
        p->_elements = (CGPathElement *)malloc(path->_count * sizeof(CGPathElement));
        if (p->_elements) {
            memcpy(p->_elements, path->_elements, path->_count * sizeof(CGPathElement));
            p->_count = path->_count;
            p->_capacity = path->_count;
        }
    }
    p->_currentPoint = path->_currentPoint;
    p->_boundingBox = path->_boundingBox;
    p->_boundingBoxValid = path->_boundingBoxValid;
    return p;
}

EXPORT CGMutablePathRef CGPathCreateMutableCopy(CGPathRef path) {
    return (CGMutablePathRef)CGPathCreateCopy(path);
}

EXPORT CGPathRef CGPathRetain(CGPathRef path) {
    if (path) __CGRetain(&((struct CGPath *)path)->_rc);
    return path;
}

EXPORT void CGPathRelease(CGPathRef path) {
    if (!path) return;
    struct CGPath *p = (struct CGPath *)path;
    if (__CGRelease(&p->_rc)) {
        free(p->_elements);
        free(p);
    }
}

/* --- mutation --- */

EXPORT void CGPathMoveToPoint(CGMutablePathRef path,
    const CGAffineTransform *m, CGFloat x, CGFloat y) {
    if (!path) return;
    CGPoint pt = CGPointMake(x, y);
    if (m) pt = CGPointApplyAffineTransform(pt, *m);
    __CGPathAppend(path, kCGPathElementMoveToPoint, &pt, 1);
    path->_currentPoint = pt;
}

EXPORT void CGPathAddLineToPoint(CGMutablePathRef path,
    const CGAffineTransform *m, CGFloat x, CGFloat y) {
    if (!path) return;
    CGPoint pt = CGPointMake(x, y);
    if (m) pt = CGPointApplyAffineTransform(pt, *m);
    __CGPathAppend(path, kCGPathElementAddLineToPoint, &pt, 1);
    path->_currentPoint = pt;
}

EXPORT void CGPathAddQuadCurveToPoint(CGMutablePathRef path,
    const CGAffineTransform *m, CGFloat cpx, CGFloat cpy,
    CGFloat x, CGFloat y) {
    if (!path) return;
    CGPoint pts[2];
    pts[0] = CGPointMake(cpx, cpy);
    pts[1] = CGPointMake(x, y);
    if (m) {
        pts[0] = CGPointApplyAffineTransform(pts[0], *m);
        pts[1] = CGPointApplyAffineTransform(pts[1], *m);
    }
    __CGPathAppend(path, kCGPathElementAddQuadCurveToPoint, pts, 2);
    path->_currentPoint = pts[1];
}

EXPORT void CGPathAddCurveToPoint(CGMutablePathRef path,
    const CGAffineTransform *m, CGFloat cp1x, CGFloat cp1y,
    CGFloat cp2x, CGFloat cp2y, CGFloat x, CGFloat y) {
    if (!path) return;
    CGPoint pts[3];
    pts[0] = CGPointMake(cp1x, cp1y);
    pts[1] = CGPointMake(cp2x, cp2y);
    pts[2] = CGPointMake(x, y);
    if (m) {
        pts[0] = CGPointApplyAffineTransform(pts[0], *m);
        pts[1] = CGPointApplyAffineTransform(pts[1], *m);
        pts[2] = CGPointApplyAffineTransform(pts[2], *m);
    }
    __CGPathAppend(path, kCGPathElementAddCurveToPoint, pts, 3);
    path->_currentPoint = pts[2];
}

EXPORT void CGPathCloseSubpath(CGMutablePathRef path) {
    if (!path) return;
    __CGPathAppend(path, kCGPathElementCloseSubpath, NULL, 0);
    /* macOS resets current point to the start of the subpath.
     * Find the last MoveTo to determine start. */
    for (size_t i = path->_count; i > 0; i--) {
        if (path->_elements[i-1].type == kCGPathElementMoveToPoint) {
            path->_currentPoint = path->_elements[i-1].points[0];
            break;
        }
    }
}

EXPORT void CGPathAddRect(CGMutablePathRef path,
    const CGAffineTransform *m, CGRect rect) {
    if (!path) return;
    /* macOS adds rect as: move(minX,minY) -> line(maxX,minY) -> line(maxX,maxY)
     * -> line(minX,maxY) -> close. Counter-clockwise in CG coords. */
    CGPathMoveToPoint(path, m, CGRectGetMinX(rect), CGRectGetMinY(rect));
    CGPathAddLineToPoint(path, m, CGRectGetMaxX(rect), CGRectGetMinY(rect));
    CGPathAddLineToPoint(path, m, CGRectGetMaxX(rect), CGRectGetMaxY(rect));
    CGPathAddLineToPoint(path, m, CGRectGetMinX(rect), CGRectGetMaxY(rect));
    CGPathCloseSubpath(path);
}

EXPORT void CGPathAddRects(CGMutablePathRef path,
    const CGAffineTransform *m, const CGRect *rects, size_t count) {
    if (!path || !rects) return;
    for (size_t i = 0; i < count; i++)
        CGPathAddRect(path, m, rects[i]);
}

EXPORT void CGPathAddLines(CGMutablePathRef path,
    const CGAffineTransform *m, const CGPoint *points, size_t count) {
    if (!path || !points || count < 1) return;
    CGPathMoveToPoint(path, m, points[0].x, points[0].y);
    for (size_t i = 1; i < count; i++)
        CGPathAddLineToPoint(path, m, points[i].x, points[i].y);
}

EXPORT void CGPathAddEllipseInRect(CGMutablePathRef path,
    const CGAffineTransform *m, CGRect rect) {
    if (!path) return;
    /* Approximate ellipse with 4 cubic Bézier curves (standard kappa = 0.5522847498) */
    CGFloat cx = CGRectGetMidX(rect), cy = CGRectGetMidY(rect);
    CGFloat rx = rect.size.width / 2.0, ry = rect.size.height / 2.0;
    CGFloat k = (CGFloat)0.5522847498;
    CGPathMoveToPoint(path, m, cx + rx, cy);
    CGPathAddCurveToPoint(path, m,
        cx + rx, cy + ry * k,
        cx + rx * k, cy + ry,
        cx, cy + ry);
    CGPathAddCurveToPoint(path, m,
        cx - rx * k, cy + ry,
        cx - rx, cy + ry * k,
        cx - rx, cy);
    CGPathAddCurveToPoint(path, m,
        cx - rx, cy - ry * k,
        cx - rx * k, cy - ry,
        cx, cy - ry);
    CGPathAddCurveToPoint(path, m,
        cx + rx * k, cy - ry,
        cx + rx, cy - ry * k,
        cx + rx, cy);
    CGPathCloseSubpath(path);
}

EXPORT void CGPathAddArc(CGMutablePathRef path,
    const CGAffineTransform *m, CGFloat x, CGFloat y,
    CGFloat radius, CGFloat startAngle, CGFloat endAngle,
    bool clockwise) {
    if (!path) return;
    /* Approximate arc with line segments (32 segments per full circle) */
    CGFloat sweep = endAngle - startAngle;
    if (clockwise) {
        if (sweep > 0) sweep -= 2.0 * 3.14159265358979323846;
    } else {
        if (sweep < 0) sweep += 2.0 * 3.14159265358979323846;
    }
    int nsegs = (int)(32.0 * __builtin_fabs(sweep) / (2.0 * 3.14159265358979323846));
    if (nsegs < 1) nsegs = 1;
    CGFloat dtheta = sweep / (CGFloat)nsegs;
    CGFloat theta = startAngle;
    CGFloat sx = x + radius * __builtin_cos(theta);
    CGFloat sy = y + radius * __builtin_sin(theta);
    /* If the path has no current point, move; otherwise line to start */
    if (path->_count == 0)
        CGPathMoveToPoint(path, m, sx, sy);
    else
        CGPathAddLineToPoint(path, m, sx, sy);
    for (int i = 1; i <= nsegs; i++) {
        theta = startAngle + dtheta * (CGFloat)i;
        CGFloat ex = x + radius * __builtin_cos(theta);
        CGFloat ey = y + radius * __builtin_sin(theta);
        CGPathAddLineToPoint(path, m, ex, ey);
    }
}

EXPORT void CGPathAddArcToPoint(CGMutablePathRef path,
    const CGAffineTransform *m, CGFloat x1, CGFloat y1,
    CGFloat x2, CGFloat y2, CGFloat radius) {
    if (!path) return;
    /* Simplified: draw line to tangent point then arc.
     * For now, approximate with two line segments (matches common usage). */
    CGPathAddLineToPoint(path, m, x1, y1);
    CGPathAddLineToPoint(path, m, x2, y2);
}

EXPORT void CGPathAddRoundedRect(CGMutablePathRef path,
    const CGAffineTransform *m, CGRect rect,
    CGFloat cornerWidth, CGFloat cornerHeight) {
    if (!path) return;
    CGFloat minX = CGRectGetMinX(rect), minY = CGRectGetMinY(rect);
    CGFloat maxX = CGRectGetMaxX(rect), maxY = CGRectGetMaxY(rect);
    CGFloat cw = cornerWidth, ch = cornerHeight;
    CGFloat k = (CGFloat)0.5522847498;
    CGPathMoveToPoint(path, m, minX + cw, minY);
    CGPathAddLineToPoint(path, m, maxX - cw, minY);
    CGPathAddCurveToPoint(path, m,
        maxX - cw + cw * k, minY,
        maxX, minY + ch - ch * k,
        maxX, minY + ch);
    CGPathAddLineToPoint(path, m, maxX, maxY - ch);
    CGPathAddCurveToPoint(path, m,
        maxX, maxY - ch + ch * k,
        maxX - cw + cw * k, maxY,
        maxX - cw, maxY);
    CGPathAddLineToPoint(path, m, minX + cw, maxY);
    CGPathAddCurveToPoint(path, m,
        minX + cw - cw * k, maxY,
        minX, maxY - ch + ch * k,
        minX, maxY - ch);
    CGPathAddLineToPoint(path, m, minX, minY + ch);
    CGPathAddCurveToPoint(path, m,
        minX, minY + ch - ch * k,
        minX + cw - cw * k, minY,
        minX + cw, minY);
    CGPathCloseSubpath(path);
}

EXPORT void CGPathAddPath(CGMutablePathRef path1,
    const CGAffineTransform *m, CGPathRef path2) {
    if (!path1 || !path2) return;
    for (size_t i = 0; i < path2->_count; i++) {
        CGPathElement *e = &path2->_elements[i];
        switch (e->type) {
            case kCGPathElementMoveToPoint:
                CGPathMoveToPoint(path1, m, e->points[0].x, e->points[0].y);
                break;
            case kCGPathElementAddLineToPoint:
                CGPathAddLineToPoint(path1, m, e->points[0].x, e->points[0].y);
                break;
            case kCGPathElementAddQuadCurveToPoint:
                CGPathAddQuadCurveToPoint(path1, m,
                    e->points[0].x, e->points[0].y,
                    e->points[1].x, e->points[1].y);
                break;
            case kCGPathElementAddCurveToPoint:
                CGPathAddCurveToPoint(path1, m,
                    e->points[0].x, e->points[0].y,
                    e->points[1].x, e->points[1].y,
                    e->points[2].x, e->points[2].y);
                break;
            case kCGPathElementCloseSubpath:
                CGPathCloseSubpath(path1);
                break;
        }
    }
}

/* --- query --- */

EXPORT bool CGPathIsEmpty(CGPathRef path) {
    return !path || path->_count == 0;
}

EXPORT CGPoint CGPathGetCurrentPoint(CGPathRef path) {
    if (!path) return CGPointZero;
    return path->_currentPoint;
}

EXPORT CGRect CGPathGetBoundingBox(CGPathRef path) {
    if (!path) return CGRectNull;
    __CGPathUpdateBBox((struct CGPath *)path);
    return path->_boundingBox;
}

EXPORT CGRect CGPathGetPathBoundingBox(CGPathRef path) {
    return CGPathGetBoundingBox(path);
}

EXPORT bool CGPathContainsPoint(CGPathRef path,
    const CGAffineTransform *m, CGPoint point, bool eoFill) {
    if (!path || path->_count == 0) return false;
    /* Ray-casting algorithm for point-in-polygon test.
     * Transform point by inverse of m if m is provided. */
    CGPoint testPt = point;
    if (m) {
        CGAffineTransform inv = CGAffineTransformInvert(*m);
        testPt = CGPointApplyAffineTransform(testPt, inv);
    }
    /* Flatten path to line segments and perform even-odd or winding test */
    int crossings = 0;
    CGPoint cur = CGPointZero, subpathStart = CGPointZero;
    for (size_t i = 0; i < path->_count; i++) {
        CGPathElement *e = &path->_elements[i];
        CGPoint next;
        switch (e->type) {
            case kCGPathElementMoveToPoint:
                cur = e->points[0];
                subpathStart = cur;
                continue;
            case kCGPathElementAddLineToPoint:
                next = e->points[0];
                break;
            case kCGPathElementCloseSubpath:
                next = subpathStart;
                break;
            default:
                /* For curves, approximate with endpoint (simplified) */
                if (e->type == kCGPathElementAddQuadCurveToPoint)
                    next = e->points[1];
                else
                    next = e->points[2];
                break;
        }
        /* Test horizontal ray from testPt going right */
        CGFloat y0 = cur.y, y1 = next.y;
        if ((y0 <= testPt.y && y1 > testPt.y) ||
            (y1 <= testPt.y && y0 > testPt.y)) {
            CGFloat xIntersect = cur.x + (testPt.y - y0) / (y1 - y0) * (next.x - cur.x);
            if (testPt.x < xIntersect)
                crossings++;
        }
        cur = next;
    }
    if (eoFill)
        return (crossings & 1) != 0;
    else
        return crossings != 0; /* Simplified winding — proper winding needs signed crossings */
}

/* --- apply --- */

EXPORT void CGPathApply(CGPathRef path, void *info,
    CGPathApplierFunction function) {
    if (!path || !function) return;
    for (size_t i = 0; i < path->_count; i++) {
        CGPathElement *e = &path->_elements[i];
        function(info, e);
    }
}

EXPORT bool CGPathEqualToPath(CGPathRef path1, CGPathRef path2) {
    if (path1 == path2) return true;
    if (!path1 || !path2) return false;
    if (path1->_count != path2->_count) return false;
    return memcmp(path1->_elements, path2->_elements,
        path1->_count * sizeof(CGPathElement)) == 0;
}

EXPORT CFTypeID CGPathGetTypeID(void) { return 0; }


/* ====================================================================
 * Section 13 — CGContext internal structure
 * ====================================================================
 * The context holds a graphics state stack (linked list). Each state
 * stores fill/stroke color, CTM, clip rect, blend mode, global alpha,
 * line width/cap/join, miter limit, flatness, should-antialias,
 * text drawing mode, character spacing, text position, and font.
 *
 * The context itself stores:
 *   - pointer to head of gstate stack
 *   - current path (owned, built up then consumed by draw/clip ops)
 *   - context type tag (bitmap, PDF, etc.)
 *   - for bitmap contexts: pixel buffer info
 * ==================================================================== */

/* CGTextDrawingMode and CGInterpolationQuality are defined as
 * typedef int32_t + #define in Section 6. No redefinition needed. */

/* --- Graphics state (GState) --- */

typedef struct __CGGState {
    /* Fill and stroke colours (RGBA components, premultiplied) */
    CGFloat fillColor[4];       /* r, g, b, a */
    CGFloat strokeColor[4];     /* r, g, b, a */

    /* Current transformation matrix */
    CGAffineTransform ctm;

    /* Clipping rectangle (in device space) — simplified single-rect clip.
     * Real CG uses a clip path/region, but for our software rasteriser
     * a single rect is sufficient for the Terminal.app use case.
     * We also keep a clip path for CGContextClip(). */
    CGRect clipRect;

    /* Line drawing parameters */
    CGFloat   lineWidth;
    CGLineCap  lineCap;
    CGLineJoin lineJoin;
    CGFloat   miterLimit;
    CGFloat   flatness;

    /* Blend mode and global alpha */
    CGBlendMode blendMode;
    CGFloat     alpha;

    /* Anti-aliasing */
    bool shouldAntialias;

    /* Text state */
    CGTextDrawingMode textDrawingMode;
    CGFloat characterSpacing;
    CGPoint textPosition;
    /* CGFontRef font — will add when CoreText is implemented */

    /* Interpolation quality for image drawing */
    CGInterpolationQuality interpolationQuality;

    /* Shadow (stub — stored but not rendered) */
    CGSize  shadowOffset;
    CGFloat shadowBlur;
    /* CGColorRef shadowColor — NULL for now */

    /* Linked list: previous state (for SaveGState/RestoreGState) */
    struct __CGGState *_prev;
} __CGGState;

/* --- GState helpers --- */

static __CGGState *__CGGStateCreate(void) {
    __CGGState *gs = (__CGGState *)calloc(1, sizeof(__CGGState));
    if (!gs) return NULL;
    /* Default fill: black opaque */
    gs->fillColor[0] = 0.0; gs->fillColor[1] = 0.0;
    gs->fillColor[2] = 0.0; gs->fillColor[3] = 1.0;
    /* Default stroke: black opaque */
    gs->strokeColor[0] = 0.0; gs->strokeColor[1] = 0.0;
    gs->strokeColor[2] = 0.0; gs->strokeColor[3] = 1.0;
    /* Identity CTM */
    gs->ctm = CGAffineTransformIdentity;
    /* Clip to infinite rect initially (will be intersected with bitmap bounds) */
    gs->clipRect = CGRectMake(-1e30, -1e30, 2e30, 2e30);
    /* Line defaults */
    gs->lineWidth = 1.0;
    gs->lineCap = kCGLineCapButt;
    gs->lineJoin = kCGLineJoinMiter;
    gs->miterLimit = 10.0;
    gs->flatness = 0.5;
    /* Blend and alpha */
    gs->blendMode = kCGBlendModeNormal;
    gs->alpha = 1.0;
    /* Anti-alias on by default */
    gs->shouldAntialias = true;
    /* Text */
    gs->textDrawingMode = kCGTextFill;
    gs->characterSpacing = 0.0;
    gs->textPosition = CGPointZero;
    /* Interpolation */
    gs->interpolationQuality = kCGInterpolationDefault;
    /* Shadow off */
    gs->shadowOffset = CGSizeMake(0, 0);
    gs->shadowBlur = 0.0;
    return gs;
}

static __CGGState *__CGGStateCopy(const __CGGState *src) {
    __CGGState *gs = (__CGGState *)malloc(sizeof(__CGGState));
    if (!gs) return NULL;
    memcpy(gs, src, sizeof(__CGGState));
    gs->_prev = NULL; /* detach from chain */
    return gs;
}

static void __CGGStateDestroy(__CGGState *gs) {
    free(gs);
}

/* --- Context type tag --- */

typedef enum {
    __kCGContextTypeBitmap = 1,
    __kCGContextTypePDF    = 2,  /* stub */
} __CGContextType;

/* --- CGContext struct --- */

struct CGContext {
    __CGRefCounted   _rc;
    __CGContextType  _type;

    /* Current graphics state (head of stack) */
    __CGGState      *_gstate;

    /* Current path being constructed */
    CGMutablePathRef _path;

    /* === Bitmap context fields === */
    void            *_data;
    size_t           _width;
    size_t           _height;
    size_t           _bitsPerComponent;
    size_t           _bytesPerRow;
    CGColorSpaceRef  _colorSpace;
    CGBitmapInfo     _bitmapInfo;
    bool             _ownsData; /* true if we allocated _data */
};


/* ====================================================================
 * Section 14 — CGBitmapContext
 * ====================================================================
 * CGBitmapContextCreate creates a context backed by a pixel buffer.
 * If data is NULL, we allocate it. The context owns the buffer in
 * that case and frees it on release.
 *
 * Supported pixel formats (matching macOS):
 *   - 8 bpc, 4 components (RGBA/BGRA), 32 bpp
 *   - kCGImageAlphaPremultipliedFirst + kCGBitmapByteOrder32Little = BGRA8888
 *   - kCGImageAlphaPremultipliedLast = RGBA8888
 * ==================================================================== */

EXPORT CGContextRef CGBitmapContextCreate(
    void *data, size_t width, size_t height,
    size_t bitsPerComponent, size_t bytesPerRow,
    CGColorSpaceRef space, uint32_t bitmapInfo) {
    if (width == 0 || height == 0) return NULL;
    if (bitsPerComponent != 8) return NULL; /* only 8bpc supported */

    /* Calculate bytesPerRow if caller passed 0 */
    size_t componentsPerPixel = 4; /* RGBA */
    if (bytesPerRow == 0)
        bytesPerRow = width * componentsPerPixel;

    bool ownsData = false;
    if (!data) {
        data = calloc(height, bytesPerRow);
        if (!data) return NULL;
        ownsData = true;
    }

    struct CGContext *ctx = (struct CGContext *)calloc(1, sizeof(struct CGContext));
    if (!ctx) {
        if (ownsData) free(data);
        return NULL;
    }

    __CGRetainInit(&ctx->_rc);
    ctx->_type = __kCGContextTypeBitmap;
    ctx->_data = data;
    ctx->_width = width;
    ctx->_height = height;
    ctx->_bitsPerComponent = bitsPerComponent;
    ctx->_bytesPerRow = bytesPerRow;
    ctx->_colorSpace = space;
    ctx->_bitmapInfo = bitmapInfo;
    ctx->_ownsData = ownsData;

    /* Initialise the graphics state */
    ctx->_gstate = __CGGStateCreate();
    if (!ctx->_gstate) {
        if (ownsData) free(data);
        free(ctx);
        return NULL;
    }
    /* Set initial clip to bitmap bounds */
    ctx->_gstate->clipRect = CGRectMake(0, 0, (CGFloat)width, (CGFloat)height);

    /* Create empty current path */
    ctx->_path = CGPathCreateMutable();

    return ctx;
}

EXPORT CGContextRef CGBitmapContextCreateWithData(
    void *data, size_t width, size_t height,
    size_t bitsPerComponent, size_t bytesPerRow,
    CGColorSpaceRef space, uint32_t bitmapInfo,
    void (*releaseCallback)(void *releaseInfo, void *data),
    void *releaseInfo) {
    /* For our purposes, ignore the release callback and delegate to the
     * standard create function. The data pointer is caller-managed. */
    (void)releaseCallback;
    (void)releaseInfo;
    CGContextRef ctx = CGBitmapContextCreate(data, width, height,
        bitsPerComponent, bytesPerRow, space, bitmapInfo);
    if (ctx && data) {
        /* Data was provided by caller — we don't own it */
        ((struct CGContext *)ctx)->_ownsData = false;
    }
    return ctx;
}

/* --- Accessors --- */

EXPORT void *CGBitmapContextGetData(CGContextRef c) {
    if (!c) return NULL;
    return c->_data;
}

EXPORT size_t CGBitmapContextGetWidth(CGContextRef c) {
    return c ? c->_width : 0;
}

EXPORT size_t CGBitmapContextGetHeight(CGContextRef c) {
    return c ? c->_height : 0;
}

EXPORT size_t CGBitmapContextGetBitsPerComponent(CGContextRef c) {
    return c ? c->_bitsPerComponent : 0;
}

EXPORT size_t CGBitmapContextGetBitsPerPixel(CGContextRef c) {
    return c ? c->_bitsPerComponent * 4 : 0; /* assume 4 components */
}

EXPORT size_t CGBitmapContextGetBytesPerRow(CGContextRef c) {
    return c ? c->_bytesPerRow : 0;
}

EXPORT CGColorSpaceRef CGBitmapContextGetColorSpace(CGContextRef c) {
    return c ? c->_colorSpace : NULL;
}

EXPORT CGImageAlphaInfo CGBitmapContextGetAlphaInfo(CGContextRef c) {
    if (!c) return kCGImageAlphaNone;
    return (CGImageAlphaInfo)(c->_bitmapInfo & kCGBitmapAlphaInfoMask);
}

EXPORT CGBitmapInfo CGBitmapContextGetBitmapInfo(CGContextRef c) {
    return c ? c->_bitmapInfo : 0;
}

/* --- Create CGImage from bitmap context --- */

EXPORT CGImageRef CGBitmapContextCreateImage(CGContextRef c) {
    if (!c || c->_type != __kCGContextTypeBitmap) return NULL;
    /* Copy the pixel data */
    size_t dataSize = c->_height * c->_bytesPerRow;
    void *dataCopy = malloc(dataSize);
    if (!dataCopy) return NULL;
    memcpy(dataCopy, c->_data, dataSize);

    /* Wrap in a data provider */
    CFDataRef cfdata = CFDataCreate(NULL, (const uint8_t *)dataCopy, (CFIndex)dataSize);
    free(dataCopy);
    if (!cfdata) return NULL;

    CGDataProviderRef provider = CGDataProviderCreateWithCFData(cfdata);
    CFRelease(cfdata);
    if (!provider) return NULL;

    CGImageRef img = CGImageCreate(
        c->_width, c->_height,
        c->_bitsPerComponent,
        c->_bitsPerComponent * 4, /* bitsPerPixel */
        c->_bytesPerRow,
        c->_colorSpace,
        c->_bitmapInfo,
        provider,
        NULL, false,
        kCGRenderingIntentDefault);

    CGDataProviderRelease(provider);
    return img;
}

/* --- Context retain/release --- */

EXPORT CGContextRef CGContextRetain(CGContextRef c) {
    if (c) __CGRetain(&c->_rc);
    return c;
}

EXPORT void CGContextRelease(CGContextRef c) {
    if (!c) return;
    if (__CGRelease(&c->_rc)) {
        /* Free gstate stack */
        __CGGState *gs = c->_gstate;
        while (gs) {
            __CGGState *prev = gs->_prev;
            __CGGStateDestroy(gs);
            gs = prev;
        }
        /* Free current path */
        if (c->_path) CGPathRelease(c->_path);
        /* Free bitmap data if we own it */
        if (c->_ownsData && c->_data) free(c->_data);
        free(c);
    }
}

EXPORT CFTypeID CGContextGetTypeID(void) { return 0; }


/* ====================================================================
 * Section 15 — CGContext drawing state
 * ====================================================================
 * SaveGState/RestoreGState, fill/stroke colour, line width/cap/join,
 * alpha, blend mode, anti-aliasing, shadow, flatness, text mode, etc.
 * ==================================================================== */

EXPORT void CGContextSaveGState(CGContextRef c) {
    if (!c || !c->_gstate) return;
    __CGGState *copy = __CGGStateCopy(c->_gstate);
    if (!copy) return;
    copy->_prev = c->_gstate;
    c->_gstate = copy;
}

EXPORT void CGContextRestoreGState(CGContextRef c) {
    if (!c || !c->_gstate || !c->_gstate->_prev) return;
    __CGGState *old = c->_gstate;
    c->_gstate = old->_prev;
    __CGGStateDestroy(old);
}

/* --- Fill colour --- */

EXPORT void CGContextSetRGBFillColor(CGContextRef c,
    CGFloat red, CGFloat green, CGFloat blue, CGFloat alpha) {
    if (!c || !c->_gstate) return;
    c->_gstate->fillColor[0] = red;
    c->_gstate->fillColor[1] = green;
    c->_gstate->fillColor[2] = blue;
    c->_gstate->fillColor[3] = alpha;
}

EXPORT void CGContextSetGrayFillColor(CGContextRef c, CGFloat gray, CGFloat alpha) {
    CGContextSetRGBFillColor(c, gray, gray, gray, alpha);
}

EXPORT void CGContextSetFillColorWithColor(CGContextRef c, CGColorRef color) {
    if (!c || !c->_gstate || !color) return;
    const CGFloat *comp = CGColorGetComponents(color);
    size_t n = CGColorGetNumberOfComponents(color);
    if (n >= 4) {
        c->_gstate->fillColor[0] = comp[0];
        c->_gstate->fillColor[1] = comp[1];
        c->_gstate->fillColor[2] = comp[2];
        c->_gstate->fillColor[3] = comp[3];
    } else if (n >= 2) {
        /* Gray + alpha */
        c->_gstate->fillColor[0] = comp[0];
        c->_gstate->fillColor[1] = comp[0];
        c->_gstate->fillColor[2] = comp[0];
        c->_gstate->fillColor[3] = comp[1];
    }
}

EXPORT void CGContextSetCMYKFillColor(CGContextRef c,
    CGFloat cyan, CGFloat magenta, CGFloat yellow, CGFloat black, CGFloat alpha) {
    if (!c || !c->_gstate) return;
    /* Simple CMYK to RGB conversion */
    CGFloat r = (1.0 - cyan)   * (1.0 - black);
    CGFloat g = (1.0 - magenta) * (1.0 - black);
    CGFloat b = (1.0 - yellow)  * (1.0 - black);
    CGContextSetRGBFillColor(c, r, g, b, alpha);
}

/* --- Stroke colour --- */

EXPORT void CGContextSetRGBStrokeColor(CGContextRef c,
    CGFloat red, CGFloat green, CGFloat blue, CGFloat alpha) {
    if (!c || !c->_gstate) return;
    c->_gstate->strokeColor[0] = red;
    c->_gstate->strokeColor[1] = green;
    c->_gstate->strokeColor[2] = blue;
    c->_gstate->strokeColor[3] = alpha;
}

EXPORT void CGContextSetGrayStrokeColor(CGContextRef c, CGFloat gray, CGFloat alpha) {
    CGContextSetRGBStrokeColor(c, gray, gray, gray, alpha);
}

EXPORT void CGContextSetStrokeColorWithColor(CGContextRef c, CGColorRef color) {
    if (!c || !c->_gstate || !color) return;
    const CGFloat *comp = CGColorGetComponents(color);
    size_t n = CGColorGetNumberOfComponents(color);
    if (n >= 4) {
        c->_gstate->strokeColor[0] = comp[0];
        c->_gstate->strokeColor[1] = comp[1];
        c->_gstate->strokeColor[2] = comp[2];
        c->_gstate->strokeColor[3] = comp[3];
    } else if (n >= 2) {
        c->_gstate->strokeColor[0] = comp[0];
        c->_gstate->strokeColor[1] = comp[0];
        c->_gstate->strokeColor[2] = comp[0];
        c->_gstate->strokeColor[3] = comp[1];
    }
}

EXPORT void CGContextSetCMYKStrokeColor(CGContextRef c,
    CGFloat cyan, CGFloat magenta, CGFloat yellow, CGFloat black, CGFloat alpha) {
    if (!c || !c->_gstate) return;
    CGFloat r = (1.0 - cyan)   * (1.0 - black);
    CGFloat g = (1.0 - magenta) * (1.0 - black);
    CGFloat b = (1.0 - yellow)  * (1.0 - black);
    CGContextSetRGBStrokeColor(c, r, g, b, alpha);
}

/* --- Fill/Stroke with color space + components (generic) --- */

EXPORT void CGContextSetFillColor(CGContextRef c, const CGFloat *components) {
    if (!c || !c->_gstate || !components) return;
    /* Assume RGBA */
    c->_gstate->fillColor[0] = components[0];
    c->_gstate->fillColor[1] = components[1];
    c->_gstate->fillColor[2] = components[2];
    c->_gstate->fillColor[3] = components[3];
}

EXPORT void CGContextSetStrokeColor(CGContextRef c, const CGFloat *components) {
    if (!c || !c->_gstate || !components) return;
    c->_gstate->strokeColor[0] = components[0];
    c->_gstate->strokeColor[1] = components[1];
    c->_gstate->strokeColor[2] = components[2];
    c->_gstate->strokeColor[3] = components[3];
}

EXPORT void CGContextSetFillColorSpace(CGContextRef c, CGColorSpaceRef space) {
    (void)c; (void)space; /* Stored implicitly — we always work in RGB */
}

EXPORT void CGContextSetStrokeColorSpace(CGContextRef c, CGColorSpaceRef space) {
    (void)c; (void)space;
}

/* --- Line parameters --- */

EXPORT void CGContextSetLineWidth(CGContextRef c, CGFloat width) {
    if (!c || !c->_gstate) return;
    c->_gstate->lineWidth = width;
}

EXPORT void CGContextSetLineCap(CGContextRef c, CGLineCap cap) {
    if (!c || !c->_gstate) return;
    c->_gstate->lineCap = cap;
}

EXPORT void CGContextSetLineJoin(CGContextRef c, CGLineJoin join) {
    if (!c || !c->_gstate) return;
    c->_gstate->lineJoin = join;
}

EXPORT void CGContextSetMiterLimit(CGContextRef c, CGFloat limit) {
    if (!c || !c->_gstate) return;
    c->_gstate->miterLimit = limit;
}

EXPORT void CGContextSetLineDash(CGContextRef c, CGFloat phase,
    const CGFloat *lengths, size_t count) {
    /* Dash pattern stored but not rendered in our rasteriser (yet) */
    (void)c; (void)phase; (void)lengths; (void)count;
}

EXPORT void CGContextSetFlatness(CGContextRef c, CGFloat flatness) {
    if (!c || !c->_gstate) return;
    c->_gstate->flatness = flatness;
}

/* --- Alpha and blend mode --- */

EXPORT void CGContextSetAlpha(CGContextRef c, CGFloat alpha) {
    if (!c || !c->_gstate) return;
    c->_gstate->alpha = alpha;
}

EXPORT void CGContextSetBlendMode(CGContextRef c, CGBlendMode mode) {
    if (!c || !c->_gstate) return;
    c->_gstate->blendMode = mode;
}

/* --- Anti-aliasing --- */

EXPORT void CGContextSetShouldAntialias(CGContextRef c, bool shouldAntialias) {
    if (!c || !c->_gstate) return;
    c->_gstate->shouldAntialias = shouldAntialias;
}

EXPORT void CGContextSetAllowsAntialiasing(CGContextRef c, bool allowsAntialiasing) {
    (void)c; (void)allowsAntialiasing; /* stored but ignored */
}

/* --- Shadow --- */

EXPORT void CGContextSetShadow(CGContextRef c, CGSize offset, CGFloat blur) {
    if (!c || !c->_gstate) return;
    c->_gstate->shadowOffset = offset;
    c->_gstate->shadowBlur = blur;
}

EXPORT void CGContextSetShadowWithColor(CGContextRef c,
    CGSize offset, CGFloat blur, CGColorRef color) {
    (void)color;
    CGContextSetShadow(c, offset, blur);
}

/* --- Text state --- */

EXPORT void CGContextSetTextDrawingMode(CGContextRef c, CGTextDrawingMode mode) {
    if (!c || !c->_gstate) return;
    c->_gstate->textDrawingMode = mode;
}

EXPORT void CGContextSetCharacterSpacing(CGContextRef c, CGFloat spacing) {
    if (!c || !c->_gstate) return;
    c->_gstate->characterSpacing = spacing;
}

EXPORT void CGContextSetTextPosition(CGContextRef c, CGFloat x, CGFloat y) {
    if (!c || !c->_gstate) return;
    c->_gstate->textPosition = CGPointMake(x, y);
}

EXPORT CGPoint CGContextGetTextPosition(CGContextRef c) {
    if (!c || !c->_gstate) return CGPointZero;
    return c->_gstate->textPosition;
}

/* --- Interpolation quality --- */

EXPORT void CGContextSetInterpolationQuality(CGContextRef c, CGInterpolationQuality quality) {
    if (!c || !c->_gstate) return;
    c->_gstate->interpolationQuality = quality;
}

EXPORT CGInterpolationQuality CGContextGetInterpolationQuality(CGContextRef c) {
    if (!c || !c->_gstate) return kCGInterpolationDefault;
    return c->_gstate->interpolationQuality;
}

/* --- Rendering intent --- */

EXPORT void CGContextSetRenderingIntent(CGContextRef c, CGColorRenderingIntent intent) {
    (void)c; (void)intent; /* stored but ignored */
}

/* --- Should smooth fonts --- */

EXPORT void CGContextSetShouldSmoothFonts(CGContextRef c, bool shouldSmooth) {
    (void)c; (void)shouldSmooth;
}

EXPORT void CGContextSetAllowsFontSmoothing(CGContextRef c, bool allows) {
    (void)c; (void)allows;
}

EXPORT void CGContextSetShouldSubpixelPositionFonts(CGContextRef c, bool should) {
    (void)c; (void)should;
}

EXPORT void CGContextSetAllowsFontSubpixelPositioning(CGContextRef c, bool allows) {
    (void)c; (void)allows;
}

EXPORT void CGContextSetShouldSubpixelQuantizeFonts(CGContextRef c, bool should) {
    (void)c; (void)should;
}

EXPORT void CGContextSetAllowsFontSubpixelQuantization(CGContextRef c, bool allows) {
    (void)c; (void)allows;
}


/* ====================================================================
 * Section 16 — CGContext CTM operations
 * ====================================================================
 * TranslateCTM, ScaleCTM, RotateCTM, ConcatCTM, GetCTM,
 * ConvertPointToDeviceSpace, ConvertPointToUserSpace, etc.
 * ==================================================================== */

EXPORT void CGContextTranslateCTM(CGContextRef c, CGFloat tx, CGFloat ty) {
    if (!c || !c->_gstate) return;
    c->_gstate->ctm = CGAffineTransformTranslate(c->_gstate->ctm, tx, ty);
}

EXPORT void CGContextScaleCTM(CGContextRef c, CGFloat sx, CGFloat sy) {
    if (!c || !c->_gstate) return;
    c->_gstate->ctm = CGAffineTransformScale(c->_gstate->ctm, sx, sy);
}

EXPORT void CGContextRotateCTM(CGContextRef c, CGFloat angle) {
    if (!c || !c->_gstate) return;
    c->_gstate->ctm = CGAffineTransformRotate(c->_gstate->ctm, angle);
}

EXPORT void CGContextConcatCTM(CGContextRef c, CGAffineTransform transform) {
    if (!c || !c->_gstate) return;
    c->_gstate->ctm = CGAffineTransformConcat(transform, c->_gstate->ctm);
}

EXPORT CGAffineTransform CGContextGetCTM(CGContextRef c) {
    if (!c || !c->_gstate) return CGAffineTransformIdentity;
    return c->_gstate->ctm;
}

EXPORT CGPoint CGContextConvertPointToDeviceSpace(CGContextRef c, CGPoint point) {
    if (!c || !c->_gstate) return point;
    return CGPointApplyAffineTransform(point, c->_gstate->ctm);
}

EXPORT CGPoint CGContextConvertPointToUserSpace(CGContextRef c, CGPoint point) {
    if (!c || !c->_gstate) return point;
    CGAffineTransform inv = CGAffineTransformInvert(c->_gstate->ctm);
    return CGPointApplyAffineTransform(point, inv);
}

EXPORT CGSize CGContextConvertSizeToDeviceSpace(CGContextRef c, CGSize size) {
    if (!c || !c->_gstate) return size;
    return CGSizeApplyAffineTransform(size, c->_gstate->ctm);
}

EXPORT CGSize CGContextConvertSizeToUserSpace(CGContextRef c, CGSize size) {
    if (!c || !c->_gstate) return size;
    CGAffineTransform inv = CGAffineTransformInvert(c->_gstate->ctm);
    return CGSizeApplyAffineTransform(size, inv);
}

EXPORT CGRect CGContextConvertRectToDeviceSpace(CGContextRef c, CGRect rect) {
    if (!c || !c->_gstate) return rect;
    CGPoint origin = CGPointApplyAffineTransform(rect.origin, c->_gstate->ctm);
    CGSize size = CGSizeApplyAffineTransform(rect.size, c->_gstate->ctm);
    return CGRectMake(origin.x, origin.y, size.width, size.height);
}

EXPORT CGRect CGContextConvertRectToUserSpace(CGContextRef c, CGRect rect) {
    if (!c || !c->_gstate) return rect;
    CGAffineTransform inv = CGAffineTransformInvert(c->_gstate->ctm);
    CGPoint origin = CGPointApplyAffineTransform(rect.origin, inv);
    CGSize size = CGSizeApplyAffineTransform(rect.size, inv);
    return CGRectMake(origin.x, origin.y, size.width, size.height);
}


/* ====================================================================
 * Section 17 — CGContext path construction
 * ====================================================================
 * These functions build a path in the context's current path object.
 * The path is consumed by drawing or clipping operations.
 * Unlike CGPath functions, these apply the CTM automatically.
 * ==================================================================== */

EXPORT void CGContextBeginPath(CGContextRef c) {
    if (!c) return;
    if (c->_path) CGPathRelease(c->_path);
    c->_path = CGPathCreateMutable();
}

EXPORT void CGContextMoveToPoint(CGContextRef c, CGFloat x, CGFloat y) {
    if (!c || !c->_path || !c->_gstate) return;
    /* Context path functions apply the CTM via the transform parameter */
    CGPathMoveToPoint(c->_path, &c->_gstate->ctm, x, y);
}

EXPORT void CGContextAddLineToPoint(CGContextRef c, CGFloat x, CGFloat y) {
    if (!c || !c->_path || !c->_gstate) return;
    CGPathAddLineToPoint(c->_path, &c->_gstate->ctm, x, y);
}

EXPORT void CGContextAddQuadCurveToPoint(CGContextRef c,
    CGFloat cpx, CGFloat cpy, CGFloat x, CGFloat y) {
    if (!c || !c->_path || !c->_gstate) return;
    CGPathAddQuadCurveToPoint(c->_path, &c->_gstate->ctm, cpx, cpy, x, y);
}

EXPORT void CGContextAddCurveToPoint(CGContextRef c,
    CGFloat cp1x, CGFloat cp1y, CGFloat cp2x, CGFloat cp2y,
    CGFloat x, CGFloat y) {
    if (!c || !c->_path || !c->_gstate) return;
    CGPathAddCurveToPoint(c->_path, &c->_gstate->ctm,
        cp1x, cp1y, cp2x, cp2y, x, y);
}

EXPORT void CGContextClosePath(CGContextRef c) {
    if (!c || !c->_path) return;
    CGPathCloseSubpath(c->_path);
}

EXPORT void CGContextAddRect(CGContextRef c, CGRect rect) {
    if (!c || !c->_path || !c->_gstate) return;
    CGPathAddRect(c->_path, &c->_gstate->ctm, rect);
}

EXPORT void CGContextAddRects(CGContextRef c, const CGRect *rects, size_t count) {
    if (!c || !c->_path || !c->_gstate || !rects) return;
    CGPathAddRects(c->_path, &c->_gstate->ctm, rects, count);
}

EXPORT void CGContextAddLines(CGContextRef c, const CGPoint *points, size_t count) {
    if (!c || !c->_path || !c->_gstate || !points) return;
    CGPathAddLines(c->_path, &c->_gstate->ctm, points, count);
}

EXPORT void CGContextAddEllipseInRect(CGContextRef c, CGRect rect) {
    if (!c || !c->_path || !c->_gstate) return;
    CGPathAddEllipseInRect(c->_path, &c->_gstate->ctm, rect);
}

EXPORT void CGContextAddArc(CGContextRef c,
    CGFloat x, CGFloat y, CGFloat radius,
    CGFloat startAngle, CGFloat endAngle, int clockwise) {
    if (!c || !c->_path || !c->_gstate) return;
    CGPathAddArc(c->_path, &c->_gstate->ctm, x, y, radius,
        startAngle, endAngle, clockwise != 0);
}

EXPORT void CGContextAddArcToPoint(CGContextRef c,
    CGFloat x1, CGFloat y1, CGFloat x2, CGFloat y2, CGFloat radius) {
    if (!c || !c->_path || !c->_gstate) return;
    CGPathAddArcToPoint(c->_path, &c->_gstate->ctm, x1, y1, x2, y2, radius);
}

EXPORT void CGContextAddPath(CGContextRef c, CGPathRef path) {
    if (!c || !c->_path || !path) return;
    /* Add all elements from the given path, applying the context CTM */
    CGPathAddPath(c->_path, &c->_gstate->ctm, path);
}

EXPORT void CGContextReplacePathWithStrokedPath(CGContextRef c) {
    /* This is a complex operation (stroke expansion). Stub for now. */
    (void)c;
}

EXPORT bool CGContextIsPathEmpty(CGContextRef c) {
    if (!c || !c->_path) return true;
    return CGPathIsEmpty(c->_path);
}

EXPORT CGPoint CGContextGetPathCurrentPoint(CGContextRef c) {
    if (!c || !c->_path) return CGPointZero;
    return CGPathGetCurrentPoint(c->_path);
}

EXPORT CGRect CGContextGetPathBoundingBox(CGContextRef c) {
    if (!c || !c->_path) return CGRectNull;
    return CGPathGetBoundingBox(c->_path);
}

EXPORT bool CGContextPathContainsPoint(CGContextRef c, CGPoint point, CGPathDrawingMode mode) {
    if (!c || !c->_path) return false;
    bool eoFill = (mode == kCGPathEOFill || mode == kCGPathEOFillStroke);
    return CGPathContainsPoint(c->_path, NULL, point, eoFill);
}

EXPORT CGPathRef CGContextCopyPath(CGContextRef c) {
    if (!c || !c->_path) return NULL;
    return CGPathCreateCopy(c->_path);
}


/* ====================================================================
 * Section 18 — CGContext drawing (software rasteriser)
 * ====================================================================
 * The hot paths: FillRect, StrokeRect, ClearRect, FillPath, StrokePath,
 * DrawPath, FillEllipseInRect, StrokeEllipseInRect, DrawImage,
 * StrokeLineSegments.
 *
 * All drawing operates on the bitmap buffer. We support:
 *   - RGBA8888 (kCGImageAlphaPremultipliedLast)
 *   - BGRA8888 (kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little)
 *
 * The rasteriser performs:
 *   1. Transform coordinates by CTM (already done for path operations)
 *   2. Intersect with clip rect
 *   3. Alpha-blend source colour into destination pixels
 * ==================================================================== */

/* --- Pixel helpers --- */

/* Determine if the bitmap is BGRA (macOS native) or RGBA */
static inline bool __CGContextIsBGRA(CGContextRef c) {
    CGImageAlphaInfo alphaInfo = (CGImageAlphaInfo)(c->_bitmapInfo & kCGBitmapAlphaInfoMask);
    uint32_t byteOrder = c->_bitmapInfo & kCGBitmapByteOrderMask;
    /* BGRA = PremultipliedFirst + ByteOrder32Little, or just ByteOrder32Little with first alpha */
    if (byteOrder == kCGBitmapByteOrder32Little &&
        (alphaInfo == kCGImageAlphaPremultipliedFirst || alphaInfo == kCGImageAlphaNoneSkipFirst))
        return true;
    return false;
}

/* Write a pixel at (px, py) with premultiplied RGBA. Respects global alpha. */
static inline void __CGContextBlendPixel(CGContextRef c, int px, int py,
    CGFloat srcR, CGFloat srcG, CGFloat srcB, CGFloat srcA) {
    if (px < 0 || py < 0 || (size_t)px >= c->_width || (size_t)py >= c->_height) return;

    /* Apply global alpha */
    CGFloat ga = c->_gstate->alpha;
    srcA *= ga;
    if (srcA <= 0.0) return;

    uint8_t *row = (uint8_t *)c->_data + (size_t)py * c->_bytesPerRow;
    uint8_t *pixel = row + (size_t)px * 4;

    bool bgra = __CGContextIsBGRA(c);
    uint8_t dstR, dstG, dstB, dstA;
    if (bgra) {
        dstB = pixel[0]; dstG = pixel[1]; dstR = pixel[2]; dstA = pixel[3];
    } else {
        dstR = pixel[0]; dstG = pixel[1]; dstB = pixel[2]; dstA = pixel[3];
    }

    /* Source-over compositing (Porter-Duff): out = src + dst * (1 - srcA) */
    if (c->_gstate->blendMode == kCGBlendModeNormal || c->_gstate->blendMode == kCGBlendModeSourceAtop) {
        /* Premultiply source */
        CGFloat sR = srcR * srcA;
        CGFloat sG = srcG * srcA;
        CGFloat sB = srcB * srcA;
        CGFloat sA = srcA;

        CGFloat dR = (CGFloat)dstR / 255.0;
        CGFloat dG = (CGFloat)dstG / 255.0;
        CGFloat dB = (CGFloat)dstB / 255.0;
        CGFloat dA = (CGFloat)dstA / 255.0;

        CGFloat oneMinusSA = 1.0 - sA;
        CGFloat outR = sR + dR * oneMinusSA;
        CGFloat outG = sG + dG * oneMinusSA;
        CGFloat outB = sB + dB * oneMinusSA;
        CGFloat outA = sA + dA * oneMinusSA;

        uint8_t oR = (uint8_t)(outR * 255.0 + 0.5);
        uint8_t oG = (uint8_t)(outG * 255.0 + 0.5);
        uint8_t oB = (uint8_t)(outB * 255.0 + 0.5);
        uint8_t oA = (uint8_t)(outA * 255.0 + 0.5);

        if (bgra) {
            pixel[0] = oB; pixel[1] = oG; pixel[2] = oR; pixel[3] = oA;
        } else {
            pixel[0] = oR; pixel[1] = oG; pixel[2] = oB; pixel[3] = oA;
        }
    } else if (c->_gstate->blendMode == kCGBlendModeCopy) {
        uint8_t oR = (uint8_t)(srcR * 255.0 + 0.5);
        uint8_t oG = (uint8_t)(srcG * 255.0 + 0.5);
        uint8_t oB = (uint8_t)(srcB * 255.0 + 0.5);
        uint8_t oA = (uint8_t)(srcA * 255.0 + 0.5);
        if (bgra) {
            pixel[0] = oB; pixel[1] = oG; pixel[2] = oR; pixel[3] = oA;
        } else {
            pixel[0] = oR; pixel[1] = oG; pixel[2] = oB; pixel[3] = oA;
        }
    } else if (c->_gstate->blendMode == kCGBlendModeClear) {
        pixel[0] = 0; pixel[1] = 0; pixel[2] = 0; pixel[3] = 0;
    }
    /* Other blend modes: fall through to normal for now */
}

/* Fast opaque fill for the common case: source alpha = 1.0, global alpha = 1.0, normal blend */
static inline void __CGContextSetPixelOpaque(CGContextRef c, int px, int py,
    uint8_t r, uint8_t g, uint8_t b) {
    if (px < 0 || py < 0 || (size_t)px >= c->_width || (size_t)py >= c->_height) return;
    uint8_t *row = (uint8_t *)c->_data + (size_t)py * c->_bytesPerRow;
    uint8_t *pixel = row + (size_t)px * 4;
    if (__CGContextIsBGRA(c)) {
        pixel[0] = b; pixel[1] = g; pixel[2] = r; pixel[3] = 255;
    } else {
        pixel[0] = r; pixel[1] = g; pixel[2] = b; pixel[3] = 255;
    }
}

/* --- Rect intersection with clip --- */

static CGRect __CGContextClipRect(CGContextRef c, CGRect rect) {
    if (!c || !c->_gstate) return CGRectNull;
    return CGRectIntersection(rect, c->_gstate->clipRect);
}

/* --- FillRect (HOT PATH) --- */

EXPORT void CGContextFillRect(CGContextRef c, CGRect rect) {
    if (!c || !c->_gstate || c->_type != __kCGContextTypeBitmap) return;

    /* Transform rect corners by CTM */
    CGAffineTransform ctm = c->_gstate->ctm;
    /* For axis-aligned rects with non-rotating CTM, we can optimise */
    CGPoint p0 = CGPointApplyAffineTransform(rect.origin, ctm);
    CGPoint p1 = CGPointApplyAffineTransform(
        CGPointMake(rect.origin.x + rect.size.width,
                    rect.origin.y + rect.size.height), ctm);

    /* Normalise */
    CGFloat x0 = p0.x < p1.x ? p0.x : p1.x;
    CGFloat y0 = p0.y < p1.y ? p0.y : p1.y;
    CGFloat x1 = p0.x > p1.x ? p0.x : p1.x;
    CGFloat y1 = p0.y > p1.y ? p0.y : p1.y;

    CGRect devRect = CGRectMake(x0, y0, x1 - x0, y1 - y0);
    devRect = __CGContextClipRect(c, devRect);
    if (CGRectIsEmpty(devRect)) return;

    CGFloat *fc = c->_gstate->fillColor;
    CGFloat ga = c->_gstate->alpha;
    CGFloat finalA = fc[3] * ga;

    int ix0 = (int)devRect.origin.x;
    int iy0 = (int)devRect.origin.y;
    int ix1 = (int)(devRect.origin.x + devRect.size.width);
    int iy1 = (int)(devRect.origin.y + devRect.size.height);

    /* Fast path: fully opaque, normal blend */
    if (finalA >= 1.0 && c->_gstate->blendMode == kCGBlendModeNormal) {
        uint8_t r = (uint8_t)(fc[0] * 255.0 + 0.5);
        uint8_t g = (uint8_t)(fc[1] * 255.0 + 0.5);
        uint8_t b = (uint8_t)(fc[2] * 255.0 + 0.5);
        bool bgra = __CGContextIsBGRA(c);
        for (int y = iy0; y < iy1; y++) {
            uint8_t *row = (uint8_t *)c->_data + (size_t)y * c->_bytesPerRow;
            for (int x = ix0; x < ix1; x++) {
                uint8_t *pixel = row + (size_t)x * 4;
                if (bgra) {
                    pixel[0] = b; pixel[1] = g; pixel[2] = r; pixel[3] = 255;
                } else {
                    pixel[0] = r; pixel[1] = g; pixel[2] = b; pixel[3] = 255;
                }
            }
        }
    } else {
        /* Blended path */
        for (int y = iy0; y < iy1; y++) {
            for (int x = ix0; x < ix1; x++) {
                __CGContextBlendPixel(c, x, y, fc[0], fc[1], fc[2], fc[3]);
            }
        }
    }
}

EXPORT void CGContextFillRects(CGContextRef c, const CGRect *rects, size_t count) {
    if (!c || !rects) return;
    for (size_t i = 0; i < count; i++)
        CGContextFillRect(c, rects[i]);
}

/* --- ClearRect --- */

EXPORT void CGContextClearRect(CGContextRef c, CGRect rect) {
    if (!c || !c->_gstate || c->_type != __kCGContextTypeBitmap) return;

    CGAffineTransform ctm = c->_gstate->ctm;
    CGPoint p0 = CGPointApplyAffineTransform(rect.origin, ctm);
    CGPoint p1 = CGPointApplyAffineTransform(
        CGPointMake(rect.origin.x + rect.size.width,
                    rect.origin.y + rect.size.height), ctm);

    CGFloat x0 = p0.x < p1.x ? p0.x : p1.x;
    CGFloat y0 = p0.y < p1.y ? p0.y : p1.y;
    CGFloat x1 = p0.x > p1.x ? p0.x : p1.x;
    CGFloat y1 = p0.y > p1.y ? p0.y : p1.y;

    CGRect devRect = __CGContextClipRect(c, CGRectMake(x0, y0, x1 - x0, y1 - y0));
    if (CGRectIsEmpty(devRect)) return;

    int ix0 = (int)devRect.origin.x;
    int iy0 = (int)devRect.origin.y;
    int ix1 = (int)(devRect.origin.x + devRect.size.width);
    int iy1 = (int)(devRect.origin.y + devRect.size.height);

    for (int y = iy0; y < iy1; y++) {
        uint8_t *row = (uint8_t *)c->_data + (size_t)y * c->_bytesPerRow;
        memset(row + (size_t)ix0 * 4, 0, (size_t)(ix1 - ix0) * 4);
    }
}

/* --- StrokeRect --- */

EXPORT void CGContextStrokeRect(CGContextRef c, CGRect rect) {
    if (!c || !c->_gstate) return;
    CGFloat lw = c->_gstate->lineWidth;
    CGFloat half = lw / 2.0;
    /* Stroke by filling four thin rects (top, bottom, left, right) */
    /* Save fill colour, set to stroke colour */
    CGFloat savedFill[4];
    memcpy(savedFill, c->_gstate->fillColor, sizeof(savedFill));
    memcpy(c->_gstate->fillColor, c->_gstate->strokeColor, sizeof(savedFill));

    /* Top */
    CGContextFillRect(c, CGRectMake(rect.origin.x - half, rect.origin.y - half,
        rect.size.width + lw, lw));
    /* Bottom */
    CGContextFillRect(c, CGRectMake(rect.origin.x - half,
        rect.origin.y + rect.size.height - half, rect.size.width + lw, lw));
    /* Left */
    CGContextFillRect(c, CGRectMake(rect.origin.x - half, rect.origin.y + half,
        lw, rect.size.height - lw));
    /* Right */
    CGContextFillRect(c, CGRectMake(rect.origin.x + rect.size.width - half,
        rect.origin.y + half, lw, rect.size.height - lw));

    memcpy(c->_gstate->fillColor, savedFill, sizeof(savedFill));
}

EXPORT void CGContextStrokeRectWithWidth(CGContextRef c, CGRect rect, CGFloat width) {
    if (!c || !c->_gstate) return;
    CGFloat savedWidth = c->_gstate->lineWidth;
    c->_gstate->lineWidth = width;
    CGContextStrokeRect(c, rect);
    c->_gstate->lineWidth = savedWidth;
}

/* --- Stroke/Fill a line between two points --- */

static void __CGContextStrokeLine(CGContextRef c,
    CGFloat x0, CGFloat y0, CGFloat x1, CGFloat y1) {
    /* Bresenham's line algorithm with line width.
     * For width=1, we draw single pixels along the line.
     * For width>1, we stamp a filled circle/square at each pixel (simplified). */
    if (!c || !c->_gstate || c->_type != __kCGContextTypeBitmap) return;

    CGFloat *sc = c->_gstate->strokeColor;
    CGFloat lw = c->_gstate->lineWidth;
    int half = (int)(lw / 2.0);

    /* Apply CTM */
    CGAffineTransform ctm = c->_gstate->ctm;
    CGPoint p0 = CGPointApplyAffineTransform(CGPointMake(x0, y0), ctm);
    CGPoint p1 = CGPointApplyAffineTransform(CGPointMake(x1, y1), ctm);

    int ix0 = (int)(p0.x + 0.5), iy0 = (int)(p0.y + 0.5);
    int ix1 = (int)(p1.x + 0.5), iy1 = (int)(p1.y + 0.5);

    int dx = ix1 - ix0, dy = iy1 - iy0;
    int sx = dx > 0 ? 1 : -1, sy = dy > 0 ? 1 : -1;
    if (dx < 0) dx = -dx;
    if (dy < 0) dy = -dy;

    int err = dx - dy;
    int cx = ix0, cy = iy0;

    CGRect clipR = c->_gstate->clipRect;

    for (;;) {
        /* Draw a square of lw×lw centred on (cx, cy) */
        for (int oy = -half; oy <= half; oy++) {
            for (int ox = -half; ox <= half; ox++) {
                int px = cx + ox, py = cy + oy;
                if (px >= (int)clipR.origin.x && px < (int)(clipR.origin.x + clipR.size.width) &&
                    py >= (int)clipR.origin.y && py < (int)(clipR.origin.y + clipR.size.height)) {
                    __CGContextBlendPixel(c, px, py, sc[0], sc[1], sc[2], sc[3]);
                }
            }
        }
        if (cx == ix1 && cy == iy1) break;
        int e2 = 2 * err;
        if (e2 > -dy) { err -= dy; cx += sx; }
        if (e2 < dx)  { err += dx; cy += sy; }
    }
}

EXPORT void CGContextStrokeLineSegments(CGContextRef c,
    const CGPoint *points, size_t count) {
    if (!c || !points || count < 2) return;
    for (size_t i = 0; i + 1 < count; i += 2) {
        __CGContextStrokeLine(c, points[i].x, points[i].y,
            points[i+1].x, points[i+1].y);
    }
}

/* --- FillPath / StrokePath / DrawPath --- */

/* Helper: fill a path using scanline rasterisation (even-odd or winding).
 * We flatten curves to line segments, then use a scanline approach. */

static void __CGContextFillPathInternal(CGContextRef c, bool eoFill) {
    if (!c || !c->_path || c->_path->_count == 0 || c->_type != __kCGContextTypeBitmap) return;

    CGFloat *fc = c->_gstate->fillColor;
    CGRect clipR = c->_gstate->clipRect;

    /* Get bounding box of path (already in device coords since CTM was applied during construction) */
    CGRect bbox = CGPathGetBoundingBox(c->_path);
    bbox = CGRectIntersection(bbox, clipR);
    if (CGRectIsEmpty(bbox)) goto done;

    int minY = (int)bbox.origin.y;
    int maxY = (int)(bbox.origin.y + bbox.size.height);
    if (minY < 0) minY = 0;
    if (maxY > (int)c->_height) maxY = (int)c->_height;

    /* For each scanline, find intersections with path edges */
    /* First, flatten path to edges (line segments) */
    size_t maxEdges = c->_path->_count + 16;
    CGPoint *edgeStart = (CGPoint *)malloc(maxEdges * sizeof(CGPoint));
    CGPoint *edgeEnd   = (CGPoint *)malloc(maxEdges * sizeof(CGPoint));
    if (!edgeStart || !edgeEnd) {
        free(edgeStart);
        free(edgeEnd);
        goto done;
    }
    size_t nEdges = 0;
    CGPoint cur = CGPointZero, subpathStart = CGPointZero;

    for (size_t i = 0; i < c->_path->_count; i++) {
        CGPathElement *e = &c->_path->_elements[i];
        CGPoint next;
        switch (e->type) {
            case kCGPathElementMoveToPoint:
                cur = e->points[0];
                subpathStart = cur;
                continue;
            case kCGPathElementAddLineToPoint:
                next = e->points[0];
                break;
            case kCGPathElementAddQuadCurveToPoint:
                /* Flatten quad curve: use endpoint (simplified) */
                next = e->points[1];
                break;
            case kCGPathElementAddCurveToPoint:
                /* Flatten cubic curve: use endpoint (simplified) */
                next = e->points[2];
                break;
            case kCGPathElementCloseSubpath:
                next = subpathStart;
                break;
            default:
                continue;
        }
        if (nEdges >= maxEdges) {
            maxEdges *= 2;
            edgeStart = (CGPoint *)realloc(edgeStart, maxEdges * sizeof(CGPoint));
            edgeEnd   = (CGPoint *)realloc(edgeEnd, maxEdges * sizeof(CGPoint));
            if (!edgeStart || !edgeEnd) goto cleanup;
        }
        edgeStart[nEdges] = cur;
        edgeEnd[nEdges]   = next;
        nEdges++;
        cur = next;
    }

    /* Scanline fill */
    {
        /* Allocate intersection buffer */
        CGFloat *xIntersections = (CGFloat *)malloc(nEdges * sizeof(CGFloat));
        if (!xIntersections) goto cleanup;

        for (int y = minY; y < maxY; y++) {
            CGFloat scanY = (CGFloat)y + 0.5;
            size_t nIntersect = 0;

            for (size_t e = 0; e < nEdges; e++) {
                CGFloat y0 = edgeStart[e].y, y1 = edgeEnd[e].y;
                if ((y0 <= scanY && y1 > scanY) || (y1 <= scanY && y0 > scanY)) {
                    CGFloat x0 = edgeStart[e].x, x1 = edgeEnd[e].x;
                    CGFloat xHit = x0 + (scanY - y0) / (y1 - y0) * (x1 - x0);
                    xIntersections[nIntersect++] = xHit;
                }
            }

            /* Sort intersections */
            for (size_t i = 1; i < nIntersect; i++) {
                CGFloat key = xIntersections[i];
                size_t j = i;
                while (j > 0 && xIntersections[j-1] > key) {
                    xIntersections[j] = xIntersections[j-1];
                    j--;
                }
                xIntersections[j] = key;
            }

            /* Fill between pairs */
            for (size_t i = 0; i + 1 < nIntersect; i += 2) {
                int xStart = (int)(xIntersections[i] + 0.5);
                int xEnd   = (int)(xIntersections[i+1] + 0.5);
                if (xStart < (int)clipR.origin.x) xStart = (int)clipR.origin.x;
                if (xEnd > (int)(clipR.origin.x + clipR.size.width))
                    xEnd = (int)(clipR.origin.x + clipR.size.width);
                for (int x = xStart; x < xEnd; x++) {
                    __CGContextBlendPixel(c, x, y, fc[0], fc[1], fc[2], fc[3]);
                }
            }
        }
        free(xIntersections);
    }

cleanup:
    free(edgeStart);
    free(edgeEnd);

done:
    /* Clear current path after drawing (matching macOS behaviour) */
    if (c->_path) {
        CGPathRelease(c->_path);
        c->_path = CGPathCreateMutable();
    }
}

static void __CGContextStrokePathInternal(CGContextRef c) {
    if (!c || !c->_path || c->_path->_count == 0) goto done;

    /* Walk the path and stroke each line segment */
    CGPoint cur = CGPointZero, subpathStart = CGPointZero;
    CGFloat *sc = c->_gstate->strokeColor;
    (void)sc; /* Used indirectly via __CGContextStrokeLine */

    /* Save fill, set fill = stroke for line drawing that uses FillRect internally */
    for (size_t i = 0; i < c->_path->_count; i++) {
        CGPathElement *e = &c->_path->_elements[i];
        CGPoint next;
        switch (e->type) {
            case kCGPathElementMoveToPoint:
                cur = e->points[0];
                subpathStart = cur;
                continue;
            case kCGPathElementAddLineToPoint:
                next = e->points[0];
                break;
            case kCGPathElementAddQuadCurveToPoint:
                next = e->points[1];
                break;
            case kCGPathElementAddCurveToPoint:
                next = e->points[2];
                break;
            case kCGPathElementCloseSubpath:
                next = subpathStart;
                break;
            default:
                continue;
        }
        /* Path points are already in device space (CTM was applied during construction),
         * so call the line stroker directly without CTM re-application.
         * We need a version that doesn't re-apply CTM. */
        {
            CGFloat lw = c->_gstate->lineWidth;
            int half = (int)(lw / 2.0);
            int ix0 = (int)(cur.x + 0.5), iy0 = (int)(cur.y + 0.5);
            int ix1 = (int)(next.x + 0.5), iy1 = (int)(next.y + 0.5);
            int dx = ix1 - ix0, dy = iy1 - iy0;
            int sx = dx > 0 ? 1 : -1, sy = dy > 0 ? 1 : -1;
            if (dx < 0) dx = -dx;
            if (dy < 0) dy = -dy;
            int err = dx - dy;
            int cx = ix0, cy = iy0;
            CGRect clipR = c->_gstate->clipRect;
            for (;;) {
                for (int oy = -half; oy <= half; oy++) {
                    for (int ox = -half; ox <= half; ox++) {
                        int px = cx + ox, py = cy + oy;
                        if (px >= (int)clipR.origin.x &&
                            px < (int)(clipR.origin.x + clipR.size.width) &&
                            py >= (int)clipR.origin.y &&
                            py < (int)(clipR.origin.y + clipR.size.height)) {
                            __CGContextBlendPixel(c, px, py,
                                c->_gstate->strokeColor[0], c->_gstate->strokeColor[1],
                                c->_gstate->strokeColor[2], c->_gstate->strokeColor[3]);
                        }
                    }
                }
                if (cx == ix1 && cy == iy1) break;
                int e2 = 2 * err;
                if (e2 > -dy) { err -= dy; cx += sx; }
                if (e2 < dx)  { err += dx; cy += sy; }
            }
        }
        cur = next;
    }

done:
    if (c && c->_path) {
        CGPathRelease(c->_path);
        c->_path = CGPathCreateMutable();
    }
}

EXPORT void CGContextFillPath(CGContextRef c) {
    __CGContextFillPathInternal(c, false);
}

EXPORT void CGContextEOFillPath(CGContextRef c) {
    __CGContextFillPathInternal(c, true);
}

EXPORT void CGContextStrokePath(CGContextRef c) {
    __CGContextStrokePathInternal(c);
}

EXPORT void CGContextDrawPath(CGContextRef c, CGPathDrawingMode mode) {
    if (!c) return;
    switch (mode) {
        case kCGPathFill:
            CGContextFillPath(c);
            break;
        case kCGPathEOFill:
            CGContextEOFillPath(c);
            break;
        case kCGPathStroke:
            CGContextStrokePath(c);
            break;
        case kCGPathFillStroke: {
            /* Need to fill then stroke, but fill consumes path.
             * Save path, fill, restore, stroke. */
            CGPathRef saved = CGPathCreateCopy(c->_path);
            __CGContextFillPathInternal(c, false);
            if (c->_path) CGPathRelease(c->_path);
            c->_path = CGPathCreateMutableCopy(saved);
            CGPathRelease(saved);
            __CGContextStrokePathInternal(c);
            break;
        }
        case kCGPathEOFillStroke: {
            CGPathRef saved = CGPathCreateCopy(c->_path);
            __CGContextFillPathInternal(c, true);
            if (c->_path) CGPathRelease(c->_path);
            c->_path = CGPathCreateMutableCopy(saved);
            CGPathRelease(saved);
            __CGContextStrokePathInternal(c);
            break;
        }
    }
}

/* --- FillEllipseInRect / StrokeEllipseInRect --- */

EXPORT void CGContextFillEllipseInRect(CGContextRef c, CGRect rect) {
    if (!c) return;
    CGContextBeginPath(c);
    CGContextAddEllipseInRect(c, rect);
    CGContextFillPath(c);
}

EXPORT void CGContextStrokeEllipseInRect(CGContextRef c, CGRect rect) {
    if (!c) return;
    CGContextBeginPath(c);
    CGContextAddEllipseInRect(c, rect);
    CGContextStrokePath(c);
}

/* --- DrawImage --- */

EXPORT void CGContextDrawImage(CGContextRef c, CGRect rect, CGImageRef image) {
    if (!c || !image || c->_type != __kCGContextTypeBitmap) return;

    /* Get source pixel data */
    CFDataRef srcData = CGDataProviderCopyData(image->_provider);
    if (!srcData) return;

    const uint8_t *srcPixels = CFDataGetBytePtr(srcData);
    size_t srcW = image->_width;
    size_t srcH = image->_height;
    size_t srcBPR = image->_bytesPerRow;
    CGBitmapInfo srcInfo = image->_bitmapInfo;

    bool srcBGRA = false;
    {
        CGImageAlphaInfo srcAlpha = (CGImageAlphaInfo)(srcInfo & kCGBitmapAlphaInfoMask);
        uint32_t srcOrder = srcInfo & kCGBitmapByteOrderMask;
        if (srcOrder == kCGBitmapByteOrder32Little &&
            (srcAlpha == kCGImageAlphaPremultipliedFirst || srcAlpha == kCGImageAlphaNoneSkipFirst))
            srcBGRA = true;
    }

    /* Transform destination rect by CTM */
    CGAffineTransform ctm = c->_gstate->ctm;
    CGPoint dp0 = CGPointApplyAffineTransform(rect.origin, ctm);
    CGPoint dp1 = CGPointApplyAffineTransform(
        CGPointMake(rect.origin.x + rect.size.width,
                    rect.origin.y + rect.size.height), ctm);

    CGFloat dstX0 = dp0.x < dp1.x ? dp0.x : dp1.x;
    CGFloat dstY0 = dp0.y < dp1.y ? dp0.y : dp1.y;
    CGFloat dstW = dp0.x > dp1.x ? dp0.x - dp1.x : dp1.x - dp0.x;
    CGFloat dstH = dp0.y > dp1.y ? dp0.y - dp1.y : dp1.y - dp0.y;

    CGRect devRect = CGRectMake(dstX0, dstY0, dstW, dstH);
    devRect = __CGContextClipRect(c, devRect);
    if (CGRectIsEmpty(devRect)) { CFRelease(srcData); return; }

    int ix0 = (int)devRect.origin.x;
    int iy0 = (int)devRect.origin.y;
    int ix1 = (int)(devRect.origin.x + devRect.size.width);
    int iy1 = (int)(devRect.origin.y + devRect.size.height);

    /* Nearest-neighbour scaling */
    for (int y = iy0; y < iy1; y++) {
        CGFloat srcFY = (CGFloat)(y - (int)dstY0) / dstH * (CGFloat)srcH;
        int sy = (int)srcFY;
        if (sy < 0) sy = 0;
        if ((size_t)sy >= srcH) sy = (int)srcH - 1;

        const uint8_t *srcRow = srcPixels + (size_t)sy * srcBPR;

        for (int x = ix0; x < ix1; x++) {
            CGFloat srcFX = (CGFloat)(x - (int)dstX0) / dstW * (CGFloat)srcW;
            int sx = (int)srcFX;
            if (sx < 0) sx = 0;
            if ((size_t)sx >= srcW) sx = (int)srcW - 1;

            const uint8_t *sp = srcRow + (size_t)sx * 4;
            CGFloat r, g, b, a;
            if (srcBGRA) {
                b = (CGFloat)sp[0] / 255.0;
                g = (CGFloat)sp[1] / 255.0;
                r = (CGFloat)sp[2] / 255.0;
                a = (CGFloat)sp[3] / 255.0;
            } else {
                r = (CGFloat)sp[0] / 255.0;
                g = (CGFloat)sp[1] / 255.0;
                b = (CGFloat)sp[2] / 255.0;
                a = (CGFloat)sp[3] / 255.0;
            }
            __CGContextBlendPixel(c, x, y, r, g, b, a);
        }
    }

    CFRelease(srcData);
}

/* --- Tiled image drawing --- */

EXPORT void CGContextDrawTiledImage(CGContextRef c, CGRect rect, CGImageRef image) {
    /* Draw image tiled to fill the current clip */
    if (!c || !image) return;
    CGRect clipR = c->_gstate->clipRect;
    CGFloat startX = clipR.origin.x;
    CGFloat startY = clipR.origin.y;
    CGFloat endX = clipR.origin.x + clipR.size.width;
    CGFloat endY = clipR.origin.y + clipR.size.height;
    for (CGFloat y = startY; y < endY; y += rect.size.height) {
        for (CGFloat x = startX; x < endX; x += rect.size.width) {
            CGContextDrawImage(c, CGRectMake(x, y, rect.size.width, rect.size.height), image);
        }
    }
}


/* ====================================================================
 * Section 19 — CGContext clipping
 * ====================================================================
 * ClipToRect intersects the current clip with a given rect.
 * Clip() intersects with the bounding box of the current path.
 * ClipToMask is stubbed (requires alpha mask support).
 * ==================================================================== */

EXPORT void CGContextClipToRect(CGContextRef c, CGRect rect) {
    if (!c || !c->_gstate) return;
    /* Transform rect by CTM */
    CGPoint p0 = CGPointApplyAffineTransform(rect.origin, c->_gstate->ctm);
    CGPoint p1 = CGPointApplyAffineTransform(
        CGPointMake(rect.origin.x + rect.size.width,
                    rect.origin.y + rect.size.height), c->_gstate->ctm);
    CGFloat x0 = p0.x < p1.x ? p0.x : p1.x;
    CGFloat y0 = p0.y < p1.y ? p0.y : p1.y;
    CGFloat x1 = p0.x > p1.x ? p0.x : p1.x;
    CGFloat y1 = p0.y > p1.y ? p0.y : p1.y;
    CGRect devRect = CGRectMake(x0, y0, x1 - x0, y1 - y0);
    c->_gstate->clipRect = CGRectIntersection(c->_gstate->clipRect, devRect);
}

EXPORT void CGContextClipToRects(CGContextRef c, const CGRect *rects, size_t count) {
    if (!c || !rects || count == 0) return;
    /* Intersect clip with the union of all rects (simplified — real CG uses rect list) */
    CGRect unionRect = rects[0];
    for (size_t i = 1; i < count; i++)
        unionRect = CGRectUnion(unionRect, rects[i]);
    CGContextClipToRect(c, unionRect);
}

EXPORT void CGContextClip(CGContextRef c) {
    if (!c || !c->_gstate || !c->_path) return;
    /* Intersect current clip with path bounding box */
    CGRect pathBBox = CGPathGetBoundingBox(c->_path);
    c->_gstate->clipRect = CGRectIntersection(c->_gstate->clipRect, pathBBox);
    /* Clear the path (matching macOS behaviour) */
    CGPathRelease(c->_path);
    c->_path = CGPathCreateMutable();
}

EXPORT void CGContextEOClip(CGContextRef c) {
    /* For our simplified rasteriser, EO clip = same as winding clip */
    CGContextClip(c);
}

EXPORT void CGContextClipToMask(CGContextRef c, CGRect rect, CGImageRef mask) {
    /* Stub — requires alpha mask rasterisation */
    (void)c; (void)rect; (void)mask;
}

EXPORT CGRect CGContextGetClipBoundingBox(CGContextRef c) {
    if (!c || !c->_gstate) return CGRectNull;
    return c->_gstate->clipRect;
}

EXPORT void CGContextResetClip(CGContextRef c) {
    if (!c || !c->_gstate) return;
    if (c->_type == __kCGContextTypeBitmap) {
        c->_gstate->clipRect = CGRectMake(0, 0, (CGFloat)c->_width, (CGFloat)c->_height);
    } else {
        c->_gstate->clipRect = CGRectMake(-1e30, -1e30, 2e30, 2e30);
    }
}


/* ====================================================================
 * Section 20 — Constructor, constant colors, remaining exports
 * ==================================================================== */

/* --- Constant color space names (CFStringRef values) --- */
/* These are created lazily — the real macOS creates them at load time
 * via a __attribute__((constructor)). We do the same. */

static CGColorSpaceRef __kCGColorSpaceGenericRGBInstance    = NULL;
static CGColorSpaceRef __kCGColorSpaceGenericGrayInstance   = NULL;
static CGColorSpaceRef __kCGColorSpaceGenericCMYKInstance   = NULL;
static CGColorSpaceRef __kCGColorSpaceSRGBInstance          = NULL;
static CGColorSpaceRef __kCGColorSpaceDisplayP3Instance     = NULL;
static CGColorSpaceRef __kCGColorSpaceGenericRGBLinearInstance = NULL;
static CGColorSpaceRef __kCGColorSpaceExtendedSRGBInstance  = NULL;

/* Constant color instances are __kCGColorWhiteInstance etc. from Section 9.
 * CGColorGetConstantColor is also defined in Section 9. */

/* --- UserDefaults / Flush (stubs) --- */

EXPORT void CGContextFlush(CGContextRef c) {
    (void)c; /* No-op for bitmap contexts */
}

EXPORT void CGContextSynchronize(CGContextRef c) {
    (void)c;
}

/* --- CGContext text drawing --- */

/* 8x16 VGA bitmap font for text rendering */
#define __CG_FONT_W 8
#define __CG_FONT_H 16

#include "cg_font8x16.inc"

EXPORT void CGContextSetFont(CGContextRef c, void *font) {
    (void)c; (void)font;
}

EXPORT void CGContextSetFontSize(CGContextRef c, CGFloat size) {
    (void)c; (void)size;
}

EXPORT void CGContextSelectFont(CGContextRef c, const char *name,
    CGFloat size, int textEncoding) {
    (void)c; (void)name; (void)size; (void)textEncoding;
}

EXPORT void CGContextShowTextAtPoint(CGContextRef c, CGFloat x, CGFloat y,
    const char *string, size_t length) {
    if (!c || !c->_gstate || !string || c->_type != __kCGContextTypeBitmap)
        return;

    CGFloat *fc = c->_gstate->fillColor;
    CGFloat ga  = c->_gstate->alpha;
    CGFloat finalA = fc[3] * ga;
    CGFloat charSpacing = c->_gstate->characterSpacing;

    /* Check if we can use the fast opaque path */
    bool opaque = (finalA >= 1.0 &&
                   c->_gstate->blendMode == kCGBlendModeNormal);

    /* Precompute uint8 colour for the opaque fast path */
    uint8_t fR = (uint8_t)(fc[0] * 255.0 + 0.5);
    uint8_t fG = (uint8_t)(fc[1] * 255.0 + 0.5);
    uint8_t fB = (uint8_t)(fc[2] * 255.0 + 0.5);

    /* Get clip rect */
    CGRect clip = c->_gstate->clipRect;
    int clipX0 = (int)clip.origin.x;
    int clipY0 = (int)clip.origin.y;
    int clipX1 = (int)(clip.origin.x + clip.size.width);
    int clipY1 = (int)(clip.origin.y + clip.size.height);

    /* Clamp clip to bitmap bounds */
    if (clipX0 < 0) clipX0 = 0;
    if (clipY0 < 0) clipY0 = 0;
    if (clipX1 > (int)c->_width)  clipX1 = (int)c->_width;
    if (clipY1 > (int)c->_height) clipY1 = (int)c->_height;

    CGFloat curX = x;
    CGFloat curY = y;

    for (size_t i = 0; i < length; i++) {
        unsigned char ch = (unsigned char)string[i];
        const unsigned char *glyph = __cg_font8x16[ch];

        /* Glyph origin: (curX, curY) is the baseline-left in CG convention.
         * Our bitmap font has 16 rows; treat y as the TOP of the glyph
         * (matching how WindowServer and AppKit callers use it). */
        int gx = (int)curX;
        int gy = (int)curY;

        /* Skip entirely if glyph is off-screen */
        if (gx + __CG_FONT_W <= clipX0 || gx >= clipX1 ||
            gy + __CG_FONT_H <= clipY0 || gy >= clipY1) {
            curX += __CG_FONT_W + charSpacing;
            continue;
        }

        for (int row = 0; row < __CG_FONT_H; row++) {
            int py = gy + row;
            if (py < clipY0 || py >= clipY1) continue;
            uint8_t bits = glyph[row];
            if (bits == 0) continue; /* empty row — skip */
            for (int col = 0; col < __CG_FONT_W; col++) {
                if (!(bits & (0x80 >> col))) continue;
                int px = gx + col;
                if (px < clipX0 || px >= clipX1) continue;
                if (opaque) {
                    __CGContextSetPixelOpaque(c, px, py, fR, fG, fB);
                } else {
                    __CGContextBlendPixel(c, px, py,
                                          fc[0], fc[1], fc[2], fc[3]);
                }
            }
        }

        curX += __CG_FONT_W + charSpacing;
    }

    /* Update text position */
    c->_gstate->textPosition = CGPointMake(curX, curY);
}

EXPORT void CGContextShowText(CGContextRef c, const char *string, size_t length) {
    if (!c || !c->_gstate) return;
    CGPoint pos = c->_gstate->textPosition;
    CGContextShowTextAtPoint(c, pos.x, pos.y, string, length);
}

EXPORT void CGContextShowGlyphs(CGContextRef c, const void *glyphs, size_t count) {
    (void)c; (void)glyphs; (void)count;
}

EXPORT void CGContextShowGlyphsAtPoint(CGContextRef c, CGFloat x, CGFloat y,
    const void *glyphs, size_t count) {
    (void)c; (void)x; (void)y; (void)glyphs; (void)count;
}

EXPORT void CGContextShowGlyphsAtPositions(CGContextRef c,
    const void *glyphs, const CGPoint *positions, size_t count) {
    (void)c; (void)glyphs; (void)positions; (void)count;
}

EXPORT void CGContextShowGlyphsWithAdvances(CGContextRef c,
    const void *glyphs, const CGSize *advances, size_t count) {
    (void)c; (void)glyphs; (void)advances; (void)count;
}

EXPORT void CGContextSetTextMatrix(CGContextRef c, CGAffineTransform t) {
    (void)c; (void)t;
}

EXPORT CGAffineTransform CGContextGetTextMatrix(CGContextRef c) {
    (void)c;
    return CGAffineTransformIdentity;
}

/* --- PDF page drawing (stub) --- */

EXPORT void CGContextDrawPDFPage(CGContextRef c, void *page) {
    (void)c; (void)page;
}

/* --- Gradient (stubs — will need CGGradient/CGShading implementation later) --- */

typedef const void *CGGradientRef;
typedef const void *CGShadingRef;

typedef enum {
    kCGGradientDrawsBeforeStartLocation = (1 << 0),
    kCGGradientDrawsAfterEndLocation    = (1 << 1)
} CGGradientDrawingOptions;

EXPORT CGGradientRef CGGradientCreateWithColorComponents(
    CGColorSpaceRef space, const CGFloat *components,
    const CGFloat *locations, size_t count) {
    (void)space; (void)components; (void)locations; (void)count;
    return NULL; /* stub */
}

EXPORT CGGradientRef CGGradientCreateWithColors(
    CGColorSpaceRef space, CFArrayRef colors, const CGFloat *locations) {
    (void)space; (void)colors; (void)locations;
    return NULL;
}

EXPORT CGGradientRef CGGradientRetain(CGGradientRef gradient) {
    return gradient;
}

EXPORT void CGGradientRelease(CGGradientRef gradient) {
    (void)gradient;
}

EXPORT void CGContextDrawLinearGradient(CGContextRef c, CGGradientRef gradient,
    CGPoint startPoint, CGPoint endPoint, CGGradientDrawingOptions options) {
    (void)c; (void)gradient; (void)startPoint; (void)endPoint; (void)options;
}

EXPORT void CGContextDrawRadialGradient(CGContextRef c, CGGradientRef gradient,
    CGPoint startCenter, CGFloat startRadius,
    CGPoint endCenter, CGFloat endRadius,
    CGGradientDrawingOptions options) {
    (void)c; (void)gradient; (void)startCenter; (void)startRadius;
    (void)endCenter; (void)endRadius; (void)options;
}

EXPORT void CGContextDrawShading(CGContextRef c, CGShadingRef shading) {
    (void)c; (void)shading;
}

/* --- CGLayer (stubs) --- */

typedef const void *CGLayerRef;

EXPORT CGLayerRef CGLayerCreateWithContext(CGContextRef c, CGSize size, CFDictionaryRef auxiliaryInfo) {
    (void)c; (void)size; (void)auxiliaryInfo;
    return NULL;
}

EXPORT void CGLayerRelease(CGLayerRef layer) {
    (void)layer;
}

EXPORT CGLayerRef CGLayerRetain(CGLayerRef layer) {
    return layer;
}

EXPORT CGContextRef CGLayerGetContext(CGLayerRef layer) {
    (void)layer;
    return NULL;
}

EXPORT CGSize CGLayerGetSize(CGLayerRef layer) {
    (void)layer;
    return CGSizeMake(0, 0);
}

EXPORT void CGContextDrawLayerInRect(CGContextRef c, CGRect rect, CGLayerRef layer) {
    (void)c; (void)rect; (void)layer;
}

EXPORT void CGContextDrawLayerAtPoint(CGContextRef c, CGPoint point, CGLayerRef layer) {
    (void)c; (void)point; (void)layer;
}

/* --- Constructor: initialise singletons --- */

__attribute__((constructor, used))
static void __CGInit(void) {
    /* Colour space singletons (already set up by the CGColorSpace functions,
     * but ensure the named variants are available) */
    __kCGColorSpaceGenericRGBInstance  = CGColorSpaceCreateDeviceRGB();
    __kCGColorSpaceGenericGrayInstance = CGColorSpaceCreateDeviceGray();
    __kCGColorSpaceGenericCMYKInstance = CGColorSpaceCreateDeviceCMYK();
    __kCGColorSpaceSRGBInstance        = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
    __kCGColorSpaceDisplayP3Instance   = __kCGColorSpaceSRGBInstance; /* alias for now */
    __kCGColorSpaceGenericRGBLinearInstance = __kCGColorSpaceGenericRGBInstance;
    __kCGColorSpaceExtendedSRGBInstance    = __kCGColorSpaceSRGBInstance;

    /* Constant colours — use the instances declared in Section 9 */
    /* White: RGBA(1,1,1,1) */
    __kCGColorWhiteInstance._rc._refCount = 0x7FFFFFFF; /* immortal */
    __kCGColorWhiteInstance._space = __kCGColorSpaceSRGBInstance;
    __kCGColorWhiteInstance._components[0] = 1.0;
    __kCGColorWhiteInstance._components[1] = 1.0;
    __kCGColorWhiteInstance._components[2] = 1.0;
    __kCGColorWhiteInstance._components[3] = 1.0;
    __kCGColorWhiteInstance._numComponents = 4;

    /* Black: RGBA(0,0,0,1) */
    __kCGColorBlackInstance._rc._refCount = 0x7FFFFFFF;
    __kCGColorBlackInstance._space = __kCGColorSpaceSRGBInstance;
    __kCGColorBlackInstance._components[0] = 0.0;
    __kCGColorBlackInstance._components[1] = 0.0;
    __kCGColorBlackInstance._components[2] = 0.0;
    __kCGColorBlackInstance._components[3] = 1.0;
    __kCGColorBlackInstance._numComponents = 4;

    /* Clear: RGBA(0,0,0,0) */
    __kCGColorClearInstance._rc._refCount = 0x7FFFFFFF;
    __kCGColorClearInstance._space = __kCGColorSpaceSRGBInstance;
    __kCGColorClearInstance._components[0] = 0.0;
    __kCGColorClearInstance._components[1] = 0.0;
    __kCGColorClearInstance._components[2] = 0.0;
    __kCGColorClearInstance._components[3] = 0.0;
    __kCGColorClearInstance._numComponents = 4;
}

/*
 * Manual __mod_init_func entry.
 *
 * Clang with -O2 -ffreestanding strips __attribute__((constructor)) from
 * @llvm.global_ctors even when __attribute__((used)) is present. Work around
 * this by manually placing the function pointer in __DATA,__mod_init_func
 * using a section attribute. dyld iterates this section and calls each
 * pointer before main().
 */
__attribute__((used, section("__DATA,__mod_init_func")))
static void (*__CGInit_ptr)(void) = __CGInit;

