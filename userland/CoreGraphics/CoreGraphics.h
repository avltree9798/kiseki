/*
 * Kiseki OS - CoreGraphics.framework
 *
 * Public API header for the CoreGraphics (Quartz 2D) library.
 * Software-rasterised 2D rendering into bitmap contexts.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <CoreFoundation/CoreFoundation.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ======================================================================
 * CGFloat
 * ====================================================================== */

#ifndef _CG_CGFLOAT_DEFINED
#define _CG_CGFLOAT_DEFINED
typedef double CGFloat;
#endif
#define CGFLOAT_IS_DOUBLE 1

/* ======================================================================
 * Geometry Types
 * ====================================================================== */

typedef struct CGPoint  { CGFloat x; CGFloat y; }           CGPoint;
typedef struct CGSize   { CGFloat width; CGFloat height; }  CGSize;
typedef struct CGVector { CGFloat dx; CGFloat dy; }         CGVector;
typedef struct CGRect   { CGPoint origin; CGSize size; }    CGRect;

typedef uint32_t CGRectEdge;
#define CGRectMinXEdge 0
#define CGRectMinYEdge 1
#define CGRectMaxXEdge 2
#define CGRectMaxYEdge 3

/* ======================================================================
 * Inline Geometry Makers
 * ====================================================================== */

static inline CGPoint CGPointMake(CGFloat x, CGFloat y) {
    CGPoint p; p.x = x; p.y = y; return p;
}

static inline CGSize CGSizeMake(CGFloat w, CGFloat h) {
    CGSize s; s.width = w; s.height = h; return s;
}

static inline CGVector CGVectorMake(CGFloat dx, CGFloat dy) {
    CGVector v; v.dx = dx; v.dy = dy; return v;
}

static inline CGRect CGRectMake(CGFloat x, CGFloat y, CGFloat w, CGFloat h) {
    CGRect r;
    r.origin.x = x; r.origin.y = y;
    r.size.width = w; r.size.height = h;
    return r;
}

/* ======================================================================
 * Geometry Constants
 * ====================================================================== */

extern const CGPoint CGPointZero;
extern const CGSize  CGSizeZero;
extern const CGRect  CGRectZero;
extern const CGRect  CGRectNull;
extern const CGRect  CGRectInfinite;

/* ======================================================================
 * CGAffineTransform
 * ====================================================================== */

typedef struct CGAffineTransform {
    CGFloat a, b, c, d;
    CGFloat tx, ty;
} CGAffineTransform;

extern const CGAffineTransform CGAffineTransformIdentity;

/* ======================================================================
 * Enumerations
 * ====================================================================== */

/* CGImageAlphaInfo */
typedef uint32_t CGImageAlphaInfo;
#define kCGImageAlphaNone               0
#define kCGImageAlphaPremultipliedLast   1
#define kCGImageAlphaPremultipliedFirst  2
#define kCGImageAlphaLast               3
#define kCGImageAlphaFirst              4
#define kCGImageAlphaNoneSkipLast       5
#define kCGImageAlphaNoneSkipFirst      6
#define kCGImageAlphaOnly               7

/* CGImageByteOrderInfo */
typedef uint32_t CGImageByteOrderInfo;
#define kCGImageByteOrderMask     0x7000
#define kCGImageByteOrderDefault  (0 << 12)
#define kCGImageByteOrder16Little (1 << 12)
#define kCGImageByteOrder32Little (2 << 12)
#define kCGImageByteOrder16Big    (3 << 12)
#define kCGImageByteOrder32Big    (4 << 12)
#define kCGImageByteOrder16Host   kCGImageByteOrder16Little
#define kCGImageByteOrder32Host   kCGImageByteOrder32Little

/* CGBitmapInfo */
typedef uint32_t CGBitmapInfo;
#define kCGBitmapAlphaInfoMask    0x1F
#define kCGBitmapByteOrderMask    0x7000
#define kCGBitmapByteOrderDefault  kCGImageByteOrderDefault
#define kCGBitmapByteOrder16Little kCGImageByteOrder16Little
#define kCGBitmapByteOrder32Little kCGImageByteOrder32Little
#define kCGBitmapByteOrder16Big    kCGImageByteOrder16Big
#define kCGBitmapByteOrder32Big    kCGImageByteOrder32Big
#define kCGBitmapByteOrder16Host   kCGImageByteOrder16Host
#define kCGBitmapByteOrder32Host   kCGImageByteOrder32Host
#define kCGBitmapFloatComponents   (1 << 8)

/* CGColorRenderingIntent */
typedef int32_t CGColorRenderingIntent;
#define kCGRenderingIntentDefault              0
#define kCGRenderingIntentAbsoluteColorimetric 1
#define kCGRenderingIntentRelativeColorimetric 2
#define kCGRenderingIntentPerceptual           3
#define kCGRenderingIntentSaturation           4

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
#define kCGTextFill       0
#define kCGTextStroke     1
#define kCGTextFillStroke 2
#define kCGTextInvisible  3

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

/* ======================================================================
 * Opaque Type Forward Declarations
 * ====================================================================== */

typedef const struct CGPath *CGPathRef;
typedef struct CGPath       *CGMutablePathRef;
typedef struct CGContext    *CGContextRef;
typedef struct CGColorSpace *CGColorSpaceRef;
typedef struct CGColor      *CGColorRef;
typedef struct CGImage      *CGImageRef;
typedef struct CGDataProvider *CGDataProviderRef;

/* ======================================================================
 * CGPathElement
 * ====================================================================== */

typedef struct CGPathElement {
    CGPathElementType type;
    CGPoint           points[3];
} CGPathElement;

typedef void (*CGPathApplierFunction)(void *info, const CGPathElement *element);

/* ======================================================================
 * CGDataProvider Callback
 * ====================================================================== */

typedef void (*CGDataProviderReleaseDataCallback)(void *info, const void *data, size_t size);

/* ======================================================================
 * Color Space Name Constants
 * ====================================================================== */

extern const CFStringRef kCGColorSpaceGenericGray;
extern const CFStringRef kCGColorSpaceGenericRGB;
extern const CFStringRef kCGColorSpaceSRGB;
extern const CFStringRef kCGColorSpaceGenericGrayGamma2_2;
extern const CFStringRef kCGColorSpaceGenericRGBLinear;
extern const CFStringRef kCGColorSpaceDisplayP3;
extern const CFStringRef kCGColorSpaceLinearSRGB;
extern const CFStringRef kCGColorSpaceExtendedSRGB;

/* ======================================================================
 * Color Name Constants
 * ====================================================================== */

extern const CFStringRef kCGColorWhite;
extern const CFStringRef kCGColorBlack;
extern const CFStringRef kCGColorClear;

/* ======================================================================
 * Geometry Functions
 * ====================================================================== */

extern CGFloat CGRectGetMinX(CGRect r);
extern CGFloat CGRectGetMidX(CGRect r);
extern CGFloat CGRectGetMaxX(CGRect r);
extern CGFloat CGRectGetMinY(CGRect r);
extern CGFloat CGRectGetMidY(CGRect r);
extern CGFloat CGRectGetMaxY(CGRect r);
extern CGFloat CGRectGetWidth(CGRect r);
extern CGFloat CGRectGetHeight(CGRect r);

extern bool CGPointEqualToPoint(CGPoint p1, CGPoint p2);
extern bool CGSizeEqualToSize(CGSize s1, CGSize s2);
extern bool CGRectEqualToRect(CGRect r1, CGRect r2);

extern CGRect CGRectStandardize(CGRect r);
extern bool   CGRectIsEmpty(CGRect r);
extern bool   CGRectIsNull(CGRect r);
extern bool   CGRectIsInfinite(CGRect r);

extern CGRect CGRectInset(CGRect r, CGFloat dx, CGFloat dy);
extern CGRect CGRectOffset(CGRect r, CGFloat dx, CGFloat dy);
extern CGRect CGRectIntegral(CGRect r);
extern CGRect CGRectUnion(CGRect r1, CGRect r2);
extern CGRect CGRectIntersection(CGRect r1, CGRect r2);

extern bool CGRectContainsPoint(CGRect r, CGPoint p);
extern bool CGRectContainsRect(CGRect r1, CGRect r2);
extern bool CGRectIntersectsRect(CGRect r1, CGRect r2);

extern void CGRectDivide(CGRect rect, CGRect *slice, CGRect *remainder,
                         CGFloat amount, CGRectEdge edge);

/* ======================================================================
 * Affine Transform Functions
 * ====================================================================== */

extern CGAffineTransform CGAffineTransformMake(CGFloat a, CGFloat b,
                                               CGFloat c, CGFloat d,
                                               CGFloat tx, CGFloat ty);
extern CGAffineTransform CGAffineTransformMakeTranslation(CGFloat tx, CGFloat ty);
extern CGAffineTransform CGAffineTransformMakeScale(CGFloat sx, CGFloat sy);
extern CGAffineTransform CGAffineTransformMakeRotation(CGFloat angle);

extern bool CGAffineTransformIsIdentity(CGAffineTransform t);

extern CGAffineTransform CGAffineTransformConcat(CGAffineTransform t1,
                                                 CGAffineTransform t2);
extern CGAffineTransform CGAffineTransformTranslate(CGAffineTransform t,
                                                    CGFloat tx, CGFloat ty);
extern CGAffineTransform CGAffineTransformScale(CGAffineTransform t,
                                                CGFloat sx, CGFloat sy);
extern CGAffineTransform CGAffineTransformRotate(CGAffineTransform t,
                                                 CGFloat angle);
extern CGAffineTransform CGAffineTransformInvert(CGAffineTransform t);

extern bool CGAffineTransformEqualToTransform(CGAffineTransform t1,
                                              CGAffineTransform t2);

extern CGPoint CGPointApplyAffineTransform(CGPoint p, CGAffineTransform t);
extern CGSize  CGSizeApplyAffineTransform(CGSize s, CGAffineTransform t);
extern CGRect  CGRectApplyAffineTransform(CGRect rect, CGAffineTransform t);

/* ======================================================================
 * Color Space Functions
 * ====================================================================== */

extern CGColorSpaceRef CGColorSpaceCreateDeviceRGB(void);
extern CGColorSpaceRef CGColorSpaceCreateDeviceGray(void);
extern CGColorSpaceRef CGColorSpaceCreateDeviceCMYK(void);
extern CGColorSpaceRef CGColorSpaceCreateWithName(CFStringRef name);

extern CGColorSpaceRef CGColorSpaceRetain(CGColorSpaceRef space);
extern void            CGColorSpaceRelease(CGColorSpaceRef space);

extern size_t          CGColorSpaceGetNumberOfComponents(CGColorSpaceRef space);
extern CGColorSpaceModel CGColorSpaceGetModel(CGColorSpaceRef space);
extern CFStringRef     CGColorSpaceCopyName(CGColorSpaceRef space);
extern CFStringRef     CGColorSpaceGetName(CGColorSpaceRef space);
extern CFTypeID        CGColorSpaceGetTypeID(void);

extern bool CGColorSpaceIsWideGamutRGB(CGColorSpaceRef space);
extern bool CGColorSpaceIsHDR(CGColorSpaceRef space);
extern bool CGColorSpaceUsesExtendedRange(CGColorSpaceRef space);
extern bool CGColorSpaceSupportsOutput(CGColorSpaceRef space);

/* ======================================================================
 * Color Functions
 * ====================================================================== */

extern CGColorRef CGColorCreate(CGColorSpaceRef space, const CGFloat *components);
extern CGColorRef CGColorCreateGenericRGB(CGFloat red, CGFloat green,
                                          CGFloat blue, CGFloat alpha);
extern CGColorRef CGColorCreateGenericGray(CGFloat gray, CGFloat alpha);
extern CGColorRef CGColorCreateSRGB(CGFloat red, CGFloat green,
                                    CGFloat blue, CGFloat alpha);
extern CGColorRef CGColorCreateCopy(CGColorRef color);
extern CGColorRef CGColorCreateCopyWithAlpha(CGColorRef color, CGFloat alpha);

extern CGColorRef CGColorRetain(CGColorRef color);
extern void       CGColorRelease(CGColorRef color);

extern bool            CGColorEqualToColor(CGColorRef c1, CGColorRef c2);
extern size_t          CGColorGetNumberOfComponents(CGColorRef color);
extern const CGFloat  *CGColorGetComponents(CGColorRef color);
extern CGFloat         CGColorGetAlpha(CGColorRef color);
extern CGColorSpaceRef CGColorGetColorSpace(CGColorRef color);
extern CFTypeID        CGColorGetTypeID(void);

extern CGColorRef CGColorGetConstantColor(CFStringRef colorName);

/* ======================================================================
 * Data Provider Functions
 * ====================================================================== */

extern CGDataProviderRef CGDataProviderCreateWithData(
    void *info, const void *data, size_t size,
    CGDataProviderReleaseDataCallback releaseData);
extern CGDataProviderRef CGDataProviderCreateWithCFData(CFDataRef data);

extern CGDataProviderRef CGDataProviderRetain(CGDataProviderRef provider);
extern void              CGDataProviderRelease(CGDataProviderRef provider);

extern CFDataRef CGDataProviderCopyData(CGDataProviderRef provider);
extern void     *CGDataProviderGetInfo(CGDataProviderRef provider);
extern CFTypeID  CGDataProviderGetTypeID(void);

/* ======================================================================
 * Image Functions
 * ====================================================================== */

extern CGImageRef CGImageCreate(size_t width, size_t height,
                                size_t bitsPerComponent, size_t bitsPerPixel,
                                size_t bytesPerRow,
                                CGColorSpaceRef space,
                                CGBitmapInfo bitmapInfo,
                                CGDataProviderRef provider,
                                const CGFloat *decode,
                                bool shouldInterpolate,
                                CGColorRenderingIntent intent);
extern CGImageRef CGImageCreateCopy(CGImageRef image);

extern CGImageRef CGImageRetain(CGImageRef image);
extern void       CGImageRelease(CGImageRef image);

extern size_t              CGImageGetWidth(CGImageRef image);
extern size_t              CGImageGetHeight(CGImageRef image);
extern size_t              CGImageGetBitsPerComponent(CGImageRef image);
extern size_t              CGImageGetBitsPerPixel(CGImageRef image);
extern size_t              CGImageGetBytesPerRow(CGImageRef image);
extern CGColorSpaceRef     CGImageGetColorSpace(CGImageRef image);
extern CGImageAlphaInfo    CGImageGetAlphaInfo(CGImageRef image);
extern CGBitmapInfo        CGImageGetBitmapInfo(CGImageRef image);
extern CGDataProviderRef   CGImageGetDataProvider(CGImageRef image);
extern bool                CGImageGetShouldInterpolate(CGImageRef image);
extern CGColorRenderingIntent CGImageGetRenderingIntent(CGImageRef image);
extern bool                CGImageIsMask(CGImageRef image);
extern CFTypeID            CGImageGetTypeID(void);

/* ======================================================================
 * Path Functions
 * ====================================================================== */

extern CGMutablePathRef CGPathCreateMutable(void);
extern CGPathRef        CGPathCreateCopy(CGPathRef path);
extern CGMutablePathRef CGPathCreateMutableCopy(CGPathRef path);

extern CGPathRef CGPathRetain(CGPathRef path);
extern void      CGPathRelease(CGPathRef path);

extern void CGPathMoveToPoint(CGMutablePathRef path,
                              const CGAffineTransform *m,
                              CGFloat x, CGFloat y);
extern void CGPathAddLineToPoint(CGMutablePathRef path,
                                 const CGAffineTransform *m,
                                 CGFloat x, CGFloat y);
extern void CGPathAddQuadCurveToPoint(CGMutablePathRef path,
                                      const CGAffineTransform *m,
                                      CGFloat cpx, CGFloat cpy,
                                      CGFloat x, CGFloat y);
extern void CGPathAddCurveToPoint(CGMutablePathRef path,
                                  const CGAffineTransform *m,
                                  CGFloat cp1x, CGFloat cp1y,
                                  CGFloat cp2x, CGFloat cp2y,
                                  CGFloat x, CGFloat y);
extern void CGPathCloseSubpath(CGMutablePathRef path);

extern void CGPathAddRect(CGMutablePathRef path,
                          const CGAffineTransform *m, CGRect rect);
extern void CGPathAddRects(CGMutablePathRef path,
                           const CGAffineTransform *m,
                           const CGRect *rects, size_t count);
extern void CGPathAddLines(CGMutablePathRef path,
                           const CGAffineTransform *m,
                           const CGPoint *points, size_t count);
extern void CGPathAddEllipseInRect(CGMutablePathRef path,
                                   const CGAffineTransform *m, CGRect rect);
extern void CGPathAddArc(CGMutablePathRef path,
                         const CGAffineTransform *m,
                         CGFloat x, CGFloat y, CGFloat radius,
                         CGFloat startAngle, CGFloat endAngle,
                         bool clockwise);
extern void CGPathAddArcToPoint(CGMutablePathRef path,
                                const CGAffineTransform *m,
                                CGFloat x1, CGFloat y1,
                                CGFloat x2, CGFloat y2,
                                CGFloat radius);
extern void CGPathAddRoundedRect(CGMutablePathRef path,
                                 const CGAffineTransform *m, CGRect rect,
                                 CGFloat cornerWidth, CGFloat cornerHeight);
extern void CGPathAddPath(CGMutablePathRef path1,
                          const CGAffineTransform *m, CGPathRef path2);

extern bool    CGPathIsEmpty(CGPathRef path);
extern CGPoint CGPathGetCurrentPoint(CGPathRef path);
extern CGRect  CGPathGetBoundingBox(CGPathRef path);
extern CGRect  CGPathGetPathBoundingBox(CGPathRef path);
extern bool    CGPathContainsPoint(CGPathRef path,
                                   const CGAffineTransform *m,
                                   CGPoint point, bool eoFill);

extern void    CGPathApply(CGPathRef path, void *info,
                           CGPathApplierFunction function);
extern bool    CGPathEqualToPath(CGPathRef path1, CGPathRef path2);
extern CFTypeID CGPathGetTypeID(void);

/* ======================================================================
 * Bitmap Context Functions
 * ====================================================================== */

extern CGContextRef CGBitmapContextCreate(
    void *data, size_t width, size_t height,
    size_t bitsPerComponent, size_t bytesPerRow,
    CGColorSpaceRef space, uint32_t bitmapInfo);
extern CGContextRef CGBitmapContextCreateWithData(
    void *data, size_t width, size_t height,
    size_t bitsPerComponent, size_t bytesPerRow,
    CGColorSpaceRef space, uint32_t bitmapInfo,
    void (*releaseCallback)(void *releaseInfo, void *data),
    void *releaseInfo);

extern void            *CGBitmapContextGetData(CGContextRef c);
extern size_t           CGBitmapContextGetWidth(CGContextRef c);
extern size_t           CGBitmapContextGetHeight(CGContextRef c);
extern size_t           CGBitmapContextGetBitsPerComponent(CGContextRef c);
extern size_t           CGBitmapContextGetBitsPerPixel(CGContextRef c);
extern size_t           CGBitmapContextGetBytesPerRow(CGContextRef c);
extern CGColorSpaceRef  CGBitmapContextGetColorSpace(CGContextRef c);
extern CGImageAlphaInfo CGBitmapContextGetAlphaInfo(CGContextRef c);
extern CGBitmapInfo     CGBitmapContextGetBitmapInfo(CGContextRef c);
extern CGImageRef       CGBitmapContextCreateImage(CGContextRef c);

/* ======================================================================
 * Context Lifecycle
 * ====================================================================== */

extern CGContextRef CGContextRetain(CGContextRef c);
extern void         CGContextRelease(CGContextRef c);
extern CFTypeID     CGContextGetTypeID(void);

/* ======================================================================
 * Context State
 * ====================================================================== */

extern void CGContextSaveGState(CGContextRef c);
extern void CGContextRestoreGState(CGContextRef c);

/* Fill color */
extern void CGContextSetRGBFillColor(CGContextRef c,
                                     CGFloat red, CGFloat green,
                                     CGFloat blue, CGFloat alpha);
extern void CGContextSetGrayFillColor(CGContextRef c,
                                      CGFloat gray, CGFloat alpha);
extern void CGContextSetFillColorWithColor(CGContextRef c, CGColorRef color);
extern void CGContextSetCMYKFillColor(CGContextRef c,
                                      CGFloat cyan, CGFloat magenta,
                                      CGFloat yellow, CGFloat black,
                                      CGFloat alpha);

/* Stroke color */
extern void CGContextSetRGBStrokeColor(CGContextRef c,
                                       CGFloat red, CGFloat green,
                                       CGFloat blue, CGFloat alpha);
extern void CGContextSetGrayStrokeColor(CGContextRef c,
                                        CGFloat gray, CGFloat alpha);
extern void CGContextSetStrokeColorWithColor(CGContextRef c, CGColorRef color);
extern void CGContextSetCMYKStrokeColor(CGContextRef c,
                                        CGFloat cyan, CGFloat magenta,
                                        CGFloat yellow, CGFloat black,
                                        CGFloat alpha);

/* Generic fill/stroke color */
extern void CGContextSetFillColor(CGContextRef c, const CGFloat *components);
extern void CGContextSetStrokeColor(CGContextRef c, const CGFloat *components);
extern void CGContextSetFillColorSpace(CGContextRef c, CGColorSpaceRef space);
extern void CGContextSetStrokeColorSpace(CGContextRef c, CGColorSpaceRef space);

/* Line parameters */
extern void CGContextSetLineWidth(CGContextRef c, CGFloat width);
extern void CGContextSetLineCap(CGContextRef c, CGLineCap cap);
extern void CGContextSetLineJoin(CGContextRef c, CGLineJoin join);
extern void CGContextSetMiterLimit(CGContextRef c, CGFloat limit);
extern void CGContextSetLineDash(CGContextRef c, CGFloat phase,
                                 const CGFloat *lengths, size_t count);
extern void CGContextSetFlatness(CGContextRef c, CGFloat flatness);

/* Alpha and blend mode */
extern void CGContextSetAlpha(CGContextRef c, CGFloat alpha);
extern void CGContextSetBlendMode(CGContextRef c, CGBlendMode mode);

/* Anti-aliasing */
extern void CGContextSetShouldAntialias(CGContextRef c, bool shouldAntialias);
extern void CGContextSetAllowsAntialiasing(CGContextRef c, bool allowsAntialiasing);

/* Shadow */
extern void CGContextSetShadow(CGContextRef c, CGSize offset, CGFloat blur);
extern void CGContextSetShadowWithColor(CGContextRef c,
                                        CGSize offset, CGFloat blur,
                                        CGColorRef color);

/* Text state */
extern void    CGContextSetTextDrawingMode(CGContextRef c, CGTextDrawingMode mode);
extern void    CGContextSetCharacterSpacing(CGContextRef c, CGFloat spacing);
extern void    CGContextSetTextPosition(CGContextRef c, CGFloat x, CGFloat y);
extern CGPoint CGContextGetTextPosition(CGContextRef c);

/* Interpolation quality */
extern void                  CGContextSetInterpolationQuality(CGContextRef c,
                                                              CGInterpolationQuality quality);
extern CGInterpolationQuality CGContextGetInterpolationQuality(CGContextRef c);

/* Rendering intent */
extern void CGContextSetRenderingIntent(CGContextRef c, CGColorRenderingIntent intent);

/* Font smoothing */
extern void CGContextSetShouldSmoothFonts(CGContextRef c, bool shouldSmooth);
extern void CGContextSetAllowsFontSmoothing(CGContextRef c, bool allows);
extern void CGContextSetShouldSubpixelPositionFonts(CGContextRef c, bool should);
extern void CGContextSetAllowsFontSubpixelPositioning(CGContextRef c, bool allows);
extern void CGContextSetShouldSubpixelQuantizeFonts(CGContextRef c, bool should);
extern void CGContextSetAllowsFontSubpixelQuantization(CGContextRef c, bool allows);

/* ======================================================================
 * Context CTM
 * ====================================================================== */

extern void              CGContextTranslateCTM(CGContextRef c, CGFloat tx, CGFloat ty);
extern void              CGContextScaleCTM(CGContextRef c, CGFloat sx, CGFloat sy);
extern void              CGContextRotateCTM(CGContextRef c, CGFloat angle);
extern void              CGContextConcatCTM(CGContextRef c, CGAffineTransform transform);
extern CGAffineTransform CGContextGetCTM(CGContextRef c);

extern CGPoint CGContextConvertPointToDeviceSpace(CGContextRef c, CGPoint point);
extern CGPoint CGContextConvertPointToUserSpace(CGContextRef c, CGPoint point);
extern CGSize  CGContextConvertSizeToDeviceSpace(CGContextRef c, CGSize size);
extern CGSize  CGContextConvertSizeToUserSpace(CGContextRef c, CGSize size);
extern CGRect  CGContextConvertRectToDeviceSpace(CGContextRef c, CGRect rect);
extern CGRect  CGContextConvertRectToUserSpace(CGContextRef c, CGRect rect);

/* ======================================================================
 * Context Path
 * ====================================================================== */

extern void CGContextBeginPath(CGContextRef c);
extern void CGContextMoveToPoint(CGContextRef c, CGFloat x, CGFloat y);
extern void CGContextAddLineToPoint(CGContextRef c, CGFloat x, CGFloat y);
extern void CGContextAddQuadCurveToPoint(CGContextRef c,
                                         CGFloat cpx, CGFloat cpy,
                                         CGFloat x, CGFloat y);
extern void CGContextAddCurveToPoint(CGContextRef c,
                                     CGFloat cp1x, CGFloat cp1y,
                                     CGFloat cp2x, CGFloat cp2y,
                                     CGFloat x, CGFloat y);
extern void CGContextClosePath(CGContextRef c);

extern void CGContextAddRect(CGContextRef c, CGRect rect);
extern void CGContextAddRects(CGContextRef c, const CGRect *rects, size_t count);
extern void CGContextAddLines(CGContextRef c, const CGPoint *points, size_t count);
extern void CGContextAddEllipseInRect(CGContextRef c, CGRect rect);
extern void CGContextAddArc(CGContextRef c,
                            CGFloat x, CGFloat y, CGFloat radius,
                            CGFloat startAngle, CGFloat endAngle,
                            int clockwise);
extern void CGContextAddArcToPoint(CGContextRef c,
                                   CGFloat x1, CGFloat y1,
                                   CGFloat x2, CGFloat y2,
                                   CGFloat radius);
extern void CGContextAddPath(CGContextRef c, CGPathRef path);

extern void      CGContextReplacePathWithStrokedPath(CGContextRef c);
extern bool      CGContextIsPathEmpty(CGContextRef c);
extern CGPoint   CGContextGetPathCurrentPoint(CGContextRef c);
extern CGRect    CGContextGetPathBoundingBox(CGContextRef c);
extern bool      CGContextPathContainsPoint(CGContextRef c, CGPoint point,
                                            CGPathDrawingMode mode);
extern CGPathRef CGContextCopyPath(CGContextRef c);

/* ======================================================================
 * Context Drawing
 * ====================================================================== */

extern void CGContextFillRect(CGContextRef c, CGRect rect);
extern void CGContextFillRects(CGContextRef c, const CGRect *rects, size_t count);
extern void CGContextClearRect(CGContextRef c, CGRect rect);
extern void CGContextStrokeRect(CGContextRef c, CGRect rect);
extern void CGContextStrokeRectWithWidth(CGContextRef c, CGRect rect, CGFloat width);
extern void CGContextStrokeLineSegments(CGContextRef c,
                                        const CGPoint *points, size_t count);

extern void CGContextFillPath(CGContextRef c);
extern void CGContextEOFillPath(CGContextRef c);
extern void CGContextStrokePath(CGContextRef c);
extern void CGContextDrawPath(CGContextRef c, CGPathDrawingMode mode);

extern void CGContextFillEllipseInRect(CGContextRef c, CGRect rect);
extern void CGContextStrokeEllipseInRect(CGContextRef c, CGRect rect);

extern void CGContextDrawImage(CGContextRef c, CGRect rect, CGImageRef image);
extern void CGContextDrawTiledImage(CGContextRef c, CGRect rect, CGImageRef image);

/* ======================================================================
 * Context Clip
 * ====================================================================== */

extern void   CGContextClip(CGContextRef c);
extern void   CGContextEOClip(CGContextRef c);
extern void   CGContextClipToRect(CGContextRef c, CGRect rect);
extern void   CGContextClipToRects(CGContextRef c, const CGRect *rects, size_t count);
extern CGRect CGContextGetClipBoundingBox(CGContextRef c);

/* ======================================================================
 * Context Text
 * ====================================================================== */

extern void CGContextShowTextAtPoint(CGContextRef c, CGFloat x, CGFloat y,
                                     const char *string, size_t length);

/* ======================================================================
 * Context Flush / Page
 * ====================================================================== */

extern void CGContextFlush(CGContextRef c);
extern void CGContextSynchronize(CGContextRef c);
extern void CGContextBeginPage(CGContextRef c, const CGRect *mediaBox);
extern void CGContextEndPage(CGContextRef c);

#ifdef __cplusplus
}
#endif
