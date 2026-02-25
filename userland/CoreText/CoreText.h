#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------------
 * Opaque Type Declarations
 * ---------------------------------------------------------------------------*/

typedef const struct __CTFont *CTFontRef;
typedef const struct __CTRun *CTRunRef;
typedef const struct __CTLine *CTLineRef;
typedef const struct __CTFramesetter *CTFramesetterRef;
typedef const struct __CTFrame *CTFrameRef;
typedef const void *CTFontDescriptorRef;
typedef const void *CTFontCollectionRef;
typedef const struct __CTParagraphStyle *CTParagraphStyleRef;

/* ---------------------------------------------------------------------------
 * Enumerations
 * ---------------------------------------------------------------------------*/

typedef enum {
    kCTRunStatusNoStatus             = 0,
    kCTRunStatusRightToLeft          = (1 << 0),
    kCTRunStatusNonMonotonic         = (1 << 1),
    kCTRunStatusHasNonIdentityMatrix = (1 << 2),
} CTRunStatus;

typedef enum {
    kCTLineTruncationStart  = 0,
    kCTLineTruncationEnd    = 1,
    kCTLineTruncationMiddle = 2,
} CTLineTruncationType;

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
    kCTParagraphStyleSpecifierAlignment              = 0,
    kCTParagraphStyleSpecifierFirstLineHeadIndent    = 1,
    kCTParagraphStyleSpecifierHeadIndent             = 2,
    kCTParagraphStyleSpecifierTailIndent             = 3,
    kCTParagraphStyleSpecifierTabStops               = 4,
    kCTParagraphStyleSpecifierDefaultTabInterval     = 5,
    kCTParagraphStyleSpecifierLineBreakMode          = 6,
    kCTParagraphStyleSpecifierLineHeightMultiple     = 7,
    kCTParagraphStyleSpecifierMaximumLineHeight      = 8,
    kCTParagraphStyleSpecifierMinimumLineHeight      = 9,
    kCTParagraphStyleSpecifierLineSpacing            = 10,
    kCTParagraphStyleSpecifierParagraphSpacing       = 11,
    kCTParagraphStyleSpecifierParagraphSpacingBefore = 12,
    kCTParagraphStyleSpecifierBaseWritingDirection   = 13,
    kCTParagraphStyleSpecifierMaximumLineSpacing     = 14,
    kCTParagraphStyleSpecifierMinimumLineSpacing     = 15,
    kCTParagraphStyleSpecifierLineSpacingAdjustment  = 16,
    kCTParagraphStyleSpecifierCount                  = 17,
} CTParagraphStyleSpecifier;

/* ---------------------------------------------------------------------------
 * Structures
 * ---------------------------------------------------------------------------*/

typedef struct {
    CTParagraphStyleSpecifier spec;
    size_t                    valueSize;
    const void               *value;
} CTParagraphStyleSetting;

/* ---------------------------------------------------------------------------
 * String Attribute Key Constants
 * ---------------------------------------------------------------------------*/

extern CFStringRef kCTFontAttributeName;
extern CFStringRef kCTForegroundColorAttributeName;
extern CFStringRef kCTBackgroundColorAttributeName;
extern CFStringRef kCTFontSizeAttribute;
extern CFStringRef kCTKernAttributeName;
extern CFStringRef kCTLigatureAttributeName;
extern CFStringRef kCTParagraphStyleAttributeName;
extern CFStringRef kCTUnderlineStyleAttributeName;
extern CFStringRef kCTStrokeWidthAttributeName;
extern CFStringRef kCTStrokeColorAttributeName;
extern CFStringRef kCTSuperscriptAttributeName;

/* ---------------------------------------------------------------------------
 * CTFont
 * ---------------------------------------------------------------------------*/

extern CTFontRef CTFontCreateWithName(CFStringRef name, CGFloat size, const CGAffineTransform *matrix);
extern CTFontRef CTFontCreateWithFontDescriptor(CTFontDescriptorRef descriptor, CGFloat size, const CGAffineTransform *matrix);
extern CTFontRef CTFontCreateCopyWithAttributes(CTFontRef font, CGFloat size, const CGAffineTransform *matrix, CTFontDescriptorRef attributes);
extern CTFontRef CTFontCreateCopyWithSymbolicTraits(CTFontRef font, CGFloat size, const CGAffineTransform *matrix, uint32_t symTraitValue, uint32_t symTraitMask);
extern CTFontRef CTFontCreateWithGraphicsFont(void *graphicsFont, CGFloat size, const CGAffineTransform *matrix, CTFontDescriptorRef attributes);
extern CTFontRef CTFontRetain(CTFontRef font);
extern void CTFontRelease(CTFontRef font);
extern CGFloat CTFontGetSize(CTFontRef font);
extern CGFloat CTFontGetAscent(CTFontRef font);
extern CGFloat CTFontGetDescent(CTFontRef font);
extern CGFloat CTFontGetLeading(CTFontRef font);
extern CGFloat CTFontGetUnderlinePosition(CTFontRef font);
extern CGFloat CTFontGetUnderlineThickness(CTFontRef font);
extern CGRect CTFontGetBoundingBox(CTFontRef font);
extern unsigned CTFontGetUnitsPerEm(CTFontRef font);
extern CFStringRef CTFontCopyPostScriptName(CTFontRef font);
extern CFStringRef CTFontCopyFamilyName(CTFontRef font);
extern CFStringRef CTFontCopyDisplayName(CTFontRef font);
extern CFStringRef CTFontCopyFullName(CTFontRef font);
extern void *CTFontCopyGraphicsFont(CTFontRef font, void *descriptorOut);
extern bool CTFontGetGlyphsForCharacters(CTFontRef font, const UniChar *characters, uint16_t *glyphs, CFIndex count);
extern CGFloat CTFontGetAdvancesForGlyphs(CTFontRef font, int orientation, const uint16_t *glyphs, CGSize *advances, CFIndex count);
extern CTFontRef CTFontCreateWithAttributes(CFDictionaryRef attributes);

/* ---------------------------------------------------------------------------
 * CTRun
 * ---------------------------------------------------------------------------*/

extern CFIndex CTRunGetGlyphCount(CTRunRef run);
extern const uint16_t *CTRunGetGlyphsPtr(CTRunRef run);
extern void CTRunGetGlyphs(CTRunRef run, CFRange range, uint16_t *buffer);
extern const CGPoint *CTRunGetPositionsPtr(CTRunRef run);
extern void CTRunGetPositions(CTRunRef run, CFRange range, CGPoint *buffer);
extern const CGSize *CTRunGetAdvancesPtr(CTRunRef run);
extern void CTRunGetAdvances(CTRunRef run, CFRange range, CGSize *buffer);
extern const CFIndex *CTRunGetStringIndicesPtr(CTRunRef run);
extern void CTRunGetStringIndices(CTRunRef run, CFRange range, CFIndex *buffer);
extern CFRange CTRunGetStringRange(CTRunRef run);
extern CTRunStatus CTRunGetStatus(CTRunRef run);
extern CFDictionaryRef CTRunGetAttributes(CTRunRef run);
extern double CTRunGetTypographicBounds(CTRunRef run, CFRange range, CGFloat *ascent, CGFloat *descent, CGFloat *leading);
extern CGRect CTRunGetImageBounds(CTRunRef run, CGContextRef context, CFRange range);
extern CGAffineTransform CTRunGetTextMatrix(CTRunRef run);
extern void CTRunDraw(CTRunRef run, CGContextRef context, CFRange range);

/* ---------------------------------------------------------------------------
 * CTLine
 * ---------------------------------------------------------------------------*/

extern CTLineRef CTLineCreateWithAttributedString(CFAttributedStringRef attrString);
extern CTLineRef CTLineCreateWithString(CFStringRef string, CFDictionaryRef attributes);
extern CTLineRef CTLineRetain(CTLineRef line);
extern void CTLineRelease(CTLineRef line);
extern CFArrayRef CTLineGetGlyphRuns(CTLineRef line);
extern CFIndex CTLineGetGlyphCount(CTLineRef line);
extern CFRange CTLineGetStringRange(CTLineRef line);
extern double CTLineGetTypographicBounds(CTLineRef line, CGFloat *ascent, CGFloat *descent, CGFloat *leading);
extern CGRect CTLineGetImageBounds(CTLineRef line, CGContextRef context);
extern double CTLineGetTrailingWhitespaceWidth(CTLineRef line);
extern double CTLineGetPenOffsetForFlush(CTLineRef line, CGFloat flushFactor, double flushWidth);
extern CFIndex CTLineGetStringIndexForPosition(CTLineRef line, CGPoint position);
extern CGFloat CTLineGetOffsetForStringIndex(CTLineRef line, CFIndex charIndex, CGFloat *secondaryOffset);
extern CTLineRef CTLineCreateTruncatedLine(CTLineRef line, double width, CTLineTruncationType truncationType, CTLineRef truncationToken);
extern CTLineRef CTLineCreateJustifiedLine(CTLineRef line, CGFloat justificationFactor, double justificationWidth);
extern void CTLineDraw(CTLineRef line, CGContextRef context);

/* ---------------------------------------------------------------------------
 * CTFramesetter
 * ---------------------------------------------------------------------------*/

extern CTFramesetterRef CTFramesetterCreateWithAttributedString(CFAttributedStringRef attrString);
extern CTFramesetterRef CTFramesetterRetain(CTFramesetterRef framesetter);
extern void CTFramesetterRelease(CTFramesetterRef framesetter);
extern CTFrameRef CTFramesetterCreateFrame(CTFramesetterRef framesetter, CFRange stringRange, CGPathRef path, CFDictionaryRef frameAttributes);
extern CGSize CTFramesetterSuggestFrameSizeWithConstraints(CTFramesetterRef framesetter, CFRange stringRange, CFDictionaryRef frameAttributes, CGSize constraints, CFRange *fitRange);

/* ---------------------------------------------------------------------------
 * CTFrame
 * ---------------------------------------------------------------------------*/

extern CTFrameRef CTFrameRetain(CTFrameRef frame);
extern void CTFrameRelease(CTFrameRef frame);
extern CFArrayRef CTFrameGetLines(CTFrameRef frame);
extern void CTFrameGetLineOrigins(CTFrameRef frame, CFRange range, CGPoint *origins);
extern CFRange CTFrameGetVisibleStringRange(CTFrameRef frame);
extern CGPathRef CTFrameGetPath(CTFrameRef frame);
extern CFDictionaryRef CTFrameGetFrameAttributes(CTFrameRef frame);
extern void CTFrameDraw(CTFrameRef frame, CGContextRef context);

/* ---------------------------------------------------------------------------
 * CTFontDescriptor
 * ---------------------------------------------------------------------------*/

extern CTFontDescriptorRef CTFontDescriptorCreateWithAttributes(CFDictionaryRef attributes);
extern CTFontDescriptorRef CTFontDescriptorCreateWithNameAndSize(CFStringRef name, CGFloat size);
extern CTFontDescriptorRef CTFontDescriptorCreateCopyWithAttributes(CTFontDescriptorRef original, CFDictionaryRef attributes);
extern CFTypeRef CTFontDescriptorCopyAttribute(CTFontDescriptorRef descriptor, CFStringRef attribute);
extern CFDictionaryRef CTFontDescriptorCopyAttributes(CTFontDescriptorRef descriptor);
extern CFArrayRef CTFontDescriptorCreateMatchingFontDescriptors(CTFontDescriptorRef descriptor, CFArrayRef mandatoryAttributes);
extern CTFontDescriptorRef CTFontDescriptorCreateMatchingFontDescriptor(CTFontDescriptorRef descriptor, CFArrayRef mandatoryAttributes);

/* ---------------------------------------------------------------------------
 * CTFontCollection
 * ---------------------------------------------------------------------------*/

extern CTFontCollectionRef CTFontCollectionCreateFromAvailableFonts(CFDictionaryRef options);
extern CFArrayRef CTFontCollectionCreateMatchingFontDescriptors(CTFontCollectionRef collection);

/* ---------------------------------------------------------------------------
 * CTParagraphStyle
 * ---------------------------------------------------------------------------*/

extern CTParagraphStyleRef CTParagraphStyleCreate(const CTParagraphStyleSetting *settings, size_t settingCount);
extern bool CTParagraphStyleGetValueForSpecifier(CTParagraphStyleRef paragraphStyle, CTParagraphStyleSpecifier spec, size_t valueBufferSize, void *valueBuffer);
extern CTParagraphStyleRef CTParagraphStyleRetain(CTParagraphStyleRef style);
extern void CTParagraphStyleRelease(CTParagraphStyleRef style);

#ifdef __cplusplus
}
#endif
