/*
 * Kiseki OS - CoreFoundation.framework
 *
 * Public header for CoreFoundation. Declares all exported types,
 * constants, and function prototypes.
 *
 * Reference: apple-oss-distributions/CF (CF-1153.18)
 *            apple/swift-corelibs-foundation
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Section 1: CoreFoundation Scalar Typedefs
 * ============================================================================ */

typedef unsigned long   CFTypeID;
typedef unsigned long   CFOptionFlags;
typedef unsigned long   CFHashCode;
typedef signed long     CFIndex;
typedef const void *    CFTypeRef;
typedef double          CFTimeInterval;
typedef double          CFAbsoluteTime;

/* ============================================================================
 * Section 2: CFRange
 * ============================================================================ */

typedef struct {
    CFIndex location;
    CFIndex length;
} CFRange;

static inline CFRange CFRangeMake(CFIndex loc, CFIndex len) {
    CFRange r;
    r.location = loc;
    r.length = len;
    return r;
}

/* ============================================================================
 * Section 3: CFComparisonResult
 * ============================================================================ */

typedef CFIndex CFComparisonResult;

#define kCFCompareLessThan    (-1L)
#define kCFCompareEqualTo     0L
#define kCFCompareGreaterThan 1L

typedef CFComparisonResult (*CFComparatorFunction)(const void *val1,
                                                   const void *val2,
                                                   void *context);

/* ============================================================================
 * Section 4: kCFNotFound
 * ============================================================================ */

#define kCFNotFound ((CFIndex)-1)

/* ============================================================================
 * Section 5: Mac-Compatibility Scalar Types
 * ============================================================================ */

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
 * Section 6: Opaque Type Forward Declarations
 * ============================================================================ */

typedef const struct __CFAllocator *         CFAllocatorRef;
typedef const struct __CFString *            CFStringRef;
typedef struct __CFString *                  CFMutableStringRef;
typedef const struct __CFArray *             CFArrayRef;
typedef struct __CFArray *                   CFMutableArrayRef;
typedef const struct __CFDictionary *        CFDictionaryRef;
typedef struct __CFDictionary *              CFMutableDictionaryRef;
typedef const struct __CFSet *               CFSetRef;
typedef struct __CFSet *                     CFMutableSetRef;
typedef const struct __CFNumber *            CFNumberRef;
typedef const struct __CFData *              CFDataRef;
typedef struct __CFData *                    CFMutableDataRef;
typedef const struct __CFBoolean *           CFBooleanRef;
typedef const struct __CFNull *              CFNullRef;
typedef const struct __CFDate *              CFDateRef;
typedef const struct __CFAttributedString *  CFAttributedStringRef;
typedef struct __CFAttributedString *        CFMutableAttributedStringRef;
typedef CFTypeRef                            CFPropertyListRef;
typedef const struct __CFRunLoop *           CFRunLoopRef;
typedef const struct __CFRunLoopSource *     CFRunLoopSourceRef;
typedef const struct __CFRunLoopTimer *      CFRunLoopTimerRef;
typedef const struct __CFRunLoopObserver *   CFRunLoopObserverRef;
typedef CFStringRef                          CFRunLoopMode;

/* ============================================================================
 * Section 7: CFStringEncoding
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
 * Section 8: CFStringCompareFlags
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
 * Section 9: CFNumberType
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
 * Section 10: Callback Structures
 * ============================================================================ */

/* --- CFAllocator callbacks --- */

typedef const void *(*CFAllocatorRetainCallBack)(const void *info);
typedef void        (*CFAllocatorReleaseCallBack)(const void *info);
typedef CFStringRef (*CFAllocatorCopyDescriptionCallBack)(const void *info);
typedef void *      (*CFAllocatorAllocateCallBack)(CFIndex allocSize, CFOptionFlags hint, void *info);
typedef void *      (*CFAllocatorReallocateCallBack)(void *ptr, CFIndex newsize, CFOptionFlags hint, void *info);
typedef void        (*CFAllocatorDeallocateCallBack)(void *ptr, void *info);
typedef CFIndex     (*CFAllocatorPreferredSizeCallBack)(CFIndex size, CFOptionFlags hint, void *info);

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

/* --- CFArray callbacks --- */

typedef const void *(*CFArrayRetainCallBack)(CFAllocatorRef allocator, const void *value);
typedef void        (*CFArrayReleaseCallBack)(CFAllocatorRef allocator, const void *value);
typedef CFStringRef (*CFArrayCopyDescriptionCallBack)(const void *value);
typedef Boolean     (*CFArrayEqualCallBack)(const void *value1, const void *value2);

typedef struct {
    CFIndex                         version;
    CFArrayRetainCallBack           retain;
    CFArrayReleaseCallBack          release;
    CFArrayCopyDescriptionCallBack  copyDescription;
    CFArrayEqualCallBack            equal;
} CFArrayCallBacks;

typedef void (*CFArrayApplierFunction)(const void *value, void *context);

/* --- CFDictionary callbacks --- */

typedef const void *(*CFDictionaryRetainCallBack)(CFAllocatorRef allocator, const void *value);
typedef void        (*CFDictionaryReleaseCallBack)(CFAllocatorRef allocator, const void *value);
typedef CFStringRef (*CFDictionaryCopyDescriptionCallBack)(const void *value);
typedef Boolean     (*CFDictionaryEqualCallBack)(const void *value1, const void *value2);
typedef CFHashCode  (*CFDictionaryHashCallBack)(const void *value);

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

/* --- CFSet callbacks --- */

typedef const void *(*CFSetRetainCallBack)(CFAllocatorRef allocator, const void *value);
typedef void        (*CFSetReleaseCallBack)(CFAllocatorRef allocator, const void *value);
typedef CFStringRef (*CFSetCopyDescriptionCallBack)(const void *value);
typedef Boolean     (*CFSetEqualCallBack)(const void *value1, const void *value2);
typedef CFHashCode  (*CFSetHashCallBack)(const void *value);

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
 * Section 11: CFRuntime (Public Subset)
 * ============================================================================ */

typedef struct __CFRuntimeBase {
    uintptr_t _cfisa;
    uint64_t  _cfinfoa;
} CFRuntimeBase;

#define _kCFRuntimeNotATypeID 0

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

/* ============================================================================
 * Section 12: CFRunLoop Types
 * ============================================================================ */

/* --- CFRunLoopActivity flags (exact Apple values) --- */

typedef CFOptionFlags CFRunLoopActivity;

#define kCFRunLoopEntry         (1UL << 0)
#define kCFRunLoopBeforeTimers  (1UL << 1)
#define kCFRunLoopBeforeSources (1UL << 2)
#define kCFRunLoopBeforeWaiting (1UL << 5)
#define kCFRunLoopAfterWaiting  (1UL << 6)
#define kCFRunLoopExit          (1UL << 7)
#define kCFRunLoopAllActivities 0x0FFFFFFFU

/* --- CFRunLoopRunResult --- */

#define kCFRunLoopRunFinished       1
#define kCFRunLoopRunStopped        2
#define kCFRunLoopRunTimedOut       3
#define kCFRunLoopRunHandledSource  4

/* --- CFRunLoop callback typedefs --- */

typedef void (*CFRunLoopTimerCallBack)(CFRunLoopTimerRef timer, void *info);
typedef void (*CFRunLoopObserverCallBack)(CFRunLoopObserverRef observer, CFRunLoopActivity activity, void *info);

/* --- CFRunLoopSourceContext (version 0 -- callback-based) --- */

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

/* ============================================================================
 * Section 13: Extern Constants
 * ============================================================================ */

extern double kCFCoreFoundationVersionNumber;

extern const CFAllocatorRef kCFAllocatorDefault;
extern const CFAllocatorRef kCFAllocatorSystemDefault;
extern const CFAllocatorRef kCFAllocatorMalloc;
extern const CFAllocatorRef kCFAllocatorMallocZone;
extern const CFAllocatorRef kCFAllocatorNull;
extern const CFAllocatorRef kCFAllocatorUseContext;

extern const CFNullRef      kCFNull;
extern const CFBooleanRef   kCFBooleanTrue;
extern const CFBooleanRef   kCFBooleanFalse;

extern const CFNumberRef    kCFNumberPositiveInfinity;
extern const CFNumberRef    kCFNumberNegativeInfinity;
extern const CFNumberRef    kCFNumberNaN;

extern const CFArrayCallBacks          kCFTypeArrayCallBacks;
extern const CFDictionaryKeyCallBacks  kCFTypeDictionaryKeyCallBacks;
extern const CFDictionaryValueCallBacks kCFTypeDictionaryValueCallBacks;
extern const CFSetCallBacks            kCFTypeSetCallBacks;
extern const CFDictionaryKeyCallBacks  kCFCopyStringDictionaryKeyCallBacks;

extern const CFRunLoopMode  kCFRunLoopDefaultMode;
extern const CFRunLoopMode  kCFRunLoopCommonModes;

/* ============================================================================
 * Section 14: CFBase / CFType Functions
 * ============================================================================ */

extern CFTypeID       CFGetTypeID(CFTypeRef cf);
extern CFTypeRef      CFRetain(CFTypeRef cf);
extern void           CFRelease(CFTypeRef cf);
extern CFTypeRef      CFAutorelease(CFTypeRef cf);
extern CFIndex        CFGetRetainCount(CFTypeRef cf);
extern Boolean        CFEqual(CFTypeRef cf1, CFTypeRef cf2);
extern CFHashCode     CFHash(CFTypeRef cf);
extern CFStringRef    CFCopyDescription(CFTypeRef cf);
extern CFStringRef    CFCopyTypeIDDescription(CFTypeID type_id);
extern CFAllocatorRef CFGetAllocator(CFTypeRef cf);
extern CFTypeRef      CFMakeCollectable(CFTypeRef cf);

extern void           CFShow(CFTypeRef obj);
extern void           CFShowStr(CFStringRef str);

/* ============================================================================
 * Section 15: CFRuntime Functions
 * ============================================================================ */

extern CFTypeID              _CFRuntimeRegisterClass(const CFRuntimeClass *cls);
extern const CFRuntimeClass *_CFRuntimeGetClassWithTypeID(CFTypeID typeID);
extern CFTypeRef             _CFRuntimeCreateInstance(CFAllocatorRef allocator,
                                                      CFTypeID typeID,
                                                      CFIndex extraBytes,
                                                      unsigned char *category);
extern void                  _CFRuntimeInitStaticInstance(void *memory, CFTypeID typeID);
extern void                  _CFRuntimeSetInstanceTypeID(CFTypeRef cf, CFTypeID typeID);

typedef uintptr_t (*__CFBridgeISALookupFn)(CFTypeID typeID);
extern void _CFRuntimeBridgeSetISALookup(__CFBridgeISALookupFn fn);

/* ============================================================================
 * Section 16: CFAllocator Functions
 * ============================================================================ */

extern CFTypeID       CFAllocatorGetTypeID(void);
extern CFAllocatorRef CFAllocatorGetDefault(void);
extern void           CFAllocatorSetDefault(CFAllocatorRef allocator);
extern CFAllocatorRef CFAllocatorCreate(CFAllocatorRef allocator, CFAllocatorContext *context);
extern void *         CFAllocatorAllocate(CFAllocatorRef allocator, CFIndex size, CFOptionFlags hint);
extern void *         CFAllocatorReallocate(CFAllocatorRef allocator, void *ptr, CFIndex newsize, CFOptionFlags hint);
extern void           CFAllocatorDeallocate(CFAllocatorRef allocator, void *ptr);
extern CFIndex        CFAllocatorGetPreferredSizeForSize(CFAllocatorRef allocator, CFIndex size, CFOptionFlags hint);
extern void           CFAllocatorGetContext(CFAllocatorRef allocator, CFAllocatorContext *context);

/* ============================================================================
 * Section 17: CFNull Functions
 * ============================================================================ */

extern CFTypeID CFNullGetTypeID(void);

/* ============================================================================
 * Section 18: CFBoolean Functions
 * ============================================================================ */

extern CFTypeID CFBooleanGetTypeID(void);
extern Boolean  CFBooleanGetValue(CFBooleanRef boolean);

/* ============================================================================
 * Section 19: CFNumber Functions
 * ============================================================================ */

extern CFTypeID          CFNumberGetTypeID(void);
extern CFNumberRef       CFNumberCreate(CFAllocatorRef allocator, CFNumberType theType, const void *valuePtr);
extern CFNumberType      CFNumberGetType(CFNumberRef number);
extern CFIndex           CFNumberGetByteSize(CFNumberRef number);
extern Boolean           CFNumberIsFloatType(CFNumberRef number);
extern Boolean           CFNumberGetValue(CFNumberRef number, CFNumberType theType, void *valuePtr);
extern CFComparisonResult CFNumberCompare(CFNumberRef number, CFNumberRef otherNumber, void *context);

/* ============================================================================
 * Section 20: CFData Functions
 * ============================================================================ */

extern CFTypeID        CFDataGetTypeID(void);
extern CFDataRef       CFDataCreate(CFAllocatorRef allocator, const UInt8 *bytes, CFIndex length);
extern CFDataRef       CFDataCreateCopy(CFAllocatorRef allocator, CFDataRef theData);
extern CFDataRef       CFDataCreateWithBytesNoCopy(CFAllocatorRef allocator,
                           const UInt8 *bytes, CFIndex length, CFAllocatorRef bytesDeallocator);
extern CFMutableDataRef CFDataCreateMutable(CFAllocatorRef allocator, CFIndex capacity);
extern CFMutableDataRef CFDataCreateMutableCopy(CFAllocatorRef allocator, CFIndex capacity, CFDataRef theData);
extern CFIndex         CFDataGetLength(CFDataRef theData);
extern const UInt8 *   CFDataGetBytePtr(CFDataRef theData);
extern void            CFDataGetBytes(CFDataRef theData, CFRange range, UInt8 *buffer);
extern UInt8 *         CFDataGetMutableBytePtr(CFMutableDataRef theData);
extern void            CFDataSetLength(CFMutableDataRef theData, CFIndex length);
extern void            CFDataAppendBytes(CFMutableDataRef theData, const UInt8 *bytes, CFIndex length);
extern void            CFDataReplaceBytes(CFMutableDataRef theData, CFRange range,
                           const UInt8 *newBytes, CFIndex newLength);
extern void            CFDataDeleteBytes(CFMutableDataRef theData, CFRange range);
extern void            CFDataIncreaseLength(CFMutableDataRef theData, CFIndex extraLength);

/* ============================================================================
 * Section 21: CFString Functions
 * ============================================================================ */

extern CFTypeID       CFStringGetTypeID(void);

/* --- Creation --- */

extern CFStringRef        CFStringCreateWithCString(CFAllocatorRef alloc, const char *cStr, CFStringEncoding encoding);
extern CFStringRef        CFStringCreateWithBytes(CFAllocatorRef alloc, const UInt8 *bytes,
                              CFIndex numBytes, CFStringEncoding encoding, Boolean isExternalRepresentation);
extern CFStringRef        CFStringCreateWithCharacters(CFAllocatorRef alloc, const UniChar *chars, CFIndex numChars);
extern CFStringRef        CFStringCreateCopy(CFAllocatorRef alloc, CFStringRef theString);
extern CFStringRef        CFStringCreateWithSubstring(CFAllocatorRef alloc, CFStringRef str, CFRange range);
extern CFMutableStringRef CFStringCreateMutable(CFAllocatorRef alloc, CFIndex maxLength);
extern CFMutableStringRef CFStringCreateMutableCopy(CFAllocatorRef alloc, CFIndex maxLength, CFStringRef theString);

/* --- Accessors --- */

extern CFIndex        CFStringGetLength(CFStringRef theString);
extern UniChar        CFStringGetCharacterAtIndex(CFStringRef theString, CFIndex idx);
extern void           CFStringGetCharacters(CFStringRef theString, CFRange range, UniChar *buffer);
extern const char *   CFStringGetCStringPtr(CFStringRef theString, CFStringEncoding encoding);
extern Boolean        CFStringGetCString(CFStringRef theString, char *buffer, CFIndex bufferSize, CFStringEncoding encoding);
extern const UniChar *CFStringGetCharactersPtr(CFStringRef theString);
extern CFIndex        CFStringGetBytes(CFStringRef theString, CFRange range,
                          CFStringEncoding encoding, UInt8 lossByte, Boolean isExternalRepresentation,
                          UInt8 *buffer, CFIndex maxBufLen, CFIndex *usedBufLen);

/* --- Comparison --- */

extern CFComparisonResult CFStringCompare(CFStringRef s1, CFStringRef s2, CFStringCompareFlags compareOptions);
extern CFComparisonResult CFStringCompareWithOptions(CFStringRef s1, CFStringRef s2,
                              CFRange rangeToCompare, CFStringCompareFlags compareOptions);
extern Boolean  CFStringHasPrefix(CFStringRef theString, CFStringRef prefix);
extern Boolean  CFStringHasSuffix(CFStringRef theString, CFStringRef suffix);
extern CFRange  CFStringFind(CFStringRef theString, CFStringRef stringToFind, CFStringCompareFlags compareOptions);
extern Boolean  CFStringFindWithOptions(CFStringRef theString, CFStringRef stringToFind,
                    CFRange rangeToSearch, CFStringCompareFlags searchOptions, CFRange *result);

/* --- Mutation --- */

extern void CFStringAppend(CFMutableStringRef theString, CFStringRef appendedString);
extern void CFStringAppendCString(CFMutableStringRef theString, const char *cStr, CFStringEncoding encoding);
extern void CFStringAppendCharacters(CFMutableStringRef theString, const UniChar *chars, CFIndex numChars);
extern void CFStringInsert(CFMutableStringRef str, CFIndex idx, CFStringRef insertedStr);
extern void CFStringDelete(CFMutableStringRef theString, CFRange range);
extern void CFStringReplace(CFMutableStringRef theString, CFRange range, CFStringRef replacement);
extern void CFStringReplaceAll(CFMutableStringRef theString, CFStringRef replacement);
extern void CFStringTrimWhitespace(CFMutableStringRef theString);
extern void CFStringLowercase(CFMutableStringRef theString, CFTypeRef locale);
extern void CFStringUppercase(CFMutableStringRef theString, CFTypeRef locale);
extern void CFStringCapitalize(CFMutableStringRef theString, CFTypeRef locale);

/* --- Encoding utilities --- */

extern CFStringEncoding CFStringGetSystemEncoding(void);
extern CFStringEncoding CFStringGetFastestEncoding(CFStringRef theString);
extern CFStringEncoding CFStringGetSmallestEncoding(CFStringRef theString);
extern Boolean          CFStringIsEncodingAvailable(CFStringEncoding encoding);
extern CFIndex          CFStringGetMaximumSizeForEncoding(CFIndex length, CFStringEncoding encoding);
extern CFIndex          CFStringGetMaximumSizeOfFileSystemRepresentation(CFStringRef string);
extern Boolean          CFStringGetFileSystemRepresentation(CFStringRef string, char *buffer, CFIndex maxBufLen);
extern CFStringRef      CFStringCreateWithFileSystemRepresentation(CFAllocatorRef alloc, const char *buffer);

/* --- Numeric parsing --- */

extern SInt32 CFStringGetIntValue(CFStringRef str);
extern double CFStringGetDoubleValue(CFStringRef str);

/* --- Format strings --- */

extern CFStringRef CFStringCreateWithFormat(CFAllocatorRef alloc, CFDictionaryRef formatOptions,
                       CFStringRef format, ...);
extern CFStringRef CFStringCreateWithFormatAndArguments(CFAllocatorRef alloc,
                       CFDictionaryRef formatOptions, CFStringRef format, va_list arguments);
extern void        CFStringAppendFormat(CFMutableStringRef theString, CFDictionaryRef formatOptions,
                       CFStringRef format, ...);
extern void        CFStringAppendFormatAndArguments(CFMutableStringRef theString,
                       CFDictionaryRef formatOptions, CFStringRef format, va_list arguments);

/* --- Join / Split --- */

extern CFStringRef CFStringCreateByCombiningStrings(CFAllocatorRef alloc,
                       CFArrayRef theArray, CFStringRef separatorString);
extern CFArrayRef  CFStringCreateArrayBySeparatingStrings(CFAllocatorRef alloc,
                       CFStringRef theString, CFStringRef separatorString);

/* --- CFSTR() macro --- */

extern CFStringRef __CFStringMakeConstantString(const char *cStr);

#define CFSTR(s) __CFStringMakeConstantString(s)

/* ============================================================================
 * Section 22: CFArray Functions
 * ============================================================================ */

extern CFTypeID         CFArrayGetTypeID(void);
extern CFArrayRef       CFArrayCreate(CFAllocatorRef allocator, const void **values,
                            CFIndex numValues, const CFArrayCallBacks *callBacks);
extern CFArrayRef       CFArrayCreateCopy(CFAllocatorRef allocator, CFArrayRef theArray);
extern CFMutableArrayRef CFArrayCreateMutable(CFAllocatorRef allocator, CFIndex capacity,
                            const CFArrayCallBacks *callBacks);
extern CFMutableArrayRef CFArrayCreateMutableCopy(CFAllocatorRef allocator, CFIndex capacity, CFArrayRef theArray);

extern CFIndex      CFArrayGetCount(CFArrayRef theArray);
extern const void * CFArrayGetValueAtIndex(CFArrayRef theArray, CFIndex idx);
extern void         CFArrayGetValues(CFArrayRef theArray, CFRange range, const void **values);
extern Boolean      CFArrayContainsValue(CFArrayRef theArray, CFRange range, const void *value);
extern CFIndex      CFArrayGetFirstIndexOfValue(CFArrayRef theArray, CFRange range, const void *value);
extern CFIndex      CFArrayGetLastIndexOfValue(CFArrayRef theArray, CFRange range, const void *value);
extern CFIndex      CFArrayGetCountOfValue(CFArrayRef theArray, CFRange range, const void *value);
extern void         CFArrayApplyFunction(CFArrayRef theArray, CFRange range,
                        CFArrayApplierFunction applier, void *context);

extern void CFArrayAppendValue(CFMutableArrayRef theArray, const void *value);
extern void CFArrayInsertValueAtIndex(CFMutableArrayRef theArray, CFIndex idx, const void *value);
extern void CFArraySetValueAtIndex(CFMutableArrayRef theArray, CFIndex idx, const void *value);
extern void CFArrayRemoveValueAtIndex(CFMutableArrayRef theArray, CFIndex idx);
extern void CFArrayRemoveAllValues(CFMutableArrayRef theArray);
extern void CFArrayReplaceValues(CFMutableArrayRef theArray, CFRange range,
                const void **newValues, CFIndex newCount);
extern void CFArrayExchangeValuesAtIndices(CFMutableArrayRef theArray, CFIndex idx1, CFIndex idx2);
extern void CFArraySortValues(CFMutableArrayRef theArray, CFRange range,
                CFComparatorFunction comparator, void *context);
extern void CFArrayAppendArray(CFMutableArrayRef theArray, CFArrayRef otherArray, CFRange otherRange);
extern CFIndex CFArrayBSearchValues(CFArrayRef theArray, CFRange range, const void *value,
                CFComparatorFunction comparator, void *context);

/* ============================================================================
 * Section 23: CFDictionary Functions
 * ============================================================================ */

extern CFTypeID            CFDictionaryGetTypeID(void);
extern CFDictionaryRef     CFDictionaryCreate(CFAllocatorRef allocator,
                               const void **keys, const void **values, CFIndex numValues,
                               const CFDictionaryKeyCallBacks *keyCallBacks,
                               const CFDictionaryValueCallBacks *valueCallBacks);
extern CFDictionaryRef     CFDictionaryCreateCopy(CFAllocatorRef allocator, CFDictionaryRef theDict);
extern CFMutableDictionaryRef CFDictionaryCreateMutable(CFAllocatorRef allocator, CFIndex capacity,
                               const CFDictionaryKeyCallBacks *keyCallBacks,
                               const CFDictionaryValueCallBacks *valueCallBacks);
extern CFMutableDictionaryRef CFDictionaryCreateMutableCopy(CFAllocatorRef allocator,
                               CFIndex capacity, CFDictionaryRef theDict);

extern CFIndex      CFDictionaryGetCount(CFDictionaryRef theDict);
extern const void * CFDictionaryGetValue(CFDictionaryRef theDict, const void *key);
extern Boolean      CFDictionaryGetValueIfPresent(CFDictionaryRef theDict, const void *key, const void **value);
extern Boolean      CFDictionaryContainsKey(CFDictionaryRef theDict, const void *key);
extern Boolean      CFDictionaryContainsValue(CFDictionaryRef theDict, const void *value);
extern void         CFDictionaryGetKeysAndValues(CFDictionaryRef theDict, const void **keys, const void **values);
extern void         CFDictionaryApplyFunction(CFDictionaryRef theDict,
                        CFDictionaryApplierFunction applier, void *context);

extern void CFDictionarySetValue(CFMutableDictionaryRef theDict, const void *key, const void *value);
extern void CFDictionaryAddValue(CFMutableDictionaryRef theDict, const void *key, const void *value);
extern void CFDictionaryReplaceValue(CFMutableDictionaryRef theDict, const void *key, const void *value);
extern void CFDictionaryRemoveValue(CFMutableDictionaryRef theDict, const void *key);
extern void CFDictionaryRemoveAllValues(CFMutableDictionaryRef theDict);

/* ============================================================================
 * Section 24: CFSet Functions
 * ============================================================================ */

extern CFTypeID       CFSetGetTypeID(void);
extern CFSetRef       CFSetCreate(CFAllocatorRef allocator, const void **values, CFIndex numValues,
                          const CFSetCallBacks *callBacks);
extern CFSetRef       CFSetCreateCopy(CFAllocatorRef allocator, CFSetRef theSet);
extern CFMutableSetRef CFSetCreateMutable(CFAllocatorRef allocator, CFIndex capacity,
                          const CFSetCallBacks *callBacks);
extern CFMutableSetRef CFSetCreateMutableCopy(CFAllocatorRef allocator, CFIndex capacity, CFSetRef theSet);

extern CFIndex      CFSetGetCount(CFSetRef theSet);
extern const void * CFSetGetValue(CFSetRef theSet, const void *value);
extern Boolean      CFSetGetValueIfPresent(CFSetRef theSet, const void *candidate, const void **value);
extern Boolean      CFSetContainsValue(CFSetRef theSet, const void *value);
extern void         CFSetGetValues(CFSetRef theSet, const void **values);
extern void         CFSetApplyFunction(CFSetRef theSet, CFSetApplierFunction applier, void *context);

extern void CFSetSetValue(CFMutableSetRef theSet, const void *value);
extern void CFSetAddValue(CFMutableSetRef theSet, const void *value);
extern void CFSetReplaceValue(CFMutableSetRef theSet, const void *value);
extern void CFSetRemoveValue(CFMutableSetRef theSet, const void *value);
extern void CFSetRemoveAllValues(CFMutableSetRef theSet);

/* ============================================================================
 * Section 25: CFDate Functions
 * ============================================================================ */

extern CFTypeID          CFDateGetTypeID(void);
extern CFDateRef         CFDateCreate(CFAllocatorRef allocator, CFAbsoluteTime at);
extern CFAbsoluteTime    CFDateGetAbsoluteTime(CFDateRef theDate);
extern CFComparisonResult CFDateCompare(CFDateRef theDate, CFDateRef otherDate, void *context);

extern CFAbsoluteTime    CFAbsoluteTimeGetCurrent(void);

/* ============================================================================
 * Section 26: CFAttributedString Functions
 * ============================================================================ */

extern CFTypeID             CFAttributedStringGetTypeID(void);
extern CFAttributedStringRef CFAttributedStringCreate(CFAllocatorRef alloc, CFStringRef str, CFDictionaryRef attributes);
extern CFIndex              CFAttributedStringGetLength(CFAttributedStringRef aStr);
extern CFStringRef          CFAttributedStringGetString(CFAttributedStringRef aStr);
extern CFDictionaryRef      CFAttributedStringGetAttributes(CFAttributedStringRef aStr, CFIndex loc, CFRange *effectiveRange);
extern CFTypeRef            CFAttributedStringGetAttribute(CFAttributedStringRef aStr, CFIndex loc,
                                CFStringRef attrName, CFRange *effectiveRange);

/* ============================================================================
 * Section 27: CFRunLoop Functions
 * ============================================================================ */

/* --- Run loop lifecycle --- */

extern CFTypeID      CFRunLoopGetTypeID(void);
extern CFRunLoopRef  CFRunLoopGetCurrent(void);
extern CFRunLoopRef  CFRunLoopGetMain(void);
extern void          CFRunLoopRun(void);
extern SInt32        CFRunLoopRunInMode(CFRunLoopMode modeName, CFTimeInterval seconds,
                         Boolean returnAfterSourceHandled);
extern void          CFRunLoopStop(CFRunLoopRef rl);
extern void          CFRunLoopWakeUp(CFRunLoopRef rl);
extern Boolean       CFRunLoopIsWaiting(CFRunLoopRef rl);
extern CFStringRef   CFRunLoopCopyCurrentMode(CFRunLoopRef rl);

/* --- Source management --- */

extern CFRunLoopSourceRef CFRunLoopSourceCreate(CFAllocatorRef allocator, CFIndex order,
                              CFRunLoopSourceContext *context);
extern CFTypeID  CFRunLoopSourceGetTypeID(void);
extern void      CFRunLoopSourceInvalidate(CFRunLoopSourceRef source);
extern Boolean   CFRunLoopSourceIsValid(CFRunLoopSourceRef source);
extern void      CFRunLoopSourceSignal(CFRunLoopSourceRef source);
extern void      CFRunLoopSourceGetContext(CFRunLoopSourceRef source, CFRunLoopSourceContext *context);

extern void      CFRunLoopAddSource(CFRunLoopRef rl, CFRunLoopSourceRef source, CFRunLoopMode modeName);
extern void      CFRunLoopRemoveSource(CFRunLoopRef rl, CFRunLoopSourceRef source, CFRunLoopMode modeName);
extern Boolean   CFRunLoopContainsSource(CFRunLoopRef rl, CFRunLoopSourceRef source, CFRunLoopMode modeName);

/* --- Timer management --- */

extern CFRunLoopTimerRef CFRunLoopTimerCreate(CFAllocatorRef allocator, CFAbsoluteTime fireDate,
                             CFTimeInterval interval, CFOptionFlags flags, CFIndex order,
                             CFRunLoopTimerCallBack callout);
extern CFTypeID        CFRunLoopTimerGetTypeID(void);
extern void            CFRunLoopTimerInvalidate(CFRunLoopTimerRef timer);
extern Boolean         CFRunLoopTimerIsValid(CFRunLoopTimerRef timer);
extern CFAbsoluteTime  CFRunLoopTimerGetNextFireDate(CFRunLoopTimerRef timer);
extern void            CFRunLoopTimerSetNextFireDate(CFRunLoopTimerRef timer, CFAbsoluteTime fireDate);
extern CFTimeInterval  CFRunLoopTimerGetInterval(CFRunLoopTimerRef timer);
extern void            CFRunLoopTimerGetContext(CFRunLoopTimerRef timer, CFRunLoopTimerContext *context);
extern Boolean         CFRunLoopTimerDoesRepeat(CFRunLoopTimerRef timer);

extern void    CFRunLoopAddTimer(CFRunLoopRef rl, CFRunLoopTimerRef timer, CFRunLoopMode modeName);
extern void    CFRunLoopRemoveTimer(CFRunLoopRef rl, CFRunLoopTimerRef timer, CFRunLoopMode modeName);
extern Boolean CFRunLoopContainsTimer(CFRunLoopRef rl, CFRunLoopTimerRef timer, CFRunLoopMode modeName);

/* --- Observer management --- */

extern CFRunLoopObserverRef CFRunLoopObserverCreate(CFAllocatorRef allocator, CFRunLoopActivity activities,
                                Boolean repeats, CFIndex order, CFRunLoopObserverCallBack callout,
                                CFRunLoopObserverContext *context);
extern CFTypeID         CFRunLoopObserverGetTypeID(void);
extern void             CFRunLoopObserverInvalidate(CFRunLoopObserverRef observer);
extern Boolean          CFRunLoopObserverIsValid(CFRunLoopObserverRef observer);
extern CFRunLoopActivity CFRunLoopObserverGetActivities(CFRunLoopObserverRef observer);
extern Boolean          CFRunLoopObserverDoesRepeat(CFRunLoopObserverRef observer);
extern void             CFRunLoopObserverGetContext(CFRunLoopObserverRef observer, CFRunLoopObserverContext *context);

extern void    CFRunLoopAddObserver(CFRunLoopRef rl, CFRunLoopObserverRef observer, CFRunLoopMode modeName);
extern void    CFRunLoopRemoveObserver(CFRunLoopRef rl, CFRunLoopObserverRef observer, CFRunLoopMode modeName);
extern Boolean CFRunLoopContainsObserver(CFRunLoopRef rl, CFRunLoopObserverRef observer, CFRunLoopMode modeName);

#ifdef __cplusplus
}
#endif
