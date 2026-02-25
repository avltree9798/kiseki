#pragma once

/*
 * Foundation.h — Kiseki OS Foundation Framework
 *
 * Public umbrella header.
 * Import with:  #import <Foundation/Foundation.h>
 */

/* ------------------------------------------------------------------ */
/*  Standard C headers                                                */
/* ------------------------------------------------------------------ */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  CoreFoundation                                                    */
/* ------------------------------------------------------------------ */

#include <CoreFoundation/CoreFoundation.h>

/* ------------------------------------------------------------------ */
/*  BOOL / nil                                                        */
/* ------------------------------------------------------------------ */

#ifndef OBJC_BOOL_DEFINED
#define OBJC_BOOL_DEFINED
typedef _Bool BOOL;
#endif
#define YES ((BOOL)1)
#define NO  ((BOOL)0)
#ifndef nil
#define nil ((id)0)
#endif

/* ------------------------------------------------------------------ */
/*  ObjC runtime helpers                                              */
/* ------------------------------------------------------------------ */

typedef id (*IMP)(id, SEL, ...);

/* ------------------------------------------------------------------ */
/*  Scalar types                                                      */
/* ------------------------------------------------------------------ */

typedef signed long         NSInteger;
typedef unsigned long       NSUInteger;
typedef double              NSTimeInterval;
#ifndef _CG_CGFLOAT_DEFINED
#define _CG_CGFLOAT_DEFINED
typedef double              CGFloat;  /* needed if CoreGraphics not imported */
#endif

/* ------------------------------------------------------------------ */
/*  NSRange                                                           */
/* ------------------------------------------------------------------ */

typedef struct _NSRange {
    NSUInteger location;
    NSUInteger length;
} NSRange;

static inline NSRange NSMakeRange(NSUInteger loc, NSUInteger len) {
    NSRange r = { loc, len };
    return r;
}

#define NSNotFound ((NSInteger)0x7fffffffffffffffL)

/* ------------------------------------------------------------------ */
/*  NSComparisonResult                                                */
/* ------------------------------------------------------------------ */

#define NSOrderedAscending  ((NSInteger)-1)
#define NSOrderedSame       ((NSInteger)0)
#define NSOrderedDescending ((NSInteger)1)

/* ================================================================== */
/*  @interface declarations                                           */
/* ================================================================== */

/* ------------------------------------------------------------------ */
/*  NSObject (root class)                                             */
/* ------------------------------------------------------------------ */

__attribute__((objc_root_class))
@interface NSObject {
    Class isa;
}

/* class methods */
+ (id)alloc;
+ (id)new;
+ (id)allocWithZone:(void *)zone;
+ (Class)class;
+ (Class)superclass;
+ (BOOL)instancesRespondToSelector:(SEL)aSelector;
+ (BOOL)conformsToProtocol:(void *)protocol;
+ (NSUInteger)hash;
+ (BOOL)isEqual:(id)object;

/* instance methods */
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

/* ------------------------------------------------------------------ */
/*  NSString                                                          */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/*  NSMutableString                                                   */
/* ------------------------------------------------------------------ */

@interface NSMutableString : NSString

- (void)appendString:(id)aString;
- (void)appendFormat:(id)format, ...;
- (void)setString:(id)aString;

@end

/* ------------------------------------------------------------------ */
/*  NSNumber                                                          */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/*  NSArray                                                           */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/*  NSMutableArray                                                    */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/*  NSDictionary                                                      */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/*  NSMutableDictionary                                               */
/* ------------------------------------------------------------------ */

@interface NSMutableDictionary : NSDictionary

+ (id)dictionary;
+ (id)dictionaryWithCapacity:(NSUInteger)numItems;

- (void)setObject:(id)anObject forKey:(id)aKey;
- (void)removeObjectForKey:(id)aKey;
- (void)removeAllObjects;

@end

/* ------------------------------------------------------------------ */
/*  NSData                                                            */
/* ------------------------------------------------------------------ */

@interface NSData : NSObject

+ (id)data;
+ (id)dataWithBytes:(const void *)bytes length:(NSUInteger)length;

- (NSUInteger)length;
- (const void *)bytes;
- (id)description;

@end

/* ------------------------------------------------------------------ */
/*  NSRunLoop                                                         */
/* ------------------------------------------------------------------ */

@interface NSRunLoop : NSObject

+ (id)currentRunLoop;
+ (id)mainRunLoop;

- (void)run;
- (void)runUntilDate:(id)limitDate;
- (BOOL)runMode:(id)mode beforeDate:(id)limitDate;
- (id)currentMode;
- (void)performSelector:(SEL)aSelector
                 target:(id)target
               argument:(id)arg
                  order:(NSUInteger)order
                  modes:(id)modes;

@end

/* ------------------------------------------------------------------ */
/*  NSAutoreleasePool                                                 */
/* ------------------------------------------------------------------ */

@interface NSAutoreleasePool : NSObject

- (id)init;
- (void)drain;

@end

/* ------------------------------------------------------------------ */
/*  NSNotificationCenter                                              */
/* ------------------------------------------------------------------ */

@interface NSNotificationCenter : NSObject

+ (id)defaultCenter;

- (void)addObserver:(id)observer
           selector:(SEL)aSelector
               name:(id)aName
             object:(id)anObject;
- (void)removeObserver:(id)observer;
- (void)postNotificationName:(id)aName object:(id)anObject;
- (void)postNotificationName:(id)aName object:(id)anObject userInfo:(id)aUserInfo;

@end

/* ------------------------------------------------------------------ */
/*  NSProcessInfo                                                     */
/* ------------------------------------------------------------------ */

@interface NSProcessInfo : NSObject

+ (id)processInfo;

- (id)processName;
- (id)arguments;
- (id)environment;
- (NSUInteger)processorCount;

@end

/* ------------------------------------------------------------------ */
/*  NSThread                                                          */
/* ------------------------------------------------------------------ */

@interface NSThread : NSObject

+ (id)currentThread;
+ (id)mainThread;
+ (BOOL)isMainThread;
+ (void)sleepForTimeInterval:(NSTimeInterval)ti;

@end

/* ------------------------------------------------------------------ */
/*  NSDate                                                            */
/* ------------------------------------------------------------------ */

@interface NSDate : NSObject

+ (id)date;
+ (id)dateWithTimeIntervalSinceNow:(NSTimeInterval)secs;
+ (id)distantFuture;
+ (id)distantPast;

- (NSTimeInterval)timeIntervalSinceNow;
- (NSTimeInterval)timeIntervalSinceReferenceDate;
- (NSTimeInterval)timeIntervalSince1970;

@end

/* ------------------------------------------------------------------ */
/*  NSBundle                                                          */
/* ------------------------------------------------------------------ */

@interface NSBundle : NSObject

+ (id)mainBundle;

- (id)bundlePath;
- (id)bundleIdentifier;
- (id)infoDictionary;
- (id)objectForInfoDictionaryKey:(id)key;

@end

/* ------------------------------------------------------------------ */
/*  NSTimer                                                           */
/* ------------------------------------------------------------------ */

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

/* ================================================================== */
/*  C functions and constants                                         */
/* ================================================================== */

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  NSLog                                                             */
/* ------------------------------------------------------------------ */

extern void NSLog(id format, ...);

/* ------------------------------------------------------------------ */
/*  Notification name constants                                       */
/* ------------------------------------------------------------------ */

extern CFStringRef NSApplicationDidFinishLaunchingNotification;
extern CFStringRef NSApplicationWillTerminateNotification;
extern CFStringRef NSWindowDidBecomeKeyNotification;
extern CFStringRef NSWindowDidResignKeyNotification;

#ifdef __cplusplus
}
#endif
