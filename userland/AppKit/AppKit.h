#pragma once

#include <Foundation/Foundation.h>
#include <CoreGraphics/CoreGraphics.h>
#include <CoreText/CoreText.h>

/* -------------------------------------------------------------------------- */
/*  Enumerations                                                              */
/* -------------------------------------------------------------------------- */

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

typedef enum {
    NSEventModifierFlagCapsLock   = 1 << 16,
    NSEventModifierFlagShift      = 1 << 17,
    NSEventModifierFlagControl    = 1 << 18,
    NSEventModifierFlagOption     = 1 << 19,
    NSEventModifierFlagCommand    = 1 << 20,
} NSEventModifierFlags;

typedef enum {
    NSWindowStyleMaskBorderless             = 0,
    NSWindowStyleMaskTitled                 = 1 << 0,
    NSWindowStyleMaskClosable               = 1 << 1,
    NSWindowStyleMaskMiniaturizable         = 1 << 2,
    NSWindowStyleMaskResizable              = 1 << 3,
    NSWindowStyleMaskFullScreen             = 1 << 14,
} NSWindowStyleMask;

typedef enum {
    NSBackingStoreRetained    = 0,
    NSBackingStoreNonretained = 1,
    NSBackingStoreBuffered    = 2,
} NSBackingStoreType;

typedef enum {
    NSApplicationActivationPolicyRegular    = 0,
    NSApplicationActivationPolicyAccessory  = 1,
    NSApplicationActivationPolicyProhibited = 2,
} NSApplicationActivationPolicy;

typedef enum {
    NSButtonTypeMomentaryLight     = 0,
    NSButtonTypeMomentaryPushIn    = 7,
    NSButtonTypeToggle             = 2,
    NSButtonTypeSwitch             = 3,
    NSButtonTypeRadio              = 4,
    NSButtonTypeOnOff              = 6,
} NSButtonType;

typedef enum {
    NSBezelStyleRounded            = 1,
    NSBezelStyleRegularSquare      = 2,
    NSBezelStyleSmallSquare        = 6,
    NSBezelStyleInline             = 15,
} NSBezelStyle;

/* -------------------------------------------------------------------------- */
/*  NSGraphicsContext                                                          */
/* -------------------------------------------------------------------------- */

@interface NSGraphicsContext : NSObject

+ (id)graphicsContextWithCGContext:(CGContextRef)cgContext flipped:(BOOL)flipped;
+ (id)currentContext;
+ (void)setCurrentContext:(id)context;
+ (void)saveGraphicsState;
+ (void)restoreGraphicsState;

- (CGContextRef)CGContext;
- (BOOL)isFlipped;
- (void)flushGraphics;

@end

/* -------------------------------------------------------------------------- */
/*  NSColor                                                                   */
/* -------------------------------------------------------------------------- */

@interface NSColor : NSObject

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

/* -------------------------------------------------------------------------- */
/*  NSFont                                                                    */
/* -------------------------------------------------------------------------- */

@interface NSFont : NSObject

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

/* -------------------------------------------------------------------------- */
/*  NSEvent                                                                   */
/* -------------------------------------------------------------------------- */

@interface NSEvent : NSObject

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

/* -------------------------------------------------------------------------- */
/*  NSResponder                                                               */
/* -------------------------------------------------------------------------- */

@interface NSResponder : NSObject

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

/* -------------------------------------------------------------------------- */
/*  NSView                                                                    */
/* -------------------------------------------------------------------------- */

@interface NSView : NSResponder

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

/* -------------------------------------------------------------------------- */
/*  NSWindow                                                                  */
/* -------------------------------------------------------------------------- */

@interface NSWindow : NSResponder

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

@end

/* -------------------------------------------------------------------------- */
/*  NSMenuItem                                                                */
/* -------------------------------------------------------------------------- */

@interface NSMenuItem : NSObject

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

/* -------------------------------------------------------------------------- */
/*  NSMenu                                                                    */
/* -------------------------------------------------------------------------- */

@interface NSMenu : NSObject

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

@end

/* -------------------------------------------------------------------------- */
/*  NSApplication                                                             */
/* -------------------------------------------------------------------------- */

@interface NSApplication : NSResponder

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

@end

/* -------------------------------------------------------------------------- */
/*  NSCell                                                                    */
/* -------------------------------------------------------------------------- */

@interface NSCell : NSObject

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

/* -------------------------------------------------------------------------- */
/*  NSControl                                                                 */
/* -------------------------------------------------------------------------- */

@interface NSControl : NSView

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

/* -------------------------------------------------------------------------- */
/*  NSTextField                                                               */
/* -------------------------------------------------------------------------- */

@interface NSTextField : NSControl

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

/* -------------------------------------------------------------------------- */
/*  NSButton                                                                  */
/* -------------------------------------------------------------------------- */

@interface NSButton : NSControl

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

/* -------------------------------------------------------------------------- */
/*  C Globals & Functions                                                     */
/* -------------------------------------------------------------------------- */

#ifdef __cplusplus
extern "C" {
#endif

extern id NSApp;

extern int NSApplicationMain(int argc, const char *argv[]);

#ifdef __cplusplus
}
#endif
