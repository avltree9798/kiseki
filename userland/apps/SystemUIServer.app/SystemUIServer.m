/*
 * Kiseki OS - SystemUIServer.app
 *
 * The right-side menu bar extras process, matching macOS architecture:
 *   - Displays a clock in the top-right area of the menu bar
 *   - Connects to WindowServer by creating a small borderless window
 *     positioned at the top-right of the screen
 *   - Runs as a separate AppKit process launched by loginwindow
 *
 * On macOS, SystemUIServer manages the right side of the menu bar
 * (clock, Wi-Fi, battery, volume, Spotlight, Siri, etc.).  Our
 * SystemUIServer creates a single borderless window at (1120, 0)
 * with size 160x22 that sits in the menu bar area and draws a
 * clock display.
 *
 * The clock updates every minute via a custom run loop that polls
 * CFAbsoluteTimeGetCurrent() between WindowServer event checks.
 *
 * Compiled with COMDAT-stripping pipeline (same as AppKit).
 */

#import <AppKit/AppKit.h>

/* ============================================================================
 * ObjC runtime functions for dynamic class creation
 * ============================================================================ */

extern Class  objc_allocateClassPair(Class superclass, const char *name, size_t extraBytes);
extern void   objc_registerClassPair(Class cls);
extern BOOL   class_addMethod(Class cls, SEL name, IMP imp, const char *types);
extern void  *objc_autoreleasePoolPush(void);
extern void   objc_autoreleasePoolPop(void *pool);

/* C library extras not in framework headers */
extern int    fprintf(void *stream, const char *fmt, ...);
extern void **__stderrp;
#define stderr (*__stderrp)

/* Screen dimensions (matching WindowServer) */
#define SCREEN_WIDTH    1280
#define SCREEN_HEIGHT   800
#define MENUBAR_HEIGHT  22

/* Clock window: positioned at top-right of menu bar */
#define CLOCK_X         1120
#define CLOCK_Y         0
#define CLOCK_WIDTH     160
#define CLOCK_HEIGHT    MENUBAR_HEIGHT

/* ============================================================================
 * ClockView — Custom NSView subclass for the clock display
 * ============================================================================ */

/*
 * Compute static clock string.  We attempt CFAbsoluteTimeGetCurrent() to
 * derive hours:minutes, but since our kernel may not have real time yet
 * we fall back to "12:00" if the result looks unreasonable.
 *
 * CFAbsoluteTime is seconds since 2001-01-01 00:00:00 UTC.
 */
static void _clockGetTimeString(char *buf, size_t buflen) {
    (void)buflen;

    /* Try to derive HH:MM from CFAbsoluteTime */
    CFAbsoluteTime now = CFAbsoluteTimeGetCurrent();

    /* Sanity check: if now is zero or negative, time is not available */
    if (now <= 0.0) {
        buf[0] = '1'; buf[1] = '2'; buf[2] = ':';
        buf[3] = '0'; buf[4] = '0'; buf[5] = '\0';
        return;
    }

    /* Convert to seconds-of-day (UTC).  Good enough for a clock display. */
    /* seconds since midnight = now mod 86400 */
    double day_seconds = now - (double)((long)(now / 86400.0)) * 86400.0;
    if (day_seconds < 0.0) day_seconds += 86400.0;

    int total_minutes = (int)(day_seconds / 60.0);
    int hours   = (total_minutes / 60) % 24;
    int minutes = total_minutes % 60;

    /* Format as HH:MM */
    buf[0] = (char)('0' + (hours / 10));
    buf[1] = (char)('0' + (hours % 10));
    buf[2] = ':';
    buf[3] = (char)('0' + (minutes / 10));
    buf[4] = (char)('0' + (minutes % 10));
    buf[5] = '\0';
}

/*
 * _ClockDrawRect — drawRect: implementation for ClockView
 */
static id _ClockDrawRect(id self, SEL _cmd, CGRect dirtyRect) {
    (void)self; (void)_cmd; (void)dirtyRect;

    /* Get the backing CGContext from NSGraphicsContext */
    NSGraphicsContext *gctx = [NSGraphicsContext currentContext];
    if (!gctx) return nil;

    CGContextRef ctx = [gctx CGContext];
    if (!ctx) return nil;

    CGRect frame = CGRectMake(0, 0, CLOCK_WIDTH, CLOCK_HEIGHT);

    /*
     * Draw menu bar background matching WindowServer's menu bar colour.
     * WindowServer renders the menu bar as (0.96, 0.96, 0.96) — we match
     * that exactly so this window blends seamlessly into the menu bar.
     */
    CGContextSetRGBFillColor(ctx, 0.96, 0.96, 0.96, 1.0);
    CGContextFillRect(ctx, frame);

    /* Get current time string */
    char timebuf[8];
    _clockGetTimeString(timebuf, sizeof(timebuf));
    size_t timelen = 5;  /* "HH:MM" is always 5 chars */

    /*
     * Draw clock text — dark text on light menu bar, matching macOS.
     * macOS uses black text in the menu bar for the clock.
     * Each character is roughly 8px wide in the system bitmap font.
     */
    CGContextSetRGBFillColor(ctx, 0.0, 0.0, 0.0, 1.0);

    CGFloat textWidth = (CGFloat)(timelen * 8);
    CGFloat textX = (CLOCK_WIDTH - textWidth) / 2.0;
    CGFloat textY = (CLOCK_HEIGHT - 12.0) / 2.0;  /* approx vertical centre */

    CGContextShowTextAtPoint(ctx, textX, textY, timebuf, timelen);

    return nil;
}

/* Global reference to clock window and view for periodic redraw */
static NSWindow *g_clockWindow = nil;
static NSView   *g_clockView = nil;

/* ============================================================================
 * SystemUIServerDelegate — applicationDidFinishLaunching:
 * ============================================================================ */

static id _sysUIAppDidFinishLaunching(id self, SEL _cmd, id notification) {
    (void)self; (void)_cmd; (void)notification;

    /* --- Create clock window --- */
    NSWindow *clockWindow = [[NSWindow alloc]
        initWithContentRect:CGRectMake(CLOCK_X, CLOCK_Y, CLOCK_WIDTH, CLOCK_HEIGHT)
                  styleMask:NSWindowStyleMaskBorderless
                    backing:NSBackingStoreBuffered
                      defer:NO];

    [clockWindow setTitle:(id)CFSTR("SystemUIServer")];

    /* Create ClockView class dynamically */
    Class ClockView = objc_allocateClassPair([NSView class], "ClockView", 0);
    class_addMethod(ClockView, @selector(drawRect:),
                    (IMP)_ClockDrawRect, "v@:{CGRect=dddd}");
    objc_registerClassPair(ClockView);

    NSView *clockView = [[ClockView alloc]
        initWithFrame:CGRectMake(0, 0, CLOCK_WIDTH, CLOCK_HEIGHT)];

    [clockWindow setContentView:clockView];
    [clockWindow makeKeyAndOrderFront:nil];

    /* Store global references for periodic clock updates */
    g_clockWindow = clockWindow;
    g_clockView = clockView;

    /* --- Set up menu --- */
    NSMenu *menu = [[NSMenu alloc] initWithTitle:(id)CFSTR("SystemUIServer")];
    [NSApp setMainMenu:menu];

    fprintf(stderr, "[SystemUIServer] Clock window created at (%d, %d) size %dx%d\n",
            CLOCK_X, CLOCK_Y, CLOCK_WIDTH, CLOCK_HEIGHT);
    return nil;
}

/* Track last minute drawn so we only redraw when the minute changes */
static int g_lastMinuteDrawn = -1;

/*
 * _clockNeedsUpdate — Check if the displayed minute has changed.
 *
 * Returns YES if the clock needs redrawing.
 */
static BOOL _clockNeedsUpdate(void) {
    CFAbsoluteTime now = CFAbsoluteTimeGetCurrent();
    if (now <= 0.0) return NO;

    double day_seconds = now - (double)((long)(now / 86400.0)) * 86400.0;
    if (day_seconds < 0.0) day_seconds += 86400.0;

    int total_minutes = (int)(day_seconds / 60.0);
    int current_minute = total_minutes % (24 * 60);

    if (current_minute != g_lastMinuteDrawn) {
        g_lastMinuteDrawn = current_minute;
        return YES;
    }
    return NO;
}

/* ============================================================================
 * main — Entry point
 *
 * Uses a custom run loop (like Terminal.app) to periodically update
 * the clock display.  On macOS, SystemUIServer uses NSTimer or
 * CFRunLoopTimer for this; we poll on each event loop iteration
 * since our AppKit doesn't have NSTimer support yet.
 * ============================================================================ */

int main(int argc, const char *argv[]) {
    (void)argc; (void)argv;
    void *pool = objc_autoreleasePoolPush();

    /* Create shared application */
    [NSApplication sharedApplication];

    /* Create delegate class dynamically */
    Class SystemUIServerDelegate = objc_allocateClassPair(
        [NSObject class], "SystemUIServerDelegate", 0);
    class_addMethod(SystemUIServerDelegate,
                    @selector(applicationDidFinishLaunching:),
                    (IMP)_sysUIAppDidFinishLaunching, "v@:@");
    objc_registerClassPair(SystemUIServerDelegate);

    /* Create delegate instance and set on NSApp */
    id delegate = [SystemUIServerDelegate new];
    [NSApp setDelegate:delegate];

    /*
     * Custom run loop with clock update polling.
     *
     * On macOS, SystemUIServer uses NSTimer / CFRunLoopTimer to
     * schedule clock updates every 60 seconds.  Since our AppKit
     * doesn't have NSTimer yet, we check on each event loop
     * iteration whether the minute has changed.
     */
    [NSApp finishLaunching];

    for (;;) {
        /* Poll WindowServer for events */
        NSEvent *event = [NSApp nextEventMatchingMask:(NSUInteger)0xFFFFFFFF
                                            untilDate:nil
                                               inMode:(id)CFSTR("kCFRunLoopDefaultMode")
                                              dequeue:YES];

        if (event) {
            [NSApp sendEvent:event];
        }

        /* Check if clock needs updating (minute changed) */
        if (_clockNeedsUpdate() && g_clockView) {
            [g_clockView setNeedsDisplay:YES];
        }

        /* Display dirty windows */
        if (g_clockWindow) {
            [g_clockWindow displayIfNeeded];
        }
    }

    objc_autoreleasePoolPop(pool);
    return 0;
}
