/*
 * Kiseki OS - Dock.app
 *
 * The Dock process, matching macOS architecture:
 *   - Renders the dock bar along the bottom of the screen
 *   - Renders the desktop wallpaper (solid colour for now)
 *   - Runs as a separate AppKit process launched by loginwindow
 *
 * On macOS, the Dock renders the desktop background (via
 * CGSSetDesktopBackground/CGSSetDesktopImage) and the dock bar.
 * Our Dock creates two windows:
 *   1. Desktop window — fullscreen, sent to back, fills with wallpaper
 *   2. Dock bar window — bottom strip, always on top
 *
 * The dock bar draws a translucent grey strip with application icons
 * (represented as simple coloured squares for now).
 *
 * Compiled with COMDAT-stripping pipeline (same as AppKit).
 */

#import <AppKit/AppKit.h>

/* ============================================================================
 * ObjC runtime functions for dynamic class creation
 *
 * These are not declared in our framework headers because the apps'
 * framework headers are for consumer use, not runtime internals.
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
#define DOCK_HEIGHT     54
#define DOCK_ICON_SIZE  40
#define DOCK_ICON_PAD   8
#define DOCK_Y          (SCREEN_HEIGHT - DOCK_HEIGHT)

/* ============================================================================
 * DockView — Custom NSView subclass for the dock bar
 * ============================================================================ */

/* We create DockView dynamically using the ObjC runtime since we can't
 * use @interface/@implementation without the full class hierarchy being
 * in this compilation unit. Instead, we use the C runtime API. */

/* Dock icon entries */
typedef struct {
    const char *label;
    CGFloat r, g, b;    /* Icon colour */
} DockIcon;

static DockIcon dock_icons[] = {
    { "Finder",   0.25, 0.55, 0.95 },  /* Blue */
    { "Terminal",  0.15, 0.15, 0.15 },  /* Dark grey */
    { "System",   0.70, 0.70, 0.70 },  /* Light grey */
};
static int dock_icon_count = 3;

/*
 * _DockDrawRect — drawRect: implementation for DockView
 */
static id _DockDrawRect(id self, SEL _cmd, CGRect dirtyRect) {
    (void)_cmd; (void)dirtyRect;

    /* Get the backing CGContext from NSGraphicsContext */
    NSGraphicsContext *gctx = [NSGraphicsContext currentContext];
    if (!gctx) return nil;

    CGContextRef ctx = [gctx CGContext];
    if (!ctx) return nil;

    /* For the dock view, frame is 0,0 to SCREEN_WIDTH x DOCK_HEIGHT */
    CGRect frame = CGRectMake(0, 0, SCREEN_WIDTH, DOCK_HEIGHT);

    /* Draw translucent dark background */
    CGContextSetRGBFillColor(ctx, 0.15, 0.15, 0.15, 0.85);
    CGContextFillRect(ctx, frame);

    /* Draw a subtle top separator line */
    CGContextSetRGBFillColor(ctx, 0.3, 0.3, 0.3, 1.0);
    CGContextFillRect(ctx, CGRectMake(0, 0, SCREEN_WIDTH, 1));

    /* Draw dock icons centred */
    CGFloat totalWidth = (CGFloat)dock_icon_count * (DOCK_ICON_SIZE + DOCK_ICON_PAD) - DOCK_ICON_PAD;
    CGFloat startX = (SCREEN_WIDTH - totalWidth) / 2.0;
    CGFloat iconY = (DOCK_HEIGHT - DOCK_ICON_SIZE) / 2.0;

    for (int i = 0; i < dock_icon_count; i++) {
        CGFloat ix = startX + (CGFloat)i * (DOCK_ICON_SIZE + DOCK_ICON_PAD);
        CGRect iconRect = CGRectMake(ix, iconY, DOCK_ICON_SIZE, DOCK_ICON_SIZE);

        /* Icon background (rounded rectangle approximated as filled rect) */
        CGContextSetRGBFillColor(ctx, dock_icons[i].r, dock_icons[i].g,
                                  dock_icons[i].b, 1.0);
        CGContextFillRect(ctx, iconRect);

        /* Icon border */
        CGContextSetRGBStrokeColor(ctx, 1.0, 1.0, 1.0, 0.3);
        CGContextSetLineWidth(ctx, 1.0);
        CGContextStrokeRect(ctx, iconRect);

        /* Label below icon (first char) — white text */
        CGContextSetRGBFillColor(ctx, 1.0, 1.0, 1.0, 0.9);
        const char *label = dock_icons[i].label;
        size_t llen = strlen(label);
        CGFloat textW = (CGFloat)(llen * 8);
        CGFloat textX = ix + (DOCK_ICON_SIZE - textW) / 2.0;
        if (textX < ix) textX = ix;
        /* Draw text inside the icon square, vertically centred */
        CGFloat textY = iconY + (DOCK_ICON_SIZE - 16.0) / 2.0;
        CGContextShowTextAtPoint(ctx, textX, textY, label, llen > 5 ? 5 : llen);
    }

    return nil;
}

/* ============================================================================
 * DesktopView — Custom NSView for the desktop wallpaper
 * ============================================================================ */

static id _DesktopDrawRect(id self, SEL _cmd, CGRect dirtyRect) {
    (void)_cmd; (void)dirtyRect;

    NSGraphicsContext *gctx = [NSGraphicsContext currentContext];
    if (!gctx) return nil;

    CGContextRef ctx = [gctx CGContext];
    if (!ctx) return nil;

    /* Draw a macOS-style gradient wallpaper (simplified: solid teal-blue) */
    CGContextSetRGBFillColor(ctx, 0.05, 0.25, 0.45, 1.0);
    CGContextFillRect(ctx, CGRectMake(0, 0, SCREEN_WIDTH, SCREEN_HEIGHT));

    /* Draw a subtle gradient effect using horizontal bands */
    for (int y = 0; y < SCREEN_HEIGHT; y += 4) {
        CGFloat t = (CGFloat)y / (CGFloat)SCREEN_HEIGHT;
        CGFloat r = 0.05 + t * 0.10;
        CGFloat g = 0.20 + t * 0.15;
        CGFloat b = 0.40 + t * 0.15;
        CGContextSetRGBFillColor(ctx, r, g, b, 1.0);
        CGContextFillRect(ctx, CGRectMake(0, y, SCREEN_WIDTH, 4));
    }

    return nil;
}

/* ============================================================================
 * DockAppDelegate — applicationDidFinishLaunching:
 * ============================================================================ */

static id _dockAppDidFinishLaunching(id self, SEL _cmd, id notification) {
    (void)_cmd; (void)notification;

    /* --- Create desktop background window --- */
    NSWindow *desktopWindow = [[NSWindow alloc]
        initWithContentRect:CGRectMake(0, 0, SCREEN_WIDTH, SCREEN_HEIGHT)
                  styleMask:NSWindowStyleMaskBorderless
                    backing:NSBackingStoreBuffered
                      defer:NO];

    [desktopWindow setTitle:(id)CFSTR("Desktop")];

    /* Create DesktopView class dynamically */
    Class DesktopView = objc_allocateClassPair([NSView class], "DesktopView", 0);
    class_addMethod(DesktopView, @selector(drawRect:),
                    (IMP)_DesktopDrawRect, "v@:{CGRect=dddd}");
    objc_registerClassPair(DesktopView);

    NSView *desktopView = [[DesktopView alloc]
        initWithFrame:CGRectMake(0, 0, SCREEN_WIDTH, SCREEN_HEIGHT)];

    [desktopWindow setContentView:desktopView];

    /*
     * Order desktop to back — behind all other windows.
     * On macOS, the desktop window uses NSWindowLevelDesktop (kCGDesktopWindowLevel)
     * and orderBack:.  Our WindowServer supports WS_ORDER_BACK.
     */
    [desktopWindow orderBack:nil];

    /* --- Create dock bar window --- */
    NSWindow *dockWindow = [[NSWindow alloc]
        initWithContentRect:CGRectMake(0, DOCK_Y, SCREEN_WIDTH, DOCK_HEIGHT)
                  styleMask:NSWindowStyleMaskBorderless
                    backing:NSBackingStoreBuffered
                      defer:NO];

    [dockWindow setTitle:(id)CFSTR("Dock")];

    /* Create DockView class dynamically */
    Class DockView = objc_allocateClassPair([NSView class], "DockView", 0);
    class_addMethod(DockView, @selector(drawRect:),
                    (IMP)_DockDrawRect, "v@:{CGRect=dddd}");
    objc_registerClassPair(DockView);

    NSView *dockView = [[DockView alloc]
        initWithFrame:CGRectMake(0, 0, SCREEN_WIDTH, DOCK_HEIGHT)];

    [dockWindow setContentView:dockView];
    [dockWindow makeKeyAndOrderFront:nil];

    /* --- Set up menu --- */
    NSMenu *menu = [[NSMenu alloc] initWithTitle:(id)CFSTR("Dock")];
    [NSApp setMainMenu:menu];

    fprintf(stderr, "[Dock] Desktop and dock bar windows created\n");
    return nil;
}

/* ============================================================================
 * main — Entry point
 * ============================================================================ */

int main(int argc, const char *argv[]) {
    (void)argc; (void)argv;
    void *pool = objc_autoreleasePoolPush();

    /* Create shared application */
    [NSApplication sharedApplication];

    /* Create delegate class dynamically */
    Class DockAppDelegate = objc_allocateClassPair(
        [NSObject class], "DockAppDelegate", 0);
    class_addMethod(DockAppDelegate,
                    @selector(applicationDidFinishLaunching:),
                    (IMP)_dockAppDidFinishLaunching, "v@:@");
    objc_registerClassPair(DockAppDelegate);

    /* Create delegate instance and set on NSApp */
    id delegate = [DockAppDelegate new];
    [NSApp setDelegate:delegate];

    /* Run the event loop */
    [NSApp run];

    objc_autoreleasePoolPop(pool);
    return 0;
}
