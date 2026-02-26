/*
 * Kiseki OS - Framebuffer Console
 *
 * Renders text onto the VirtIO GPU framebuffer using the built-in
 * 8x16 VGA bitmap font. Provides a VT100-compatible text console
 * with scrolling, analogous to XNU's osfmk/console/video_console.c.
 *
 * The fbconsole is wired as the t_putc callback for a dedicated TTY
 * so that getty/login/bash can operate on it like a physical terminal.
 */

#ifndef _KERN_FBCONSOLE_H
#define _KERN_FBCONSOLE_H

#include <kiseki/types.h>

/* Forward declaration */
struct tty;

/*
 * fbconsole_init - Initialise the framebuffer console.
 *
 * Must be called after virtio_gpu_init() has successfully created
 * a framebuffer. Sets up the text grid, clears the screen, and
 * creates the fbconsole TTY.
 *
 * Returns 0 on success, -1 if no framebuffer is available.
 */
int fbconsole_init(void);

/*
 * fbconsole_putc - Output a character to the framebuffer console.
 *
 * This is the t_putc callback for the fbconsole TTY. Handles:
 *   - Printable characters (rendered via the 8x16 font)
 *   - \n (newline — advance row, scroll if needed)
 *   - \r (carriage return — reset column to 0)
 *   - \b (backspace — move cursor left)
 *   - \t (tab — advance to next 8-column boundary)
 *   - Automatic line wrapping and scrolling
 */
void fbconsole_putc(char c);

/*
 * fbconsole_get_tty - Get the TTY associated with the framebuffer console.
 *
 * Returns NULL if fbconsole is not initialised.
 */
struct tty *fbconsole_get_tty(void);

/*
 * fbconsole_active - Check if the framebuffer console is initialised.
 */
bool fbconsole_active(void);

/*
 * fbconsole_flush - Flush pending dirty region to the GPU.
 *
 * Characters written via fbconsole_putc() are batched — only \n
 * triggers an automatic flush. Call this to force immediate display
 * update (e.g., after writing a prompt that doesn't end with \n).
 */
void fbconsole_flush(void);

/*
 * fbconsole_disable - Disable the framebuffer console.
 *
 * IOK-C1: Called by WindowServer (via IOKit) when it takes ownership
 * of the framebuffer. After this call, fbconsole_putc() becomes a
 * no-op and the console will not write pixels or issue GPU flushes.
 *
 * This prevents the dual-writer race where both fbconsole and
 * WindowServer write pixels and flush the GPU concurrently.
 *
 * Analogous to XNU's vc_progress_set(TRUE, 0) which disables the
 * boot console when the WindowServer registers.
 */
void fbconsole_disable(void);

/*
 * fbconsole_enable - Re-enable the framebuffer console.
 *
 * Called when WindowServer exits or crashes, allowing the text
 * console to resume for diagnostics.
 */
void fbconsole_enable(void);

#endif /* _KERN_FBCONSOLE_H */
