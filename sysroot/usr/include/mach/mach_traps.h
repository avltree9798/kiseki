/*
 * Kiseki OS - Userland Mach mach_traps.h
 *
 * Mach trap function declarations for userland.
 * These are the fast-path system calls (negative x16 via svc #0x80).
 *
 * Reference: osfmk/mach/mach_traps.h
 */

#ifndef _MACH_MACH_TRAPS_H_
#define _MACH_MACH_TRAPS_H_

#include <mach/port.h>
#include <mach/kern_return.h>
#include <mach/message.h>
#include <mach/mach_types.h>

/* ============================================================================
 * Mach Trap Function Declarations
 *
 * These correspond to the Mach trap table entries in the kernel.
 * Each invokes svc #0x80 with a negative syscall number in x16.
 * ============================================================================ */

/*
 * mach_reply_port - Allocate a temporary reply port
 *
 * Trap: -26
 * Returns a new port with receive right, intended for one-time use
 * in request/reply IPC patterns.
 */
extern mach_port_t mach_reply_port(void);

/*
 * mach_thread_self - Get the current thread's control port
 *
 * Trap: -27
 * Returns a send right to the calling thread's port.
 * Caller must deallocate with mach_port_deallocate() when done.
 */
extern mach_port_t mach_thread_self(void);

/*
 * mach_task_self - Get the current task's control port
 *
 * Trap: -28
 * Returns a send right to the calling task's port.
 *
 * Note: On macOS, mach_task_self() is actually a macro that reads
 * a cached value from libSystem. We implement it as a function that
 * invokes the trap. The mach_task_self_ global provides the cached
 * version (set during libSystem init).
 */
extern mach_port_t mach_task_self(void);

/*
 * mach_task_self_ - Cached task self port
 *
 * On macOS, mach_task_self() is a macro:
 *   #define mach_task_self() mach_task_self_
 * where mach_task_self_ is a global set at process start.
 * We provide this global for compatibility but programs can also
 * call the function form directly.
 */
extern mach_port_t mach_task_self_;

/*
 * mach_msg_trap - Low-level message send/receive trap
 *
 * Trap: -31
 * This is the raw trap entry point. Most code should use mach_msg()
 * from <mach/message.h> which wraps this.
 */
extern mach_msg_return_t mach_msg_trap(
    mach_msg_header_t   *msg,
    mach_msg_option_t   option,
    mach_msg_size_t     send_size,
    mach_msg_size_t     rcv_size,
    mach_port_name_t    rcv_name,
    mach_msg_timeout_t  timeout,
    mach_port_name_t    notify);

#endif /* _MACH_MACH_TRAPS_H_ */
