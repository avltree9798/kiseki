/*
 * Kiseki OS - Kernel Main Entry Point
 *
 * Called by boot.S after BSS is cleared and stack is set up.
 * Initializes all kernel subsystems and launches the first user process.
 */

#include <kiseki/types.h>
#include <kiseki/platform.h>
#include <kern/kprintf.h>
#include <drivers/uart.h>
#include <drivers/gic.h>
#include <drivers/timer.h>
#include <kern/pmm.h>
#include <kern/vmm.h>
#include <kern/thread.h>
#include <drivers/blkdev.h>
#include <fs/buf.h>
#include <fs/vfs.h>
#include <fs/ext4.h>
#include <mach/ipc.h>
#include <kern/proc.h>
#include <net/net.h>

/* Functions without dedicated headers */
extern void commpage_init(void);
extern void smp_init(void);

/* Scheduler tick rate: 100 Hz = 10ms quantum */
#define SCHED_HZ    100

/* Linker-provided symbols */
extern uint64_t __text_start;
extern uint64_t __text_end;
extern uint64_t __bss_start;
extern uint64_t __bss_end;
extern uint64_t __kernel_end;
extern uint64_t __heap_start;

/* Forward declaration */
static void kernel_bootstrap_thread_func(void *arg);

/*
 * kmain - Primary kernel entry point (called from boot.S on core 0)
 *
 * @dtb_addr: Device Tree Blob physical address (if provided by bootloader)
 */
void kmain(uint64_t dtb_addr)
{
    (void)dtb_addr;  /* TODO: parse DTB */

    /* ================================================================
     * Phase 1: Early console
     * ================================================================ */
    uart_init();

    kprintf("\n");
    kprintf("========================================\n");
    kprintf("  Kiseki OS v0.1.0 (%s)\n", PLATFORM_NAME);
    kprintf("  ARM64 Hybrid Kernel (Mach + BSD)\n");
    kprintf("========================================\n");
    kprintf("\n");

    kprintf("[boot] Kernel loaded at 0x%lx - 0x%lx\n",
            (uint64_t)&__text_start, (uint64_t)&__kernel_end);
    kprintf("[boot] BSS:  0x%lx - 0x%lx\n",
            (uint64_t)&__bss_start, (uint64_t)&__bss_end);
    kprintf("[boot] Heap starts at 0x%lx\n",
            (uint64_t)&__heap_start);

    /* ================================================================
     * Phase 2: Interrupt controller (GICv2)
     * ================================================================ */
    kprintf("[boot] Initialising GIC...\n");
    gic_init();
    gic_init_percpu();

    /* Enable UART RX interrupts now that GIC is up (for Ctrl+C support) */
    uart_enable_irq();

    /* ================================================================
     * Phase 3: Physical memory manager (buddy allocator)
     * ================================================================ */
    kprintf("[boot] Initialising physical memory manager...\n");
    pmm_init((uint64_t)&__heap_start, RAM_BASE + RAM_SIZE);

    /* ================================================================
     * Phase 4: Virtual memory + MMU
     * ================================================================ */
    kprintf("[boot] Initialising virtual memory...\n");
    vmm_init();

    /* ================================================================
     * Phase 5: Threading & MLFQ Scheduler
     * ================================================================ */
    kprintf("[boot] Initialising threading...\n");
    thread_init();
    sched_init();

    /* ================================================================
     * Phase 6: ARM Generic Timer (100Hz tick)
     * ================================================================ */
    kprintf("[boot] Initialising timer...\n");
    timer_init(SCHED_HZ);

    /*
     * NOTE: IRQs are NOT enabled here. They remain masked until
     * load_context() jumps to thread_trampoline, which does
     * "msr daifclr, #0x2" to unmask IRQs on the bootstrap thread's
     * own PMM stack. This prevents timer IRQs from triggering
     * sched_switch() while still on the boot stack, which would
     * corrupt the idle thread's context.sp with boot stack values.
     *
     * The timer hardware is programmed but interrupts are pending
     * until unmasked — this is safe.
     */

    /* ================================================================
     * Phase 7: SMP — Bring up secondary cores via PSCI
     * ================================================================ */
    kprintf("[boot] Starting secondary cores...\n");
    smp_init();

    /* ================================================================
     * Phase 8: Block device subsystem (virtio-blk / eMMC)
     * ================================================================ */
    kprintf("[boot] Initialising block devices...\n");
    int blk_ret = blkdev_init();
    if (blk_ret < 0) {
        kprintf("[boot] WARNING: Block device init failed (%d)\n", blk_ret);
        kprintf("[boot] No root filesystem available.\n");
    }

    /* ================================================================
     * Phase 9: Buffer cache (LRU, 256 x 4KB)
     * ================================================================ */
    kprintf("[boot] Initialising buffer cache...\n");
    buf_init();

    /* ================================================================
     * Phase 10: Virtual File System
     * ================================================================ */
    kprintf("[boot] Initialising VFS...\n");
    vfs_init();

    /* Initialize the console TTY (terminal line discipline) */
    extern void tty_init(void);
    tty_init();

    extern void pty_init(void);
    pty_init();

    /* ================================================================
     * Phase 11: Ext4 filesystem driver
     * ================================================================ */
    kprintf("[boot] Registering Ext4 filesystem...\n");
    ext4_fs_init();

    /* ================================================================
     * Phase 12: Mount root filesystem
     * ================================================================ */
    if (blk_ret >= 0) {
        kprintf("[boot] Mounting root filesystem (ext4 on /dev/vda)...\n");
        int mount_ret = vfs_mount("ext4", "/", 0, 0);
        if (mount_ret < 0) {
            kprintf("[boot] WARNING: Root mount failed (%d)\n", mount_ret);
        } else {
            kprintf("[boot] Root filesystem mounted at /\n");
        }
    }

    /* ================================================================
     * Phase 12b: Device filesystem (devfs at /dev)
     * ================================================================ */
    kprintf("[boot] Mounting devfs at /dev...\n");
    extern void devfs_init(void);
    devfs_init();
    int devfs_ret = vfs_mount("devfs", "/dev", 0, 0);
    if (devfs_ret < 0) {
        kprintf("[boot] WARNING: devfs mount failed (%d)\n", devfs_ret);
    }

    /* ================================================================
     * Phase 12c: Start buffer cache sync daemon
     * ================================================================ */
    kprintf("[boot] Starting buffer cache sync daemon...\n");
    extern void buf_start_sync_daemon(void);
    buf_start_sync_daemon();

    /* ================================================================
     * Phase 13: Mach IPC subsystem
     * ================================================================ */
    kprintf("[boot] Initialising Mach IPC...\n");
    ipc_init();

    /* ================================================================
     * Phase 14: CommPage (user-kernel shared page)
     * ================================================================ */
    kprintf("[boot] Initialising CommPage...\n");
    commpage_init();

    /* ================================================================
     * Phase 15: Process subsystem
     * ================================================================ */
    kprintf("[boot] Initialising process subsystem...\n");
    proc_init();

    /* ================================================================
     * Phase 16: Networking (TCP/IP stack, BSD sockets)
     * ================================================================ */
    kprintf("[boot] Initialising networking...\n");
    net_init();

    /* ================================================================
     * Phase 16b: VirtIO GPU framebuffer
     * ================================================================ */
    kprintf("[boot] Initialising VirtIO GPU...\n");
    extern int virtio_gpu_init(void);
    int gpu_ret = virtio_gpu_init();
    if (gpu_ret < 0) {
        kprintf("[boot] No VirtIO GPU found (non-fatal)\n");
    }

    /* ================================================================
     * Phase 16c: Framebuffer console
     * ================================================================ */
    extern int fbconsole_init(void);
    if (gpu_ret == 0) {
        kprintf("[boot] Initialising framebuffer console...\n");
        int fb_ret = fbconsole_init();
        if (fb_ret < 0) {
            kprintf("[boot] Framebuffer console init failed (non-fatal)\n");
        }
    }

    /* ================================================================
     * Phase 16d: VirtIO input keyboard
     * ================================================================ */
    extern int virtio_input_init(void);
    kprintf("[boot] Initialising VirtIO input...\n");
    int input_ret = virtio_input_init();
    if (input_ret < 0) {
        kprintf("[boot] No VirtIO input device found (non-fatal)\n");
    }

    /* ================================================================
     * Phase 17: Create bootstrap thread and abandon boot stack
     * ================================================================ */
    kprintf("\n");
    kprintf("[boot] *** All subsystems initialized ***\n");
    kprintf("[boot] Creating bootstrap thread...\n");
    kprintf("\n");

    /*
     * XNU-style boot flow:
     *
     * 1. Create a kernel_bootstrap_thread with its own PMM-allocated stack.
     * 2. Set the idle thread as current_thread (it keeps its own PMM stack).
     * 3. Call load_context() to jump into the bootstrap thread, abandoning
     *    the boot stack forever.
     *
     * kernel_bootstrap_thread will:
     *   - Call kernel_init_process() which creates PID 1 and enqueues it
     *     on the run queue (no manual eret — scheduler dispatches it)
     *   - Call thread_exit() to terminate itself
     *
     * This eliminates the root cause of boot stack corruption: the boot
     * stack is abandoned entirely, idle threads use PMM stacks, and PID 1
     * is launched by the scheduler rather than by a manual eret.
     *
     * Reference: XNU osfmk/kern/startup.c kernel_bootstrap()
     */
    struct thread *bootstrap_thread = thread_create(
        "kernel_bootstrap", kernel_bootstrap_thread_func, NULL, PRI_MAX);
    if (bootstrap_thread == NULL)
        panic("Cannot create kernel bootstrap thread");

    kprintf("[boot] Bootstrap thread created (tid=%lu)\n",
            bootstrap_thread->tid);
    kprintf("[boot] Abandoning boot stack, jumping to bootstrap thread...\n");

    /*
     * Set bootstrap_thread as current_thread before load_context().
     *
     * thread_trampoline (the LR target of load_context) reads
     * cd->current_thread to get the entry function pointer, so we
     * must install bootstrap_thread as current before jumping.
     *
     * Mask IRQs to prevent preemption between setting current_thread
     * and load_context. thread_trampoline will re-enable IRQs.
     */
    __asm__ volatile("msr daifset, #0x2" ::: "memory");
    {
        struct cpu_data *cd;
        __asm__ volatile("mrs %0, tpidr_el1" : "=r"(cd));
        cd->current_thread = bootstrap_thread;
        bootstrap_thread->cpu = 0;
    }

    /*
     * load_context() is a one-way jump: it restores the bootstrap
     * thread's saved context (callee-saved regs + SP) and rets into
     * thread_trampoline, which calls kernel_bootstrap_thread_func().
     *
     * The boot stack (set up by boot.S) is NEVER used again.
     */
    load_context(&bootstrap_thread->context);

    /* NOTREACHED — load_context never returns */
    __builtin_unreachable();
}

/*
 * kernel_bootstrap_thread_func - Runs on its own PMM-allocated stack
 *
 * This is the XNU equivalent of kernel_bootstrap_thread().
 * It finishes the boot sequence by launching PID 1 via the scheduler,
 * then terminates itself.
 *
 * At this point, the boot stack has been abandoned forever.
 */
static void kernel_bootstrap_thread_func(void *arg __unused)
{
    kprintf("[bootstrap] Running on PMM-allocated stack\n");

    /*
     * Launch PID 1.
     * kernel_init_process() creates the init process, loads the Mach-O
     * binary, sets up the user stack, and enqueues init's thread on
     * the run queue. It returns normally — the scheduler will pick up
     * init_thread and dispatch it to init_thread_return → eret → EL0.
     */
    kprintf("[bootstrap] Launching PID 1...\n");
    kernel_init_process();

    kprintf("[bootstrap] PID 1 enqueued. Bootstrap thread exiting.\n");

    /*
     * Terminate this thread. The scheduler will pick it up and the
     * thread slot will be recycled. We are done with bootstrapping.
     *
     * thread_exit() calls sched_switch() which never returns.
     */
    thread_exit();
}

/*
 * secondary_main - Entry point for secondary CPU cores
 *
 * Called by boot.S after per-core stack is set up.
 *
 * @core_id: The core number (1, 2, 3, ...)
 */
void secondary_main(uint64_t core_id)
{
    /*
     * CRITICAL: Enable MMU + caches before touching any shared data.
     * Secondary cores start with MMU off (PSCI reset value). Without
     * caches, LDAXR/STXR exclusive monitors may not work correctly
     * across cores, and stores from the boot CPU may be invisible.
     */
    vmm_init_percpu();

    gic_init_percpu();
    sched_init_percpu();
    timer_init_percpu();
    kprintf("[smp] Core %lu online (scheduler + timer ready)\n", core_id);

    /*
     * XNU-style: abandon this CPU's boot stack by jumping into the
     * idle thread via load_context(). The idle thread has its own
     * PMM-allocated stack. thread_trampoline will enable IRQs and
     * call idle_thread_func(), which does the WFI loop.
     *
     * This mirrors how CPU0 abandons its boot stack in kmain().
     */
    {
        struct cpu_data *cd;
        __asm__ volatile("mrs %0, tpidr_el1" : "=r"(cd));

        kprintf("[smp] Core %lu: abandoning boot stack, jumping to idle thread\n",
                core_id);

        load_context(&cd->idle_thread->context);
    }

    /* NOTREACHED — load_context never returns */
    __builtin_unreachable();
}

/*
 * exception_handler_early - Temporary exception handler
 *
 * Called from vectors.S for any unhandled exception.
 * Prints diagnostic info and halts.
 */
void exception_handler_early(uint64_t esr, uint64_t elr,
                             uint64_t far, uint64_t spsr)
{
    uint32_t ec = (esr >> 26) & 0x3F;  /* Exception Class */
    uint32_t iss = esr & 0x1FFFFFF;     /* Instruction Specific Syndrome */

    kprintf("\n!!! UNHANDLED EXCEPTION !!!\n");
    kprintf("  ESR_EL1:  0x%lx (EC=0x%x ISS=0x%x)\n", esr, ec, iss);
    kprintf("  ELR_EL1:  0x%lx (faulting PC)\n", elr);
    kprintf("  FAR_EL1:  0x%lx (fault address)\n", far);
    kprintf("  SPSR_EL1: 0x%lx\n", spsr);

    /* Decode common exception classes */
    switch (ec) {
    case 0x15: kprintf("  Type: SVC from AArch64\n"); break;
    case 0x20: kprintf("  Type: Instruction Abort (lower EL)\n"); break;
    case 0x21: kprintf("  Type: Instruction Abort (same EL)\n"); break;
    case 0x24: kprintf("  Type: Data Abort (lower EL)\n"); break;
    case 0x25: kprintf("  Type: Data Abort (same EL)\n"); break;
    case 0x00: kprintf("  Type: Unknown reason\n"); break;
    default:   kprintf("  Type: EC 0x%x (see ARM ARM)\n", ec); break;
    }

    panic("System halted due to unhandled exception");
}
