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
    kprintf("[boot] Initializing GIC...\n");
    gic_init();
    gic_init_percpu();

    /* Enable UART RX interrupts now that GIC is up (for Ctrl+C support) */
    uart_enable_irq();

    /* ================================================================
     * Phase 3: Physical memory manager (buddy allocator)
     * ================================================================ */
    kprintf("[boot] Initializing physical memory manager...\n");
    pmm_init((uint64_t)&__heap_start, RAM_BASE + RAM_SIZE);

    /* ================================================================
     * Phase 4: Virtual memory + MMU
     * ================================================================ */
    kprintf("[boot] Initializing virtual memory...\n");
    vmm_init();

    /* ================================================================
     * Phase 5: Threading & MLFQ Scheduler
     * ================================================================ */
    kprintf("[boot] Initializing threading...\n");
    thread_init();
    sched_init();

    /* ================================================================
     * Phase 6: ARM Generic Timer (100Hz tick)
     * ================================================================ */
    kprintf("[boot] Initializing timer...\n");
    timer_init(SCHED_HZ);

    /* Enable interrupts */
    kprintf("[boot] Enabling interrupts...\n");
    __asm__ volatile("msr daifclr, #0x2");  /* Clear IRQ mask (DAIF.I) */

    /* ================================================================
     * Phase 7: SMP — Bring up secondary cores via PSCI
     * ================================================================ */
    kprintf("[boot] Starting secondary cores...\n");
    smp_init();

    /* ================================================================
     * Phase 8: Block device subsystem (virtio-blk / eMMC)
     * ================================================================ */
    kprintf("[boot] Initializing block devices...\n");
    int blk_ret = blkdev_init();
    if (blk_ret < 0) {
        kprintf("[boot] WARNING: Block device init failed (%d)\n", blk_ret);
        kprintf("[boot] No root filesystem available.\n");
    }

    /* ================================================================
     * Phase 9: Buffer cache (LRU, 256 x 4KB)
     * ================================================================ */
    kprintf("[boot] Initializing buffer cache...\n");
    buf_init();

    /* ================================================================
     * Phase 10: Virtual File System
     * ================================================================ */
    kprintf("[boot] Initializing VFS...\n");
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
     * Phase 13: Mach IPC subsystem
     * ================================================================ */
    kprintf("[boot] Initializing Mach IPC...\n");
    ipc_init();

    /* ================================================================
     * Phase 14: CommPage (user-kernel shared page)
     * ================================================================ */
    kprintf("[boot] Initializing CommPage...\n");
    commpage_init();

    /* ================================================================
     * Phase 15: Process subsystem
     * ================================================================ */
    kprintf("[boot] Initializing process subsystem...\n");
    proc_init();

    /* ================================================================
     * Phase 16: Networking (TCP/IP stack, BSD sockets)
     * ================================================================ */
    kprintf("[boot] Initializing networking...\n");
    net_init();

    /* ================================================================
     * Phase 17: Launch PID 1 — /bin/bash
     * ================================================================ */
    kprintf("\n");
    kprintf("[boot] *** All subsystems initialized ***\n");
    kprintf("[boot] Launching /bin/bash as PID 1...\n");
    kprintf("\n");

    /*
     * kernel_init_process() creates the first user process (PID 1).
     * It loads /bin/bash (or falls back to /bin/sh, /sbin/init) from
     * the mounted root filesystem via the Mach-O loader, sets up the
     * user address space with Darwin ABI (argc/argv/envp on stack),
     * maps the CommPage, and drops to EL0 via eret.
     *
     * This function never returns.
     */
    kernel_init_process();

    /* NOTREACHED */
    panic("kernel_init_process() returned");
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
    gic_init_percpu();
    sched_init_percpu();
    timer_init_percpu();
    kprintf("[smp] Core %lu online (scheduler + timer ready)\n", core_id);

    /* Enable interrupts on this core */
    __asm__ volatile("msr daifclr, #0x2");

    /* Enter idle loop - scheduler will assign work via IPI */
    for (;;) {
        __asm__ volatile("wfi");
    }
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
