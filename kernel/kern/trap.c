/*
 * Kiseki OS - Trap Handling (C dispatch)
 *
 * Receives saved trap frames from vectors.S and dispatches to
 * the appropriate handler: IRQ, syscall, page fault, etc.
 */

#include <kiseki/types.h>
#include <machine/trap.h>
#include <kern/kprintf.h>
#include <kern/thread.h>
#include <kern/proc.h>
#include <kern/vmm.h>
#include <kern/pmm.h>
#include <bsd/syscall.h>
#include <bsd/signal.h>
#include <drivers/gic.h>
#include <drivers/timer.h>
#include <drivers/uart.h>
#include <kiseki/platform.h>

/* Forward declarations for subsystems not yet implemented */
extern void irq_dispatch(uint32_t irq);

/*
 * trap_sync_el1 - Synchronous exception from kernel mode (EL1)
 *
 * This should only happen on kernel bugs (e.g., null pointer deref).
 */
void trap_sync_el1(struct trap_frame *tf)
{
    uint32_t ec = (tf->esr >> 26) & 0x3F;

    kprintf("\n!!! KERNEL TRAP (sync EL1) !!!\n");
    kprintf("  EC=0x%x  ELR=0x%lx  FAR=0x%lx\n", ec, tf->elr, tf->far);

    switch (ec) {
    case EC_DABT_SAME:
        kprintf("  Data Abort in kernel at 0x%lx\n", tf->far);
        break;
    case EC_IABT_SAME:
        kprintf("  Instruction Abort in kernel at 0x%lx\n", tf->far);
        break;
    default:
        kprintf("  Unhandled EC=0x%x\n", ec);
        break;
    }

    panic("Kernel fault - cannot recover");
}

/*
 * trap_irq_el1 - IRQ while in kernel mode
 *
 * Read the interrupt ID from GIC, dispatch, and EOI.
 */
void trap_irq_el1(struct trap_frame *tf)
{
    (void)tf;

    uint32_t irq = gic_acknowledge();

    if (irq >= 1020) {
        /* Spurious interrupt */
        return;
    }

    irq_dispatch(irq);

    gic_end_of_interrupt(irq);

    /* Check for preemption after handling kernel-mode IRQ */
    struct cpu_data *cd;
    __asm__ volatile("mrs %0, tpidr_el1" : "=r"(cd));
    if (cd && cd->need_resched) {
        sched_switch();
    }
}

/*
 * trap_sync_el0 - Synchronous exception from user mode (EL0)
 *
 * Handles SVC (syscalls), page faults, alignment faults, etc.
 */
void trap_sync_el0(struct trap_frame *tf)
{
    uint32_t ec = (tf->esr >> 26) & 0x3F;

    switch (ec) {
    case EC_SVC_A64:
        /* SVC #0x80 - System call
         * XNU convention: syscall number in x16
         * Positive x16 -> BSD syscall
         * Negative x16 -> Mach trap
         * Arguments in x0-x5, return value in x0
         * Error: carry flag set in SPSR, positive errno in x0
         */
        syscall_handler(tf);

        /* Check for pending signals before returning to user mode */
        {
            struct thread *th = current_thread_get();
            if (th != NULL)
                signal_check(th, tf);
        }
        break;

    case EC_DABT_LOWER: {
        /* Data abort from user space — attempt vm_fault resolution */
        uint32_t dfsc = tf->esr & 0x3F;
        uint32_t wnr = (tf->esr >> 6) & 1;
        uint64_t fault_va = tf->far;

        /*
         * Translation faults (DFSC 0x04-0x07) mean the page isn't mapped.
         * Try to handle by:
         *   1. Stack auto-grow: if the fault address is within a reasonable
         *      distance below the current stack pointer (user stack grows down),
         *      allocate a page and map it.
         *   2. General demand-paging: allocate a zero page for valid regions.
         *
         * Access flag faults (0x08-0x0B) and permission faults (0x0C-0x0F)
         * are genuine violations — deliver SIGSEGV.
         */
        uint32_t fault_type = dfsc & 0x3C;  /* bits [5:2] */
        bool handled = false;

        if (fault_type == 0x04) {
            /* Translation fault — page not present */
            struct proc *p = proc_current();
            if (p && p->p_vmspace && p->p_vmspace->pgd) {
                /*
                 * Check if fault address is in the user stack region.
                 * User stack typically starts near 0x16F000000 and grows down.
                 * We'll allow auto-grow for addresses within 1MB below SP.
                 * Also handle general heap/bss regions by allowing any
                 * user-space address that isn't in the commpage.
                 */
                uint64_t page_va = fault_va & ~(uint64_t)0xFFF;

                /* Don't auto-map kernel addresses or commpage */
                if (page_va < 0xFFFF000000000000ULL && page_va != 0) {
                    uint64_t new_page = pmm_alloc_pages(0);
                    if (new_page != 0) {
                        /* Zero the page */
                        uint8_t *pp = (uint8_t *)new_page;
                        for (int zi = 0; zi < 4096; zi++)
                            pp[zi] = 0;

                        uint64_t pte_flags = wnr ?
                            PTE_USER_RW : PTE_USER_RO;
                        /* Map as RW — most user pages need write */
                        pte_flags = PTE_USER_RW;

                        if (vmm_map_page(p->p_vmspace->pgd,
                                         page_va, new_page, pte_flags) == 0) {
                            handled = true;
                        } else {
                            pmm_free_pages(new_page, 0);
                        }
                    }
                }
            }
        }

        if (handled)
            break;

        /* Could not resolve — deliver SIGSEGV or kill */
        kprintf("\n[trap] User data abort at FAR=0x%lx PC=0x%lx\n",
                tf->far, tf->elr);
        kprintf("  ESR=0x%lx DFSC=0x%x %s\n",
                tf->esr, dfsc, wnr ? "WRITE" : "READ");
        kprintf("  x0=0x%lx  x1=0x%lx  x30=0x%lx  SP=0x%lx\n",
                tf->regs[0], tf->regs[1], tf->regs[30], tf->sp);

        {
            struct proc *p = proc_current();
            if (p) {
                kprintf("  PID=%d name='%s'\n", p->p_pid, p->p_comm);
                /* Deliver SIGSEGV to the process */
                signal_send_pgid(p->p_pgrp, SIGSEGV);
                signal_check(current_thread_get(), tf);
                /* If handler caught it, we'll return to userspace */
                break;
            }
        }

        kprintf("[trap] Killing process due to unhandled data abort\n");
        extern void thread_exit(void);
        thread_exit();
        break;
    }

    case EC_IABT_LOWER: {
        /* Instruction abort from user space */
        uint32_t ifsc = tf->esr & 0x3F;
        kprintf("\n[trap] User instruction abort at FAR=0x%lx PC=0x%lx\n",
                tf->far, tf->elr);
        kprintf("  ESR=0x%lx IFSC=0x%x\n", tf->esr, ifsc);
        kprintf("  x30(LR)=0x%lx SP=0x%lx\n", tf->regs[30], tf->sp);

        {
            extern struct proc *proc_current(void);
            struct proc *p = proc_current();
            if (p)
                kprintf("  PID=%d name='%s'\n", p->p_pid, p->p_comm);
        }

        kprintf("[trap] Killing process due to unhandled instruction abort\n");
        extern void thread_exit(void);
        thread_exit();
        break;
    }

    case EC_SP_ALIGN:
    case EC_PC_ALIGN:
        kprintf("[trap] Alignment fault, PC=0x%lx LR=0x%lx SP=0x%lx\n",
                tf->elr, tf->regs[30], tf->sp);
        kprintf("[trap] Killing process due to alignment fault\n");
        {
            extern void thread_exit(void);
            thread_exit();
        }
        break;

    case EC_BRK:
        kprintf("[trap] BRK (breakpoint) at PC=0x%lx LR=0x%lx\n",
                tf->elr, tf->regs[30]);
        kprintf("[trap] Killing process due to breakpoint trap\n");
        {
            extern void thread_exit(void);
            thread_exit();
        }
        break;

    default:
        kprintf("[trap] Unhandled user exception EC=0x%x, PC=0x%lx LR=0x%lx SP=0x%lx\n",
                ec, tf->elr, tf->regs[30], tf->sp);
        kprintf("[trap] Killing process\n");
        {
            extern void thread_exit(void);
            thread_exit();
        }
        break;
    }
}

/*
 * trap_irq_el0 - IRQ while in user mode
 *
 * Same as kernel IRQ dispatch, but on return we may need
 * to check for pending signals or reschedule.
 */
void trap_irq_el0(struct trap_frame *tf)
{
    (void)tf;

    uint32_t irq = gic_acknowledge();

    if (irq >= 1020)
        return;

    irq_dispatch(irq);

    gic_end_of_interrupt(irq);

    /*
     * Check if we need to reschedule before returning to user mode.
     * This handles preemption: if a timer tick expired the current
     * thread's quantum, sched_tick set need_resched = true.
     */
    struct cpu_data *cd;
    __asm__ volatile("mrs %0, tpidr_el1" : "=r"(cd));
    if (cd && cd->need_resched) {
        sched_switch();
    }

    /* Check for pending signals before returning to user mode */
    {
        struct thread *th = current_thread_get();
        if (th != NULL)
            signal_check(th, tf);
    }
}

/*
 * irq_dispatch - Route an IRQ to the correct handler
 *
 * Simple table-based dispatch. Will be expanded as drivers register handlers.
 */
/* VirtIO-net interrupt handler (defined in virtio_net.c) */
extern void virtio_net_recv(void);

void irq_dispatch(uint32_t irq)
{
    switch (irq) {
    case TIMER_IRQ:
        timer_handler();
        break;

    case UART0_IRQ:
        uart_irq_handler();
        break;

    case IPI_RESCHEDULE: {
        /* Force reschedule on this core */
        struct cpu_data *cd_ipi;
        __asm__ volatile("mrs %0, tpidr_el1" : "=r"(cd_ipi));
        if (cd_ipi)
            cd_ipi->need_resched = 1;
        break;
    }

    case IPI_TLB_FLUSH:
        /* Full TLB invalidation on this core */
        __asm__ volatile("tlbi vmalle1" ::: "memory");
        __asm__ volatile("dsb sy" ::: "memory");
        __asm__ volatile("isb");
        break;

    case IPI_HALT:
        kprintf("[irq] Halt IPI received - stopping core\n");
        for (;;)
            __asm__ volatile("wfi");
        break;

    default:
        /* Check if this is a VirtIO MMIO interrupt (IRQ 48..79) */
        if (irq >= VIRTIO_MMIO_IRQ_BASE &&
            irq < VIRTIO_MMIO_IRQ_BASE + VIRTIO_MMIO_COUNT) {
            virtio_net_recv();
        } else {
            kprintf("[irq] Unhandled IRQ %u\n", irq);
        }
        break;
    }
}
