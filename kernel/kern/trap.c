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

    /* Also read live system registers for comparison (trap frame may be stale
     * if this is a nested exception or if the exception occurred mid-restore) */
    uint64_t live_esr, live_elr, live_far, live_spsr;
    __asm__ volatile("mrs %0, esr_el1"  : "=r"(live_esr));
    __asm__ volatile("mrs %0, elr_el1"  : "=r"(live_elr));
    __asm__ volatile("mrs %0, far_el1"  : "=r"(live_far));
    __asm__ volatile("mrs %0, spsr_el1" : "=r"(live_spsr));

    kprintf("\n!!! KERNEL TRAP (sync EL1) !!!\n");
    kprintf("  EC=0x%x  ELR=0x%lx  FAR=0x%lx\n", ec, tf->elr, tf->far);
    kprintf("  ESR=0x%lx  SPSR=0x%lx\n", tf->esr, tf->spsr);
    kprintf("  LIVE ESR=0x%lx  ELR=0x%lx  FAR=0x%lx  SPSR=0x%lx\n",
            live_esr, live_elr, live_far, live_spsr);
    kprintf("  x0=0x%lx  x1=0x%lx  x19=0x%lx  x30=0x%lx\n",
            tf->regs[0], tf->regs[1], tf->regs[19], tf->regs[30]);
    kprintf("  SP(from tf)=0x%lx\n", tf->sp);

    /* Dump TTBR values to understand address space */
    uint64_t ttbr0, ttbr1;
    __asm__ volatile("mrs %0, ttbr0_el1" : "=r"(ttbr0));
    __asm__ volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1));
    kprintf("  TTBR0=0x%lx  TTBR1=0x%lx\n", ttbr0, ttbr1);

    /* Get current thread info */
    struct cpu_data *cd;
    __asm__ volatile("mrs %0, tpidr_el1" : "=r"(cd));
    if (cd && cd->current_thread) {
        struct thread *th = cd->current_thread;
        kprintf("  Current thread: tid=%lu state=%d\n", th->tid, th->state);
        kprintf("  thread context: x30=0x%lx sp=0x%lx x19=0x%lx x20=0x%lx x29=0x%lx\n",
                th->context.x30, th->context.sp, th->context.x19,
                th->context.x20, th->context.x29);
        if (th->task) {
            kprintf("  task pid=%d vm_space=%p\n",
                    th->task->pid, (void *)th->task->vm_space);
        }
        /* Dump kernel stack bounds */
        kprintf("  kernel_stack=[0x%lx..0x%lx] size=0x%lx\n",
                (uint64_t)th->kernel_stack,
                (uint64_t)th->kernel_stack + th->kernel_stack_size,
                th->kernel_stack_size);
        /* Check if the tf pointer is within the thread's kernel stack */
        {
            uint64_t klo = (uint64_t)th->kernel_stack;
            uint64_t khi = klo + th->kernel_stack_size;
            uint64_t tf_addr = (uint64_t)tf;
            if (tf_addr >= klo && tf_addr < khi)
                kprintf("  tf=0x%lx IS within kernel stack (offset=0x%lx from top)\n",
                        tf_addr, khi - tf_addr);
            else
                kprintf("  !!! tf=0x%lx OUTSIDE kernel stack [0x%lx..0x%lx] !!!\n",
                        tf_addr, klo, khi);
        }
        /* Dump a few words from the kernel stack at the saved context.sp */
        {
            uint64_t ctx_sp = th->context.sp;
            uint64_t klo = (uint64_t)th->kernel_stack;
            uint64_t khi = klo + th->kernel_stack_size;
            if (ctx_sp >= klo && ctx_sp < khi && (ctx_sp + 64) <= khi) {
                uint64_t *sp_ptr = (uint64_t *)ctx_sp;
                kprintf("  Stack dump at ctx.sp=0x%lx:\n", ctx_sp);
                kprintf("    [sp+0x00]=0x%lx [sp+0x08]=0x%lx [sp+0x10]=0x%lx [sp+0x18]=0x%lx\n",
                        sp_ptr[0], sp_ptr[1], sp_ptr[2], sp_ptr[3]);
                kprintf("    [sp+0x20]=0x%lx [sp+0x28]=0x%lx [sp+0x30]=0x%lx [sp+0x38]=0x%lx\n",
                        sp_ptr[4], sp_ptr[5], sp_ptr[6], sp_ptr[7]);
            }
        }
    }

    /* Dump ALL trap frame registers for full context */
    kprintf("  Full trap frame dump:\n");
    for (int i = 0; i < 31; i += 4) {
        if (i + 3 < 31) {
            kprintf("    x%d=0x%lx  x%d=0x%lx  x%d=0x%lx  x%d=0x%lx\n",
                    i, tf->regs[i], i+1, tf->regs[i+1],
                    i+2, tf->regs[i+2], i+3, tf->regs[i+3]);
        } else {
            for (int j = i; j < 31; j++)
                kprintf("    x%d=0x%lx\n", j, tf->regs[j]);
        }
    }

    switch (ec) {
    case EC_DABT_SAME:
        kprintf("  Data Abort in kernel at 0x%lx\n", tf->far);
        break;
    case EC_IABT_SAME:
        kprintf("  Instruction Abort in kernel at 0x%lx\n", tf->far);
        /* Additional: check if FAR matches a user stack address pattern */
        if (tf->far >= 0x7FFF00000000ULL) {
            kprintf("  !!! FAR is a USER STACK address — kernel tried to execute user code!\n");
            kprintf("  !!! This means x30 (LR) was corrupted with a user address.\n");
            kprintf("  !!! Check context_switch or trap frame restore path.\n");
        }
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
    (void)tf;  /* Used only when DEBUG tracing is enabled */
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
         *
         * CRITICAL: Enable interrupts during syscall processing.
         *
         * ARM64 exception entry from EL0 masks IRQs (PSTATE.I=1).
         * If we leave IRQs masked for the entire syscall, this CPU
         * cannot receive timer ticks, which means:
         *   1. sched_tick() never runs on this CPU
         *   2. sched_wakeup_sleepers() never runs on this CPU
         *   3. All deadline-based wakeups depend on OTHER CPUs
         *
         * On real XNU, the kernel unmasks IRQs early in the syscall
         * path (via ml_set_interrupts_enabled() called from the
         * trap handler). Blocking syscalls like mach_msg must be
         * able to receive timer ticks for timeout expiry.
         *
         * We unmask IRQs here. The trap frame has already been saved,
         * and the kernel stack is set up, so it's safe to take IRQs.
         * On return, RESTORE_REGS restores SPSR_EL1 (the EL0 state)
         * which already has the correct IRQ mask for user mode.
         */
        __asm__ volatile("msr daifclr, #0x2" ::: "memory");

#if DEBUG
        {
            int64_t scnum = (int64_t)tf->regs[16];
            /* Only trace fork (2), wait4 (7), execve (59), exit (1) */
            if (scnum == 2 || scnum == 7 || scnum == 59 || scnum == 1) {
                struct thread *_th = current_thread_get();
                pid_t _pid = (_th && _th->task) ? _th->task->pid : -1;
                kprintf("[SYSCALL] ENTER: pid=%d tid=%lu sc=%ld ELR=0x%lx user_SP=0x%lx user_x30=0x%lx\n",
                        _pid, _th ? _th->tid : 0, scnum, tf->elr, tf->sp, tf->regs[30]);
                kprintf("[SYSCALL]   tf=0x%lx hw_sp=", (uint64_t)tf);
                uint64_t _hw_sp;
                __asm__ volatile("mov %0, sp" : "=r"(_hw_sp));
                kprintf("0x%lx\n", _hw_sp);
            }
        }
#endif
        syscall_handler(tf);

        /*
         * Mask IRQs before checking signals and returning to EL0.
         * signal_check() manipulates the trap frame and must not be
         * interrupted mid-modification. The RESTORE_REGS + eret path
         * restores SPSR_EL1 (which has EL0's PSTATE), so masking here
         * has no effect on the returned-to user mode state.
         */
        __asm__ volatile("msr daifset, #0x2" ::: "memory");

#if DEBUG
        {
            int64_t scnum = (int64_t)tf->regs[16];
            if (scnum == 2 || scnum == 7 || scnum == 59 || scnum == 1) {
                struct thread *_th = current_thread_get();
                pid_t _pid = (_th && _th->task) ? _th->task->pid : -1;
                kprintf("[SYSCALL] EXIT: pid=%d tid=%lu sc=%ld ret_x0=0x%lx ELR=0x%lx user_SP=0x%lx\n",
                        _pid, _th ? _th->tid : 0, scnum, tf->regs[0], tf->elr, tf->sp);
            }
        }
#endif

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
        } else if ((dfsc & 0x3C) == 0x0C && wnr) {
            /*
             * Permission fault on write — check for COW page.
             * DFSC 0x0C-0x0F are permission faults at different levels:
             *   0x0C = level 0, 0x0D = level 1, 0x0E = level 2, 0x0F = level 3
             * Masking with 0x3C gives 0x0C for all permission fault levels.
             * If the page has PTE_COW set, handle via copy-on-write.
             */
            struct proc *p = proc_current();
            if (p && p->p_vmspace) {
                uint64_t page_va = fault_va & ~(uint64_t)0xFFF;
                
                /* Check if page has COW bit set */
                pte_t *pte = vmm_get_pte(p->p_vmspace->pgd, page_va);
                if (pte && (*pte & PTE_VALID) && (*pte & PTE_COW)) {
                    /* COW fault — make a private copy */
                    if (vmm_copy_on_write(p->p_vmspace, page_va) == 0) {
                        handled = true;
                    }
                }
            }
        }

         if (handled)
            break;

        /*
         * Alignment fault (DFSC=0x21) from QEMU TCG:
         *
         * QEMU TCG checks alignment BEFORE performing the TLB lookup.
         * When the faulting address is unaligned AND the page is not in
         * the TLB, QEMU reports DFSC=0x21 (alignment fault) instead of
         * a translation fault (DFSC=0x04-0x07).  We handle three cases:
         *
         * 1. The faulting page is unmapped → demand-page it.
         * 2. An unaligned access spans a page boundary and the NEXT page
         *    is unmapped → demand-page the next page too.
         * 3. Both pages are already mapped → the fault is spurious
         *    (SCTLR_EL1.A=0 disables alignment checking).  Simply retry
         *    the instruction.  This commonly occurs with ObjC runtime
         *    data structures (SparseArray, dtable nodes) that straddle
         *    page boundaries.
         */
        if ((dfsc & 0x3F) == 0x21) {
            struct proc *p = proc_current();
            if (p && p->p_vmspace && p->p_vmspace->pgd) {
                uint64_t page_va = fault_va & ~(uint64_t)0xFFF;
                int pages_fixed = 0;

                /*
                 * Check the page containing the faulting address.
                 * If unmapped, demand-page it.
                 */
                pte_t *pte = vmm_get_pte(p->p_vmspace->pgd, page_va);
                if (!pte || !(*pte & PTE_VALID)) {
                    if (page_va < 0xFFFF000000000000ULL && page_va != 0) {
                        uint64_t new_page = pmm_alloc_pages(0);
                        if (new_page != 0) {
                            uint8_t *pp = (uint8_t *)new_page;
                            for (int zi = 0; zi < 4096; zi++)
                                pp[zi] = 0;
                            if (vmm_map_page(p->p_vmspace->pgd,
                                             page_va, new_page, PTE_USER_RW) == 0) {
                                pages_fixed++;
                            } else {
                                pmm_free_pages(new_page, 0);
                            }
                        }
                    }
                }

                /*
                 * For unaligned accesses that span a page boundary, the
                 * next page may also need to be demand-paged.  An access
                 * of up to 16 bytes (LDP Q-reg pair) at address A can
                 * touch page_va and page_va + 0x1000.
                 */
                uint64_t next_page_va = page_va + 0x1000;
                if ((fault_va & 0xFFF) != 0 &&
                    next_page_va < 0xFFFF000000000000ULL) {
                    pte_t *pte2 = vmm_get_pte(p->p_vmspace->pgd, next_page_va);
                    if (!pte2 || !(*pte2 & PTE_VALID)) {
                        uint64_t new_page = pmm_alloc_pages(0);
                        if (new_page != 0) {
                            uint8_t *pp = (uint8_t *)new_page;
                            for (int zi = 0; zi < 4096; zi++)
                                pp[zi] = 0;
                            if (vmm_map_page(p->p_vmspace->pgd,
                                             next_page_va, new_page,
                                             PTE_USER_RW) == 0) {
                                pages_fixed++;
                            } else {
                                pmm_free_pages(new_page, 0);
                            }
                        }
                    }
                }

                /*
                 * If we mapped any pages, or if both pages were already
                 * mapped (spurious alignment fault under TCG with
                 * SCTLR_EL1.A=0), simply retry the instruction.
                 */
                pte = vmm_get_pte(p->p_vmspace->pgd, page_va);
                if (pte && (*pte & PTE_VALID)) {
                    handled = true;
                }
            }
            if (handled)
                break;
        }

        /* Could not resolve — deliver SIGSEGV or kill */
        kprintf("\n[trap] User data abort at FAR=0x%lx PC=0x%lx\n",
                tf->far, tf->elr);
        kprintf("  ESR=0x%lx DFSC=0x%x %s\n",
                tf->esr, dfsc, wnr ? "WRITE" : "READ");
        kprintf("  x0=0x%lx  x1=0x%lx  x30=0x%lx  SP=0x%lx\n",
                tf->regs[0], tf->regs[1], tf->regs[30], tf->sp);

        /* Dump SCTLR_EL1 and PTE for diagnostic purposes */
        {
            uint64_t sctlr_val;
            __asm__ volatile("mrs %0, sctlr_el1" : "=r"(sctlr_val));
            kprintf("  SCTLR_EL1=0x%lx (A=%d)\n", sctlr_val,
                    (int)((sctlr_val >> 1) & 1));
            struct proc *dp = proc_current();
            if (dp && dp->p_vmspace && dp->p_vmspace->pgd) {
                uint64_t fpage = fault_va & ~(uint64_t)0xFFF;
                pte_t *pte = vmm_get_pte(dp->p_vmspace->pgd, fpage);
                if (pte)
                    kprintf("  PTE for 0x%lx: 0x%lx (valid=%d)\n",
                            fpage, *pte, (int)(*pte & PTE_VALID));
                else
                    kprintf("  PTE for 0x%lx: NOT PRESENT (walk returned NULL)\n",
                            fpage);
            }
        }

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
        /*
         * Instruction abort from user space.
         *
         * Like data aborts, instruction aborts can be caused by:
         *   - Translation faults (IFSC 0x04-0x07): page not mapped
         *   - Permission faults (IFSC 0x0C-0x0F): page mapped but not executable
         *   - External aborts (IFSC 0x10): bus error / stage-2 fault
         *
         * After fork with COW, code pages are marked read-only. While
         * ARM64 allows instruction fetch from read-only pages (UXN=0),
         * some scenarios (e.g., COW pages that were writable+executable)
         * may need COW resolution to restore proper attributes. Also,
         * translation faults need demand-paging just like data aborts.
         */
        uint32_t ifsc = tf->esr & 0x3F;
        uint32_t fault_type = ifsc & 0x3C;
        bool handled = false;

        struct proc *p = proc_current();

        if (fault_type == 0x04 && p && p->p_vmspace && p->p_vmspace->pgd) {
            /*
             * Translation fault on instruction fetch — page not present.
             * Demand-page it the same way we handle data translation faults.
             */
            uint64_t page_va = tf->far & ~(uint64_t)0xFFF;

            if (page_va < 0xFFFF000000000000ULL && page_va != 0) {
                uint64_t new_page = pmm_alloc_pages(0);
                if (new_page != 0) {
                    uint8_t *pp = (uint8_t *)new_page;
                    for (int zi = 0; zi < 4096; zi++)
                        pp[zi] = 0;

                    /* Executable page: map RO with execute permission */
                    uint64_t pte_flags = PTE_USER_RX;

                    if (vmm_map_page(p->p_vmspace->pgd,
                                     page_va, new_page, pte_flags) == 0) {
                        /* Ensure I-cache sees the new mapping */
                        __asm__ volatile("ic ivau, %0" :: "r"(page_va) : "memory");
                        __asm__ volatile("dsb ish; isb" ::: "memory");
                        handled = true;
                    } else {
                        pmm_free_pages(new_page, 0);
                    }
                }
            }
        } else if (fault_type == 0x0C && p && p->p_vmspace) {
            /*
             * Permission fault on instruction fetch.
             * This can happen after fork if a COW page that was originally
             * RWX gets marked RO+COW. While ARM64 permits instruction fetch
             * from RO pages (when UXN=0), resolve the COW anyway to restore
             * proper page attributes and avoid further faults.
             */
            uint64_t page_va = tf->far & ~(uint64_t)0xFFF;

            pte_t *pte = vmm_get_pte(p->p_vmspace->pgd, page_va);
            if (pte && (*pte & PTE_VALID) && (*pte & PTE_COW)) {
                if (vmm_copy_on_write(p->p_vmspace, page_va) == 0) {
                    /* Flush I-cache for this VA after COW resolution */
                    __asm__ volatile("ic ivau, %0" :: "r"(page_va) : "memory");
                    __asm__ volatile("dsb ish; isb" ::: "memory");
                    handled = true;
                }
            }
        } else if (ifsc == 0x10 && p && p->p_vmspace && p->p_vmspace->pgd) {
            /*
             * External abort on instruction fetch (IFSC=0x10).
             *
             * This can happen when the hardware page table walker encounters
             * stale or incoherent page table entries, particularly after fork
             * when COW pages share physical memory between parent and child.
             *
             * Try a targeted TLB + I-cache invalidation for this VA. If the
             * page is mapped and valid, the re-walk should succeed.
             */
            uint64_t page_va = tf->far & ~(uint64_t)0xFFF;

            pte_t *pte = vmm_get_pte(p->p_vmspace->pgd, page_va);
            if (pte && (*pte & PTE_VALID)) {
                /* Force TLB and I-cache invalidation for this VA */
                __asm__ volatile("tlbi vale1is, %0" :: "r"(page_va >> 12) : "memory");
                __asm__ volatile("dsb ish" ::: "memory");
                __asm__ volatile("ic ivau, %0" :: "r"(page_va) : "memory");
                __asm__ volatile("dsb ish; isb" ::: "memory");

                /* If COW, resolve it */
                if (*pte & PTE_COW) {
                    if (vmm_copy_on_write(p->p_vmspace, page_va) == 0) {
                        __asm__ volatile("ic ivau, %0" :: "r"(page_va) : "memory");
                        __asm__ volatile("dsb ish; isb" ::: "memory");
                    }
                }
                handled = true;
            }
        }

        if (handled)
            break;

        /* Could not resolve — dump debug info and kill */
        kprintf("\n[trap] User instruction abort at FAR=0x%lx PC=0x%lx\n",
                tf->far, tf->elr);
        kprintf("  ESR=0x%lx IFSC=0x%x\n", tf->esr, ifsc);
        kprintf("  x30(LR)=0x%lx SP=0x%lx\n", tf->regs[30], tf->sp);

        if (p) {
            kprintf("  PID=%d name='%s'\n", p->p_pid, p->p_comm);

            if (p->p_vmspace && p->p_vmspace->pgd) {
                uint64_t fault_va = tf->far & ~0xFFFUL;
                uint64_t fault_offset = tf->far & 0xFFFUL;

                /* Do a manual page table walk to verify structure */
                pte_t *pgd = p->p_vmspace->pgd;
                uint64_t l0_idx = (tf->far >> 39) & 0x1FF;
                uint64_t l1_idx = (tf->far >> 30) & 0x1FF;
                uint64_t l2_idx = (tf->far >> 21) & 0x1FF;
                uint64_t l3_idx = (tf->far >> 12) & 0x1FF;

                kprintf("  Page table walk for VA 0x%lx:\n", tf->far);
                kprintf("    L0[%lu] @ %p = 0x%lx\n", l0_idx, &pgd[l0_idx], pgd[l0_idx]);

                if (pgd[l0_idx] & PTE_VALID) {
                    pte_t *l1 = (pte_t *)PTE_TO_PHYS(pgd[l0_idx]);
                    kprintf("    L1[%lu] @ %p = 0x%lx\n", l1_idx, &l1[l1_idx], l1[l1_idx]);

                    if (l1[l1_idx] & PTE_VALID) {
                        pte_t *l2 = (pte_t *)PTE_TO_PHYS(l1[l1_idx]);
                        kprintf("    L2[%lu] @ %p = 0x%lx\n", l2_idx, &l2[l2_idx], l2[l2_idx]);

                        if (l2[l2_idx] & PTE_VALID) {
                            pte_t *l3 = (pte_t *)PTE_TO_PHYS(l2[l2_idx]);
                            kprintf("    L3[%lu] @ %p = 0x%lx\n", l3_idx, &l3[l3_idx], l3[l3_idx]);
                        }
                    }
                }

                pte_t *pte = vmm_get_pte(p->p_vmspace->pgd, fault_va);
                if (pte) {
                    kprintf("  PTE for VA 0x%lx: 0x%lx\n", fault_va, *pte);
                    kprintf("    PA=0x%lx AttrIdx=%lu AP=%lu SH=%lu AF=%lu\n",
                            PTE_TO_PHYS(*pte),
                            (*pte >> 2) & 7,
                            (*pte >> 6) & 3,
                            (*pte >> 8) & 3,
                            (*pte >> 10) & 1);
                    kprintf("    PXN=%lu UXN=%lu COW=%lu\n",
                            (*pte >> 53) & 1,
                            (*pte >> 54) & 1,
                            (*pte >> 55) & 1);

                    /* Dump physical memory content at fault address */
                    uint64_t pa = PTE_TO_PHYS(*pte) + fault_offset;
                    uint32_t *mem = (uint32_t *)pa;
                    kprintf("  Physical mem at 0x%lx: 0x%08x 0x%08x 0x%08x 0x%08x\n",
                            pa, mem[0], mem[1], mem[2], mem[3]);

                    /* Check page refcount */
                    uint32_t refcnt = pmm_page_refcount(PTE_TO_PHYS(*pte));
                    kprintf("  Page refcount: %u\n", refcnt);
                } else {
                    kprintf("  PTE for VA 0x%lx: NULL (not mapped!)\n", fault_va);
                }

                /* Also dump current TTBR0 */
                uint64_t ttbr0;
                __asm__ volatile("mrs %0, ttbr0_el1" : "=r"(ttbr0));
                kprintf("  TTBR0_EL1=0x%lx (expected pgd=0x%lx)\n",
                        ttbr0, (uint64_t)p->p_vmspace->pgd);
            }

            /* Deliver SIGSEGV */
            signal_send_pgid(p->p_pgrp, SIGSEGV);
            signal_check(current_thread_get(), tf);
            break;
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

/* VirtIO-GPU interrupt handler and IRQ query (defined in virtio_gpu.c) */
extern void virtio_gpu_irq_handler(void);
extern uint32_t virtio_gpu_get_irq(void);

/* VirtIO-input interrupt handlers and IRQ queries (defined in virtio_input.c) */
extern void virtio_input_irq_handler(void);
extern uint32_t virtio_input_get_irq(void);
extern void virtio_input_tablet_irq_handler(void);
extern uint32_t virtio_input_tablet_get_irq(void);

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
            if (irq == virtio_gpu_get_irq())
                virtio_gpu_irq_handler();
            else if (irq == virtio_input_get_irq())
                virtio_input_irq_handler();
            else if (irq == virtio_input_tablet_get_irq())
                virtio_input_tablet_irq_handler();
            else
                virtio_net_recv();
        } else {
            kprintf("[irq] Unhandled IRQ %u\n", irq);
        }
        break;
    }
}
