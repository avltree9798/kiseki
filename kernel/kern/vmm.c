/*
 * Kiseki OS - Virtual Memory Manager
 *
 * ARM64 4-level page table (4KB granule).
 * Sets up kernel identity mapping + higher-half mapping,
 * manages user-space page tables per process.
 */

#include <kiseki/types.h>
#include <kiseki/platform.h>
#include <kern/vmm.h>
#include <kern/pmm.h>
#include <kern/kprintf.h>
#include <kern/sync.h>

/* BSD errno values used by vm_map operations */
#ifndef EINVAL
#define EINVAL  22
#endif
#ifndef ENOMEM
#define ENOMEM  12
#endif
#ifndef EACCES
#define EACCES  13
#endif

/* Kernel L0 page table (allocated at init, never freed) */
static pte_t *kernel_pgd;

/* ASID counter */
static uint64_t next_asid = 1;

/* Global VMM lock — protects page table walks that allocate intermediate
 * levels (walk_pgd with alloc=true), ASID assignment, and page table
 * modifications. A coarse global lock for now; a per-vm_space lock
 * would reduce contention but is more complex to retrofit. */
static spinlock_t vmm_lock = SPINLOCK_INIT;

/* --- Helper: zero a page-sized buffer --- */
static void zero_page(void *p)
{
    uint64_t *q = (uint64_t *)p;
    for (int i = 0; i < 512; i++)
        q[i] = 0;
}

/* --- Helper: allocate a zeroed page for page tables --- */
static pte_t *alloc_pt_page(void)
{
    uint64_t pa = pmm_alloc_page();
    if (!pa)
        return NULL;
    /* We're in identity-mapped kernel, so PA == VA (pre-MMU or identity-mapped) */
    zero_page((void *)pa);
    return (pte_t *)pa;
}

/* --- Page table index extraction --- */
#define L0_IDX(va)  (((va) >> 39) & 0x1FF)
#define L1_IDX(va)  (((va) >> 30) & 0x1FF)
#define L2_IDX(va)  (((va) >> 21) & 0x1FF)
#define L3_IDX(va)  (((va) >> 12) & 0x1FF)

/*
 * walk_pgd - Walk page tables, optionally allocating missing levels
 *
 * Returns pointer to the L3 PTE slot for the given VA.
 * If alloc is false and a level is missing, returns NULL.
 */
static pte_t *walk_pgd(pte_t *pgd, uint64_t va, bool alloc)
{
    /* L0 -> L1 */
    pte_t *l0e = &pgd[L0_IDX(va)];
    pte_t *l1;
    if (*l0e & PTE_VALID) {
        l1 = (pte_t *)PTE_TO_PHYS(*l0e);
    } else {
        if (!alloc) return NULL;
        l1 = alloc_pt_page();
        if (!l1) return NULL;
        *l0e = (uint64_t)l1 | PTE_TABLE | PTE_VALID;
        /*
         * DSB ensures the table entry write is visible to the hardware
         * page table walker before we continue. Without this, the walker
         * may see stale/zero data and report a translation fault even
         * though the software sees the correct value (cached).
         *
         * Use DSB ISH (not just ISHST) to ensure all observers see the write,
         * then ISB to synchronise the instruction stream.
         */
        __asm__ volatile("dsb ish" ::: "memory");
#if DEBUG
        kprintf("[walk_pgd] alloc L1: pgd[%lu]=0x%lx -> L1@0x%lx\n",
                L0_IDX(va), *l0e, (uint64_t)l1);
#endif
    }

    /* L1 -> L2 */
    pte_t *l1e = &l1[L1_IDX(va)];
    pte_t *l2;
    if (*l1e & PTE_VALID) {
        l2 = (pte_t *)PTE_TO_PHYS(*l1e);
    } else {
        if (!alloc) return NULL;
        l2 = alloc_pt_page();
        if (!l2) return NULL;
        *l1e = (uint64_t)l2 | PTE_TABLE | PTE_VALID;
        __asm__ volatile("dsb ish" ::: "memory");
#if DEBUG
        kprintf("[walk_pgd] alloc L2: L1[%lu]=0x%lx -> L2@0x%lx (VA=0x%lx)\n",
                L1_IDX(va), *l1e, (uint64_t)l2, va);
#endif
    }

    /* L2 -> L3 */
    pte_t *l2e = &l2[L2_IDX(va)];
    pte_t *l3;
    if (*l2e & PTE_VALID) {
        l3 = (pte_t *)PTE_TO_PHYS(*l2e);
    } else {
        if (!alloc) return NULL;
        l3 = alloc_pt_page();
        if (!l3) return NULL;
        *l2e = (uint64_t)l3 | PTE_TABLE | PTE_VALID;
        __asm__ volatile("dsb ish" ::: "memory");
#if DEBUG
        kprintf("[walk_pgd] alloc L3: L2[%lu]=0x%lx -> L3@0x%lx (VA=0x%lx)\n",
                L2_IDX(va), *l2e, (uint64_t)l3, va);
#endif
    }

    return &l3[L3_IDX(va)];
}

/* --- Public API --- */

int vmm_map_page(pte_t *pgd, uint64_t va, uint64_t pa, uint64_t flags)
{
    uint64_t irq_flags;
    spin_lock_irqsave(&vmm_lock, &irq_flags);

    pte_t *pte = walk_pgd(pgd, va, true);
    if (!pte) {
        spin_unlock_irqrestore(&vmm_lock, irq_flags);
        return -1;
    }
    *pte = (pa & PTE_ADDR_MASK) | flags;

    /*
     * Ensure the L3 PTE write is visible to the hardware page table walker.
     * DSB ISH: Data Synchronization Barrier, Inner Shareable.
     * This ensures all preceding stores to the page tables are complete
     * before any subsequent memory access or page table walk.
     */
    __asm__ volatile("dsb ish" ::: "memory");

#if DEBUG
    if (va >= 0x200000000UL && va < 0x400000000UL) {
        kprintf("[vmm_map_page] VA=0x%lx PA=0x%lx flags=0x%lx pte@0x%lx=0x%lx\n",
                va, pa, flags, (uint64_t)pte, *pte);
    }
#endif

    spin_unlock_irqrestore(&vmm_lock, irq_flags);
    return 0;
}

uint64_t vmm_unmap_page(pte_t *pgd, uint64_t va)
{
    uint64_t irq_flags;
    spin_lock_irqsave(&vmm_lock, &irq_flags);

    pte_t *pte = walk_pgd(pgd, va, false);
    if (!pte || !(*pte & PTE_VALID)) {
        spin_unlock_irqrestore(&vmm_lock, irq_flags);
        return 0;
    }
    uint64_t pa = PTE_TO_PHYS(*pte);
    *pte = 0;
    /* Invalidate TLB for this VA across ALL ASIDs. */
    __asm__ volatile("tlbi vaae1, %0" :: "r"(va >> 12));
    __asm__ volatile("dsb sy; isb");

    spin_unlock_irqrestore(&vmm_lock, irq_flags);
    return pa;
}

int vmm_map_range(pte_t *pgd, uint64_t va_start, uint64_t pa_start,
                  uint64_t size, uint64_t flags)
{
    for (uint64_t off = 0; off < size; off += PAGE_SIZE) {
        if (vmm_map_page(pgd, va_start + off, pa_start + off, flags) < 0)
            return -1;
    }
    return 0;
}

uint64_t vmm_translate(pte_t *pgd, uint64_t va)
{
    uint64_t irq_flags;
    spin_lock_irqsave(&vmm_lock, &irq_flags);

    pte_t *pte = walk_pgd(pgd, va, false);
    if (!pte || !(*pte & PTE_VALID)) {
        spin_unlock_irqrestore(&vmm_lock, irq_flags);
        return 0;
    }
    uint64_t pa = PTE_TO_PHYS(*pte) | (va & (PAGE_SIZE - 1));

    spin_unlock_irqrestore(&vmm_lock, irq_flags);
    return pa;
}

/*
 * vmm_init - Set up kernel page tables and enable the MMU
 *
 * Creates identity mapping for:
 *   1. Kernel text/data/BSS (normal cacheable)
 *   2. Device MMIO regions (device non-cacheable)
 *   3. All RAM for the physical allocator
 *
 * Then sets MAIR, TCR, TTBR1, and enables the MMU.
 */
void vmm_init(void)
{
    /* Linker symbols not needed here (pmm already knows heap start) */

    kernel_pgd = alloc_pt_page();
    if (!kernel_pgd)
        panic("vmm_init: cannot allocate kernel L0 table");

    kprintf("[vmm] Kernel L0 table at 0x%lx\n", (uint64_t)kernel_pgd);

    /*
     * Identity map all of RAM (simplified: map 0..RAM_SIZE).
     * This lets us access physical addresses directly.
     * A proper higher-half mapping would offset by KERNEL_VA_BASE,
     * but for now identity mapping is simpler and works.
     */
    uint64_t ram_end = RAM_BASE + RAM_SIZE;
    kprintf("[vmm] Identity mapping RAM: 0x%lx - 0x%lx\n", RAM_BASE, ram_end);

    for (uint64_t addr = RAM_BASE; addr < ram_end; addr += PAGE_SIZE) {
        vmm_map_page(kernel_pgd, addr, addr, PTE_KERNEL_RWX);
    }

    /* Map UART MMIO as device memory */
    vmm_map_page(kernel_pgd, UART0_BASE, UART0_BASE, PTE_DEVICE);

    /* Map GIC MMIO */
    for (uint64_t off = 0; off < 0x10000; off += PAGE_SIZE) {
        vmm_map_page(kernel_pgd, GICD_BASE + off, GICD_BASE + off, PTE_DEVICE);
        vmm_map_page(kernel_pgd, GICC_BASE + off, GICC_BASE + off, PTE_DEVICE);
    }

#ifdef PLATFORM_QEMU
    /* Map virtio MMIO region */
    for (uint32_t i = 0; i < VIRTIO_MMIO_COUNT; i++) {
        uint64_t base = VIRTIO_MMIO_BASE + i * VIRTIO_MMIO_STRIDE;
        vmm_map_page(kernel_pgd, base, base, PTE_DEVICE);
    }
#endif

    /*
     * Configure MAIR_EL1 (Memory Attribute Indirection Register)
     *
     * Index 0: Device-nGnRnE (0x00)
     * Index 1: Normal Non-Cacheable (0x44)
     * Index 2: Normal Write-Back Cacheable (0xFF)
     */
    uint64_t mair = (0x00UL << (MAIR_DEVICE_nGnRnE * 8)) |
                    (0x44UL << (MAIR_NORMAL_NC * 8)) |
                    (0xFFUL << (MAIR_NORMAL_WB * 8));
    __asm__ volatile("msr mair_el1, %0" :: "r"(mair));

    /*
     * Configure TCR_EL1 (Translation Control Register)
     *
     * T0SZ = 16 (48-bit user VA space)
     * T1SZ = 16 (48-bit kernel VA space) - not used yet
     * TG0  = 0  (4KB granule for TTBR0)
     * TG1  = 2  (4KB granule for TTBR1)
     * SH0  = 3  (Inner shareable)
     * ORGN0 = 1 (Write-Back, Write-Allocate)
     * IRGN0 = 1 (Write-Back, Write-Allocate)
     */
    uint64_t tcr = (16UL << 0)  |   /* T0SZ */
                   (16UL << 16) |   /* T1SZ */
                   (0UL << 14)  |   /* TG0 = 4KB */
                   (2UL << 30)  |   /* TG1 = 4KB */
                   (3UL << 12)  |   /* SH0 = Inner shareable */
                   (1UL << 10)  |   /* ORGN0 = WB WA */
                   (1UL << 8)   |   /* IRGN0 = WB WA */
                   (3UL << 28)  |   /* SH1 = Inner shareable */
                   (1UL << 26)  |   /* ORGN1 = WB WA */
                   (1UL << 24);     /* IRGN1 = WB WA */
    __asm__ volatile("msr tcr_el1, %0" :: "r"(tcr));

    /* Set TTBR0_EL1 for identity-mapped kernel (we use lower half for now) */
    __asm__ volatile("msr ttbr0_el1, %0" :: "r"((uint64_t)kernel_pgd));

    /* Set TTBR1_EL1 for kernel higher-half (same table for now) */
    __asm__ volatile("msr ttbr1_el1, %0" :: "r"((uint64_t)kernel_pgd));

    /* Ensure all writes are visible before enabling MMU */
    __asm__ volatile("isb");
    __asm__ volatile("dsb sy");
    __asm__ volatile("tlbi vmalle1");
    __asm__ volatile("dsb sy");
    __asm__ volatile("isb");

    /* Enable MMU: set SCTLR_EL1.M (bit 0) and caches */
    uint64_t sctlr;
    __asm__ volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
    sctlr |= (1UL << 0);   /* M: MMU enable */
    sctlr |= (1UL << 2);   /* C: Data cache enable */
    sctlr |= (1UL << 12);  /* I: Instruction cache enable */
    __asm__ volatile("msr sctlr_el1, %0" :: "r"(sctlr));
    __asm__ volatile("isb");

    kprintf("[vmm] MMU enabled\n");
}

/* --- User address space management --- */

struct vm_space *vmm_create_space(void)
{
    /* Allocate vm_space struct from a page (wasteful but simple for now) */
    uint64_t pa = pmm_alloc_page();
    if (!pa) return NULL;
    struct vm_space *space = (struct vm_space *)pa;

    space->pgd = alloc_pt_page();
    if (!space->pgd) {
        pmm_free_page(pa);
        return NULL;
    }

    /*
     * Share the kernel's lower-half page table entries with this user space.
     *
     * The kernel runs in the lower half (TTBR0) with identity mapping.
     * When we switch TTBR0 to a user page table and take an exception,
     * the CPU needs to find kernel code/data at their identity-mapped
     * addresses.
     *
     * IMPORTANT: We cannot simply copy L0 entries from kernel_pgd,
     * because L0[0] covers 512GB (0x0 - 0x7FFFFFFFFF), which includes
     * BOTH kernel addresses (RAM at 0x40000000, MMIO at 0x08000000)
     * AND user addresses (main binary at 0x100000000, dyld at
     * 0x200000000, mmap at 0x300000000). If we shared the kernel's L0[0]
     * directly, all processes would share the same L1 table, and
     * walk_pgd would allocate user L2/L3 entries inside the kernel's L1,
     * causing cross-process page table corruption.
     *
     * Solution: for L0 entries that the kernel uses, allocate a SEPARATE
     * L1 table per process and copy only the kernel's L1 entries into it.
     * User L1 entries (for L1 indices not used by the kernel) start empty
     * and get their own L2/L3 allocations via walk_pgd.
     */
    if (kernel_pgd != NULL) {
        for (int i = 0; i < PT_ENTRIES; i++) {
            if (!(kernel_pgd[i] & PTE_VALID))
                continue;

            /*
             * Allocate a per-process L1 table and copy the kernel's
             * L1 entries into it. This gives the process its own L1
             * so that walk_pgd allocations for user VAs in this L0
             * range don't pollute the kernel's page tables.
             */
            pte_t *kernel_l1 = (pte_t *)PTE_TO_PHYS(kernel_pgd[i]);
            pte_t *user_l1 = alloc_pt_page();
            if (!user_l1) {
                /* OOM — free what we've allocated so far */
                pmm_free_page((uint64_t)space->pgd);
                pmm_free_page(pa);
                return NULL;
            }

            /* Copy kernel L1 entries (identity mapping, MMIO, etc.) */
            for (int j = 0; j < PT_ENTRIES; j++) {
                user_l1[j] = kernel_l1[j];
            }

            /* Install the per-process L1 in the user's L0 */
            space->pgd[i] = (uint64_t)user_l1 | PTE_TABLE | PTE_VALID;
        }
    }

    /*
     * Assign ASID. TCR_EL1.AS=0 → 8-bit ASIDs (0-255).
     * ASID 0 is reserved for the kernel identity mapping (used in bare
     * TTBR0 writes like the kernel PGD switch in proc_exit/exec).
     * So user ASIDs range from 1 to 255. When we wrap, flush the entire
     * TLB so stale entries from the previous generation can't alias.
     */
    /*
     * Create the vm_map for this address space.
     *
     * The user VA layout is:
     *   0x100000000 — Mach-O main binary
     *   0x200000000 — dyld
     *   0x300000000 — mmap region
     *   ...
     *   0x7FFFFFFF0000 — user stack top
     *
     * We set min_offset to 0 (some regions like commpage are below
     * USER_VA_BASE) and max_offset to just above the stack.
     */
    space->map = vm_map_create(0, USER_STACK_TOP + PAGE_SIZE);
    if (!space->map) {
        /* OOM — clean up and fail */
        /* Free per-process L1 tables */
        for (int i = 0; i < PT_ENTRIES; i++) {
            if (space->pgd[i] & PTE_VALID)
                pmm_free_page(PTE_TO_PHYS(space->pgd[i]));
        }
        pmm_free_page((uint64_t)space->pgd);
        pmm_free_page(pa);
        return NULL;
    }

    uint64_t irq_flags;
    spin_lock_irqsave(&vmm_lock, &irq_flags);
    space->asid = next_asid++;
    if (next_asid > 255) {
        next_asid = 1;
        /* Broadcast TLB invalidate for SMP when ASIDs wrap */
        __asm__ volatile("tlbi vmalle1is; dsb ish; isb" ::: "memory");
    }
    spin_unlock_irqrestore(&vmm_lock, irq_flags);
    return space;
}

/*
 * destroy_l2_subtree - Free an L2 table, its L3 tables, and all data pages
 */
static void destroy_l2_subtree(pte_t *l2)
{
    for (int i2 = 0; i2 < PT_ENTRIES; i2++) {
        if (!(l2[i2] & PTE_VALID))
            continue;

        pte_t *l3 = (pte_t *)PTE_TO_PHYS(l2[i2]);

        for (int i3 = 0; i3 < PT_ENTRIES; i3++) {
            if (!(l3[i3] & PTE_VALID))
                continue;
            /* Release the data page (respects refcount for shared pages
                         * like the commpage). Pages with refcount=1 get freed
                         * immediately; shared pages just have their count
                         * decremented. */
                        pmm_page_unref(PTE_TO_PHYS(l3[i3]));
        }

        /* Free the L3 table page */
        pmm_free_page((uint64_t)l3);
    }

    /* Free the L2 table page */
    pmm_free_page((uint64_t)l2);
}

void vmm_destroy_space(struct vm_space *space)
{
    if (!space) return;

    uint64_t irq_flags;
    spin_lock_irqsave(&vmm_lock, &irq_flags);

    if (space->pgd) {
        pte_t *l0 = space->pgd;

        for (int i0 = 0; i0 < PT_ENTRIES; i0++) {
            if (!(l0[i0] & PTE_VALID))
                continue;

            pte_t *l1 = (pte_t *)PTE_TO_PHYS(l0[i0]);

            /*
             * Determine if this L0 entry corresponds to a kernel L0 slot.
             *
             * vmm_create_space allocates a per-process L1 for each valid
             * kernel L0 entry and copies the kernel's L1 entries into it.
             * We must NOT free L1 entries that point into the kernel's
             * L2/L3 hierarchy (those are shared). We identify them by
             * comparing against the kernel's L1 table at the same L0 index.
             *
             * For L0 entries that have NO kernel counterpart (e.g., the
             * user stack at L0=255), all L1 entries are user-owned.
             */
            pte_t *kernel_l1 = NULL;
            if (kernel_pgd && (kernel_pgd[i0] & PTE_VALID)) {
                kernel_l1 = (pte_t *)PTE_TO_PHYS(kernel_pgd[i0]);
            }

            for (int i1 = 0; i1 < PT_ENTRIES; i1++) {
                if (!(l1[i1] & PTE_VALID))
                    continue;

                /*
                 * Skip L1 entries that came from the kernel. These point
                 * to the kernel's L2 tables (identity mapping, MMIO, etc.)
                 * and must not be freed.
                 */
                if (kernel_l1 && l1[i1] == kernel_l1[i1])
                    continue;

                pte_t *l2 = (pte_t *)PTE_TO_PHYS(l1[i1]);
                destroy_l2_subtree(l2);
            }

            /* Free the per-process L1 table page.
             * For kernel-shared L0 indices, this is the per-process copy
             * allocated in vmm_create_space. For purely user L0 indices,
             * this is the L1 allocated by walk_pgd. */
            pmm_free_page((uint64_t)l1);
        }

        /* Free the L0 table page */
        pmm_free_page((uint64_t)space->pgd);
    }

    /* Free the vm_map */
    if (space->map) {
        spin_unlock_irqrestore(&vmm_lock, irq_flags);
        vm_map_destroy(space->map);
        spin_lock_irqsave(&vmm_lock, &irq_flags);
    }

    /* Free the vm_space struct itself */
    pmm_free_page((uint64_t)space);

    spin_unlock_irqrestore(&vmm_lock, irq_flags);
}

void vmm_switch_space(struct vm_space *space)
{
    uint64_t ttbr0 = (uint64_t)space->pgd | (space->asid << 48);

    /* Debug TTBR0 switch logging removed (too verbose for per-switch) */

    __asm__ volatile("msr ttbr0_el1, %0" :: "r"(ttbr0));
    /*
     * Full TLB invalidation on every TTBR0 switch.
     *
     * With only 8-bit ASIDs (TCR_EL1.AS=0) and no ASID recycling logic,
     * stale TLB entries from previous address spaces can alias after
     * wrapping. A full tlbi vmalle1is is the safe approach for SMP.
     * Once we have proper ASID lifecycle management we can switch to
     * targeted invalidation (tlbi aside1is) or skip the flush when
     * ASIDs differ.
     *
     * Use Inner Shareable variant (vmalle1is) to broadcast to all CPUs.
     */
    __asm__ volatile("tlbi vmalle1is" ::: "memory");
    __asm__ volatile("dsb ish" ::: "memory");
    __asm__ volatile("isb");
}

int vmm_copy_on_write(struct vm_space *space, uint64_t va)
{
    uint64_t irq_flags;
    spin_lock_irqsave(&vmm_lock, &irq_flags);

    pte_t *pte = walk_pgd(space->pgd, va, false);
    if (!pte || !(*pte & PTE_VALID)) {
        spin_unlock_irqrestore(&vmm_lock, irq_flags);
        return -1;
    }

    uint64_t old_pa = PTE_TO_PHYS(*pte);
    uint32_t refcount = pmm_page_refcount(old_pa);

    /*
     * Preserve the original flags (UXN, PXN, cacheability, etc.) but
     * change the AP bits from RO to RW. This avoids destroying execute
     * permission on __TEXT pages.
     *
     * AP field is bits [7:6]. Clear them and set AP_RW_ALL (bit 6).
     * Also clear the PTE_COW bit since the page is no longer shared.
     */
    uint64_t orig_flags = *pte & ~PTE_ADDR_MASK;
    uint64_t new_flags = (orig_flags & ~(3UL << 6) & ~PTE_COW) | PTE_AP_RW_ALL;

    if (refcount <= 1) {
        /* Sole owner — make writable in-place */
        *pte = (old_pa & PTE_ADDR_MASK) | new_flags;
        /* Use Inner Shareable TLBI for SMP correctness */
        __asm__ volatile("tlbi vale1is, %0" :: "r"(va >> 12) : "memory");
        __asm__ volatile("dsb ish; isb" ::: "memory");
        spin_unlock_irqrestore(&vmm_lock, irq_flags);
        return 0;
    }

    /* Multiple owners: copy the page */
    spin_unlock_irqrestore(&vmm_lock, irq_flags);

    uint64_t new_pa = pmm_alloc_page();
    if (!new_pa)
        return -1;

    /* Copy 4KB */
    uint64_t *src = (uint64_t *)old_pa;
    uint64_t *dst = (uint64_t *)new_pa;
    for (int i = 0; i < 512; i++)
        dst[i] = src[i];

    /* Re-acquire lock to update PTE */
    spin_lock_irqsave(&vmm_lock, &irq_flags);

    /* Map the new page with writable flags (preserving XN bits) */
    *pte = (new_pa & PTE_ADDR_MASK) | new_flags;

    /* Drop reference on old page */
    pmm_page_unref(old_pa);

    /* Use Inner Shareable TLBI for SMP correctness */
    __asm__ volatile("tlbi vale1is, %0" :: "r"(va >> 12) : "memory");
    __asm__ volatile("dsb ish; isb" ::: "memory");

    spin_unlock_irqrestore(&vmm_lock, irq_flags);
    return 0;
}

pte_t *vmm_get_kernel_pgd(void)
{
    return kernel_pgd;
}

/*
 * vmm_init_percpu - Enable the MMU on a secondary CPU core
 *
 * Secondary cores start with the MMU off (PSCI CPU_ON brings up cores
 * with SCTLR_EL1 at reset value). They must configure MAIR, TCR,
 * TTBR0/TTBR1 identically to the boot CPU (set up by vmm_init()),
 * then enable the MMU+caches before touching any spinlocks or shared
 * data structures.  Without cacheable memory, the exclusive monitor
 * (LDAXR/STXR) used by spinlocks may not function correctly across
 * cores, and cached stores from the boot CPU may be invisible.
 */
void vmm_init_percpu(void)
{
    /* MAIR: must match vmm_init() exactly */
    uint64_t mair = (0x00UL << (MAIR_DEVICE_nGnRnE * 8)) |
                    (0x44UL << (MAIR_NORMAL_NC * 8)) |
                    (0xFFUL << (MAIR_NORMAL_WB * 8));
    __asm__ volatile("msr mair_el1, %0" :: "r"(mair));

    /* TCR: must match vmm_init() exactly */
    uint64_t tcr = (16UL << 0)  |   /* T0SZ */
                   (16UL << 16) |   /* T1SZ */
                   (0UL << 14)  |   /* TG0 = 4KB */
                   (2UL << 30)  |   /* TG1 = 4KB */
                   (3UL << 12)  |   /* SH0 = Inner shareable */
                   (1UL << 10)  |   /* ORGN0 = WB WA */
                   (1UL << 8)   |   /* IRGN0 = WB WA */
                   (3UL << 28)  |   /* SH1 = Inner shareable */
                   (1UL << 26)  |   /* ORGN1 = WB WA */
                   (1UL << 24);     /* IRGN1 = WB WA */
    __asm__ volatile("msr tcr_el1, %0" :: "r"(tcr));

    /* Load the same kernel page tables that CPU0 set up */
    __asm__ volatile("msr ttbr0_el1, %0" :: "r"((uint64_t)kernel_pgd));
    __asm__ volatile("msr ttbr1_el1, %0" :: "r"((uint64_t)kernel_pgd));

    /* Barriers + TLB invalidate before enabling */
    __asm__ volatile("isb");
    __asm__ volatile("dsb sy");
    __asm__ volatile("tlbi vmalle1");
    __asm__ volatile("dsb sy");
    __asm__ volatile("isb");

    /* Enable MMU + caches */
    uint64_t sctlr;
    __asm__ volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
    sctlr |= (1UL << 0);   /* M: MMU enable */
    sctlr |= (1UL << 2);   /* C: Data cache enable */
    sctlr |= (1UL << 12);  /* I: Instruction cache enable */
    __asm__ volatile("msr sctlr_el1, %0" :: "r"(sctlr));
    __asm__ volatile("isb");
}

int vmm_protect_page(pte_t *pgd, uint64_t va, uint64_t new_flags)
{
    uint64_t irq_flags;
    spin_lock_irqsave(&vmm_lock, &irq_flags);

    pte_t *pte = walk_pgd(pgd, va, false);
    if (!pte || !(*pte & PTE_VALID)) {
        spin_unlock_irqrestore(&vmm_lock, irq_flags);
        return -1;
    }

    uint64_t pa = PTE_TO_PHYS(*pte);
    *pte = (pa & PTE_ADDR_MASK) | new_flags;

    /* Invalidate TLB for this VA (all ASIDs since we use vmalle1 on switch) */
    __asm__ volatile("tlbi vale1, %0" :: "r"(va >> 12));
    __asm__ volatile("dsb sy; isb");

    spin_unlock_irqrestore(&vmm_lock, irq_flags);
    return 0;
}

pte_t *vmm_get_pte(pte_t *pgd, uint64_t va)
{
    return walk_pgd(pgd, va, false);
}

/* ============================================================================
 * VM Map — Region-level virtual memory management
 *
 * Modelled on XNU's vm_map (osfmk/vm/vm_map.c). Tracks what virtual
 * address regions are mapped, with what protections, inheritance, and
 * backing store. The vm_map is authoritative; the pmap (hardware page
 * tables) is a cache.
 *
 * Implementation uses a sentinel-headed sorted doubly-linked list of
 * vm_map_entry structures. XNU also uses an RB-tree for O(log n) lookup;
 * we omit that for now and use linear search — sufficient for the current
 * scale of ~50-100 entries per process.
 * ============================================================================ */

/*
 * vm_map_alloc_entry - Allocate an entry from the map's static pool
 */
static struct vm_map_entry *vm_map_alloc_entry(struct vm_map *map)
{
    for (int i = 0; i < VM_MAP_ENTRIES_MAX; i++) {
        if (!map->entry_used[i]) {
            map->entry_used[i] = 1;
            struct vm_map_entry *e = &map->entries[i];
            e->prev = NULL;
            e->next = NULL;
            e->vme_start = 0;
            e->vme_end = 0;
            e->protection = 0;
            e->max_protection = 0;
            e->inheritance = VM_INHERIT_DEFAULT;
            e->is_shared = 0;
            e->needs_copy = 0;
            e->wired = 0;
            e->_pad_bits = 0;
            e->backing_fd = -1;
            e->file_offset = 0;
            e->backing_vnode = NULL;
            return e;
        }
    }
    return NULL;  /* Pool exhausted */
}

/*
 * vm_map_free_entry - Return an entry to the map's static pool
 */
static void vm_map_free_entry(struct vm_map *map, struct vm_map_entry *entry)
{
    /* Calculate index from pointer arithmetic */
    int idx = (int)(entry - map->entries);
    if (idx >= 0 && idx < VM_MAP_ENTRIES_MAX) {
        map->entry_used[idx] = 0;
    }
}

/*
 * vm_map_entry_link - Insert entry into the list after the given predecessor
 */
static void vm_map_entry_link(struct vm_map_entry *after,
                              struct vm_map_entry *entry)
{
    entry->prev = after;
    entry->next = after->next;
    after->next->prev = entry;
    after->next = entry;
}

/*
 * vm_map_entry_unlink - Remove entry from the list
 */
static void vm_map_entry_unlink(struct vm_map_entry *entry)
{
    entry->prev->next = entry->next;
    entry->next->prev = entry->prev;
    entry->prev = NULL;
    entry->next = NULL;
}

/* --- Public VM Map API --- */

struct vm_map *vm_map_create(uint64_t min_offset, uint64_t max_offset)
{
    /*
     * Allocate a vm_map from physical pages. The struct is large due to
     * the static entry pool, so we allocate enough contiguous pages.
     */
    uint64_t map_size = sizeof(struct vm_map);
    uint64_t pages_needed = (map_size + PAGE_SIZE - 1) / PAGE_SIZE;

    /* Use the buddy allocator for multi-page allocation */
    uint32_t order = 0;
    while ((1UL << order) < pages_needed)
        order++;

    uint64_t pa = pmm_alloc_pages(order);
    if (!pa)
        return NULL;

    struct vm_map *map = (struct vm_map *)pa;

    /* Zero the entire allocation */
    uint8_t *p = (uint8_t *)pa;
    for (uint64_t i = 0; i < (1UL << order) * PAGE_SIZE; i++)
        p[i] = 0;

    /* Initialise sentinel — points to itself (empty list) */
    map->header.prev = &map->header;
    map->header.next = &map->header;
    map->header.vme_start = min_offset;
    map->header.vme_end = max_offset;

    map->nentries = 0;
    map->min_offset = min_offset;
    map->max_offset = max_offset;
    /*
     * hint_addr controls where vm_map_find_space starts searching for
     * free gaps. Setting it to USER_MMAP_BASE (0x300000000) ensures
     * that the first anonymous mmap does not return VA 0, which
     * userspace (dyld, libSystem) interprets as NULL / failure.
     *
     * Fixed mappings (MAP_FIXED) bypass the hint entirely, so Mach-O
     * load addresses at 0x100000000 and dyld at 0x200000000 still work.
     */
    map->hint_addr = (min_offset < USER_MMAP_BASE && max_offset > USER_MMAP_BASE)
                     ? USER_MMAP_BASE : min_offset;
    map->lock = (spinlock_t)SPINLOCK_INIT;

    return map;
}

void vm_map_destroy(struct vm_map *map)
{
    if (!map)
        return;

    /* Free the allocation. Calculate order from struct size. */
    uint64_t map_size = sizeof(struct vm_map);
    uint64_t pages_needed = (map_size + PAGE_SIZE - 1) / PAGE_SIZE;
    uint32_t order = 0;
    while ((1UL << order) < pages_needed)
        order++;

    pmm_free_pages((uint64_t)map, order);
}

bool vm_map_lookup_entry(struct vm_map *map, uint64_t addr,
                         struct vm_map_entry **entry)
{
    /*
     * Walk the sorted list to find the entry containing addr, or the
     * entry just before the gap where addr falls.
     *
     * XNU checks a hint cache first, then falls through to RB-tree.
     * We do a simple linear scan — sufficient for ~100 entries.
     */
    struct vm_map_entry *cur = map->header.next;
    struct vm_map_entry *prev = &map->header;

    while (cur != &map->header) {
        if (addr < cur->vme_start) {
            /* addr is in the gap before cur */
            *entry = prev;
            return false;
        }
        if (addr < cur->vme_end) {
            /* addr is within cur */
            *entry = cur;
            return true;
        }
        prev = cur;
        cur = cur->next;
    }

    /* addr is past all entries */
    *entry = prev;
    return false;
}

/*
 * vm_map_find_space - Find a free gap of at least 'size' bytes
 *
 * Searches from hint_addr forward, wrapping once if needed.
 * Returns the start address of the gap, or 0 on failure.
 */
static uint64_t vm_map_find_space(struct vm_map *map, uint64_t size)
{
    uint64_t start = ALIGN_UP(map->hint_addr, PAGE_SIZE);

    /* Walk entries to find a gap */
    struct vm_map_entry *cur = map->header.next;

    /* Skip entries that end before our search start */
    while (cur != &map->header && cur->vme_end <= start)
        cur = cur->next;

    /* Try to fit in gaps */
    while (cur != &map->header) {
        /* Gap is [start, cur->vme_start) */
        if (start + size <= cur->vme_start && start + size <= map->max_offset) {
            map->hint_addr = start + size;
            return start;
        }
        /* Move past this entry */
        start = ALIGN_UP(cur->vme_end, PAGE_SIZE);
        cur = cur->next;
    }

    /* Gap after last entry: [start, max_offset) */
    if (start + size <= map->max_offset) {
        map->hint_addr = start + size;
        return start;
    }

    /* Wrap: try from min_offset if hint was past the start */
    if (map->hint_addr > map->min_offset) {
        start = ALIGN_UP(map->min_offset, PAGE_SIZE);
        cur = map->header.next;

        while (cur != &map->header) {
            if (start + size <= cur->vme_start && start + size <= map->max_offset) {
                map->hint_addr = start + size;
                return start;
            }
            start = ALIGN_UP(cur->vme_end, PAGE_SIZE);
            cur = cur->next;
        }
        if (start + size <= map->max_offset) {
            map->hint_addr = start + size;
            return start;
        }
    }

    return 0;  /* No space found */
}

int vm_map_enter(struct vm_map *map, uint64_t *addr, uint64_t size,
                 uint8_t protection, uint8_t max_protection,
                 uint8_t inheritance, bool is_shared,
                 int fd, uint64_t file_offset, struct vnode *vnode)
{
    if (size == 0 || (size & (PAGE_SIZE - 1)))
        return -EINVAL;

    uint64_t irq_flags;
    spin_lock_irqsave(&map->lock, &irq_flags);

    uint64_t map_addr;
    bool fixed = (*addr != 0);

    if (fixed) {
        /* MAP_FIXED — use the exact address. Check for overlap. */
        map_addr = *addr;
        if (map_addr < map->min_offset || map_addr + size > map->max_offset) {
            spin_unlock_irqrestore(&map->lock, irq_flags);
            return -EINVAL;
        }

        /* Check that the range doesn't overlap existing entries */
        struct vm_map_entry *cur = map->header.next;
        while (cur != &map->header) {
            if (cur->vme_start < map_addr + size &&
                cur->vme_end > map_addr) {
                /*
                 * Overlap detected. XNU's MAP_FIXED with vmf_overwrite
                 * removes existing entries. We do the same.
                 */
                spin_unlock_irqrestore(&map->lock, irq_flags);
                vm_map_remove(map, map_addr, map_addr + size);
                spin_lock_irqsave(&map->lock, &irq_flags);
                break;
            }
            cur = cur->next;
        }
    } else {
        /* Find free space */
        map_addr = vm_map_find_space(map, size);
        if (map_addr == 0) {
            spin_unlock_irqrestore(&map->lock, irq_flags);
            return -ENOMEM;
        }
    }

    /* Allocate an entry */
    struct vm_map_entry *new_entry = vm_map_alloc_entry(map);
    if (!new_entry) {
        spin_unlock_irqrestore(&map->lock, irq_flags);
        return -ENOMEM;
    }

    new_entry->vme_start = map_addr;
    new_entry->vme_end = map_addr + size;
    new_entry->protection = protection;
    new_entry->max_protection = max_protection;
    new_entry->inheritance = inheritance;
    new_entry->is_shared = is_shared ? 1 : 0;
    new_entry->needs_copy = 0;
    new_entry->backing_fd = fd;
    new_entry->file_offset = file_offset;
    new_entry->backing_vnode = vnode;

    /* Find insertion point — after the last entry with vme_start <= map_addr */
    struct vm_map_entry *after = &map->header;
    struct vm_map_entry *cur = map->header.next;
    while (cur != &map->header && cur->vme_start <= map_addr) {
        after = cur;
        cur = cur->next;
    }

    vm_map_entry_link(after, new_entry);
    map->nentries++;

    *addr = map_addr;
    spin_unlock_irqrestore(&map->lock, irq_flags);
    return 0;
}

/*
 * vm_map_clip_start - Split an entry at 'start'
 *
 * If start is within the entry (not at the beginning), splits the entry
 * into two: [vme_start, start) and [start, vme_end).
 */
static int vm_map_clip_start(struct vm_map *map, struct vm_map_entry *entry,
                             uint64_t start)
{
    if (start <= entry->vme_start)
        return 0;  /* Nothing to clip */
    if (start >= entry->vme_end)
        return 0;

    /* Allocate a new entry for the left portion */
    struct vm_map_entry *left = vm_map_alloc_entry(map);
    if (!left)
        return -ENOMEM;

    /* Left gets [vme_start, start) */
    left->vme_start = entry->vme_start;
    left->vme_end = start;
    left->protection = entry->protection;
    left->max_protection = entry->max_protection;
    left->inheritance = entry->inheritance;
    left->is_shared = entry->is_shared;
    left->needs_copy = entry->needs_copy;
    left->wired = entry->wired;
    left->backing_fd = entry->backing_fd;
    left->file_offset = entry->file_offset;
    left->backing_vnode = entry->backing_vnode;

    /* Original entry shrinks to [start, vme_end) */
    uint64_t removed_size = start - entry->vme_start;
    entry->vme_start = start;
    if (entry->backing_vnode)
        entry->file_offset += removed_size;

    /* Insert left before entry */
    vm_map_entry_link(entry->prev, left);
    map->nentries++;

    return 0;
}

/*
 * vm_map_clip_end - Split an entry at 'end'
 *
 * If end is within the entry (not at the end), splits the entry
 * into two: [vme_start, end) and [end, vme_end).
 */
static int vm_map_clip_end(struct vm_map *map, struct vm_map_entry *entry,
                           uint64_t end)
{
    if (end >= entry->vme_end)
        return 0;
    if (end <= entry->vme_start)
        return 0;

    /* Allocate a new entry for the right portion */
    struct vm_map_entry *right = vm_map_alloc_entry(map);
    if (!right)
        return -ENOMEM;

    /* Right gets [end, vme_end) */
    right->vme_start = end;
    right->vme_end = entry->vme_end;
    right->protection = entry->protection;
    right->max_protection = entry->max_protection;
    right->inheritance = entry->inheritance;
    right->is_shared = entry->is_shared;
    right->needs_copy = entry->needs_copy;
    right->wired = entry->wired;
    right->backing_fd = entry->backing_fd;
    if (entry->backing_vnode)
        right->file_offset = entry->file_offset + (end - entry->vme_start);
    else
        right->file_offset = 0;
    right->backing_vnode = entry->backing_vnode;

    /* Original entry shrinks to [vme_start, end) */
    entry->vme_end = end;

    /* Insert right after entry */
    vm_map_entry_link(entry, right);
    map->nentries++;

    return 0;
}

int vm_map_remove(struct vm_map *map, uint64_t start, uint64_t end)
{
    uint64_t irq_flags;
    spin_lock_irqsave(&map->lock, &irq_flags);

    /* Find the first entry that could overlap [start, end) */
    struct vm_map_entry *cur = map->header.next;
    while (cur != &map->header && cur->vme_end <= start)
        cur = cur->next;

    if (cur == &map->header || cur->vme_start >= end) {
        /* No overlap */
        spin_unlock_irqrestore(&map->lock, irq_flags);
        return 0;
    }

    /* Clip the first overlapping entry at 'start' */
    int ret = vm_map_clip_start(map, cur, start);
    if (ret != 0) {
        spin_unlock_irqrestore(&map->lock, irq_flags);
        return ret;
    }

    /* Re-find after potential clip */
    cur = map->header.next;
    while (cur != &map->header && cur->vme_end <= start)
        cur = cur->next;

    /* Clip the last overlapping entry at 'end' */
    struct vm_map_entry *last = cur;
    while (last != &map->header && last->vme_start < end) {
        if (last->vme_end > end) {
            ret = vm_map_clip_end(map, last, end);
            if (ret != 0) {
                spin_unlock_irqrestore(&map->lock, irq_flags);
                return ret;
            }
            break;
        }
        last = last->next;
    }

    /* Remove all entries fully within [start, end) */
    cur = map->header.next;
    while (cur != &map->header && cur->vme_end <= start)
        cur = cur->next;

    while (cur != &map->header && cur->vme_start < end) {
        struct vm_map_entry *next = cur->next;
        vm_map_entry_unlink(cur);
        vm_map_free_entry(map, cur);
        map->nentries--;
        cur = next;
    }

    spin_unlock_irqrestore(&map->lock, irq_flags);
    return 0;
}

int vm_map_protect(struct vm_map *map, uint64_t start, uint64_t end,
                   uint8_t new_prot)
{
    uint64_t irq_flags;
    spin_lock_irqsave(&map->lock, &irq_flags);

    /* Find first overlapping entry */
    struct vm_map_entry *cur = map->header.next;
    while (cur != &map->header && cur->vme_end <= start)
        cur = cur->next;

    if (cur == &map->header || cur->vme_start >= end) {
        spin_unlock_irqrestore(&map->lock, irq_flags);
        return -ENOMEM;  /* No entries in range */
    }

    /* Clip at boundaries */
    int ret = vm_map_clip_start(map, cur, start);
    if (ret != 0) {
        spin_unlock_irqrestore(&map->lock, irq_flags);
        return ret;
    }

    /* Re-find after clip */
    cur = map->header.next;
    while (cur != &map->header && cur->vme_end <= start)
        cur = cur->next;

    /* Walk entries in range and update protection */
    while (cur != &map->header && cur->vme_start < end) {
        /* Clip end if this entry extends past our range */
        ret = vm_map_clip_end(map, cur, end);
        if (ret != 0) {
            spin_unlock_irqrestore(&map->lock, irq_flags);
            return ret;
        }

        /* Check max_protection allows the new protection */
        if ((new_prot & ~cur->max_protection) != 0) {
            spin_unlock_irqrestore(&map->lock, irq_flags);
            return -EACCES;
        }

        cur->protection = new_prot;
        cur = cur->next;
    }

    spin_unlock_irqrestore(&map->lock, irq_flags);
    return 0;
}

int vm_map_fork(struct vm_map *dst, struct vm_map *src)
{
    uint64_t irq_flags;
    spin_lock_irqsave(&src->lock, &irq_flags);

    struct vm_map_entry *cur = src->header.next;

    while (cur != &src->header) {
        switch (cur->inheritance) {
        case VM_INHERIT_NONE:
            /* Child does not get this region */
            break;

        case VM_INHERIT_SHARE:
        case VM_INHERIT_COPY: {
            /* Allocate a corresponding entry in dst */
            struct vm_map_entry *new_entry = vm_map_alloc_entry(dst);
            if (!new_entry) {
                spin_unlock_irqrestore(&src->lock, irq_flags);
                return -ENOMEM;
            }

            new_entry->vme_start = cur->vme_start;
            new_entry->vme_end = cur->vme_end;
            new_entry->protection = cur->protection;
            new_entry->max_protection = cur->max_protection;
            new_entry->inheritance = cur->inheritance;
            new_entry->is_shared = cur->is_shared;
            new_entry->needs_copy = (cur->inheritance == VM_INHERIT_COPY) ? 1 : 0;
            new_entry->wired = 0;
            new_entry->backing_fd = cur->backing_fd;
            new_entry->file_offset = cur->file_offset;
            new_entry->backing_vnode = cur->backing_vnode;

            /* Insert at end of dst list (entries are already sorted) */
            vm_map_entry_link(dst->header.prev, new_entry);
            dst->nentries++;
            break;
        }
        }

        cur = cur->next;
    }

    spin_unlock_irqrestore(&src->lock, irq_flags);
    return 0;
}

/*
 * vmm_copy_space - Deep-copy user pages from src to dst address space
 *
 * Walks the 4-level page table of src. Skips L0 entries that were copied
 * from kernel_pgd (those are shared kernel mappings). For each valid L3
 * PTE, allocates a new physical page, copies 4KB, and maps it into dst
 * with the same flags.
 */
/*
 * vmm_copy_space - Copy-on-write fork of address space
 *
 * Instead of deep-copying all pages, we:
 *   1. Share the same physical pages between parent and child
 *   2. Mark writable pages as read-only with PTE_COW set
 *   3. Increment the page's reference count
 *   4. On write fault, vmm_copy_on_write() makes a private copy
 *
 * Read-only pages (like __TEXT) are shared directly without COW marking.
 * This dramatically reduces fork() overhead for large processes.
 */
int vmm_copy_space(struct vm_space *dst, struct vm_space *src)
{
    if (!dst || !src || !dst->pgd || !src->pgd)
        return -1;

    pte_t *src_l0 = src->pgd;
    uint64_t pages_shared = 0;
    uint64_t irq_flags;

#if DEBUG
    kprintf("[vmm_copy_space] src_pgd=0x%lx dst_pgd=0x%lx\n",
            (uint64_t)src->pgd, (uint64_t)dst->pgd);
#endif

    spin_lock_irqsave(&vmm_lock, &irq_flags);

    for (int i0 = 0; i0 < PT_ENTRIES; i0++) {
        if (!(src_l0[i0] & PTE_VALID))
            continue;

        pte_t *src_l1 = (pte_t *)PTE_TO_PHYS(src_l0[i0]);

        /*
         * Determine the kernel's L1 table for this L0 index (if any).
         * vmm_create_space allocates a per-process L1 that copies the
         * kernel's L1 entries. We must skip those kernel L1 entries
         * (they point into the kernel's L2/L3 hierarchy and must not
         * be duplicated). Only user L1 entries (those that differ from
         * the kernel's) contain user pages to copy.
         */
        pte_t *kernel_l1 = NULL;
        if (kernel_pgd && (kernel_pgd[i0] & PTE_VALID)) {
            kernel_l1 = (pte_t *)PTE_TO_PHYS(kernel_pgd[i0]);
        }

        for (int i1 = 0; i1 < PT_ENTRIES; i1++) {
            if (!(src_l1[i1] & PTE_VALID))
                continue;

            /* Skip kernel L1 entries (shared from kernel_pgd's L1) */
            if (kernel_l1 && src_l1[i1] == kernel_l1[i1])
                continue;

            pte_t *src_l2 = (pte_t *)PTE_TO_PHYS(src_l1[i1]);

            for (int i2 = 0; i2 < PT_ENTRIES; i2++) {
                if (!(src_l2[i2] & PTE_VALID))
                    continue;

                pte_t *src_l3 = (pte_t *)PTE_TO_PHYS(src_l2[i2]);

                for (int i3 = 0; i3 < PT_ENTRIES; i3++) {
                    pte_t pte = src_l3[i3];
                    if (!(pte & PTE_VALID))
                        continue;

                    /* Reconstruct the VA from the indices */
                    uint64_t va = ((uint64_t)i0 << 39) |
                                  ((uint64_t)i1 << 30) |
                                  ((uint64_t)i2 << 21) |
                                  ((uint64_t)i3 << 12);

                    uint64_t pa = PTE_TO_PHYS(pte);
                    uint64_t flags = pte & ~PTE_ADDR_MASK;

                    /*
                     * COW logic:
                     * - If page is writable (AP_RW_ALL), mark both parent and
                     *   child as read-only with PTE_COW set
                     * - If page is already read-only, share directly (no COW
                     *   needed since neither can write to it)
                     */
                    bool is_writable = ((flags >> 6) & 3) == 1;  /* AP_RW_ALL = 1 */
                    
                    if (is_writable) {
                        /*
                         * Make page read-only in parent and mark COW.
                         * AP bits [7:6]: 01 = RW_ALL, 11 = RO_ALL
                         * Set to RO_ALL (set both bits 6 and 7) and add COW.
                         */
                        uint64_t cow_flags = (flags | (3UL << 6)) | PTE_COW;
                        
                        /* Update parent's PTE to be COW read-only */
                        src_l3[i3] = (pa & PTE_ADDR_MASK) | cow_flags;

                        /*
                         * Immediately invalidate the parent's TLB entry for
                         * this VA. Without this, the parent CPU may hold a
                         * stale writable TLB entry and silently write to
                         * the now-shared page without triggering a COW fault,
                         * corrupting the child's data.
                         *
                         * Must use IS (Inner Shareable) variant on SMP to
                         * broadcast to all CPUs. DSB ensures the PTE store
                         * and TLBI complete before we continue.
                         */
                        __asm__ volatile("dsb ishst" ::: "memory");
                        __asm__ volatile("tlbi vale1is, %0" :: "r"(va >> 12) : "memory");
                        __asm__ volatile("dsb ish" ::: "memory");
                        
                        /* Map into child with same COW read-only flags */
                        spin_unlock_irqrestore(&vmm_lock, irq_flags);
                        if (vmm_map_page(dst->pgd, va, pa, cow_flags) != 0) {
                            kprintf("[vmm] vmm_copy_space: map failed at VA 0x%lx\n", va);
                            return -1;
                        }
                        spin_lock_irqsave(&vmm_lock, &irq_flags);
                    } else {
                        /* Page is already read-only, share directly */
                        spin_unlock_irqrestore(&vmm_lock, irq_flags);
                        if (vmm_map_page(dst->pgd, va, pa, flags) != 0) {
                            kprintf("[vmm] vmm_copy_space: map failed at VA 0x%lx\n", va);
                            return -1;
                        }
                        spin_lock_irqsave(&vmm_lock, &irq_flags);
                    }

                    /* Increment reference count on the shared page */
                    pmm_page_ref(pa);
                    pages_shared++;

#if DEBUG
                    /* Log dyld range pages specifically */
                    if (va >= 0x200000000UL && va < 0x400000000UL) {
                        kprintf("[vmm_copy_space] dyld page VA=0x%lx PA=0x%lx\n", va, pa);
                    }
#endif
                }
            }
        }
    }

#if DEBUG
    kprintf("[vmm_copy_space] copied %lu pages total\n", pages_shared);
    /* Verify dst page tables before flush */
    kprintf("[vmm_copy_space] dst L0[0]=0x%lx\n", dst->pgd[0]);
    if (dst->pgd[0] & PTE_VALID) {
        pte_t *dst_l1 = (pte_t *)PTE_TO_PHYS(dst->pgd[0]);
        kprintf("[vmm_copy_space] dst L1[12]=0x%lx\n", dst_l1[12]);
    }
#endif

    /*
     * Ensure all page table modifications are visible to other CPUs.
     * On ARM, the page table walker uses the data cache, so we need to
     * ensure PTE writes reach the Point of Coherency before other CPUs
     * can see them via their page table walkers.
     *
     * DSB ISHST ensures all stores (PTE writes) are visible to all CPUs
     * in the Inner Shareable domain before the TLBI.
     *
     * Also invalidate instruction caches here - when sharing code pages,
     * other CPUs may have stale instruction cache entries for the same
     * physical addresses but different virtual addresses (from previous
     * processes). The IC IALLUIS ensures all CPUs refetch from memory.
     */
    __asm__ volatile("dsb ishst" ::: "memory");   /* Ensure PTE stores visible */
    __asm__ volatile("tlbi vmalle1is" ::: "memory"); /* Broadcast TLB invalidate */
    __asm__ volatile("dsb ish" ::: "memory");     /* Wait for TLBI completion */
    __asm__ volatile("ic ialluis" ::: "memory");  /* Broadcast I-cache invalidate */
    __asm__ volatile("dsb ish" ::: "memory");     /* Wait for IC completion */
    __asm__ volatile("isb");

#if DEBUG
    kprintf("[vmm_copy_space] TLB flushed, DSB done\n");
#endif

    spin_unlock_irqrestore(&vmm_lock, irq_flags);

    /*
     * Fork the vm_map: copy region metadata from parent to child.
     * This must happen after the page-table-level COW setup above,
     * because vm_map_fork only copies the region descriptors — it
     * doesn't touch the pmap.
     */
    if (src->map && dst->map) {
        int map_ret = vm_map_fork(dst->map, src->map);
        if (map_ret != 0) {
            kprintf("[vmm] vm_map_fork failed: %d\n", map_ret);
            return map_ret;
        }
    }

    return 0;
}
