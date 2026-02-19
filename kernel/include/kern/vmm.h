/*
 * Kiseki OS - Virtual Memory Manager (VMM)
 *
 * ARM64 4-level page table management.
 *
 * AArch64 translation:
 *   L0 (PGD) -> L1 (PUD) -> L2 (PMD) -> L3 (PTE) -> 4KB page
 *
 * Bits [47:39] -> L0 index (512 entries)
 * Bits [38:30] -> L1 index (512 entries)
 * Bits [29:21] -> L2 index (512 entries)
 * Bits [20:12] -> L3 index (512 entries)
 * Bits [11:0]  -> Page offset
 *
 * Kernel space: TTBR1_EL1 (upper VA, 0xFFFF000000000000+)
 * User space:   TTBR0_EL1 (lower VA, 0x0000000000000000+)
 */

#ifndef _KERN_VMM_H
#define _KERN_VMM_H

#include <kiseki/types.h>

/* Page table entry bits (ARMv8 Stage 1) */
#define PTE_VALID       (1UL << 0)      /* Entry is valid */
#define PTE_TABLE       (1UL << 1)      /* Table descriptor (L0-L2) / Page (L3) */
#define PTE_PAGE        (3UL << 0)      /* L3 page descriptor (valid + page) */

/* Lower attributes (bits [11:2]) */
#define PTE_ATTR_IDX(n) ((uint64_t)(n) << 2)  /* MAIR index */
#define PTE_NS          (1UL << 5)      /* Non-secure */
#define PTE_AP_RW_EL1   (0UL << 6)     /* EL1 R/W, EL0 no access */
#define PTE_AP_RW_ALL   (1UL << 6)     /* EL1 R/W, EL0 R/W */
#define PTE_AP_RO_EL1   (2UL << 6)     /* EL1 R/O, EL0 no access */
#define PTE_AP_RO_ALL   (3UL << 6)     /* EL1 R/O, EL0 R/O */
#define PTE_SH_NONE     (0UL << 8)
#define PTE_SH_OUTER    (2UL << 8)
#define PTE_SH_INNER    (3UL << 8)
#define PTE_AF          (1UL << 10)     /* Access Flag */

/* Upper attributes (bits [63:50]) */
#define PTE_PXN         (1UL << 53)     /* Privileged Execute Never */
#define PTE_UXN         (1UL << 54)     /* User Execute Never */

/* MAIR indices (set during MMU init) */
#define MAIR_DEVICE_nGnRnE  0   /* Device memory (strongly ordered) */
#define MAIR_NORMAL_NC       1   /* Normal non-cacheable */
#define MAIR_NORMAL_WB       2   /* Normal write-back cacheable */

/* Common PTE combinations */
#define PTE_KERNEL_RWX  (PTE_PAGE | PTE_AF | PTE_SH_INNER | \
                         PTE_AP_RW_EL1 | PTE_ATTR_IDX(MAIR_NORMAL_WB) | PTE_UXN)
#define PTE_KERNEL_RW   (PTE_KERNEL_RWX | PTE_PXN)
#define PTE_KERNEL_RO   (PTE_PAGE | PTE_AF | PTE_SH_INNER | \
                         PTE_AP_RO_EL1 | PTE_ATTR_IDX(MAIR_NORMAL_WB) | PTE_UXN | PTE_PXN)
#define PTE_DEVICE      (PTE_PAGE | PTE_AF | PTE_SH_NONE | \
                         PTE_AP_RW_EL1 | PTE_ATTR_IDX(MAIR_DEVICE_nGnRnE) | PTE_PXN | PTE_UXN)

#define PTE_USER_RWX    (PTE_PAGE | PTE_AF | PTE_SH_INNER | \
                         PTE_AP_RW_ALL | PTE_ATTR_IDX(MAIR_NORMAL_WB))
#define PTE_USER_RW     (PTE_USER_RWX | PTE_PXN | PTE_UXN)
#define PTE_USER_RO     (PTE_PAGE | PTE_AF | PTE_SH_INNER | \
                         PTE_AP_RO_ALL | PTE_ATTR_IDX(MAIR_NORMAL_WB) | PTE_PXN | PTE_UXN)
#define PTE_USER_RX     (PTE_PAGE | PTE_AF | PTE_SH_INNER | \
                         PTE_AP_RO_ALL | PTE_ATTR_IDX(MAIR_NORMAL_WB) | PTE_PXN)

/* Address extraction from PTE */
#define PTE_ADDR_MASK   0x0000FFFFFFFFF000UL
#define PTE_TO_PHYS(pte) ((pte) & PTE_ADDR_MASK)

/* Virtual address layout */
#define KERNEL_VA_BASE      0xFFFF000000000000UL
#define USER_VA_BASE        0x0000000100000000UL  /* Mach-O load address */
#define USER_STACK_TOP      0x00007FFFFFFF0000UL
#define COMMPAGE_VA         0x0000000FFFFFC000UL  /* Darwin CommPage */

/* Page table = 512 entries * 8 bytes = 4096 bytes = 1 page */
#define PT_ENTRIES      512

/* Page table type */
typedef uint64_t pte_t;

/*
 * vm_space - Per-process virtual address space
 */
struct vm_space {
    pte_t *pgd;         /* L0 page table (physical address) */
    uint64_t asid;      /* Address Space ID for TLB tagging */
};

/*
 * vmm_init - Initialize kernel page tables and enable MMU
 *
 * Sets up identity mapping for kernel, maps MMIO regions,
 * configures MAIR/TCR/SCTLR, enables MMU.
 */
void vmm_init(void);

/*
 * vmm_map_page - Map a single virtual page to a physical page
 *
 * @pgd:    L0 page table (physical address)
 * @va:     Virtual address (page-aligned)
 * @pa:     Physical address (page-aligned)
 * @flags:  PTE flags (permissions, attributes)
 *
 * Allocates intermediate page table levels as needed.
 * Returns 0 on success, -1 on failure.
 */
int vmm_map_page(pte_t *pgd, uint64_t va, uint64_t pa, uint64_t flags);

/*
 * vmm_unmap_page - Remove a virtual page mapping
 *
 * @pgd: L0 page table
 * @va:  Virtual address to unmap
 *
 * Returns the physical address that was mapped, or 0 if not mapped.
 */
uint64_t vmm_unmap_page(pte_t *pgd, uint64_t va);

/*
 * vmm_map_range - Map a range of contiguous physical pages
 */
int vmm_map_range(pte_t *pgd, uint64_t va_start, uint64_t pa_start,
                  uint64_t size, uint64_t flags);

/*
 * vmm_translate - Walk page table and return physical address
 *
 * Returns physical address for a VA, or 0 if unmapped.
 */
uint64_t vmm_translate(pte_t *pgd, uint64_t va);

/*
 * vmm_create_space - Create a new user address space
 *
 * Allocates a fresh L0 table. Kernel mappings are shared via TTBR1.
 */
struct vm_space *vmm_create_space(void);

/*
 * vmm_destroy_space - Tear down a user address space
 *
 * Frees all page tables and mapped pages.
 */
void vmm_destroy_space(struct vm_space *space);

/*
 * vmm_switch_space - Switch to a different user address space
 *
 * Updates TTBR0_EL1 with the new L0 table.
 */
void vmm_switch_space(struct vm_space *space);

/*
 * vmm_copy_on_write - Handle a COW fault
 *
 * @space: Faulting address space
 * @va:    Faulting virtual address
 *
 * If the page is shared (refcount > 1), copies it and remaps as writable.
 * Returns 0 on success, -1 on failure.
 */
int vmm_copy_on_write(struct vm_space *space, uint64_t va);

/*
 * vmm_copy_space - Deep copy user pages from one address space to another
 *
 * Walks the source page tables (L0→L3). For each valid L3 PTE that maps
 * a user page (i.e., not a kernel L0 entry shared from kernel_pgd),
 * allocates a fresh physical page, copies 4KB of data, and maps it into
 * the destination at the same VA with the same PTE flags.
 *
 * This is a full copy, not COW. COW would mark pages read-only and bump
 * refcounts — that optimization comes later.
 *
 * @dst: Destination address space (freshly created by vmm_create_space)
 * @src: Source address space (parent process)
 *
 * Returns 0 on success, -1 on failure (OOM).
 */
int vmm_copy_space(struct vm_space *dst, struct vm_space *src);

/*
 * vmm_get_kernel_pgd - Get the kernel's L0 page table
 */
pte_t *vmm_get_kernel_pgd(void);

/*
 * vmm_protect_page - Change PTE flags for a single mapped page
 *
 * @pgd:       L0 page table
 * @va:        Virtual address (page-aligned)
 * @new_flags: New PTE flags (PTE_USER_RX, PTE_USER_RW, etc.)
 *
 * Returns 0 on success, -1 if the page is not mapped.
 * Invalidates the TLB entry for the VA.
 */
int vmm_protect_page(pte_t *pgd, uint64_t va, uint64_t new_flags);

#endif /* _KERN_VMM_H */
