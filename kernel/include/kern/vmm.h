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
#include <kern/sync.h>

/* Forward declarations */
struct vnode;

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

/*
 * Software-defined PTE bits (available in bits [58:55], ignored by hardware)
 * We use bit 55 for COW tracking since hardware ignores it.
 */
#define PTE_COW         (1UL << 55)     /* Copy-on-write: page is shared, copy on write fault */

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
/*
 * User read-execute: cacheable (WB), read-only from both EL0 and EL1,
 * PXN prevents kernel execution, UXN clear allows user execution.
 */
#define PTE_USER_RX     (PTE_PAGE | PTE_AF | PTE_SH_INNER | \
                         PTE_AP_RO_ALL | PTE_ATTR_IDX(MAIR_NORMAL_WB) | PTE_PXN)

/* Address extraction from PTE */
#define PTE_ADDR_MASK   0x0000FFFFFFFFF000UL
#define PTE_TO_PHYS(pte) ((pte) & PTE_ADDR_MASK)

/* Virtual address layout */
#define KERNEL_VA_BASE      0xFFFF000000000000UL
#define USER_VA_BASE        0x0000000100000000UL  /* Mach-O load address */
#define USER_MMAP_BASE      0x0000000300000000UL  /* Anonymous mmap region */
#define USER_STACK_TOP      0x00007FFFFFFF0000UL
#define COMMPAGE_VA         0x0000000FFFFFC000UL  /* Darwin CommPage */

/* Page table = 512 entries * 8 bytes = 4096 bytes = 1 page */
#define PT_ENTRIES      512

/* Page table type */
typedef uint64_t pte_t;

/*
 * VM Map — Per-process virtual address region tracking
 *
 * Modelled on XNU's vm_map / vm_map_entry (osfmk/vm/vm_map.h).
 * Each process has a vm_map containing a sorted doubly-linked list
 * of vm_map_entry structures describing every mapped region.
 *
 * The pmap (hardware page tables) is a cache of the vm_map's truth —
 * the vm_map is authoritative for what is mapped, with what protections,
 * and how regions behave on fork.
 */

/* VM inheritance values — how a region behaves across fork() */
#define VM_INHERIT_SHARE    0   /* Child shares the same mapping (MAP_SHARED) */
#define VM_INHERIT_COPY     1   /* Child gets a COW copy (MAP_PRIVATE) */
#define VM_INHERIT_NONE     2   /* Child does not inherit this mapping */
#define VM_INHERIT_DEFAULT  VM_INHERIT_COPY

/* VM protection bits (match PROT_* but kept separate for kernel use) */
#define VM_PROT_NONE        0x00
#define VM_PROT_READ        0x01
#define VM_PROT_WRITE       0x02
#define VM_PROT_EXECUTE     0x04
#define VM_PROT_ALL         (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE)

/* Maximum number of vm_map entries per process */
#define VM_MAP_ENTRIES_MAX  512

/*
 * vm_map_entry — Describes a single contiguous virtual memory region.
 *
 * Reference: XNU struct vm_map_entry (osfmk/vm/vm_map_xnu.h)
 *
 * Entries are kept in a sorted doubly-linked list ordered by vme_start.
 * Entries never overlap. Gaps between entries represent unmapped space.
 */
struct vm_map_entry {
    /* Linked list pointers (sorted by vme_start) */
    struct vm_map_entry *prev;
    struct vm_map_entry *next;

    /* Virtual address range [vme_start, vme_end) — page-aligned */
    uint64_t        vme_start;
    uint64_t        vme_end;

    /* Protection */
    uint8_t         protection;         /* Current vm_prot (R/W/X) */
    uint8_t         max_protection;     /* Ceiling — mprotect cannot exceed */

    /* Fork inheritance */
    uint8_t         inheritance;        /* VM_INHERIT_{SHARE,COPY,NONE} */

    /* Flags */
    uint8_t         is_shared   : 1;    /* Region is shared (MAP_SHARED) */
    uint8_t         needs_copy  : 1;    /* Deferred COW (shadow on write) */
    uint8_t         wired       : 1;    /* Pages are pinned (mlock) */
    uint8_t         _pad_bits   : 5;

    /* Backing store */
    int             backing_fd;         /* File descriptor (-1 = anonymous) */
    uint64_t        file_offset;        /* Offset into backing file */
    struct vnode    *backing_vnode;      /* Vnode for file-backed (NULL = anon) */
};

/*
 * vm_map — Per-process virtual memory map.
 *
 * Reference: XNU struct _vm_map (osfmk/vm/vm_map_xnu.h)
 *
 * Contains a sentinel-headed doubly-linked list of vm_map_entry.
 * The sentinel's vme_start/vme_end define the valid VA range.
 */
struct vm_map {
    struct vm_map_entry header;         /* Sentinel node (list head) */
    int             nentries;           /* Number of entries */
    uint64_t        min_offset;         /* Lowest valid user VA */
    uint64_t        max_offset;         /* Highest valid user VA */
    uint64_t        hint_addr;          /* Hint for next allocation */
    spinlock_t      lock;               /* Protects the map */

    /* Static entry pool — avoids needing kmalloc for entries */
    struct vm_map_entry entries[VM_MAP_ENTRIES_MAX];
    uint8_t         entry_used[VM_MAP_ENTRIES_MAX];
};

/*
 * vm_space - Per-process virtual address space
 *
 * Combines the hardware page tables (pmap) with the software vm_map.
 */
struct vm_space {
    pte_t *pgd;             /* L0 page table (physical address) — the pmap */
    uint64_t asid;          /* Address Space ID for TLB tagging */
    struct vm_map *map;     /* Software VM region map (NULL for kernel) */
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
 * refcounts — that optimisation comes later.
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
 * vmm_init_percpu - Enable MMU on a secondary CPU core
 *
 * Configures MAIR, TCR, TTBR0/TTBR1 (from kernel_pgd) and enables
 * the MMU + data/instruction caches.  Must be called before any
 * spinlock or shared-data access on the secondary core.
 */
void vmm_init_percpu(void);

/*
 * vmm_get_pte - Walk page table and return pointer to L3 PTE
 *
 * @pgd: L0 page table
 * @va:  Virtual address
 *
 * Returns pointer to the L3 PTE for va, or NULL if not mapped.
 */
pte_t *vmm_get_pte(pte_t *pgd, uint64_t va);

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

/* ============================================================================
 * VM Map API — Region-level virtual memory management
 *
 * Modelled on XNU's vm_map_enter / vm_map_lookup_entry / vm_map_clip /
 * vm_map_remove / vm_map_fork (osfmk/vm/vm_map.c).
 * ============================================================================ */

/*
 * vm_map_create - Allocate and initialise a new vm_map
 *
 * @min_offset: Lowest valid user VA (typically USER_VA_BASE or 0)
 * @max_offset: Highest valid user VA (typically USER_STACK_TOP + guard)
 *
 * Returns the new map, or NULL on failure.
 */
struct vm_map *vm_map_create(uint64_t min_offset, uint64_t max_offset);

/*
 * vm_map_destroy - Destroy a vm_map and free the backing allocation
 *
 * Does NOT unmap pages from the pmap — caller must handle that.
 */
void vm_map_destroy(struct vm_map *map);

/*
 * vm_map_enter - Create a new mapping in the address space
 *
 * Finds free space (or uses addr if MAP_FIXED) and inserts a new entry.
 * Does NOT allocate physical pages — the caller maps pages separately.
 *
 * @map:            Target vm_map
 * @addr:           In/out — hint or fixed address; returns chosen address
 * @size:           Size of the mapping (page-aligned)
 * @protection:     Initial vm_prot
 * @max_protection: Maximum vm_prot (ceiling for mprotect)
 * @inheritance:    Fork behaviour (VM_INHERIT_*)
 * @is_shared:      true for MAP_SHARED
 * @fd:             Backing file descriptor (-1 for anonymous)
 * @file_offset:    Offset into backing file
 * @vnode:          Backing vnode (NULL for anonymous)
 *
 * Returns 0 on success, -errno on failure.
 */
int vm_map_enter(struct vm_map *map, uint64_t *addr, uint64_t size,
                 uint8_t protection, uint8_t max_protection,
                 uint8_t inheritance, bool is_shared,
                 int fd, uint64_t file_offset, struct vnode *vnode);

/*
 * vm_map_lookup_entry - Find the entry containing a given address
 *
 * @map:  Target vm_map
 * @addr: Virtual address to look up
 * @entry: Out — set to the entry containing addr, or the entry just
 *         before the gap where addr would fall
 *
 * Returns true if addr is within an entry, false if in a gap.
 */
bool vm_map_lookup_entry(struct vm_map *map, uint64_t addr,
                         struct vm_map_entry **entry);

/*
 * vm_map_remove - Remove all mappings in [start, end)
 *
 * Clips entries at the boundaries and removes interior entries.
 * Does NOT unmap pages from the pmap — caller must handle that.
 *
 * Returns 0 on success, -errno on failure.
 */
int vm_map_remove(struct vm_map *map, uint64_t start, uint64_t end);

/*
 * vm_map_protect - Change protection on [start, end)
 *
 * Clips entries at boundaries and updates protection fields.
 * Does NOT update the pmap — caller must update PTEs.
 *
 * Returns 0 on success, -errno on failure.
 */
int vm_map_protect(struct vm_map *map, uint64_t start, uint64_t end,
                   uint8_t new_prot);

/*
 * vm_map_fork - Copy a vm_map for fork(), respecting inheritance
 *
 * Walks the source map's entries. For VM_INHERIT_COPY entries, creates
 * corresponding entries in the destination map. For VM_INHERIT_SHARE,
 * creates shared entries pointing to the same backing. VM_INHERIT_NONE
 * entries are skipped.
 *
 * Does NOT manipulate page tables — caller handles COW PTE setup.
 *
 * Returns 0 on success, -errno on failure.
 */
int vm_map_fork(struct vm_map *dst, struct vm_map *src);

#endif /* _KERN_VMM_H */
