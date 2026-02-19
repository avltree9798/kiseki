/*
 * Kiseki OS - Physical Memory Manager (PMM)
 *
 * Buddy allocator for physical page frames.
 * Manages all available RAM after the kernel image.
 *
 * Design:
 *   - Page size: 4KB (PAGE_SIZE)
 *   - Maximum order: 10 (largest block = 4MB)
 *   - Free lists per order, bitmap tracking
 *   - O(log n) alloc/free
 */

#ifndef _KERN_PMM_H
#define _KERN_PMM_H

#include <kiseki/types.h>

/* Buddy allocator configuration */
#define PMM_MAX_ORDER       10      /* 2^10 * 4K = 4MB max block */
#define PMM_MAX_PAGES       (256 * 1024)  /* Support up to 1GB RAM = 256K pages */

/* Page flags */
#define PAGE_FREE           0x00
#define PAGE_USED           0x01
#define PAGE_KERNEL         0x02
#define PAGE_RESERVED       0x04

/*
 * Physical page descriptor
 */
struct page {
    uint32_t flags;
    uint32_t order;         /* Current buddy order (if head of a free block) */
    uint32_t refcount;      /* Reference count (for COW) */
    uint32_t _pad;
    struct page *next;      /* Next in free list */
    struct page *prev;      /* Prev in free list */
};

/*
 * pmm_init - Initialize the physical memory manager
 *
 * @ram_start: Start of usable RAM (physical address)
 * @ram_end:   End of usable RAM (physical address)
 *
 * The region before ram_start (kernel image, stacks) is marked reserved.
 */
void pmm_init(uint64_t ram_start, uint64_t ram_end);

/*
 * pmm_alloc_pages - Allocate 2^order contiguous physical pages
 *
 * @order: Power of 2 (0 = 1 page, 1 = 2 pages, ..., 10 = 1024 pages)
 *
 * Returns physical address of the allocated block, or 0 on failure.
 */
uint64_t pmm_alloc_pages(uint32_t order);

/*
 * pmm_alloc_page - Allocate a single physical page
 */
uint64_t pmm_alloc_page(void);

/*
 * pmm_free_pages - Free a previously allocated block
 *
 * @paddr: Physical address (must be aligned to 2^order * PAGE_SIZE)
 * @order: Same order used during allocation
 */
void pmm_free_pages(uint64_t paddr, uint32_t order);

/*
 * pmm_free_page - Free a single physical page
 */
void pmm_free_page(uint64_t paddr);

/*
 * Page reference counting (for COW)
 */
void pmm_page_ref(uint64_t paddr);
void pmm_page_unref(uint64_t paddr);
uint32_t pmm_page_refcount(uint64_t paddr);

/*
 * pmm_get_free_pages - Get count of free pages
 */
uint64_t pmm_get_free_pages(void);

/*
 * pmm_get_total_pages - Get total managed pages
 */
uint64_t pmm_get_total_pages(void);

/*
 * Helper: physical address <-> page index
 */
struct page *pmm_pa_to_page(uint64_t paddr);
uint64_t pmm_page_to_pa(struct page *pg);

#endif /* _KERN_PMM_H */
