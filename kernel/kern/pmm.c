/*
 * Kiseki OS - Physical Memory Manager (Buddy Allocator)
 *
 * Classic buddy system with free lists per order.
 * Supports reference counting for Copy-on-Write pages.
 */

#include <kiseki/types.h>
#include <kern/pmm.h>
#include <kern/kprintf.h>
#include <kern/sync.h>

/* Page descriptor array (statically allocated for up to 1GB) */
static struct page pages[PMM_MAX_PAGES];

/* Free lists: one doubly-linked list per order */
static struct page *free_list[PMM_MAX_ORDER + 1];

/* Statistics */
static uint64_t total_pages;
static uint64_t free_pages;
static uint64_t ram_base;   /* Physical address of first managed page */

/* Spinlock protecting all PMM state (free lists, page descriptors, stats).
 * Must be held for the duration of any alloc/free/ref operation. */
static spinlock_t pmm_lock = SPINLOCK_INIT;

/* --- Free list helpers --- */

static void list_add(struct page **head, struct page *pg)
{
    pg->next = *head;
    pg->prev = NULL;
    if (*head)
        (*head)->prev = pg;
    *head = pg;
}

static void list_remove(struct page **head, struct page *pg)
{
    if (pg->prev)
        pg->prev->next = pg->next;
    else
        *head = pg->next;
    if (pg->next)
        pg->next->prev = pg->prev;
    pg->next = pg->prev = NULL;
}

/* --- Address conversion --- */

struct page *pmm_pa_to_page(uint64_t paddr)
{
    uint64_t idx = (paddr - ram_base) >> PAGE_SHIFT;
    if (idx >= total_pages)
        return NULL;
    return &pages[idx];
}

uint64_t pmm_page_to_pa(struct page *pg)
{
    uint64_t idx = (uint64_t)(pg - pages);
    return ram_base + (idx << PAGE_SHIFT);
}

static uint64_t page_index(struct page *pg)
{
    return (uint64_t)(pg - pages);
}

/* --- Buddy helpers --- */

static struct page *buddy_of(struct page *pg, uint32_t order)
{
    uint64_t idx = page_index(pg);
    uint64_t buddy_idx = idx ^ (1UL << order);
    if (buddy_idx >= total_pages)
        return NULL;
    return &pages[buddy_idx];
}

/* --- PMM Init --- */

void pmm_init(uint64_t mem_start, uint64_t mem_end)
{
    /* Align start up, end down to page boundaries */
    mem_start = ALIGN_UP(mem_start, PAGE_SIZE);
    mem_end = ALIGN_DOWN(mem_end, PAGE_SIZE);

    ram_base = mem_start;
    total_pages = (mem_end - mem_start) >> PAGE_SHIFT;

    if (total_pages > PMM_MAX_PAGES)
        total_pages = PMM_MAX_PAGES;

    free_pages = 0;

    /* Initialize all free lists */
    for (int i = 0; i <= PMM_MAX_ORDER; i++)
        free_list[i] = NULL;

    /* Mark all pages as reserved initially */
    for (uint64_t i = 0; i < total_pages; i++) {
        pages[i].flags = PAGE_RESERVED;
        pages[i].order = 0;
        pages[i].refcount = 0;
        pages[i].next = NULL;
        pages[i].prev = NULL;
    }

    /* Free all pages - buddy allocator will coalesce naturally */
    for (uint64_t i = 0; i < total_pages; i++) {
        /* Try to add as largest possible aligned block */
        uint32_t order = 0;
        while (order < PMM_MAX_ORDER) {
            uint64_t block_pages = 1UL << (order + 1);
            if (i + block_pages > total_pages)
                break;
            if (i & ((1UL << (order + 1)) - 1))
                break;
            order++;
        }

        /* Check if entire block fits */
        uint64_t block_size = 1UL << order;
        if (i + block_size <= total_pages && (i & (block_size - 1)) == 0) {
            pages[i].flags = PAGE_FREE;
            pages[i].order = order;
            list_add(&free_list[order], &pages[i]);
            free_pages += block_size;
            i += block_size - 1; /* skip rest of block (-1 because loop increments) */
        }
    }

    kprintf("[pmm] %lu pages (%lu MB) managed, %lu pages free\n",
            total_pages, (total_pages * PAGE_SIZE) >> 20, free_pages);
}

/* --- Allocation --- */

uint64_t pmm_alloc_pages(uint32_t order)
{
    if (order > PMM_MAX_ORDER)
        return 0;

    uint64_t flags;
    spin_lock_irqsave(&pmm_lock, &flags);

    /* Find smallest available order >= requested */
    uint32_t current_order = order;
    while (current_order <= PMM_MAX_ORDER && !free_list[current_order])
        current_order++;

    if (current_order > PMM_MAX_ORDER) {
        spin_unlock_irqrestore(&pmm_lock, flags);
        return 0;   /* Out of memory */
    }

    /* Remove block from free list */
    struct page *block = free_list[current_order];
    list_remove(&free_list[current_order], block);
    block->flags = PAGE_USED;
    block->order = order;
    block->refcount = 1;

    /* Split larger block down to requested order */
    while (current_order > order) {
        current_order--;
        /* The "buddy" half becomes a free block at the lower order */
        struct page *buddy = &pages[page_index(block) + (1UL << current_order)];
        buddy->flags = PAGE_FREE;
        buddy->order = current_order;
        buddy->refcount = 0;
        list_add(&free_list[current_order], buddy);
        free_pages += (1UL << current_order);
    }

    free_pages -= (1UL << order);
    uint64_t pa = pmm_page_to_pa(block);

    spin_unlock_irqrestore(&pmm_lock, flags);
    return pa;
}

uint64_t pmm_alloc_page(void)
{
    return pmm_alloc_pages(0);
}

/* --- Freeing --- */

void pmm_free_pages(uint64_t paddr, uint32_t order)
{
    struct page *pg = pmm_pa_to_page(paddr);
    if (!pg)
        return;

    uint64_t flags;
    spin_lock_irqsave(&pmm_lock, &flags);

    if (pg->flags == PAGE_FREE) {
        spin_unlock_irqrestore(&pmm_lock, flags);
        return;
    }

    pg->flags = PAGE_FREE;
    pg->refcount = 0;
    free_pages += (1UL << order);

    /* Coalesce with buddy */
    while (order < PMM_MAX_ORDER) {
        struct page *buddy = buddy_of(pg, order);
        if (!buddy || buddy->flags != PAGE_FREE || buddy->order != order)
            break;

        /* Remove buddy from its free list */
        list_remove(&free_list[order], buddy);
        free_pages -= (1UL << order); /* will re-add at higher order */

        /* Merge: always keep the lower-addressed block as head */
        if (page_index(buddy) < page_index(pg))
            pg = buddy;

        order++;
    }

    pg->order = order;
    list_add(&free_list[order], pg);

    spin_unlock_irqrestore(&pmm_lock, flags);
}

void pmm_free_page(uint64_t paddr)
{
    pmm_free_pages(paddr, 0);
}

/* --- Reference counting (COW) --- */

void pmm_page_ref(uint64_t paddr)
{
    struct page *pg = pmm_pa_to_page(paddr);
    if (!pg)
        return;

    uint64_t flags;
    spin_lock_irqsave(&pmm_lock, &flags);
    pg->refcount++;
    spin_unlock_irqrestore(&pmm_lock, flags);
}

void pmm_page_unref(uint64_t paddr)
{
    struct page *pg = pmm_pa_to_page(paddr);
    if (!pg)
        return;

    uint64_t flags;
    spin_lock_irqsave(&pmm_lock, &flags);

    if (pg->refcount > 0)
        pg->refcount--;

    if (pg->refcount == 0) {
        /* Free the page while still holding the lock.
         * pmm_free_pages will try to take the lock again,
         * so we call the internal free logic directly. */
        pg->flags = PAGE_FREE;
        free_pages += 1;

        /* Coalesce with buddy */
        uint32_t order = 0;
        while (order < PMM_MAX_ORDER) {
            struct page *buddy = buddy_of(pg, order);
            if (!buddy || buddy->flags != PAGE_FREE || buddy->order != order)
                break;
            list_remove(&free_list[order], buddy);
            free_pages -= (1UL << order);
            if (page_index(buddy) < page_index(pg))
                pg = buddy;
            order++;
        }
        pg->order = order;
        list_add(&free_list[order], pg);
    }

    spin_unlock_irqrestore(&pmm_lock, flags);
}

uint32_t pmm_page_refcount(uint64_t paddr)
{
    struct page *pg = pmm_pa_to_page(paddr);
    if (!pg)
        return 0;
    /* Read is atomic on ARM64 for aligned 32-bit, but let's be safe */
    uint64_t flags;
    spin_lock_irqsave(&pmm_lock, &flags);
    uint32_t rc = pg->refcount;
    spin_unlock_irqrestore(&pmm_lock, flags);
    return rc;
}

/* --- Statistics --- */

uint64_t pmm_get_free_pages(void)
{
    return free_pages;
}

uint64_t pmm_get_total_pages(void)
{
    return total_pages;
}
