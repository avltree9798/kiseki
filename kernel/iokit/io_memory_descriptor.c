/*
 * Kiseki OS - IOKit Memory Descriptor Implementation
 *
 * Implements IOMemoryDescriptor and IOMemoryMap for mapping device
 * physical memory into user task address spaces.
 *
 * Reference: XNU iokit/Kernel/IOMemoryDescriptor.cpp
 */

#include <iokit/io_memory_descriptor.h>
#include <kern/vmm.h>
#include <kern/thread.h>
#include <kern/kprintf.h>

/* ============================================================================
 * Class Metadata
 * ============================================================================ */

const struct io_class_meta io_memory_descriptor_meta = {
    .class_name     = "IOMemoryDescriptor",
    .super_meta     = &io_object_meta,
    .instance_size  = sizeof(struct io_memory_descriptor),
};

const struct io_class_meta io_memory_map_meta = {
    .class_name     = "IOMemoryMap",
    .super_meta     = &io_object_meta,
    .instance_size  = sizeof(struct io_memory_map),
};

/* ============================================================================
 * Static Pools
 * ============================================================================ */

static struct io_memory_descriptor desc_pool[IO_MEMORY_DESCRIPTOR_POOL_SIZE];
static bool desc_pool_used[IO_MEMORY_DESCRIPTOR_POOL_SIZE];
static spinlock_t desc_pool_lock = SPINLOCK_INIT;

static struct io_memory_map map_pool[IO_MEMORY_MAP_POOL_SIZE];
static bool map_pool_used[IO_MEMORY_MAP_POOL_SIZE];
static spinlock_t map_pool_lock = SPINLOCK_INIT;

struct io_memory_descriptor *
io_memory_descriptor_alloc(void)
{
    uint64_t flags;
    spin_lock_irqsave(&desc_pool_lock, &flags);

    for (uint32_t i = 0; i < IO_MEMORY_DESCRIPTOR_POOL_SIZE; i++) {
        if (!desc_pool_used[i]) {
            desc_pool_used[i] = true;

            uint8_t *p = (uint8_t *)&desc_pool[i];
            for (uint32_t j = 0; j < sizeof(struct io_memory_descriptor); j++)
                p[j] = 0;

            desc_pool[i].pool_allocated = true;
            desc_pool[i].pool_index = i;

            spin_unlock_irqrestore(&desc_pool_lock, flags);
            return &desc_pool[i];
        }
    }

    spin_unlock_irqrestore(&desc_pool_lock, flags);
    return NULL;
}

void
io_memory_descriptor_free_to_pool(struct io_memory_descriptor *desc)
{
    if (!desc || !desc->pool_allocated)
        return;

    uint64_t flags;
    spin_lock_irqsave(&desc_pool_lock, &flags);
    if (desc->pool_index < IO_MEMORY_DESCRIPTOR_POOL_SIZE)
        desc_pool_used[desc->pool_index] = false;
    spin_unlock_irqrestore(&desc_pool_lock, flags);
}

struct io_memory_map *
io_memory_map_alloc(void)
{
    uint64_t flags;
    spin_lock_irqsave(&map_pool_lock, &flags);

    for (uint32_t i = 0; i < IO_MEMORY_MAP_POOL_SIZE; i++) {
        if (!map_pool_used[i]) {
            map_pool_used[i] = true;

            uint8_t *p = (uint8_t *)&map_pool[i];
            for (uint32_t j = 0; j < sizeof(struct io_memory_map); j++)
                p[j] = 0;

            map_pool[i].pool_allocated = true;
            map_pool[i].pool_index = i;

            spin_unlock_irqrestore(&map_pool_lock, flags);
            return &map_pool[i];
        }
    }

    spin_unlock_irqrestore(&map_pool_lock, flags);
    return NULL;
}

void
io_memory_map_free_to_pool(struct io_memory_map *map)
{
    if (!map || !map->pool_allocated)
        return;

    uint64_t flags;
    spin_lock_irqsave(&map_pool_lock, &flags);
    if (map->pool_index < IO_MEMORY_MAP_POOL_SIZE)
        map_pool_used[map->pool_index] = false;
    spin_unlock_irqrestore(&map_pool_lock, flags);
}

/* ============================================================================
 * Vtables
 * ============================================================================ */

static void desc_free(struct io_object *obj)
{
    io_memory_descriptor_free_to_pool((struct io_memory_descriptor *)obj);
}

static const struct io_object_vtable desc_vtable = {
    .free = desc_free,
};

static void map_free(struct io_object *obj)
{
    struct io_memory_map *map = (struct io_memory_map *)obj;

    /* Release the backing descriptor */
    if (map->descriptor)
        io_object_release(&map->descriptor->obj);

    io_memory_map_free_to_pool(map);
}

static const struct io_object_vtable map_vtable = {
    .free = map_free,
};

/* ============================================================================
 * IOMemoryDescriptor::withRange (contiguous physical)
 *
 * Reference: XNU IODeviceMemory::withRange()
 * ============================================================================ */

struct io_memory_descriptor *
io_memory_descriptor_create_with_phys_range(IOPhysicalAddress phys_addr,
                                            IOByteCount length,
                                            IODirection direction,
                                            IOOptionBits options)
{
    struct io_memory_descriptor *desc = io_memory_descriptor_alloc();
    if (!desc)
        return NULL;

    io_object_init(&desc->obj, &desc_vtable, &io_memory_descriptor_meta);

    desc->type = IO_MEM_TYPE_PHYS_CONTIGUOUS;
    desc->direction = direction;
    desc->length = length;
    desc->phys_addr = phys_addr;
    desc->range_count = 0;
    desc->kva = 0;
    desc->options = options;

    return desc;
}

/* ============================================================================
 * IOMemoryDescriptor::map
 *
 * Maps the described physical memory into a task's address space.
 * Uses vm_map_enter() to allocate VA, then vmm_map_page() for each page.
 *
 * For device memory (framebuffer), uses PTE_USER_RW with device
 * memory attributes if kIOMapInhibitCache is set, otherwise normal
 * write-back cacheable.
 *
 * Reference: XNU IOMemoryDescriptor::map(),
 *            IOGeneralMemoryDescriptor::doMap()
 * ============================================================================ */

struct io_memory_map *
io_memory_descriptor_map(struct io_memory_descriptor *desc,
                         struct task *task,
                         IOOptionBits options)
{
    if (!desc || !task || !task->vm_space || !task->vm_space->map)
        return NULL;

    /* Only support contiguous physical range for now */
    if (desc->type != IO_MEM_TYPE_PHYS_CONTIGUOUS) {
        kprintf("IOKit: io_memory_descriptor_map: unsupported type %d\n",
                desc->type);
        return NULL;
    }

    IOByteCount length = desc->length;
    uint64_t aligned_length = ALIGN_UP(length, PAGE_SIZE);

    /* Allocate VA in the task's address space */
    uint64_t va = 0;
    int ret = vm_map_enter(task->vm_space->map, &va, aligned_length,
                           VM_PROT_READ | VM_PROT_WRITE,
                           VM_PROT_ALL,
                           VM_INHERIT_SHARE,
                           true,   /* is_shared — device memory */
                           -1, 0, NULL);
    if (ret != 0) {
        kprintf("IOKit: io_memory_descriptor_map: vm_map_enter failed (%d)\n",
                ret);
        return NULL;
    }

    /*
     * Determine PTE flags based on cache mode.
     *
     * On XNU, IOMemoryDescriptor::doMap() consults the cache mode from
     * the descriptor's options and sets appropriate page table attributes.
     *
     * For framebuffer/device memory: non-cacheable or write-combining.
     * For normal memory: write-back cacheable.
     */
    uint64_t pte_flags;
    if (options & kIOMapInhibitCache) {
        /* Device memory: non-cacheable, strongly ordered */
        pte_flags = PTE_PAGE | PTE_AF | PTE_SH_NONE |
                    PTE_AP_RW_ALL | PTE_ATTR_IDX(MAIR_DEVICE_nGnRnE) |
                    PTE_PXN | PTE_UXN;
    } else if (options & kIOMapWriteCombineCache) {
        /* Write-combining: non-cacheable (normal NC) */
        pte_flags = PTE_PAGE | PTE_AF | PTE_SH_INNER |
                    PTE_AP_RW_ALL | PTE_ATTR_IDX(MAIR_NORMAL_NC) |
                    PTE_PXN | PTE_UXN;
    } else {
        /* Default: write-back cacheable */
        pte_flags = PTE_USER_RW;
    }

    /* Map each physical page into the task */
    IOPhysicalAddress pa = desc->phys_addr;
    for (uint64_t offset = 0; offset < aligned_length; offset += PAGE_SIZE) {
        int mret = vmm_map_page(task->vm_space->pgd,
                                va + offset, pa + offset,
                                pte_flags);
        if (mret != 0) {
            kprintf("IOKit: io_memory_descriptor_map: vmm_map_page failed "
                    "at offset 0x%lx\n", offset);
            /* TODO: unmap already-mapped pages on failure */
            return NULL;
        }
    }

    /* Create the mapping object */
    struct io_memory_map *map = io_memory_map_alloc();
    if (!map) {
        /* TODO: unmap pages */
        return NULL;
    }

    io_object_init(&map->obj, &map_vtable, &io_memory_map_meta);

    map->descriptor = desc;
    io_object_retain(&desc->obj);  /* Map holds a reference to descriptor */

    map->task = task;
    map->virtual_address = va;
    map->length = length;
    map->options = options;

    kprintf("IOKit: mapped 0x%lx bytes phys 0x%lx -> VA 0x%lx in task '%s'\n",
            (uint64_t)length, (uint64_t)desc->phys_addr, va, task->name);

    return map;
}

/* ============================================================================
 * Accessors
 * ============================================================================ */

IOPhysicalAddress
io_memory_descriptor_get_phys_address(struct io_memory_descriptor *desc)
{
    return desc ? desc->phys_addr : 0;
}

IOByteCount
io_memory_descriptor_get_length(struct io_memory_descriptor *desc)
{
    return desc ? desc->length : 0;
}

uint64_t
io_memory_map_get_virtual_address(struct io_memory_map *map)
{
    return map ? map->virtual_address : 0;
}

IOByteCount
io_memory_map_get_length(struct io_memory_map *map)
{
    return map ? map->length : 0;
}

/* ============================================================================
 * Unmap
 *
 * Reference: XNU IOMemoryMap::unmap()
 * ============================================================================ */

IOReturn
io_memory_map_unmap(struct io_memory_map *map)
{
    if (!map || !map->task || !map->task->vm_space)
        return kIOReturnBadArgument;

    uint64_t aligned_length = ALIGN_UP(map->length, PAGE_SIZE);

    /* Unmap pages from the task's pmap */
    for (uint64_t offset = 0; offset < aligned_length; offset += PAGE_SIZE) {
        vmm_unmap_page(map->task->vm_space->pgd,
                       map->virtual_address + offset);
    }

    /* Remove the VM map entry */
    vm_map_remove(map->task->vm_space->map,
                  map->virtual_address,
                  map->virtual_address + aligned_length);

    map->virtual_address = 0;
    map->length = 0;

    return kIOReturnSuccess;
}
