/*
 * Kiseki OS - IOKit Memory Descriptor
 *
 * Describes physical memory ranges that can be mapped into user tasks.
 * Used by IOFramebuffer to share the GPU framebuffer with WindowServer.
 *
 * On XNU, IOMemoryDescriptor is a C++ class with subclasses:
 *   - IOGeneralMemoryDescriptor (scatter-gather)
 *   - IOBufferMemoryDescriptor (contiguous kernel buffer)
 *   - IODeviceMemory (device MMIO regions)
 *
 * We implement a simplified C version that covers the main use cases:
 *   1. Contiguous physical range (framebuffer, device MMIO)
 *   2. Map into user task (vm_map_enter + vmm_map_page)
 *
 * Reference: XNU iokit/Kernel/IOMemoryDescriptor.cpp
 */

#ifndef _IOKIT_IO_MEMORY_DESCRIPTOR_H
#define _IOKIT_IO_MEMORY_DESCRIPTOR_H

#include <iokit/io_object.h>
#include <iokit/iokit_types.h>

/* Forward declarations */
struct task;
struct vm_space;

/* ============================================================================
 * IOMemoryDescriptor Types
 * ============================================================================ */

typedef enum {
    IO_MEM_TYPE_PHYS_CONTIGUOUS = 0,    /* Contiguous physical range */
    IO_MEM_TYPE_PHYS_SCATTER    = 1,    /* Scatter-gather list */
    IO_MEM_TYPE_KERNEL_BUFFER   = 2,    /* Kernel virtual buffer */
} io_mem_desc_type_t;

/* Maximum scatter-gather entries */
#define IO_MEM_DESC_MAX_RANGES  16

/* ============================================================================
 * io_memory_descriptor - Describes a region of physical/virtual memory
 *
 * Reference: XNU IOMemoryDescriptor
 * ============================================================================ */

struct io_memory_descriptor {
    /* Base object (for refcounting) */
    struct io_object        obj;

    /* Descriptor type */
    io_mem_desc_type_t      type;

    /* Direction hint (for cache management) */
    IODirection             direction;

    /* Total byte length */
    IOByteCount             length;

    /* For IO_MEM_TYPE_PHYS_CONTIGUOUS: single physical range */
    IOPhysicalAddress       phys_addr;

    /* For IO_MEM_TYPE_PHYS_SCATTER: scatter-gather list */
    IOPhysicalRange         ranges[IO_MEM_DESC_MAX_RANGES];
    uint32_t                range_count;

    /* For IO_MEM_TYPE_KERNEL_BUFFER: kernel virtual address */
    IOVirtualAddress        kva;

    /* Options (cache mode, etc.) */
    IOOptionBits            options;

    /* Pool tracking */
    bool                    pool_allocated;
    uint32_t                pool_index;
};

/* ============================================================================
 * io_memory_map - Represents a mapping of an IOMemoryDescriptor into a task
 *
 * Created by io_memory_descriptor_map(). The mapping can be unmapped
 * explicitly or is automatically cleaned up when the user client closes.
 *
 * Reference: XNU IOMemoryMap
 * ============================================================================ */

struct io_memory_map {
    struct io_object        obj;

    struct io_memory_descriptor *descriptor;    /* Backing descriptor */
    struct task             *task;               /* Task the memory is mapped into */
    uint64_t                virtual_address;     /* VA in the task's address space */
    IOByteCount             length;              /* Mapped length */
    IOOptionBits            options;             /* Map options used */

    /* Pool tracking */
    bool                    pool_allocated;
    uint32_t                pool_index;
};

/* ============================================================================
 * IOMemoryDescriptor API
 * ============================================================================ */

/*
 * io_memory_descriptor_create_with_phys_range
 *
 * Create a memory descriptor for a contiguous physical address range.
 * Used for device memory (e.g., framebuffer).
 *
 * @phys_addr:  Physical base address
 * @length:     Byte count
 * @direction:  DMA direction hint
 * @options:    Cache mode flags (kIOMapInhibitCache, etc.)
 *
 * Returns a new descriptor, or NULL.
 *
 * Reference: XNU IODeviceMemory::withRange()
 */
struct io_memory_descriptor *
io_memory_descriptor_create_with_phys_range(IOPhysicalAddress phys_addr,
                                            IOByteCount length,
                                            IODirection direction,
                                            IOOptionBits options);

/*
 * io_memory_descriptor_map
 *
 * Map the descriptor's physical memory into a task's address space.
 * Allocates VA via vm_map_enter(), maps pages via vmm_map_page().
 *
 * @desc:       Memory descriptor to map
 * @task:       Target task
 * @options:    Mapping options (cache mode, kIOMapAnywhere, etc.)
 *
 * Returns an io_memory_map on success, NULL on failure.
 *
 * Reference: XNU IOMemoryDescriptor::map(),
 *            IOMemoryDescriptor::createMappingInTask()
 */
struct io_memory_map *
io_memory_descriptor_map(struct io_memory_descriptor *desc,
                         struct task *task,
                         IOOptionBits options);

/*
 * io_memory_descriptor_get_phys_address
 *
 * Get the physical address at a given offset.
 *
 * Reference: XNU IOMemoryDescriptor::getPhysicalAddress()
 */
IOPhysicalAddress
io_memory_descriptor_get_phys_address(struct io_memory_descriptor *desc);

/*
 * io_memory_descriptor_get_length
 *
 * Get the total byte length.
 */
IOByteCount
io_memory_descriptor_get_length(struct io_memory_descriptor *desc);

/* ============================================================================
 * IOMemoryMap API
 * ============================================================================ */

/*
 * io_memory_map_get_virtual_address
 *
 * Get the virtual address in the mapped task.
 *
 * Reference: XNU IOMemoryMap::getVirtualAddress()
 */
uint64_t io_memory_map_get_virtual_address(struct io_memory_map *map);

/*
 * io_memory_map_get_length
 *
 * Get the mapped length.
 */
IOByteCount io_memory_map_get_length(struct io_memory_map *map);

/*
 * io_memory_map_unmap
 *
 * Unmap the memory from the task's address space.
 *
 * Reference: XNU IOMemoryMap::unmap()
 */
IOReturn io_memory_map_unmap(struct io_memory_map *map);

/* ============================================================================
 * Class Metadata
 * ============================================================================ */

extern const struct io_class_meta io_memory_descriptor_meta;
extern const struct io_class_meta io_memory_map_meta;

/* ============================================================================
 * Static Pool
 * ============================================================================ */

#define IO_MEMORY_DESCRIPTOR_POOL_SIZE  64
#define IO_MEMORY_MAP_POOL_SIZE         64

struct io_memory_descriptor *io_memory_descriptor_alloc(void);
void io_memory_descriptor_free_to_pool(struct io_memory_descriptor *desc);

struct io_memory_map *io_memory_map_alloc(void);
void io_memory_map_free_to_pool(struct io_memory_map *map);

#endif /* _IOKIT_IO_MEMORY_DESCRIPTOR_H */
