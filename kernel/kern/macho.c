/*
 * Kiseki OS - Mach-O Binary Loader
 *
 * Loads 64-bit Mach-O executables (MH_EXECUTE) and the dynamic linker
 * (MH_DYLINKER) into user address spaces.
 *
 * This implementation follows XNU bsd/kern/mach_loader.c:
 *   - Multi-pass load command parsing (metadata, then segments, then dyld)
 *   - Recursive dyld loading via parse_machfile() at depth 2
 *   - ASLR slide for PIE binaries
 *   - __PAGEZERO enforcement
 *   - LC_MAIN: kernel does NOT use entryoff; marks needs_dynlinker=true
 *     and defers to dyld for entry resolution
 *   - LC_UNIXTHREAD: sets entry point directly (used by dyld itself)
 *
 * Reference: XNU bsd/kern/mach_loader.c (Apple APSL)
 */

#include <kiseki/types.h>
#include <kern/macho.h>
#include <kern/vmm.h>
#include <kern/pmm.h>
#include <kern/kprintf.h>
#include <fs/vfs.h>

/* ============================================================================
 * Internal Helpers
 * ============================================================================ */

static void memset_k(void *dst, int val, uint64_t n)
{
    uint8_t *d = (uint8_t *)dst;
    while (n--)
        *d++ = (uint8_t)val;
}

static void memcpy_k(void *dst, const void *src, uint64_t n)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    while (n--)
        *d++ = *s++;
}

static void strncpy_k(char *dst, const char *src, uint64_t n)
{
    uint64_t i;
    for (i = 0; i < n && src[i] != '\0'; i++)
        dst[i] = src[i];
    for (; i < n; i++)
        dst[i] = '\0';
}

static int strncmp_k(const char *a, const char *b, uint64_t n)
{
    for (uint64_t i = 0; i < n; i++) {
        if (a[i] != b[i])
            return (uint8_t)a[i] - (uint8_t)b[i];
        if (a[i] == '\0')
            return 0;
    }
    return 0;
}

/*
 * vmprot_to_pte - Convert Mach-O VM protection flags to ARM64 PTE flags
 */
static uint64_t vmprot_to_pte(uint32_t prot)
{
    if (prot == VM_PROT_NONE)
        return 0;

    /* Read + Execute (typical __TEXT) */
    if ((prot & VM_PROT_READ) && (prot & VM_PROT_EXECUTE) &&
        !(prot & VM_PROT_WRITE))
        return PTE_USER_RX;

    /* Read + Write (typical __DATA, __DATA_CONST) */
    if ((prot & VM_PROT_READ) && (prot & VM_PROT_WRITE) &&
        !(prot & VM_PROT_EXECUTE))
        return PTE_USER_RW;

    /* Read + Write + Execute */
    if ((prot & VM_PROT_READ) && (prot & VM_PROT_WRITE) &&
        (prot & VM_PROT_EXECUTE))
        return PTE_USER_RWX;

    /* Read-only */
    if ((prot & VM_PROT_READ) && !(prot & VM_PROT_WRITE) &&
        !(prot & VM_PROT_EXECUTE))
        return PTE_USER_RO;

    return PTE_USER_RO;
}

/* ============================================================================
 * Segment Mapping
 * ============================================================================ */

/*
 * load_segment - Map a single LC_SEGMENT_64 into user VM
 *
 * Handles:
 *   - __PAGEZERO: skipped (unmapped guard)
 *   - Segments with file data: read from VFS, copy to allocated pages
 *   - Zero-fill (vmsize > filesize): allocated as zero pages (BSS)
 *   - Slide: all vmaddrs are adjusted by slide
 *
 * @fd:        File descriptor for the Mach-O binary
 * @seg:       The segment_command_64 to load
 * @space:     Target user VM space
 * @slide:     ASLR slide to apply
 * @result:    Load result to update with segment info
 *
 * Returns LOAD_SUCCESS or error.
 */
static load_return_t
load_segment(int fd, struct segment_command_64 *seg,
             struct vm_space *space, int64_t slide,
             load_result_t *result)
{
    /*
     * Skip __PAGEZERO: vmaddr == 0, filesize == 0, no permissions.
     * It's the 4GB null guard page. We just note it in the result.
     */
    if (seg->vmaddr == 0 && seg->filesize == 0 && seg->vmsize > 0 &&
        seg->initprot == 0 && seg->maxprot == 0) {
        result->has_pagezero = true;
        return LOAD_SUCCESS;
    }

    /* Skip zero-size segments */
    if (seg->vmsize == 0)
        return LOAD_SUCCESS;

    /* Apply slide */
    uint64_t vmaddr = seg->vmaddr + (uint64_t)slide;
    uint64_t vmsize = seg->vmsize;
    uint64_t fileoff = seg->fileoff;
    uint64_t filesize = seg->filesize;

    /* Convert protections */
    uint64_t pte_flags = vmprot_to_pte(seg->initprot);
    if (pte_flags == 0 && vmsize > 0)
        pte_flags = PTE_USER_RO;  /* Fallback for __LINKEDIT etc. */

    /* Track segment in result */
    if (strncmp_k(seg->segname, "__TEXT", 6) == 0) {
        result->text_base = vmaddr;
        result->text_size = vmsize;
        /* If this segment maps offset 0, record the mach_header location */
        if (seg->fileoff == 0 && seg->filesize > 0)
            result->mach_header = vmaddr;
    } else if (strncmp_k(seg->segname, "__DATA", 6) == 0 &&
               seg->segname[6] != '_') {  /* __DATA but not __DATA_CONST */
        result->data_base = vmaddr;
        result->data_size = vmsize;
    } else if (strncmp_k(seg->segname, "__LINKEDIT", 10) == 0) {
        result->linkedit_base = vmaddr;
        result->linkedit_size = vmsize;
    }

    /* Track VM range */
    if (vmaddr < result->min_vm_addr)
        result->min_vm_addr = vmaddr;
    if (vmaddr + vmsize > result->max_vm_addr)
        result->max_vm_addr = vmaddr + vmsize;

    /*
     * Map pages: read file data into allocated physical pages, zero-fill
     * any remaining pages beyond filesize.
     */
    uint64_t vm_pages = ALIGN_UP(vmsize, PAGE_SIZE) / PAGE_SIZE;
    uint64_t file_remaining = filesize;

    /* Seek to segment data in file */
    if (filesize > 0) {
        int64_t seekret = vfs_lseek(fd, (int64_t)fileoff, SEEK_SET);
        if (seekret < 0) {
            kprintf("macho: seek failed for '%.16s': %ld\n",
                    seg->segname, seekret);
            return LOAD_IOERROR;
        }
    }

    for (uint64_t p = 0; p < vm_pages; p++) {
        uint64_t pa = pmm_alloc_page();
        if (pa == 0) {
            kprintf("macho: OOM mapping '%.16s'\n", seg->segname);
            return LOAD_NOSPACE;
        }

        /*
         * Kernel uses identity mapping (PA == VA for RAM),
         * so we can read directly into the physical page.
         */
        uint8_t *kva = (uint8_t *)pa;
        memset_k(kva, 0, PAGE_SIZE);

        /* Copy file data if any remains */
        if (file_remaining > 0) {
            uint64_t chunk = file_remaining;
            if (chunk > PAGE_SIZE)
                chunk = PAGE_SIZE;

            /* Read directly into the page — no intermediate buffer needed */
            int64_t nread = vfs_read(fd, kva, chunk);
            (void)nread;

            file_remaining -= chunk;
        }

        uint64_t va = vmaddr + (p * PAGE_SIZE);
        int ret = vmm_map_page(space->pgd, va, pa, pte_flags);
        if (ret != 0) {
            kprintf("macho: map failed VA 0x%lx -> PA 0x%lx\n", va, pa);
            pmm_free_page(pa);
            return LOAD_NOSPACE;
        }
    }

    return LOAD_SUCCESS;
}

/* ============================================================================
 * parse_machfile - Core Mach-O parser (XNU-style)
 *
 * Multi-pass load command processing:
 *   Pass 1: Metadata — LC_UUID, LC_MAIN, LC_UNIXTHREAD, LC_BUILD_VERSION
 *   Pass 2: Segments — LC_SEGMENT_64 (map into user VM)
 *   Pass 3: Linking — LC_LOAD_DYLINKER (recursive dyld load),
 *           LC_LOAD_DYLIB (record dependencies)
 *
 * @fd:      Open file descriptor for the Mach-O binary
 * @hdr:     Already-validated Mach-O header
 * @space:   Target user VM space
 * @depth:   Recursion depth (1=main binary, 2=dyld)
 * @slide:   ASLR slide to apply
 * @result:  Load result to fill
 * @binresult: Parent binary's load result (non-NULL when loading dyld)
 *
 * Returns LOAD_SUCCESS or error.
 * ============================================================================ */

static load_return_t
parse_machfile(int fd, struct mach_header_64 *hdr,
               struct vm_space *space, int depth,
               int64_t slide, load_result_t *result,
               load_result_t *binresult __attribute__((unused)))
{
    load_return_t ret = LOAD_SUCCESS;

    /*
     * Limit recursion depth to prevent infinite loops.
     * XNU uses depth > 2 check.
     */
    if (depth > 2) {
        kprintf("macho: recursion depth exceeded\n");
        return LOAD_FAILURE;
    }

    /*
     * Validate filetype for the current depth.
     * depth 1 = main binary (MH_EXECUTE)
     * depth 2 = dynamic linker (MH_DYLINKER)
     */
    if (depth == 1 && hdr->filetype != MH_EXECUTE) {
        kprintf("macho: expected MH_EXECUTE at depth 1, got %u\n",
                hdr->filetype);
        return LOAD_BADMACHO;
    }
    if (depth == 2 && hdr->filetype != MH_DYLINKER) {
        kprintf("macho: expected MH_DYLINKER at depth 2, got %u\n",
                hdr->filetype);
        return LOAD_BADMACHO;
    }

    /*
     * For PIE and dyld, apply ASLR slide.
     * For now, Kiseki doesn't randomize (slide=0), but the infrastructure
     * is here for when we add ASLR.
     */
    if (hdr->flags & MH_PIE)
        result->is_pie = true;

    result->slide = slide;

    /*
     * Read all load commands into a kernel buffer.
     */
    uint32_t cmds_size = hdr->sizeofcmds;
    if (cmds_size > (512 * 1024)) {
        kprintf("macho: load commands too large (%u bytes)\n", cmds_size);
        return LOAD_BADMACHO;
    }

    /* Allocate kernel buffer for load commands */
    uint32_t cmds_pages = (cmds_size + PAGE_SIZE - 1) / PAGE_SIZE;
    uint32_t order = 0;
    {
        uint32_t p = 1;
        while (p < cmds_pages) {
            p <<= 1;
            order++;
        }
    }
    uint64_t cmds_pa = pmm_alloc_pages(order);
    if (cmds_pa == 0) {
        kprintf("macho: cannot allocate buffer for load commands\n");
        return LOAD_NOSPACE;
    }

    /* Identity mapping: PA == VA for RAM */
    uint8_t *cmds_buf = (uint8_t *)cmds_pa;
    int64_t nread = vfs_read(fd, cmds_buf, cmds_size);
    if (nread != (int64_t)cmds_size) {
        kprintf("macho: short read on load commands (%ld/%u)\n",
                (long)nread, cmds_size);
        pmm_free_pages(cmds_pa, order);
        return LOAD_IOERROR;
    }

    /*
     * ================================================================
     * PASS 1: Metadata
     *
     * Process: LC_UUID, LC_MAIN, LC_UNIXTHREAD, LC_BUILD_VERSION,
     *          LC_SEGMENT_64 (just to find __TEXT base for mach_header)
     * ================================================================
     */
    uint8_t *cmd_ptr = cmds_buf;
    uint64_t text_base = 0;
    struct dylinker_command *dylinker_lcp = NULL;

    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (cmd_ptr + sizeof(struct load_command) > cmds_buf + cmds_size)
            break;
        struct load_command *lc = (struct load_command *)cmd_ptr;
        if (lc->cmdsize < sizeof(struct load_command) ||
            cmd_ptr + lc->cmdsize > cmds_buf + cmds_size)
            break;

        switch (lc->cmd) {
        case LC_SEGMENT_64: {
            struct segment_command_64 *seg =
                (struct segment_command_64 *)cmd_ptr;
            /* Find __TEXT base for LC_MAIN offset calculation */
            if (strncmp_k(seg->segname, "__TEXT", 6) == 0)
                text_base = seg->vmaddr + (uint64_t)slide;
            break;
        }

        case LC_MAIN: {
            /*
             * LC_MAIN: XNU does NOT use entryoff here.
             * Instead, it marks needs_dynlinker=true and lets dyld
             * read LC_MAIN at runtime to find the entry offset.
             *
             * We only extract the stack size and record that we
             * are using LC_MAIN.
             *
             * However, if we have NO dyld (static binary), we must
             * use entryoff ourselves as a fallback.
             */
            if (lc->cmdsize < sizeof(struct entry_point_command))
                break;
            struct entry_point_command *ep =
                (struct entry_point_command *)cmd_ptr;

            if (result->thread_count != 0) {
                kprintf("macho: duplicate LC_MAIN/LC_UNIXTHREAD\n");
                break;
            }

            result->using_lcmain = true;
            result->needs_dynlinker = true;

            if (ep->stacksize > 0) {
                result->user_stack_size = ep->stacksize;
                result->custom_stack = true;
            }

            /*
             * Store entryoff as a fallback entry point.
             * If dyld doesn't load, we use text_base + entryoff.
             * This gets overwritten if dyld loads successfully.
             */
            result->entry_point = text_base + ep->entryoff;
            result->validentry = true;
            result->thread_count++;

            break;
        }

        case LC_UNIXTHREAD: {
            /*
             * LC_UNIXTHREAD: Contains the initial thread state.
             * The PC field gives the absolute entry point.
             * Used by the dynamic linker itself (MH_DYLINKER).
             * Also used by static executables.
             */
            if (result->thread_count != 0) {
                kprintf("macho: duplicate LC_UNIXTHREAD/LC_MAIN\n");
                break;
            }

            struct thread_command *tc = (struct thread_command *)cmd_ptr;
            if (tc->cmdsize >= sizeof(struct thread_command) + 8) {
                uint32_t *state_ptr = (uint32_t *)(cmd_ptr +
                                     sizeof(struct thread_command));
                uint32_t flavor = state_ptr[0];

                if (flavor == ARM_THREAD_STATE64) {
                    struct arm_thread_state64 *ts =
                        (struct arm_thread_state64 *)(state_ptr + 2);
                    result->entry_point = ts->pc + (uint64_t)slide;
                    result->validentry = true;
                    result->thread_count++;
                }
            }
            break;
        }

        case LC_UUID: {
            if (lc->cmdsize < sizeof(struct uuid_command))
                break;
            struct uuid_command *uc = (struct uuid_command *)cmd_ptr;
            memcpy_k(result->uuid, uc->uuid, 16);
            result->has_uuid = true;
            break;
        }

        case LC_LOAD_DYLINKER: {
            /* Save pointer for pass 3 */
            if (depth == 1)
                dylinker_lcp = (struct dylinker_command *)cmd_ptr;
            break;
        }

        case LC_LOAD_DYLIB:
        case LC_REEXPORT_DYLIB: {
            /* Record dylib dependencies */
            struct dylib_command *dl = (struct dylib_command *)cmd_ptr;
            uint32_t name_off = dl->dylib.name_offset;
            if (name_off < lc->cmdsize &&
                result->ndylibs < MACHO_MAX_DYLIBS) {
                const char *dylib_path = (const char *)(cmd_ptr + name_off);
                strncpy_k(result->dylib_paths[result->ndylibs], dylib_path,
                          MACHO_DYLINKER_PATH_MAX - 1);
                result->ndylibs++;
            }
            break;
        }

        default:
            break;
        }

        cmd_ptr += lc->cmdsize;
    }

    /*
     * ================================================================
     * PASS 2: Map Segments
     *
     * For each LC_SEGMENT_64, load it into user VM.
     * ================================================================
     */
    cmd_ptr = cmds_buf;
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (cmd_ptr + sizeof(struct load_command) > cmds_buf + cmds_size)
            break;
        struct load_command *lc = (struct load_command *)cmd_ptr;
        if (lc->cmdsize < sizeof(struct load_command) ||
            cmd_ptr + lc->cmdsize > cmds_buf + cmds_size)
            break;

        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg =
                (struct segment_command_64 *)cmd_ptr;

            ret = load_segment(fd, seg, space, slide, result);
            if (ret != LOAD_SUCCESS) {
                kprintf("macho: load_segment failed for '%.16s': %d\n",
                        seg->segname, ret);
                pmm_free_pages(cmds_pa, order);
                return ret;
            }
        }

        cmd_ptr += lc->cmdsize;
    }

    /*
     * ================================================================
     * PASS 3: Dynamic Linker
     *
     * If LC_LOAD_DYLINKER was found (depth==1), recursively load dyld.
     * This mirrors XNU's load_dylinker() function.
     * ================================================================
     */
    if (dylinker_lcp != NULL && depth == 1) {
        if (dylinker_lcp->cmdsize < sizeof(struct dylinker_command) ||
            dylinker_lcp->name_offset >= dylinker_lcp->cmdsize) {
            pmm_free_pages(cmds_pa, order);
            return LOAD_BADMACHO;
        }

        const char *dyld_path = (const char *)((uint8_t *)dylinker_lcp +
                                dylinker_lcp->name_offset);

        /* Validate the path is null-terminated within the command */
        uint32_t maxsz = dylinker_lcp->cmdsize - dylinker_lcp->name_offset;
        uint64_t namelen = 0;
        while (namelen < maxsz && dyld_path[namelen] != '\0')
            namelen++;
        if (namelen >= maxsz) {
            pmm_free_pages(cmds_pa, order);
            return LOAD_BADMACHO;
        }

        strncpy_k(result->dylinker_path, dyld_path,
                  MACHO_DYLINKER_PATH_MAX - 1);
        result->dylinker_path[MACHO_DYLINKER_PATH_MAX - 1] = '\0';

        /*
         * Open dyld and load it recursively.
         * XNU's load_dylinker calls get_macho_vnode + parse_machfile
         * at depth+1.
         */
        int dyld_fd = vfs_open(result->dylinker_path, O_RDONLY, 0);
        if (dyld_fd < 0) {
            kprintf("macho: cannot open dyld '%s': %d\n",
                    result->dylinker_path, -dyld_fd);
            /* Don't fail — fall back to direct entry */
            kprintf("macho: WARNING: falling back to direct entry "
                    "(no dynamic linker)\n");
        } else {
            /* Read dyld's Mach-O header */
            struct mach_header_64 dyld_hdr;
            int64_t dread = vfs_read(dyld_fd, &dyld_hdr, sizeof(dyld_hdr));
            if (dread != (int64_t)sizeof(dyld_hdr)) {
                kprintf("macho: short read on dyld header\n");
                vfs_close(dyld_fd);
            } else if (dyld_hdr.magic != MH_MAGIC_64 ||
                       (dyld_hdr.cputype & ~CPU_ARCH_MASK) !=
                       (CPU_TYPE_ARM & ~0) ||
                       dyld_hdr.filetype != MH_DYLINKER) {
                kprintf("macho: dyld is not a valid MH_DYLINKER "
                        "(magic=0x%x type=%u)\n",
                        dyld_hdr.magic, dyld_hdr.filetype);
                vfs_close(dyld_fd);
            } else {
                /*
                 * Recursively parse dyld at depth 2.
                 *
                 * dyld loads at a separate location. XNU gives it an
                 * independent ASLR slide. For now we use slide=0 and
                 * let dyld's own vmaddrs determine placement.
                 *
                 * If dyld has no load address (vmaddr==0, fileoff==0),
                 * XNU places it after the main binary's max_vm_addr.
                 * We handle that below.
                 */
                /*
                 * Allocate dyld_result from PMM instead of the stack.
                 * load_result_t is ~17KB — putting it on the 16KB kernel
                 * stack causes stack overflow and corrupts the caller's
                 * result struct.
                 */
                uint64_t dr_pa = pmm_alloc_pages(3); /* 32KB (order 3 = 8 pages) */
                if (dr_pa == 0) {
                    kprintf("macho: OOM for dyld_result\n");
                    vfs_close(dyld_fd);
                } else {
                load_result_t *dyld_result = (load_result_t *)dr_pa;
                memset_k(dyld_result, 0, sizeof(*dyld_result));
                dyld_result->min_vm_addr = 0xFFFFFFFFFFFFFFFFUL;

                /*
                 * Compute dyld's slide. Our dyld is built with __TEXT
                 * at vmaddr 0, so we must slide it to a valid location.
                 * Place dyld right after the main binary's max VM address,
                 * aligned to 64KB (for ARM64 page table efficiency).
                 */
                int64_t dyld_slide = 0;
                uint64_t dyld_base = ALIGN_UP(result->max_vm_addr,
                                              0x10000);
                if (dyld_base < 0x200000000UL)
                    dyld_base = 0x200000000UL;  /* Minimum: 8GB mark */
                dyld_slide = (int64_t)dyld_base;

                load_return_t dyld_ret = parse_machfile(
                    dyld_fd, &dyld_hdr, space, depth + 1,
                    dyld_slide, dyld_result, result);

                vfs_close(dyld_fd);

                if (dyld_ret == LOAD_SUCCESS) {
                    /*
                     * XNU behavior: dyld's entry point overwrites the
                     * main binary's entry point. The kernel jumps to dyld,
                     * and dyld finds main() via LC_MAIN in the binary's
                     * own Mach-O header (which we pass on the stack).
                     */
                    result->entry_point = dyld_result->entry_point;
                    result->validentry = dyld_result->validentry;
                    result->dynlinker = true;
                    result->dynlinker_mach_header = dyld_result->mach_header;

                    /* Copy dyld's all_image_info if set */
                    if (dyld_result->all_image_info_addr != 0) {
                        result->all_image_info_addr =
                            dyld_result->all_image_info_addr;
                        result->all_image_info_size =
                            dyld_result->all_image_info_size;
                    }

                } else {
                    kprintf("macho: dyld load failed: %d "
                            "(falling back to direct entry)\n", dyld_ret);
                }

                pmm_free_pages(dr_pa, 3);
                }
            }
        }
    }

    /* Free load commands buffer */
    pmm_free_pages(cmds_pa, order);

    /*
     * Final validation: we must have an entry point.
     */
    if (!result->validentry) {
        kprintf("macho: no entry point found\n");
        return LOAD_BADMACHO;
    }

    return LOAD_SUCCESS;
}

/* ============================================================================
 * Public API
 * ============================================================================ */

/*
 * macho_validate_header - Validate a Mach-O 64-bit header
 */
int macho_validate_header(const struct mach_header_64 *hdr)
{
    if (hdr->magic != MH_MAGIC_64) {
        if (hdr->magic == MH_CIGAM_64) {
            kprintf("macho: byte-swapped Mach-O not supported\n");
            return -EINVAL;
        }
        if (hdr->magic == MH_MAGIC) {
            kprintf("macho: 32-bit Mach-O not supported\n");
            return -EINVAL;
        }
        kprintf("macho: bad magic 0x%x\n", hdr->magic);
        return -EINVAL;
    }

    if (hdr->cputype != (uint32_t)CPU_TYPE_ARM64) {
        kprintf("macho: unsupported cputype 0x%x (expected ARM64)\n",
                hdr->cputype);
        return -EINVAL;
    }

    if (hdr->filetype != MH_EXECUTE && hdr->filetype != MH_DYLINKER) {
        kprintf("macho: unsupported filetype %u\n", hdr->filetype);
        return -EINVAL;
    }

    if (hdr->ncmds > MACHO_MAX_LOAD_CMDS) {
        kprintf("macho: too many load commands (%u > %u)\n",
                hdr->ncmds, MACHO_MAX_LOAD_CMDS);
        return -EINVAL;
    }

    if (hdr->sizeofcmds > (512 * 1024)) {
        kprintf("macho: load commands too large (%u bytes)\n",
                hdr->sizeofcmds);
        return -EINVAL;
    }

    return 0;
}

/*
 * macho_load - Load a Mach-O executable into a user address space
 *
 * Main entry point for exec. Opens the file, reads the header,
 * and calls parse_machfile for the full multi-pass load.
 *
 * For executables with LC_MAIN + LC_LOAD_DYLINKER:
 *   - Segments are mapped
 *   - dyld is loaded recursively
 *   - result->entry_point is set to dyld's entry
 *   - result->mach_header is set to the main binary's __TEXT base
 *   - The caller (proc.c) pushes mach_header onto the stack for dyld
 *
 * For static executables with LC_UNIXTHREAD:
 *   - Segments are mapped
 *   - result->entry_point is set to the PC from the thread state
 *   - No dyld loading
 */
load_return_t macho_load(const char *path, struct vm_space *space,
                         load_result_t *result)
{
    struct mach_header_64 hdr;
    int fd;
    int64_t nread;
    int ret;

    /* Zero the result */
    memset_k(result, 0, sizeof(*result));
    result->min_vm_addr = 0xFFFFFFFFFFFFFFFFUL;

    /* Open the binary */
    fd = vfs_open(path, O_RDONLY, 0);
    if (fd < 0) {
        kprintf("macho: cannot open '%s': error %d\n", path, -fd);
        return LOAD_IOERROR;
    }

    /* Read the Mach-O header */
    nread = vfs_read(fd, &hdr, sizeof(hdr));
    if (nread != (int64_t)sizeof(hdr)) {
        kprintf("macho: short read on header (%ld bytes)\n", (long)nread);
        vfs_close(fd);
        return LOAD_IOERROR;
    }

    /* Validate header */
    ret = macho_validate_header(&hdr);
    if (ret != 0) {
        vfs_close(fd);
        return LOAD_BADMACHO;
    }

    /*
     * Parse and load at depth 1 (main binary), slide 0.
     *
     * When ASLR is implemented, compute a random slide here and
     * pass it to parse_machfile (only for PIE binaries).
     */
    int64_t aslr_slide = 0;

    load_return_t lret = parse_machfile(fd, &hdr, space, 1,
                                        aslr_slide, result, NULL);

    vfs_close(fd);

    if (lret != LOAD_SUCCESS)
        return lret;

    return LOAD_SUCCESS;
}
