/*
 * Kiseki OS - Mach-O Binary Format Definitions
 *
 * Structures and constants for the 64-bit Mach-O executable format,
 * matching Apple's <mach-o/loader.h> layout exactly.
 *
 * The loader implementation follows XNU's bsd/kern/mach_loader.c:
 *   - Multi-pass load command parsing
 *   - Recursive dyld loading via parse_machfile()
 *   - ASLR slide support for PIE binaries
 *   - Proper __PAGEZERO enforcement
 *
 * Reference: XNU bsd/kern/mach_loader.c, Apple cctools/include/mach-o/loader.h
 */

#ifndef _KERN_MACHO_H
#define _KERN_MACHO_H

#include <kiseki/types.h>

/* Forward declarations */
struct vm_space;

/* ============================================================================
 * Mach-O Magic Numbers
 * ============================================================================ */

#define MH_MAGIC_64         0xFEEDFACF  /* 64-bit Mach-O */
#define MH_CIGAM_64         0xCFFAEDFE  /* 64-bit byte-swapped */
#define MH_MAGIC            0xFEEDFACE  /* 32-bit Mach-O (rejected) */

/* ============================================================================
 * CPU Types (cputype field)
 * ============================================================================ */

#define CPU_ARCH_ABI64          0x01000000
#define CPU_ARCH_MASK           0xFF000000
#define CPU_TYPE_ARM            12
#define CPU_TYPE_ARM64          (CPU_TYPE_ARM | CPU_ARCH_ABI64)  /* 0x0100000C */

/* CPU subtypes */
#define CPU_SUBTYPE_ALL         0
#define CPU_SUBTYPE_ARM64_ALL   0
#define CPU_SUBTYPE_ARM64E      2
#define CPU_SUBTYPE_MASK        0xFF000000

/* ============================================================================
 * File Types (filetype field)
 * ============================================================================ */

#define MH_OBJECT           0x1     /* Relocatable object file */
#define MH_EXECUTE          0x2     /* Demand-paged executable */
#define MH_FVMLIB           0x3     /* Fixed VM shared library */
#define MH_CORE             0x4     /* Core file */
#define MH_PRELOAD          0x5     /* Preloaded executable */
#define MH_DYLIB            0x6     /* Dynamically bound shared library */
#define MH_DYLINKER         0x7     /* Dynamic link editor */
#define MH_BUNDLE           0x8     /* Dynamically bound bundle */
#define MH_DYLIB_STUB       0x9     /* Shared library stub */
#define MH_DSYM             0xA     /* Debug symbols */
#define MH_KEXT_BUNDLE      0xB     /* Kernel extension */
#define MH_FILESET          0xC     /* Kernel cache / file set */

/* ============================================================================
 * Mach-O Header Flags (flags field)
 * ============================================================================ */

#define MH_NOUNDEFS         0x00000001  /* No undefined references */
#define MH_INCRLINK         0x00000002  /* Output of incremental link */
#define MH_DYLDLINK         0x00000004  /* Input for the dynamic linker */
#define MH_BINDATLOAD       0x00000008  /* Bind undefined refs at load time */
#define MH_PREBOUND         0x00000010  /* Prebound (unused in practice) */
#define MH_SPLIT_SEGS       0x00000020  /* Split read-only and read-write */
#define MH_TWOLEVEL         0x00000080  /* Two-level namespaces */
#define MH_FORCE_FLAT       0x00000100  /* Force flat namespace */
#define MH_NOMULTIDEFS      0x00000200  /* No multiple definitions */
#define MH_PIE              0x00200000  /* Position-independent executable */
#define MH_HAS_TLV_DESCRIPTORS 0x00800000  /* Has thread-local variables */
#define MH_NO_HEAP_EXECUTION   0x01000000  /* No heap execution */
#define MH_ALLOW_STACK_EXECUTION 0x00020000

/* ============================================================================
 * Mach-O 64-bit Header
 *
 * Sits at offset 0 of any 64-bit Mach-O file.
 * Total size: 32 bytes.
 * ============================================================================ */

struct mach_header_64 {
    uint32_t    magic;          /* MH_MAGIC_64 */
    uint32_t    cputype;        /* CPU_TYPE_ARM64 */
    uint32_t    cpusubtype;     /* CPU_SUBTYPE_ALL */
    uint32_t    filetype;       /* MH_EXECUTE, MH_DYLIB, etc. */
    uint32_t    ncmds;          /* Number of load commands */
    uint32_t    sizeofcmds;     /* Size of all load commands */
    uint32_t    flags;          /* MH_PIE, MH_DYLDLINK, etc. */
    uint32_t    reserved;       /* Reserved (padding to 8-byte align) */
} __packed;

/* ============================================================================
 * Load Command Header
 *
 * Every load command starts with this 8-byte header.
 * ============================================================================ */

struct load_command {
    uint32_t    cmd;            /* Load command type (LC_*) */
    uint32_t    cmdsize;        /* Total size of this command */
} __packed;

/* ============================================================================
 * Load Command Types
 * ============================================================================ */

#define LC_REQ_DYLD             0x80000000

#define LC_SEGMENT_64           0x19        /* 64-bit segment */
#define LC_SYMTAB               0x02        /* Symbol table */
#define LC_SYMSEG               0x03        /* Symbol segment (obsolete) */
#define LC_THREAD               0x04        /* Thread state */
#define LC_UNIXTHREAD           0x05        /* Unix thread (entry + stack) */
#define LC_DYSYMTAB             0x0B        /* Dynamic symbol table */
#define LC_LOAD_DYLIB           0x0C        /* Load a dylib */
#define LC_ID_DYLIB             0x0D        /* Dylib identification */
#define LC_LOAD_DYLINKER        0x0E        /* Load dynamic linker */
#define LC_ID_DYLINKER          0x0F        /* Dynamic linker identification */
#define LC_PREBOUND_DYLIB       0x10        /* Prebound dylib */
#define LC_UUID                 0x1B        /* UUID */
#define LC_CODE_SIGNATURE       0x1D        /* Code signature */
#define LC_SEGMENT_SPLIT_INFO   0x1E        /* Segment split info */
#define LC_REEXPORT_DYLIB       (0x1F | LC_REQ_DYLD)
#define LC_ENCRYPTION_INFO_64   0x2C        /* 64-bit encryption info */
#define LC_DYLD_INFO            0x22        /* Compressed dyld info */
#define LC_DYLD_INFO_ONLY       (0x22 | LC_REQ_DYLD)
#define LC_FUNCTION_STARTS      0x26        /* Function start addresses */
#define LC_MAIN                 (0x28 | LC_REQ_DYLD)  /* Entry point */
#define LC_DATA_IN_CODE         0x29        /* Data in code info */
#define LC_SOURCE_VERSION       0x2A        /* Source version */
#define LC_DYLIB_CODE_SIGN_DRS  0x2B        /* Dylib code signing DRs */
#define LC_BUILD_VERSION        0x32        /* Build version */
#define LC_DYLD_EXPORTS_TRIE    (0x33 | LC_REQ_DYLD)
#define LC_DYLD_CHAINED_FIXUPS  (0x34 | LC_REQ_DYLD)
#define LC_FILESET_ENTRY        (0x35 | LC_REQ_DYLD)

/* ============================================================================
 * VM Protection Flags
 * ============================================================================ */

#define VM_PROT_NONE            0x00
#define VM_PROT_READ            0x01
#define VM_PROT_WRITE           0x02
#define VM_PROT_EXECUTE         0x04
#define VM_PROT_ALL             (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE)

/* ============================================================================
 * LC_SEGMENT_64 - 64-bit Segment Load Command
 * ============================================================================ */

struct segment_command_64 {
    uint32_t    cmd;            /* LC_SEGMENT_64 */
    uint32_t    cmdsize;
    char        segname[16];    /* Segment name (e.g., "__TEXT", "__DATA") */
    uint64_t    vmaddr;         /* Virtual address of this segment */
    uint64_t    vmsize;         /* Virtual memory size */
    uint64_t    fileoff;        /* File offset of this segment */
    uint64_t    filesize;       /* Amount to map from file */
    uint32_t    maxprot;        /* Maximum VM protection */
    uint32_t    initprot;       /* Initial VM protection */
    uint32_t    nsects;         /* Number of sections in this segment */
    uint32_t    flags;          /* Segment flags */
} __packed;

/* Segment flags */
#define SG_HIGHVM               0x1
#define SG_NORELOC              0x4
#define SG_PROTECTED_VERSION_1  0x8

/* ============================================================================
 * section_64 - 64-bit Section
 * ============================================================================ */

struct section_64 {
    char        sectname[16];   /* Section name (e.g., "__text", "__data") */
    char        segname[16];    /* Owning segment name */
    uint64_t    addr;           /* Virtual address */
    uint64_t    size;           /* Size in bytes */
    uint32_t    offset;         /* File offset */
    uint32_t    align;          /* Power of 2 alignment */
    uint32_t    reloff;         /* File offset of relocations */
    uint32_t    nreloc;         /* Number of relocation entries */
    uint32_t    flags;          /* Section type and attributes */
    uint32_t    reserved1;
    uint32_t    reserved2;
    uint32_t    reserved3;
} __packed;

/* Section types (low byte of flags) */
#define S_REGULAR                       0x0
#define S_ZEROFILL                      0x1
#define S_CSTRING_LITERALS              0x2
#define S_4BYTE_LITERALS                0x3
#define S_8BYTE_LITERALS                0x4
#define S_LITERAL_POINTERS              0x5
#define S_NON_LAZY_SYMBOL_POINTERS      0x6
#define S_LAZY_SYMBOL_POINTERS          0x7
#define S_SYMBOL_STUBS                  0x8
#define S_MOD_INIT_FUNC_POINTERS        0x9
#define S_MOD_TERM_FUNC_POINTERS        0xA
#define S_THREAD_LOCAL_REGULAR          0x11
#define S_THREAD_LOCAL_ZEROFILL         0x12
#define S_THREAD_LOCAL_VARIABLES        0x13

/* Section attributes */
#define S_ATTR_PURE_INSTRUCTIONS        0x80000000
#define S_ATTR_SOME_INSTRUCTIONS        0x00000400
#define S_ATTR_NO_TOC                   0x40000000
#define S_ATTR_STRIP_STATIC_SYMS        0x20000000

#define SECTION_TYPE(flags)             ((flags) & 0xFF)
#define SECTION_ATTRIBUTES(flags)       ((flags) & 0xFFFFFF00)

/* ============================================================================
 * LC_MAIN - Entry Point Command
 * ============================================================================ */

struct entry_point_command {
    uint32_t    cmd;            /* LC_MAIN */
    uint32_t    cmdsize;        /* 24 */
    uint64_t    entryoff;       /* File offset of main() from start of __TEXT */
    uint64_t    stacksize;      /* Initial stack size (0 = default) */
} __packed;

/* ============================================================================
 * LC_UNIXTHREAD - Unix Thread State Command
 * ============================================================================ */

struct thread_command {
    uint32_t    cmd;            /* LC_UNIXTHREAD or LC_THREAD */
    uint32_t    cmdsize;
} __packed;

/* ARM64 thread state flavor */
#define ARM_THREAD_STATE64      6
#define ARM_THREAD_STATE64_COUNT 68

struct arm_thread_state64 {
    uint64_t    x[29];          /* General purpose registers x0-x28 */
    uint64_t    fp;             /* Frame pointer (x29) */
    uint64_t    lr;             /* Link register (x30) */
    uint64_t    sp;             /* Stack pointer */
    uint64_t    pc;             /* Program counter */
    uint32_t    cpsr;           /* Current program status register */
    uint32_t    flags;          /* Flags */
} __packed;

/* ============================================================================
 * LC_LOAD_DYLINKER - Dynamic Linker Command
 * ============================================================================ */

struct dylinker_command {
    uint32_t    cmd;            /* LC_LOAD_DYLINKER or LC_ID_DYLINKER */
    uint32_t    cmdsize;
    uint32_t    name_offset;    /* Offset of path string from start of command */
} __packed;

/* ============================================================================
 * LC_LOAD_DYLIB / LC_ID_DYLIB - Dylib Command
 * ============================================================================ */

struct dylib {
    uint32_t    name_offset;
    uint32_t    timestamp;
    uint32_t    current_version;
    uint32_t    compatibility_version;
} __packed;

struct dylib_command {
    uint32_t    cmd;
    uint32_t    cmdsize;
    struct dylib dylib;
} __packed;

/* ============================================================================
 * LC_SYMTAB - Symbol Table Command
 * ============================================================================ */

struct symtab_command {
    uint32_t    cmd;
    uint32_t    cmdsize;
    uint32_t    symoff;
    uint32_t    nsyms;
    uint32_t    stroff;
    uint32_t    strsize;
} __packed;

/* ============================================================================
 * LC_DYSYMTAB - Dynamic Symbol Table Command
 * ============================================================================ */

struct dysymtab_command {
    uint32_t    cmd;
    uint32_t    cmdsize;
    uint32_t    ilocalsym;
    uint32_t    nlocalsym;
    uint32_t    iextdefsym;
    uint32_t    nextdefsym;
    uint32_t    iundefsym;
    uint32_t    nundefsym;
    uint32_t    tocoff;
    uint32_t    ntoc;
    uint32_t    modtaboff;
    uint32_t    nmodtab;
    uint32_t    extrefsymoff;
    uint32_t    nextrefsyms;
    uint32_t    indirectsymoff;
    uint32_t    nindirectsyms;
    uint32_t    extreloff;
    uint32_t    nextrel;
    uint32_t    locreloff;
    uint32_t    nlocrel;
} __packed;

/* ============================================================================
 * LC_UUID - UUID Command
 * ============================================================================ */

struct uuid_command {
    uint32_t    cmd;
    uint32_t    cmdsize;
    uint8_t     uuid[16];
} __packed;

/* ============================================================================
 * LC_BUILD_VERSION - Build Version Command
 * ============================================================================ */

struct build_version_command {
    uint32_t    cmd;
    uint32_t    cmdsize;
    uint32_t    platform;
    uint32_t    minos;
    uint32_t    sdk;
    uint32_t    ntools;
} __packed;

/* Platform identifiers */
#define PLATFORM_MACOS          1
#define PLATFORM_IOS            2
#define PLATFORM_TVOS           3
#define PLATFORM_WATCHOS        4
#define PLATFORM_BRIDGEOS       5
#define PLATFORM_DRIVERKIT      10

/* ============================================================================
 * LC_SOURCE_VERSION
 * ============================================================================ */

struct source_version_command {
    uint32_t    cmd;
    uint32_t    cmdsize;
    uint64_t    version;
} __packed;

/* ============================================================================
 * LC_DYLD_INFO / LC_DYLD_INFO_ONLY
 * ============================================================================ */

struct dyld_info_command {
    uint32_t    cmd;
    uint32_t    cmdsize;
    uint32_t    rebase_off;
    uint32_t    rebase_size;
    uint32_t    bind_off;
    uint32_t    bind_size;
    uint32_t    weak_bind_off;
    uint32_t    weak_bind_size;
    uint32_t    lazy_bind_off;
    uint32_t    lazy_bind_size;
    uint32_t    export_off;
    uint32_t    export_size;
} __packed;

/* ============================================================================
 * LC_DYLD_CHAINED_FIXUPS
 * ============================================================================ */

struct linkedit_data_command {
    uint32_t    cmd;
    uint32_t    cmdsize;
    uint32_t    dataoff;
    uint32_t    datasize;
} __packed;

/* ============================================================================
 * nlist_64 - Symbol Table Entry (64-bit)
 * ============================================================================ */

struct nlist_64 {
    uint32_t    n_strx;
    uint8_t     n_type;
    uint8_t     n_sect;
    uint16_t    n_desc;
    uint64_t    n_value;
} __packed;

/* n_type masks */
#define N_STAB      0xE0
#define N_PEXT      0x10
#define N_TYPE      0x0E
#define N_EXT       0x01

/* n_type values */
#define N_UNDF      0x00
#define N_ABS       0x02
#define N_SECT      0x0E
#define N_PBUD      0x0C
#define N_INDR      0x0A

#define NO_SECT     0

/* ============================================================================
 * Load Return Codes (matching XNU)
 * ============================================================================ */

typedef int load_return_t;

#define LOAD_SUCCESS        0
#define LOAD_BADARCH        1
#define LOAD_BADMACHO       2
#define LOAD_SHLIB          3
#define LOAD_FAILURE        5
#define LOAD_NOSPACE        6
#define LOAD_PROTECT        7
#define LOAD_RESOURCE       8
#define LOAD_IOERROR        9

/* ============================================================================
 * Mach-O Loader Limits
 * ============================================================================ */

#define MACHO_MAX_LOAD_CMDS     256     /* Max load commands */
#define MACHO_MAX_SEGMENTS      16      /* Maximum segments we handle */
#define MACHO_MAX_DYLIBS        64      /* Maximum dylib dependencies */
#define MACHO_DYLINKER_PATH_MAX 256     /* Max dylinker path length */

/* Default dyld path (XNU enforces this on release builds) */
#define DEFAULT_DYLD_PATH       "/usr/lib/dyld"

/* ============================================================================
 * load_result_t - Load Result Structure (matching XNU)
 *
 * Returned by macho_load / parse_machfile with all information needed
 * to start the process.
 * ============================================================================ */

typedef struct load_result {
    /* Entry point and header location */
    uint64_t    entry_point;            /* Resolved entry point VA */
    uint64_t    mach_header;            /* VA of mach_header in user space */

    /* Segment info */
    uint64_t    text_base;              /* Base VA of __TEXT segment */
    uint64_t    text_size;              /* Size of __TEXT segment */
    uint64_t    data_base;              /* Base VA of __DATA segment */
    uint64_t    data_size;              /* Size of __DATA segment */
    uint64_t    linkedit_base;          /* Base VA of __LINKEDIT segment */
    uint64_t    linkedit_size;          /* Size of __LINKEDIT */

    /* VM range (min/max across all segments) */
    uint64_t    min_vm_addr;
    uint64_t    max_vm_addr;

    /* Stack */
    uint64_t    user_stack;             /* User stack top */
    uint64_t    user_stack_size;        /* Requested stack size (0 = default) */
    bool        custom_stack;           /* Stack size was explicitly set */

    /* dyld info */
    bool        needs_dynlinker;        /* Binary requires dynamic linker */
    bool        dynlinker;              /* A dynamic linker was loaded */
    bool        using_lcmain;           /* Used LC_MAIN (not LC_UNIXTHREAD) */

    /* Dynamic linker info */
    char        dylinker_path[MACHO_DYLINKER_PATH_MAX];

    /* dyld's all_image_info section */
    uint64_t    all_image_info_addr;
    uint64_t    all_image_info_size;

    /* dyld's own mach_header (when loading dyld separately) */
    uint64_t    dynlinker_mach_header;

    /* Dylib dependencies */
    uint32_t    ndylibs;
    char        dylib_paths[MACHO_MAX_DYLIBS][MACHO_DYLINKER_PATH_MAX];

    /* UUID */
    uint8_t     uuid[16];
    bool        has_uuid;

    /* Flags */
    bool        has_pagezero;           /* Binary has __PAGEZERO */
    bool        is_pie;                 /* Binary is position-independent */
    int64_t     slide;                  /* ASLR slide applied */

    /* Validation counters */
    uint32_t    thread_count;           /* LC_UNIXTHREAD/LC_MAIN count */
    bool        validentry;             /* Entry point was set */
} load_result_t;

/* ============================================================================
 * Mach-O Loader API
 * ============================================================================ */

/*
 * macho_load - Load a Mach-O executable into a user address space
 *
 * This is the main entry point called by sys_execve_impl and
 * kernel_init_process. It handles:
 *   1. Open and read the Mach-O header from VFS
 *   2. Multi-pass load command parsing (matching XNU)
 *   3. Segment mapping into user VM
 *   4. Recursive dyld loading if LC_LOAD_DYLINKER is present
 *
 * If the binary uses LC_MAIN (standard for modern macOS binaries),
 * the kernel does NOT use entryoff. Instead it marks needs_dynlinker=true,
 * loads dyld, and the entry_point is set to dyld's entry. Dyld then
 * reads LC_MAIN from the binary's Mach-O header at runtime.
 *
 * Returns LOAD_SUCCESS on success, LOAD_* error code on failure.
 */
load_return_t macho_load(const char *path, struct vm_space *space,
                         load_result_t *result);

/*
 * macho_validate_header - Validate a Mach-O header
 */
int macho_validate_header(const struct mach_header_64 *hdr);

#endif /* _KERN_MACHO_H */
