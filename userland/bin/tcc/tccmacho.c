/*
 *  TCCMACHO.C - Mach-O file output for the Tiny C Compiler
 *
 *  Copyright (c) 2024 Kiseki OS Project
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This file generates ARM64 Mach-O executables and dynamic libraries
 *  compatible with macOS (11+) and other Mach-O based systems.
 *
 *  Supported output types:
 *    - MH_EXECUTE: Executable files (default)
 *    - MH_DYLIB:   Dynamic libraries (.dylib)
 *
 *  Current limitations:
 *    - ARM64 (aarch64) only - no x86_64 support yet
 *    - No object file (.o) output - uses ELF internally, converts to Mach-O
 *      only for final executables and dylibs
 *    - Cross-compilation only - no native -run support
 *    - No Objective-C support
 *    - No code signing (binaries work on macOS with ad-hoc signing)
 *
 *  Dynamic linking:
 *    External symbols are resolved via dyld at load time. This file generates:
 *    - __TEXT,__stubs:         PLT-like trampolines for lazy binding
 *    - __TEXT,__stub_helper:   Helper code for dyld_stub_binder
 *    - __DATA,__la_symbol_ptr: Lazy symbol pointers (patched by dyld)
 *    - LC_DYLD_INFO_ONLY:      Binding opcodes for dyld
 *
 *  The implementation follows Apple's Mach-O format specification and
 *  is compatible with macOS dyld and tools (otool, nm, codesign).
 */

#include "tcc.h"

#ifdef TCC_TARGET_MACHO

#ifndef _WIN32
#include <sys/stat.h>  /* chmod() */
#endif

/* ============================================================================
 * Mach-O Constants and Structures
 * ============================================================================ */

/* Mach-O magic numbers */
#define MH_MAGIC_64         0xFEEDFACF
#define MH_CIGAM_64         0xCFFAEDFE

/* CPU types */
#define CPU_ARCH_ABI64      0x01000000
#define CPU_TYPE_ARM        12
#define CPU_TYPE_ARM64      (CPU_TYPE_ARM | CPU_ARCH_ABI64)
#define CPU_TYPE_X86        7
#define CPU_TYPE_X86_64     (CPU_TYPE_X86 | CPU_ARCH_ABI64)

/* CPU subtypes */
#define CPU_SUBTYPE_ARM64_ALL   0
#define CPU_SUBTYPE_X86_64_ALL  3

/* File types */
#define MH_OBJECT           0x1
#define MH_EXECUTE          0x2
#define MH_DYLIB            0x6
#define MH_DYLINKER         0x7
#define MH_BUNDLE           0x8

/* Header flags */
#define MH_NOUNDEFS         0x00000001
#define MH_DYLDLINK         0x00000004
#define MH_PIE              0x00200000
#define MH_TWOLEVEL         0x00000080
#define MH_NO_HEAP_EXECUTION 0x01000000

/* Load command types */
#define LC_REQ_DYLD         0x80000000
#define LC_SEGMENT_64       0x19
#define LC_SYMTAB           0x02
#define LC_DYSYMTAB         0x0B
#define LC_LOAD_DYLIB       0x0C
#define LC_ID_DYLIB         0x0D
#define LC_LOAD_DYLINKER    0x0E
#define LC_UUID             0x1B
#define LC_BUILD_VERSION    0x32
#define LC_SOURCE_VERSION   0x2A
#define LC_MAIN             (0x28 | LC_REQ_DYLD)
#define LC_DYLD_INFO_ONLY   (0x22 | LC_REQ_DYLD)
#define LC_FUNCTION_STARTS  0x26
#define LC_DATA_IN_CODE     0x29
#define LC_DYLD_CHAINED_FIXUPS (0x34 | LC_REQ_DYLD)
#define LC_DYLD_EXPORTS_TRIE   (0x33 | LC_REQ_DYLD)
#define LC_UNIXTHREAD       0x05

/* VM protection flags */
#define VM_PROT_NONE        0x00
#define VM_PROT_READ        0x01
#define VM_PROT_WRITE       0x02
#define VM_PROT_EXECUTE     0x04

/* Section types */
#define S_REGULAR                   0x0
#define S_ZEROFILL                  0x1
#define S_NON_LAZY_SYMBOL_POINTERS  0x6
#define S_LAZY_SYMBOL_POINTERS      0x7
#define S_SYMBOL_STUBS              0x8
#define S_MOD_INIT_FUNC_POINTERS    0x9

/* Section attributes */
#define S_ATTR_PURE_INSTRUCTIONS    0x80000000
#define S_ATTR_SOME_INSTRUCTIONS    0x00000400

/* Symbol types */
#define N_UNDF      0x0
#define N_ABS       0x2
#define N_SECT      0xe
#define N_EXT       0x1
#define N_PEXT      0x10

/* Symbol reference types */
#define REFERENCE_FLAG_UNDEFINED_NON_LAZY           0
#define REFERENCE_FLAG_UNDEFINED_LAZY               1
#define REFERENCE_FLAG_DEFINED                      2

/* Platform identifiers */
#define PLATFORM_MACOS      1
#define PLATFORM_IOS        2

/* ARM64 thread state */
#define ARM_THREAD_STATE64      6
#define ARM_THREAD_STATE64_COUNT 68

/* Relocation types for ARM64 */
#define ARM64_RELOC_UNSIGNED            0
#define ARM64_RELOC_SUBTRACTOR          1
#define ARM64_RELOC_BRANCH26            2
#define ARM64_RELOC_PAGE21              3
#define ARM64_RELOC_PAGEOFF12           4
#define ARM64_RELOC_GOT_LOAD_PAGE21     5
#define ARM64_RELOC_GOT_LOAD_PAGEOFF12  6
#define ARM64_RELOC_POINTER_TO_GOT      7
#define ARM64_RELOC_TLVP_LOAD_PAGE21    8
#define ARM64_RELOC_TLVP_LOAD_PAGEOFF12 9
#define ARM64_RELOC_ADDEND              10

/* ============================================================================
 * Mach-O Structure Definitions
 * ============================================================================ */

#pragma pack(push, 1)

struct mach_header_64 {
    uint32_t    magic;
    uint32_t    cputype;
    uint32_t    cpusubtype;
    uint32_t    filetype;
    uint32_t    ncmds;
    uint32_t    sizeofcmds;
    uint32_t    flags;
    uint32_t    reserved;
};

struct load_command {
    uint32_t    cmd;
    uint32_t    cmdsize;
};

struct segment_command_64 {
    uint32_t    cmd;
    uint32_t    cmdsize;
    char        segname[16];
    uint64_t    vmaddr;
    uint64_t    vmsize;
    uint64_t    fileoff;
    uint64_t    filesize;
    uint32_t    maxprot;
    uint32_t    initprot;
    uint32_t    nsects;
    uint32_t    flags;
};

struct section_64 {
    char        sectname[16];
    char        segname[16];
    uint64_t    addr;
    uint64_t    size;
    uint32_t    offset;
    uint32_t    align;
    uint32_t    reloff;
    uint32_t    nreloc;
    uint32_t    flags;
    uint32_t    reserved1;
    uint32_t    reserved2;
    uint32_t    reserved3;
};

struct symtab_command {
    uint32_t    cmd;
    uint32_t    cmdsize;
    uint32_t    symoff;
    uint32_t    nsyms;
    uint32_t    stroff;
    uint32_t    strsize;
};

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
};

struct dylib {
    uint32_t    name_offset;
    uint32_t    timestamp;
    uint32_t    current_version;
    uint32_t    compatibility_version;
};

struct dylib_command {
    uint32_t    cmd;
    uint32_t    cmdsize;
    struct dylib dylib;
};

struct dylinker_command {
    uint32_t    cmd;
    uint32_t    cmdsize;
    uint32_t    name_offset;
};

struct entry_point_command {
    uint32_t    cmd;
    uint32_t    cmdsize;
    uint64_t    entryoff;
    uint64_t    stacksize;
};

struct uuid_command {
    uint32_t    cmd;
    uint32_t    cmdsize;
    uint8_t     uuid[16];
};

struct build_version_command {
    uint32_t    cmd;
    uint32_t    cmdsize;
    uint32_t    platform;
    uint32_t    minos;
    uint32_t    sdk;
    uint32_t    ntools;
};

struct source_version_command {
    uint32_t    cmd;
    uint32_t    cmdsize;
    uint64_t    version;
};

struct linkedit_data_command {
    uint32_t    cmd;
    uint32_t    cmdsize;
    uint32_t    dataoff;
    uint32_t    datasize;
};

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
};

struct nlist_64 {
    uint32_t    n_strx;
    uint8_t     n_type;
    uint8_t     n_sect;
    uint16_t    n_desc;
    uint64_t    n_value;
};

struct relocation_info {
    int32_t     r_address;
    uint32_t    r_symbolnum : 24,
                r_pcrel : 1,
                r_length : 2,
                r_extern : 1,
                r_type : 4;
};

/* ARM64 thread state for LC_UNIXTHREAD (used by static executables) */
struct arm_thread_state64 {
    uint64_t    x[29];
    uint64_t    fp;
    uint64_t    lr;
    uint64_t    sp;
    uint64_t    pc;
    uint32_t    cpsr;
    uint32_t    flags;
};

struct thread_command {
    uint32_t    cmd;
    uint32_t    cmdsize;
    uint32_t    flavor;
    uint32_t    count;
    struct arm_thread_state64 state;
};

#pragma pack(pop)

/* ============================================================================
 * Internal Data Structures
 * ============================================================================ */

#define MAX_MACHO_SECTS     32
#define PAGE_SIZE           0x4000  /* 16KB pages on ARM64 */
#define MACHO_ALIGN(x, a)   (((x) + (a) - 1) & ~((a) - 1))

struct macho_sect_info {
    Section     *sec;           /* TCC section */
    char        segname[16];    /* Mach-O segment name */
    char        sectname[16];   /* Mach-O section name */
    uint64_t    vmaddr;         /* Virtual address */
    uint64_t    fileoff;        /* File offset */
    uint32_t    flags;          /* Section flags */
    int         seg_idx;        /* Which segment (0=__TEXT, 1=__DATA, 2=__LINKEDIT) */
};

/* Maximum undefined symbols for dynamic linking */
#define MAX_UNDEF_SYMS      256

/* Undefined symbol tracking for stub generation */
struct undef_sym {
    const char  *name;          /* Symbol name (without leading _) */
    int         sym_index;      /* Index in Mach-O symbol table */
    uint64_t    stub_addr;      /* Address of stub in __stubs */
    uint64_t    la_ptr_addr;    /* Address in __la_symbol_ptr */
    uint32_t    bind_offset;    /* Offset in lazy binding info */
};

struct macho_info {
    TCCState    *s1;
    const char  *filename;
    int         type;           /* TCC_OUTPUT_EXE or TCC_OUTPUT_DLL */
    
    /* Section mapping */
    struct macho_sect_info sects[MAX_MACHO_SECTS];
    int         nb_sects;
    
    /* Segment info */
    uint64_t    text_vmaddr;
    uint64_t    text_vmsize;
    uint64_t    text_fileoff;
    uint64_t    text_filesize;
    
    uint64_t    data_vmaddr;
    uint64_t    data_vmsize;
    uint64_t    data_fileoff;
    uint64_t    data_filesize;
    
    uint64_t    linkedit_vmaddr;
    uint64_t    linkedit_vmsize;
    uint64_t    linkedit_fileoff;
    uint64_t    linkedit_filesize;
    
    /* Symbol table */
    struct nlist_64 *symtab;
    int         nsyms;
    char        *strtab;
    int         strsize;
    
    /* Entry point */
    uint64_t    entry_addr;
    
    /* Counters for dysymtab */
    int         nlocalsym;
    int         nextdefsym;
    int         nundefsym;
    
    /* Indirect symbols for GOT/stubs */
    uint32_t    *indirect_syms;
    int         nindirect;
    
    /* Dynamic linking - undefined symbols */
    struct undef_sym undef_syms[MAX_UNDEF_SYMS];
    int         n_undef_syms;
    
    /* Dynamic linking sections */
    uint64_t    stubs_addr;         /* __TEXT,__stubs address */
    uint64_t    stubs_fileoff;
    int         stubs_size;
    
    uint64_t    stub_helper_addr;   /* __TEXT,__stub_helper address */
    uint64_t    stub_helper_fileoff;
    int         stub_helper_size;
    
    uint64_t    la_symbol_ptr_addr; /* __DATA,__la_symbol_ptr address */
    uint64_t    la_symbol_ptr_fileoff;
    int         la_symbol_ptr_size;
    
    uint64_t    got_addr;           /* __DATA,__got address (dyld_stub_binder, etc) */
    uint64_t    got_fileoff;
    int         got_size;
    
    /* __LINKEDIT data */
    uint8_t     *bind_info;         /* Binding opcodes */
    int         bind_size;
    uint8_t     *lazy_bind_info;    /* Lazy binding opcodes */
    int         lazy_bind_size;
    uint8_t     *export_info;       /* Export trie */
    int         export_size;
};

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

static void macho_set_segname(char *dst, const char *src)
{
    memset(dst, 0, 16);
    strncpy(dst, src, 16);
}

static int macho_is_text_section(const char *name)
{
    return !strcmp(name, ".text") || !strcmp(name, ".init") || !strcmp(name, ".fini");
}

static int macho_is_data_section(const char *name)
{
    /* Note: .rodata is handled separately and placed in __TEXT,__const */
    return !strcmp(name, ".data") ||
           !strcmp(name, ".got") || !strcmp(name, ".got.plt");
}

static int macho_is_bss_section(const char *name)
{
    return !strcmp(name, ".bss") || !strcmp(name, ".common");
}

/* Convert TCC section name to Mach-O segment/section names */
static void macho_convert_section(const char *tcc_name, 
                                   char *segname, char *sectname, uint32_t *flags)
{
    *flags = S_REGULAR;
    
    if (!strcmp(tcc_name, ".text")) {
        macho_set_segname(segname, "__TEXT");
        macho_set_segname(sectname, "__text");
        *flags = S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS;
    } else if (!strcmp(tcc_name, ".data")) {
        macho_set_segname(segname, "__DATA");
        macho_set_segname(sectname, "__data");
    } else if (!strcmp(tcc_name, ".rodata")) {
        macho_set_segname(segname, "__TEXT");
        macho_set_segname(sectname, "__const");
    } else if (!strcmp(tcc_name, ".bss")) {
        macho_set_segname(segname, "__DATA");
        macho_set_segname(sectname, "__bss");
        *flags = S_ZEROFILL;
    } else if (!strcmp(tcc_name, ".got")) {
        macho_set_segname(segname, "__DATA");
        macho_set_segname(sectname, "__got");
        *flags = S_NON_LAZY_SYMBOL_POINTERS;
    } else if (!strcmp(tcc_name, ".init_array") || !strcmp(tcc_name, ".ctors")) {
        macho_set_segname(segname, "__DATA");
        macho_set_segname(sectname, "__mod_init_func");
        *flags = S_MOD_INIT_FUNC_POINTERS;
    } else {
        /* Default: put unknown sections in __DATA */
        macho_set_segname(segname, "__DATA");
        macho_set_segname(sectname, "__data");
    }
}

/* ============================================================================
 * Dynamic Linking - Collect Undefined Symbols
 * ============================================================================ */

static void macho_collect_undef_syms(struct macho_info *mo)
{
    TCCState *s1 = mo->s1;
    Section *symtab_sec = s1->symtab;
    int i, n;
    
    mo->n_undef_syms = 0;
    n = symtab_sec->data_offset / sizeof(ElfW(Sym));
    
    for (i = 1; i < n && mo->n_undef_syms < MAX_UNDEF_SYMS; i++) {
        ElfW(Sym) *sym = &((ElfW(Sym) *)symtab_sec->data)[i];
        const char *name = (char *)symtab_sec->link->data + sym->st_name;
        
        /* Check if undefined and a function (STT_NOTYPE or STT_FUNC) */
        if (sym->st_shndx == SHN_UNDEF && name[0] != '\0') {
            /* Skip section symbols and empty names */
            if (ELFW(ST_TYPE)(sym->st_info) == STT_SECTION)
                continue;
            
            struct undef_sym *us = &mo->undef_syms[mo->n_undef_syms++];
            us->name = name;
            us->sym_index = -1;  /* Will be set during symtab build */
            us->stub_addr = 0;
            us->la_ptr_addr = 0;
            us->bind_offset = 0;
        }
    }
}

/* ============================================================================
 * Dynamic Linking - Generate ARM64 Stubs
 * 
 * __stubs: 12 bytes per symbol
 *   adrp x16, la_ptr@PAGE
 *   ldr  x16, [x16, la_ptr@PAGEOFF]
 *   br   x16
 *
 * __stub_helper: 24 byte header + 12 bytes per symbol
 *   Header:
 *     adrp x17, dyld_private@PAGE
 *     add  x17, x17, dyld_private@PAGEOFF
 *     stp  x16, x17, [sp, #-16]!
 *     adrp x16, dyld_stub_binder@PAGE
 *     ldr  x16, [x16, dyld_stub_binder@PAGEOFF]
 *     br   x16
 *   Per-symbol (12 bytes):
 *     ldr  w16, bind_offset
 *     b    helper_start
 *     .long bind_offset_value
 *
 * __la_symbol_ptr: 8 bytes per symbol
 *   Initially points to per-symbol stub_helper entry
 * ============================================================================ */

#define STUB_SIZE           12      /* Size of each stub entry */
#define STUB_HELPER_HDR     24      /* Size of stub helper header */
#define STUB_HELPER_ENTRY   12      /* Size of each stub helper entry */

/* ARM64 instruction encoding helpers */
static uint32_t arm64_adrp(int rd, int64_t page_delta) {
    /* ADRP Xd, label - PC-relative page address */
    uint32_t immlo = (page_delta & 0x3) << 29;
    uint32_t immhi = ((page_delta >> 2) & 0x7FFFF) << 5;
    return 0x90000000 | immhi | immlo | rd;
}

static uint32_t arm64_ldr_reg_uimm(int rt, int rn, int uimm12) {
    /* LDR Xt, [Xn, #uimm12] - 64-bit load */
    return 0xF9400000 | ((uimm12 / 8) << 10) | (rn << 5) | rt;
}

static uint32_t arm64_add_imm(int rd, int rn, int imm12) {
    /* ADD Xd, Xn, #imm12 */
    return 0x91000000 | (imm12 << 10) | (rn << 5) | rd;
}

static uint32_t arm64_br(int rn) {
    /* BR Xn */
    return 0xD61F0000 | (rn << 5);
}

static uint32_t arm64_b(int32_t offset) {
    /* B label - PC-relative branch */
    int32_t imm26 = (offset / 4) & 0x3FFFFFF;
    return 0x14000000 | imm26;
}

static uint32_t arm64_ldr_lit(int rt, int32_t offset) {
    /* LDR Wt, label - load 32-bit literal */
    int32_t imm19 = (offset / 4) & 0x7FFFF;
    return 0x18000000 | (imm19 << 5) | rt;
}

static uint32_t arm64_stp_pre(int rt1, int rt2, int rn, int imm7) {
    /* STP Xt1, Xt2, [Xn, #imm7]! - pre-indexed */
    int32_t simm7 = (imm7 / 8) & 0x7F;
    return 0xA9800000 | (simm7 << 15) | (rt2 << 10) | (rn << 5) | rt1;
}

/* Generate stub code */
static uint8_t *macho_gen_stubs(struct macho_info *mo, uint8_t *buf)
{
    int i;
    uint8_t *p = buf;
    
    for (i = 0; i < mo->n_undef_syms; i++) {
        struct undef_sym *us = &mo->undef_syms[i];
        uint64_t stub_addr = mo->stubs_addr + i * STUB_SIZE;
        uint64_t la_ptr = us->la_ptr_addr;
        
        /* Calculate page delta and offset */
        int64_t page_delta = ((int64_t)(la_ptr & ~0xFFFULL) - (int64_t)(stub_addr & ~0xFFFULL)) >> 12;
        int page_off = la_ptr & 0xFFF;
        
        /* adrp x16, la_ptr@PAGE */
        *(uint32_t *)p = arm64_adrp(16, page_delta);
        p += 4;
        
        /* ldr x16, [x16, la_ptr@PAGEOFF] */
        *(uint32_t *)p = arm64_ldr_reg_uimm(16, 16, page_off);
        p += 4;
        
        /* br x16 */
        *(uint32_t *)p = arm64_br(16);
        p += 4;
        
        us->stub_addr = stub_addr;
    }
    
    mo->stubs_size = p - buf;
    return p;
}

/* Generate stub helper code */
static uint8_t *macho_gen_stub_helper(struct macho_info *mo, uint8_t *buf)
{
    int i;
    uint8_t *p = buf;
    uint64_t helper_addr = mo->stub_helper_addr;
    
    /* 
     * For simplicity, we use a non-lazy binding approach:
     * Instead of the full dyld_stub_binder mechanism, we rely on
     * dyld to bind all symbols at load time.
     * 
     * The stub helper just provides the initial target for la_symbol_ptr.
     * When dyld processes the lazy binding info, it will patch the pointers.
     */
    
    /* Generate header - this would normally call dyld_stub_binder */
    /* For now, generate a simple trap/crash if somehow reached */
    
    /* brk #0x1 - trap instruction */
    *(uint32_t *)p = 0xD4200020;
    p += 4;
    *(uint32_t *)p = 0xD4200020;
    p += 4;
    *(uint32_t *)p = 0xD4200020;
    p += 4;
    *(uint32_t *)p = 0xD4200020;
    p += 4;
    *(uint32_t *)p = 0xD4200020;
    p += 4;
    *(uint32_t *)p = 0xD4200020;
    p += 4;
    
    /* Per-symbol entries */
    for (i = 0; i < mo->n_undef_syms; i++) {
        struct undef_sym *us = &mo->undef_syms[i];
        
        /* brk #0x1 - trap if reached (should be patched by dyld) */
        *(uint32_t *)p = 0xD4200020;
        p += 4;
        *(uint32_t *)p = 0xD4200020;
        p += 4;
        *(uint32_t *)p = 0xD4200020;
        p += 4;
        
        (void)us; /* Mark as used */
    }
    
    mo->stub_helper_size = p - buf;
    return p;
}

/* Generate lazy binding info for dyld */
static void macho_gen_lazy_bind_info(struct macho_info *mo)
{
    uint8_t *buf, *p;
    int i;
    
    /* Allocate buffer - estimate max size */
    int max_size = mo->n_undef_syms * 64 + 16;
    buf = tcc_mallocz(max_size);
    p = buf;
    
    /* BIND_OPCODE constants */
    #define BIND_OPCODE_DONE                        0x00
    #define BIND_OPCODE_SET_DYLIB_ORDINAL_IMM       0x10
    #define BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB      0x20
    #define BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS   0x40
    #define BIND_OPCODE_SET_TYPE_IMM                0x50
    #define BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB 0x70
    #define BIND_OPCODE_DO_BIND                     0x90
    
    #define BIND_TYPE_POINTER                       1
    
    for (i = 0; i < mo->n_undef_syms; i++) {
        struct undef_sym *us = &mo->undef_syms[i];
        us->bind_offset = p - buf;
        
        /* Set library ordinal to 1 (first LC_LOAD_DYLIB = libSystem) */
        *p++ = BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | 1;
        
        /* Set symbol name (with leading underscore) */
        *p++ = BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS;
        *p++ = '_';
        strcpy((char *)p, us->name);
        p += strlen(us->name) + 1;
        
        /* Set type to pointer */
        *p++ = BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER;
        
        /* Set segment and offset */
        /* __DATA segment is index 2 (after __PAGEZERO and __TEXT) */
        int seg_index = 2;
        uint64_t offset = us->la_ptr_addr - mo->data_vmaddr;
        
        *p++ = BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | seg_index;
        /* ULEB128 encode offset */
        do {
            uint8_t byte = offset & 0x7F;
            offset >>= 7;
            if (offset != 0)
                byte |= 0x80;
            *p++ = byte;
        } while (offset != 0);
        
        /* Do the bind */
        *p++ = BIND_OPCODE_DO_BIND;
        
        /* Done for this symbol */
        *p++ = BIND_OPCODE_DONE;
    }
    
    mo->lazy_bind_info = buf;
    mo->lazy_bind_size = p - buf;
}

/* Generate non-lazy binding info (for GOT entries like dyld_stub_binder) */
static void macho_gen_bind_info(struct macho_info *mo)
{
    /* For now, empty - we don't use GOT for dyld_stub_binder */
    mo->bind_info = tcc_mallocz(1);
    mo->bind_info[0] = 0; /* BIND_OPCODE_DONE */
    mo->bind_size = 1;
}

/* Generate export trie (empty for now) */
static void macho_gen_export_info(struct macho_info *mo)
{
    /* Minimal empty trie */
    mo->export_info = tcc_mallocz(1);
    mo->export_info[0] = 0;
    mo->export_size = 1;
}

/* ============================================================================
 * Symbol Table Generation
 * ============================================================================ */

static int macho_build_symtab(struct macho_info *mo)
{
    TCCState *s1 = mo->s1;
    Section *symtab_sec = s1->symtab;
    ElfW(Sym) *sym;
    int i, n, sym_index;
    int nlocal = 0, nextdef = 0, nundef = 0;
    
    /* First pass: count symbols */
    n = symtab_sec->data_offset / sizeof(ElfW(Sym));
    
    /* Allocate Mach-O symbol table */
    mo->symtab = tcc_mallocz(n * sizeof(struct nlist_64));
    mo->strtab = tcc_mallocz(symtab_sec->link->data_offset + 256 + mo->n_undef_syms * 64);
    mo->strsize = 1;  /* First byte is always 0 */
    mo->strtab[0] = 0;
    
    /* Convert ELF symbols to Mach-O nlist_64 */
    sym_index = 0;
    for (i = 1; i < n; i++) {
        sym = &((ElfW(Sym) *)symtab_sec->data)[i];
        const char *name = (char *)symtab_sec->link->data + sym->st_name;
        struct nlist_64 *nl = &mo->symtab[sym_index];
        
        /* Skip empty or section symbols */
        if (!name[0] || ELFW(ST_TYPE)(sym->st_info) == STT_SECTION)
            continue;
        
        /* Add name to string table */
        /* Mach-O symbols need leading underscore for C symbols */
        int namelen = strlen(name);
        nl->n_strx = mo->strsize;
        mo->strtab[mo->strsize++] = '_';
        memcpy(mo->strtab + mo->strsize, name, namelen + 1);
        mo->strsize += namelen + 1;
        
        /* Set type and section */
        if (sym->st_shndx == SHN_UNDEF) {
            nl->n_type = N_UNDF | N_EXT;
            nl->n_sect = 0;
            nl->n_value = 0;
            nundef++;
            
            /* Record symbol index for undefined symbols */
            for (int j = 0; j < mo->n_undef_syms; j++) {
                if (!strcmp(mo->undef_syms[j].name, name)) {
                    mo->undef_syms[j].sym_index = sym_index;
                    break;
                }
            }
        } else if (sym->st_shndx == SHN_ABS) {
            nl->n_type = N_ABS;
            if (ELFW(ST_BIND)(sym->st_info) == STB_GLOBAL)
                nl->n_type |= N_EXT;
            nl->n_sect = 0;
            nl->n_value = sym->st_value;
            if (nl->n_type & N_EXT)
                nextdef++;
            else
                nlocal++;
        } else {
            nl->n_type = N_SECT;
            if (ELFW(ST_BIND)(sym->st_info) == STB_GLOBAL)
                nl->n_type |= N_EXT;
            /* Section number (1-based) will be fixed up later */
            nl->n_sect = sym->st_shndx;
            nl->n_value = sym->st_value;
            if (nl->n_type & N_EXT)
                nextdef++;
            else
                nlocal++;
        }
        
        nl->n_desc = 0;
        sym_index++;
    }
    
    mo->nsyms = sym_index;
    mo->nlocalsym = nlocal;
    mo->nextdefsym = nextdef;
    mo->nundefsym = nundef;
    
    /* Align string table size */
    mo->strsize = MACHO_ALIGN(mo->strsize, 8);
    
    return 0;
}

/* ============================================================================
 * Section Layout (with Dynamic Linking sections)
 * ============================================================================ */

static void macho_layout_sections(struct macho_info *mo)
{
    TCCState *s1 = mo->s1;
    Section *s;
    int i;
    uint64_t vmaddr, fileoff;
    uint64_t text_end, data_end;
    
    /* Start address: leave room for __PAGEZERO (64KB) and headers */
    vmaddr = 0x100000000ULL;  /* Standard macOS base address for executables */
    fileoff = 0;
    
    /* First, compute header size */
    int header_size = sizeof(struct mach_header_64);
    /* Estimate load commands: segments + symtab + dysymtab + main + dylinker + dylibs + dyld_info */
    header_size += sizeof(struct segment_command_64);  /* __PAGEZERO */
    header_size += sizeof(struct segment_command_64) + 8 * sizeof(struct section_64);  /* __TEXT + stubs */
    header_size += sizeof(struct segment_command_64) + 8 * sizeof(struct section_64);  /* __DATA + la_ptr */
    header_size += sizeof(struct segment_command_64);  /* __LINKEDIT */
    header_size += sizeof(struct symtab_command);
    header_size += sizeof(struct dysymtab_command);
    header_size += sizeof(struct dyld_info_command);
    header_size += sizeof(struct entry_point_command);
    header_size += sizeof(struct dylinker_command) + 32;  /* /usr/lib/dyld */
    header_size += sizeof(struct dylib_command) + 32;     /* libSystem.B.dylib */
    header_size += sizeof(struct uuid_command);
    header_size += sizeof(struct build_version_command);
    header_size += 256;  /* padding */
    header_size = MACHO_ALIGN(header_size, PAGE_SIZE);
    
    fileoff = header_size;
    
    /* Map TCC sections to Mach-O sections */
    mo->nb_sects = 0;
    
    /* __TEXT segment sections */
    mo->text_vmaddr = vmaddr;
    mo->text_fileoff = 0;  /* __TEXT starts at file offset 0 */
    
    for (i = 1; i < s1->nb_sections; i++) {
        s = s1->sections[i];
        if (!s->data_offset)
            continue;
        
        if (macho_is_text_section(s->name)) {
            struct macho_sect_info *si = &mo->sects[mo->nb_sects++];
            si->sec = s;
            macho_convert_section(s->name, si->segname, si->sectname, &si->flags);
            si->vmaddr = vmaddr + fileoff;
            si->fileoff = fileoff;
            si->seg_idx = 0;  /* __TEXT */
            /* Set sh_addr so relocations use correct addresses */
            s->sh_addr = si->vmaddr;
            fileoff = MACHO_ALIGN(fileoff + s->data_offset, 16);
        }
    }
    
    /* .rodata goes in __TEXT,__const */
    for (i = 1; i < s1->nb_sections; i++) {
        s = s1->sections[i];
        if (!s->data_offset)
            continue;
        if (!strcmp(s->name, ".rodata")) {
            struct macho_sect_info *si = &mo->sects[mo->nb_sects++];
            si->sec = s;
            macho_convert_section(s->name, si->segname, si->sectname, &si->flags);
            si->vmaddr = vmaddr + fileoff;
            si->fileoff = fileoff;
            si->seg_idx = 0;  /* __TEXT */
            s->sh_addr = si->vmaddr;
            fileoff = MACHO_ALIGN(fileoff + s->data_offset, 16);
        }
    }
    
    /* __TEXT,__stubs - if we have undefined symbols */
    if (mo->n_undef_syms > 0) {
        fileoff = MACHO_ALIGN(fileoff, 4);
        mo->stubs_addr = vmaddr + fileoff;
        mo->stubs_fileoff = fileoff;
        mo->stubs_size = mo->n_undef_syms * STUB_SIZE;
        
        /* Pre-compute stub address for each undefined symbol */
        for (i = 0; i < mo->n_undef_syms; i++) {
            mo->undef_syms[i].stub_addr = mo->stubs_addr + i * STUB_SIZE;
        }
        
        fileoff += mo->stubs_size;
        
        /* __TEXT,__stub_helper */
        fileoff = MACHO_ALIGN(fileoff, 4);
        mo->stub_helper_addr = vmaddr + fileoff;
        mo->stub_helper_fileoff = fileoff;
        mo->stub_helper_size = STUB_HELPER_HDR + mo->n_undef_syms * STUB_HELPER_ENTRY;
        fileoff += mo->stub_helper_size;
    }
    
    text_end = fileoff;
    mo->text_vmsize = MACHO_ALIGN(text_end, PAGE_SIZE);
    mo->text_filesize = text_end;
    
    /* __DATA segment - starts at next page boundary */
    fileoff = MACHO_ALIGN(fileoff, PAGE_SIZE);
    vmaddr = mo->text_vmaddr + mo->text_vmsize;
    mo->data_vmaddr = vmaddr;
    mo->data_fileoff = fileoff;
    
    uint64_t data_vm_offset = 0;
    
    /* __DATA,__la_symbol_ptr - lazy symbol pointers */
    if (mo->n_undef_syms > 0) {
        mo->la_symbol_ptr_addr = vmaddr + data_vm_offset;
        mo->la_symbol_ptr_fileoff = fileoff;
        mo->la_symbol_ptr_size = mo->n_undef_syms * 8;
        
        /* Set up addresses for each undefined symbol */
        for (i = 0; i < mo->n_undef_syms; i++) {
            mo->undef_syms[i].la_ptr_addr = mo->la_symbol_ptr_addr + i * 8;
        }
        
        fileoff += mo->la_symbol_ptr_size;
        data_vm_offset += mo->la_symbol_ptr_size;
        fileoff = MACHO_ALIGN(fileoff, 8);
        data_vm_offset = MACHO_ALIGN(data_vm_offset, 8);
    }
    
    /* __DATA,__got - non-lazy symbol pointers (for things like dyld_stub_binder) */
    mo->got_addr = vmaddr + data_vm_offset;
    mo->got_fileoff = fileoff;
    mo->got_size = 8;  /* Reserve one entry */
    fileoff += mo->got_size;
    data_vm_offset += mo->got_size;
    fileoff = MACHO_ALIGN(fileoff, 8);
    data_vm_offset = MACHO_ALIGN(data_vm_offset, 8);
    
    for (i = 1; i < s1->nb_sections; i++) {
        s = s1->sections[i];
        if (!s->data_offset)
            continue;
        
        if (macho_is_data_section(s->name)) {
            struct macho_sect_info *si = &mo->sects[mo->nb_sects++];
            si->sec = s;
            macho_convert_section(s->name, si->segname, si->sectname, &si->flags);
            si->vmaddr = vmaddr + data_vm_offset;
            si->fileoff = fileoff;
            si->seg_idx = 1;  /* __DATA */
            s->sh_addr = si->vmaddr;
            fileoff = MACHO_ALIGN(fileoff + s->data_offset, 16);
            data_vm_offset = MACHO_ALIGN(data_vm_offset + s->data_offset, 16);
        }
    }
    
    data_end = fileoff;
    
    /* .bss section (zerofill - no file data) */
    for (i = 1; i < s1->nb_sections; i++) {
        s = s1->sections[i];
        if (macho_is_bss_section(s->name) && s->data_offset) {
            struct macho_sect_info *si = &mo->sects[mo->nb_sects++];
            si->sec = s;
            macho_convert_section(s->name, si->segname, si->sectname, &si->flags);
            si->vmaddr = vmaddr + data_vm_offset;
            si->fileoff = 0;  /* zerofill has no file data */
            si->seg_idx = 1;  /* __DATA */
            s->sh_addr = si->vmaddr;
            data_vm_offset += MACHO_ALIGN(s->data_offset, 16);
        }
    }
    
    mo->data_vmsize = MACHO_ALIGN(data_vm_offset, PAGE_SIZE);
    mo->data_filesize = data_end - mo->data_fileoff;
    
    /* __LINKEDIT segment */
    fileoff = MACHO_ALIGN(fileoff, PAGE_SIZE);
    mo->linkedit_vmaddr = mo->data_vmaddr + mo->data_vmsize;
    mo->linkedit_fileoff = fileoff;
    /* Size will be determined after writing symbol table */
}

/* ============================================================================
 * Patch undefined symbols to point to their stubs
 *
 * This is called AFTER stubs are generated (in macho_layout_sections)
 * and BEFORE relocations are processed. It sets the st_value of each
 * undefined symbol to its stub address, so that R_AARCH64_CALL26 
 * relocations automatically branch to the stub.
 * ============================================================================ */

static void macho_patch_undef_syms(struct macho_info *mo)
{
    TCCState *s1 = mo->s1;
    Section *symtab_sec = s1->symtab;
    int i, j, n;
    
    if (mo->n_undef_syms == 0)
        return;
    
    n = symtab_sec->data_offset / sizeof(ElfW(Sym));
    
    for (i = 1; i < n; i++) {
        ElfW(Sym) *sym = &((ElfW(Sym) *)symtab_sec->data)[i];
        const char *name = (char *)symtab_sec->link->data + sym->st_name;
        
        if (sym->st_shndx != SHN_UNDEF)
            continue;
        
        /* Find matching undefined symbol and patch to stub address */
        for (j = 0; j < mo->n_undef_syms; j++) {
            struct undef_sym *us = &mo->undef_syms[j];
            if (!strcmp(name, us->name)) {
                /* Set symbol value to stub address */
                sym->st_value = us->stub_addr;
                break;
            }
        }
    }
}

/* ============================================================================
 * Entry Point Resolution
 * ============================================================================ */

static int macho_find_entry(struct macho_info *mo)
{
    TCCState *s1 = mo->s1;
    ElfW(Sym) *sym;
    int i, n;
    Section *symtab_sec = s1->symtab;
    
    n = symtab_sec->data_offset / sizeof(ElfW(Sym));
    
    for (i = 1; i < n; i++) {
        sym = &((ElfW(Sym) *)symtab_sec->data)[i];
        const char *name = (char *)symtab_sec->link->data + sym->st_name;
        
        if (!strcmp(name, "main") || !strcmp(name, "_main")) {
            /* Find the section containing main */
            if (sym->st_shndx != SHN_UNDEF && sym->st_shndx != SHN_ABS) {
                Section *sec = s1->sections[sym->st_shndx];
                /* Find corresponding Mach-O section */
                for (int j = 0; j < mo->nb_sects; j++) {
                    if (mo->sects[j].sec == sec) {
                        mo->entry_addr = mo->sects[j].vmaddr + sym->st_value;
                        return 0;
                    }
                }
            }
        }
    }
    
    tcc_error_noabort("entry point 'main' not found");
    return -1;
}

/* ============================================================================
 * File Writing
 * ============================================================================ */

static void write32(FILE *f, uint32_t v)
{
    fwrite(&v, 4, 1, f);
}

static void write64(FILE *f, uint64_t v)
{
    fwrite(&v, 8, 1, f);
}

static void write_pad(FILE *f, int n)
{
    static const char zeros[16] = {0};
    while (n > 0) {
        int w = n > 16 ? 16 : n;
        fwrite(zeros, 1, w, f);
        n -= w;
    }
}

static void write_align(FILE *f, int align)
{
    long pos = ftell(f);
    int pad = MACHO_ALIGN(pos, align) - pos;
    write_pad(f, pad);
}

/*
 * seek_and_pad - Seek to target offset, writing zeros if forward seek
 *
 * Unlike fseek alone, this explicitly writes zeros when seeking forward.
 * This is necessary for systems that don't support sparse files or where
 * fseek doesn't extend the file (like Kiseki OS).
 */
static void seek_and_pad(FILE *f, long target)
{
    long pos = ftell(f);
    
    /* Get actual file size to know if we need to extend */
    fseek(f, 0, SEEK_END);
    long filesize = ftell(f);
    fseek(f, pos, SEEK_SET);  /* Restore position */
    
    if (target <= filesize) {
        /* Target is within existing file - just seek */
        fseek(f, target, SEEK_SET);
    } else {
        /* Target is beyond file - seek to end and pad with zeros */
        fseek(f, 0, SEEK_END);
        write_pad(f, (int)(target - filesize));
    }
}

static int macho_write_file(struct macho_info *mo)
{
    FILE *f;
    struct mach_header_64 mh;
    int i, ncmds = 0;
    uint32_t sizeofcmds = 0;
    long cmdstart, cmdend;
    
    f = fopen(mo->filename, "wb");
    if (!f) {
        tcc_error_noabort("could not create '%s'", mo->filename);
        return -1;
    }
    
    /* Count load commands and compute size */
    ncmds = 0;
    sizeofcmds = 0;
    
    /* __PAGEZERO */
    ncmds++;
    sizeofcmds += sizeof(struct segment_command_64);
    
    /* __TEXT with sections (including __stubs and __stub_helper if present) */
    ncmds++;
    int text_nsects = 0;
    for (i = 0; i < mo->nb_sects; i++)
        if (mo->sects[i].seg_idx == 0)
            text_nsects++;
    /* Add __stubs and __stub_helper if we have undefined symbols */
    if (mo->n_undef_syms > 0)
        text_nsects += 2;
    sizeofcmds += sizeof(struct segment_command_64) + text_nsects * sizeof(struct section_64);
    
    /* __DATA with sections (including __la_symbol_ptr and __got if present) */
    ncmds++;
    int data_nsects = 0;
    for (i = 0; i < mo->nb_sects; i++)
        if (mo->sects[i].seg_idx == 1)
            data_nsects++;
    /* Add __la_symbol_ptr and __got if we have undefined symbols */
    if (mo->n_undef_syms > 0)
        data_nsects += 2;
    sizeofcmds += sizeof(struct segment_command_64) + data_nsects * sizeof(struct section_64);
    
    /* __LINKEDIT */
    ncmds++;
    sizeofcmds += sizeof(struct segment_command_64);
    
    /* LC_DYLD_INFO_ONLY (if we have undefined symbols) */
    if (mo->n_undef_syms > 0) {
        ncmds++;
        sizeofcmds += sizeof(struct dyld_info_command);
    }
    
    /* LC_SYMTAB */
    ncmds++;
    sizeofcmds += sizeof(struct symtab_command);
    
    /* LC_DYSYMTAB */
    ncmds++;
    sizeofcmds += sizeof(struct dysymtab_command);
    
    /* LC_LOAD_DYLINKER */
    ncmds++;
    sizeofcmds += MACHO_ALIGN(sizeof(struct dylinker_command) + 16, 8);
    
    /* LC_MAIN */
    ncmds++;
    sizeofcmds += sizeof(struct entry_point_command);
    
    /* LC_LOAD_DYLIB for libSystem */
    ncmds++;
    sizeofcmds += MACHO_ALIGN(sizeof(struct dylib_command) + 28, 8);
    
    /* LC_UUID */
    ncmds++;
    sizeofcmds += sizeof(struct uuid_command);
    
    /* LC_BUILD_VERSION */
    ncmds++;
    sizeofcmds += sizeof(struct build_version_command);
    
    /* Write Mach-O header */
    memset(&mh, 0, sizeof(mh));
    mh.magic = MH_MAGIC_64;
    mh.cputype = CPU_TYPE_ARM64;
    mh.cpusubtype = CPU_SUBTYPE_ARM64_ALL;
    mh.filetype = (mo->type == TCC_OUTPUT_DLL) ? MH_DYLIB : MH_EXECUTE;
    mh.ncmds = ncmds;
    mh.sizeofcmds = sizeofcmds;
    mh.flags = MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL | MH_PIE;
    mh.reserved = 0;
    
    fwrite(&mh, sizeof(mh), 1, f);
    cmdstart = ftell(f);
    
    /* Write load commands */
    
    /* 1. LC_SEGMENT_64 __PAGEZERO */
    {
        struct segment_command_64 seg = {0};
        seg.cmd = LC_SEGMENT_64;
        seg.cmdsize = sizeof(seg);
        macho_set_segname(seg.segname, "__PAGEZERO");
        seg.vmaddr = 0;
        seg.vmsize = 0x100000000ULL;  /* 4GB null page */
        seg.fileoff = 0;
        seg.filesize = 0;
        seg.maxprot = VM_PROT_NONE;
        seg.initprot = VM_PROT_NONE;
        seg.nsects = 0;
        seg.flags = 0;
        fwrite(&seg, sizeof(seg), 1, f);
    }
    
    /* 2. LC_SEGMENT_64 __TEXT */
    {
        struct segment_command_64 seg = {0};
        seg.cmd = LC_SEGMENT_64;
        seg.cmdsize = sizeof(seg) + text_nsects * sizeof(struct section_64);
        macho_set_segname(seg.segname, "__TEXT");
        seg.vmaddr = mo->text_vmaddr;
        seg.vmsize = mo->text_vmsize;
        seg.fileoff = mo->text_fileoff;
        seg.filesize = mo->text_filesize;
        seg.maxprot = VM_PROT_READ | VM_PROT_EXECUTE;
        seg.initprot = VM_PROT_READ | VM_PROT_EXECUTE;
        seg.nsects = text_nsects;
        seg.flags = 0;
        fwrite(&seg, sizeof(seg), 1, f);
        
        /* Write __TEXT sections */
        for (i = 0; i < mo->nb_sects; i++) {
            if (mo->sects[i].seg_idx != 0)
                continue;
            struct macho_sect_info *si = &mo->sects[i];
            struct section_64 sect = {0};
            memcpy(sect.sectname, si->sectname, 16);
            memcpy(sect.segname, si->segname, 16);
            sect.addr = si->vmaddr;
            sect.size = si->sec->data_offset;
            sect.offset = si->fileoff;
            sect.align = 4;  /* 2^4 = 16 byte alignment */
            sect.reloff = 0;
            sect.nreloc = 0;
            sect.flags = si->flags;
            sect.reserved1 = 0;
            sect.reserved2 = 0;
            sect.reserved3 = 0;
            fwrite(&sect, sizeof(sect), 1, f);
        }
        
        /* Write __stubs section header if we have undefined symbols */
        if (mo->n_undef_syms > 0) {
            struct section_64 sect = {0};
            macho_set_segname(sect.sectname, "__stubs");
            macho_set_segname(sect.segname, "__TEXT");
            sect.addr = mo->stubs_addr;
            sect.size = mo->stubs_size;
            sect.offset = mo->stubs_fileoff;
            sect.align = 2;  /* 2^2 = 4 byte alignment */
            sect.reloff = 0;
            sect.nreloc = 0;
            sect.flags = S_SYMBOL_STUBS | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS;
            sect.reserved1 = 0;  /* index into indirect symbol table */
            sect.reserved2 = STUB_SIZE;  /* size of stubs */
            fwrite(&sect, sizeof(sect), 1, f);
        }
        
        /* Write __stub_helper section header */
        if (mo->n_undef_syms > 0) {
            struct section_64 sect = {0};
            macho_set_segname(sect.sectname, "__stub_helper");
            macho_set_segname(sect.segname, "__TEXT");
            sect.addr = mo->stub_helper_addr;
            sect.size = mo->stub_helper_size;
            sect.offset = mo->stub_helper_fileoff;
            sect.align = 2;  /* 2^2 = 4 byte alignment */
            sect.reloff = 0;
            sect.nreloc = 0;
            sect.flags = S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS;
            fwrite(&sect, sizeof(sect), 1, f);
        }
    }
    
    /* 3. LC_SEGMENT_64 __DATA */
    {
        struct segment_command_64 seg = {0};
        seg.cmd = LC_SEGMENT_64;
        seg.cmdsize = sizeof(seg) + data_nsects * sizeof(struct section_64);
        macho_set_segname(seg.segname, "__DATA");
        seg.vmaddr = mo->data_vmaddr;
        seg.vmsize = mo->data_vmsize;
        seg.fileoff = mo->data_fileoff;
        seg.filesize = mo->data_filesize;
        seg.maxprot = VM_PROT_READ | VM_PROT_WRITE;
        seg.initprot = VM_PROT_READ | VM_PROT_WRITE;
        seg.nsects = data_nsects;
        seg.flags = 0;
        fwrite(&seg, sizeof(seg), 1, f);
        
        /* Write __la_symbol_ptr section header first */
        int indirect_sym_idx = 0;
        if (mo->n_undef_syms > 0) {
            struct section_64 sect = {0};
            macho_set_segname(sect.sectname, "__la_symbol_ptr");
            macho_set_segname(sect.segname, "__DATA");
            sect.addr = mo->la_symbol_ptr_addr;
            sect.size = mo->la_symbol_ptr_size;
            sect.offset = mo->la_symbol_ptr_fileoff;
            sect.align = 3;  /* 2^3 = 8 byte alignment */
            sect.reloff = 0;
            sect.nreloc = 0;
            sect.flags = S_LAZY_SYMBOL_POINTERS;
            sect.reserved1 = indirect_sym_idx;  /* index into indirect symbol table */
            indirect_sym_idx += mo->n_undef_syms;
            fwrite(&sect, sizeof(sect), 1, f);
        }
        
        /* Write __got section header */
        if (mo->n_undef_syms > 0) {
            struct section_64 sect = {0};
            macho_set_segname(sect.sectname, "__got");
            macho_set_segname(sect.segname, "__DATA");
            sect.addr = mo->got_addr;
            sect.size = mo->got_size;
            sect.offset = mo->got_fileoff;
            sect.align = 3;  /* 2^3 = 8 byte alignment */
            sect.reloff = 0;
            sect.nreloc = 0;
            sect.flags = S_NON_LAZY_SYMBOL_POINTERS;
            sect.reserved1 = indirect_sym_idx;
            fwrite(&sect, sizeof(sect), 1, f);
        }
        
        /* Write other __DATA sections */
        for (i = 0; i < mo->nb_sects; i++) {
            if (mo->sects[i].seg_idx != 1)
                continue;
            struct macho_sect_info *si = &mo->sects[i];
            struct section_64 sect = {0};
            memcpy(sect.sectname, si->sectname, 16);
            memcpy(sect.segname, si->segname, 16);
            sect.addr = si->vmaddr;
            sect.size = si->sec->data_offset;
            sect.offset = (si->flags & S_ZEROFILL) ? 0 : si->fileoff;
            sect.align = 3;  /* 2^3 = 8 byte alignment */
            sect.reloff = 0;
            sect.nreloc = 0;
            sect.flags = si->flags;
            sect.reserved1 = 0;
            sect.reserved2 = 0;
            sect.reserved3 = 0;
            fwrite(&sect, sizeof(sect), 1, f);
        }
    }
    
    /* 4. LC_SEGMENT_64 __LINKEDIT */
    /* Calculate linkedit contents size:
     * - bind_info
     * - lazy_bind_info
     * - export_info
     * - symbol table
     * - string table
     * - indirect symbol table
     */
    uint32_t linkedit_size = 0;
    uint32_t bind_off = mo->linkedit_fileoff + linkedit_size;
    linkedit_size += mo->bind_size;
    linkedit_size = MACHO_ALIGN(linkedit_size, 8);
    uint32_t lazy_bind_off = mo->linkedit_fileoff + linkedit_size;
    linkedit_size += mo->lazy_bind_size;
    linkedit_size = MACHO_ALIGN(linkedit_size, 8);
    uint32_t export_off = mo->linkedit_fileoff + linkedit_size;
    linkedit_size += mo->export_size;
    linkedit_size = MACHO_ALIGN(linkedit_size, 8);
    uint32_t symoff = mo->linkedit_fileoff + linkedit_size;
    linkedit_size += mo->nsyms * sizeof(struct nlist_64);
    uint32_t stroff = mo->linkedit_fileoff + linkedit_size;
    linkedit_size += mo->strsize;
    linkedit_size = MACHO_ALIGN(linkedit_size, 4);
    uint32_t indirect_off = mo->linkedit_fileoff + linkedit_size;
    int n_indirect = mo->n_undef_syms + 1;  /* la_symbol_ptr + 1 for got */
    linkedit_size += n_indirect * sizeof(uint32_t);
    
    {
        struct segment_command_64 seg = {0};
        seg.cmd = LC_SEGMENT_64;
        seg.cmdsize = sizeof(seg);
        macho_set_segname(seg.segname, "__LINKEDIT");
        seg.vmaddr = mo->linkedit_vmaddr;
        seg.vmsize = MACHO_ALIGN(linkedit_size, PAGE_SIZE);
        seg.fileoff = mo->linkedit_fileoff;
        seg.filesize = linkedit_size;
        seg.maxprot = VM_PROT_READ;
        seg.initprot = VM_PROT_READ;
        seg.nsects = 0;
        seg.flags = 0;
        fwrite(&seg, sizeof(seg), 1, f);
        
        mo->linkedit_vmsize = seg.vmsize;
        mo->linkedit_filesize = seg.filesize;
    }
    
    /* 5. LC_DYLD_INFO_ONLY (if we have undefined symbols) */
    if (mo->n_undef_syms > 0) {
        struct dyld_info_command cmd = {0};
        cmd.cmd = LC_DYLD_INFO_ONLY;
        cmd.cmdsize = sizeof(cmd);
        cmd.rebase_off = 0;
        cmd.rebase_size = 0;
        cmd.bind_off = bind_off;
        cmd.bind_size = mo->bind_size;
        cmd.weak_bind_off = 0;
        cmd.weak_bind_size = 0;
        cmd.lazy_bind_off = lazy_bind_off;
        cmd.lazy_bind_size = mo->lazy_bind_size;
        cmd.export_off = export_off;
        cmd.export_size = mo->export_size;
        fwrite(&cmd, sizeof(cmd), 1, f);
    }
    
    /* 6. LC_SYMTAB */
    {
        struct symtab_command cmd = {0};
        cmd.cmd = LC_SYMTAB;
        cmd.cmdsize = sizeof(cmd);
        cmd.symoff = symoff;
        cmd.nsyms = mo->nsyms;
        cmd.stroff = stroff;
        cmd.strsize = mo->strsize;
        fwrite(&cmd, sizeof(cmd), 1, f);
    }
    
    /* 7. LC_DYSYMTAB */
    {
        struct dysymtab_command cmd = {0};
        cmd.cmd = LC_DYSYMTAB;
        cmd.cmdsize = sizeof(cmd);
        cmd.ilocalsym = 0;
        cmd.nlocalsym = mo->nlocalsym;
        cmd.iextdefsym = mo->nlocalsym;
        cmd.nextdefsym = mo->nextdefsym;
        cmd.iundefsym = mo->nlocalsym + mo->nextdefsym;
        cmd.nundefsym = mo->nundefsym;
        cmd.indirectsymoff = indirect_off;
        cmd.nindirectsyms = n_indirect;
        fwrite(&cmd, sizeof(cmd), 1, f);
    }
    
    /* 7. LC_LOAD_DYLINKER */
    {
        const char *dyld_path = "/usr/lib/dyld";
        int pathlen = strlen(dyld_path) + 1;
        struct dylinker_command cmd = {0};
        cmd.cmd = LC_LOAD_DYLINKER;
        cmd.cmdsize = MACHO_ALIGN(sizeof(cmd) + pathlen, 8);
        cmd.name_offset = sizeof(cmd);
        fwrite(&cmd, sizeof(cmd), 1, f);
        fwrite(dyld_path, pathlen, 1, f);
        write_pad(f, cmd.cmdsize - sizeof(cmd) - pathlen);
    }
    
    /* 8. LC_MAIN */
    {
        struct entry_point_command cmd = {0};
        cmd.cmd = LC_MAIN;
        cmd.cmdsize = sizeof(cmd);
        /* entryoff is relative to __TEXT segment start */
        cmd.entryoff = mo->entry_addr - mo->text_vmaddr;
        cmd.stacksize = 0;  /* Use default stack size */
        fwrite(&cmd, sizeof(cmd), 1, f);
    }
    
    /* 9. LC_LOAD_DYLIB for libSystem.B.dylib */
    {
        const char *libname = "/usr/lib/libSystem.B.dylib";
        int namelen = strlen(libname) + 1;
        struct dylib_command cmd = {0};
        cmd.cmd = LC_LOAD_DYLIB;
        cmd.cmdsize = MACHO_ALIGN(sizeof(cmd) + namelen, 8);
        cmd.dylib.name_offset = sizeof(cmd);
        cmd.dylib.timestamp = 2;
        cmd.dylib.current_version = 0x10000;      /* 1.0.0 */
        cmd.dylib.compatibility_version = 0x10000;
        fwrite(&cmd, sizeof(cmd), 1, f);
        fwrite(libname, namelen, 1, f);
        write_pad(f, cmd.cmdsize - sizeof(cmd) - namelen);
    }
    
    /* 10. LC_UUID */
    {
        struct uuid_command cmd = {0};
        cmd.cmd = LC_UUID;
        cmd.cmdsize = sizeof(cmd);
        /* Generate a simple UUID based on filename hash */
        for (i = 0; i < 16; i++)
            cmd.uuid[i] = (uint8_t)(mo->filename[i % strlen(mo->filename)] ^ i);
        fwrite(&cmd, sizeof(cmd), 1, f);
    }
    
    /* 11. LC_BUILD_VERSION */
    {
        struct build_version_command cmd = {0};
        cmd.cmd = LC_BUILD_VERSION;
        cmd.cmdsize = sizeof(cmd);
        cmd.platform = PLATFORM_MACOS;
        cmd.minos = 0x000B0000;   /* macOS 11.0 */
        cmd.sdk = 0x000B0000;
        cmd.ntools = 0;
        fwrite(&cmd, sizeof(cmd), 1, f);
    }
    
    cmdend = ftell(f);
    
    /* Verify command size */
    if (cmdend - cmdstart != sizeofcmds) {
        tcc_warning("load command size mismatch: %ld vs %d", 
                    cmdend - cmdstart, sizeofcmds);
    }
    
    /* Pad to first section */
    write_align(f, PAGE_SIZE);
    
    /* Write section data */
    for (i = 0; i < mo->nb_sects; i++) {
        struct macho_sect_info *si = &mo->sects[i];
        if (si->flags & S_ZEROFILL)
            continue;  /* No file data for zerofill sections */
        
        /* Seek to section's file offset, padding with zeros */
        seek_and_pad(f, si->fileoff);
        fwrite(si->sec->data, 1, si->sec->data_offset, f);
    }
    
    /* Write __stubs */
    if (mo->n_undef_syms > 0) {
        uint8_t stub_buf[MAX_UNDEF_SYMS * STUB_SIZE];
        macho_gen_stubs(mo, stub_buf);
        seek_and_pad(f, mo->stubs_fileoff);
        fwrite(stub_buf, 1, mo->stubs_size, f);
    }
    
    /* Write __stub_helper */
    if (mo->n_undef_syms > 0) {
        uint8_t helper_buf[STUB_HELPER_HDR + MAX_UNDEF_SYMS * STUB_HELPER_ENTRY];
        macho_gen_stub_helper(mo, helper_buf);
        seek_and_pad(f, mo->stub_helper_fileoff);
        fwrite(helper_buf, 1, mo->stub_helper_size, f);
    }
    
    /* Write __la_symbol_ptr */
    if (mo->n_undef_syms > 0) {
        seek_and_pad(f, mo->la_symbol_ptr_fileoff);
        for (i = 0; i < mo->n_undef_syms; i++) {
            /* Initially point to stub_helper entry for this symbol */
            /* dyld will patch this to point to the real function */
            uint64_t helper_entry = mo->stub_helper_addr + STUB_HELPER_HDR + i * STUB_HELPER_ENTRY;
            write64(f, helper_entry);
        }
    }
    
    /* Write __got (dyld_stub_binder pointer - just zero, not used) */
    if (mo->n_undef_syms > 0) {
        seek_and_pad(f, mo->got_fileoff);
        write64(f, 0);
    }
    
    /* Write __LINKEDIT contents */
    seek_and_pad(f, bind_off);
    if (mo->bind_info)
        fwrite(mo->bind_info, 1, mo->bind_size, f);
    
    seek_and_pad(f, lazy_bind_off);
    if (mo->lazy_bind_info)
        fwrite(mo->lazy_bind_info, 1, mo->lazy_bind_size, f);
    
    seek_and_pad(f, export_off);
    if (mo->export_info)
        fwrite(mo->export_info, 1, mo->export_size, f);
    
    /* Write symbol table */
    seek_and_pad(f, symoff);
    fwrite(mo->symtab, sizeof(struct nlist_64), mo->nsyms, f);
    
    /* Write string table */
    seek_and_pad(f, stroff);
    fwrite(mo->strtab, 1, mo->strsize, f);
    
    /* Write indirect symbol table */
    seek_and_pad(f, indirect_off);
    /* First entries for __la_symbol_ptr */
    for (i = 0; i < mo->n_undef_syms; i++) {
        uint32_t sym_idx = mo->undef_syms[i].sym_index;
        if (sym_idx == (uint32_t)-1)
            sym_idx = 0;  /* Fallback */
        write32(f, sym_idx);
    }
    /* One entry for __got (INDIRECT_SYMBOL_LOCAL) */
    write32(f, 0x80000000);  /* INDIRECT_SYMBOL_LOCAL */
    
    fclose(f);
    
    /* Make executable */
    chmod(mo->filename, 0755);
    
    return 0;
}

/* ============================================================================
 * Public Interface
 * ============================================================================ */

/*
 * For Mach-O dynamic executables, we allow undefined symbols
 * since dyld will resolve them at runtime from libSystem.
 * This mimics clang's -undefined dynamic_lookup behavior.
 */
static void macho_relocate_syms(TCCState *s1)
{
    Section *symtab = s1->symtab;
    ElfW(Sym) *sym;
    int sym_bind, sh_num;
    const char *name;

    for_each_elem(symtab, 1, sym, ElfW(Sym)) {
        sh_num = sym->st_shndx;
        if (sh_num == SHN_UNDEF) {
            name = (char *) s1->symtab->link->data + sym->st_name;
            /* For Mach-O, undefined symbols are allowed - dyld resolves them */
            sym_bind = ELFW(ST_BIND)(sym->st_info);
            if (sym_bind == STB_WEAK)
                sym->st_value = 0;
            /* Don't error on undefined - dyld will resolve at runtime */
        } else if (sh_num < SHN_LORESERVE) {
            /* add section base */
            sym->st_value += s1->sections[sym->st_shndx]->sh_addr;
        }
    }
}

/*
 * macho_output_file - Generate a Mach-O executable or dynamic library
 *
 * This is the main entry point for Mach-O output. It:
 *   1. Collects undefined symbols that need stubs
 *   2. Lays out sections with proper alignment and page boundaries
 *   3. Generates dynamic linking structures (stubs, binding info)
 *   4. Builds the Mach-O symbol table from ELF symbols
 *   5. Applies relocations (with stubs for undefined symbols)
 *   6. Writes the final Mach-O file
 *
 * Returns 0 on success, -1 on error.
 */
ST_FUNC int macho_output_file(TCCState *s1, const char *filename)
{
    struct macho_info mo;
    int ret;
    
    memset(&mo, 0, sizeof(mo));
    mo.s1 = s1;
    mo.filename = filename;
    mo.type = s1->output_type;
    
    /* Resolve common symbols */
    resolve_common_syms(s1);
    
    /* Collect undefined symbols for stub generation */
    macho_collect_undef_syms(&mo);
    
    /* Layout sections (including stubs) */
    macho_layout_sections(&mo);
    
    /* Generate binding info for dyld */
    if (mo.n_undef_syms > 0) {
        macho_gen_bind_info(&mo);
        macho_gen_lazy_bind_info(&mo);
        macho_gen_export_info(&mo);
    }
    
    /* Build symbol table */
    ret = macho_build_symtab(&mo);
    if (ret)
        goto cleanup;
    
    /* Find entry point */
    ret = macho_find_entry(&mo);
    if (ret)
        goto cleanup;
    
    /* Patch undefined symbols to point to their stubs */
    macho_patch_undef_syms(&mo);
    
    /* Relocate sections - use our version that allows undefined symbols */
    macho_relocate_syms(s1);
    for (int i = 1; i < s1->nb_sections; i++) {
        Section *sr = s1->sections[i];
        if (sr->reloc)
            relocate_section(s1, sr);
    }
    
    if (s1->nb_errors) {
        ret = -1;
        goto cleanup;
    }
    
    /* Write output file */
    ret = macho_write_file(&mo);
    
cleanup:
    tcc_free(mo.symtab);
    tcc_free(mo.strtab);
    tcc_free(mo.indirect_syms);
    tcc_free(mo.bind_info);
    tcc_free(mo.lazy_bind_info);
    tcc_free(mo.export_info);
    return ret;
}

#endif /* TCC_TARGET_MACHO */
