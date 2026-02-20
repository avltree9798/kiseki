/*
 * Kiseki OS - Dynamic Linker (dyld)
 *
 * A real Mach-O dynamic linker that:
 *   1. Parses the main binary's load commands (already mapped by the kernel)
 *   2. Loads required dylibs from disk (libSystem.B.dylib etc.)
 *   3. Processes rebase opcodes (DYLD_INFO_ONLY or chained fixups)
 *   4. Resolves and applies bind opcodes (symbol binding)
 *   5. Eagerly resolves lazy bindings (avoids needing dyld_stub_binder)
 *   6. Finds LC_MAIN and jumps to the program's entry point
 *
 * This is a freestanding binary (MH_DYLINKER). It uses raw syscalls
 * for all I/O and has no dependencies on any library.
 *
 * Syscall convention (Kiseki/XNU ARM64):
 *   x16 = syscall number, x0-x5 = args
 *   svc #0x80
 *   On error: carry flag set in PSTATE, x0 = positive errno
 *   On success: carry clear, x0 = return value
 */

/* ============================================================================
 * Primitive Types (freestanding — no system headers)
 * ============================================================================ */

typedef signed char         int8_t;
typedef unsigned char       uint8_t;
typedef signed short        int16_t;
typedef unsigned short      uint16_t;
typedef signed int          int32_t;
typedef unsigned int        uint32_t;
typedef signed long long    int64_t;
typedef unsigned long long  uint64_t;
typedef signed long         ssize_t;
typedef unsigned long       size_t;
typedef _Bool               bool;

#define true  1
#define false 0
#define NULL  ((void *)0)

/* ============================================================================
 * Syscall Numbers (must match kernel)
 * ============================================================================ */

#define SYS_exit    1
#define SYS_read    3
#define SYS_write   4
#define SYS_open    5
#define SYS_close   6
#define SYS_lseek   199
#define SYS_mmap    197
#define SYS_munmap  73

/* mmap constants */
#define PROT_NONE   0x00
#define PROT_READ   0x01
#define PROT_WRITE  0x02
#define PROT_EXEC   0x04

#define MAP_PRIVATE 0x0002
#define MAP_FIXED   0x0010
#define MAP_ANON    0x1000

#define MAP_FAILED  ((void *)(long)-1)

/* open flags */
#define O_RDONLY    0x0000

/* lseek whence */
#define SEEK_SET    0
#define SEEK_CUR    1
#define SEEK_END    2

/* ============================================================================
 * Raw Syscall Interface
 *
 * Uses inline asm with the Kiseki/XNU ARM64 ABI:
 *   x16 = syscall number, x0-x5 = arguments
 *   svc #0x80
 *   Carry flag set on error (x0 = positive errno)
 * ============================================================================ */

static long __syscall(long number, long a0, long a1, long a2,
                      long a3, long a4, long a5)
{
    register long x16 __asm__("x16") = number;
    register long x0  __asm__("x0")  = a0;
    register long x1  __asm__("x1")  = a1;
    register long x2  __asm__("x2")  = a2;
    register long x3  __asm__("x3")  = a3;
    register long x4  __asm__("x4")  = a4;
    register long x5  __asm__("x5")  = a5;
    register long nzcv;

    __asm__ volatile(
        "svc    #0x80\n\t"
        "mrs    %[nzcv], nzcv"
        : [nzcv] "=r" (nzcv),
          "+r" (x0)
        : "r" (x16), "r" (x1), "r" (x2), "r" (x3), "r" (x4), "r" (x5)
        : "memory", "cc"
    );

    if (nzcv & (1L << 29))
        return -x0;    /* Error: return -errno */
    return x0;
}

__attribute__((noreturn))
static void sys_exit(int status)
{
    __syscall(SYS_exit, status, 0, 0, 0, 0, 0);
    for (;;) __builtin_unreachable();
}

static ssize_t sys_write(int fd, const void *buf, size_t count)
{
    return (ssize_t)__syscall(SYS_write, fd, (long)buf, (long)count, 0, 0, 0);
}

static ssize_t sys_read(int fd, void *buf, size_t count)
{
    return (ssize_t)__syscall(SYS_read, fd, (long)buf, (long)count, 0, 0, 0);
}

static int sys_open(const char *path, int flags, int mode)
{
    return (int)__syscall(SYS_open, (long)path, flags, mode, 0, 0, 0);
}

static int sys_close(int fd)
{
    return (int)__syscall(SYS_close, fd, 0, 0, 0, 0, 0);
}

static long sys_lseek(int fd, long offset, int whence)
{
    return __syscall(SYS_lseek, fd, offset, whence, 0, 0, 0);
}

static void *sys_mmap(void *addr, size_t len, int prot, int flags,
                      int fd, long offset)
{
    long r = __syscall(SYS_mmap, (long)addr, (long)len, prot, flags, fd, offset);
    if (r < 0)
        return MAP_FAILED;
    return (void *)r;
}

/* ============================================================================
 * String / Memory Utilities (freestanding)
 * ============================================================================ */

static size_t dyld_strlen(const char *s)
{
    size_t n = 0;
    while (*s++) n++;
    return n;
}

static int dyld_strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return (uint8_t)*a - (uint8_t)*b;
}

static int dyld_strncmp(const char *a, const char *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i])
            return (uint8_t)a[i] - (uint8_t)b[i];
        if (a[i] == '\0')
            return 0;
    }
    return 0;
}

static void dyld_memcpy(void *dst, const void *src, size_t n)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    while (n--) *d++ = *s++;
}

static void dyld_memset(void *dst, int val, size_t n)
{
    uint8_t *d = (uint8_t *)dst;
    while (n--) *d++ = (uint8_t)val;
}

/* ============================================================================
 * Console Output (for diagnostics)
 * ============================================================================ */

static void dyld_puts(const char *s)
{
    sys_write(2, s, dyld_strlen(s));
}

__attribute__((unused))
static void dyld_put_hex(uint64_t val)
{
    char buf[19]; /* "0x" + 16 hex digits + NUL */
    buf[0] = '0';
    buf[1] = 'x';
    for (int i = 15; i >= 0; i--) {
        int nib = (val >> (i * 4)) & 0xF;
        buf[17 - i] = (nib < 10) ? ('0' + nib) : ('a' + nib - 10);
    }
    buf[18] = '\0';
    dyld_puts(buf);
}

static void dyld_put_dec(uint64_t val)
{
    char buf[21];
    int pos = 20;
    buf[pos] = '\0';
    if (val == 0) {
        buf[--pos] = '0';
    } else {
        while (val > 0) {
            buf[--pos] = '0' + (val % 10);
            val /= 10;
        }
    }
    dyld_puts(&buf[pos]);
}

__attribute__((noreturn))
static void dyld_fatal(const char *msg)
{
    dyld_puts("dyld: fatal: ");
    dyld_puts(msg);
    dyld_puts("\n");
    sys_exit(127);
}

/* ============================================================================
 * Mach-O Structure Definitions
 *
 * These must match the kernel's definitions exactly. We define them here
 * because dyld is freestanding and cannot include kernel headers.
 * ============================================================================ */

#define MH_MAGIC_64     0xFEEDFACF

/* CPU types */
#define CPU_ARCH_ABI64          0x01000000
#define CPU_TYPE_ARM            12
#define CPU_TYPE_ARM64          (CPU_TYPE_ARM | CPU_ARCH_ABI64)

/* File types */
#define MH_EXECUTE      0x2
#define MH_DYLIB        0x6
#define MH_DYLINKER     0x7

/* Mach-O flags */
#define MH_PIE          0x00200000

struct mach_header_64 {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
};

struct load_command {
    uint32_t cmd;
    uint32_t cmdsize;
};

/* Load command types */
#define LC_REQ_DYLD             0x80000000
#define LC_SEGMENT_64           0x19
#define LC_SYMTAB               0x02
#define LC_DYSYMTAB             0x0B
#define LC_LOAD_DYLIB           0x0C
#define LC_ID_DYLIB             0x0D
#define LC_LOAD_DYLINKER        0x0E
#define LC_ID_DYLINKER          0x0F
#define LC_UUID                 0x1B
#define LC_UNIXTHREAD           0x05
#define LC_DYLD_INFO            0x22
#define LC_DYLD_INFO_ONLY       (0x22 | LC_REQ_DYLD)
#define LC_MAIN                 (0x28 | LC_REQ_DYLD)
#define LC_REEXPORT_DYLIB       (0x1F | LC_REQ_DYLD)
#define LC_DYLD_EXPORTS_TRIE    (0x33 | LC_REQ_DYLD)
#define LC_DYLD_CHAINED_FIXUPS  (0x34 | LC_REQ_DYLD)

struct segment_command_64 {
    uint32_t cmd;
    uint32_t cmdsize;
    char     segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
};

struct section_64 {
    char     sectname[16];
    char     segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
};

struct entry_point_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint64_t entryoff;
    uint64_t stacksize;
};

struct dylib {
    uint32_t name_offset;
    uint32_t timestamp;
    uint32_t current_version;
    uint32_t compatibility_version;
};

struct dylib_command {
    uint32_t     cmd;
    uint32_t     cmdsize;
    struct dylib dylib;
};

struct symtab_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t symoff;
    uint32_t nsyms;
    uint32_t stroff;
    uint32_t strsize;
};

struct dysymtab_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t ilocalsym;
    uint32_t nlocalsym;
    uint32_t iextdefsym;
    uint32_t nextdefsym;
    uint32_t iundefsym;
    uint32_t nundefsym;
    uint32_t tocoff;
    uint32_t ntoc;
    uint32_t modtaboff;
    uint32_t nmodtab;
    uint32_t extrefsymoff;
    uint32_t nextrefsyms;
    uint32_t indirectsymoff;
    uint32_t nindirectsyms;
    uint32_t extreloff;
    uint32_t nextrel;
    uint32_t locreloff;
    uint32_t nlocrel;
};

struct dyld_info_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t rebase_off;
    uint32_t rebase_size;
    uint32_t bind_off;
    uint32_t bind_size;
    uint32_t weak_bind_off;
    uint32_t weak_bind_size;
    uint32_t lazy_bind_off;
    uint32_t lazy_bind_size;
    uint32_t export_off;
    uint32_t export_size;
};

struct linkedit_data_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t dataoff;
    uint32_t datasize;
};

struct nlist_64 {
    uint32_t n_strx;
    uint8_t  n_type;
    uint8_t  n_sect;
    uint16_t n_desc;
    uint64_t n_value;
};

/* nlist n_type masks */
#define N_STAB  0xE0
#define N_PEXT  0x10
#define N_TYPE  0x0E
#define N_EXT   0x01
#define N_UNDF  0x00
#define N_ABS   0x02
#define N_SECT  0x0E

/* ============================================================================
 * Rebase Opcodes (DYLD_INFO_ONLY)
 * ============================================================================ */

#define REBASE_OPCODE_MASK                              0xF0
#define REBASE_IMMEDIATE_MASK                           0x0F
#define REBASE_OPCODE_DONE                              0x00
#define REBASE_OPCODE_SET_TYPE_IMM                      0x10
#define REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB       0x20
#define REBASE_OPCODE_ADD_ADDR_ULEB                     0x30
#define REBASE_OPCODE_ADD_ADDR_IMM_SCALED               0x40
#define REBASE_OPCODE_DO_REBASE_IMM_TIMES               0x50
#define REBASE_OPCODE_DO_REBASE_ULEB_TIMES              0x60
#define REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB           0x70
#define REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB 0x80

#define REBASE_TYPE_POINTER     1

/* ============================================================================
 * Bind Opcodes (DYLD_INFO_ONLY)
 * ============================================================================ */

#define BIND_OPCODE_MASK                                0xF0
#define BIND_IMMEDIATE_MASK                             0x0F
#define BIND_OPCODE_DONE                                0x00
#define BIND_OPCODE_SET_DYLIB_ORDINAL_IMM               0x10
#define BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB              0x20
#define BIND_OPCODE_SET_DYLIB_SPECIAL_IMM               0x30
#define BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM       0x40
#define BIND_OPCODE_SET_TYPE_IMM                        0x50
#define BIND_OPCODE_SET_ADDEND_SLEB                     0x60
#define BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB         0x70
#define BIND_OPCODE_ADD_ADDR_ULEB                       0x80
#define BIND_OPCODE_DO_BIND                             0x90
#define BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB               0xA0
#define BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED         0xB0
#define BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB    0xC0
#define BIND_OPCODE_THREADED                            0xD0

#define BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB 0x00
#define BIND_SUBOPCODE_THREADED_APPLY                   0x01

#define BIND_TYPE_POINTER   1

/* ============================================================================
 * Chained Fixups Structures
 * ============================================================================ */

struct dyld_chained_fixups_header {
    uint32_t fixups_version;
    uint32_t starts_offset;
    uint32_t imports_offset;
    uint32_t symbols_offset;
    uint32_t imports_count;
    uint32_t imports_format;
    uint32_t symbols_format;
};

struct dyld_chained_starts_in_image {
    uint32_t seg_count;
    uint32_t seg_info_offset[]; /* flexible array */
};

struct dyld_chained_starts_in_segment {
    uint32_t size;
    uint16_t page_size;
    uint16_t pointer_format;
    uint64_t segment_offset;
    uint32_t max_valid_pointer;
    uint16_t page_count;
    uint16_t page_start[];      /* flexible array */
};

struct dyld_chained_import {
    uint32_t data; /* lib_ordinal:8, weak_import:1, name_offset:23 */
};

#define DYLD_CHAINED_IMPORT             1
#define DYLD_CHAINED_PTR_ARM64E         1
#define DYLD_CHAINED_PTR_64             2
#define DYLD_CHAINED_PTR_64_OFFSET      6
#define DYLD_CHAINED_PTR_START_NONE     0xFFFF

/* ============================================================================
 * ULEB128 / SLEB128 Decoding
 * ============================================================================ */

static uint64_t read_uleb128(const uint8_t **p, const uint8_t *end)
{
    uint64_t result = 0;
    unsigned shift = 0;
    uint8_t byte;

    do {
        if (*p >= end)
            return result;
        byte = **p;
        (*p)++;
        result |= ((uint64_t)(byte & 0x7F)) << shift;
        shift += 7;
    } while (byte & 0x80);

    return result;
}

static int64_t read_sleb128(const uint8_t **p, const uint8_t *end)
{
    int64_t result = 0;
    unsigned shift = 0;
    uint8_t byte;

    do {
        if (*p >= end)
            return result;
        byte = **p;
        (*p)++;
        result |= ((int64_t)(byte & 0x7F)) << shift;
        shift += 7;
    } while (byte & 0x80);

    /* Sign-extend if the high bit of the last byte was set */
    if ((shift < 64) && (byte & 0x40))
        result |= -(((int64_t)1) << shift);

    return result;
}

/* ============================================================================
 * File I/O Helpers
 *
 * Read an entire file into memory via mmap for simplicity.
 * ============================================================================ */

static uint8_t *read_file(const char *path, size_t *out_size)
{
    int fd = sys_open(path, O_RDONLY, 0);
    if (fd < 0) {
        dyld_puts("dyld: cannot open '");
        dyld_puts(path);
        dyld_puts("'\n");
        return NULL;
    }

    /* Get file size by seeking to end */
    long size = sys_lseek(fd, 0, SEEK_END);
    if (size <= 0) {
        sys_close(fd);
        return NULL;
    }
    sys_lseek(fd, 0, SEEK_SET);

    /* Allocate memory via anonymous mmap */
    uint8_t *buf = (uint8_t *)sys_mmap(NULL, (size_t)size,
                                        PROT_READ | PROT_WRITE,
                                        MAP_PRIVATE | MAP_ANON, -1, 0);
    if (buf == MAP_FAILED) {
        sys_close(fd);
        return NULL;
    }

    /* Read the entire file */
    size_t total = 0;
    while (total < (size_t)size) {
        ssize_t n = sys_read(fd, buf + total, (size_t)size - total);
        if (n <= 0)
            break;
        total += (size_t)n;
    }

    sys_close(fd);

    if (total == 0) {
        /* Free the mapping; we got nothing */
        return NULL;
    }

    *out_size = total;
    return buf;
}

/* ============================================================================
 * Loaded Image Tracking
 *
 * We track each loaded Mach-O image (main binary + dylibs) so we can
 * resolve symbols during binding.
 * ============================================================================ */

#define MAX_IMAGES      32
#define MAX_SEGMENTS    8

struct loaded_segment {
    char     segname[16];
    uint64_t vmaddr;    /* Virtual address (after slide) */
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
};

struct loaded_image {
    const char              *path;
    const struct mach_header_64 *mh;        /* Mach-O header in memory */
    uint64_t                slide;          /* ASLR slide applied */
    uint64_t                text_base;      /* __TEXT vmaddr + slide */
    uint64_t                text_size;

    /* Segment info */
    struct loaded_segment   segs[MAX_SEGMENTS];
    uint32_t                nsegs;

    /* __LINKEDIT info */
    uint64_t                linkedit_vmaddr;    /* VA of __LINKEDIT */
    uint64_t                linkedit_fileoff;   /* file offset of __LINKEDIT */

    /* Symbol table (from LC_SYMTAB, points into loaded file data) */
    const struct nlist_64   *symtab;
    uint32_t                nsyms;
    const char              *strtab;
    uint32_t                strsize;

    /* DYLD_INFO_ONLY */
    bool                    has_dyld_info;
    uint32_t                rebase_off;
    uint32_t                rebase_size;
    uint32_t                bind_off;
    uint32_t                bind_size;
    uint32_t                weak_bind_off;
    uint32_t                weak_bind_size;
    uint32_t                lazy_bind_off;
    uint32_t                lazy_bind_size;
    uint32_t                export_off;
    uint32_t                export_size;

    /* Chained fixups */
    bool                    has_chained_fixups;
    uint32_t                chained_fixups_off;
    uint32_t                chained_fixups_size;

    /* Export trie (LC_DYLD_EXPORTS_TRIE or from LC_DYLD_INFO_ONLY) */
    bool                    has_exports_trie;
    uint32_t                exports_trie_off;
    uint32_t                exports_trie_size;

    /* LC_MAIN */
    bool                    has_main;
    uint64_t                main_entryoff;

    /* Dylib dependencies */
    uint32_t                ndylibs;
    const char              *dylib_paths[32];

    /* Raw file data (for dylibs we loaded from disk) */
    uint8_t                 *file_data;
    size_t                  file_size;
};

static struct loaded_image images[MAX_IMAGES];
static uint32_t            num_images = 0;

/* Pointer to dyld's own image entry (set during initialization) */
static struct loaded_image *dyld_image = NULL;

/* ============================================================================
 * Parse Mach-O Load Commands
 *
 * Walks the load commands of a mach_header_64 and fills in a loaded_image.
 * The mach_header must already be in readable memory (mapped by kernel
 * for the main binary, or loaded by us for dylibs).
 * ============================================================================ */

static void parse_load_commands(struct loaded_image *img)
{
    const struct mach_header_64 *mh = img->mh;
    const uint8_t *cmd_ptr = (const uint8_t *)(mh + 1); /* after header */
    uint32_t ncmds = mh->ncmds;

    for (uint32_t i = 0; i < ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cmd_ptr;
        if (lc->cmdsize < sizeof(struct load_command))
            break;

        switch (lc->cmd) {

        case LC_SEGMENT_64: {
            const struct segment_command_64 *seg =
                (const struct segment_command_64 *)cmd_ptr;

            /* Track segments */
            if (img->nsegs < MAX_SEGMENTS) {
                struct loaded_segment *ls = &img->segs[img->nsegs];
                dyld_memcpy(ls->segname, seg->segname, 16);
                ls->vmaddr   = seg->vmaddr + img->slide;
                ls->vmsize   = seg->vmsize;
                ls->fileoff  = seg->fileoff;
                ls->filesize = seg->filesize;
                img->nsegs++;
            }

            if (dyld_strncmp(seg->segname, "__TEXT", 6) == 0) {
                img->text_base = seg->vmaddr + img->slide;
                img->text_size = seg->vmsize;
            }

            if (dyld_strncmp(seg->segname, "__LINKEDIT", 10) == 0) {
                img->linkedit_vmaddr  = seg->vmaddr + img->slide;
                img->linkedit_fileoff = seg->fileoff;
            }
            break;
        }

        case LC_SYMTAB: {
            const struct symtab_command *sym =
                (const struct symtab_command *)cmd_ptr;

            /*
             * The symbol table and string table live in __LINKEDIT.
             * Their file offsets need to be translated to virtual addresses.
             * VA = linkedit_vmaddr + (file_offset - linkedit_fileoff)
             */
            if (img->linkedit_vmaddr != 0 && img->linkedit_fileoff != 0) {
                img->symtab = (const struct nlist_64 *)(
                    img->linkedit_vmaddr +
                    (sym->symoff - img->linkedit_fileoff));
                img->nsyms   = sym->nsyms;
                img->strtab  = (const char *)(
                    img->linkedit_vmaddr +
                    (sym->stroff - img->linkedit_fileoff));
                img->strsize = sym->strsize;
            } else {
                /*
                 * __LINKEDIT not yet parsed. We do a two-pass approach:
                 * first find __LINKEDIT, then come back. For simplicity,
                 * we'll defer this to a second pass below.
                 */
            }
            break;
        }

        case LC_DYLD_INFO:
        case LC_DYLD_INFO_ONLY: {
            const struct dyld_info_command *di =
                (const struct dyld_info_command *)cmd_ptr;
            img->has_dyld_info    = true;
            img->rebase_off       = di->rebase_off;
            img->rebase_size      = di->rebase_size;
            img->bind_off         = di->bind_off;
            img->bind_size        = di->bind_size;
            img->weak_bind_off    = di->weak_bind_off;
            img->weak_bind_size   = di->weak_bind_size;
            img->lazy_bind_off    = di->lazy_bind_off;
            img->lazy_bind_size   = di->lazy_bind_size;
            img->export_off       = di->export_off;
            img->export_size      = di->export_size;

            /* Also treat export info from DYLD_INFO as an exports trie */
            if (di->export_off != 0 && di->export_size != 0) {
                img->has_exports_trie  = true;
                img->exports_trie_off  = di->export_off;
                img->exports_trie_size = di->export_size;
            }
            break;
        }

        case LC_DYLD_CHAINED_FIXUPS: {
            const struct linkedit_data_command *ldc =
                (const struct linkedit_data_command *)cmd_ptr;
            img->has_chained_fixups   = true;
            img->chained_fixups_off   = ldc->dataoff;
            img->chained_fixups_size  = ldc->datasize;
            break;
        }

        case LC_DYLD_EXPORTS_TRIE: {
            const struct linkedit_data_command *ldc =
                (const struct linkedit_data_command *)cmd_ptr;
            img->has_exports_trie   = true;
            img->exports_trie_off   = ldc->dataoff;
            img->exports_trie_size  = ldc->datasize;
            break;
        }

        case LC_MAIN: {
            const struct entry_point_command *ep =
                (const struct entry_point_command *)cmd_ptr;
            img->has_main      = true;
            img->main_entryoff = ep->entryoff;
            break;
        }

        case LC_LOAD_DYLIB:
        case LC_REEXPORT_DYLIB: {
            const struct dylib_command *dl =
                (const struct dylib_command *)cmd_ptr;
            uint32_t name_off = dl->dylib.name_offset;
            if (name_off < lc->cmdsize && img->ndylibs < 32) {
                img->dylib_paths[img->ndylibs] =
                    (const char *)(cmd_ptr + name_off);
                img->ndylibs++;
            }
            break;
        }

        default:
            break;
        }

        cmd_ptr += lc->cmdsize;
    }

    /*
     * Second pass for LC_SYMTAB: if we didn't resolve symtab/strtab above
     * (because __LINKEDIT came after LC_SYMTAB in load command order),
     * resolve it now.
     */
    if (img->symtab == NULL && img->linkedit_vmaddr != 0) {
        cmd_ptr = (const uint8_t *)(mh + 1);
        for (uint32_t i = 0; i < ncmds; i++) {
            const struct load_command *lc =
                (const struct load_command *)cmd_ptr;
            if (lc->cmdsize < sizeof(struct load_command))
                break;

            if (lc->cmd == LC_SYMTAB) {
                const struct symtab_command *sym =
                    (const struct symtab_command *)cmd_ptr;
                img->symtab = (const struct nlist_64 *)(
                    img->linkedit_vmaddr +
                    (sym->symoff - img->linkedit_fileoff));
                img->nsyms   = sym->nsyms;
                img->strtab  = (const char *)(
                    img->linkedit_vmaddr +
                    (sym->stroff - img->linkedit_fileoff));
                img->strsize = sym->strsize;
                break;
            }

            cmd_ptr += lc->cmdsize;
        }
    }
}

/* ============================================================================
 * Symbol Resolution
 *
 * Look up a symbol name in a loaded image. Searches the nlist_64 symbol
 * table for a defined external symbol with the given name.
 * ============================================================================ */

static uint64_t lookup_symbol_in_image(const struct loaded_image *img,
                                       const char *name)
{
    if (img->symtab == NULL || img->strtab == NULL)
        return 0;

    for (uint32_t i = 0; i < img->nsyms; i++) {
        const struct nlist_64 *nl = &img->symtab[i];

        /* Skip debug symbols */
        if (nl->n_type & N_STAB)
            continue;

        /* Must be external and defined */
        if (!(nl->n_type & N_EXT))
            continue;
        if ((nl->n_type & N_TYPE) == N_UNDF)
            continue;

        /* Compare name */
        if (nl->n_strx < img->strsize) {
            const char *sym_name = img->strtab + nl->n_strx;
            if (dyld_strcmp(sym_name, name) == 0) {
                return nl->n_value + img->slide;
            }
        }
    }

    return 0;
}

/*
 * Export trie lookup: walk the compressed prefix trie in __LINKEDIT.
 *
 * The trie is a DAG where each node has:
 *   - terminal info size (ULEB128): if > 0, this node is a terminal
 *     - flags (ULEB128)
 *     - address (ULEB128) — offset from image base
 *   - child count (uint8_t)
 *   - for each child:
 *     - edge label (null-terminated string)
 *     - child node offset (ULEB128) from trie start
 */
static uint64_t lookup_export_trie(const struct loaded_image *img,
                                   const char *name)
{
    if (!img->has_exports_trie)
        return 0;
    if (img->linkedit_vmaddr == 0)
        return 0;

    const uint8_t *trie_start = (const uint8_t *)(
        img->linkedit_vmaddr +
        (img->exports_trie_off - img->linkedit_fileoff));
    const uint8_t *trie_end = trie_start + img->exports_trie_size;

    const uint8_t *node = trie_start;
    const char *s = name;

    while (node < trie_end) {
        /* Read terminal info size */
        const uint8_t *p = node;
        uint64_t term_size = read_uleb128(&p, trie_end);

        if (*s == '\0' && term_size != 0) {
            /* We matched the full symbol name and this is a terminal node */
            uint64_t flags = read_uleb128(&p, trie_end);
            (void)flags; /* We don't use flags for now */
            uint64_t address = read_uleb128(&p, trie_end);
            return img->text_base + address;
        }

        /*
         * Skip past terminal info to reach the children.
         * The terminal data starts right after the term_size ULEB.
         * If term_size > 0, skip term_size bytes of terminal data.
         * Then read child count.
         */
        const uint8_t *after_term;
        if (term_size == 0) {
            after_term = p; /* p is already past the ULEB for term_size */
        } else {
            /*
             * Re-read term_size ULEB from node to get pointer past it,
             * then skip term_size bytes of payload.
             */
            const uint8_t *tp = node;
            uint64_t ts = read_uleb128(&tp, trie_end);
            after_term = tp + ts;
        }

        if (after_term >= trie_end)
            return 0;

        uint8_t child_count = *after_term++;
        const uint8_t *cp = after_term;

        /* Search children for a matching edge */
        bool found = false;
        for (uint8_t c = 0; c < child_count; c++) {
            /* Read edge label (null-terminated string) and compare */
            const char *sp = s;
            bool match = true;

            while (*cp != '\0') {
                if (cp >= trie_end)
                    return 0;
                if (match && *sp != (char)*cp)
                    match = false;
                if (match)
                    sp++;
                cp++;
            }
            cp++; /* skip null terminator */

            /* Read child node offset */
            uint64_t child_offset = read_uleb128(&cp, trie_end);

            if (match) {
                /* Follow this edge */
                node = trie_start + child_offset;
                s = sp;
                found = true;
                break;
            }
        }

        if (!found)
            return 0;
    }

    return 0;
}

/*
 * Resolve a symbol name across all loaded images.
 * The ordinal indicates which dylib to search (1-based from LC_LOAD_DYLIB order).
 *   ordinal 1 = first dylib, 2 = second, etc.
 *   ordinal 0 = self
 *   ordinal -1 = main executable
 *   ordinal -2 = flat lookup (search all)
 *   ordinal -3 = self (alias)
 *
 * For simplicity we search all images if we can't find it in the target.
 */
static uint64_t get_stub_binder_addr(void);  /* forward decl */

static uint64_t resolve_symbol(const char *name, int ordinal,
                               const struct loaded_image *requester)
{
    uint64_t addr = 0;

    /*
     * Special case: dyld_stub_binder is emitted by the linker without
     * the usual underscore prefix. It's a dyld-internal symbol.
     * Since we eagerly resolve all lazy bindings, return our trap address.
     */
    if (dyld_strcmp(name, "dyld_stub_binder") == 0)
        return get_stub_binder_addr();

    /* Try targeted lookup first */
    if (ordinal > 0) {
        /*
         * ordinal is 1-based index into the requester's dylib list.
         * We need to find which loaded image corresponds to that dylib.
         */
        uint32_t idx = (uint32_t)(ordinal - 1);
        if (idx < requester->ndylibs) {
            /* Find the loaded image matching this dylib path */
            const char *target_path = requester->dylib_paths[idx];
            for (uint32_t i = 0; i < num_images; i++) {
                /*
                 * Compare paths. dylib paths in LC_LOAD_DYLIB are full
                 * paths like "/usr/lib/libSystem.B.dylib". Match by
                 * comparing the full path or just the filename.
                 */
                if (images[i].path != NULL &&
                    dyld_strcmp(images[i].path, target_path) == 0) {
                    /* Try export trie first, then nlist symbol table */
                    addr = lookup_export_trie(&images[i], name);
                    if (addr == 0)
                        addr = lookup_symbol_in_image(&images[i], name);
                    if (addr != 0)
                        return addr;
                }
            }
        }
    }

    /* Flat namespace fallback: search all loaded images */
    for (uint32_t i = 0; i < num_images; i++) {
        addr = lookup_export_trie(&images[i], name);
        if (addr == 0)
            addr = lookup_symbol_in_image(&images[i], name);
        if (addr != 0)
            return addr;
    }

    return 0;
}

/* ============================================================================
 * Segment Address Lookup
 *
 * Given a segment index and an image, return the segment's base VA.
 * Used by rebase/bind opcodes that reference segments by index.
 * ============================================================================ */

static uint64_t segment_address(const struct loaded_image *img,
                                uint32_t seg_index)
{
    if (seg_index < img->nsegs)
        return img->segs[seg_index].vmaddr;
    return 0;
}

static uint64_t segment_size(const struct loaded_image *img,
                             uint32_t seg_index)
{
    if (seg_index < img->nsegs)
        return img->segs[seg_index].vmsize;
    return 0;
}

/* ============================================================================
 * Rebase Opcodes (DYLD_INFO_ONLY)
 *
 * Rebase opcodes adjust internal pointers in the binary for the ASLR slide.
 * Each fixup location contains (original_value + slide).
 * ============================================================================ */

static void process_rebases(struct loaded_image *img)
{
    if (!img->has_dyld_info || img->rebase_size == 0)
        return;
    if (img->linkedit_vmaddr == 0)
        return;

    const uint8_t *start = (const uint8_t *)(
        img->linkedit_vmaddr +
        (img->rebase_off - img->linkedit_fileoff));
    const uint8_t *end = start + img->rebase_size;
    const uint8_t *p = start;

    uint32_t seg_index = 0;
    uint64_t seg_offset = 0;
    uint32_t type = REBASE_TYPE_POINTER;
    int64_t  slide = (int64_t)img->slide;
    bool done = false;

    while (!done && p < end) {
        uint8_t byte = *p++;
        uint8_t opcode = byte & REBASE_OPCODE_MASK;
        uint8_t imm    = byte & REBASE_IMMEDIATE_MASK;

        switch (opcode) {

        case REBASE_OPCODE_DONE:
            done = true;
            break;

        case REBASE_OPCODE_SET_TYPE_IMM:
            type = imm;
            break;

        case REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
            seg_index  = imm;
            seg_offset = read_uleb128(&p, end);
            break;

        case REBASE_OPCODE_ADD_ADDR_ULEB:
            seg_offset += read_uleb128(&p, end);
            break;

        case REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
            seg_offset += (uint64_t)imm * sizeof(uint64_t);
            break;

        case REBASE_OPCODE_DO_REBASE_IMM_TIMES: {
            uint64_t addr = segment_address(img, seg_index) + seg_offset;
            for (uint8_t j = 0; j < imm; j++) {
                if (type == REBASE_TYPE_POINTER) {
                    uint64_t *slot = (uint64_t *)addr;
                    *slot += (uint64_t)slide;
                }
                addr += sizeof(uint64_t);
                seg_offset += sizeof(uint64_t);
            }
            break;
        }

        case REBASE_OPCODE_DO_REBASE_ULEB_TIMES: {
            uint64_t count = read_uleb128(&p, end);
            uint64_t addr = segment_address(img, seg_index) + seg_offset;
            for (uint64_t j = 0; j < count; j++) {
                if (type == REBASE_TYPE_POINTER) {
                    uint64_t *slot = (uint64_t *)addr;
                    *slot += (uint64_t)slide;
                }
                addr += sizeof(uint64_t);
                seg_offset += sizeof(uint64_t);
            }
            break;
        }

        case REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: {
            uint64_t addr = segment_address(img, seg_index) + seg_offset;
            if (type == REBASE_TYPE_POINTER) {
                uint64_t *slot = (uint64_t *)addr;
                *slot += (uint64_t)slide;
            }
            seg_offset += sizeof(uint64_t) + read_uleb128(&p, end);
            break;
        }

        case REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: {
            uint64_t count = read_uleb128(&p, end);
            uint64_t skip  = read_uleb128(&p, end);
            uint64_t addr = segment_address(img, seg_index) + seg_offset;
            for (uint64_t j = 0; j < count; j++) {
                if (type == REBASE_TYPE_POINTER) {
                    uint64_t *slot = (uint64_t *)addr;
                    *slot += (uint64_t)slide;
                }
                addr += sizeof(uint64_t) + skip;
                seg_offset += sizeof(uint64_t) + skip;
            }
            break;
        }

        default:
            /* Unknown opcode — skip and hope for the best */
            break;
        }
    }
}

/* ============================================================================
 * Bind Opcodes (DYLD_INFO_ONLY)
 *
 * Process bind and lazy_bind opcode streams. For each BIND_OPCODE_DO_BIND,
 * resolve the symbol and write the address into the target location.
 *
 * We eagerly resolve lazy bindings too (same logic), so we don't need
 * a real dyld_stub_binder implementation.
 * ============================================================================ */

static void process_binds(struct loaded_image *img,
                          const uint8_t *start, const uint8_t *end,
                          bool is_lazy)
{
    const uint8_t *p = start;

    int          ordinal    = 0;
    const char  *sym_name   = "";
    uint32_t     seg_index  = 0;
    uint64_t     seg_offset = 0;
    uint32_t     type       = BIND_TYPE_POINTER;
    int64_t      addend     = 0;

    /* For threaded bind (BIND_OPCODE_THREADED) */
    bool         threaded   = false;
    uint64_t     bind_count = 0;
    /* Table of symbol names/ordinals for threaded binds */
    struct {
        const char *name;
        int         ordinal;
        int64_t     addend;
    } threaded_table[256];
    uint32_t threaded_idx = 0;

    bool done = false;

    while (!done && p < end) {
        uint8_t byte = *p++;
        uint8_t opcode = byte & BIND_OPCODE_MASK;
        uint8_t imm    = byte & BIND_IMMEDIATE_MASK;

        switch (opcode) {

        case BIND_OPCODE_DONE:
            if (is_lazy) {
                /* In lazy binds, DONE separates entries; continue */
            } else {
                done = true;
            }
            break;

        case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
            ordinal = (int)imm;
            break;

        case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
            ordinal = (int)read_uleb128(&p, end);
            break;

        case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
            if (imm == 0) {
                ordinal = 0;    /* self */
            } else {
                /* Sign-extend the 4-bit immediate */
                ordinal = (int)(int8_t)(BIND_OPCODE_MASK | imm);
            }
            break;

        case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
            sym_name = (const char *)p;
            while (p < end && *p != '\0') p++;
            if (p < end) p++; /* skip null */
            break;

        case BIND_OPCODE_SET_TYPE_IMM:
            type = imm;
            break;

        case BIND_OPCODE_SET_ADDEND_SLEB:
            addend = read_sleb128(&p, end);
            break;

        case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
            seg_index  = imm;
            seg_offset = read_uleb128(&p, end);
            break;

        case BIND_OPCODE_ADD_ADDR_ULEB:
            seg_offset += read_uleb128(&p, end);
            break;

        case BIND_OPCODE_DO_BIND: {
            uint64_t addr = segment_address(img, seg_index) + seg_offset;
            uint64_t target = resolve_symbol(sym_name, ordinal, img);

#ifdef DEBUG
            dyld_puts("dyld:   BIND '");
            dyld_puts(sym_name);
            dyld_puts("' -> 0x");
            dyld_put_hex(target);
            dyld_puts(" at 0x");
            dyld_put_hex(addr);
            dyld_puts("\n");
#endif

            if (target == 0) {
                dyld_puts("dyld: warning: unresolved symbol '");
                dyld_puts(sym_name);
                dyld_puts("'\n");
            }

            if (type == BIND_TYPE_POINTER) {
                *(uint64_t *)addr = target + (uint64_t)addend;
            }

            seg_offset += sizeof(uint64_t);
            break;
        }

        case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: {
            uint64_t addr = segment_address(img, seg_index) + seg_offset;
            uint64_t target = resolve_symbol(sym_name, ordinal, img);
            if (target == 0) {
                dyld_puts("dyld: warning: unresolved symbol '");
                dyld_puts(sym_name);
                dyld_puts("'\n");
            }
            if (type == BIND_TYPE_POINTER) {
                *(uint64_t *)addr = target + (uint64_t)addend;
            }
            seg_offset += sizeof(uint64_t) + read_uleb128(&p, end);
            break;
        }

        case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: {
            uint64_t addr = segment_address(img, seg_index) + seg_offset;
            uint64_t target = resolve_symbol(sym_name, ordinal, img);
            if (target == 0) {
                dyld_puts("dyld: warning: unresolved symbol '");
                dyld_puts(sym_name);
                dyld_puts("'\n");
            }
            if (type == BIND_TYPE_POINTER) {
                *(uint64_t *)addr = target + (uint64_t)addend;
            }
            seg_offset += sizeof(uint64_t) + (uint64_t)imm * sizeof(uint64_t);
            break;
        }

        case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: {
            uint64_t count = read_uleb128(&p, end);
            uint64_t skip  = read_uleb128(&p, end);
            uint64_t target = resolve_symbol(sym_name, ordinal, img);
            if (target == 0) {
                dyld_puts("dyld: warning: unresolved symbol '");
                dyld_puts(sym_name);
                dyld_puts("'\n");
            }
            uint64_t addr = segment_address(img, seg_index) + seg_offset;
            for (uint64_t j = 0; j < count; j++) {
                if (type == BIND_TYPE_POINTER) {
                    *(uint64_t *)addr = target + (uint64_t)addend;
                }
                addr += sizeof(uint64_t) + skip;
                seg_offset += sizeof(uint64_t) + skip;
            }
            break;
        }

        case BIND_OPCODE_THREADED: {
            switch (imm) {
            case BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB:
                bind_count = read_uleb128(&p, end);
                threaded = true;
                threaded_idx = 0;
                (void)bind_count;
                break;

            case BIND_SUBOPCODE_THREADED_APPLY: {
                /*
                 * Walk the chain of fixups in the current segment.
                 * Each 64-bit value encodes either a rebase or a bind
                 * and contains a 'next' field linking to the next fixup.
                 */
                uint64_t addr = segment_address(img, seg_index) + seg_offset;
                uint64_t seg_end = segment_address(img, seg_index) +
                                   segment_size(img, seg_index);

                while (addr != 0 && addr < seg_end) {
                    uint64_t raw = *(uint64_t *)addr;
                    bool is_bind = (raw >> 63) & 1;
                    uint16_t delta = (uint16_t)((raw >> 52) & 0x7FF);

                    if (is_bind) {
                        uint32_t bind_ord = (uint32_t)(raw & 0xFFFF);
                        if (bind_ord < threaded_idx) {
                            uint64_t target = resolve_symbol(
                                threaded_table[bind_ord].name,
                                threaded_table[bind_ord].ordinal,
                                img);
                            *(uint64_t *)addr = target +
                                (uint64_t)threaded_table[bind_ord].addend;
                        }
                    } else {
                        /* Rebase: target is in bits [51:0], add slide */
                        uint64_t target = raw & 0x7FFFFFFFFFFFF;
                        uint8_t high8 = (uint8_t)((raw >> 52) & 0xFF);
                        /* Reconstruct the full pointer */
                        target |= (uint64_t)high8 << 56;
                        target += img->slide;
                        /* Preserve the high bits for the delta chain */
                        *(uint64_t *)addr = target;
                    }

                    if (delta == 0)
                        break;
                    addr += (uint64_t)delta * sizeof(uint64_t);
                }
                break;
            }

            default:
                break;
            }
            break;
        }

        default:
            /* Unknown opcode */
            break;
        }

        /*
         * For threaded binds, after SET_SYMBOL_TRAILING_FLAGS_IMM,
         * record the entry in our table.
         */
        if (threaded && opcode == BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM) {
            /* This was a SET_SYMBOL, record it */
        }
        if (threaded && opcode == BIND_OPCODE_SET_ADDEND_SLEB) {
            /* Update the current entry's addend */
        }
        /*
         * For threaded binds, each bind entry is defined by:
         *   SET_DYLIB_ORDINAL_*, SET_SYMBOL_TRAILING_FLAGS_IMM,
         *   optionally SET_ADDEND_SLEB, then DO_BIND.
         * The DO_BIND adds the symbol to the ordinal table.
         */
        if (threaded && opcode == BIND_OPCODE_DO_BIND) {
            /* In threaded mode, DO_BIND doesn't actually write;
             * it adds the symbol to the ordinal table */
            if (threaded_idx < 256) {
                /* Undo the seg_offset advance and the write we did above
                 * in the DO_BIND handler. In threaded mode, DO_BIND only
                 * records the symbol. */
                seg_offset -= sizeof(uint64_t); /* undo advance */
                threaded_table[threaded_idx].name    = sym_name;
                threaded_table[threaded_idx].ordinal = ordinal;
                threaded_table[threaded_idx].addend  = addend;
                threaded_idx++;
            }
        }
    }
}

static void process_all_binds(struct loaded_image *img)
{
#ifdef DEBUG
    dyld_puts("dyld: process_all_binds for '");
    if (img->path)
        dyld_puts(img->path);
    else
        dyld_puts("(main)");
    dyld_puts("'\n");
#endif

    if (!img->has_dyld_info) {
#ifdef DEBUG
        dyld_puts("dyld:   no DYLD_INFO, skipping\n");
#endif
        return;
    }
    if (img->linkedit_vmaddr == 0) {
#ifdef DEBUG
        dyld_puts("dyld:   no LINKEDIT vmaddr, skipping\n");
#endif
        return;
    }

#ifdef DEBUG
    dyld_puts("dyld:   linkedit_vmaddr=0x");
    dyld_put_hex(img->linkedit_vmaddr);
    dyld_puts(" linkedit_fileoff=0x");
    dyld_put_hex(img->linkedit_fileoff);
    dyld_puts("\n");
#endif

    /* Non-lazy binds */
    if (img->bind_size > 0) {
        const uint8_t *start = (const uint8_t *)(
            img->linkedit_vmaddr +
            (img->bind_off - img->linkedit_fileoff));
        const uint8_t *end = start + img->bind_size;
        process_binds(img, start, end, false);
    }

    /* Lazy binds (eagerly resolved) */
    if (img->lazy_bind_size > 0) {
        const uint8_t *start = (const uint8_t *)(
            img->linkedit_vmaddr +
            (img->lazy_bind_off - img->linkedit_fileoff));
        const uint8_t *end = start + img->lazy_bind_size;
        process_binds(img, start, end, true);
    }

    /* Weak binds */
    if (img->weak_bind_size > 0) {
        const uint8_t *start = (const uint8_t *)(
            img->linkedit_vmaddr +
            (img->weak_bind_off - img->linkedit_fileoff));
        const uint8_t *end = start + img->weak_bind_size;
        process_binds(img, start, end, false);
    }
}

/* ============================================================================
 * Chained Fixups (LC_DYLD_CHAINED_FIXUPS)
 *
 * Newer Mach-O format where fixup locations are threaded through the
 * data segment as a linked list per page, rather than using opcode streams.
 * ============================================================================ */

static void process_chained_fixups(struct loaded_image *img)
{
    if (!img->has_chained_fixups)
        return;
    if (img->linkedit_vmaddr == 0)
        return;

    const uint8_t *fixup_data = (const uint8_t *)(
        img->linkedit_vmaddr +
        (img->chained_fixups_off - img->linkedit_fileoff));

    const struct dyld_chained_fixups_header *header =
        (const struct dyld_chained_fixups_header *)fixup_data;

    /* Imports table */
    const struct dyld_chained_import *imports =
        (const struct dyld_chained_import *)(fixup_data + header->imports_offset);
    const char *symbols_base =
        (const char *)(fixup_data + header->symbols_offset);

    /* Starts-in-image */
    const struct dyld_chained_starts_in_image *starts =
        (const struct dyld_chained_starts_in_image *)(
            fixup_data + header->starts_offset);

    /* Process each segment */
    for (uint32_t seg = 0; seg < starts->seg_count; seg++) {
        uint32_t seg_off = starts->seg_info_offset[seg];
        if (seg_off == 0)
            continue;

        const struct dyld_chained_starts_in_segment *seg_starts =
            (const struct dyld_chained_starts_in_segment *)(
                (const uint8_t *)starts + seg_off);

        uint16_t pointer_format = seg_starts->pointer_format;
        uint64_t seg_base = img->text_base + seg_starts->segment_offset;

        /* Determine stride based on pointer format */
        uint32_t stride;
        switch (pointer_format) {
        case DYLD_CHAINED_PTR_64:
        case DYLD_CHAINED_PTR_64_OFFSET:
            stride = 4;
            break;
        case DYLD_CHAINED_PTR_ARM64E:
            stride = 8;
            break;
        default:
            stride = 4;
            break;
        }

        /* Walk each page */
        for (uint16_t page = 0; page < seg_starts->page_count; page++) {
            uint16_t page_start = seg_starts->page_start[page];
            if (page_start == DYLD_CHAINED_PTR_START_NONE)
                continue;

            uint64_t page_base = seg_base +
                (uint64_t)page * (uint64_t)seg_starts->page_size;
            uint64_t addr = page_base + page_start;

            /* Walk the chain */
            for (;;) {
                uint64_t raw = *(uint64_t *)addr;
                bool is_bind = (raw >> 63) & 1;
                uint64_t next;

                if (pointer_format == DYLD_CHAINED_PTR_64) {
                    /*
                     * DYLD_CHAINED_PTR_64 (format 2):
                     *   Rebase: bit63=0
                     *     target: bits [35:0]  (36 bits, vmaddr)
                     *     high8:  bits [43:36] (8 bits)
                     *     next:   bits [51:44] (8 bits)
                     *   Bind: bit63=1
                     *     ordinal: bits [23:0]  (24 bits)
                     *     addend:  bits [31:24] (8 bits)
                     *     next:    bits [51:32] (20 bits) — wait, that's wrong.
                     *
                     * Actually for format 2 (DYLD_CHAINED_PTR_64):
                     *   Rebase: bit63=0
                     *     target: bits [35:0]
                     *     high8:  bits [43:36]
                     *     next:   bits [51:44]
                     *     bind:   bit 62 (=0)
                     *   Bind: bit63=1
                     *     ordinal: bits [23:0]
                     *     addend:  bits [31:24]
                     *     reserved:bits [51:32]
                     *     next:    bits [62:52] — 11 bits
                     */
                    if (!is_bind) {
                        /* Rebase */
                        uint64_t target = raw & 0xFFFFFFFFF;       /* bits [35:0] */
                        uint8_t high8   = (uint8_t)((raw >> 36) & 0xFF);  /* bits [43:36] */
                        next            = (raw >> 44) & 0xFF;      /* bits [51:44] */

                        uint64_t value = target + img->slide;
                        value |= (uint64_t)high8 << 56;
                        *(uint64_t *)addr = value;
                    } else {
                        /* Bind */
                        uint32_t bind_ordinal = (uint32_t)(raw & 0xFFFFFF);
                        uint8_t  bind_addend  = (uint8_t)((raw >> 24) & 0xFF);
                        next = (raw >> 52) & 0x7FF; /* bits [62:52], 11 bits */

                        if (bind_ordinal < header->imports_count) {
                            uint32_t imp_data = imports[bind_ordinal].data;
                            uint32_t name_off = (imp_data >> 9) & 0x7FFFFF;
                            /* uint8_t lib_ord = imp_data & 0xFF; */
                            const char *sym_name = symbols_base + name_off;

                            int lib_ordinal = (int)(int8_t)(imp_data & 0xFF);
                            uint64_t target = resolve_symbol(
                                sym_name, lib_ordinal, img);
                            if (target == 0) {
                                dyld_puts("dyld: warning: chained unresolved '");
                                dyld_puts(sym_name);
                                dyld_puts("'\n");
                            }
                            *(uint64_t *)addr = target + (uint64_t)bind_addend;
                        }
                    }
                }
                else if (pointer_format == DYLD_CHAINED_PTR_64_OFFSET) {
                    /*
                     * DYLD_CHAINED_PTR_64_OFFSET (format 6):
                     *   Rebase: bit63=0
                     *     target: bits [35:0]  (36 bits, offset from mach_header)
                     *     high8:  bits [43:36] (8 bits)
                     *     next:   bits [51:44] (8 bits)
                     *   Bind: bit63=1
                     *     ordinal: bits [23:0]
                     *     addend:  bits [31:24]
                     *     reserved:bits [51:32]
                     *     next:    bits [62:52] (11 bits)
                     */
                    if (!is_bind) {
                        /* Rebase: target is an offset from image base */
                        uint64_t target = raw & 0xFFFFFFFFF;       /* bits [35:0] */
                        uint8_t high8   = (uint8_t)((raw >> 36) & 0xFF);
                        next            = (raw >> 44) & 0xFF;

                        /* In PTR_64_OFFSET, target is offset from mach_header */
                        uint64_t value = img->text_base + target;
                        value |= (uint64_t)high8 << 56;
                        *(uint64_t *)addr = value;
                    } else {
                        /* Bind: same as PTR_64 */
                        uint32_t bind_ordinal = (uint32_t)(raw & 0xFFFFFF);
                        uint8_t  bind_addend  = (uint8_t)((raw >> 24) & 0xFF);
                        next = (raw >> 52) & 0x7FF;

                        if (bind_ordinal < header->imports_count) {
                            uint32_t imp_data = imports[bind_ordinal].data;
                            uint32_t name_off = (imp_data >> 9) & 0x7FFFFF;
                            const char *sym_name = symbols_base + name_off;

                            int lib_ordinal = (int)(int8_t)(imp_data & 0xFF);
                            uint64_t target = resolve_symbol(
                                sym_name, lib_ordinal, img);
                            if (target == 0) {
                                dyld_puts("dyld: warning: chained unresolved '");
                                dyld_puts(sym_name);
                                dyld_puts("'\n");
                            }
                            *(uint64_t *)addr = target + (uint64_t)bind_addend;
                        }
                    }
                }
                else {
                    /* Unsupported format — bail out of this chain */
                    dyld_puts("dyld: unsupported chained pointer format ");
                    dyld_put_dec(pointer_format);
                    dyld_puts("\n");
                    break;
                }

                if (next == 0)
                    break;
                addr += next * stride;
            }
        }
    }
}

/* ============================================================================
 * Load a Dylib from Disk
 *
 * Reads the dylib file, parses its Mach-O header, mmaps its segments
 * into our address space, and registers it as a loaded image for symbol
 * resolution.
 * ============================================================================ */

static struct loaded_image *load_dylib(const char *path)
{
    /*
     * Return dyld's own image when asked to load /usr/lib/dyld.
     * libSystem has a dependency on dyld (for dyld_stub_binder).
     * Since dyld is already running, we return our pre-registered image
     * so symbol resolution can find dyld_stub_binder.
     */
    if (dyld_strcmp(path, "/usr/lib/dyld") == 0) {
        return dyld_image;  /* Return dyld's own image */
    }

    if (num_images >= MAX_IMAGES) {
        dyld_puts("dyld: too many loaded images\n");
        return NULL;
    }

    /* Read the entire file into memory */
    size_t file_size = 0;
    uint8_t *file_data = read_file(path, &file_size);
    if (file_data == NULL) {
        dyld_puts("dyld: failed to read '");
        dyld_puts(path);
        dyld_puts("'\n");
        return NULL;
    }

    /* Validate Mach-O header */
    if (file_size < sizeof(struct mach_header_64)) {
        dyld_puts("dyld: file too small for mach_header\n");
        return NULL;
    }

    const struct mach_header_64 *mh = (const struct mach_header_64 *)file_data;
    if (mh->magic != MH_MAGIC_64) {
        dyld_puts("dyld: bad magic in '");
        dyld_puts(path);
        dyld_puts("'\n");
        return NULL;
    }

    if (mh->filetype != MH_DYLIB) {
        dyld_puts("dyld: '");
        dyld_puts(path);
        dyld_puts("' is not MH_DYLIB\n");
        return NULL;
    }

    /*
     * First pass: find segments and determine the total VM range.
     * We'll mmap the segments into their specified vmaddrs.
     *
     * For a dylib, segments have their preferred vmaddrs. Since the
     * kernel didn't map these, we need to map them ourselves. We
     * apply a slide if the preferred address is already taken or is 0.
     */
    const uint8_t *cmd_ptr = (const uint8_t *)(mh + 1);
    uint64_t min_addr = (uint64_t)-1;
    uint64_t max_addr = 0;
    bool has_text = false;

    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cmd_ptr;
        if (lc->cmdsize < sizeof(struct load_command))
            break;

        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg =
                (const struct segment_command_64 *)cmd_ptr;

            /* Skip __PAGEZERO */
            if (seg->vmaddr == 0 && seg->filesize == 0 &&
                seg->vmsize > 0 && seg->initprot == 0)
                goto next_cmd;

            if (seg->vmsize == 0)
                goto next_cmd;

            if (seg->vmaddr < min_addr)
                min_addr = seg->vmaddr;
            if (seg->vmaddr + seg->vmsize > max_addr)
                max_addr = seg->vmaddr + seg->vmsize;

            if (dyld_strncmp(seg->segname, "__TEXT", 6) == 0)
                has_text = true;
        }
    next_cmd:
        cmd_ptr += lc->cmdsize;
    }

    if (!has_text || max_addr <= min_addr) {
        dyld_puts("dyld: invalid segment layout in '");
        dyld_puts(path);
        dyld_puts("'\n");
        return NULL;
    }

    /*
     * Allocate a contiguous VM region for the dylib.
     * We request an anonymous mapping at any address and then use
     * MAP_FIXED to place individual segments within this region.
     */
    uint64_t total_vm_size = max_addr - min_addr;
    uint64_t page_size = 0x1000; /* 4KB pages (Kiseki kernel page size) */
    total_vm_size = (total_vm_size + page_size - 1) & ~(page_size - 1);

    uint8_t *base = (uint8_t *)sys_mmap(NULL, total_vm_size,
                                         PROT_READ | PROT_WRITE | PROT_EXEC,
                                         MAP_PRIVATE | MAP_ANON, -1, 0);
    if (base == MAP_FAILED) {
        dyld_puts("dyld: mmap failed for dylib VM region\n");
        return NULL;
    }

    int64_t slide = (int64_t)((uint64_t)base - min_addr);

    /*
     * Second pass: copy segment data from the file into the mapped region.
     * For each segment, copy filesize bytes from file_data + fileoff,
     * and zero-fill the rest up to vmsize.
     */
    cmd_ptr = (const uint8_t *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cmd_ptr;
        if (lc->cmdsize < sizeof(struct load_command))
            break;

        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg =
                (const struct segment_command_64 *)cmd_ptr;

            /* Skip __PAGEZERO */
            if (seg->vmaddr == 0 && seg->filesize == 0 &&
                seg->vmsize > 0 && seg->initprot == 0)
                goto next_cmd2;

            if (seg->vmsize == 0)
                goto next_cmd2;

            uint64_t dest = seg->vmaddr + (uint64_t)slide;

            /* Copy file data */
            if (seg->filesize > 0 && seg->fileoff + seg->filesize <= file_size) {
                dyld_memcpy((void *)dest, file_data + seg->fileoff,
                            (size_t)seg->filesize);
            }

            /* Zero-fill beyond filesize */
            if (seg->vmsize > seg->filesize) {
                dyld_memset((void *)(dest + seg->filesize), 0,
                            (size_t)(seg->vmsize - seg->filesize));
            }
        }
    next_cmd2:
        cmd_ptr += lc->cmdsize;
    }

    /*
     * Register the loaded image.
     * The mach_header pointer is now at (min_addr + slide) which is base.
     * But the actual file_data still has the header for load command parsing.
     * We set img->mh to point at the mapped header in the new region.
     */
    struct loaded_image *img = &images[num_images++];
    dyld_memset(img, 0, sizeof(*img));
    img->path      = path;
    img->mh        = (const struct mach_header_64 *)((uint64_t)mh->filetype == MH_DYLIB ? base : base);
    /* The mach_header in the mapped region is at the start of __TEXT which starts at min_addr */
    img->mh        = (const struct mach_header_64 *)(min_addr + (uint64_t)slide);
    img->slide     = (uint64_t)slide;
    img->file_data = file_data;
    img->file_size = file_size;

    /* Parse load commands from the now-mapped image */
    parse_load_commands(img);

    return img;
}

/* ============================================================================
 * dyld_stub_binder Trap
 *
 * We eagerly resolve all lazy bindings, so dyld_stub_binder should never
 * be called. However, the binary's __got has a slot for it. We write the
 * address of this function into that slot; if it's ever called, we trap.
 *
 * The actual dyld_stub_binder symbol is defined in start.S (in assembly)
 * so that ld64 sees it as defined during linking. The assembly stub calls
 * this C function to handle the fatal error.
 * ============================================================================ */

/*
 * dyld_stub_binder_trap - Called by assembly stub when lazy binding is attempted
 *
 * This should never happen since we eagerly resolve all bindings.
 */
__attribute__((noreturn, used))
void dyld_stub_binder_trap(void)
{
    dyld_fatal("dyld_stub_binder called — this should not happen "
               "(all lazy bindings should be eagerly resolved)");
}

/* dyld_stub_binder is defined in start.S */
extern void dyld_stub_binder(void);

/* Address of the stub binder for binding */
static uint64_t get_stub_binder_addr(void)
{
    return (uint64_t)(void *)dyld_stub_binder;
}

/* ============================================================================
 * Main Entry Point
 *
 * Called from start.S with the stack parameters extracted from the kernel's
 * setup. This is the core of dyld: load, link, and hand off to main().
 * ============================================================================ */

void dyld_main(const struct mach_header_64 *main_mh,
               long argc, const char **argv,
               const char **envp, const char **apple)
{
    (void)apple;

    /* Validate main binary header */
    if (main_mh == NULL || main_mh->magic != MH_MAGIC_64) {
        dyld_fatal("invalid mach_header for main binary");
    }

    if (main_mh->filetype != MH_EXECUTE) {
        dyld_fatal("main binary is not MH_EXECUTE");
    }

    /* ----------------------------------------------------------------
     * Phase 1: Parse the main binary's load commands
     *
     * The kernel has already mapped all segments of the main binary.
     * We just need to read the load commands to find:
     *   - LC_LOAD_DYLIB dependencies
     *   - LC_DYLD_INFO_ONLY or LC_DYLD_CHAINED_FIXUPS
     *   - LC_MAIN entry point offset
     *   - LC_SEGMENT_64 segment info
     * ---------------------------------------------------------------- */
    struct loaded_image *main_img = &images[num_images++];
    dyld_memset(main_img, 0, sizeof(*main_img));
    main_img->path  = argv[0]; /* Best guess at the binary's path */
    main_img->mh    = main_mh;
    main_img->slide = 0; /* Kernel applies ASLR, but mh is at the slid address */

    parse_load_commands(main_img);

    /* ----------------------------------------------------------------
     * Phase 2: Load required dylibs
     *
     * For each LC_LOAD_DYLIB in the main binary, load the dylib from
     * disk, map its segments, and parse its load commands.
     * ---------------------------------------------------------------- */
    for (uint32_t i = 0; i < main_img->ndylibs; i++) {
        const char *dylib_path = main_img->dylib_paths[i];
        if (dylib_path == NULL)
            continue;

        /*
         * Skip /usr/lib/dyld - it's not a library, it's the dynamic linker
         * (us!). Some libraries incorrectly list it as a dependency due to
         * linking against dyld.tbd for dyld_stub_binder. We're already
         * running, so just skip it.
         */
        if (dyld_strcmp(dylib_path, "/usr/lib/dyld") == 0)
            continue;

        /* Check if already loaded */
        bool already_loaded = false;
        for (uint32_t j = 1; j < num_images; j++) {
            if (images[j].path != NULL &&
                dyld_strcmp(images[j].path, dylib_path) == 0) {
                already_loaded = true;
                break;
            }
        }

        if (!already_loaded) {
            struct loaded_image *dylib = load_dylib(dylib_path);
            if (dylib == NULL) {
                dyld_puts("dyld: warning: could not load '");
                dyld_puts(dylib_path);
                dyld_puts("' — continuing\n");
            } else {
                /*
                 * Recursively load this dylib's dependencies too.
                 * For now we do one level deep (libSystem.B.dylib's
                 * own re-exports are handled via its exports trie).
                 */
                for (uint32_t k = 0; k < dylib->ndylibs; k++) {
                    const char *dep = dylib->dylib_paths[k];
                    if (dep == NULL)
                        continue;
                    /* Skip dyld itself (see comment above) */
                    if (dyld_strcmp(dep, "/usr/lib/dyld") == 0)
                        continue;
                    bool dep_loaded = false;
                    for (uint32_t m = 0; m < num_images; m++) {
                        if (images[m].path != NULL &&
                            dyld_strcmp(images[m].path, dep) == 0) {
                            dep_loaded = true;
                            break;
                        }
                    }
                    if (!dep_loaded) {
                        load_dylib(dep);
                        /* We don't fail if transitive deps fail */
                    }
                }
            }
        }
    }

    /* ----------------------------------------------------------------
     * Phase 3: Process fixups for the main binary
     *
     * Apply rebase + bind using either DYLD_INFO_ONLY opcodes or
     * chained fixups format.
     * ---------------------------------------------------------------- */

    if (main_img->has_chained_fixups) {
        process_chained_fixups(main_img);
    } else if (main_img->has_dyld_info) {
        process_rebases(main_img);
        process_all_binds(main_img);
    }

    /*
     * Also process fixups for loaded dylibs (they may have their own
     * internal rebases and binds).
     */
    for (uint32_t i = 1; i < num_images; i++) {
        struct loaded_image *img = &images[i];
        if (img->has_chained_fixups) {
            process_chained_fixups(img);
        } else if (img->has_dyld_info) {
            process_rebases(img);
            process_all_binds(img);
        }
    }

    /* ----------------------------------------------------------------
     * Phase 4: Resolve dyld_stub_binder
     *
     * The main binary's __got has a slot for dyld_stub_binder.
     * Even though we eagerly resolve all lazy binds, the stub_helper
     * code references it. Write our trap address there.
     *
     * We search for the symbol in the bind opcodes — it should have
     * been handled during binding above. If not found as a pending
     * bind, we try to patch it directly.
     * ---------------------------------------------------------------- */

    /*
     * The dyld_stub_binder symbol should have been resolved during
     * bind processing. Since we eagerly resolve lazy bindings and
     * point dyld_stub_binder to our trap, the binary should work.
     *
     * If the bind had an entry for "dyld_stub_binder" pointing to
     * an unresolved symbol, we already wrote 0 + a warning.
     * Let's fix that by scanning the GOT.
     */

    /* Find __DATA_CONST,__got or __DATA,__got section */
    {
        const uint8_t *cmd_ptr = (const uint8_t *)(main_mh + 1);
        for (uint32_t i = 0; i < main_mh->ncmds; i++) {
            const struct load_command *lc =
                (const struct load_command *)cmd_ptr;
            if (lc->cmdsize < sizeof(struct load_command))
                break;

            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg =
                    (const struct segment_command_64 *)cmd_ptr;
                const struct section_64 *sect =
                    (const struct section_64 *)(cmd_ptr +
                        sizeof(struct segment_command_64));

                for (uint32_t j = 0; j < seg->nsects; j++) {
                    if (dyld_strncmp(sect[j].sectname, "__got", 5) == 0) {
                        /*
                         * The __got section contains function pointers.
                         * Any slot that is 0 might be dyld_stub_binder.
                         * We set all zero slots to our trap.
                         */
                        uint64_t got_addr = sect[j].addr + main_img->slide;
                        uint64_t got_count = sect[j].size / sizeof(uint64_t);
                        uint64_t *got = (uint64_t *)got_addr;
                        for (uint64_t k = 0; k < got_count; k++) {
                            if (got[k] == 0) {
                                got[k] = get_stub_binder_addr();
                            }
                        }
                    }
                }
            }
            cmd_ptr += lc->cmdsize;
        }
    }

    /* ----------------------------------------------------------------
     * Phase 5: Set up environ in libSystem
     *
     * Before calling main(), we need to set the 'environ' global in
     * libSystem so that getenv/setenv/execv work correctly. Look up
     * the symbol and write envp to it.
     * ---------------------------------------------------------------- */
    for (uint32_t i = 1; i < num_images; i++) {
        uint64_t environ_addr = lookup_symbol_in_image(&images[i], "_environ");
        if (environ_addr != 0) {
            /* Found environ - write envp to it */
            *(const char ***)environ_addr = envp;
            break;
        }
    }

    /* ----------------------------------------------------------------
     * Phase 6: Find entry point and jump to main()
     *
     * Read LC_MAIN from the main binary to get entryoff.
     * Compute main_addr = text_base + entryoff.
     * Call main(argc, argv, envp, apple).
     * ---------------------------------------------------------------- */

    if (!main_img->has_main) {
        dyld_fatal("main binary has no LC_MAIN");
    }

    uint64_t main_addr = main_img->text_base + main_img->main_entryoff;

#ifdef DEBUG
    dyld_puts("dyld: text_base=0x");
    dyld_put_hex(main_img->text_base);
    dyld_puts(" entryoff=0x");
    dyld_put_hex(main_img->main_entryoff);
    dyld_puts("\n");
    dyld_puts("dyld: jumping to main at 0x");
    dyld_put_hex(main_addr);
    dyld_puts("\n");

    /* Read first instruction at entry point to verify mapping */
    uint32_t *entry_insn = (uint32_t *)main_addr;
    dyld_puts("dyld: first instruction = 0x");
    dyld_put_hex(*entry_insn);
    dyld_puts("\n");
#endif

    /*
     * Call main(argc, argv, envp, apple).
     *
     * The C standard signature is: int main(int argc, char *argv[])
     * but XNU/dyld traditionally calls: main(argc, argv, envp, apple)
     * with apple being a Darwin extension. libSystem's crt initializer
     * typically calls main this way.
     *
     * We cast main_addr to a function pointer and call it directly.
     */
    typedef int (*main_func_t)(int, const char **, const char **,
                               const char **);
    main_func_t entry = (main_func_t)main_addr;

    int ret = entry((int)argc, argv, envp, apple);

    /*
     * main() returned — call libc exit() to flush stdio buffers.
     * In Mach-O, C symbol "exit" becomes "_exit" (leading underscore).
     * The raw _exit() syscall wrapper becomes "__exit".
     */
    typedef void (*exit_func_t)(int) __attribute__((noreturn));
    uint64_t exit_addr = 0;

#ifdef DEBUG
    dyld_puts("dyld: main returned ");
    dyld_put_dec(ret);
    dyld_puts(", looking for _exit\n");
#endif

    /* Search for _exit (libc exit) in loaded images */
    for (uint32_t i = 0; i < num_images; i++) {
#ifdef DEBUG
        dyld_puts("dyld: checking image ");
        dyld_put_dec(i);
        dyld_puts(": ");
        dyld_puts(images[i].path ? images[i].path : "(null)");
        dyld_puts("\n");
#endif
        exit_addr = lookup_export_trie(&images[i], "_exit");
        if (exit_addr)
            break;
        exit_addr = lookup_symbol_in_image(&images[i], "_exit");
        if (exit_addr)
            break;
    }

#ifdef DEBUG
    dyld_puts("dyld: _exit addr = 0x");
    dyld_put_hex(exit_addr);
    dyld_puts("\n");
#endif

    if (exit_addr) {
#ifdef DEBUG
        dyld_puts("dyld: calling libc exit at 0x");
        dyld_put_hex(exit_addr);
        dyld_puts(" with status ");
        dyld_put_dec(ret);
        dyld_puts("\n");
#endif
        exit_func_t libc_exit = (exit_func_t)exit_addr;
        libc_exit(ret);
#ifdef DEBUG
        /* Should never reach here since exit is noreturn */
        dyld_puts("dyld: ERROR - exit() returned!\n");
#endif
    }

#ifdef DEBUG
    dyld_puts("dyld: _exit not found, using raw syscall\n");
#endif

    /* Fallback to raw syscall if exit() not found */
    sys_exit(ret);
}
