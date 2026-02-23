/*
 * objdump - display information from object files
 *
 * Kiseki OS coreutils
 * Unix-compliant object file display utility with ARM64 disassembler
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

static const char *progname = "objdump";

/* ============================================================================
 * Mach-O Structures
 * ============================================================================ */

/* Mach-O magic numbers */
#define MH_MAGIC_64     0xfeedfacf
#define MH_CIGAM_64     0xcffaedfe

/* CPU types */
#define CPU_TYPE_ARM64  0x0100000c

/* File types */
#define MH_EXECUTE      0x2
#define MH_DYLIB        0x6
#define MH_DYLINKER     0x7

/* Load command types */
#define LC_SEGMENT_64   0x19
#define LC_SYMTAB       0x02
#define LC_DYSYMTAB     0x0b

/* Section types */
#define S_REGULAR       0x0

/* Mach-O 64-bit header */
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

/* Load command header */
struct load_command {
    uint32_t cmd;
    uint32_t cmdsize;
};

/* Segment command 64-bit */
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

/* Section 64-bit */
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

/* Symbol table command */
struct symtab_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t symoff;
    uint32_t nsyms;
    uint32_t stroff;
    uint32_t strsize;
};

/* nlist_64 symbol table entry */
struct nlist_64 {
    uint32_t n_strx;
    uint8_t  n_type;
    uint8_t  n_sect;
    uint16_t n_desc;
    uint64_t n_value;
};

/* ============================================================================
 * ARM64 Instruction Decoding
 * ============================================================================ */

/* ARM64 condition codes */
static const char *cond_names[] = {
    "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
    "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"
};

/* ARM64 register names */
static const char *reg_names_64[] = {
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
    "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
    "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
    "x24", "x25", "x26", "x27", "x28", "x29", "x30", "sp"
};

static const char *reg_names_32[] = {
    "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7",
    "w8", "w9", "w10", "w11", "w12", "w13", "w14", "w15",
    "w16", "w17", "w18", "w19", "w20", "w21", "w22", "w23",
    "w24", "w25", "w26", "w27", "w28", "w29", "w30", "wsp"
};

/* Get register name */
static const char *get_reg(int reg, int is_64bit)
{
    if (reg < 0 || reg > 31) return "???";
    if (reg == 31) return is_64bit ? "sp" : "wsp";
    return is_64bit ? reg_names_64[reg] : reg_names_32[reg];
}

/* Get register name (with xzr/wzr for reg 31) */
static const char *get_reg_zr(int reg, int is_64bit)
{
    if (reg < 0 || reg > 31) return "???";
    if (reg == 31) return is_64bit ? "xzr" : "wzr";
    return is_64bit ? reg_names_64[reg] : reg_names_32[reg];
}

/* Sign extend a value */
static int64_t sign_extend(uint64_t value, int bits)
{
    uint64_t sign_bit = 1ULL << (bits - 1);
    if (value & sign_bit)
        return (int64_t)(value | ~((1ULL << bits) - 1));
    return (int64_t)value;
}

/* Decode ARM64 instruction */
static int disasm_arm64(uint32_t insn, uint64_t addr, char *buf, size_t bufsize)
{
    buf[0] = '\0';
    
    /* Extract common fields */
    uint32_t op0 = (insn >> 25) & 0xf;
    
    /* Data processing - immediate */
    if ((op0 & 0xe) == 0x8 || (op0 & 0xe) == 0xa) {
        uint32_t sf = (insn >> 31) & 1;
        uint32_t opc = (insn >> 29) & 3;
        uint32_t op = (insn >> 23) & 7;
        
        /* ADD/SUB immediate */
        if (op == 1 || op == 2) {
            uint32_t sh = (insn >> 22) & 1;
            uint32_t imm12 = (insn >> 10) & 0xfff;
            uint32_t rn = (insn >> 5) & 0x1f;
            uint32_t rd = insn & 0x1f;
            
            const char *mnem;
            int sets_flags = opc & 1;
            int is_sub = (opc >> 1) & 1;
            
            if (is_sub) {
                mnem = sets_flags ? "subs" : "sub";
                /* CMP is SUB with rd=xzr/wzr */
                if (rd == 31 && sets_flags) mnem = "cmp";
            } else {
                mnem = sets_flags ? "adds" : "add";
                /* CMN is ADD with rd=xzr/wzr */
                if (rd == 31 && sets_flags) mnem = "cmn";
            }
            
            if (sh) imm12 <<= 12;
            
            if ((rd == 31 && sets_flags) || (rn == 31 && !sets_flags)) {
                /* CMP/CMN or MOV (rd=sp) */
                if (strcmp(mnem, "cmp") == 0 || strcmp(mnem, "cmn") == 0) {
                    snprintf(buf, bufsize, "%s\t%s, #%u",
                             mnem, get_reg(rn, sf), imm12);
                } else {
                    snprintf(buf, bufsize, "%s\t%s, %s, #%u",
                             mnem, get_reg(rd, sf), get_reg(rn, sf), imm12);
                }
            } else {
                snprintf(buf, bufsize, "%s\t%s, %s, #%u",
                         mnem, get_reg(rd, sf), get_reg(rn, sf), imm12);
            }
            return 0;
        }
        
        /* MOV/MOVN/MOVZ/MOVK immediate */
        if (op == 5) {
            uint32_t hw = (insn >> 21) & 3;
            uint32_t imm16 = (insn >> 5) & 0xffff;
            uint32_t rd = insn & 0x1f;
            
            const char *mnem;
            switch (opc) {
            case 0: mnem = "movn"; break;
            case 2: mnem = "movz"; break;
            case 3: mnem = "movk"; break;
            default: mnem = "mov?"; break;
            }
            
            if (hw == 0 && opc == 2) {
                /* MOV alias for MOVZ with hw=0 */
                snprintf(buf, bufsize, "mov\t%s, #%u",
                         get_reg(rd, sf), imm16);
            } else {
                snprintf(buf, bufsize, "%s\t%s, #%u, lsl #%u",
                         mnem, get_reg(rd, sf), imm16, hw * 16);
            }
            return 0;
        }
        
        /* Logical immediate */
        if (op == 4) {
            uint32_t rd = insn & 0x1f;
            uint32_t rn = (insn >> 5) & 0x1f;
            /* Decode bitmask immediate is complex - simplified version */
            const char *mnem;
            switch (opc) {
            case 0: mnem = "and"; break;
            case 1: mnem = "orr"; break;
            case 2: mnem = "eor"; break;
            case 3: mnem = "ands"; break;
            default: mnem = "log?"; break;
            }
            snprintf(buf, bufsize, "%s\t%s, %s, #<imm>",
                     mnem, get_reg_zr(rd, sf), get_reg_zr(rn, sf));
            return 0;
        }
        
        /* PC-relative addressing */
        if ((op0 & 0xe) == 0x8) {
            uint32_t op_adr = (insn >> 31) & 1;
            int64_t immhi = (insn >> 5) & 0x7ffff;
            int64_t immlo = (insn >> 29) & 3;
            uint32_t rd = insn & 0x1f;
            
            int64_t imm = (immhi << 2) | immlo;
            imm = sign_extend(imm, 21);
            
            if (op_adr) {
                /* ADRP */
                imm <<= 12;
                uint64_t target = (addr & ~0xfffULL) + imm;
                snprintf(buf, bufsize, "adrp\t%s, 0x%llx",
                         get_reg(rd, 1), (unsigned long long)target);
            } else {
                /* ADR */
                uint64_t target = addr + imm;
                snprintf(buf, bufsize, "adr\t%s, 0x%llx",
                         get_reg(rd, 1), (unsigned long long)target);
            }
            return 0;
        }
    }
    
    /* Branches */
    if ((op0 & 0xe) == 0xa) {
        /* Conditional branch */
        if ((insn & 0xff000010) == 0x54000000) {
            int64_t imm19 = (insn >> 5) & 0x7ffff;
            imm19 = sign_extend(imm19, 19) << 2;
            uint32_t cond = insn & 0xf;
            uint64_t target = addr + imm19;
            snprintf(buf, bufsize, "b.%s\t0x%llx",
                     cond_names[cond], (unsigned long long)target);
            return 0;
        }
        
        /* Compare and branch */
        if ((insn & 0x7e000000) == 0x34000000) {
            uint32_t sf = (insn >> 31) & 1;
            uint32_t op = (insn >> 24) & 1;
            int64_t imm19 = (insn >> 5) & 0x7ffff;
            imm19 = sign_extend(imm19, 19) << 2;
            uint32_t rt = insn & 0x1f;
            uint64_t target = addr + imm19;
            snprintf(buf, bufsize, "%s\t%s, 0x%llx",
                     op ? "cbnz" : "cbz",
                     get_reg(rt, sf), (unsigned long long)target);
            return 0;
        }
        
        /* Test and branch */
        if ((insn & 0x7e000000) == 0x36000000) {
            uint32_t b5 = (insn >> 31) & 1;
            uint32_t op = (insn >> 24) & 1;
            uint32_t b40 = (insn >> 19) & 0x1f;
            int64_t imm14 = (insn >> 5) & 0x3fff;
            imm14 = sign_extend(imm14, 14) << 2;
            uint32_t rt = insn & 0x1f;
            uint32_t bit = (b5 << 5) | b40;
            uint64_t target = addr + imm14;
            snprintf(buf, bufsize, "%s\t%s, #%u, 0x%llx",
                     op ? "tbnz" : "tbz",
                     get_reg(rt, b5), bit, (unsigned long long)target);
            return 0;
        }
    }
    
    /* Unconditional branch */
    if ((insn & 0xfc000000) == 0x14000000) {
        int64_t imm26 = insn & 0x3ffffff;
        imm26 = sign_extend(imm26, 26) << 2;
        uint64_t target = addr + imm26;
        snprintf(buf, bufsize, "b\t0x%llx", (unsigned long long)target);
        return 0;
    }
    
    if ((insn & 0xfc000000) == 0x94000000) {
        int64_t imm26 = insn & 0x3ffffff;
        imm26 = sign_extend(imm26, 26) << 2;
        uint64_t target = addr + imm26;
        snprintf(buf, bufsize, "bl\t0x%llx", (unsigned long long)target);
        return 0;
    }
    
    /* Unconditional branch register */
    if ((insn & 0xfe1ffc1f) == 0xd61f0000) {
        uint32_t opc = (insn >> 21) & 0xf;
        uint32_t rn = (insn >> 5) & 0x1f;
        const char *mnem;
        switch (opc) {
        case 0: mnem = "br"; break;
        case 1: mnem = "blr"; break;
        case 2: mnem = "ret"; break;
        default: mnem = "br?"; break;
        }
        if (opc == 2 && rn == 30) {
            snprintf(buf, bufsize, "ret");
        } else {
            snprintf(buf, bufsize, "%s\t%s", mnem, get_reg(rn, 1));
        }
        return 0;
    }
    
    /* Load/Store register */
    if ((op0 & 0x5) == 0x4) {
        uint32_t size = (insn >> 30) & 3;
        uint32_t v = (insn >> 26) & 1;
        uint32_t opc_ls = (insn >> 22) & 3;
        
        /* Load/Store unsigned immediate */
        if ((insn & 0x3b000000) == 0x39000000) {
            uint32_t imm12 = (insn >> 10) & 0xfff;
            uint32_t rn = (insn >> 5) & 0x1f;
            uint32_t rt = insn & 0x1f;
            
            int is_load = opc_ls & 1;
            int scale = (v ? 4 : size);
            int64_t offset = imm12 << scale;
            
            const char *mnem;
            if (!v) {
                if (is_load) {
                    switch (size) {
                    case 0: mnem = (opc_ls == 1) ? "ldrb" : "ldrsb"; break;
                    case 1: mnem = (opc_ls == 1) ? "ldrh" : "ldrsh"; break;
                    case 2: mnem = (opc_ls == 1) ? "ldr" : "ldrsw"; break;
                    case 3: mnem = "ldr"; break;
                    default: mnem = "ldr?"; break;
                    }
                } else {
                    switch (size) {
                    case 0: mnem = "strb"; break;
                    case 1: mnem = "strh"; break;
                    case 2: case 3: mnem = "str"; break;
                    default: mnem = "str?"; break;
                    }
                }
            } else {
                mnem = is_load ? "ldr" : "str";
            }
            
            int is_64 = (size == 3) || (v && size >= 2);
            if (offset == 0) {
                snprintf(buf, bufsize, "%s\t%s, [%s]",
                         mnem, get_reg(rt, is_64), get_reg(rn, 1));
            } else {
                snprintf(buf, bufsize, "%s\t%s, [%s, #%lld]",
                         mnem, get_reg(rt, is_64), get_reg(rn, 1), (long long)offset);
            }
            return 0;
        }
        
        /* Load/Store register pair */
        if ((insn & 0x3a000000) == 0x28000000) {
            uint32_t opc_pair = (insn >> 30) & 3;
            uint32_t is_load = (insn >> 22) & 1;
            int64_t imm7 = (insn >> 15) & 0x7f;
            imm7 = sign_extend(imm7, 7);
            uint32_t rt2 = (insn >> 10) & 0x1f;
            uint32_t rn = (insn >> 5) & 0x1f;
            uint32_t rt = insn & 0x1f;
            
            int scale = 2 + (opc_pair >> 1);
            int64_t offset = imm7 << scale;
            int is_64 = opc_pair >> 1;
            
            const char *mnem = is_load ? "ldp" : "stp";
            
            if (offset == 0) {
                snprintf(buf, bufsize, "%s\t%s, %s, [%s]",
                         mnem, get_reg(rt, is_64), get_reg(rt2, is_64), get_reg(rn, 1));
            } else {
                snprintf(buf, bufsize, "%s\t%s, %s, [%s, #%lld]",
                         mnem, get_reg(rt, is_64), get_reg(rt2, is_64),
                         get_reg(rn, 1), (long long)offset);
            }
            return 0;
        }
    }
    
    /* Data processing - register */
    if ((op0 & 0x7) == 0x5) {
        uint32_t sf = (insn >> 31) & 1;
        uint32_t opc = (insn >> 29) & 3;
        uint32_t op21 = (insn >> 21) & 0xf;
        
        /* Logical shifted register */
        if ((op21 & 0x8) == 0) {
            uint32_t shift = (insn >> 22) & 3;
            uint32_t n = (insn >> 21) & 1;
            uint32_t rm = (insn >> 16) & 0x1f;
            uint32_t imm6 = (insn >> 10) & 0x3f;
            uint32_t rn = (insn >> 5) & 0x1f;
            uint32_t rd = insn & 0x1f;
            
            const char *mnem;
            switch ((opc << 1) | n) {
            case 0: mnem = "and"; break;
            case 1: mnem = "bic"; break;
            case 2: mnem = "orr"; break;
            case 3: mnem = "orn"; break;
            case 4: mnem = "eor"; break;
            case 5: mnem = "eon"; break;
            case 6: mnem = "ands"; break;
            case 7: mnem = "bics"; break;
            default: mnem = "log?"; break;
            }
            
            /* MOV alias */
            if (opc == 1 && !n && rn == 31 && imm6 == 0 && shift == 0) {
                snprintf(buf, bufsize, "mov\t%s, %s",
                         get_reg(rd, sf), get_reg(rm, sf));
                return 0;
            }
            
            const char *shift_names[] = {"lsl", "lsr", "asr", "ror"};
            if (imm6 == 0) {
                snprintf(buf, bufsize, "%s\t%s, %s, %s",
                         mnem, get_reg_zr(rd, sf), get_reg_zr(rn, sf), get_reg_zr(rm, sf));
            } else {
                snprintf(buf, bufsize, "%s\t%s, %s, %s, %s #%u",
                         mnem, get_reg_zr(rd, sf), get_reg_zr(rn, sf),
                         get_reg_zr(rm, sf), shift_names[shift], imm6);
            }
            return 0;
        }
        
        /* Add/Sub shifted/extended register */
        if ((op21 & 0x9) == 0x8) {
            uint32_t is_sub = (opc >> 1) & 1;
            uint32_t sets_flags = opc & 1;
            uint32_t shift = (insn >> 22) & 3;
            uint32_t rm = (insn >> 16) & 0x1f;
            uint32_t imm6 = (insn >> 10) & 0x3f;
            uint32_t rn = (insn >> 5) & 0x1f;
            uint32_t rd = insn & 0x1f;
            
            const char *mnem;
            if (is_sub) {
                mnem = sets_flags ? "subs" : "sub";
                if (rd == 31 && sets_flags) mnem = "cmp";
                if (rn == 31 && !sets_flags) mnem = "neg";
            } else {
                mnem = sets_flags ? "adds" : "add";
                if (rd == 31 && sets_flags) mnem = "cmn";
            }
            
            if (strcmp(mnem, "cmp") == 0 || strcmp(mnem, "cmn") == 0) {
                snprintf(buf, bufsize, "%s\t%s, %s",
                         mnem, get_reg(rn, sf), get_reg(rm, sf));
            } else if (strcmp(mnem, "neg") == 0) {
                snprintf(buf, bufsize, "%s\t%s, %s",
                         mnem, get_reg(rd, sf), get_reg(rm, sf));
            } else if (imm6 == 0) {
                snprintf(buf, bufsize, "%s\t%s, %s, %s",
                         mnem, get_reg(rd, sf), get_reg(rn, sf), get_reg(rm, sf));
            } else {
                const char *shift_names[] = {"lsl", "lsr", "asr", "???"};
                snprintf(buf, bufsize, "%s\t%s, %s, %s, %s #%u",
                         mnem, get_reg(rd, sf), get_reg(rn, sf),
                         get_reg(rm, sf), shift_names[shift], imm6);
            }
            return 0;
        }
    }
    
    /* System instructions */
    if ((insn & 0xffc00000) == 0xd5000000) {
        uint32_t l = (insn >> 21) & 1;
        uint32_t op0_sys = (insn >> 19) & 3;
        uint32_t op1 = (insn >> 16) & 7;
        uint32_t crn = (insn >> 12) & 0xf;
        uint32_t crm = (insn >> 8) & 0xf;
        uint32_t op2 = (insn >> 5) & 7;
        uint32_t rt = insn & 0x1f;
        
        /* NOP, YIELD, WFE, WFI, SEV, SEVL */
        if (op0_sys == 0 && l == 0 && crn == 4 && rt == 31) {
            const char *hint_names[] = {
                "nop", "yield", "wfe", "wfi", "sev", "sevl", NULL
            };
            if (op2 < 6 && crm == 0) {
                snprintf(buf, bufsize, "%s", hint_names[op2]);
                return 0;
            }
        }
        
        /* MSR/MRS */
        if (op0_sys >= 2) {
            if (l) {
                snprintf(buf, bufsize, "mrs\t%s, S%u_%u_C%u_C%u_%u",
                         get_reg(rt, 1), op0_sys, op1, crn, crm, op2);
            } else {
                snprintf(buf, bufsize, "msr\tS%u_%u_C%u_C%u_%u, %s",
                         op0_sys, op1, crn, crm, op2, get_reg(rt, 1));
            }
            return 0;
        }
    }
    
    /* SVC (supervisor call) */
    if ((insn & 0xffe0001f) == 0xd4000001) {
        uint32_t imm16 = (insn >> 5) & 0xffff;
        snprintf(buf, bufsize, "svc\t#0x%x", imm16);
        return 0;
    }
    
    /* BRK (breakpoint) */
    if ((insn & 0xffe0001f) == 0xd4200000) {
        uint32_t imm16 = (insn >> 5) & 0xffff;
        snprintf(buf, bufsize, "brk\t#0x%x", imm16);
        return 0;
    }
    
    /* HLT */
    if ((insn & 0xffe0001f) == 0xd4400000) {
        uint32_t imm16 = (insn >> 5) & 0xffff;
        snprintf(buf, bufsize, "hlt\t#0x%x", imm16);
        return 0;
    }
    
    /* Unknown instruction */
    snprintf(buf, bufsize, ".inst\t0x%08x", insn);
    return -1;
}

/* ============================================================================
 * File Format Parsing
 * ============================================================================ */

static void usage(void)
{
    fprintf(stderr, "Usage: %s [OPTIONS] FILE...\n", progname);
    fprintf(stderr, "Display information from object files.\n\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -d    disassemble executable sections\n");
    fprintf(stderr, "  -D    disassemble all sections\n");
    fprintf(stderr, "  -f    display file headers\n");
    fprintf(stderr, "  -h    display section headers\n");
    fprintf(stderr, "  -t    display symbol table\n");
    fprintf(stderr, "  -x    display all headers\n");
    fprintf(stderr, "  --help display this help and exit\n");
}

/* Find symbol by address */
static const char *find_symbol(struct nlist_64 *syms, uint32_t nsyms,
                               const char *strtab, uint64_t addr)
{
    for (uint32_t i = 0; i < nsyms; i++) {
        if (syms[i].n_value == addr && syms[i].n_strx > 0) {
            return strtab + syms[i].n_strx;
        }
    }
    return NULL;
}

static int process_macho(const char *path, unsigned char *data, size_t size,
                         int show_header, int show_sections, int show_symbols,
                         int disasm, int disasm_all)
{
    struct mach_header_64 *mh = (struct mach_header_64 *)data;
    
    /* Verify it's a 64-bit Mach-O */
    if (mh->magic != MH_MAGIC_64) {
        fprintf(stderr, "%s: not a 64-bit Mach-O file\n", path);
        return 1;
    }
    
    if (show_header) {
        printf("\n%s:\tfile format mach-o-arm64\n", path);
        printf("architecture: arm64\n");
        
        const char *filetype_name;
        switch (mh->filetype) {
        case MH_EXECUTE:   filetype_name = "EXECUTE"; break;
        case MH_DYLIB:     filetype_name = "DYLIB"; break;
        case MH_DYLINKER:  filetype_name = "DYLINKER"; break;
        default:           filetype_name = "UNKNOWN"; break;
        }
        printf("filetype: %s (%u)\n", filetype_name, mh->filetype);
        printf("ncmds: %u\n", mh->ncmds);
        printf("sizeofcmds: %u\n", mh->sizeofcmds);
        printf("flags: 0x%08x\n", mh->flags);
    }
    
    /* Find sections and symbol table */
    struct section_64 *text_sect = NULL;
    struct symtab_command *symtab_cmd = NULL;
    
    unsigned char *cmd_ptr = data + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        struct load_command *lc = (struct load_command *)cmd_ptr;
        
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)cmd_ptr;
            
            if (show_sections) {
                if (i == 0) printf("\nSections:\n");
                printf("  %s:\n", seg->segname);
            }
            
            struct section_64 *sects = (struct section_64 *)(cmd_ptr + sizeof(struct segment_command_64));
            for (uint32_t j = 0; j < seg->nsects; j++) {
                if (show_sections) {
                    printf("    %-16s addr=0x%llx size=0x%llx offset=0x%x\n",
                           sects[j].sectname,
                           (unsigned long long)sects[j].addr,
                           (unsigned long long)sects[j].size,
                           sects[j].offset);
                }
                
                /* Find __TEXT,__text section */
                if (strncmp(sects[j].segname, "__TEXT", 16) == 0 &&
                    strncmp(sects[j].sectname, "__text", 16) == 0) {
                    text_sect = &sects[j];
                }
            }
        }
        
        if (lc->cmd == LC_SYMTAB) {
            symtab_cmd = (struct symtab_command *)cmd_ptr;
        }
        
        cmd_ptr += lc->cmdsize;
    }
    
    /* Display symbols */
    if (show_symbols && symtab_cmd) {
        printf("\nSYMBOL TABLE:\n");
        
        struct nlist_64 *syms = (struct nlist_64 *)(data + symtab_cmd->symoff);
        const char *strtab = (const char *)(data + symtab_cmd->stroff);
        
        for (uint32_t i = 0; i < symtab_cmd->nsyms; i++) {
            const char *name = "";
            if (syms[i].n_strx < symtab_cmd->strsize)
                name = strtab + syms[i].n_strx;
            
            char type = '?';
            if ((syms[i].n_type & 0xe) == 0xe) type = 'T';  /* External defined */
            else if ((syms[i].n_type & 0xe) == 0) type = 'U'; /* Undefined */
            else if (syms[i].n_sect) type = 't';  /* Local defined */
            
            printf("%016llx %c %s\n",
                   (unsigned long long)syms[i].n_value, type, name);
        }
    }
    
    /* Disassemble */
    if (disasm && text_sect) {
        printf("\nDisassembly of section __TEXT,__text:\n\n");
        
        /* Get symbol table for address lookup */
        struct nlist_64 *syms = NULL;
        const char *strtab = NULL;
        uint32_t nsyms = 0;
        if (symtab_cmd) {
            syms = (struct nlist_64 *)(data + symtab_cmd->symoff);
            strtab = (const char *)(data + symtab_cmd->stroff);
            nsyms = symtab_cmd->nsyms;
        }
        
        uint32_t *code = (uint32_t *)(data + text_sect->offset);
        size_t ninst = text_sect->size / 4;
        uint64_t addr = text_sect->addr;
        
        for (size_t i = 0; i < ninst; i++) {
            /* Check for symbol at this address */
            const char *sym = find_symbol(syms, nsyms, strtab, addr);
            if (sym && sym[0]) {
                printf("\n%016llx <%s>:\n",
                       (unsigned long long)addr, sym);
            }
            
            char disasm_buf[128];
            disasm_arm64(code[i], addr, disasm_buf, sizeof(disasm_buf));
            
            printf("%8llx:\t%08x \t%s\n",
                   (unsigned long long)addr, code[i], disasm_buf);
            
            addr += 4;
        }
    }
    
    return 0;
}

int main(int argc, char *argv[])
{
    int show_header = 0;
    int show_sections = 0;
    int show_symbols = 0;
    int disasm = 0;
    int disasm_all = 0;
    int i;
    
    /* Parse options */
    for (i = 1; i < argc && argv[i][0] == '-'; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            usage();
            return 0;
        }
        if (strcmp(argv[i], "--") == 0) {
            i++;
            break;
        }
        for (const char *p = argv[i] + 1; *p; p++) {
            switch (*p) {
            case 'd': disasm = 1; break;
            case 'D': disasm = 1; disasm_all = 1; break;
            case 'f': show_header = 1; break;
            case 'h': show_sections = 1; break;
            case 't': show_symbols = 1; break;
            case 'x':
                show_header = 1;
                show_sections = 1;
                show_symbols = 1;
                break;
            default:
                fprintf(stderr, "%s: invalid option -- '%c'\n", progname, *p);
                usage();
                return 1;
            }
        }
    }
    
    /* Default to showing headers if no options */
    if (!show_header && !show_sections && !show_symbols && !disasm) {
        show_header = 1;
    }
    
    if (i >= argc) {
        fprintf(stderr, "%s: no input files\n", progname);
        return 1;
    }
    
    int ret = 0;
    for (; i < argc; i++) {
        const char *path = argv[i];
        
        /* Open file */
        int fd = open(path, O_RDONLY);
        if (fd < 0) {
            fprintf(stderr, "%s: '%s': %s\n", progname, path, strerror(errno));
            ret = 1;
            continue;
        }
        
        /* Get file size */
        struct stat st;
        if (fstat(fd, &st) < 0) {
            fprintf(stderr, "%s: '%s': %s\n", progname, path, strerror(errno));
            close(fd);
            ret = 1;
            continue;
        }
        
        /* Read file */
        unsigned char *data = malloc(st.st_size);
        if (!data) {
            fprintf(stderr, "%s: out of memory\n", progname);
            close(fd);
            ret = 1;
            continue;
        }
        
        if (read(fd, data, st.st_size) != st.st_size) {
            fprintf(stderr, "%s: '%s': read error\n", progname, path);
            free(data);
            close(fd);
            ret = 1;
            continue;
        }
        close(fd);
        
        /* Check magic */
        if (st.st_size >= 4) {
            uint32_t magic = *(uint32_t *)data;
            if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
                if (process_macho(path, data, st.st_size,
                                  show_header, show_sections, show_symbols,
                                  disasm, disasm_all) != 0) {
                    ret = 1;
                }
            } else {
                fprintf(stderr, "%s: '%s': file format not recognized\n",
                        progname, path);
                ret = 1;
            }
        } else {
            fprintf(stderr, "%s: '%s': file too small\n", progname, path);
            ret = 1;
        }
        
        free(data);
    }
    
    return ret;
}
