/*
 * Kiseki OS - Trap Frame Definition
 *
 * Saved register state pushed on the kernel stack during exceptions.
 * Used by both synchronous traps (syscalls, faults) and async (IRQ).
 *
 * This header is included from both C and assembly, so the constants
 * section must be pure #defines.
 */

#ifndef _MACHINE_TRAP_H
#define _MACHINE_TRAP_H

/* Offsets for assembly (must match struct layout) */
#define TF_X0       (0 * 8)
#define TF_X1       (1 * 8)
#define TF_X2       (2 * 8)
#define TF_X3       (3 * 8)
#define TF_X16      (16 * 8)
#define TF_X18      (18 * 8)
#define TF_X29      (29 * 8)
#define TF_X30      (30 * 8)
#define TF_SP       (31 * 8)
#define TF_ELR      (32 * 8)
#define TF_SPSR     (33 * 8)
#define TF_ESR      (34 * 8)
#define TF_FAR      (35 * 8)
#define TF_SIZE     (36 * 8)

/*
 * Exception class codes (ESR_EL1.EC field, bits [31:26])
 */
#define EC_UNKNOWN          0x00
#define EC_SVC_A64          0x15    /* SVC from AArch64 */
#define EC_IABT_LOWER       0x20    /* Instruction Abort from lower EL */
#define EC_IABT_SAME        0x21    /* Instruction Abort from same EL */
#define EC_PC_ALIGN         0x22    /* PC Alignment fault */
#define EC_DABT_LOWER       0x24    /* Data Abort from lower EL */
#define EC_DABT_SAME        0x25    /* Data Abort from same EL */
#define EC_SP_ALIGN         0x26    /* SP Alignment fault */
#define EC_BRK              0x3C    /* BRK instruction */

/* C-only definitions */
#ifndef __ASSEMBLER__

#include <kiseki/types.h>

/*
 * trap_frame - Saved CPU state during an exception
 *
 * Layout must match the save/restore order in vectors.S exactly.
 * Total size: 36 * 8 = 288 bytes.
 */
struct trap_frame {
    uint64_t regs[31];  /* x0-x30 */
    uint64_t sp;        /* saved SP (SP_EL0 for user traps, SP_ELx for kernel) */
    uint64_t elr;       /* Exception Link Register (return PC) */
    uint64_t spsr;      /* Saved Program Status Register */
    uint64_t esr;       /* Exception Syndrome Register */
    uint64_t far;       /* Fault Address Register */
};

/*
 * Exception handlers (implemented in trap.c)
 */
void trap_sync_el1(struct trap_frame *tf);
void trap_irq_el1(struct trap_frame *tf);
void trap_sync_el0(struct trap_frame *tf);
void trap_irq_el0(struct trap_frame *tf);

#endif /* !__ASSEMBLER__ */

#endif /* _MACHINE_TRAP_H */
