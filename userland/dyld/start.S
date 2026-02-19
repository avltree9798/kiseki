/*
 * Kiseki OS - Dynamic Linker Entry Point (start.S)
 *
 * This is the first code that executes when the kernel jumps to dyld.
 * dyld is an MH_DYLINKER binary with LC_UNIXTHREAD, so the kernel sets
 * ELR_EL1 to _start and the stack is already set up.
 *
 * Stack layout on entry (set up by kernel/kern/proc.c):
 *
 *   sp -> [ mach_header_addr ]   <- pointer to main binary's mach_header_64
 *          [ argc             ]
 *          [ argv[0]          ]
 *          [ argv[1]          ]
 *          [ ...              ]
 *          [ NULL             ]   <- argv terminator
 *          [ envp[0]          ]
 *          [ envp[1]          ]
 *          [ ...              ]
 *          [ NULL             ]   <- envp terminator
 *          [ apple[0]         ]
 *          [ ...              ]
 *          [ NULL             ]   <- apple terminator
 *
 * We extract these values and call:
 *   dyld_main(mach_header, argc, argv, envp, apple)
 */

    .text
    .globl _start
    .p2align 2
_start:
    /*
     * x0 = mach_header pointer (of main binary)
     * Read from top of stack.
     */
    ldr     x0, [sp]

    /* x1 = argc, at sp+8 */
    ldr     x1, [sp, #8]

    /* x2 = argv, at sp+16 */
    add     x2, sp, #16

    /*
     * x3 = envp = argv + (argc + 1) * 8
     * Skip past all argv entries plus the NULL terminator.
     */
    add     x3, x1, #1
    lsl     x3, x3, #3
    add     x3, x2, x3

    /*
     * x4 = apple
     * Scan past envp entries to find the NULL terminator,
     * then the next pointer is the start of apple[].
     */
    mov     x4, x3
.Lscan_envp:
    ldr     x5, [x4], #8
    cbnz    x5, .Lscan_envp
    /* x4 now points to apple[0] (past the envp NULL terminator) */

    /*
     * Call dyld_main(mach_header, argc, argv, envp, apple)
     *   x0 = mach_header  (already set)
     *   x1 = argc         (already set)
     *   x2 = argv         (already set)
     *   x3 = envp         (already set)
     *   x4 = apple        (already set)
     */
    bl      _dyld_main

    /*
     * dyld_main should never return. If it does, exit with status 127
     * (conventional "command not found / could not exec" code).
     */
    mov     x0, #127
    mov     x16, #1         /* SYS_exit */
    svc     #0x80
    brk     #0xDEAD         /* Should never reach here */
