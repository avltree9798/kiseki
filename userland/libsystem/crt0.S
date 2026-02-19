/*
 * Kiseki OS - C Runtime Startup (crt0)
 *
 * Entry point for all userland Mach-O executables.
 * The kernel places argc, argv, envp on the stack before jumping here:
 *
 * Stack layout on entry (XNU/dyld convention):
 *   sp+0:  argc (uint64_t)
 *   sp+8:  argv[0]
 *   sp+8+8*argc: NULL (argv terminator)
 *   sp+8+8*(argc+1): envp[0]
 *   ...
 *   NULL (envp terminator)
 *
 * We extract argc/argv/envp, set up environ, then call main().
 * On return from main, we call exit(retval).
 */

    .text
    .globl _start
    .type _start, %function
    .align 4
_start:
    /* Clear frame pointer for clean backtrace termination */
    mov     x29, #0
    mov     x30, #0

    /* Load argc from top of stack */
    ldr     x0, [sp]           /* x0 = argc */

    /* argv = sp + 8 */
    add     x1, sp, #8         /* x1 = argv */

    /* envp = argv + (argc + 1) * 8  (skip argv[] and its NULL terminator) */
    add     x2, x0, #1         /* argc + 1 */
    lsl     x2, x2, #3         /* (argc + 1) * 8 */
    add     x2, x1, x2         /* x2 = envp */

    /* Store envp in the global 'environ' variable */
    adrp    x3, environ
    add     x3, x3, :lo12:environ
    str     x2, [x3]

    /* Align stack to 16 bytes (ABI requirement) */
    mov     x3, sp
    and     x3, x3, #~0xF
    mov     sp, x3

    /* Call main(argc, argv, envp) */
    bl      main

    /* main() returned in x0; call exit(x0) */
    bl      exit

    /* Should never reach here, but just in case */
    mov     x16, #1             /* SYS_exit */
    mov     x0, #127
    svc     #0x80
    b       .                   /* Infinite loop as safety net */

    .size _start, . - _start
