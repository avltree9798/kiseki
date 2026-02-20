/*
 * Kiseki OS - dyld_stub_binder stub
 *
 * Required by ld64 as an initial-undefined symbol for all dylibs.
 * Kiseki's dyld does eager binding, so this is never actually called.
 */

.globl _dyld_stub_binder
.p2align 2
_dyld_stub_binder:
    brk #0xf
    ret
