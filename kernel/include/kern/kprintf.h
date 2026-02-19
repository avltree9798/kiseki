/*
 * Kiseki OS - Kernel printf
 *
 * Early console output for debugging. Uses UART as backend.
 */

#ifndef _KERN_KPRINTF_H
#define _KERN_KPRINTF_H

#include <kiseki/types.h>

/*
 * kprintf - Kernel printf (subset of printf)
 *
 * Supported format specifiers:
 *   %d, %i  - signed decimal
 *   %u      - unsigned decimal
 *   %x, %X  - hexadecimal (lower/upper)
 *   %p      - pointer (hex with 0x prefix)
 *   %s      - string
 *   %c      - character
 *   %ld     - long signed decimal
 *   %lu     - long unsigned decimal
 *   %lx     - long hex
 *   %%      - literal %
 */
void kprintf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/*
 * kputs - Print string without formatting
 */
void kputs(const char *s);

/*
 * kputc - Print single character
 */
void kputc(char c);

/*
 * panic - Print message and halt the system
 */
void panic(const char *fmt, ...) __noreturn __attribute__((format(printf, 1, 2)));

#endif /* _KERN_KPRINTF_H */
