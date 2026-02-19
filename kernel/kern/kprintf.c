/*
 * Kiseki OS - Kernel Printf Implementation
 *
 * Minimal printf for kernel debugging. Outputs via UART.
 * No heap allocation, no floating point.
 */

#include <kiseki/types.h>
#include <kern/kprintf.h>
#include <drivers/uart.h>

/* va_list using GCC builtins (freestanding, no libc needed) */
typedef __builtin_va_list   va_list;
#define va_start(ap, last)  __builtin_va_start(ap, last)
#define va_end(ap)          __builtin_va_end(ap)
#define va_arg(ap, type)    __builtin_va_arg(ap, type)

/* --- Internal helpers --- */

static void print_char(char c)
{
    if (c == '\n')
        uart_putc('\r');    /* UART convention: \n -> \r\n */
    uart_putc(c);
}

static void print_string(const char *s)
{
    if (!s)
        s = "(null)";
    while (*s)
        print_char(*s++);
}

static void print_string_n(const char *s, int maxlen)
{
    if (!s)
        s = "(null)";
    int i = 0;
    while (*s && i < maxlen) {
        print_char(*s++);
        i++;
    }
}

static void print_unsigned(uint64_t val, int base, int uppercase, int width, char pad)
{
    char buf[20];   /* max uint64 decimal is 20 digits */
    const char *digits = uppercase ? "0123456789ABCDEF" : "0123456789abcdef";
    int i = 0;

    if (val == 0) {
        buf[i++] = '0';
    } else {
        while (val > 0) {
            buf[i++] = digits[val % base];
            val /= base;
        }
    }

    /* Pad to minimum width */
    while (i < width)
        buf[i++] = pad;

    /* Print in reverse */
    while (--i >= 0)
        print_char(buf[i]);
}

static void print_signed(int64_t val, int width, char pad)
{
    if (val < 0) {
        print_char('-');
        val = -val;
        if (width > 0) width--;
    }
    print_unsigned((uint64_t)val, 10, 0, width, pad);
}

/* --- Core formatter (shared by kprintf and panic) --- */

static void kvprintf(const char *fmt, va_list ap)
{
    while (*fmt) {
        if (*fmt != '%') {
            print_char(*fmt++);
            continue;
        }
        fmt++;  /* skip '%' */

        /* Parse width and padding */
        char pad = ' ';
        int width = 0;
        int precision = -1;  /* -1 = not specified */

        if (*fmt == '0') {
            pad = '0';
            fmt++;
        }
        while (*fmt >= '0' && *fmt <= '9') {
            width = width * 10 + (*fmt - '0');
            fmt++;
        }

        /* Parse precision (.N) */
        if (*fmt == '.') {
            fmt++;
            precision = 0;
            while (*fmt >= '0' && *fmt <= '9') {
                precision = precision * 10 + (*fmt - '0');
                fmt++;
            }
        }

        /* Parse length modifier */
        int is_long = 0;
        if (*fmt == 'l') {
            is_long = 1;
            fmt++;
        }

        /* Parse conversion specifier */
        switch (*fmt) {
        case 'd':
        case 'i':
            if (is_long)
                print_signed(va_arg(ap, int64_t), width, pad);
            else
                print_signed(va_arg(ap, int32_t), width, pad);
            break;

        case 'u':
            if (is_long)
                print_unsigned(va_arg(ap, uint64_t), 10, 0, width, pad);
            else
                print_unsigned(va_arg(ap, uint32_t), 10, 0, width, pad);
            break;

        case 'x':
            if (is_long)
                print_unsigned(va_arg(ap, uint64_t), 16, 0, width, pad);
            else
                print_unsigned(va_arg(ap, uint32_t), 16, 0, width, pad);
            break;

        case 'X':
            if (is_long)
                print_unsigned(va_arg(ap, uint64_t), 16, 1, width, pad);
            else
                print_unsigned(va_arg(ap, uint32_t), 16, 1, width, pad);
            break;

        case 'p':
            print_string("0x");
            print_unsigned(va_arg(ap, uint64_t), 16, 0, 16, '0');
            break;

        case 's':
            if (precision >= 0)
                print_string_n(va_arg(ap, const char *), precision);
            else
                print_string(va_arg(ap, const char *));
            break;

        case 'c':
            print_char((char)va_arg(ap, int));
            break;

        case '%':
            print_char('%');
            break;

        default:
            print_char('%');
            print_char(*fmt);
            break;
        }
        fmt++;
    }
}

/* --- Public API --- */

void kputc(char c)
{
    print_char(c);
}

void kputs(const char *s)
{
    print_string(s);
}

void kprintf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    kvprintf(fmt, ap);
    va_end(ap);
}

void panic(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    kprintf("\n*** KERNEL PANIC ***\n");
    kvprintf(fmt, ap);
    kprintf("\n*** System halted ***\n");

    va_end(ap);

    /* Disable interrupts and halt all cores */
    __asm__ volatile("msr daifset, #0xF");  /* Mask all interrupts */
    for (;;) {
        __asm__ volatile("wfi");
    }
}
