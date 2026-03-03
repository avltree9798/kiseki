/*
 * Kiseki OS - Kernel Printf Implementation
 *
 * Minimal printf for kernel debugging. Outputs via UART and,
 * when available, the framebuffer console.
 *
 * Like XNU's PE_kputc, print_char() fans out to all registered
 * console backends. The framebuffer mirror is enabled once
 * fbconsole_init() completes successfully (checked via
 * fbconsole_active()).
 *
 * IMPORTANT: kprintf output bypasses the TTY line discipline
 * entirely. It goes directly to the hardware (UART) and to
 * the framebuffer pixel renderer. This is intentional — kernel
 * messages must always be visible regardless of TTY state.
 *
 * Reference: XNU osfmk/console/serial_console.c (PE_kputc)
 *
 * No heap allocation, no floating point.
 */

#include <kiseki/types.h>
#include <kern/kprintf.h>
#include <kern/fbconsole.h>
#include <drivers/uart.h>

/* va_list using GCC builtins (freestanding, no libc needed) */
typedef __builtin_va_list   va_list;
#define va_start(ap, last)  __builtin_va_start(ap, last)
#define va_end(ap)          __builtin_va_end(ap)
#define va_arg(ap, type)    __builtin_va_arg(ap, type)

/*
 * SMP serialization: prevent interleaved output from multiple cores.
 * Uses a simple spinlock with IRQ save to ensure entire kprintf calls
 * are atomic. This is critical for readable debug output on SMP.
 */
#include <kern/sync.h>

static spinlock_t kprintf_lock = SPINLOCK_INIT;

/* --- Internal helpers --- */

static void print_char(char c)
{
    /* Primary output: serial console (UART) */
    if (c == '\n')
        uart_putc('\r');    /* UART convention: \n -> \r\n */
    uart_putc(c);

    /*
     * Secondary output: framebuffer console (when available).
     *
     * Like XNU's PE_kputc which calls both serial_putc and
     * vc_putchar, we mirror all kernel output to the framebuffer
     * so boot messages and panics are visible on the graphical
     * display.
     *
     * The VT100 parser in fbconsole treats \n as a pure line feed
     * (advance row only, no carriage return), matching standard
     * VT100/ANSI behaviour. kprintf output needs \r before \n to
     * return the cursor to column 0, just like we do for UART.
     */
    if (fbconsole_active()) {
        if (c == '\n')
            fbconsole_putc('\r');
        fbconsole_putc(c);
    }
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

/* --- UART-only output (bypasses fbconsole, safe under gpu_lock) --- */

static void uart_print_char(char c)
{
    if (c == '\n')
        uart_putc('\r');
    uart_putc(c);
}

static void uart_vprintf(const char *fmt, va_list ap)
{
    /* Minimal inline formatter — same logic as kvprintf but uses
     * uart_print_char instead of print_char to avoid fbconsole. */
    while (*fmt) {
        if (*fmt != '%') {
            uart_print_char(*fmt++);
            continue;
        }
        fmt++;
        char pad = ' ';
        int width = 0;
        int is_long = 0;
        if (*fmt == '0') { pad = '0'; fmt++; }
        while (*fmt >= '0' && *fmt <= '9') {
            width = width * 10 + (*fmt - '0');
            fmt++;
        }
        if (*fmt == '.') {
            fmt++;
            while (*fmt >= '0' && *fmt <= '9') fmt++;
        }
        if (*fmt == 'l') { is_long = 1; fmt++; }
        switch (*fmt) {
        case 'd': case 'i': {
            int64_t v = is_long ? va_arg(ap, int64_t) : va_arg(ap, int32_t);
            if (v < 0) { uart_print_char('-'); v = -v; }
            char buf[20]; int i = 0;
            if (v == 0) buf[i++] = '0';
            else while (v > 0) { buf[i++] = '0' + (v % 10); v /= 10; }
            while (i < width) buf[i++] = pad;
            while (--i >= 0) uart_print_char(buf[i]);
            break;
        }
        case 'u': {
            uint64_t v = is_long ? va_arg(ap, uint64_t) : va_arg(ap, uint32_t);
            char buf[20]; int i = 0;
            if (v == 0) buf[i++] = '0';
            else while (v > 0) { buf[i++] = '0' + (v % 10); v /= 10; }
            while (i < width) buf[i++] = pad;
            while (--i >= 0) uart_print_char(buf[i]);
            break;
        }
        case 'x': case 'X': {
            uint64_t v = is_long ? va_arg(ap, uint64_t) : va_arg(ap, uint32_t);
            const char *d = (*fmt == 'X') ? "0123456789ABCDEF" : "0123456789abcdef";
            char buf[16]; int i = 0;
            if (v == 0) buf[i++] = '0';
            else while (v > 0) { buf[i++] = d[v & 0xf]; v >>= 4; }
            while (i < width) buf[i++] = pad;
            while (--i >= 0) uart_print_char(buf[i]);
            break;
        }
        case 'p': {
            uint64_t v = va_arg(ap, uint64_t);
            uart_print_char('0'); uart_print_char('x');
            const char *d = "0123456789abcdef";
            for (int i = 60; i >= 0; i -= 4) uart_print_char(d[(v >> i) & 0xf]);
            break;
        }
        case 's': {
            const char *s = va_arg(ap, const char *);
            if (!s) s = "(null)";
            while (*s) uart_print_char(*s++);
            break;
        }
        case 'c': uart_print_char((char)va_arg(ap, int)); break;
        case '%': uart_print_char('%'); break;
        default: uart_print_char('%'); uart_print_char(*fmt); break;
        }
        fmt++;
    }
}

/* --- Public API --- */

void kprintf_lock_acquire(uint64_t *flags)
{
    spin_lock_irqsave(&kprintf_lock, flags);
}

void kprintf_lock_release(uint64_t flags)
{
    spin_unlock_irqrestore(&kprintf_lock, flags);
}

void kputc(char c)
{
    uint64_t flags;
    spin_lock_irqsave(&kprintf_lock, &flags);
    print_char(c);
    spin_unlock_irqrestore(&kprintf_lock, flags);
}

void kputs(const char *s)
{
    uint64_t flags;
    spin_lock_irqsave(&kprintf_lock, &flags);
    print_string(s);
    spin_unlock_irqrestore(&kprintf_lock, flags);
}

void kprintf(const char *fmt, ...)
{
    uint64_t flags;
    spin_lock_irqsave(&kprintf_lock, &flags);

    va_list ap;
    va_start(ap, fmt);
    kvprintf(fmt, ap);
    va_end(ap);

    spin_unlock_irqrestore(&kprintf_lock, flags);
}

void uart_printf(const char *fmt, ...)
{
    uint64_t flags;
    spin_lock_irqsave(&kprintf_lock, &flags);

    va_list ap;
    va_start(ap, fmt);
    uart_vprintf(fmt, ap);
    va_end(ap);

    spin_unlock_irqrestore(&kprintf_lock, flags);
}

void panic(const char *fmt, ...)
{
    /* Disable interrupts immediately — no lock needed during panic
     * (we might already be holding kprintf_lock, and other cores
     * will be halted shortly anyway). */
    __asm__ volatile("msr daifset, #0xF");

    va_list ap;
    va_start(ap, fmt);

    /* Direct output, bypassing lock to avoid deadlock */
    print_string("\n*** KERNEL PANIC ***\n");
    kvprintf(fmt, ap);
    print_string("\n*** System halted ***\n");

    va_end(ap);

    /* Halt all cores */
    for (;;) {
        __asm__ volatile("wfi");
    }
}
