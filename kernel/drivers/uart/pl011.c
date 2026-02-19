/*
 * Kiseki OS - PL011 UART Driver
 *
 * ARM PrimeCell UART (PL011) driver for QEMU virt machine.
 * Used as the primary serial console during development.
 *
 * Reference: ARM PrimeCell UART (PL011) Technical Reference Manual
 */

#include <kiseki/types.h>
#include <kiseki/platform.h>
#include <drivers/uart.h>
#include <drivers/gic.h>

#ifdef PLATFORM_QEMU

/* PL011 Register Offsets */
#define UART_DR         0x000   /* Data Register */
#define UART_RSR        0x004   /* Receive Status Register */
#define UART_FR         0x018   /* Flag Register */
#define UART_IBRD       0x024   /* Integer Baud Rate Divisor */
#define UART_FBRD       0x028   /* Fractional Baud Rate Divisor */
#define UART_LCRH       0x02C   /* Line Control Register */
#define UART_CR         0x030   /* Control Register */
#define UART_IFLS       0x034   /* Interrupt FIFO Level Select */
#define UART_IMSC       0x038   /* Interrupt Mask Set/Clear */
#define UART_RIS        0x03C   /* Raw Interrupt Status */
#define UART_MIS        0x040   /* Masked Interrupt Status */
#define UART_ICR        0x044   /* Interrupt Clear Register */

/* Flag Register bits */
#define FR_TXFF         (1 << 5)    /* Transmit FIFO Full */
#define FR_RXFE         (1 << 4)    /* Receive FIFO Empty */
#define FR_BUSY         (1 << 3)    /* UART Busy */

/* Line Control bits */
#define LCRH_WLEN_8     (3 << 5)    /* 8-bit word length */
#define LCRH_FEN        (1 << 4)    /* FIFO Enable */

/* Control Register bits */
#define CR_UARTEN       (1 << 0)    /* UART Enable */
#define CR_TXE          (1 << 8)    /* Transmit Enable */
#define CR_RXE          (1 << 9)    /* Receive Enable */

/* Interrupt bits */
#define IMSC_RXIM       (1 << 4)    /* Receive interrupt mask */
#define IMSC_RTIM       (1 << 6)    /* Receive timeout interrupt mask */
#define ICR_ALL         0x7FF       /* All interrupt clear bits */

/* MMIO access helpers */
static inline void mmio_write32(uint64_t addr, uint32_t val)
{
    *(volatile uint32_t *)addr = val;
}

static inline uint32_t mmio_read32(uint64_t addr)
{
    return *(volatile uint32_t *)addr;
}

void uart_init(void)
{
    uint64_t base = UART0_BASE;

    /* Disable UART while configuring */
    mmio_write32(base + UART_CR, 0);

    /* Clear pending interrupts */
    mmio_write32(base + UART_ICR, 0x7FF);

    /*
     * Set baud rate to 115200 with 24MHz reference clock (QEMU default).
     * Divisor = 24000000 / (16 * 115200) = 13.0208...
     * IBRD = 13, FBRD = round(0.0208 * 64) = 1
     */
    mmio_write32(base + UART_IBRD, 13);
    mmio_write32(base + UART_FBRD, 1);

    /* 8 data bits, no parity, 1 stop bit, FIFO enabled */
    mmio_write32(base + UART_LCRH, LCRH_WLEN_8 | LCRH_FEN);

    /* NOTE: UART RX interrupts are NOT enabled here because GIC is not
     * initialized yet. Call uart_enable_irq() after gic_init(). */

    /* Enable UART, TX, and RX */
    mmio_write32(base + UART_CR, CR_UARTEN | CR_TXE | CR_RXE);
}

/*
 * uart_enable_irq - Enable UART RX interrupts.
 *
 * Must be called after gic_init() completes, since it registers
 * the UART IRQ with the GIC. Enables PL011 RX and RX timeout
 * interrupts so Ctrl+C works even when no process is reading stdin.
 */
void uart_enable_irq(void)
{
    uint64_t base = UART0_BASE;

    /* Set FIFO trigger level: RX interrupt at 1/8 full */
    mmio_write32(base + UART_IFLS, 0);

    /* Enable RX and RX timeout interrupts in PL011 */
    mmio_write32(base + UART_IMSC, IMSC_RXIM | IMSC_RTIM);

    /* Enable UART IRQ in GIC */
    gic_enable_irq(UART0_IRQ);
    gic_set_priority(UART0_IRQ, 0xA0);  /* Lower priority than timer */
}

void uart_putc(char c)
{
    uint64_t base = UART0_BASE;

    /* Wait until transmit FIFO is not full */
    while (mmio_read32(base + UART_FR) & FR_TXFF)
        ;

    mmio_write32(base + UART_DR, (uint32_t)c);
}

char uart_getc(void)
{
    uint64_t base = UART0_BASE;

    /* Wait until receive FIFO is not empty */
    while (mmio_read32(base + UART_FR) & FR_RXFE)
        ;

    return (char)(mmio_read32(base + UART_DR) & 0xFF);
}

void uart_puts(const char *s)
{
    while (*s) {
        if (*s == '\n')
            uart_putc('\r');
        uart_putc(*s++);
    }
}

bool uart_tx_ready(void)
{
    return !(mmio_read32(UART0_BASE + UART_FR) & FR_TXFF);
}

bool uart_rx_ready(void)
{
    return !(mmio_read32(UART0_BASE + UART_FR) & FR_RXFE);
}

/*
 * uart_irq_handler - Called from irq_dispatch when UART RX interrupt fires.
 *
 * Drains the UART receive FIFO and passes each character to tty_input_char().
 * This enables Ctrl+C to work even when no process is blocked in tty_read().
 */
void uart_irq_handler(void)
{
    uint64_t base = UART0_BASE;

    /* Clear RX and RT interrupt flags */
    mmio_write32(base + UART_ICR, IMSC_RXIM | IMSC_RTIM);

    /* Drain all available characters from the FIFO */
    while (!(mmio_read32(base + UART_FR) & FR_RXFE)) {
        char c = (char)(mmio_read32(base + UART_DR) & 0xFF);
        /* Pass to TTY layer for signal generation and buffering */
        extern void tty_input_char(char c);
        tty_input_char(c);
    }
}

#endif /* PLATFORM_QEMU */
