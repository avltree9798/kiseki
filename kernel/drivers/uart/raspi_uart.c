/*
 * Kiseki OS - Raspberry Pi 4 UART Driver
 *
 * Uses the PL011 UART0 on BCM2711 (mapped at 0xFE201000).
 * The mini UART (UART1) is also available but less reliable.
 *
 * Note: GPIO pins must be configured for UART before use.
 * GPIO 14 = TXD0, GPIO 15 = RXD0 (ALT0 function).
 */

#include <kiseki/types.h>
#include <kiseki/platform.h>
#include <drivers/uart.h>

#ifdef PLATFORM_RASPI4

/* GPIO Register Offsets */
#define GPFSEL1         (GPIO_BASE + 0x04)
#define GPPUD           (GPIO_BASE + 0x94)  /* BCM2711 uses GPIO_PUP_PDN_CNTRL */
#define GPIO_PUP_PDN0   (GPIO_BASE + 0xE4)

/* PL011 Register Offsets (same as QEMU, different base) */
#define UART_DR         0x000
#define UART_FR         0x018
#define UART_IBRD       0x024
#define UART_FBRD       0x028
#define UART_LCRH       0x02C
#define UART_CR         0x030
#define UART_ICR        0x044

#define FR_TXFF         (1 << 5)
#define FR_RXFE         (1 << 4)
#define LCRH_WLEN_8     (3 << 5)
#define LCRH_FEN        (1 << 4)
#define CR_UARTEN       (1 << 0)
#define CR_TXE          (1 << 8)
#define CR_RXE          (1 << 9)

static inline void mmio_write32(uint64_t addr, uint32_t val)
{
    *(volatile uint32_t *)addr = val;
}

static inline uint32_t mmio_read32(uint64_t addr)
{
    return *(volatile uint32_t *)addr;
}

static void gpio_setup_uart(void)
{
    /*
     * Configure GPIO 14 and 15 for ALT0 (UART0 TXD/RXD).
     * GPFSEL1 controls GPIOs 10-19.
     * GPIO 14: bits [14:12] = ALT0 = 0b100
     * GPIO 15: bits [17:15] = ALT0 = 0b100
     */
    uint32_t sel = mmio_read32(GPFSEL1);
    sel &= ~((7 << 12) | (7 << 15));   /* Clear GPIO 14 and 15 */
    sel |= (4 << 12) | (4 << 15);      /* Set ALT0 */
    mmio_write32(GPFSEL1, sel);

    /* Disable pull-up/pull-down on GPIO 14 and 15 */
    /* BCM2711 uses different pull control than BCM2835 */
    uint32_t pup = mmio_read32(GPIO_PUP_PDN0);
    pup &= ~((3 << 28) | (3 << 30));   /* GPIO 14 and 15: no pull */
    mmio_write32(GPIO_PUP_PDN0, pup);
}

void uart_init(void)
{
    uint64_t base = UART0_BASE;

    /* Configure GPIO pins first */
    gpio_setup_uart();

    /* Disable UART */
    mmio_write32(base + UART_CR, 0);

    /* Clear interrupts */
    mmio_write32(base + UART_ICR, 0x7FF);

    /*
     * Baud rate 115200 with 48MHz clock (RPi4 default for PL011).
     * Divisor = 48000000 / (16 * 115200) = 26.0416...
     * IBRD = 26, FBRD = round(0.0416 * 64) = 3
     */
    mmio_write32(base + UART_IBRD, 26);
    mmio_write32(base + UART_FBRD, 3);

    /* 8N1, FIFO enabled */
    mmio_write32(base + UART_LCRH, LCRH_WLEN_8 | LCRH_FEN);

    /* Enable UART, TX, RX */
    mmio_write32(base + UART_CR, CR_UARTEN | CR_TXE | CR_RXE);
}

void uart_putc(char c)
{
    while (mmio_read32(UART0_BASE + UART_FR) & FR_TXFF)
        ;
    mmio_write32(UART0_BASE + UART_DR, (uint32_t)c);
}

char uart_getc(void)
{
    while (mmio_read32(UART0_BASE + UART_FR) & FR_RXFE)
        ;
    return (char)(mmio_read32(UART0_BASE + UART_DR) & 0xFF);
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

#endif /* PLATFORM_RASPI4 */
