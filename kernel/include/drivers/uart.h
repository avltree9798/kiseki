/*
 * Kiseki OS - UART Driver Interface
 *
 * Platform-agnostic UART interface. Backend selected at compile time.
 */

#ifndef _DRIVERS_UART_H
#define _DRIVERS_UART_H

#include <kiseki/types.h>

/*
 * uart_init - Initialize the UART hardware
 *
 * Must be called before any other UART functions.
 * Configures baud rate, data bits, stop bits, etc.
 */
void uart_init(void);

/*
 * uart_putc - Send a single character
 *
 * Blocks until the transmit FIFO has space.
 */
void uart_putc(char c);

/*
 * uart_getc - Receive a single character
 *
 * Blocks until a character is available in the receive FIFO.
 */
char uart_getc(void);

/*
 * uart_puts - Send a null-terminated string
 */
void uart_puts(const char *s);

/*
 * uart_tx_ready - Check if transmitter is ready
 *
 * Returns true if the UART can accept a character for transmission.
 */
bool uart_tx_ready(void);

/*
 * uart_rx_ready - Check if receiver has data
 *
 * Returns true if there is a character available to read.
 */
bool uart_rx_ready(void);

/*
 * uart_enable_irq - Enable UART RX interrupts
 *
 * Must be called after gic_init(). Enables PL011 RX interrupts
 * so that Ctrl+C works even when no process is blocked in read().
 */
void uart_enable_irq(void);

/*
 * uart_irq_handler - Handle UART receive interrupt
 *
 * Called from irq_dispatch when the UART fires an RX interrupt.
 * Drains the FIFO and passes characters to tty_input_char().
 */
void uart_irq_handler(void);

#endif /* _DRIVERS_UART_H */
