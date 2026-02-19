/*
 * Kiseki OS - ARM Generic Timer Interface
 *
 * Uses the ARM Generic Timer (CNTV - Virtual Timer) to generate
 * periodic interrupts for the scheduler tick.
 *
 * The virtual timer is available at EL1 without hypervisor setup
 * and fires PPI #27 (IRQ 27) on each core.
 */

#ifndef _DRIVERS_TIMER_H
#define _DRIVERS_TIMER_H

#include <kiseki/types.h>

/* Timer PPI interrupt number */
#define TIMER_IRQ       27      /* Virtual timer PPI */

/*
 * timer_init - Initialize the ARM Generic Timer
 *
 * Sets up periodic tick at the specified frequency.
 * Must be called on each CPU core.
 *
 * @hz: Timer frequency in Hz (e.g., 100 for 10ms tick)
 */
void timer_init(uint32_t hz);

/*
 * timer_init_percpu - Per-CPU timer initialization
 *
 * Called on secondary cores after they come online.
 */
void timer_init_percpu(void);

/*
 * timer_handler - Timer interrupt handler
 *
 * Called from the IRQ dispatch path when the timer fires.
 * Rearms the timer and calls sched_tick().
 */
void timer_handler(void);

/*
 * timer_get_ticks - Get monotonic tick count
 *
 * Returns the number of timer ticks since boot (per-CPU).
 */
uint64_t timer_get_ticks(void);

/*
 * timer_get_freq - Get the timer counter frequency
 *
 * Returns the CNTFRQ_EL0 value in Hz.
 */
uint64_t timer_get_freq(void);

/*
 * timer_delay_us - Busy-wait delay in microseconds
 */
void timer_delay_us(uint64_t us);

#endif /* _DRIVERS_TIMER_H */
