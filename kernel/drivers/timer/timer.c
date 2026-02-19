/*
 * Kiseki OS - ARM Generic Timer Driver
 *
 * Uses the EL1 Virtual Timer (CNTV) for scheduler ticks.
 * Each CPU core has its own independent timer.
 *
 * Timer PPI: IRQ 27 (CNTV_EL0 virtual timer)
 *
 * Registers:
 *   CNTFRQ_EL0  - Counter frequency (read-only, set by firmware)
 *   CNTVCT_EL0  - Virtual count (monotonic counter)
 *   CNTV_TVAL_EL0 - Timer value (countdown, fires when reaches 0)
 *   CNTV_CTL_EL0  - Timer control (enable, mask, status)
 */

#include <kiseki/types.h>
#include <kiseki/platform.h>
#include <kern/kprintf.h>
#include <drivers/timer.h>
#include <drivers/gic.h>
#include <kern/thread.h>

/* CNTV_CTL_EL0 bits */
#define CTL_ENABLE      (1 << 0)    /* Timer enable */
#define CTL_IMASK       (1 << 1)    /* Interrupt mask (1 = masked) */
#define CTL_ISTATUS     (1 << 2)    /* Interrupt status (read-only) */

/* Per-CPU timer state */
static uint64_t timer_interval;     /* Counter ticks per scheduler tick */
static volatile uint64_t tick_count; /* Global tick counter */

/* --- ARM system register accessors --- */

static inline uint64_t read_cntfrq(void)
{
    uint64_t val;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(val));
    return val;
}

static inline uint64_t read_cntvct(void)
{
    uint64_t val;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(val));
    return val;
}

static inline void write_cntv_tval(uint64_t val)
{
    __asm__ volatile("msr cntv_tval_el0, %0" :: "r"(val));
}

static inline void write_cntv_ctl(uint64_t val)
{
    __asm__ volatile("msr cntv_ctl_el0, %0" :: "r"(val));
}

static inline uint64_t read_cntv_ctl(void)
{
    uint64_t val;
    __asm__ volatile("mrs %0, cntv_ctl_el0" : "=r"(val));
    return val;
}

/*
 * timer_init - Initialize the timer on the boot CPU
 *
 * @hz: Desired tick frequency (e.g., 100 = 10ms period)
 */
void timer_init(uint32_t hz)
{
    uint64_t freq = read_cntfrq();
    timer_interval = freq / hz;
    tick_count = 0;

    kprintf("[timer] Counter freq: %lu Hz, interval: %lu ticks (%u Hz)\n",
            freq, timer_interval, hz);

    /* Enable the virtual timer interrupt in GIC */
    gic_enable_irq(TIMER_IRQ);
    gic_set_priority(TIMER_IRQ, 0x80);  /* Medium priority */

    /* Set countdown and enable */
    write_cntv_tval(timer_interval);
    write_cntv_ctl(CTL_ENABLE);         /* Enable, unmask */

    kprintf("[timer] Timer armed (PPI %u)\n", TIMER_IRQ);
}

/*
 * timer_init_percpu - Set up timer on a secondary core
 */
void timer_init_percpu(void)
{
    gic_enable_irq(TIMER_IRQ);
    gic_set_priority(TIMER_IRQ, 0x80);
    write_cntv_tval(timer_interval);
    write_cntv_ctl(CTL_ENABLE);
}

/*
 * timer_handler - Called from IRQ dispatch when TIMER_IRQ fires
 *
 * Rearms the timer and calls the scheduler tick.
 */
void timer_handler(void)
{
    tick_count++;

    /* Rearm: set TVAL for next period */
    write_cntv_tval(timer_interval);

    /* Clear any pending status by re-enabling */
    write_cntv_ctl(CTL_ENABLE);

    /* Call scheduler tick */
    sched_tick();
}

uint64_t timer_get_ticks(void)
{
    return tick_count;
}

uint64_t timer_get_freq(void)
{
    return read_cntfrq();
}

void timer_delay_us(uint64_t us)
{
    uint64_t freq = read_cntfrq();
    uint64_t target = read_cntvct() + (freq * us / 1000000);
    while (read_cntvct() < target)
        __asm__ volatile("yield");
}
