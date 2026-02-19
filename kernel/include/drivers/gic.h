/*
 * Kiseki OS - Generic Interrupt Controller (GIC) Interface
 *
 * Supports GICv2 (QEMU virt, RPi4 GIC-400).
 */

#ifndef _DRIVERS_GIC_H
#define _DRIVERS_GIC_H

#include <kiseki/types.h>

/* Interrupt types */
#define GIC_SGI_MAX         16      /* Software Generated Interrupts: 0-15 */
#define GIC_PPI_START       16      /* Private Peripheral Interrupts: 16-31 */
#define GIC_SPI_START       32      /* Shared Peripheral Interrupts: 32+ */
#define GIC_MAX_IRQ         1020

/* IPI definitions */
#define IPI_RESCHEDULE      0
#define IPI_TLB_FLUSH       1
#define IPI_HALT            2

/*
 * gic_init - Initialize the GIC distributor and CPU interface
 */
void gic_init(void);

/*
 * gic_init_percpu - Per-CPU GIC initialization (called by each core)
 */
void gic_init_percpu(void);

/*
 * gic_enable_irq - Enable a specific interrupt
 */
void gic_enable_irq(uint32_t irq);

/*
 * gic_disable_irq - Disable a specific interrupt
 */
void gic_disable_irq(uint32_t irq);

/*
 * gic_acknowledge - Read and acknowledge the highest-priority pending interrupt
 *
 * Returns the interrupt ID (or 1023 if spurious).
 */
uint32_t gic_acknowledge(void);

/*
 * gic_end_of_interrupt - Signal end of interrupt processing
 */
void gic_end_of_interrupt(uint32_t irq);

/*
 * gic_send_sgi - Send a Software Generated Interrupt (IPI)
 *
 * @sgi_id:     SGI number (0-15)
 * @target_cpu: Target CPU bitmask (bit N = core N)
 */
void gic_send_sgi(uint32_t sgi_id, uint32_t target_cpu);

/*
 * gic_set_priority - Set interrupt priority
 *
 * @irq:      Interrupt number
 * @priority: Priority value (0 = highest, 255 = lowest)
 */
void gic_set_priority(uint32_t irq, uint8_t priority);

#endif /* _DRIVERS_GIC_H */
