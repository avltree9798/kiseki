/*
 * Kiseki OS - GICv2 Driver
 *
 * ARM Generic Interrupt Controller v2 driver.
 * Used on both QEMU virt (GICv2) and Raspberry Pi 4 (GIC-400).
 *
 * Reference: ARM GIC Architecture Specification v2.0
 */

#include <kiseki/types.h>
#include <kiseki/platform.h>
#include <drivers/gic.h>
#include <kern/kprintf.h>

/* ============================================================================
 * GIC Distributor (GICD) Register Offsets
 * ============================================================================ */
#define GICD_CTLR           0x000   /* Distributor Control Register */
#define GICD_TYPER          0x004   /* Interrupt Controller Type Register */
#define GICD_ISENABLER(n)   (0x100 + (n) * 4)  /* Interrupt Set-Enable */
#define GICD_ICENABLER(n)   (0x180 + (n) * 4)  /* Interrupt Clear-Enable */
#define GICD_ISPENDR(n)     (0x200 + (n) * 4)  /* Interrupt Set-Pending */
#define GICD_ICPENDR(n)     (0x280 + (n) * 4)  /* Interrupt Clear-Pending */
#define GICD_IPRIORITYR(n)  (0x400 + (n) * 4)  /* Interrupt Priority */
#define GICD_ITARGETSR(n)   (0x800 + (n) * 4)  /* Interrupt Processor Targets */
#define GICD_ICFGR(n)       (0xC00 + (n) * 4)  /* Interrupt Configuration */
#define GICD_SGIR           0xF00   /* Software Generated Interrupt Register */

/* ============================================================================
 * GIC CPU Interface (GICC) Register Offsets
 * ============================================================================ */
#define GICC_CTLR           0x000   /* CPU Interface Control Register */
#define GICC_PMR            0x004   /* Interrupt Priority Mask Register */
#define GICC_IAR            0x00C   /* Interrupt Acknowledge Register */
#define GICC_EOIR           0x010   /* End of Interrupt Register */

/* GICD_CTLR bits */
#define GICD_CTLR_ENABLE    (1 << 0)

/* GICC_CTLR bits */
#define GICC_CTLR_ENABLE    (1 << 0)

/* MMIO helpers */
static inline void mmio_write32(uint64_t addr, uint32_t val)
{
    *(volatile uint32_t *)addr = val;
}

static inline uint32_t mmio_read32(uint64_t addr)
{
    return *(volatile uint32_t *)addr;
}

/* Number of supported IRQ lines (read from GICD_TYPER) */
static uint32_t max_irqs;

void gic_init(void)
{
    /* Disable distributor while configuring */
    mmio_write32(GICD_BASE + GICD_CTLR, 0);

    /* Read number of supported interrupts */
    uint32_t typer = mmio_read32(GICD_BASE + GICD_TYPER);
    max_irqs = ((typer & 0x1F) + 1) * 32;
    if (max_irqs > GIC_MAX_IRQ)
        max_irqs = GIC_MAX_IRQ;

    kprintf("[gic] GICv2: %u IRQ lines\n", max_irqs);

    /* Disable all interrupts */
    for (uint32_t i = 0; i < max_irqs / 32; i++)
        mmio_write32(GICD_BASE + GICD_ICENABLER(i), 0xFFFFFFFF);

    /* Clear all pending interrupts */
    for (uint32_t i = 0; i < max_irqs / 32; i++)
        mmio_write32(GICD_BASE + GICD_ICPENDR(i), 0xFFFFFFFF);

    /* Set all SPI priorities to default (0xA0) */
    for (uint32_t i = GIC_SPI_START / 4; i < max_irqs / 4; i++)
        mmio_write32(GICD_BASE + GICD_IPRIORITYR(i), 0xA0A0A0A0);

    /* Route all SPIs to core 0 by default */
    for (uint32_t i = GIC_SPI_START / 4; i < max_irqs / 4; i++)
        mmio_write32(GICD_BASE + GICD_ITARGETSR(i), 0x01010101);

    /* Set all SPIs as level-triggered */
    for (uint32_t i = GIC_SPI_START / 16; i < max_irqs / 16; i++)
        mmio_write32(GICD_BASE + GICD_ICFGR(i), 0);

    /* Enable distributor */
    mmio_write32(GICD_BASE + GICD_CTLR, GICD_CTLR_ENABLE);
}

void gic_init_percpu(void)
{
    /* Set priority mask to accept all priorities */
    mmio_write32(GICC_BASE + GICC_PMR, 0xFF);

    /* Enable CPU interface */
    mmio_write32(GICC_BASE + GICC_CTLR, GICC_CTLR_ENABLE);
}

void gic_enable_irq(uint32_t irq)
{
    if (irq >= max_irqs) return;
    uint32_t reg = irq / 32;
    uint32_t bit = irq % 32;
    mmio_write32(GICD_BASE + GICD_ISENABLER(reg), (1 << bit));
}

void gic_disable_irq(uint32_t irq)
{
    if (irq >= max_irqs) return;
    uint32_t reg = irq / 32;
    uint32_t bit = irq % 32;
    mmio_write32(GICD_BASE + GICD_ICENABLER(reg), (1 << bit));
}

uint32_t gic_acknowledge(void)
{
    return mmio_read32(GICC_BASE + GICC_IAR) & 0x3FF;
}

void gic_end_of_interrupt(uint32_t irq)
{
    mmio_write32(GICC_BASE + GICC_EOIR, irq);
}

void gic_send_sgi(uint32_t sgi_id, uint32_t target_cpu)
{
    /*
     * GICD_SGIR format:
     *   [25:24] TargetListFilter: 0b00 = use target list
     *   [23:16] CPUTargetList: bitmask of target CPUs
     *   [3:0]   INTID: SGI interrupt number
     */
    uint32_t val = (target_cpu << 16) | (sgi_id & 0xF);
    mmio_write32(GICD_BASE + GICD_SGIR, val);
}

void gic_set_priority(uint32_t irq, uint8_t priority)
{
    if (irq >= max_irqs) return;
    uint32_t reg = irq / 4;
    uint32_t offset = (irq % 4) * 8;
    uint32_t val = mmio_read32(GICD_BASE + GICD_IPRIORITYR(reg));
    val &= ~(0xFF << offset);
    val |= ((uint32_t)priority << offset);
    mmio_write32(GICD_BASE + GICD_IPRIORITYR(reg), val);
}
