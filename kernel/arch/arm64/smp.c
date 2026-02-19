/*
 * Kiseki OS - SMP (Symmetric Multi-Processing)
 *
 * Secondary core bringup using PSCI (Power State Coordination Interface).
 * Brings up secondary cores via PSCI CPU_ON; each core enters
 * secondary_entry in vectors.S, initializes GIC, and enters the scheduler.
 */

#include <kiseki/types.h>
#include <kiseki/platform.h>
#include <kern/kprintf.h>

/* PSCI function IDs (SMCCC convention) */
#define PSCI_CPU_ON_64      0xC4000003

/*
 * psci_cpu_on - Start a secondary CPU core
 *
 * @target_cpu:  MPIDR affinity value of the target core
 * @entry_point: Physical address where the core should begin execution
 * @context_id:  Value passed in x0 to the entry point
 *
 * Returns 0 on success, negative PSCI error code on failure.
 */
static int64_t psci_cpu_on(uint64_t target_cpu, uint64_t entry_point,
                           uint64_t context_id)
{
    int64_t result;

    __asm__ volatile(
        "mov x0, %1\n"     /* Function ID */
        "mov x1, %2\n"     /* target_cpu */
        "mov x2, %3\n"     /* entry_point */
        "mov x3, %4\n"     /* context_id */
        "hvc #0\n"         /* Hypervisor call (QEMU uses HVC for PSCI) */
        "mov %0, x0\n"     /* Return value */
        : "=r"(result)
        : "r"((uint64_t)PSCI_CPU_ON_64),
          "r"(target_cpu),
          "r"(entry_point),
          "r"(context_id)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
          "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
          "x16", "x17", "memory"
    );

    return result;
}

/* External symbol from boot.S */
extern void _secondary_entry(void);

/*
 * smp_init - Bring up secondary CPU cores
 *
 * Called from kmain() on core 0 after basic initialization.
 */
void smp_init(void)
{
    kprintf("[smp] Bringing up secondary cores...\n");

    for (uint32_t core = 1; core < MAX_CPUS; core++) {
        int64_t ret = psci_cpu_on(core, (uint64_t)_secondary_entry, 0);
        if (ret == 0) {
            kprintf("[smp] Core %u: started\n", core);
        } else {
            kprintf("[smp] Core %u: PSCI CPU_ON failed (err=%ld)\n",
                    core, ret);
        }
    }
}
