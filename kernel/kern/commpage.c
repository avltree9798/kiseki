/*
 * Kiseki OS - Darwin CommPage Implementation
 *
 * The CommPage is a single read-only page mapped at a fixed virtual address
 * (COMMPAGE_VA = 0x0000000FFFFFC000) in every user process's address space.
 * It provides fast, kernel-maintained data that user-space code can read
 * without a syscall, such as:
 *
 *   - System time (read from CNTVCT_EL0)
 *   - CPU count
 *   - Page size
 *   - CPU capabilities / feature flags
 *
 * On real macOS/Darwin, the CommPage also contains optimised routines
 * (memcpy, bzero, pthread_self) that libSystem calls into. We provide
 * stubs and basic data fields.
 *
 * The CommPage physical page is allocated once at boot and shared
 * (read-only) across all user address spaces. A kernel function
 * updates time-sensitive fields periodically.
 *
 * Layout matches Apple's CommPage structure offsets where practical.
 *
 * Reference: XNU osfmk/arm64/commpage/commpage.c
 */

#include <kiseki/types.h>
#include <kiseki/platform.h>
#include <kern/vmm.h>
#include <kern/pmm.h>
#include <kern/kprintf.h>

/* ============================================================================
 * CommPage Layout Constants
 *
 * These are byte offsets from the start of the CommPage.
 * Apple's official offsets are used where known; others are
 * Kiseki-specific.
 * ============================================================================ */

/* Signature / magic (for validation) */
#define COMMPAGE_SIGNATURE_OFFSET       0x000   /* uint64_t */

/* System info */
#define COMMPAGE_VERSION_OFFSET         0x008   /* uint32_t: CommPage version */
#define COMMPAGE_CPU_COUNT_OFFSET       0x00C   /* uint32_t: Number of CPUs */
#define COMMPAGE_PAGE_SIZE_OFFSET       0x010   /* uint32_t: VM page size */
#define COMMPAGE_CACHE_LINE_OFFSET      0x014   /* uint32_t: Cache line size */

/* CPU capabilities (Apple-compatible bit positions) */
#define COMMPAGE_CPU_CAPS_OFFSET        0x020   /* uint64_t: CPU capability flags */

/* Time info (updated by kernel on timer tick or lazily) */
#define COMMPAGE_TIMEBASE_OFFSET        0x040   /* uint64_t: CNTFRQ_EL0 (counter frequency) */
#define COMMPAGE_TIMESTAMP_OFFSET       0x048   /* uint64_t: Last CNTVCT snapshot */
#define COMMPAGE_UNIXTIME_OFFSET        0x050   /* uint64_t: Seconds since epoch */
#define COMMPAGE_UNIXTIME_USEC_OFFSET   0x058   /* uint64_t: Microseconds part */

/* Boot time */
#define COMMPAGE_BOOTTIME_SEC_OFFSET    0x060   /* uint64_t */
#define COMMPAGE_BOOTTIME_USEC_OFFSET   0x068   /* uint64_t */

/* Kernel version string (null-terminated, max 64 bytes) */
#define COMMPAGE_KERN_VERSION_OFFSET    0x100   /* char[64] */

/* Stub routines (tiny ARM64 code sequences) */
#define COMMPAGE_STUB_GETTIMEOFDAY      0x200   /* gettimeofday stub */
#define COMMPAGE_STUB_NANOTIME          0x240   /* mach_absolute_time stub */
#define COMMPAGE_STUB_SIGRETURN         0x280   /* signal return trampoline */

/*
 * Boot epoch: Feb 19, 2026 00:00:00 UTC
 * Calculated as seconds since Unix epoch (Jan 1, 1970).
 * This gives us a reasonable wall-clock starting point.
 * 56 years (1970-2026) + leap year adjustments.
 */
#define BOOT_EPOCH_SECS     1771372800ULL

/* Counter value at boot — set during commpage_init */
static uint64_t boot_cntvct = 0;
static uint64_t boot_cntfrq = 0;

/* Total CommPage size = 1 page */
#define COMMPAGE_SIZE                   PAGE_SIZE

/* Signature magic value */
#define COMMPAGE_MAGIC                  0x4B49534B434F4D50UL  /* "KISKCOMP" */

/* CommPage version */
#define COMMPAGE_VERSION                1

/* ============================================================================
 * ARM64 CPU Capability Flags (macOS-compatible bit positions)
 *
 * These match the kHas* flags from XNU's commpage.h. User-space code
 * (libSystem, etc.) reads COMMPAGE_CPU_CAPS_OFFSET to check for features.
 *
 * Reference: XNU osfmk/arm64/commpage/commpage_asm.h
 * ============================================================================ */
#define kHasNeon                (1ULL << 0)     /* SIMD/NEON always present on ARMv8 */
#define kHasFP                  (1ULL << 1)     /* Floating-point always present */
#define kHasCRC32               (1ULL << 2)     /* CRC32 instructions */
#define kHasAES                 (1ULL << 3)     /* AES crypto */
#define kHasSHA1                (1ULL << 4)     /* SHA-1 crypto */
#define kHasSHA2                (1ULL << 5)     /* SHA-256 crypto */
#define kHasSHA512              (1ULL << 6)     /* SHA-512 crypto (ARMv8.2) */
#define kHasAtomics             (1ULL << 7)     /* LSE atomics (ARMv8.1) */
#define kHasRDM                 (1ULL << 8)     /* SQRDMLAH (ARMv8.1) */
#define kHasDotProd             (1ULL << 9)     /* Dot product (ARMv8.2) */
#define kHasFHM                 (1ULL << 10)    /* FP16 multiply-accumulate */
#define kHasFP16                (1ULL << 11)    /* FP16 support */
#define kHasARMv8_2             (1ULL << 12)    /* ARMv8.2-A baseline */
#define kHasARMv8_3             (1ULL << 13)    /* ARMv8.3-A baseline */
#define kHasARMv8_4             (1ULL << 14)    /* ARMv8.4-A baseline */

/* ============================================================================
 * Global State
 * ============================================================================ */

/* Physical address of the CommPage */
static uint64_t commpage_phys = 0;

/* Kernel-accessible pointer to the CommPage */
static uint8_t *commpage_kva = NULL;

/* ============================================================================
 * Internal Helpers
 * ============================================================================ */

static void commpage_memset(void *dst, int val, uint64_t n)
{
    uint8_t *d = (uint8_t *)dst;
    while (n--)
        *d++ = (uint8_t)val;
}

static void commpage_memcpy(void *dst, const void *src, uint64_t n)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    while (n--)
        *d++ = *s++;
}

static void commpage_write_u32(uint32_t offset, uint32_t value)
{
    if (commpage_kva && offset + sizeof(uint32_t) <= COMMPAGE_SIZE) {
        *(volatile uint32_t *)(commpage_kva + offset) = value;
    }
}

static void commpage_write_u64(uint32_t offset, uint64_t value)
{
    if (commpage_kva && offset + sizeof(uint64_t) <= COMMPAGE_SIZE) {
        *(volatile uint64_t *)(commpage_kva + offset) = value;
    }
}

/*
 * read_cntfrq - Read the ARM counter frequency register
 */
static uint64_t read_cntfrq(void)
{
    uint64_t freq;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(freq));
    return freq;
}

/*
 * read_cntvct - Read the ARM virtual counter
 */
static uint64_t read_cntvct(void)
{
    uint64_t cnt;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(cnt));
    return cnt;
}

/*
 * detect_cpu_capabilities - Probe ARM64 feature registers
 *
 * Reads ID_AA64ISAR0_EL1, ID_AA64ISAR1_EL1, ID_AA64MMFR0_EL1, etc.
 * to determine which optional features are available.
 *
 * Returns a bitmask of kHas* flags.
 *
 * Note: We're running on QEMU virt with Cortex-A72, which has:
 *   - NEON/FP (always)
 *   - CRC32
 *   - AES, SHA1, SHA2
 *   - NO LSE atomics (that's ARMv8.1, A72 is ARMv8.0)
 */
static uint64_t detect_cpu_capabilities(void)
{
    uint64_t caps = 0;
    uint64_t isar0, isar1, pfr0;

    /* All ARMv8 cores have NEON and FP */
    caps |= kHasNeon | kHasFP;

    /* Read ID_AA64ISAR0_EL1: AES, SHA1, SHA2, CRC32, atomics */
    __asm__ volatile("mrs %0, id_aa64isar0_el1" : "=r"(isar0));

    /* AES: bits [7:4], non-zero means supported */
    if ((isar0 >> 4) & 0xF)
        caps |= kHasAES;

    /* SHA1: bits [11:8] */
    if ((isar0 >> 8) & 0xF)
        caps |= kHasSHA1;

    /* SHA2: bits [15:12] */
    if ((isar0 >> 12) & 0xF)
        caps |= kHasSHA2;

    /* CRC32: bits [19:16] */
    if ((isar0 >> 16) & 0xF)
        caps |= kHasCRC32;

    /* Atomics (LSE): bits [23:20], value >= 2 means supported */
    if (((isar0 >> 20) & 0xF) >= 2)
        caps |= kHasAtomics;

    /* SHA512: bits [15:12] of ISAR2, but let's check ISAR0[15:12] for SHA2-512 */
    /* Actually SHA512 is in ISAR0 bits [15:12] value == 2 */
    if (((isar0 >> 12) & 0xF) >= 2)
        caps |= kHasSHA512;

    /* RDM: bits [31:28], value >= 1 */
    if ((isar0 >> 28) & 0xF)
        caps |= kHasRDM;

    /* Read ID_AA64ISAR1_EL1: DotProd, FHM, etc. */
    __asm__ volatile("mrs %0, id_aa64isar1_el1" : "=r"(isar1));

    /* DotProd: bits [3:0] */
    if (isar1 & 0xF)
        caps |= kHasDotProd;

    /* FHM: bits [7:4] */
    if ((isar1 >> 4) & 0xF)
        caps |= kHasFHM;

    /* Read ID_AA64PFR0_EL1: FP16, architecture version */
    __asm__ volatile("mrs %0, id_aa64pfr0_el1" : "=r"(pfr0));

    /* FP16: AdvSIMD [23:20] value == 1 means FP16 supported */
    if (((pfr0 >> 20) & 0xF) == 1)
        caps |= kHasFP16;

    return caps;
}

/* ============================================================================
 * ARM64 CommPage Stub Code
 *
 * These are tiny ARM64 instruction sequences placed in the CommPage.
 * User-space code can call/branch to these addresses for fast operations
 * that need no syscall.
 *
 * gettimeofday stub:
 *   Reads CNTVCT_EL0 and CNTFRQ_EL0 (both EL0-accessible), converts
 *   to microseconds, and returns the result.
 *
 * nanotime stub:
 *   Returns the raw CNTVCT_EL0 value (mach_absolute_time equivalent).
 * ============================================================================ */

/*
 * ARM64 instructions for the nanotime stub:
 *   mrs x0, cntvct_el0     -> 0xD53BE040
 *   ret                    -> 0xD65F03C0
 */
static const uint32_t stub_nanotime[] = {
    0xD53BE040,     /* mrs x0, cntvct_el0 */
    0xD65F03C0,     /* ret */
};

/*
 * ARM64 instructions for the gettimeofday stub:
 *
 * This is a simplified stub. It reads the counter and frequency,
 * divides counter / freq to get seconds, and computes the remainder
 * for microseconds. A real implementation would use the timebase
 * data stored in the CommPage to avoid the division.
 *
 *   mrs x1, cntfrq_el0     -> 0xD53BE001
 *   mrs x0, cntvct_el0     -> 0xD53BE040
 *   udiv x2, x0, x1        -> 0x9AC10802   (seconds = cnt / freq)
 *   msub x3, x2, x1, x0    -> 0x9B018043   (remainder = cnt - sec*freq)
 *   mov x4, #1000000        -> requires multiple instructions
 *   ... (complex; return raw counter for now)
 *   mov x0, x2              -> 0xAA0203E0   (return seconds in x0)
 *   mov x1, x3              -> 0xAA0303E1   (return remainder in x1)
 *   ret                     -> 0xD65F03C0
 *
 * Simplified version: just return raw CNTVCT (caller computes time).
 */
static const uint32_t stub_gettimeofday[] = {
    0xD53BE001,     /* mrs x1, cntfrq_el0 */
    0xD53BE040,     /* mrs x0, cntvct_el0 */
    0x9AC10802,     /* udiv x2, x0, x1    (seconds) */
    0x9B018043,     /* msub x3, x2, x1, x0 (remainder ticks) */
    0xAA0203E0,     /* mov x0, x2         (seconds -> x0) */
    0xAA0303E1,     /* mov x1, x3         (rem ticks -> x1; caller * 1e6/freq) */
    0xD65F03C0,     /* ret */
};

/*
 * ARM64 instructions for the sigreturn trampoline:
 *
 * When a signal handler returns, it jumps here to restore the
 * original context via the sigreturn syscall.
 *
 *   mov x16, #184          -> 0xD2801710   (movz x16, #0xB8 = SYS_sigreturn)
 *   svc #0x80              -> 0xD4001001   (syscall)
 *
 * The saved trap_frame (sigcontext) is at the current SP when this runs.
 * sigreturn reads it from SP and restores all registers + PC.
 */
static const uint32_t stub_sigreturn[] = {
    0xD2801710,     /* movz x16, #184 (SYS_sigreturn) */
    0xD4001001,     /* svc #0x80 */
};

/* ============================================================================
 * CommPage Initialization
 * ============================================================================ */

/*
 * commpage_init - Allocate and populate the CommPage
 *
 * Called once during kernel startup (after PMM and VMM are initialized).
 * Allocates a single physical page, fills in system data and stub code,
 * and stores the physical address for later mapping into user spaces.
 */
void commpage_init(void)
{
    kprintf("[commpage] Initializing CommPage at VA 0x%lx...\n", COMMPAGE_VA);

    /* Allocate a physical page */
    commpage_phys = pmm_alloc_page();
    if (commpage_phys == 0)
        panic("commpage: cannot allocate physical page");

    /* Get kernel-accessible address (identity mapping: PA == VA for RAM) */
    commpage_kva = (uint8_t *)commpage_phys;

    /* Zero the entire page */
    commpage_memset(commpage_kva, 0, COMMPAGE_SIZE);

    /* Write signature */
    commpage_write_u64(COMMPAGE_SIGNATURE_OFFSET, COMMPAGE_MAGIC);

    /* System info */
    commpage_write_u32(COMMPAGE_VERSION_OFFSET, COMMPAGE_VERSION);
    commpage_write_u32(COMMPAGE_CPU_COUNT_OFFSET, MAX_CPUS);
    commpage_write_u32(COMMPAGE_PAGE_SIZE_OFFSET, PAGE_SIZE);
    commpage_write_u32(COMMPAGE_CACHE_LINE_OFFSET, 64);  /* Typical A72 cache line */

    /* CPU capabilities: detect from ARM ID registers */
    uint64_t cpu_caps = detect_cpu_capabilities();
    commpage_write_u64(COMMPAGE_CPU_CAPS_OFFSET, cpu_caps);
    kprintf("[commpage] CPU capabilities: 0x%lx\n", cpu_caps);

    /* Time info */
    uint64_t freq = read_cntfrq();
    commpage_write_u64(COMMPAGE_TIMEBASE_OFFSET, freq);
    commpage_write_u64(COMMPAGE_TIMESTAMP_OFFSET, read_cntvct());
    /* Record boot counter for unix time derivation */
    boot_cntvct = read_cntvct();
    boot_cntfrq = freq;

    /* Initial unix time = boot epoch */
    commpage_write_u64(COMMPAGE_UNIXTIME_OFFSET, BOOT_EPOCH_SECS);
    commpage_write_u64(COMMPAGE_UNIXTIME_USEC_OFFSET, 0);

    /* Boot time */
    commpage_write_u64(COMMPAGE_BOOTTIME_SEC_OFFSET, BOOT_EPOCH_SECS);
    commpage_write_u64(COMMPAGE_BOOTTIME_USEC_OFFSET, 0);

    /* Kernel version string */
    const char *version = "Kiseki OS v0.1.0 (ARM64)";
    uint64_t vlen = 0;
    while (version[vlen] != '\0')
        vlen++;
    if (vlen > 63)
        vlen = 63;
    commpage_memcpy(commpage_kva + COMMPAGE_KERN_VERSION_OFFSET, version, vlen);
    commpage_kva[COMMPAGE_KERN_VERSION_OFFSET + vlen] = '\0';

    /* Install stub code */
    commpage_memcpy(commpage_kva + COMMPAGE_STUB_GETTIMEOFDAY,
                    stub_gettimeofday, sizeof(stub_gettimeofday));
    commpage_memcpy(commpage_kva + COMMPAGE_STUB_NANOTIME,
                    stub_nanotime, sizeof(stub_nanotime));
    commpage_memcpy(commpage_kva + COMMPAGE_STUB_SIGRETURN,
                    stub_sigreturn, sizeof(stub_sigreturn));

    kprintf("[commpage] CommPage ready: phys=0x%lx freq=%lu Hz\n",
            commpage_phys, freq);
    kprintf("[commpage] sigreturn trampoline at CommPage+0x%x\n",
            COMMPAGE_STUB_SIGRETURN);
    kprintf("[commpage] gettimeofday stub at CommPage+0x%x\n",
            COMMPAGE_STUB_GETTIMEOFDAY);
    kprintf("[commpage] nanotime stub at CommPage+0x%x\n",
            COMMPAGE_STUB_NANOTIME);
}

/* ============================================================================
 * CommPage Mapping
 * ============================================================================ */

/*
 * commpage_map - Map the CommPage into a user address space
 *
 * @space: User VM space to map into
 *
 * Maps the shared CommPage physical page at COMMPAGE_VA (0x0000000FFFFFC000)
 * with read-only + execute permissions. User code can read data fields
 * and call the stub routines.
 *
 * This is called for every new process (during proc_create or execve).
 */
void commpage_map(struct vm_space *space)
{
    if (commpage_phys == 0) {
        kprintf("commpage: not initialized, skipping map\n");
        return;
    }

    if (space == NULL || space->pgd == NULL) {
        kprintf("commpage: NULL space, skipping map\n");
        return;
    }

    /*
     * Map as user read-only + executable.
     * The stubs contain executable ARM64 instructions, so we need
     * execute permission. Data fields are read via LDR.
     */
    int ret = vmm_map_page(space->pgd, COMMPAGE_VA, commpage_phys, PTE_USER_RX);
    if (ret != 0) {
        kprintf("commpage: failed to map at VA 0x%lx\n", COMMPAGE_VA);
    }

    /*
     * Bump the page's reference count so it doesn't get freed
     * when any single process exits.
     */
    pmm_page_ref(commpage_phys);
}

/* ============================================================================
 * CommPage Update
 * ============================================================================ */

/*
 * commpage_update_time - Update time fields in the CommPage
 *
 * Called periodically (e.g., from the timer tick handler) to keep
 * the CommPage timestamp reasonably fresh. User code that reads
 * CNTVCT directly will always get the current time; the CommPage
 * timestamp is a snapshot for code that wants a quick-and-dirty time.
 */
void commpage_update_time(void)
{
    if (commpage_kva == NULL)
        return;

    uint64_t now = read_cntvct();
    commpage_write_u64(COMMPAGE_TIMESTAMP_OFFSET, now);

    /* Compute unix time from boot counter + boot epoch */
    if (boot_cntfrq > 0) {
        uint64_t elapsed_ticks = now - boot_cntvct;
        uint64_t elapsed_secs = elapsed_ticks / boot_cntfrq;
        uint64_t remainder_ticks = elapsed_ticks % boot_cntfrq;
        uint64_t elapsed_usec = (remainder_ticks * 1000000ULL) / boot_cntfrq;

        commpage_write_u64(COMMPAGE_UNIXTIME_OFFSET,
                           BOOT_EPOCH_SECS + elapsed_secs);
        commpage_write_u64(COMMPAGE_UNIXTIME_USEC_OFFSET, elapsed_usec);
    }
}

/*
 * commpage_set_unixtime - Set the CommPage Unix timestamp
 *
 * @seconds: Seconds since epoch
 * @usec:    Microseconds
 *
 * Called when the kernel determines wall clock time (from RTC, NTP, etc.)
 */
void commpage_set_unixtime(uint64_t seconds, uint64_t usec)
{
    if (commpage_kva == NULL)
        return;

    commpage_write_u64(COMMPAGE_UNIXTIME_OFFSET, seconds);
    commpage_write_u64(COMMPAGE_UNIXTIME_USEC_OFFSET, usec);
}

/*
 * commpage_set_cpu_count - Update the CPU count in CommPage
 *
 * @count: Number of online CPUs
 *
 * Called when secondary cores come online.
 */
void commpage_set_cpu_count(uint32_t count)
{
    commpage_write_u32(COMMPAGE_CPU_COUNT_OFFSET, count);
}
