This is a crucial addition. While I referenced "process structures" and "threads," I did not explicitly detail the **Scheduler**, **Symmetric Multi-Processing (SMP)**, or **Synchronization Primitives**. For an XNU-like OS, the Mach threading model is the heart of the system.

Here is the **Updated & Finalized Master Specification (v1.1)**, now explicitly detailing the Multitasking and Multiprocessing subsystems.

---

# Kiseki Operating System: Master Architecture & Design Specification (v1.1)

**Project Codename:** Kiseki
**Target Architecture:** ARM64 (AArch64)
**Primary Hardware:** QEMU `virt` Machine (Dev), Raspberry Pi 4/5 (Prod)
**Kernel Type:** Hybrid (XNU-Derivative: Mach Microkernel + BSD Personality)
**Binary Format:** Native Mach-O 64-bit (`MH_MAGIC_64`)
**Compatibility Target:** macOS 14+ (Sonoma) / Darwin 23.x ABI

---

## 1. Executive Summary
Kiseki is a Unix-like operating system designed to run native macOS ARM64 CLI binaries on non-Apple hardware. It achieves this by implementing a clean-room version of the XNU kernel interfaces (Mach traps and BSD syscalls) while using standard PC hardware abstractions. It features a persistent Ext4 root filesystem, a full multi-user security model, and robust support for **Symmetric Multi-Processing (SMP)** and **Preemptive Multitasking**.

## 2. Kernel Architecture: The Scheduler & Threading

### 2.1. Threading Model (Mach Threads)
Kiseki implements a **1:1 Threading Model**, meaning every user-space `pthread` maps directly to one kernel thread (`thread_t`).

*   **Thread Structure (`thread_t`):**
    *   `uint64_t tid`: Unique Thread ID.
    *   `uint64_t context[32]`: Saved register state (x0-x30, SP, PC, PSTATE).
    *   `int state`: `TH_RUN` (Running), `TH_WAIT` (Blocked), `TH_IDLE`, `TH_TERM`.
    *   `int priority`: Base priority (0-127).
    *   `int sched_policy`: `SCHED_FIFO` (Real-time), `SCHED_RR` (Round Robin), `SCHED_OTHER` (Standard).
    *   `uint64_t continuation`: Function pointer for "stackless" context switching (Mach optimization).

### 2.2. The Scheduler (Multitasking)
*   **Algorithm:** **Multilevel Feedback Queue (MLFQ)**.
    *   High-priority threads (Real-time/Audio) preempt lower ones immediately.
    *   Aging mechanism prevents starvation of low-priority threads.
*   **Time Slicing:**
    *   **Quantum:** 10ms default timeslice.
    *   **Timer Interrupt:** The ARM Generic Timer (`CNTV_TVAL_EL0`) fires periodically to trigger `sched_tick()`.
*   **Preemption:**
    *   If `current_thread->quantum_remaining <= 0`, call `thread_block()` and pick next thread.
    *   **User Preemption:** Occurs on return from syscall/interrupt.
    *   **Kernel Preemption:** Allowed at defined "preemption points" (not inside spinlocks).

### 2.3. Symmetric Multi-Processing (SMP) & Parallelism
Kiseki supports utilizing all available CPU cores (e.g., 4 cores on Pi 4).

*   **Boot Process (Core 0 -> Core N):**
    *   Core 0 (BSP - Boot Strap Processor) boots first.
    *   BSP parses Device Tree/ACPI to find secondary cores.
    *   BSP uses **PSCI (Power State Coordination Interface)** commands (`smc #0`) to wake up Core 1..N (APs - Application Processors).
*   **Per-CPU Data (`cpu_data_t`):**
    *   Stored in `TPIDR_EL1` (Kernel Thread Pointer).
    *   Contains: `current_thread`, `idle_thread`, `run_queue` (local to core).
*   **Load Balancing:**
    *   A "Work Stealing" algorithm runs periodically. If Core 0 is overloaded and Core 1 is idle, Core 1 "steals" a thread from Core 0's run queue.
*   **Inter-Processor Interrupts (IPI):**
    *   **Mechanism:** GICv2/v3 SGIs (Software Generated Interrupts).
    *   **Usage:**
        *   `IPI_RESCHEDULE`: Force a remote core to call the scheduler immediately.
        *   `IPI_TLB_FLUSH`: Invalidate TLB entries on other cores when page tables change.
        *   `IPI_HALT`: Stop all cores for kernel panic/shutdown.

### 2.4. Synchronization Primitives
To safely handle parallelism, Kiseki implements XNU-compatible locking.

*   **Spinlocks (`hw_lock`):**
    *   For protecting short critical sections (e.g., Run Queues, Scheduler structs).
    *   Implementation: `ldaxr` / `stlxr` (ARMv8 atomics). Disables interrupts while held.
*   **Mutexes (`lck_mtx`):**
    *   For protecting long critical sections (can sleep).
    *   Supports "Priority Inheritance" to prevent priority inversion.
*   **Semaphores (`semaphore`):**
    *   Counting semaphores for resource tracking.
    *   Mapped to `semaphore_signal_trap` and `semaphore_wait_trap`.
*   **Condition Variables (`cond_var`):**
    *   Wait queues for threads sleeping on an event.

---

## 3. The Darwin Compatibility Layer (The "XNU Persona")

To run unmodified macOS binaries, Kiseki must perfectly emulate the kernel-user ABI.

### 3.1. System Call Interface (`svc #0x80`)
*   **Mechanism:** Trap handler examines `x16`.
    *   **Positive `x16`:** Dispatch to BSD Syscall Table.
    *   **Negative `x16`:** Dispatch to Mach Trap Table.
*   **Error Handling:**
    *   XNU sets `PSTATE.C` (Carry Flag) on error.
    *   XNU puts positive error code in `x0`.

### 3.2. Mandatory BSD Syscalls (Partial List)
Must match `bsd/sys/syscall.h` from Apple XNU source.
| Syscall # | Name | Signature | Notes |
| :--- | :--- | :--- | :--- |
| **1** | `exit` | `void exit(int)` | |
| **2** | `fork` | `int fork(void)` | Implements copy-on-write process duplication. |
| **3** | `read` | `ssize_t read(int, void*, size_t)` | |
| **4** | `write` | `ssize_t write(int, void*, size_t)` | |
| **5** | `open` | `int open(char*, int, int)` | **Critical:** Flag translation required. |
| **202** | `sysctl` | `int sysctl(...)` | Required for `libc` init (`hw.pagesize`). |
| **328** | `pthread_kill`| `int pthread_kill(port, sig)` | Required for signal delivery. |

### 3.3. Mandatory Mach Traps
These are essential for the threading model.
| Trap # | Name | Function |
| :--- | :--- | :--- |
| **-31** | `mach_msg_trap` | IPC core. Sends/Receives messages on ports. |
| **-33** | `semaphore_signal` | Thread synchronization. |
| **-36** | `task_self_trap` | Returns process port. |
| **-59** | `swtch_pri` | Voluntary context switch (yield). |

### 3.4. Memory Emulation
*   **CommPage:** A fixed page at `0x0000000FFFFFC000` containing optimized routines (`bzero`, `gettimeofday`).
    *   *Requirement:* Kernel must populate this page during boot.
*   **Page Zero:** The first 4GB of virtual address space (`0x0 - 0x100000000`) must be unmapped.
*   **Binary Load Address:** Mach-O binaries are loaded at `0x100000000` or higher.
*   **TLS (Thread Local Storage):**
    *   User space uses `TPIDR_EL0` to point to thread-local data.
    *   Kernel must preserve `x18` (Platform Register) during context switches.

---

## 4. Storage Subsystem (Ext4)

Kiseki replaces the XNU APFS/HFS+ layer with a native Linux Ext4 driver.

### 4.1. Block Device Interface
*   **Drivers:** `virtio-blk` (QEMU), `emmc` (RasPi).
*   **Buffer Cache:** LRU-based block cache.

### 4.2. Ext4 Implementation Details
*   **Superblock:** Parse `0xEF53` magic.
*   **Features:** `EXT4_FEATURE_INCOMPAT_EXTENTS` (Tree-based allocation), `EXT4_FEATURE_COMPAT_DIR_INDEX` (HTree).
*   **VFS Translation:**
    *   Map Ext4 Inodes to Kiseki Vnodes.
    *   Translate `open(O_CREAT)` flags from XNU bitmask to Ext4 bitmask.

---

## 5. Security & Multi-User Subsystem

Kiseki implements a 4.4BSD-derived security model.

### 5.1. Authentication Structures
*   **`struct ucred`:**
    *   `uid_t cr_uid`: Effective User ID.
    *   `uid_t cr_ruid`: Real User ID.
    *   `gid_t cr_groups[NGROUPS]`: Group membership list.
*   **Root User:** UID 0 bypasses all permission checks.

### 5.2. Permission Enforcement
*   **VFS Gate:** `vfs_access(vnode, mode, cred)` called on every file operation.
    *   Checks Owner (User) bits.
    *   Checks Group bits.
    *   Checks Other (World) bits.
*   **Set-UID (SUID):**
    *   During `execve()`, check Inode mode for `S_ISUID` (`04000`).
    *   If set, `new_proc->cred->uid = inode->uid`.
    *   **Required for:** `sudo`, `su`.

### 5.3. Userland Security Binaries
Standard Unix utilities compiled as Mach-O:
1.  **`/bin/login`**: Authenticates users against `/etc/shadow`, sets UID/GID, spawns shell.
2.  **`/usr/bin/sudo`**: SUID Root binary, parses `/etc/sudoers`.
3.  **`/usr/sbin/adduser` & `usermod`**: Manage `/etc/passwd`.

---

## 6. Networking Subsystem

### 6.1. BSD Sockets
*   **Syscalls:** `socket`, `bind`, `listen`, `accept`, `connect`, `sendto`, `recvfrom`.
*   **Structs:** `sockaddr_in` (IPv4), `sockaddr_in6` (IPv6).

### 6.2. Stack Implementation
*   **L2:** Ethernet framing.
*   **L3:** IPv4/IPv6 handling, ARP table.
*   **L4:** TCP state machine and UDP.
*   **Drivers:** `virtio-net` (QEMU), `genet` (RasPi).

---

## 7. Development Methodology (Strict TDD)

### 7.1. Workflow
1.  **Red:** Write a failing test case in `tests/`.
2.  **Green:** Write minimal kernel code to pass.
3.  **Refactor:** Optimize.

### 7.2. Testing Strategy
*   **Unit Tests:** Compile kernel subsystems as user-space programs on host.
*   **Integration Tests:** Boot Kiseki in QEMU and run test payloads.

---

## 8. Directory Structure

```text
Kiseki/
├── Makefile                 # Build automation
├── boot/                    # Bootloader stubs (EFI/U-Boot)
├── kernel/
│   ├── arch/arm64/          # boot.S, context_switch.S, smp.c (Multiprocessing)
│   ├── kern/                # scheduler.c, thread.c, sync_lock.c, ipc_tt.c
│   ├── bsd/                 # Syscalls (sys_generic.c), VFS (vfs_syscalls.c)
│   ├── mach/                # IPC (mach_msg.c), Mach Traps
│   ├── fs/ext4/             # Ext4 driver implementation
│   ├── net/                 # TCP/IP Stack
│   └── drivers/             # virtio, pl011, gic
├── userland/
│   ├── libsystem/           # libc, libpthread, libm (Mach-O dylibs)
│   ├── dyld/                # Dynamic Linker implementation
│   └── bin/                 # Core utils (login, sh, ls, cat)
└── tests/                   # TDD Test Suite
```

---

## 9. Notes
- Don't cut corner by implementing ramfs, I need a real file system (like extf4), you may use an opensource version of it if needed (I prefer you to implement this yourself)
- Make sure everything is testable
- We need all default binary working just like their macos counterpart (like echo, cat, ls, mkdir, rm, sudo, su, adduser, usermod, chmod) and all of their flags (ls -lah / ls -l / ls -ah / rm -r / rm -rf)
**End of Specification**