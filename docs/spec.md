# Kiseki Operating System: Architecture & Design Specification

**Version:** 2.0
**Target Architecture:** ARM64 (AArch64)
**Primary Hardware:** QEMU `virt` machine (development), Raspberry Pi 4/5 (production)
**Kernel Type:** Hybrid (Mach microkernel + BSD personality)
**Binary Format:** Mach-O 64-bit (`MH_MAGIC_64`)
**Compatibility Target:** macOS 14+ (Sonoma) / Darwin 23.x ARM64 ABI

---

## 1. Philosophy

### 1.1. Why "Kiseki"?

奇跡 (kiseki) is the Japanese word for **miracle**.

Running native macOS ARM64 binaries on bare-metal non-Apple hardware - without Apple's kernel, without Apple's bootloader, without a single line of Apple's code - should not be possible. The Mach-O format, the XNU syscall conventions, the Darwin ABI: these were designed for a vertically integrated ecosystem where Apple controls the hardware, the firmware, the kernel, and the userland. Reproducing enough of that interface to make real binaries believe they are on macOS, on a QEMU `virt` machine or a Raspberry Pi, is an act of unreasonable ambition.

The name also acknowledges the nature of building an operating system from nothing. The project began with a UART printing characters to a serial console. No scheduler. No memory allocator. No filesystem. Just voltage on a wire. From that starting point, every new subsystem that comes to life - the first process that forks, the first file that opens, the first TCP handshake that completes - is a small miracle. Kiseki is the sum of these miracles.

The project embodies a conviction: that the best way to understand a system is to build it, completely, from first principles. Not to patch an existing kernel. Not to port a compatibility layer. To write every line - the boot code, the page table walker, the scheduler, the filesystem driver, the TCP state machine, the shell - and in doing so, to truly comprehend what an operating system is.

### 1.2. Design Principles

1. **Darwin ABI fidelity.** The kernel-user interface must match XNU exactly. `svc #0x80`, syscall number in `x16`, carry flag on error, positive errno in `x0`. Struct layouts match the macOS ARM64 SDK to the byte. A binary compiled with `clang -target arm64-apple-macos11` on a Mac must run unmodified on Kiseki.

2. **No stubs.** Every feature is implemented properly or not at all. A syscall that returns `ENOSYS` is preferable to one that silently does nothing. When a subsystem is built, it handles edge cases, error paths, and concurrent access correctly.

3. **Transparency.** The kernel is a single flat C codebase with no abstraction for its own sake. Data structures are visible. Control flow is traceable. A developer reading any source file should be able to understand what it does without consulting a framework manual.

4. **Correctness over performance.** A correct implementation that runs slowly is more valuable than a fast one that corrupts memory. Optimisations are added after the system works, not before.

---

## 2. Executive Summary

Kiseki is a Unix-like operating system that runs native macOS ARM64 CLI binaries on non-Apple hardware. It achieves this by implementing a clean-room version of the XNU kernel interfaces - Mach traps and BSD syscalls - while targeting standard virtualised and embedded ARM64 platforms.

The system comprises:
- A **hybrid kernel** (~22,000 lines of C and ARM64 assembly) implementing the Mach microkernel, BSD personality, Ext4 filesystem, TCP/IP networking, and device drivers
- A **dynamic linker** (dyld) and **C library** (libSystem.B.dylib, ~3,200 lines) providing the Darwin userland ABI
- **75 Mach-O userland binaries** including bash, awk, sed, grep, curl, TCC compiler, and a full set of coreutils
- A **native C compiler** (TCC) that runs on Kiseki and produces working Mach-O ARM64 binaries
- A **4-core SMP** scheduler with pre-emptive multitasking
- A complete **TCP/IP stack** with BSD socket API
- A **pseudo-terminal** subsystem for remote shell sessions

---

## 3. Platform Support

### 3.1. QEMU `virt` Machine (Development)

| Resource | Address / Value |
|---|---|
| CPU | Cortex-A72, 4 cores |
| RAM | `0x40000000` – `0x7FFFFFFF` (1 GB) |
| Kernel load | `0x40080000` |
| PL011 UART | `0x09000000`, IRQ 33 |
| GICv2 Distributor | `0x08000000` |
| GICv2 CPU Interface | `0x08010000` |
| VirtIO MMIO | `0x0A000000`, stride `0x200`, 32 transports, IRQ base 48 |
| PL031 RTC | `0x09010000` |
| Network | VirtIO-net, user-mode: guest `10.0.2.15`, gateway `10.0.2.2` |

### 3.2. Raspberry Pi 4 (Production)

| Resource | Address / Value |
|---|---|
| CPU | Cortex-A72 (BCM2711), 4 cores |
| RAM | `0x00000000` – `0x3FFFFFFF` (1 GB low) |
| Kernel load | `0x00080000` |
| PL011 UART0 | `0xFE201000`, IRQ 153 |
| Mini UART | `0xFE215040` |
| GIC-400 Distributor | `0xFF841000` |
| GIC-400 CPU Interface | `0xFF842000` |
| eMMC/SD | `0xFE340000` |
| GENET Ethernet | `0xFD580000` |
| GPIO | `0xFE200000` |
| Mailbox | `0xFE00B880` |

### 3.3. Common Constants

| Constant | Value |
|---|---|
| `MAX_CPUS` | 4 |
| `KERNEL_STACK_SIZE` | 32 KB per CPU |
| Secondary core stacks | 16 KB per core |

---

## 4. Boot Sequence

### 4.1. ARM64 Boot (`boot.S`)

1. **Core selection.** Read `MPIDR_EL1 & 0xFF`. Non-zero cores enter `WFE` spin loop.
2. **Exception level drop.** Core 0 checks `CurrentEL`:
   - EL2: Configure `HCR_EL2.RW = 1` (AArch64 at EL1), set `SPSR_EL2 = 0x3C5` (all exceptions masked, EL1h mode), `ERET` to EL1.
   - EL1: Proceed directly.
3. **System register setup.** Disable MMU (`SCTLR_EL1.M = 0`), enable FP/SIMD (`CPACR_EL1.FPEN = 0b11`).
4. **Exception vectors.** `VBAR_EL1 = _vectors`.
5. **Stack.** `SP = __stack_top`.
6. **BSS clear.** Zero-fill `__bss_start` to `__bss_end`.
7. **Enter C.** Call `kmain(0)`.

### 4.2. Kernel Initialisation (`main.c`)

Seventeen-phase boot, executed sequentially on core 0:

| Phase | Subsystem | Details |
|---|---|---|
| 1 | UART | `uart_init()`. Prints banner: `Kiseki OS v0.1.0`. |
| 2 | Interrupts | `gic_init()`, `gic_init_percpu()`, `uart_enable_irq()`. GICv2 initialisation, UART RX interrupt enabled. |
| 3 | Physical memory | `pmm_init(__heap_start, RAM_BASE + RAM_SIZE)`. Buddy allocator. |
| 4 | Virtual memory | `vmm_init()`. Page table setup, identity mapping. |
| 5 | Threading | `thread_init()`, `sched_init()`. Thread pool (256), MLFQ scheduler (128 levels). |
| 6 | Timer | `timer_init(100)`. ARM Generic Timer at 100 Hz. Enables IRQs. |
| 7 | SMP | `smp_init()`. Wakes secondary cores via PSCI `smc #0`. |
| 8 | Block device | `blkdev_init()`. VirtIO-blk (QEMU) or eMMC (RPi). |
| 9 | Buffer cache | `buf_init()`. LRU cache, 256 × 4 KB blocks. |
| 10 | TTY + PTY | `tty_init()`, `pty_init()`. Console terminal and pseudo-terminal pool (16 pairs). |
| 11 | Ext4 | `ext4_fs_init()`. Registers Ext4 filesystem type with VFS. |
| 12 | Root mount | `vfs_mount("ext4", "/", 0, 0)`. Mounts root filesystem. |
| 12b | Device FS | `devfs_init()`, `vfs_mount("devfs", "/dev", 0, 0)`. Creates `/dev/console`, `/dev/null`, `/dev/zero`, `/dev/urandom`. |
| 13 | Mach IPC | `ipc_init()`. Port namespace, kernel IPC space. |
| 14 | CommPage | `commpage_init()`. Shared kernel-user page at `0xFFFFFFFFFFFFC000`. |
| 15 | Processes | `proc_init()`. Process table (256 slots), PID 0 (kernel). |
| 16 | Networking | `net_init()`. TCP/IP stack, socket table (64), VirtIO-net driver, IP/gateway configuration. |
| 17 | PID 1 | `kernel_init_process()`. Loads `/sbin/init` (or `/bin/bash` fallback) as Mach-O. Never returns. |

### 4.3. Secondary Core Boot

Each secondary core, once woken by PSCI:
1. Drops from EL2 to EL1 (if needed).
2. Sets per-core stack: `SP = __stack_top - (core_id × 16 KB)`.
3. Calls `secondary_main(core_id)`: GIC per-CPU init, scheduler per-CPU init, timer per-CPU init, enables interrupts, enters idle loop (`WFI`).

### 4.4. Userland Boot Chain

```
/sbin/init → /sbin/getty (per TTY) → /bin/login → /bin/bash
```

- **init**: PID 1. Mounts root, spawns getty for each configured terminal.
- **getty**: Opens `/dev/console`, sets controlling terminal (`TIOCSCTTY`), prints login prompt, execs login.
- **login**: Reads username/password, authenticates against `/etc/passwd` + `/etc/shadow`, sets UID/GID/groups, execs user's shell.
- **bash**: Interactive shell with job control, pipelines, redirections.

---

## 5. Kernel Architecture

### 5.1. Threading Model

Kiseki implements a **1:1 threading model**. Each user-space pthread maps to exactly one kernel thread.

**Thread structure (`struct thread`):**

| Field | Type | Purpose |
|---|---|---|
| `tid` | `uint64_t` | Unique thread ID |
| `state` | `int` | `TH_RUN` (0), `TH_WAIT` (1), `TH_IDLE` (2), `TH_TERM` (3) |
| `priority` | `int` | Base priority (0–127) |
| `effective_priority` | `int` | After priority inheritance/decay |
| `sched_policy` | `int` | `SCHED_OTHER` (0), `SCHED_FIFO` (1), `SCHED_RR` (2) |
| `quantum` | `int` | Remaining time quantum (ticks) |
| `cpu` | `int` | CPU core this thread runs on |
| `context` | `struct cpu_context` | Callee-saved registers (x19–x30, SP) |
| `kernel_stack` | `uint64_t *` | 16 KB kernel stack (4 pages) |
| `task` | `struct task *` | Owning Mach task (process container) |
| `continuation` | `uint64_t` | Mach stackless context switch optimisation |

**Task structure (`struct task`)** - the Mach process container:

| Field | Type | Purpose |
|---|---|---|
| `pid` | `pid_t` | Process ID |
| `name` | `char[32]` | Process name |
| `vm_space` | `struct vm_space *` | Virtual address space |
| `threads` | `struct thread *` | Thread list |
| `task_port` | `mach_port_t` | Mach task port |
| `ipc_space` | `struct ipc_space *` | IPC port namespace |
| `uid`, `gid`, `euid`, `egid` | uid/gid types | Credentials |

### 5.2. Scheduler

**Algorithm:** Multilevel Feedback Queue (MLFQ) with 128 priority levels.

- **Per-CPU run queues.** Each CPU core maintains an independent 128-level MLFQ. Per-CPU data is stored in `TPIDR_EL1`.
- **Time quantum.** 10 ms default (10 timer ticks at 100 Hz).
- **Timer tick (`sched_tick`).** Called from the ARM Generic Timer interrupt at 100 Hz:
  - Decrements `quantum` for the running thread.
  - When quantum expires for `SCHED_OTHER` threads: decrement `effective_priority` by 1, set `need_resched`.
  - Every 100 ticks: boost all waiting threads' `effective_priority` toward their base `priority` by +1 (prevents starvation).
- **Thread selection (`sched_pick_next`).** Scans from priority 127 down to 0, returns the head thread of the highest non-empty queue. Falls back to idle thread.
- **Context switch (`sched_switch`).** Saves callee-saved registers (x19–x30, SP), switches `TTBR0_EL1` if the new thread belongs to a different task (different address space), restores new thread's registers.
- **Pre-emption.** User pre-emption on return from syscall/interrupt. Kernel pre-emption at defined points (not inside spinlocks).

### 5.3. SMP

- 4-core support via PSCI (`smc #0`) for secondary core bringup.
- Inter-Processor Interrupts (IPI) via GICv2 SGIs:
  - `IPI_RESCHEDULE`: Force a remote core to invoke the scheduler.
  - `IPI_TLB_FLUSH`: Invalidate TLB entries on all cores after page table changes.
  - `IPI_HALT`: Stop all cores for kernel panic or shutdown.
- Load balancing: work-stealing algorithm runs periodically; idle cores steal threads from overloaded cores.

### 5.4. Synchronisation Primitives

| Primitive | Implementation | Use |
|---|---|---|
| **Spinlock** (`hw_lock`) | `ldaxr`/`stlxr` (ARMv8 atomics), disables IRQs while held | Short critical sections (run queues, scheduler) |
| **Mutex** (`lck_mtx`) | Sleeping lock with priority inheritance | Long critical sections (filesystem, IPC) |
| **Semaphore** | Counting semaphore | Resource tracking, maps to Mach `semaphore_signal`/`wait` traps |
| **Condition variable** | Wait queue with thread blocking | Sleeping on events (pipe data, socket accept) |

### 5.5. Virtual Memory

- 4 KB page size.
- 4-level ARM64 page tables (PGD → PUD → PMD → PTE).
- Per-process address spaces via `TTBR0_EL1` (user) and `TTBR1_EL1` (kernel).
- Demand paging: page faults allocate physical pages on first access.
- Copy-on-write: `fork()` shares parent pages read-only; write faults duplicate the page.
- Page zero: first 4 GB (`0x0` – `0x100000000`) unmapped (Darwin convention).
- Binary load address: `0x100000000` or higher (Mach-O `__PAGEZERO` segment).
- CommPage: `0xFFFFFFFFFFFFC000` - shared read-only page with optimised `gettimeofday`.

### 5.6. Physical Memory

- Buddy allocator initialised from `__heap_start` to `RAM_BASE + RAM_SIZE`.
- Supports order-0 (4 KB) through order-10 (4 MB) allocations.
- `pmm_alloc_pages(order)` / `pmm_free_pages(addr, order)`.

---

## 6. Darwin Compatibility Layer

### 6.1. Syscall Interface

User code executes `svc #0x80` with the syscall number in register `x16`:

- **Positive x16**: BSD syscall dispatch.
- **Negative x16**: Mach trap dispatch (negate to get trap number).
- **Arguments**: `x0`–`x5`.
- **Return value**: `x0`.
- **Error convention**: On error, set PSTATE carry flag (`SPSR` bit 29) and place positive errno in `x0`. On success, clear carry flag.

### 6.2. BSD Syscalls

100+ syscalls implemented with XNU-compatible numbers. Full list:

**Process lifecycle:** `exit` (1), `fork` (2), `execve` (59), `wait4` (7), `getpid` (20), `getppid` (39), `kill` (37), `setpgid` (82), `getpgrp` (81), `getpgid` (151), `setsid` (147)

**Credentials:** `getuid` (24), `geteuid` (25), `setuid` (23), `getgid` (47), `getegid` (43), `setgid` (181), `issetugid` (327), `chown` (16), `fchown` (123), `lchown` (254), `getgroups` (79), `setgroups` (80)

**File I/O:** `open` (5), `close` (6), `read` (3), `write` (4), `pread` (173), `pwrite` (174), `lseek` (199), `fstat` (153), `fstat64` (189), `stat` (338), `lstat` (340), `dup` (41), `dup2` (90), `pipe` (42), `fcntl` (92), `ioctl` (54), `access` (33), `umask` (60), `fchmod` (124), `chmod` (15), `link` (9), `unlink` (10), `symlink` (57), `readlink` (58), `rename` (128), `mkdir` (136), `rmdir` (137), `chdir` (12), `fchdir` (13), `getcwd` (304), `getdirentries` (196), `mknod` (14), `sync` (36)

**Memory:** `mmap` (197), `munmap` (73), `mprotect` (74)

**Signals:** `sigaction` (46), `sigprocmask` (48), `sigreturn` (184), `pthread_kill` (286)

**Networking:** `socket` (97), `bind` (104), `listen` (106), `accept` (30), `connect` (98), `sendto` (133), `recvfrom` (29), `shutdown` (134), `setsockopt` (105), `getsockopt` (118), `getpeername` (31), `getsockname` (32)

**Time:** `gettimeofday` (116), `settimeofday` (122), `nanosleep` (240)

**Filesystem info:** `statfs` (157), `fstatfs` (158)

**System:** `sysctl` (202), `reboot` (55), `select` (93), `proc_info` (336), `getentropy` (500)

**No-cancel variants:** `read_nocancel` (396), `write_nocancel` (397), `open_nocancel` (398), `close_nocancel` (399), `fcntl_nocancel` (406)

**Kiseki extensions:** `openpty` (501) - allocate a pseudo-terminal pair.

### 6.3. Mach Traps

| Trap # | Name | Function |
|---|---|---|
| −26 | `mach_reply_port` | Allocate a reply port |
| −27 | `thread_self_trap` | Return current thread's port |
| −28 | `task_self_trap` | Return current task's port |
| −31 | `mach_msg_trap` | IPC core: send/receive messages on ports |
| −32 | `mach_msg_overwrite_trap` | IPC with overwrite semantics |
| −36 | `mach_port_allocate` | Allocate a new port right |
| −37 | `mach_port_deallocate` | Deallocate a port right |

### 6.4. ABI Details

- **Struct stat**: 144 bytes (matches macOS ARM64 SDK).
- **Struct dirent**: 1,048 bytes (matches macOS ARM64 SDK).
- **Struct statfs**: matches macOS layout.
- **Struct termios**: 72 bytes. `tcflag_t` = `uint64_t`, `cc_t` = `uint8_t`, `speed_t` = `uint64_t`, `NCCS` = 20.
- **Struct winsize**: 8 bytes.
- **Page zero**: `0x0` – `0x100000000` unmapped.
- **TLS**: `TPIDR_EL0` holds thread-local storage pointer. `x18` (platform register) preserved across context switches.

---

## 7. Signals

POSIX signal handling with Darwin-compatible numbering:

| # | Signal | Default | # | Signal | Default |
|---|---|---|---|---|---|
| 1 | `SIGHUP` | Terminate | 17 | `SIGSTOP` | Stop (uncatchable) |
| 2 | `SIGINT` | Terminate | 18 | `SIGTSTP` | Stop |
| 3 | `SIGQUIT` | Core dump | 19 | `SIGCONT` | Continue |
| 4 | `SIGILL` | Core dump | 20 | `SIGCHLD` | Ignore |
| 5 | `SIGTRAP` | Core dump | 21 | `SIGTTIN` | Stop |
| 6 | `SIGABRT` | Core dump | 22 | `SIGTTOU` | Stop |
| 8 | `SIGFPE` | Core dump | 23 | `SIGIO` | Ignore |
| 9 | `SIGKILL` | Terminate (uncatchable) | 24 | `SIGXCPU` | Terminate |
| 10 | `SIGBUS` | Core dump | 25 | `SIGXFSZ` | Terminate |
| 11 | `SIGSEGV` | Core dump | 28 | `SIGWINCH` | Ignore |
| 13 | `SIGPIPE` | Terminate | 30 | `SIGUSR1` | Terminate |
| 14 | `SIGALRM` | Terminate | 31 | `SIGUSR2` | Terminate |
| 15 | `SIGTERM` | Terminate | | | |

Per-process signal state (`struct sigacts`): 32 `sigaction` slots, pending mask, blocked mask, alternate signal stack.

Signal delivery from TTY: UART RX interrupt fires `tty_input_char()`, which checks ISIG + control characters (VINTR → `SIGINT`, VQUIT → `SIGQUIT`, VSUSP → `SIGTSTP`) and sends signals to the TTY's foreground process group (`t_pgrp`).

---

## 8. Process Model

### 8.1. Process Structure (`struct proc`)

256-slot process table. Key fields:

| Field | Purpose |
|---|---|
| `p_pid`, `p_ppid` | Process and parent PID |
| `p_comm[32]` | Process name |
| `p_state` | `UNUSED`, `EMBRYO`, `RUNNING`, `SLEEPING`, `STOPPED`, `ZOMBIE` |
| `p_task` | Pointer to Mach task |
| `p_vmspace` | Virtual address space |
| `p_ucred` | Credentials (real/effective UID/GID, groups) |
| `p_fd` | File descriptor table (256 slots per process) |
| `p_sigacts` | Signal actions, pending/blocked masks |
| `p_pgrp`, `p_session` | Process group and session |
| `p_cwd` | Current working directory vnode |
| `p_umask` | File creation mask |
| `p_entry_point`, `p_needs_dyld`, `p_dylinker` | Mach-O loader state |
| `p_start_time`, `p_user_ticks`, `p_sys_ticks` | Resource accounting |

### 8.2. Mach-O Loading

The kernel's Mach-O loader (`macho.c`) processes:

- `MH_MAGIC_64` (`0xFEEDFACF`) header validation.
- `LC_SEGMENT_64`: Map `__TEXT`, `__DATA`, `__LINKEDIT` segments into process address space.
- `LC_MAIN`: Extract entry point offset.
- `LC_LOAD_DYLINKER`: Record dynamic linker path (typically `/usr/lib/dyld`).
- `LC_LOAD_DYLIB`: Record required libraries (resolved by dyld at load time).

If the binary requires dyld, the kernel loads both the binary and dyld, and sets the initial PC to dyld's entry point. dyld then resolves libSystem.B.dylib symbols and jumps to the binary's `main`.

---

## 9. Filesystem

### 9.1. VFS Layer

The Virtual Filesystem provides a unified interface across filesystem types:

- **Vnode** abstraction with reference counting.
- **Mount table** supporting multiple simultaneous mounts.
- **Path resolution** with `.` and `..` traversal, symlink following.
- **File descriptor table**: 256 per process, with `dup`/`dup2`/`fork` sharing.
- **Operations**: lookup, read, write, readdir, create, mkdir, unlink, getattr, setattr, readlink.
- **Permission checking**: Integrated Unix DAC at VFS layer (see Section 12.2).

**Vnode structure:**
```c
struct vnode {
    uint32_t    v_refcount;     // Reference count
    enum vtype  v_type;         // VREG, VDIR, VLNK, VCHR, VBLK, VFIFO, VSOCK
    uint64_t    v_ino;          // Inode number
    uint64_t    v_size;         // File size in bytes
    mode_t      v_mode;         // Permission bits
    uid_t       v_uid;          // Owner UID
    gid_t       v_gid;          // Owner GID
    uint32_t    v_nlink;        // Link count
    void       *v_data;         // Filesystem-specific data
    struct vnode_ops *v_ops;    // Filesystem operations
    struct mount *v_mount;      // Mount point
    spinlock_t  v_lock;         // Per-vnode lock
};
```

**Path resolution (`resolve_path`):**
1. Start at root vnode (or cwd for relative paths).
2. For each path component:
   - Check execute permission on current directory.
   - Look up component name in directory.
   - Handle `.` (stay), `..` (parent), symlinks (follow).
3. Return final vnode with reference held.
4. For create/unlink: return parent vnode + last component name.

### 9.2. Ext4 Driver

Full read/write Ext4 implementation supporting:

- **Superblock**: Magic `0xEF53`, dynamic revision.
- **Block groups**: Group descriptor table with free block/inode tracking.
- **Extents** (`EXT4_FEATURE_INCOMPAT_EXTENTS`): Tree-based block allocation with extent header magic `0xF30A`.
- **Legacy block map**: Direct blocks (0–11), indirect (12), double indirect (13), triple indirect (14). Full read/write support for indirect blocks enables files larger than 48KB on 4KB block filesystems.
- **Directories**: Linear and HTree indexed (`EXT4_FEATURE_COMPAT_DIR_INDEX`).
- **Inode sizes**: 128-byte or 256-byte with extended attributes.
- **File types**: Regular, directory, symlink, character device, block device, FIFO, socket.
- **Permissions**: Full POSIX mode bits including SUID, SGID, sticky.
- **64-bit mode** (`EXT4_FEATURE_INCOMPAT_64BIT`): Large volume support.
- **Write support**: File creation, data writing, directory entry insertion, inode allocation, block allocation, metadata update.

**Extent-based file extension (`ext4_extent_alloc_block`):**

When a file needs to grow beyond its current allocation:

1. **Find last extent**: Walk extent tree to find the last extent covering the file.
2. **Try contiguous extension**: Check if the block immediately after the last extent is free. If so, increment `ee_len` (most efficient).
3. **Allocate new extent**: If contiguous extension not possible, find a free block in the same block group (or any block group), create a new extent entry.
4. **Update extent tree**: Insert new extent into the tree, handling splits if needed.
5. **Update inode**: Increment `i_blocks`, update `i_size`, write inode back.

**Block allocation strategy:**
- Prefer same block group as existing data (locality).
- Prefer contiguous blocks when possible (extent-friendly).
- Fall back to any free block in any block group.

**Extent tree structure:**
```
Extent header (12 bytes):
  eh_magic:   0xF30A
  eh_entries: Number of extents/index entries
  eh_max:     Maximum entries capacity
  eh_depth:   0 = leaf (extents), >0 = index nodes

Extent entry (12 bytes):
  ee_block:   Logical block number (file offset / block_size)
  ee_len:     Number of blocks in extent (max 32768)
  ee_start:   Physical block number (48-bit)
```

### 9.3. devfs

In-memory device filesystem mounted at `/dev`:

- `/dev/console` - PL011 UART (backed by console TTY).
- `/dev/null` - Discards writes, reads return EOF.
- `/dev/zero` - Reads return zero bytes.
- `/dev/urandom` - Pseudo-random bytes (LFSR-based).

### 9.4. Buffer Cache

LRU block cache: 256 buffers × 4 KB.

**Operations:**
- `buf_read(dev, blkno)`: Read block, return cached buffer.
- `buf_write(buf)`: Mark buffer dirty, schedule writeback.
- `buf_sync()`: Flush all dirty buffers to disk.

**Buffer states:**
- Clean: Matches on-disk data.
- Dirty: Modified, pending writeback.
- Busy: Currently being read/written.

**Background sync daemon (`bufsync_thread`):**
- Kernel thread started during boot.
- Sleeps for 30 seconds using `thread_sleep_ticks()`.
- Wakes up and calls `buf_sync()` to flush dirty buffers.
- Runs silently (no logging on each sync).
- Also triggered by `sync` syscall and before `reboot`/`halt`.

**Timed sleep implementation:**
- Threads can sleep for a specified number of timer ticks.
- Sleep queue sorted by wakeup time.
- `sched_wakeup_sleepers()` called on each timer tick to wake expired threads.

---

## 10. Terminal Subsystem

### 10.1. Console TTY

Single console TTY backed by PL011 UART with:

- **termios** (72 bytes, matches macOS ARM64 layout).
- **Canonical mode** (`ICANON`): Line-buffered input with editing (backspace, kill, word-erase).
- **Raw mode** (`!ICANON`): Character-at-a-time with `VMIN`/`VTIME`.
- **Echo** (`ECHO`, `ECHOE`, `ECHOCTL`): Character and control-character echo.
- **Signal generation** (`ISIG`): Ctrl-C → `SIGINT`, Ctrl-\ → `SIGQUIT`, Ctrl-Z → `SIGTSTP`.
- **Output processing** (`OPOST`, `ONLCR`): NL → CR+NL mapping.
- **Input processing** (`ICRNL`): CR → NL mapping.
- **Window size** tracking (`TIOCGWINSZ`/`TIOCSWINSZ`), default 80×24.
- **Foreground process group** (`TIOCSPGRP`/`TIOCGPGRP`).
- **UART RX interrupts**: Characters buffered in ring buffer from IRQ context; signal generation works even when no process is reading.

### 10.2. Pseudo-Terminal (PTY) Subsystem

Pool of 16 PTY pairs for remote shell sessions (SSH):

- **Master side**: Read/write file descriptor for the controlling process.
- **Slave side**: Full `struct tty` with termios, line discipline, winsize, process group.
- **Data flow**: Master write → m2s ring buffer → slave reads (with line discipline). Slave write → s2m ring buffer → master reads.
- **Ring buffers**: 4,096 bytes per direction.
- **Syscall**: `openpty(int *master, int *slave, ...)` (syscall 501) - allocates a pair and returns both file descriptors.
- **ioctl**: Slave fd supports all terminal ioctls (`TIOCGETA`, `TIOCSETA`, `TIOCGWINSZ`, `TIOCSWINSZ`, `TIOCSCTTY`, `TIOCSPGRP`, etc.).

---

## 11. Networking

### 11.1. Architecture

```
Application (socket API)
    ↕
BSD Socket Layer (64 sockets, circular 4 KB sockbufs)
    ↕
TCP / UDP / ICMP
    ↕
IPv4 (routing, fragmentation)
    ↕
Ethernet + ARP
    ↕
VirtIO-net Driver (QEMU) / GENET (RPi, planned)
```

### 11.2. VirtIO-net Driver

Full VirtIO MMIO network driver (~530 lines):
- Feature negotiation, virtqueue setup (RX + TX).
- Scatter-gather I/O with VirtIO descriptors.
- Interrupt-driven receive, polled transmit.
- MAC address from VirtIO config space.

### 11.3. Ethernet + ARP

- Ethernet II framing (14-byte header).
- ARP cache with request/reply handling.
- ARP-pending queue: packets waiting for address resolution are queued and transmitted once the ARP reply arrives.

### 11.4. IPv4

- Input demultiplexing by protocol (TCP/UDP/ICMP).
- Output routing: if destination is on the local subnet, ARP directly; otherwise route via gateway.
- Configurable IP address, netmask, and gateway.

### 11.5. TCP

Full RFC 793 state machine (~780 lines):

- **Active open** (client): `SYN_SENT` → `ESTABLISHED` with SYN retransmission.
- **Passive open** (server): `LISTEN` → allocate child socket + TCB on SYN → `SYN_RCVD` → `ESTABLISHED` on ACK.
- **Data transfer**: Segmentation from socket send buffer, delivery to socket receive buffer. `PSH` flag on data segments.
- **Connection teardown**: `FIN_WAIT_1` → `FIN_WAIT_2` → `TIME_WAIT` (active close), `CLOSE_WAIT` → `LAST_ACK` (passive close).
- **RST handling**: In all states. RST sent for segments arriving on non-existent connections.
- **MSS option**: Sent in SYN/SYN-ACK (1460 bytes).
- **Checksum**: Full TCP pseudo-header checksum (RFC 793).
- **SYN retransmission**: In both `SYN_SENT` (client) and `SYN_RCVD` (server, on duplicate SYN).

### 11.6. UDP

Connectionless datagram service (~140 lines). Input demultiplexing by port, output via IP layer.

### 11.7. ICMP

Echo request/reply handling (~160 lines). Supports `ping` from guest and from host.

### 11.8. BSD Socket API

64-socket table with circular 4 KB send/receive buffers per socket.

Supported operations: `socket`, `bind`, `listen`, `accept`, `connect`, `send`/`sendto`, `recv`/`recvfrom`, `shutdown`, `close`, `setsockopt`, `getsockopt`, `getpeername`, `getsockname`.

---

## 12. Security

### 12.1. Credentials

Per-process `struct ucred`:
- Real UID/GID (`cr_ruid`, `cr_rgid`).
- Effective UID/GID (`cr_uid`, `cr_gid`).
- Supplementary group membership list (up to 16 groups).

Root (UID 0) bypasses all permission checks.

Credential handling in `fork()` and `exec()`:
- `fork()`: Child inherits credentials from `proc->p_ucred` (BSD style).
- `setuid()`/`setgid()`: Updates both Mach task credentials and BSD proc credentials.
- `su`/`login`: Call `setgid()` before `setuid()` (must set GID while still root).

### 12.2. VFS Permission Checking

The VFS layer enforces Unix discretionary access control via `vfs_check_permission()`:

**Permission check algorithm:**
```c
if (uid == 0) return ALLOW;  // Root bypasses all checks
if (uid == file_owner)
    check owner bits (mode >> 6) & 0x7
else if (gid == file_group || gid in supplementary_groups)
    check group bits (mode >> 3) & 0x7
else
    check other bits (mode) & 0x7
```

**Operations requiring permission checks:**

| Operation | Permission Required | Target |
|-----------|---------------------|--------|
| `vfs_open(O_RDONLY)` | Read | File |
| `vfs_open(O_WRONLY)` | Write | File |
| `vfs_open(O_RDWR)` | Read + Write | File |
| `vfs_open(O_CREAT)` | Write | Parent directory |
| `vfs_mkdir()` | Write | Parent directory |
| `vfs_unlink()` | Write | Parent directory |
| `vfs_rename()` | Write | Both parent directories |
| Directory traversal | Execute | Each directory in path |

**Error codes:**
- `EACCES` (13): Permission denied.
- `EPERM` (1): Operation not permitted (e.g., non-owner trying to chown).

### 12.3. File Permissions

Standard Unix discretionary access control:
- Owner/group/other read/write/execute bits (9 bits total).
- Special bits: SUID (`S_ISUID` 0o4000), SGID (`S_ISGID` 0o2000), sticky (`S_ISVTX` 0o1000).
- SUID: During `execve()`, set effective UID to file owner.
- SGID: During `execve()`, set effective GID to file group.
- Sticky bit: On directories, only file owner can delete files.

**Mode representation:**
```
15-12  11-9    8-6     5-3     2-0
type   special owner   group   other
       suid    rwx     rwx     rwx
       sgid
       sticky
```

### 12.4. Authentication

- `/etc/passwd`: User database (username:x:UID:GID:comment:home:shell).
- `/etc/shadow`: Password hashes (username:hash:lastchg:min:max:warn:::).
- `/etc/group`: Group database (groupname:x:GID:members).
- `/bin/login`: Authenticates against passwd/shadow, sets GID then UID, spawns shell.
- Default credentials: `root:toor`.

**Password verification:**
- Plain text: `plain:password`
- Hash: `hash:XXXX` (DJB2 hash, hex encoded)
- Locked account: `!` or `*`
- No password: empty field

### 12.5. User Management (macOS-compliant)

**useradd** - Create new user accounts:
- Default home directory: `/Users/<username>` (macOS style, not `/home`)
- UIDs start at 501 (macOS convention for regular users)
- User private group created automatically (same name and GID as UID)
- Home directory created by default with mode 0700
- Skeleton files copied from `/etc/skel/` with correct ownership
- Options: `-d` (home), `-s` (shell), `-g` (primary GID), `-G` (supplementary groups), `-c` (comment), `-u` (UID), `-M` (no home)

**Supplementary groups (-G option):**
```bash
useradd -G wheel,sudo alice  # Add alice to wheel and sudo groups
```
Modifies `/etc/group` to add user to each specified group's member list.

**passwd** - Change user password:
- Minimum password length enforcement
- Updates `/etc/shadow` with new hash
- Root can change any password; users can only change their own

**su** - Switch user:
1. Authenticate target user (unless caller is root)
2. `setgid(target_gid)` - must be done while still root
3. `setuid(target_uid)` - drops root privileges
4. Set environment: `HOME`, `USER`, `LOGNAME`, `SHELL`, `PATH`
5. `chdir(home)` if login shell (`su -`)
6. `execv(shell)`

**login** - User authentication:
1. Read username from terminal
2. Look up user in `/etc/passwd`
3. Read password (with echo disabled)
4. Verify against `/etc/shadow`
5. `setgid(gid)` then `setuid(uid)`
6. Set environment variables
7. `chdir(home)` and `exec(shell)`

---

## 13. Userland

### 13.1. Dynamic Linker (dyld)

Custom Mach-O dynamic linker loaded at `/usr/lib/dyld`:
- Parses `LC_LOAD_DYLIB` commands from the main binary.
- Maps libSystem.B.dylib into the process address space.
- Resolves symbol references via Mach-O symbol table + string table.
- **Sets `environ` in libSystem** before calling main (enables getenv/setenv/execv).
- Jumps to the binary's entry point (`LC_MAIN`).

**Environment variable setup:**

Before calling `main()`, dyld finds and sets the `_environ` symbol in libSystem:
```c
for (uint32_t i = 1; i < num_images; i++) {
    uint64_t environ_addr = lookup_symbol_in_image(&images[i], "_environ");
    if (environ_addr != 0) {
        *(const char ***)environ_addr = envp;
        break;
    }
}
```

This ensures environment variables inherited from the parent process are accessible via `getenv()` and are passed to child processes via `execv()`.

### 13.2. libSystem.B.dylib

Freestanding C library (~3,200 lines) providing:
- **Standard I/O**: `printf`, `fprintf`, `sprintf`, `snprintf`, `vprintf`, `puts`, `putchar`, `fopen`, `fclose`, `fread`, `fwrite`, `fgets`, `fputs`, `fflush`, `feof`, `ferror`.
- **String/memory**: `strlen`, `strcmp`, `strncmp`, `strcpy`, `strncpy`, `strcat`, `strncat`, `strstr`, `strchr`, `strrchr`, `strdup`, `strtok`, `strtok_r`, `memcpy`, `memmove`, `memset`, `memcmp`, `bzero`.
- **Conversion**: `atoi`, `atol`, `strtol`, `strtoul`, `strtoll`, `strtoull`, `strtod`.
- **Memory allocation**: `malloc`, `free`, `calloc`, `realloc` (simple bump allocator with free list).
- **Process**: `fork`, `execve`, `execv`, `execvp`, `exit`, `_exit`, `wait`, `waitpid`, `getpid`, `getppid`, `kill`, `sleep`, `usleep`, `nanosleep`.
- **File I/O**: `open`, `close`, `read`, `write`, `lseek`, `stat`, `fstat`, `lstat`, `access`, `unlink`, `rename`, `mkdir`, `rmdir`, `getcwd`, `chdir`, `dup`, `dup2`, `pipe`, `fcntl`, `ioctl`, `sync`.
- **Ownership**: `chown`, `fchown`, `lchown`, `chmod`, `fchmod`.
- **Signals**: `signal`, `sigaction`, `sigprocmask`, `sigemptyset`, `sigfillset`, `sigaddset`.
- **Networking**: `socket`, `bind`, `listen`, `accept`, `connect`, `send`, `recv`, `sendto`, `recvfrom`, `shutdown`, `setsockopt`, `getsockopt`, `htons`, `htonl`, `ntohs`, `ntohl`, `inet_addr`, `inet_ntoa`.
- **Terminal**: `tcgetattr`, `tcsetattr`, `openpty`, `isatty`, `ttyname`.
- **Time**: `time`, `gettimeofday`, `settimeofday`.
- **Directory**: `opendir`, `readdir`, `closedir`.
- **Environment**: `getenv`, `setenv`, `unsetenv` (modifies `environ` global).
- **System**: `sysctl`, `getentropy`, `sysconf`, `popen`, `pclose`, `system`.
- **Mach**: Inline `__syscall()` wrapper for `svc #0x80`.

### 13.3. Userland Binaries (75 Mach-O executables)

**Shell:** bash (full implementation with lexer, parser, executor, job control, builtins, readline, `time` keyword)

**Compiler:** TCC (Tiny C Compiler) - native C compiler that produces working Mach-O ARM64 binaries

**System daemons:** init, getty, login, halt, reboot, shutdown, sshd

**User management:** useradd, usermod, passwd, su, sudo, whoami, id

**Coreutils:** awk, basename, cat, chmod, chown, clear, cp, curl, cut, date, df, dirname, du, echo, env, expr, false, find, grep, head, hostname, ifconfig, kill, ln, ls, mkdir, mount, mv, nc, ntpdate, ping, printf, ps, rm, rmdir, sed, sleep, sort, sync, tail, tee, test, time, timeout, touch, tr, true, umount, uname, uniq, wc, which, xargs, yes

All compiled with `clang -target arm64-apple-macos11` using the macOS SDK headers, producing standard Mach-O binaries that link against libSystem.B.dylib.

### 13.4. TCC (Tiny C Compiler)

Kiseki includes a fully functional port of TCC that runs natively and produces ARM64 Mach-O executables:

**Capabilities:**
- Compiles C99 code to ARM64 machine code
- Generates proper Mach-O executable format with LC_MAIN, LC_LOAD_DYLIB, LC_LOAD_DYLINKER
- Dynamic linking against libSystem.B.dylib
- Produces binaries that work identically to clang-compiled ones

**Usage:**
```bash
# Compile and run a C program on Kiseki
echo '#include <stdio.h>
int main() { printf("Hello from TCC!\\n"); return 0; }' > hello.c
tcc -o hello hello.c
./hello
```

**Implementation notes:**
- Custom `tccmacho.c` backend generates Mach-O instead of ELF
- ARM64 code generation via `arm64-gen.c`
- Stub generation for lazy symbol binding (dyld compatibility)
- String constants properly placed in `__DATA,__data` section

---

## 14. Exception Handling

### 14.1. Trap Frame

288-byte structure saved on every exception:

| Offset | Field | Description |
|---|---|---|
| 0–240 | `regs[31]` | x0–x30 |
| 248 | `sp` | SP_EL0 (user traps) |
| 256 | `elr` | Exception Link Register (return PC) |
| 264 | `spsr` | Saved Program Status Register |
| 272 | `esr` | Exception Syndrome Register |
| 280 | `far` | Fault Address Register |

### 14.2. Exception Classes

| EC | Name | Handler |
|---|---|---|
| `0x15` | SVC from AArch64 | `syscall_handler()` - BSD/Mach dispatch |
| `0x20` | Instruction abort (lower EL) | Demand paging or `SIGSEGV` |
| `0x24` | Data abort (lower EL) | Copy-on-write, demand paging, or `SIGSEGV` |
| `0x22` | PC alignment fault | `SIGBUS` |
| `0x26` | SP alignment fault | `SIGBUS` |
| `0x3C` | BRK instruction | `SIGTRAP` |

### 14.3. IRQ Dispatch

Timer interrupt (100 Hz) → `sched_tick()`.
UART0 RX interrupt (IRQ 33) → `uart_irq_handler()` → `tty_input_char()`.
VirtIO-net interrupt → packet receive.

---

## 15. Directory Structure

```
kiseki/
├── Makefile                        # Top-level kernel build + QEMU run
├── README.md                       # Project overview
├── docs/
│   └── spec.md                     # This specification
├── scripts/
│   └── mkdisk.sh                   # 64 MB ext4 root filesystem builder
├── kernel/                         # ~21,000 lines
│   ├── arch/arm64/                 # ARM64-specific (boot, vectors, context switch, SMP)
│   ├── kern/                       # Core kernel (scheduler, processes, VMM, PMM, TTY, PTY, sync)
│   ├── bsd/                        # BSD personality (syscalls, security)
│   ├── mach/                       # Mach microkernel (IPC, ports)
│   ├── fs/                         # Filesystems (VFS, Ext4, devfs, buffer cache)
│   ├── net/                        # Networking (sockets, TCP, UDP, IP, ICMP, Ethernet, ARP)
│   ├── drivers/                    # Device drivers (UART, GIC, timer, VirtIO, eMMC)
│   └── include/                    # 26 kernel headers
├── userland/                       # ~40,000 lines
│   ├── Makefile                    # Master userland build
│   ├── dyld/                       # Dynamic linker
│   ├── libsystem/                  # libSystem.B.dylib (~3,100 lines)
│   ├── bin/                        # 59 coreutils + bash
│   └── sbin/                       # System binaries (init, getty, login, halt)
└── tests/                          # Unit test framework
```

---

## 16. Build System

### 16.1. Kernel

Cross-compiled with `aarch64-elf-gcc`:
- `-ffreestanding -fno-builtin -fno-stack-protector -nostdinc -nostdlib`
- `-mcpu=cortex-a72 -mgeneral-regs-only`
- `-std=gnu11 -O2 -g`
- `-Werror`

Linked with custom linker script (`linker-qemu.ld` or `linker-raspi4.ld`). Output: ELF for QEMU direct kernel boot, binary for bare-metal.

### 16.2. Userland

Compiled with macOS `clang`:
- `-target arm64-apple-macos11 -isysroot $(xcrun --show-sdk-path)`
- `-Wall -Wextra -O2`
- Links dynamically against `/usr/lib/libSystem.B.dylib`

libSystem.B.dylib is compiled as a Mach-O shared library (`MH_DYLIB`).

### 16.3. Disk Image

`scripts/mkdisk.sh` creates a 64 MB ext4 image with:
- Standard Unix hierarchy (`/bin`, `/sbin`, `/usr`, `/etc`, `/dev`, `/tmp`, `/var`, `/home`)
- All 68 Mach-O binaries
- `/usr/lib/dyld` and `/usr/lib/libSystem.B.dylib`
- `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/profile`

---

**End of Specification**
