# Kiseki OS

A hybrid kernel operating system for ARM64 that runs **unmodified macOS Mach-O binaries** on non-Apple hardware, with a full graphical desktop matching the macOS architecture from kernel to AppKit.

Kiseki implements the Darwin/XNU kernel-user ABI — Mach traps, BSD syscalls, Mach-O loading, dyld — from scratch in C and ARM64 assembly, then builds the entire GUI stack on top: IOKit, WindowServer, CoreFoundation, CoreGraphics, CoreText, Foundation, and AppKit. You compile a program on your Mac with `clang -target arm64-apple-macos11`, copy the binary to a Kiseki disk image, and it runs.

## Why "Kiseki"?

奇跡 (kiseki) is the Japanese word for **miracle**.

Running native macOS binaries on bare-metal non-Apple hardware — without Apple's kernel, without Apple's bootloader, without any of Apple's code — is the kind of thing that shouldn't be possible. The Mach-O format, the XNU syscall conventions, the Darwin ABI — these were designed for a vertically integrated stack. Reproducing enough of that stack to make real binaries think they're on macOS, on a QEMU virt machine or a Raspberry Pi, is an act of unreasonable ambition.

The name is also a nod to the project's origin: the miracle of starting with nothing — no operating system, no standard library, no file system — just a UART printing characters to a serial console — and ending up with a multi-user graphical Unix system running bash, 68 coreutils, a TCP/IP stack, an Objective-C runtime, and a full macOS-style desktop with Finder, Terminal, and a window compositor.

Every working syscall is a small miracle. Every binary that loads and runs is another. The project is the sum of these miracles.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   GUI Applications (Mach-O)                  │
│  Dock.app · Finder.app · Terminal.app · SystemUIServer.app   │
│                      loginwindow                             │
├─────────────────────────────────────────────────────────────┤
│                    Framework Stack                            │
│  AppKit · Foundation · CoreText · CoreGraphics               │
│  CoreFoundation · libobjc2 (GNUstep)                         │
├─────────────────────────────────────────────────────────────┤
│                      WindowServer                            │
│  Quartz compositor · Mach IPC protocol · HID dispatch        │
├─────────────────────────────────────────────────────────────┤
│                  CLI Userland (Mach-O)                        │
│  bash, ls, cat, grep, awk, sed, curl, nc, tcc, ps...         │
│          libSystem.B.dylib  ←  dyld                          │
├─────────────────────────────────────────────────────────────┤
│             svc #0x80 (syscall gate)                         │
│         x16 > 0 → BSD    x16 < 0 → Mach                     │
├──────────────────────┬──────────────────────────────────────┤
│   BSD Personality     │      Mach Microkernel                │
│  POSIX syscalls       │  IPC, tasks, threads                 │
│  VFS, processes       │  ports, messages                     │
│  signals, pipes       │  semaphores                          │
├──────────────────────┴──────────────────────────────────────┤
│                    Kernel Core                                │
│  Scheduler (MLFQ) · SMP (4 cores) · VMM (4K pages, COW)     │
│  PMM (buddy) · TTY · PTY · Spinlocks · Mutexes              │
├─────────────────────────────────────────────────────────────┤
│                      IOKit                                    │
│  IOFramebuffer · IOHIDSystem · IOMemoryDescriptor            │
│  IOServiceMatching · IOUserClient · I/O Registry             │
├─────────────────────────────────────────────────────────────┤
│                      Drivers                                  │
│  VirtIO-GPU · VirtIO-input · VirtIO-blk · VirtIO-net        │
│  PL011 UART · GICv2 · ARM Timer · eMMC (RPi)                │
├─────────────────────────────────────────────────────────────┤
│                    Filesystems                                │
│  Ext4 (read/write) · devfs · Buffer cache                    │
├─────────────────────────────────────────────────────────────┤
│                     Networking                                │
│  Ethernet · ARP · IPv4 · TCP · UDP · ICMP                    │
│  BSD socket API · DNS (mDNSResponder)                         │
└─────────────────────────────────────────────────────────────┘
```

**Kernel type:** Hybrid (Mach microkernel + BSD personality), following the XNU architecture.

**Binary format:** Mach-O 64-bit exclusively. No ELF. Normal macOS ARM64 binaries run unmodified.

**Syscall interface:** `svc #0x80`, syscall number in `x16`. Positive = BSD, negative = Mach trap. Error convention: carry flag set in PSTATE, positive errno in `x0`.

## Features

### Kernel
- 4-core SMP with per-CPU run queues, IPI support, and SMP-safe synchronisation
- Pre-emptive multitasking with multilevel feedback queue scheduler
- Full virtual memory management (4K pages, per-process page tables, ASID tagging)
- Demand paging with copy-on-write fork
- FP/NEON state save/restore (q0-q31, FPCR, FPSR) on user↔kernel transitions
- Mach-O binary loader with ASLR, LC_SEGMENT_64, LC_MAIN, LC_LOAD_DYLINKER
- Custom dyld (dynamic linker) resolving libSystem symbols at load time
- 100+ BSD syscalls (fork, exec, pipe, dup2, select, mmap, signals, sockets...)
- Mach traps (task_self, mach_msg, semaphore operations, thread_self, port_allocate/deallocate)
- Mach IPC with per-task port name spaces, full port right translation, and OOL memory descriptors
- Bootstrap service registry (register, look_up, check_in) for launchd-style daemon management
- IOKit device framework (IOFramebuffer, IOHIDSystem, user clients, memory mapping)
- CommPage at `0xFFFFFFFFFFFFC000` with optimised gettimeofday and sigreturn trampoline
- Full termios/TTY subsystem with canonical and raw modes
- Pseudo-terminal (PTY) subsystem for terminal emulator sessions
- Signal delivery with proper handler dispatch, sigreturn, and process group signals

### Graphics & GUI
- **VirtIO GPU** 2D framebuffer driver (1280×800, 32-bit BGRX)
- **VirtIO input** driver for keyboard (US QWERTY) and tablet (absolute coordinates)
- **IOKit** device framework matching macOS: IOFramebuffer, IOHIDSystem, IOMemoryDescriptor, user client connections, MMIO memory mapping to user space
- **WindowServer** — Quartz-like display compositor communicating via Mach IPC
  - Back-to-front painter's algorithm compositing
  - Per-window pixel buffers received via OOL Mach messages
  - HID event ring buffer shared with kernel via IOHIDSystem
  - Window management: create, destroy, order front/back, move, resize, focus
  - Menu bar rendering, desktop background, cursor drawing
- **Objective-C runtime** — GNUstep libobjc2 (ABI v1), compiled with `clang -fobjc-runtime=gnustep-1.9`
- **Framework stack** matching macOS layering:
  - **CoreFoundation** — CFString, CFArray, CFDictionary, CFRunLoop, CFSocket
  - **CoreGraphics** — CGBitmapContext, CGPath, CGFont, affine transforms, Quartz 2D drawing
  - **CoreText** — CTFont, CTLine, glyph rendering with built-in bitmap font
  - **Foundation** — NSObject, NSString, NSArray, NSDictionary, NSRunLoop, NSAutoreleasePool, NSNotificationCenter
  - **AppKit** — NSApplication, NSWindow, NSView, NSEvent, NSResponder chain, NSMenu, NSTextField, NSButton, NSControl/NSCell
- **GUI Applications:**
  - **Dock.app** (`/System/Library/CoreServices/`) — Desktop wallpaper + dock bar
  - **Finder.app** (`/System/Library/CoreServices/`) — File browser with sidebar, directory navigation, double-click-to-launch
  - **Terminal.app** (`/Applications/`) — VT100 terminal emulator backed by PTY, running bash
  - **SystemUIServer.app** (`/System/Library/CoreServices/`) — Menu bar clock
  - **loginwindow** (`/sbin/`) — Graphical login screen, GUI session launcher

### Filesystems
- Ext4 read/write with extents, directory indexing, block groups
- **Extent-based file extension**: Allocates new blocks and extends extent tree
- **Indirect block support**: Single/double/triple indirect blocks for large files (>48KB)
- VFS layer with mount points, path resolution, file descriptor management
- **VFS permission model**: Unix owner/group/other with root bypass
- devfs for `/dev/console`, `/dev/null`, `/dev/zero`, `/dev/urandom`
- **Buffer cache sync daemon**: Background kernel thread flushes dirty buffers every 30s
- 64MB root filesystem with standard Unix directory hierarchy

### Networking
- Full TCP/IP stack (not a stub — real implementations)
- VirtIO-net driver for QEMU, planned genet for Raspberry Pi
- Ethernet framing with ARP cache and neighbour resolution
- IPv4 routing with configurable gateway and netmask
- TCP: full state machine, three-way handshake, active and passive open, FIN/RST, retransmission
- UDP: connectionless datagram support with auto-binding of ephemeral ports
- ICMP: echo request/reply (ping)
- DNS resolution via mDNSResponder daemon (getaddrinfo → Mach IPC → UDP DNS)
- `/etc/resolv.conf` support with fallback to DHCP-provided DNS
- BSD socket API: socket, bind, listen, accept, connect, send, recv, shutdown, close

### Userland
- **82 Mach-O executables** on the root filesystem (68 in `/bin`, 10 in `/sbin`, 4 GUI apps)
- **6 frameworks** as Mach-O dylibs (IOKit, CoreFoundation, CoreGraphics, CoreText, Foundation, AppKit)
- **TCC (Tiny C Compiler)**: Native C compiler that runs on Kiseki and produces working Mach-O binaries
- Full bash shell with job control, pipelines, redirections, `time` keyword
- 68 coreutils: ls, cat, grep, awk, sed, sort, find, wc, cut, head, tail, tr, xargs, vi, and more
- System daemons: init (launchd), getty, login, mDNSResponder, sshd, WindowServer, loginwindow
- Network tools: curl, nc, ping, ifconfig, ntpdate
- User management: useradd, usermod, passwd, su, sudo, whoami, id
- Power management: halt, reboot, shutdown
- libSystem.B.dylib: complete freestanding C library (~7,950 lines)
- libobjc.A.dylib: GNUstep Objective-C runtime
- **Unit test suite**: Comprehensive libSystem tests (string.h, stdlib.h, stdio.h, unistd.h, etc.)

### Security

Kiseki implements security mechanisms that mirror the macOS/Darwin model. This section is written for security engineers — it explains what protections exist, how they work at the hardware and kernel level, and where the current implementation diverges from production macOS.

#### Memory Isolation (EL0/EL1 Separation)

ARM64 provides two translation table base registers: TTBR0_EL1 for user space (lower half) and TTBR1_EL1 for kernel space (upper half). Kiseki uses per-process page tables (switched via TTBR0 on context switch) with 8-bit ASIDs (Address Space Identifiers) to tag TLB entries per process, avoiding full TLB flushes on most context switches. Each process has a completely independent set of L0→L3 page tables, so a corrupted page table in one process cannot affect another.

At the syscall boundary (`svc #0x80`), execution transitions from EL0 (user mode) to EL1 (kernel mode). The exception vector saves the full CPU state — including all 31 GPRs, SP, ELR, SPSR, ESR, FAR, and the complete FP/NEON state (FPCR, FPSR, q0-q31) — into an 816-byte trap frame on the kernel stack. This prevents user register state from leaking into kernel context or vice versa.

#### ASLR (Address Space Layout Randomisation)

Kiseki implements **PIE (Position-Independent Executable) ASLR** for user binaries. When a Mach-O binary is loaded, the kernel reads the ARM generic timer counter (`cntvct_el0`) as an entropy source and computes a random "slide" — an offset added to every segment's load address. The slide is 16MB-aligned with 4 bits of entropy (16 possible positions in a 256MB range). dyld inherits a separate slide derived from the main binary's virtual memory ceiling.

**What's missing vs. macOS:** Stack base, mmap base, and heap base are currently at fixed addresses. macOS randomises all of these independently. The entropy pool (4 bits) is smaller than macOS's (which uses ~16 bits for the main binary slide on arm64). There is no KASLR — the kernel loads at a fixed physical address (`0x40080000`).

#### W^X (Write XOR Execute) Enforcement

The Mach-O loader maps segments with correct hardware page protections derived from the binary's `vm_prot` flags:
- `__TEXT` segments → `PTE_USER_RX` (read + execute, no write)
- `__DATA` segments → `PTE_USER_RW` (read + write, no execute — both `PTE_PXN` and `PTE_UXN` set)
- `__LINKEDIT` → `PTE_USER_RO` (read-only)

ARM64 provides separate execute-never bits for user (`PTE_UXN`) and kernel (`PTE_PXN`). All user data pages have `PTE_UXN` set, preventing code execution from the stack, heap, or any writable data region. Kernel code pages have `PTE_PXN` clear but `PTE_UXN` set, so user-space code cannot be executed at EL1.

**What's missing vs. macOS:** The `mmap` syscall permits `PROT_READ|PROT_WRITE|PROT_EXEC` (RWX) mappings if requested — there is no kernel-enforced W^X policy rejecting such requests. macOS enforces code signing and restricts RWX pages via the `MAP_JIT` entitlement. The kernel itself maps all RAM as RWX in the identity map (no kernel-side W^X separation).

#### __PAGEZERO and Null Dereference Prevention

Every Mach-O binary contains a `__PAGEZERO` segment covering virtual addresses 0 through 4GB. The kernel's Mach-O loader recognises this segment and skips mapping it, leaving the first 4GB of user virtual address space as an unmapped hole. Any null pointer dereference (or dereference of a small integer cast to a pointer) triggers a page fault that the kernel handles as `SIGSEGV`. This matches the macOS/iOS behaviour and prevents an entire class of null-pointer exploitation.

#### Mach Port Name Space Isolation

Mach IPC security relies on **port name spaces**: every process has its own mapping from integer "names" (like file descriptors) to kernel port objects. A port name `5` in process A refers to a completely different kernel port than name `5` in process B. The kernel validates every port name against the calling task's own `ipc_space` table — out-of-range or inactive names return `KERN_INVALID_NAME`. Port rights (send, receive, send-once) are tracked per-entry and verified on every `mach_msg` send/receive operation.

This means a process cannot forge port names to access another process's ports. The only way to obtain a send right to a port is through legitimate IPC (e.g., `bootstrap_look_up`, or receiving a port right in a Mach message). This is the same security model used by macOS for inter-process communication.

#### Copy-on-Write Security

When `fork()` creates a child process, the kernel does not immediately copy the parent's memory. Instead, it marks all writable pages as **read-only** in both parent and child, with a software-defined COW bit (PTE bit 55) set. When either process writes to a COW page, the resulting page fault triggers the COW handler, which:
1. Checks the page's reference count
2. If shared (refcount > 1): allocates a fresh physical page, copies the 4KB data, maps the new page as writable, decrements the old page's refcount
3. If sole owner (refcount == 1): simply re-marks the page as writable (no copy needed)

The parent's TLB entries are immediately invalidated after COW marking to prevent stale writable entries from bypassing the protection. This prevents data leakage between forked processes and matches the XNU COW implementation.

#### CommPage (Read-Only Shared Kernel-User Page)

The CommPage is a single physical page mapped at a fixed user-space address (`0xFFFFFFFFFFFFC000`) with `PTE_USER_RX` (read + execute, no write). It contains:
- `gettimeofday` stub — reads the ARM generic timer directly, avoiding a syscall
- `nanotime` stub — high-resolution timestamp without kernel entry
- `sigreturn` trampoline — the return-from-signal-handler code

The CommPage is shared across all processes (same physical page) but is read-only from user space, so no process can modify the stubs to attack other processes. This matches the macOS CommPage at the same canonical address.

#### Signal Delivery and Sigreturn

When the kernel delivers a signal to a user process, it saves the current trap frame (register state) onto the user stack, sets up the user's registered signal handler as the new PC, and sets the link register (LR) to the CommPage sigreturn trampoline. When the handler returns, the trampoline executes `sigreturn(2)`, which restores the saved register state.

**Known weakness:** The kernel's `sys_sigreturn` reads the saved trap frame from user-controlled stack memory without a cryptographic token or canary to verify it was placed there by the kernel. This means a **Sigreturn-Oriented Programming (SROP)** attack could forge arbitrary register state (including PC) by placing a crafted trap frame on the stack and calling sigreturn. macOS mitigates this with PAC (Pointer Authentication Codes) on the saved state; Kiseki does not yet implement PAC.

#### Stack Canaries

Userland binaries compiled with `-fstack-protector` use a stack canary (guard value) to detect buffer overflows. libSystem provides `__stack_chk_guard` and `__stack_chk_fail`. However, the guard value is currently a **static compile-time constant** rather than a per-process random value initialised from `/dev/urandom` at startup. This means the canary value is predictable, significantly weakening the protection. The kernel itself is compiled with `-fno-stack-protector`.

#### GOT/PLT and Dynamic Linking

dyld resolves all symbol bindings eagerly at load time (no lazy binding), which eliminates the attack surface of writable `__la_symbol_ptr` stubs that lazy binding would require. However, after symbol resolution, the GOT (Global Offset Table) sections remain writable — dyld does not call `mprotect` to make them read-only (no RELRO equivalent). A memory corruption primitive that can write to the GOT can redirect function calls to arbitrary addresses.

#### Credential Management (Unix DAC)

Each process carries a `ucred` structure with real/effective/saved UID and GID, plus supplementary groups. The `execve` path checks for SUID/SGID bits on the binary and elevates credentials accordingly. `setuid`/`setgid` syscalls require `euid == 0` for arbitrary changes. File access is checked via `vfs_access()` implementing standard Unix owner/group/other permission bits, with root (uid 0) bypassing all checks.

#### What's NOT Implemented (vs. macOS)

| Feature | macOS | Kiseki | Notes |
|---------|-------|--------|-------|
| KASLR | Yes (kernel slide) | No | Kernel at fixed address |
| PAN (Privileged Access Never) | Yes | No | Kernel can read/write user memory directly |
| PAC (Pointer Authentication) | Yes (ARMv8.3+) | No | Target CPU is ARMv8.0 (Cortex-A72) |
| MTE (Memory Tagging) | Yes (ARMv8.5+) | No | Not available on Cortex-A72 |
| Code signing | Yes (mandatory) | No | Any Mach-O binary runs |
| Sandbox (App Sandbox) | Yes (Seatbelt) | No | No sandboxing |
| System Integrity Protection | Yes (SIP) | No | Root has full access |
| RELRO (read-only GOT) | Yes | No | GOT remains writable |
| Per-process stack canary | Yes (random) | No | Static constant |
| Stack randomisation | Yes | No | Fixed stack top |
| mmap ASLR | Yes | No | Fixed mmap base |
| Kernel W^X | Yes | No | Kernel RAM is RWX |
| Secure sigreturn (PAC) | Yes | No | SROP possible |

### User Management (macOS-compliant)
- `useradd`: Creates users with home directories in `/Users/<username>`
- UIDs start at 501 (macOS convention)
- User private groups created automatically
- Skeleton files copied from `/etc/skel` with correct ownership
- Supplementary groups via `-G wheel,sudo` option
- `passwd`: Password management with strength checking
- `su`: Switch user with proper setgid/setuid sequence
- `login`: Full PAM-style authentication flow
- Default root password: `toor`

## Building

### Prerequisites

- macOS host (for Mach-O userland compilation)
- `aarch64-elf-gcc` cross-compiler (kernel)
- QEMU with `qemu-system-aarch64`
- LLVM (`llc` for ObjC COMDAT-stripping pipeline)
- Xcode Command Line Tools (provides macOS SDK)

```bash
# Install cross-compiler (macOS)
brew install aarch64-elf-gcc

# Install QEMU
brew install qemu

# Install LLVM (for ObjC compilation pipeline)
brew install llvm
```

### Build Commands

```bash
# Build kernel only
make -j4

# Build all userland (dyld + libSystem + frameworks + 82 binaries)
make -C userland all

# Create root filesystem disk image
./scripts/mkdisk.sh build/disk.img

# Boot in QEMU
make run

# Build everything at once
make world

# Run automated libSystem unit tests
make test-kiseki
```

### QEMU Configuration

The default QEMU invocation uses:
- `virt` machine with Cortex-A72 CPU (ARMv8.0), 4 cores, 4GB RAM
- TCG accelerator (software emulation)
- Cocoa display backend (native macOS window)
- VirtIO block device for the root filesystem
- VirtIO network device with vmnet-shared (guest gets real LAN IP)
- VirtIO GPU device (1280×800 framebuffer)
- VirtIO keyboard and tablet (absolute pointing) input devices
- Guest IP: `192.168.64.10`, Gateway: `192.168.64.1`

## Boot Sequence

```
Power On
  → boot.S: Set up EL1, MMU, stack, wake secondary cores via PSCI
  → main.c: Initialize subsystems in order:
      GIC → UART → PMM → VMM → Timer → Scheduler → SMP →
      Block devices → VFS → Ext4 → devfs → Buffer cache →
      Mach IPC → IOKit → CommPage → Processes → Network →
      VirtIO GPU → IOFramebuffer → Framebuffer console →
      VirtIO input → IOHIDSystem →
      Load /sbin/init from Mach-O
  → init (launchd): Parse /System/Library/LaunchDaemons/*.plist,
      pre-create Mach service ports, fork/exec daemons
      (WindowServer, loginwindow, mDNSResponder)
  → WindowServer: Maps VRAM via IOKit, enters compositor event loop
  → loginwindow: Connects to WindowServer via Mach IPC,
      displays graphical login, authenticates user
  → GUI session: loginwindow fork/execs Dock, Finder,
      SystemUIServer, Terminal
  → Terminal.app: Opens PTY, fork/execs /bin/bash
  → bash: Interactive shell session
```

## Project Structure

```
kiseki/
├── Makefile                        # Top-level build (kernel + QEMU)
├── README.md
├── docs/
│   ├── kiseki-internals.md         # Comprehensive internals guide (~5,500 lines)
│   ├── spec.md                     # Architecture specification
│   ├── development-guide.md        # Development guide and conventions
│   ├── implementing-syscalls.md    # Guide to adding new syscalls
│   └── porting-software.md         # Guide to porting software to Kiseki
├── scripts/
│   └── mkdisk.sh                   # Root filesystem image builder
├── config/
│   └── LaunchDaemons/              # Launchd plist files for system daemons
├── kernel/
│   ├── arch/arm64/
│   │   ├── boot.S                  # Entry point, EL2→EL1, MMU setup
│   │   ├── vectors.S               # Exception vector table (NEON save/restore)
│   │   ├── context_switch.S        # Thread context save/restore (+ d8-d15 NEON)
│   │   └── smp.c                   # Secondary core bringup (PSCI)
│   ├── kern/
│   │   ├── main.c                  # Kernel main, 22-phase boot sequence
│   │   ├── proc.c                  # Process management, fork, exec
│   │   ├── sched.c                 # MLFQ scheduler (SMP-safe)
│   │   ├── vmm.c                   # Virtual memory, page tables, COW
│   │   ├── pmm.c                   # Buddy physical memory allocator
│   │   ├── trap.c                  # Exception/interrupt dispatch
│   │   ├── tty.c                   # Terminal line discipline
│   │   ├��─ pty.c                   # Pseudo-terminal pairs
│   │   ├── sync.c                  # Spinlocks, mutexes (SMP-safe)
│   │   ├── macho.c                 # Mach-O binary loader (ASLR)
│   │   ├── commpage.c              # CommPage (sigreturn trampoline)
│   │   ├── fbconsole.c             # Framebuffer text console
│   │   └── kprintf.c              # Kernel printf (SMP spinlock)
│   ├── bsd/
│   │   ├── syscalls.c              # BSD syscall dispatch (~5,400 lines)
│   │   └── security.c             # Credential checks, SUID, DAC
│   ├── mach/
│   │   └── ipc.c                   # Mach IPC, ports, bootstrap, OOL (~2,500 lines)
│   ├��─ iokit/
│   │   ├── iokit.c                 # IOKit core, registry, matching
│   │   ├── io_framebuffer.c        # IOFramebuffer driver (VirtIO GPU)
│   │   ├── io_hid.c               # IOHIDSystem driver (input events)
│   │   └── io_memory_descriptor.c  # User-space memory mapping
│   ├── fs/
│   │   ├── vfs.c                   # Virtual filesystem layer
│   │   ├── ext4/ext4.c             # Ext4 read/write driver
│   │   ├── devfs.c                 # Device filesystem
│   │   └── buf.c                   # Block buffer cache
│   ├── net/
│   │   ├── socket.c                # BSD socket layer
│   │   ├── tcp.c                   # TCP state machine
│   │   ├── ip.c                    # IPv4 routing
│   │   ├── eth.c                   # Ethernet + ARP
│   │   ├── udp.c                   # UDP
│   │   └── icmp.c                  # ICMP echo
│   ├── drivers/
│   │   ├── uart/pl011.c            # PL011 UART (QEMU)
│   │   ├── gic/gicv2.c             # ARM GIC interrupt controller
│   │   ├── timer/timer.c           # ARM generic timer (SMP-safe)
│   │   ├── virtio/virtio_blk.c     # VirtIO block device
│   │   ├── virtio/virtio_net.c     # VirtIO network device
│   │   ├── virtio/virtio_gpu.c     # VirtIO GPU 2D framebuffer
│   │   ├── virtio/virtio_input.c   # VirtIO keyboard + tablet
│   │   └── blkdev/blkdev.c         # Block device abstraction
│   └── include/                    # Kernel headers (42 files)
├── userland/
│   ├── Makefile                    # Userland master build
│   ├── dyld/                       # Dynamic linker (Mach-O)
│   ├── libsystem/
│   │   ├── libSystem.c             # Freestanding C library (~7,950 lines)
│   │   └��─ include/                # Userland headers
│   ├── libobjc/                    # GNUstep libobjc2 runtime
│   ├── CoreFoundation/             # CF framework (CFString, CFRunLoop, ...)
│   ├── CoreGraphics/               # Quartz 2D drawing (~3,200 lines)
│   ├── CoreText/                   # Text rendering (CTFont, CTLine)
│   ├── Foundation/                 # ObjC foundation (NSString, NSArray, ...)
│   ├── AppKit/                     # GUI toolkit (~3,400 lines)
│   ├── IOKit/                      # IOKit client library
│   ├── bin/                        # 68 coreutils + bash + TCC
│   │   ├── bash/                   # Full bash implementation
│   │   ├── awk/                    # AWK interpreter
│   │   ├── sed/                    # Stream editor
│   │   ├── grep/                   # Pattern matcher
│   │   ├── curl/                   # HTTP client
│   │   ├── vi/                     # Text editor
│   │   └── ...                     # ls, cat, cp, mv, rm, ps, kill, etc.
│   ├── sbin/
│   │   ├── init.c                  # PID 1 / launchd (~980 lines)
│   │   ├── WindowServer.c          # Display compositor (~1,850 lines)
│   │   ├── loginwindow.c           # Graphical login manager (~980 lines)
│   │   ├── mDNSResponder.c         # DNS resolution daemon
│   │   ├── getty.c                 # Terminal login prompt
│   │   ├── login.c                 # User authentication
│   │   └── halt.c                  # System shutdown/reboot
│   └── apps/
│       ├── Dock.app/               # Desktop wallpaper + dock bar
│       ├── Finder.app/             # File browser
│       ├── Terminal.app/           # VT100 terminal emulator
│       └── SystemUIServer.app/     # Menu bar clock
└── tests/                          # Unit test framework
```

## Code Statistics

| Component | Files | Lines |
|-----------|-------|-------|
| Kernel (C + ASM) | 53 | ~38,500 |
| Kernel headers | 42 | ~9,500 |
| Userland (C + H + ObjC) | 294 | ~139,000 |
| **Total** | **~389** | **~187,000** |

## Roadmap

- [x] Hybrid kernel (Mach + BSD)
- [x] Mach-O loader + dyld
- [x] Ext4 filesystem (read/write)
- [x] SMP (4 cores)
- [x] Pre-emptive multitasking
- [x] Full bash shell
- [x] 68 coreutils
- [x] TCP/IP networking stack
- [x] PTY subsystem
- [x] Native C compiler (TCC)
- [x] Mach IPC with per-task port spaces and port right translation
- [x] Launchd-style init with plist parsing and service port pre-creation
- [x] DNS resolution (getaddrinfo → mDNSResponder → UDP DNS)
- [x] IOKit device framework (IOFramebuffer, IOHIDSystem)
- [x] VirtIO GPU framebuffer + VirtIO input drivers
- [x] WindowServer compositor with Mach IPC protocol
- [x] Objective-C runtime (GNUstep libobjc2)
- [x] Framework stack (CoreFoundation → CoreGraphics → CoreText → Foundation → AppKit)
- [x] Graphical desktop (Dock, Finder, Terminal, SystemUIServer, loginwindow)
- [ ] SSH server (in progress — transport working, crypto stubs remain)
- [ ] Lua interpreter
- [ ] Python interpreter

## License

This project is a research and educational endeavour in operating system construction.
