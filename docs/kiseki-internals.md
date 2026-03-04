# Kiseki OS Internals

### A Comprehensive Guide to Building a macOS-Compatible Operating System from Scratch

**Target audience:** Software engineers comfortable reading C code but with no systems-programming or OS-development background. Every concept — from CPU privilege levels to page tables to Mach ports — is explained from first principles. No prior knowledge of ARM64 assembly, kernel development, or operating system theory is assumed.

**Codebase reference:** All line numbers and code references point to the Kiseki repository as of the latest commit on `origin/main`. Where relevant, XNU source code from [apple-oss-distributions/xnu](https://github.com/apple-oss-distributions/xnu/) is cited for comparison.

**Codebase statistics:**

| Component | Files | Lines of Code |
|-----------|------:|-------------:|
| Kernel C source | 50 | 37,850 |
| Kernel assembly (ARM64) | 3 | 717 |
| Kernel headers | 42 | 9,478 |
| Userland C/ObjC source | 167 | 114,968 |
| Userland assembly | 8 | ~600 |
| Userland headers | 127 | ~8,000 |
| **Total** | **~397** | **~171,600** |

---

## Table of Contents

- [Chapter 1: Introduction & Overview](#chapter-1-introduction--overview)
  - [1.1 What Is Kiseki?](#11-what-is-kiseki)
  - [1.2 Architecture at a Glance](#12-architecture-at-a-glance)
  - [1.3 How macOS Works (The 10,000-Foot View)](#13-how-macos-works-the-10000-foot-view)
  - [1.4 Hardware Target](#14-hardware-target)
  - [1.5 Codebase Map](#15-codebase-map)
- [Chapter 2: ARM64 Boot & Early Initialisation](#chapter-2-arm64-boot--early-initialisation)
  - [2.1 Five Foundational Concepts](#21-five-foundational-concepts)
  - [2.2 The Boot Sequence (boot.S)](#22-the-boot-sequence-boots)
  - [2.3 The Vector Table (vectors.S)](#23-the-vector-table-vectorss)
  - [2.4 Context Switching (context_switch.S)](#24-context-switching-context_switchs)
  - [2.5 The 17-Phase Kernel Bootstrap (kmain)](#25-the-17-phase-kernel-bootstrap-kmain)
  - [2.6 Secondary Core Bring-Up (SMP)](#26-secondary-core-bring-up-smp)
- [Chapter 3: Physical & Virtual Memory](#chapter-3-physical--virtual-memory)
  - [3.1 Why Virtual Memory Exists](#31-why-virtual-memory-exists)
  - [3.2 The Buddy Allocator (PMM)](#32-the-buddy-allocator-pmm)
  - [3.3 ARM64 Page Tables](#33-arm64-page-tables)
  - [3.4 Kernel Address Space Setup](#34-kernel-address-space-setup)
  - [3.5 User Address Spaces](#35-user-address-spaces)
  - [3.6 Copy-on-Write (COW)](#36-copy-on-write-cow)
  - [3.7 The VM Map](#37-the-vm-map)
- [Chapter 4: Threads, Scheduling & Synchronisation](#chapter-4-threads-scheduling--synchronisation)
  - [4.1 What Is a Thread?](#41-what-is-a-thread)
  - [4.2 Thread Representation](#42-thread-representation)
  - [4.3 The MLFQ Scheduler](#43-the-mlfq-scheduler)
  - [4.4 SMP Load Balancing](#44-smp-load-balancing)
  - [4.5 Spinlocks, Mutexes & Condition Variables](#45-spinlocks-mutexes--condition-variables)
  - [4.6 The Timer Driver](#46-the-timer-driver)
- [Chapter 5: Processes -- Fork, Exec, Exit](#chapter-5-processes----fork-exec-exit)
  - [5.1 The Process Structure](#51-the-process-structure)
  - [5.2 Fork](#52-fork)
  - [5.3 Exec](#53-exec)
  - [5.4 Exit](#54-exit)
  - [5.5 Wait](#55-wait)
  - [5.6 The First User Process (PID 1)](#56-the-first-user-process-pid-1)
  - [5.7 File Descriptors](#57-file-descriptors)
- [Chapter 6: Mach IPC](#chapter-6-mach-ipc)
  - [6.1 Core Concepts](#61-core-concepts)
  - [6.2 Kernel Data Structures](#62-kernel-data-structures)
  - [6.3 The Message Header](#63-the-message-header)
  - [6.4 The mach_msg_trap Flow](#64-the-mach_msg_trap-flow)
  - [6.5 Out-of-Line (OOL) Memory](#65-out-of-line-ool-memory)
  - [6.6 IOKit Kobject Dispatch](#66-iokit-kobject-dispatch)
  - [6.7 Bootstrap Services](#67-bootstrap-services)
  - [6.8 Mach Traps Summary](#68-mach-traps-summary)
- [Chapter 7: BSD Syscalls & POSIX Interface](#chapter-7-bsd-syscalls--posix-interface)
  - [7.1 The Trap Handler](#71-the-trap-handler)
  - [7.2 BSD Syscall Catalogue](#72-bsd-syscall-catalogue)
  - [7.3 How a Syscall Works End-to-End](#73-how-a-syscall-works-end-to-end)
  - [7.4 Path Resolution](#74-path-resolution)
  - [7.5 Signal Delivery](#75-signal-delivery)
  - [7.6 Demand Paging in the Trap Handler](#76-demand-paging-in-the-trap-handler)
  - [7.7 Security: DAC Permission Checks](#77-security-dac-permission-checks)
- [Chapter 8: Filesystem -- VFS, Ext4, Buffer Cache](#chapter-8-filesystem----vfs-ext4-buffer-cache)
  - [8.1 The VFS Layer](#81-the-vfs-layer)
  - [8.2 The Ext4 Filesystem Driver](#82-the-ext4-filesystem-driver)
  - [8.3 The Buffer Cache](#83-the-buffer-cache)
  - [8.4 The Device Filesystem (devfs)](#84-the-device-filesystem-devfs)
  - [8.5 How It All Fits Together](#85-how-it-all-fits-together)
- [Chapter 9: Networking — TCP/IP Stack](#chapter-9-networking--tcpip-stack)
  - [9.1 Stack Overview](#91-stack-overview)
  - [9.2 Ethernet & ARP](#92-ethernet--arp)
  - [9.3 IPv4 & ICMP](#93-ipv4--icmp)
  - [9.4 UDP & DHCP](#94-udp--dhcp)
  - [9.5 TCP](#95-tcp)
  - [9.6 BSD Sockets](#96-bsd-sockets)
- [Chapter 10: IOKit & Device Drivers](#chapter-10-iokit--device-drivers)
  - [10.1 What Is IOKit?](#101-what-is-iokit)
  - [10.2 The IOKit Object Model](#102-the-iokit-object-model)
  - [10.3 The I/O Registry](#103-the-io-registry)
  - [10.4 Driver Matching & Lifecycle](#104-driver-matching--lifecycle)
  - [10.5 IOUserClient & External Methods](#105-iouserclient--external-methods)
  - [10.6 IOFramebuffer -- The GPU Driver](#106-ioframebuffer----the-gpu-driver)
  - [10.7 IOHIDSystem -- Input Events](#107-iohidsystem----input-events)
  - [10.8 VirtIO Transport Layer](#108-virtio-transport-layer)
  - [10.9 VirtIO GPU Protocol](#109-virtio-gpu-protocol)
  - [10.10 VirtIO Block, Network & Input](#1010-virtio-block-network--input)
  - [10.11 GICv2 -- The Interrupt Controller](#1011-gicv2----the-interrupt-controller)
  - [10.12 PL011 UART](#1012-pl011-uart)
  - [10.13 TTY Subsystem](#1013-tty-subsystem)
  - [10.14 Pseudo-Terminals (PTY)](#1014-pseudo-terminals-pty)
  - [10.15 Framebuffer Console](#1015-framebuffer-console)
  - [10.16 Comparison with XNU/macOS IOKit](#1016-comparison-with-xnumacos-iokit)
- [Chapter 11: Userland -- dyld, libSystem, crt0](#chapter-11-userland----dyld-libsystem-crt0)
  - [11.1 The Mach-O Binary Format](#111-the-mach-o-binary-format)
  - [11.2 dyld -- The Dynamic Linker](#112-dyld----the-dynamic-linker)
  - [11.3 libSystem.B.dylib -- The C Library](#113-libsystembdylib----the-c-library)
  - [11.4 crt0 and Program Startup](#114-crt0-and-program-startup)
  - [11.5 The Objective-C Runtime (libobjc)](#115-the-objective-c-runtime-libobjc)
- [Chapter 12: WindowServer & GUI Architecture](#chapter-12-windowserver--gui-architecture)
  - [12.1 WindowServer Overview](#121-windowserver-overview)
  - [12.2 The IPC Protocol](#122-the-ipc-protocol)
  - [12.3 Window Compositing](#123-window-compositing)
  - [12.4 Input Event Dispatch](#124-input-event-dispatch)
  - [12.5 loginwindow -- Session Management](#125-loginwindow----session-management)
  - [12.6 init -- The launchd-Style PID 1](#126-init----the-launchd-style-pid-1)
- [Chapter 13: Framework Stack -- CoreFoundation through AppKit](#chapter-13-framework-stack----corefoundation-through-appkit)
  - [13.1 The Freestanding Pattern](#131-the-freestanding-pattern)
  - [13.2 CoreFoundation](#132-corefoundation)
  - [13.3 CoreGraphics](#133-coregraphics)
  - [13.4 CoreText](#134-coretext)
  - [13.5 Foundation](#135-foundation)
  - [13.6 AppKit](#136-appkit)
  - [13.7 The Objective-C Runtime (libobjc)](#137-the-objective-c-runtime-libobjc)
- [Chapter 14: Applications](#chapter-14-applications)
  - [14.1 Application Architecture -- Common Patterns](#141-application-architecture----common-patterns)
  - [14.2 Dock.app -- Desktop & Dock Bar](#142-dockapp----desktop--dock-bar)
  - [14.3 Finder.app -- File Browser](#143-finderapp----file-browser)
  - [14.4 Terminal.app -- VT100 Terminal Emulator](#144-terminalapp----vt100-terminal-emulator)
  - [14.5 SystemUIServer.app -- Menu Bar Clock](#145-systemuiserverapp----menu-bar-clock)
- [Chapter 15: Build System & Toolchain](#chapter-15-build-system--toolchain)
  - [15.1 Build Overview -- `make world`](#151-build-overview----make-world)
  - [15.2 Kernel Build -- Bare-Metal ELF](#152-kernel-build----bare-metal-elf)
  - [15.3 Userland Build -- Mach-O with macOS Clang](#153-userland-build----mach-o-with-macos-clang)
  - [15.4 The COMDAT-Stripping Pipeline](#154-the-comdat-stripping-pipeline)
  - [15.5 Disk Image Creation -- mkdisk.sh](#155-disk-image-creation----mkdisksh)
  - [15.6 QEMU Launch](#156-qemu-launch)
  - [15.7 Debug and Test Targets](#157-debug-and-test-targets)
  - [15.8 Build Output Summary](#158-build-output-summary)
- [Chapter 16: Security Audit & Hardening](#chapter-16-security-audit--hardening)
  - [16.1 Memory Safety](#161-memory-safety)
  - [16.2 Access Control](#162-access-control)
  - [16.3 Authentication](#163-authentication)
  - [16.4 Network Security](#164-network-security)
  - [16.5 Kernel Attack Surface](#165-kernel-attack-surface)
  - [16.6 Information Disclosure](#166-information-disclosure)
  - [16.7 Physical and Side-Channel Attacks](#167-physical-and-side-channel-attacks)
  - [16.8 Security Hardening Roadmap](#168-security-hardening-roadmap)

---

## Chapter 1: Introduction & Overview

### 1.1 What Is Kiseki?

Kiseki (Japanese for "miracle") is a from-scratch operating system for ARM64 that faithfully reimplements the architecture of Apple's macOS — from the Mach/BSD hybrid kernel up through the Objective-C GUI frameworks. It is not a port of XNU or Darwin; every line of code is original, written to behave identically to macOS where it matters for binary-format compatibility and architectural understanding.

The system boots on QEMU's `virt` machine (and Raspberry Pi 4) with:

- A **Mach + BSD hybrid kernel** with 102 syscalls and 12 Mach traps
- **4-core SMP** with an MLFQ scheduler (128 priority levels)
- ARM64 **4-level page tables** with copy-on-write fork
- Full **Mach IPC** with per-task port namespaces and out-of-line memory descriptors
- A read/write **ext4 filesystem** with extent trees and a 256-slot buffer cache
- A **TCP/IP networking stack** with DHCP, ARP, ICMP, UDP, and TCP
- A **dynamic linker** (`dyld`) that loads Mach-O binaries with chained fixups
- A complete **C library** (`libSystem.B.dylib`, 7,948 lines)
- An **IOKit driver framework** with VirtIO GPU, input, block, and network drivers
- A **Quartz-like WindowServer** compositor with cursor, menu bar, and Z-ordered windows
- **Six frameworks**: CoreFoundation, CoreGraphics, CoreText, Foundation, AppKit, and IOKit (userland)
- **Four GUI applications**: Dock, Finder, Terminal, and SystemUIServer
- **65+ command-line utilities** including `bash` and a native C compiler (`tcc`)
- An **SSH server** with Curve25519 key exchange

The goal is not to run unmodified macOS binaries (that would require Apple's proprietary code), but to build a system that is **structurally identical** to macOS — so that studying Kiseki teaches you exactly how macOS works, from the syscall ABI to the Mach message format to the way AppKit dispatches events.

### 1.2 Architecture at a Glance

```
+=======================================================================+
|                         User Space (EL0)                              |
|                                                                       |
|  +----------+ +----------+ +----------+ +-------------------+         |
|  | Dock.app | |Finder.app| |Terminal  | |SystemUIServer.app |         |
|  +----+-----+ +----+-----+ +----+-----+ +---------+---------+         |
|       |            |            |                 |                   |
|  +----+------------+------------+-----------------+-------------+     |
|  |                     AppKit.framework                         |     |
|  |              (NSApplication, NSWindow, NSView)               |     |
|  +-----------------------------+--------------------------------+     |
|  | Foundation.framework        | CoreText.framework             |     |
|  | (NSString, NSArray)         | (CTFont, CTLine)               |     |
|  +-----------------------------+--------------------------------+     |
|  |                  CoreGraphics.framework                      |     |
|  |           (CGContext, CGPath, CGColor, CGImage)              |     |
|  +--------------------------------------------------------------+     |
|  |                  CoreFoundation.framework                    |     |
|  |       (CFString, CFArray, CFDictionary, CFRunLoop)           |     |
|  +-----------------------------+--------------------------------+     |
|  | libobjc.A.dylib             | IOKit.framework (user)         |     |
|  | (GNUstep libobjc2)          | (IOServiceOpen, etc.)          |     |
|  +-----------------------------+--------------------------------+     |
|  |                libSystem.B.dylib (C library)                 |     |
|  |       malloc, printf, read, write, mach_msg, ...             |     |
|  +--------------------------------------------------------------+     |
|  |                     dyld (dynamic linker)                    |     |
|  |          Mach-O loading, symbol binding, fixups              |     |
|  +----------------------------+---+-----------------------------+     |
|                               |                                       |
|  +---------------+ +----------+----+ +------------------+             |
|  | WindowServer  | |  loginwindow  | |   init (PID 1)   |             |
|  | (compositor)  | | (session mgr) | |  (launchd-style) |             |
|  +-------+-------+ +--------------+  +------------------+             |
|          |                svc #0x80                                   |
+==========+============================================================+
|          |              Kernel Space (EL1)                            |
|          v                                                            |
|  +-----------------------------------------------------------------+  |
|  |                     Trap Handler (trap.c)                       |  |
|  |        x16 > 0 --> BSD syscall    x16 < 0 --> Mach trap         |  |
|  +------------------------------+----------------------------------+  |
|  |       Mach Layer             |          BSD Layer               |  |
|  |  +---------------------+    |  +----------------------------+   |  |
|  |  | Mach IPC            |    |  | 102 BSD Syscalls           |   |  |
|  |  | (ports, msgs,       |    |  | (open, read, write,        |   |  |
|  |  |  OOL, bootstrap)    |    |  |  fork, exec, mmap, ...)    |   |  |
|  |  +---------------------+    |  +----------------------------+   |  |
|  |  | Tasks & Threads     |    |  | VFS + Ext4 + devfs         |   |  |
|  |  +---------------------+    |  +----------------------------+   |  |
|  |  | Virtual Memory      |    |  | TCP/IP + BSD Sockets       |   |  |
|  |  | (4-level PT,        |    |  +----------------------------+   |  |
|  |  |  COW, vm_map)       |    |  | Process Model              |   |  |
|  |  +---------------------+    |  | (fork/exec/exit/signals)   |   |  |
|  |  | Physical Memory     |    |  +----------------------------+   |  |
|  |  | (Buddy Alloc)       |    |  | TTY + PTY                  |   |  |
|  |  +---------------------+    |  +----------------------------+   |  |
|  |  | MLFQ Scheduler      |    |                                   |  |
|  |  | (128 levels,        |    |                                   |  |
|  |  |  4 CPUs, IPI)       |    |                                   |  |
|  |  +---------------------+    |                                   |  |
|  +------------------------------+----------------------------------+  |
|  |                           IOKit                                 |  |
|  |  IOService --> IOUserClient --> IOFramebuffer / IOHIDSystem     |  |
|  |  IOMemoryDescriptor, IOWorkLoop, I/O Registry                   |  |
|  +-----------------------------------------------------------------+  |
|  |                         Drivers                                 |  |
|  |  VirtIO GPU | VirtIO Block | VirtIO Net | VirtIO Input          |  |
|  |  GICv2      | ARM Timer    | PL011 UART | Framebuffer Console   |  |
|  +-----------------------------------------------------------------+  |
|  |                      Architecture                               |  |
|  |  boot.S | vectors.S | context_switch.S | linker-qemu.ld         |  |
|  +-----------------------------------------------------------------+  |
+=======================================================================+
```

### 1.3 How macOS Works (The 10,000-Foot View)

Before diving into Kiseki's implementation, let's establish how a real macOS system is structured. If you already know this, skip ahead — but most software engineers have a fuzzy picture of the layers.

**macOS is not a monolithic kernel.** It is a **hybrid** of two very different operating system traditions:

1. **Mach** (from Carnegie Mellon University, 1985) — provides the low-level primitives: tasks (address spaces), threads, virtual memory, and inter-process communication via message-passing on ports.

2. **BSD** (from UC Berkeley, 1977) — provides the POSIX interface: processes, file descriptors, the VFS, the TCP/IP stack, signals, and the syscall ABI.

Apple's kernel, **XNU** ("X is Not Unix"), welds these together. A single kernel image contains both the Mach layer and the BSD layer. Every process is simultaneously a Mach task (with a port namespace and threads) and a BSD process (with a PID, file descriptors, and credentials). The syscall entry point (`svc #0x80` on ARM64) inspects register `x16`:

- **Positive x16** -> BSD syscall (e.g., `x16=4` -> `write()`)
- **Negative x16** -> Mach trap (e.g., `x16=-31` -> `mach_msg_trap()`)

This duality is the heart of macOS, and it is the heart of Kiseki.

> **XNU reference:** The syscall dispatch lives in `bsd/dev/arm/systemcalls.c` and `osfmk/arm64/sleh.c`. In Kiseki, the equivalent is `kernel/kern/trap.c:169` (`trap_sync_el0`).

**Above the kernel**, macOS provides:

- **`dyld`** — the dynamic linker that loads Mach-O executables and their dependent `.dylib` files
- **`libSystem.B.dylib`** — the C library (wrapping libsystem_c, libsystem_kernel, libsystem_malloc, etc.)
- **`launchd`** (PID 1) — the init system that reads property lists and launches daemons
- **WindowServer** — the display compositor (a userland process, not in-kernel)
- **CoreFoundation -> CoreGraphics -> CoreText -> Foundation -> AppKit** — the framework stack

Kiseki reimplements all of these.

### 1.4 Hardware Target

Kiseki targets the **QEMU `virt` machine** with the following configuration:

```
qemu-system-aarch64 \
    -M virt -accel tcg -cpu cortex-a72 -smp 4 -m 4G \
    -display cocoa \
    -kernel build/kiseki.elf \
    -serial mon:stdio \
    -drive id=hd0,file=build/disk.img,format=raw,if=none \
    -device virtio-blk-device,drive=hd0 \
    -device virtio-gpu-device \
    -device virtio-keyboard-device \
    -device virtio-tablet-device \
    -netdev vmnet-shared,id=net0 \
    -device virtio-net-device,netdev=net0
```

The QEMU `virt` machine provides:

| Component | Address / IRQ | Kiseki Driver |
|-----------|--------------|---------------|
| ARM Generic Timer | PPI #27 | `kernel/drivers/timer/timer.c` (182 lines) |
| GICv2 (interrupt controller) | GICD `0x08000000`, GICC `0x08010000` | `kernel/drivers/gic/gicv2.c` (150 lines) |
| PL011 UART | `0x09000000`, SPI #33 | `kernel/drivers/uart/pl011.c` (174 lines) |
| VirtIO MMIO (32 slots) | `0x0A000000`+, SPI #48+ | `kernel/drivers/virtio/` |
| RAM | `0x40000000` - `0x13FFFFFFF` (4 GB) | Managed by PMM + VMM |

> **Why TCG instead of HVF?** Apple Silicon's hardware virtualisation (HVF) has cache-coherency issues that cause External Abort exceptions during instruction fetch after `fork()`. The `tcg` (software emulation) accelerator avoids this at the cost of speed.

The kernel is loaded as an ELF at physical address `0x40080000` (the first 512 KB of RAM is reserved for QEMU's device tree blob). The linker script (`kernel/arch/arm64/linker-qemu.ld`, 95 lines) places `.text` first (with `boot.S` at the entry point), followed by `.rodata`, `.data`, `.bss`, a 128 KB stack area (32 KB x 4 cores), and the heap start marker.

```
Physical Memory Layout (QEMU virt, 4 GB)

              +---------------------------+
0x00000000    |   MMIO Region             |  GIC, UART, VirtIO
              +---------------------------+
0x40000000    |   Device Tree Blob        |  512 KB reserved by QEMU
              +---------------------------+
0x40080000    |   Kernel .text            |  Code (boot.S entry point at top)
              |   Kernel .rodata          |  Read-only data
              |   Kernel .data            |  Initialised globals
              |   Kernel .bss             |  Uninitialised globals (zeroed by boot.S)
              |   Boot Stacks             |  32 KB x 4 cores = 128 KB
              +---------------------------+
              |   __heap_start            |  Everything below here is managed by
              |                           |  the PMM (free pages / buddy allocator)
              |          ...              |
              |                           |
0x13FFFFFFF   +---------------------------+  RAM End (4 GB)
```

Kiseki also supports the **Raspberry Pi 4** (BCM2711, GIC-400, eMMC) via an alternate linker script and platform-specific UART/eMMC drivers.

### 1.5 Codebase Map

```
kiseki/
├── kernel/                          # Kernel source (53 files, ~48,000 lines)
│   ├── arch/arm64/
│   │   ├── boot.S                   # Entry point, EL2->EL1 drop (181 lines)
│   │   ├── vectors.S                # Exception vector table (403 lines)
│   │   ├── context_switch.S         # Thread context switch (133 lines)
│   │   ├── smp.c                    # PSCI secondary core startup (71 lines)
│   │   └── linker-qemu.ld           # Linker script (95 lines)
│   ├── kern/
│   │   ├── main.c                   # kmain() bootstrap (458 lines)
│   │   ├── trap.c                   # Exception handlers (839 lines)
│   │   ├── vmm.c                    # Virtual memory manager (1,492 lines)
│   │   ├── pmm.c                    # Physical memory buddy allocator (387 lines)
│   │   ├── sched.c                  # MLFQ scheduler (1,313 lines)
│   │   ├── sync.c                   # Spinlocks, mutexes, condvars (410 lines)
│   │   ├── proc.c                   # Process management, fork/exec (1,801 lines)
│   │   ├── tty.c                    # TTY line discipline (801 lines)
│   │   ├── pty.c                    # Pseudo-terminals (604 lines)
│   │   ├── macho.c                  # Mach-O loader (839 lines)
│   │   ├── commpage.c               # CommPage (signal trampoline) (514 lines)
│   │   ├── kprintf.c                # Kernel printf with SMP lock (384 lines)
│   │   ├── fbconsole.c              # Framebuffer text console (1,116 lines)
│   │   └── font8x16.c              # Bitmap font data (798 lines)
│   ├── mach/
│   │   └── ipc.c                    # Mach IPC (ports, msgs, OOL) (2,485 lines)
│   ├── bsd/
│   │   ├── syscalls.c               # All 102 BSD syscalls (5,416 lines)
│   │   └── security.c              # DAC permissions, SUID (247 lines)
│   ├── fs/
│   │   ├── vfs.c                    # Virtual filesystem layer (1,454 lines)
│   │   ├── ext4/ext4.c              # Ext4 driver (2,836 lines)
│   │   ├── buf.c                    # Buffer cache (416 lines)
│   │   └── devfs.c                  # Device filesystem (548 lines)
│   ├── net/
│   │   ├── eth.c                    # Ethernet + ARP (555 lines)
│   │   ├── ip.c                     # IPv4 (319 lines)
│   │   ├── tcp.c                    # TCP (785 lines)
│   │   ├── udp.c                    # UDP (148 lines)
│   │   ├── dhcp.c                   # DHCP client (399 lines)
│   │   ├── icmp.c                   # ICMP (152 lines)
│   │   └── socket.c                # BSD socket syscalls (1,021 lines)
│   ├── iokit/                       # IOKit framework (11 files, ~4,900 lines)
│   │   ├── io_registry.c            # I/O Registry + matching (423 lines)
│   │   ├── io_service.c             # IOService lifecycle (457 lines)
│   │   ├── io_user_client.c          # External method dispatch (359 lines)
│   │   ├── io_framebuffer.c         # IOFramebuffer driver (788 lines)
│   │   ├── io_hid_system.c          # IOHIDSystem (input events) (457 lines)
│   │   ├── io_memory_descriptor.c   # User-space memory mapping (355 lines)
│   │   ├── iokit_mach.c             # Mach IPC bridge for IOKit (977 lines)
│   │   └── ...                      # io_object, io_property, io_work_loop
│   ├── drivers/
│   │   ├── virtio/virtio_gpu.c       # VirtIO GPU 2D (1,137 lines)
│   │   ├── virtio/virtio_blk.c      # VirtIO block (582 lines)
│   │   ├── virtio/virtio_input.c    # VirtIO keyboard+tablet (959 lines)
│   │   ├── net/virtio_net.c         # VirtIO network (573 lines)
│   │   ├── gic/gicv2.c             # GICv2 interrupt controller (150 lines)
│   │   ├── timer/timer.c           # ARM Generic Timer (182 lines)
│   │   └── uart/pl011.c            # PL011 UART (174 lines)
│   └── include/                     # 42 kernel headers (~9,500 lines)
│
├── userland/                        # Userland source (175 files, ~124,000 lines)
│   ├── dyld/dyld.c                  # Dynamic linker (2,438 lines)
│   ├── libsystem/libSystem.c        # C library (7,948 lines)
│   ├── libobjc/                     # GNUstep ObjC runtime (~100 files)
│   ├── CoreFoundation/              # CFString, CFArray, CFRunLoop (4,841 lines)
│   ├── CoreGraphics/                # CGContext, bitmap rendering (3,162 lines)
│   ├── CoreText/                    # Font rendering (1,961 lines)
│   ├── Foundation/                  # NSObject, NSString, bridging (1,616 lines)
│   ├── AppKit/                      # NSWindow, NSView, WS IPC (3,410 lines)
│   ├── IOKit/                       # IOKit user library (977 lines)
│   ├── sbin/
│   │   ├── WindowServer.c            # Display compositor (1,854 lines)
│   │   ├── init.c                    # PID 1 process manager (978 lines)
│   │   ├── loginwindow.c            # Login UI + session (980 lines)
│   │   ├── sshd.c                   # SSH server (1,657 lines)
│   │   └── mDNSResponder.c          # DNS daemon (561 lines)
│   ├── apps/
│   │   ├── Dock.app/Dock.m          # Desktop + dock bar (271 lines)
│   │   ├── Finder.app/Finder.m      # File browser (925 lines)
│   │   ├── Terminal.app/Terminal.m   # VT100 terminal (1,071 lines)
│   │   └── SystemUIServer.app/      # Menu bar clock (289 lines)
│   └── bin/                          # 60+ coreutils (cat, ls, grep, ...)
│
├── scripts/mkdisk.sh                # Ext4 disk image builder (835 lines)
├── Makefile                         # Root build system (359 lines)
├── include/sys/syscall.h            # Shared syscall numbers (181 lines)
└── docs/                            # This book
```

---

## Chapter 2: ARM64 Boot & Early Initialisation

This chapter covers everything that happens from the moment the CPU powers on to the moment the first user process is running. We will walk through three assembly files (`boot.S`, `vectors.S`, `context_switch.S`) and one C file (`main.c`) line by line. By the end, you will understand:

- What exception levels are and why they matter
- How a kernel drops from hypervisor mode to kernel mode
- How the CPU knows where to jump when a syscall or interrupt happens
- How threads are created and context-switched
- The 17 phases of kernel bootstrap, in dependency order
- How secondary CPU cores are brought online

### 2.1 Five Foundational Concepts

Before we can read a single line of assembly, we need to establish five concepts that every operating system depends on. If you've never worked below the level of `printf()`, this section is for you. None of this is ARM64-specific — every modern CPU has equivalents.

#### Concept 1: Exception Levels (Privilege Rings)

A CPU does not treat all code equally. It has a built-in notion of **privilege** — a piece of code can either be "trusted" (allowed to touch any hardware register, any memory address, any instruction) or "untrusted" (restricted to a safe sandbox). This is how your OS prevents a buggy web browser from overwriting kernel memory.

ARM64 calls these privilege tiers **Exception Levels (ELs)**:

```
  ┌──────────────────────────────────────────────────────────────┐
  │  EL3  Secure Monitor                                         │
  │  ARM TrustZone firmware. Kiseki never runs here.             │
  ├──────────────────────────────────────────────────────────────┤
  │  EL2  Hypervisor                                             │
  │  VMMs like QEMU's KVM. QEMU starts the kernel here.          │
  ├──────────────────────────────────────────────────────────────┤
  │  EL1  Kernel (Supervisor)                                    │
  │  The OS kernel. Full hardware access. Kiseki lives here.     │
  ├──────────────────────────────────────────────────────────────┤
  │  EL0  User                                                   │
  │  Applications. No direct hardware access.                    │
  └──────────────────────────────────────────────────────────────┘
           Higher privilege ▲                  ▼ Lower privilege
```

**Key rule: You can only move "up" (to higher privilege) through a hardware-defined mechanism called an exception.** A user program cannot simply jump to kernel code. It must execute a special instruction (`svc` on ARM64, `syscall` on x86), which causes the CPU to automatically:

1. Save the current program counter (PC) and processor state
2. Switch to the higher exception level
3. Jump to a fixed address (the **vector table** — see Concept 5)

Going "down" (from kernel to user) is done with the `eret` (Exception Return) instruction, which reverses the process.

> **x86 equivalent:** EL0 ≈ Ring 3, EL1 ≈ Ring 0. x86 has Ring 1 and Ring 2, but nobody uses them. ARM's EL2 is like Intel VT-x root mode.

> **Why does QEMU start at EL2?** QEMU's `virt` machine emulates a hypervisor-capable system. The firmware hands control to the kernel at EL2 because real hardware (like a Raspberry Pi) starts at EL2 as well. The kernel must immediately drop itself to EL1 — running an OS kernel at EL2 would work, but would prevent ever using virtualisation features.

**How to read the current exception level in code:**

```c
// ARM64 system register: CurrentEL
// Bits [3:2] encode the level:  EL0=0b00, EL1=0b01, EL2=0b10, EL3=0b11
// But the register value is shifted left by 2:
//   EL0 → 0x0, EL1 → 0x4, EL2 → 0x8, EL3 → 0xC
mrs     x0, CurrentEL       // Move from System Register to x0
and     x0, x0, #0xC        // Mask to bits [3:2]
cmp     x0, #0x8            // Compare with 0x8 (EL2)
```

This is exactly what `boot.S:31-33` does.

#### Concept 2: System Calls (Trapping Into the Kernel)

When your C program calls `write(fd, buf, len)`, the C library does NOT call a kernel function directly. It cannot — the kernel is at EL1 and your program is at EL0. Instead, the C library executes:

```asm
mov     x16, #4          // x16 = syscall number (SYS_write = 4)
mov     x0, x1           // x0 = fd  (first argument)
mov     x1, x2           // x1 = buf (second argument)
mov     x2, x3           // x2 = len (third argument)
svc     #0x80            // Supervisor Call — trap to EL1
```

The `svc #0x80` instruction is the **system call trap**. It causes the CPU to:

1. Save the current PC to `ELR_EL1` (Exception Link Register) — this is the address to return to
2. Save the current processor state to `SPSR_EL1` (Saved Program Status Register)
3. Set the exception class in `ESR_EL1` to `EC=0x15` (SVC from AArch64)
4. Jump to the kernel's synchronous exception vector (at offset `+0x400` in the vector table)
5. The exception level changes from EL0 to EL1 — the kernel is now in control

The kernel reads `x16` to determine which syscall was requested, calls the appropriate handler, puts the return value in `x0`, and executes `eret` to return to EL0.

```
User (EL0)                              Kernel (EL1)
┌─────────────────┐                    ┌─────────────────────────┐
│ mov x16, #4     │                    │                         │
│ mov x0, fd      │                    │                         │
│ svc #0x80 ──────┼───── TRAP ────────►│ trap_sync_el0(tf)       │
│                 │                    │   EC == SVC?            │
│                 │                    │   x16 > 0 → BSD syscall │
│                 │                    │   x16 < 0 → Mach trap   │
│                 │                    │   call sys_write(...)   │
│                 │                    │   tf->regs[0] = result  │
│ // x0 = result  │◄──── eret ─────────│   return                │
│ // continues... │                    │                         │
└─────────────────┘                    └─────────────────────────┘
```

> **Kiseki-specific:** Kiseki uses the same convention as macOS/XNU: `svc #0x80` with the syscall number in `x16`. Positive `x16` → BSD syscall. Negative `x16` → Mach trap. The dispatch code is in `kernel/kern/trap.c:169`.

> **x86 equivalent:** `syscall` instruction (fast) or `int 0x80` (legacy). Linux puts the syscall number in `rax` instead of a separate register.

#### Concept 3: Interrupts (Hardware Knocking on the Door)

A **system call** is a *synchronous* exception — the program explicitly asks to enter the kernel. An **interrupt** (IRQ) is *asynchronous* — the hardware demands the CPU's attention at an unpredictable time.

Examples of interrupts:
- The **timer** fires every 10ms to trigger a scheduler tick
- The **disk** has finished reading a block of data
- The **network card** has received a packet
- The **keyboard** has a key press event

When an interrupt fires, the CPU does almost the same thing as for a syscall: it saves the current state and jumps to the vector table. But it jumps to a *different* vector entry (the IRQ vector instead of the synchronous vector), and the kernel calls a different handler (`trap_irq_el0` instead of `trap_sync_el0`).

```
User (EL0)                              Kernel (EL1)
┌─────────────────┐                    ┌──────────────────────────┐
│ add x0, x1, x2  │                    │                          │
│ // working...   │                    │                          │
│ ldr x3, [x4]  ──┼───── IRQ!! ──────>│ trap_irq_el0(tf)         │
│                 │    (timer fired)   │   gic_ack_interrupt()    │
│                 │                    │   timer_handler()        │
│                 │                    │   sched_tick()           │
│                 │                    │   gic_end_interrupt()    │
│ // resumes here │◄──── eret ─────────│   return                 │
│ str x3, [x5]    │                    │                          │
└─────────────────┘                    └──────────────────────────┘
```

The user program doesn't even know it was interrupted — the kernel saves and restores all registers perfectly. From the program's perspective, `ldr x3, [x4]` and `str x3, [x5]` appear to execute back-to-back.

> **Masking interrupts:** The kernel can temporarily disable interrupts using the `DAIF` flags in the processor state register. `msr daifset, #0x2` masks IRQs (the `I` bit). `msr daifclr, #0x2` unmasks them. This is critical during context switches and spinlock-protected sections where being interrupted would cause corruption.

#### Concept 4: Page Faults (Memory Traps)

When a program accesses a virtual address, the **MMU** (Memory Management Unit) translates it to a physical address using **page tables** (covered in Chapter 3). But sometimes the translation fails:

- The page isn't mapped (e.g., first access to a `malloc`'d region)
- The page is read-only and the program tried to write (e.g., copy-on-write after `fork()`)
- The page is at address 0 (null pointer dereference)

When this happens, the CPU generates a **Data Abort** (for loads/stores) or **Instruction Abort** (for code fetch). The mechanism is identical to a syscall — save state, jump to the vector table, enter the kernel at EL1. The kernel reads:

- `ESR_EL1` — the Exception Syndrome Register, which tells you *what kind* of fault
- `FAR_EL1` — the Fault Address Register, which tells you *what address* was accessed

The kernel then decides: is this a legitimate fault (allocate a page, do copy-on-write) or a bug (segfault → kill the process)?

```
Classification of traps by ESR_EL1.EC (Exception Class):

 EC       Meaning                         Kiseki handler
────────────────────────────────────────────────────────────
 0x15     SVC from AArch64 (syscall)      trap.c → bsd_syscall() / mach_trap()
 0x20     Instruction Abort (from EL0)    trap.c → handle_page_fault()
 0x21     Instruction Abort (from EL1)    trap.c → panic (kernel bug)
 0x24     Data Abort (from EL0)           trap.c → handle_page_fault()
 0x25     Data Abort (from EL1)           trap.c → panic (kernel bug)
 0x22     PC Alignment Fault              trap.c → kill process (SIGBUS)
 0x26     SP Alignment Fault              trap.c → kill process (SIGBUS)
 0x3C     BRK (debugger breakpoint)       trap.c → kill process (SIGTRAP)
```

> **These constants are defined in `kernel/include/machine/trap.h:41-49`.**

#### Concept 5: The Vector Table (Where the CPU Jumps)

All three mechanisms above — syscalls, interrupts, and page faults — end up at the same place: the **exception vector table**. This is a fixed-format table that the kernel places in memory and registers with the CPU via the `VBAR_EL1` (Vector Base Address Register) system register.

ARM64's vector table has **16 entries**, each exactly **128 bytes** (32 instructions). The entries are organized in a 4×4 grid:

```
                          Synchronous    IRQ          FIQ         SError
                         ┌────────────┬────────────┬────────────┬────────────┐
 From current EL,        │  +0x000    │  +0x080    │  +0x100    │  +0x180    │
 using SP_EL0 (unused)   │ (unused)   │ (unused)   │ (unused)   │ (unused)   │
                         ├────────────┼────────────┼────────────┼────────────┤
 From current EL,        │  +0x200    │  +0x280    │  +0x300    │  +0x380    │
 using SP_ELx (kernel)   │ EL1 sync   │ EL1 IRQ    │ (unused)   │ (unused)   │
                         ├────────────┼────────────┼────────────┼────────────┤
 From lower EL,          │  +0x400    │  +0x480    │  +0x500    │  +0x580    │
 AArch64 (user mode)     │ EL0 sync ★ │ EL0 IRQ ★  │ (unused)   │ (unused)   │
                         ├────────────┼────────────┼────────────┼────────────┤
 From lower EL,          │  +0x600    │  +0x680    │  +0x700    │  +0x780    │
 AArch32 (not used)      │ (unused)   │ (unused)   │ (unused)   │ (unused)   │
                         └────────────┴────────────┴────────────┴────────────┘
                          ★ = the hot paths (syscalls and timer ticks from user mode)
```

Each 128-byte slot is too small for a full handler, so Kiseki (like XNU) just places a `b` (branch) instruction in each slot that jumps to an out-of-line handler:

```asm
// vectors.S:171 — EL0 synchronous exception (syscalls, page faults)
.balign 128; b _handle_el0_sync
```

The out-of-line handler calls `SAVE_REGS`, invokes the C handler, then calls `RESTORE_REGS` and `eret`.

> **x86 equivalent:** The IDT (Interrupt Descriptor Table) serves the same purpose. Each IDT entry points to a handler. The ARM64 vector table is simpler — fixed 128-byte slots at fixed offsets instead of variable-length descriptors.

---

**Summary of the five concepts:**

| # | Concept | Mechanism | Direction | ARM64 instruction |
|---|---------|-----------|-----------|------------------|
| 1 | Exception Levels | CPU privilege tiers | — | `mrs CurrentEL` |
| 2 | System Calls | App requests kernel service | EL0 -> EL1 | `svc #0x80` |
| 3 | Interrupts | Hardware demands attention | any → EL1 | (automatic) |
| 4 | Page Faults | Bad memory access | any → EL1 | (automatic) |
| 5 | Vector Table | Where the CPU jumps for all of the above | — | `msr vbar_el1, x0` |

All five of these will appear in the next sections. Now let's read the actual code.

### 2.2 The Boot Sequence (boot.S)

**File:** `kernel/arch/arm64/boot.S` (181 lines)

When QEMU's firmware finishes initialising the virtual machine, it sets the program counter to the kernel's entry point (`_start`, placed at physical address `0x40080000` by the linker script) and begins executing. At this moment:

- We are at **EL2** (hypervisor level)
- The **MMU is off** — all addresses are physical
- **Caches are off** — every memory access goes to RAM
- **Interrupts are masked** — we're alone, no timer ticks
- **All cores are running** — cores 1-3 will also reach `_start`

The boot code must: identify which core we are, park all non-primary cores, drop from EL2 to EL1, configure essential system registers, set up a stack, clear BSS, and call `kmain()`. Let's walk through it.

#### Step 1: Identify the Core (lines 22-26)

```asm
_start:
    mrs     x0, mpidr_el1          // Read Multiprocessor Affinity Register
    and     x0, x0, #0xFF          // Extract Aff0 (core number: 0, 1, 2, 3)
    cbnz    x0, _secondary_spin    // If not core 0, go to sleep
```

**Why this matters:** On a 4-core system, QEMU starts *all four cores* executing `_start` simultaneously. Only core 0 should proceed with boot — the others would race on BSS clearing, stack setup, and `kmain()`, corrupting everything. So cores 1-3 are sent to `_secondary_spin` (line 171), which is an infinite `wfe` (Wait For Event) loop — a low-power sleep state. They will be woken up later by PSCI in Phase 7 (§2.6).

> **`MPIDR_EL1`** is the "Multiprocessor ID Register." On QEMU's `virt` machine, the lowest byte (`Aff0`) contains the core number (0-3). On real hardware the encoding is more complex (cluster IDs, etc.), but for QEMU this suffices.

#### Step 2: Check Current Exception Level (lines 30-38)

```asm
    mrs     x0, CurrentEL
    and     x0, x0, #0xC          // EL2=0x8, EL1=0x4
    cmp     x0, #0x8
    b.eq    _from_el2              // We're at EL2 → need to drop
    cmp     x0, #0x4
    b.eq    _at_el1                // Already at EL1 → skip drop
    b       _halt                  // EL3? Not expected → halt
```

QEMU starts at EL2. A Raspberry Pi 4 (with its default firmware) starts at EL1. This code handles both.

#### Step 3: Drop from EL2 to EL1 (lines 41-58)

This is the most subtle part of boot. We need to convince the CPU to lower its own privilege level. The trick: we set up a *fake exception return*.

```asm
_from_el2:
    // 1. Tell EL1 to use AArch64 (not AArch32)
    mov     x0, #(1 << 31)        // HCR_EL2.RW = 1 → AArch64 at EL1
    msr     hcr_el2, x0

    // 2. Allow EL1 and EL0 to use FP/SIMD (don't trap)
    msr     cptr_el2, xzr         // Clear all trap bits

    // 3. Set the "return state" — what EL and flags to have after eret
    mov     x0, #0x3C5            // SPSR = D|A|I|F masked, M[4:0]=00101 (EL1h)
    msr     spsr_el2, x0

    // 4. Set the "return address" — where to jump after eret
    adr     x0, _at_el1
    msr     elr_el2, x0

    // 5. Execute the exception return
    eret
```

**Let's unpack the magic number `0x3C5`:**

```
Bit field breakdown of SPSR_EL2 = 0x3C5 = 0b0000_0000_0000_0000_0000_0011_1100_0101

  Bit 9 (D): 1 = Debug exceptions masked
  Bit 8 (A): 1 = SError masked
  Bit 7 (I): 1 = IRQ masked
  Bit 6 (F): 1 = FIQ masked
  Bits [4:0] (M): 00101 = EL1h (EL1 using SP_EL1)

So: "return to EL1, using the EL1 stack pointer, with all interrupts masked."
```

The `eret` instruction atomically:
1. Loads the PC from `ELR_EL2` (→ `_at_el1`)
2. Loads the processor state from `SPSR_EL2` (→ EL1h, interrupts masked)
3. We are now at EL1

> **Why not just stay at EL2?** EL2 is designed for hypervisors. Page table formats differ at EL2 (stage-2 only), many system registers are unavailable, and EL2 cannot trap from EL0 (user processes) directly. Every OS kernel runs at EL1.

#### Step 4: Configure System Registers at EL1 (lines 61-82)

Now at EL1, we configure the hardware for kernel operation:

```asm
_at_el1:
    // Disable MMU and caches (we're running with physical addresses)
    mrs     x0, sctlr_el1
    bic     x0, x0, #(1 << 0)     // M=0: MMU off
    bic     x0, x0, #(1 << 2)     // C=0: Data cache off
    bic     x0, x0, #(1 << 12)    // I=0: Instruction cache off
    msr     sctlr_el1, x0
    isb                             // Instruction Sync Barrier

    // Enable FP/SIMD for EL1 and EL0
    mov     x0, #(3 << 20)         // CPACR_EL1.FPEN = 0b11
    msr     cpacr_el1, x0
    isb

    // Install the exception vector table
    ldr     x0, =_vectors
    msr     vbar_el1, x0
    isb
```

**Three critical things happen here:**

1. **MMU/caches off:** The MMU will be turned on later in Phase 4 (`vmm_init()`). Until then, every address is physical. The caches are off because we haven't set up the memory attribute tables yet (MAIR_EL1, TCR_EL1). Accessing cached memory without proper configuration would cause undefined behaviour.

2. **FP/SIMD enabled:** Without `CPACR_EL1.FPEN = 0b11`, any floating-point or NEON instruction (including compiler-generated ones in user programs) would trap with `EC=0x7`. The kernel itself is compiled with `-mgeneral-regs-only` to avoid FP/SIMD, but user programs use it freely.

3. **Vector table installed:** The `_vectors` label (from `vectors.S`) is loaded into `VBAR_EL1`. From this point on, any exception (syscall, IRQ, page fault) will jump to the appropriate slot in this table.

> **`isb` (Instruction Synchronisation Barrier):** System register writes take effect "sometime in the future" -- the CPU's pipeline might still be executing instructions fetched under the old settings. `isb` flushes the pipeline, guaranteeing that subsequent instructions see the new register values. After writing `VBAR_EL1`, we *must* `isb` before any exception could occur, or the CPU might jump to the *old* vector table.

#### Step 5: Set Up the Boot Stack (lines 84-89)

```asm
    ldr     x0, =__stack_top
    mov     sp, x0
```

`__stack_top` is defined by the linker script (`linker-qemu.ld`). The kernel reserves 128 KB of stack space (32 KB × 4 cores), laid out as:

```
  __stack_top  ───────────────── ◄─── Core 0 SP starts here
                   32 KB
  __stack_top - 0x8000  ──────── ◄─── Core 1 SP
                   32 KB
  __stack_top - 0x10000 ──────── ◄─── Core 2 SP
                   32 KB
  __stack_top - 0x18000 ──────── ◄─── Core 3 SP
                   32 KB
  __stack_base ──────────────────
```

The stack grows **downward** on ARM64 (as on x86). Core 0 gets the highest address; each subsequent core gets 32 KB lower. This boot stack is temporary — after `kmain()` creates the bootstrap thread (Phase 17), this stack is abandoned forever.

> **32 KB vs the old 16 KB:** The kernel stack was originally 16 KB, but deep call chains during the 17-phase bootstrap (particularly ext4 mount → VFS → buffer cache) would overflow it. We doubled it to 32 KB in a prior session.

#### Step 6: Clear BSS (lines 91-99)

```asm
    ldr     x0, =__bss_start
    ldr     x1, =__bss_end
_bss_clear:
    cmp     x0, x1
    b.ge    _bss_done
    str     xzr, [x0], #8          // Store zero, advance pointer by 8 bytes
    b       _bss_clear
```

**What is BSS?** The `.bss` section contains all global and static variables that are declared without an initialiser (e.g., `static int counter;`). The C standard guarantees they start as zero. The ELF loader doesn't store zeros in the file (that would waste space), so the boot code must zero this memory region before calling any C code.

`xzr` is the ARM64 "zero register" — a hardware register that always reads as zero. The loop writes 8 bytes of zeros at a time until `__bss_start` through `__bss_end` is cleared.

#### Step 7: Call kmain (lines 105-109)

```asm
    mov     x0, #0                 // DTB pointer (TODO: preserve from entry)
    bl      kmain                  // Branch with Link → C entry point
    b       _halt                  // If kmain returns (it shouldn't), halt
```

We pass 0 as the DTB (Device Tree Blob) address because boot.S clobbered `x0` during core ID detection. QEMU passes the DTB address in `x0` at entry, but we haven't implemented DTB parsing yet — device addresses are hardcoded to match QEMU's `virt` machine layout.

`bl` (Branch with Link) saves the return address in `x30` (LR). `kmain()` never returns — it creates a bootstrap thread and calls `load_context()` to abandon the boot stack (see §2.5). But if it somehow did return, we'd fall through to `_halt` (an infinite `wfi` loop).

#### The Complete Boot Flow

```
Power On (QEMU)
     │
     ▼
  _start (boot.S:22)                    All 4 cores start here
     │
     ├── Core 1,2,3 ──► _secondary_spin (wfe loop)
     │
     ▼ Core 0 only
  Check CurrentEL
     │
     ├── EL2 ──► _from_el2
     │              │
     │              ▼
     │           Configure HCR_EL2, SPSR_EL2, ELR_EL2
     │              │
     │              ▼
     │           eret ──────────────────────┐
     │                                      │
     ├── EL1 ──────────────────────────────►│
     │                                      │
     ▼                                      ▼
  _at_el1 (boot.S:61)                Now at EL1
     │
     ├── Disable MMU + caches (SCTLR_EL1)
     ├── Enable FP/SIMD (CPACR_EL1)
     ├── Install vector table (VBAR_EL1)
     ├── Set up boot stack (SP = __stack_top)
     ├── Clear BSS (__bss_start → __bss_end)
     │
     ▼
  kmain() (main.c:48)                17-phase bootstrap begins
```

### 2.3 The Vector Table (vectors.S)

**File:** `kernel/arch/arm64/vectors.S` (403 lines)

The vector table is the kernel's switchboard — every syscall, every interrupt, and every page fault arrives here. This file contains:

1. The `SAVE_REGS` / `RESTORE_REGS` macros that build and tear down **trap frames**
2. The 16-entry vector table itself
3. Four out-of-line exception handlers
4. Three special return paths for newly created threads

#### The Trap Frame

When the CPU takes an exception, the kernel must save *all* of the user's register state so it can be restored later. This saved state is called a **trap frame** and it lives on the kernel stack.

**File:** `kernel/include/machine/trap.h` (87 lines)

```c
struct trap_frame {
    uint64_t regs[31];  // x0-x30 (31 general-purpose registers)
    uint64_t sp;        // saved Stack Pointer
    uint64_t elr;       // Exception Link Register (return PC)
    uint64_t spsr;      // Saved Program Status Register
    uint64_t esr;       // Exception Syndrome Register
    uint64_t far;       // Fault Address Register
    // FP/NEON state (saved only for EL0 traps):
    uint64_t fpcr;      // Floating-Point Control Register
    uint64_t fpsr;      // Floating-Point Status Register
    uint64_t neon[64];  // q0-q31 (each 128-bit = 2 × uint64_t)
};
```

The total size is **816 bytes** (`TF_SIZE`). Here's the layout visually:

```
                Trap Frame (816 bytes, on kernel stack)
Offset    Field          Size     Notes
──────────────────────────────────────────────────────────
  0       x0-x30         248B     31 × 8 bytes (GPRs)
248       SP              8B      SP_EL0 for user traps
256       ELR             8B      Return address (PC to resume)
264       SPSR            8B      Saved processor state
272       ESR             8B      What caused the exception
280       FAR             8B      Fault address (for aborts)
288       FPCR            8B      FP control ─┐
296       FPSR            8B      FP status   ├─ Only saved
304       q0-q31        512B      NEON regs   ┘  for EL0 traps
──────────────────────────────────────────────────────────
816       Total                   = TF_SIZE
```

#### Why Two Sizes? EL0 vs EL1 Traps

When the kernel itself takes an exception (e.g., a page fault during `kmalloc`), it does NOT save the FP/NEON registers. Why? The kernel is compiled with `-mgeneral-regs-only`, so the compiler never generates FP/NEON instructions. The 816-byte frame is allocated (to keep the stack offsets consistent), but only the first 288 bytes are written.

When *user code* traps into the kernel, we must save the full 816 bytes — user programs use NEON freely (the compiler generates SIMD instructions for memcpy, floating-point arithmetic, etc.), and if the kernel context-switches to another process before returning, that other process's NEON state would overwrite the registers.

#### SAVE_REGS: Building the Trap Frame

```asm
.macro SAVE_REGS el                   // el=0 for user, el=1 for kernel
    sub     sp, sp, #TF_SIZE          // Allocate 816 bytes on kernel stack
    stp     x0, x1, [sp, #(0 * 8)]   // Save x0, x1 at offset 0
    stp     x2, x3, [sp, #(2 * 8)]   // Save x2, x3 at offset 16
    ...                                // (saves all 31 GPRs)
    str     x30, [sp, #(30 * 8)]     // Save x30 (Link Register)

    .if \el == 0
        mrs     x0, sp_el0            // User trap: save USER stack pointer
    .else
        add     x0, sp, #TF_SIZE      // Kernel trap: save pre-exception SP
    .endif
    str     x0, [sp, #TF_SP]

    mrs     x0, elr_el1               // Save return address
    str     x0, [sp, #TF_ELR]
    mrs     x0, spsr_el1              // Save processor state
    str     x0, [sp, #TF_SPSR]
    mrs     x0, esr_el1               // Save exception syndrome
    str     x0, [sp, #TF_ESR]
    mrs     x0, far_el1               // Save fault address
    str     x0, [sp, #TF_FAR]

    .if \el == 0
        mrs     x0, fpcr              // Save FP control register
        str     x0, [sp, #TF_FPCR]
        mrs     x0, fpsr              // Save FP status register
        str     x0, [sp, #TF_FPSR]
        stp     q0,  q1,  [sp, #(TF_NEON_BASE + 0 * 16)]  // Save q0-q31
        stp     q2,  q3,  [sp, #(TF_NEON_BASE + 2 * 16)]  // (128-bit pairs)
        ...
        stp     q30, q31, [sp, #(TF_NEON_BASE + 30 * 16)]
    .endif

    mov     x0, sp                    // x0 = pointer to trap frame
.endm
```

After `SAVE_REGS`, `x0` points to the trap frame. This pointer is passed as the first argument to the C handler (ARM64 calling convention: first argument in `x0`).

> **`stp` (Store Pair):** ARM64 can store two 64-bit registers (or two 128-bit NEON registers) in a single instruction. `stp x0, x1, [sp, #0]` writes x0 at SP+0 and x1 at SP+8. This is why ARM64 trap frame save/restore is so efficient — 31 GPRs need only 16 `stp` + 1 `str` instructions.

> **`sp_el0` vs `sp`:** ARM64 has *two* stack pointers at EL1: `SP_EL1` (the kernel stack, selected by the `h` suffix in EL1h) and `SP_EL0` (the user stack, saved in a separate register). When we trap from EL0, the CPU switches to `SP_EL1` automatically, but the user's stack pointer is preserved in `SP_EL0` — we just need to save it.

#### RESTORE_REGS: Tearing Down the Trap Frame

`RESTORE_REGS` does the exact reverse: restores system registers, optionally restores FP/NEON, restores all GPRs, deallocates the frame, and executes `eret`.

```asm
.macro RESTORE_REGS el
    ldr     x0, [sp, #TF_ELR]
    msr     elr_el1, x0              // Restore return address
    ldr     x0, [sp, #TF_SPSR]
    msr     spsr_el1, x0             // Restore processor state

    .if \el == 0
        ldr     x0, [sp, #TF_SP]
        msr     sp_el0, x0           // Restore user stack pointer
        // Restore FPCR, FPSR, q0-q31...
    .endif

    ldp     x0, x1, [sp, #(0 * 8)]  // Restore x0, x1
    ...
    ldr     x30, [sp, #(30 * 8)]    // Restore x30

    add     sp, sp, #TF_SIZE         // Deallocate trap frame
    isb                               // Ensure all writes complete
    eret                              // Return to EL0 (or EL1)
.endm
```

The `eret` at the end atomically restores the PC (from `ELR_EL1`) and the processor state (from `SPSR_EL1`), dropping back to whichever exception level the trap came from.

#### The Vector Table Itself (lines 153-180)

```asm
.balign 2048                          // Must be 2048-byte aligned
.global _vectors
_vectors:

// Row 0: Current EL with SP_EL0 (unused — Kiseki always uses SP_ELx)
.balign 128; b _vec_unhandled         // +0x000  Synchronous
.balign 128; b _vec_unhandled         // +0x080  IRQ
.balign 128; b _vec_unhandled         // +0x100  FIQ
.balign 128; b _vec_unhandled         // +0x180  SError

// Row 1: Current EL with SP_ELx (kernel-mode exceptions)
.balign 128; b _handle_el1h_sync      // +0x200  Kernel sync (page fault in kernel)
.balign 128; b _handle_el1h_irq       // +0x280  Kernel IRQ (timer tick during syscall)
.balign 128; b _vec_unhandled         // +0x300  FIQ (unused)
.balign 128; b _vec_unhandled         // +0x380  SError (unused)

// Row 2: Lower EL, AArch64 (user-mode exceptions) ★ HOT PATH
.balign 128; b _handle_el0_sync       // +0x400  User sync (syscalls + faults)
.balign 128; b _handle_el0_irq        // +0x480  User IRQ (timer tick in user code)
.balign 128; b _vec_unhandled         // +0x500  FIQ (unused)
.balign 128; b _vec_unhandled         // +0x580  SError (unused)

// Row 3: Lower EL, AArch32 (not supported)
.balign 128; b _vec_unhandled         // +0x600 through +0x780
...
```

Only **4 of the 16 entries** are actually used: EL1 sync, EL1 IRQ, EL0 sync, and EL0 IRQ. The rest branch to `_vec_unhandled`, which reads the exception registers, calls `exception_handler_early()` (defined in `main.c:434`), and halts.

> **`.balign 2048`:** The ARM64 architecture requires the vector table base to be 2048-byte aligned. Each entry must be 128-byte aligned (`.balign 128`). The assembler inserts padding NOPs to satisfy these constraints.

#### The Out-of-Line Handlers (lines 186-204)

Each handler follows the same pattern: save → call C → restore:

```asm
_handle_el0_sync:                     // User-mode synchronous exception
    SAVE_REGS 0                       // Build full 816-byte trap frame
    bl      trap_sync_el0             // Call C handler (trap.c)
    RESTORE_REGS 0                    // Restore and eret to EL0

_handle_el0_irq:                      // User-mode IRQ
    SAVE_REGS 0
    bl      trap_irq_el0
    RESTORE_REGS 0

_handle_el1h_sync:                    // Kernel-mode synchronous exception
    SAVE_REGS 1                       // Build partial trap frame (no NEON)
    bl      trap_sync_el1
    RESTORE_REGS 1

_handle_el1h_irq:                     // Kernel-mode IRQ
    SAVE_REGS 1
    bl      trap_irq_el1
    RESTORE_REGS 1
```

The C handlers in `trap.c` decode `ESR_EL1` to determine the exception type and dispatch accordingly:

```
trap_sync_el0(tf):
  EC = tf->esr >> 26
  switch(EC):
    case 0x15 (SVC):
      if tf->regs[16] >= 0  → bsd_syscall(tf)    // 102 BSD syscalls
      else                   → mach_trap(tf)       // 12 Mach traps
    case 0x20 (Instruction Abort):
    case 0x24 (Data Abort):
      → handle_page_fault(tf)
    case 0x3C (BRK):
      → deliver SIGTRAP
    default:
      → kill process with SIGKILL
```

#### Three Special Return Paths

When the kernel creates a new user-mode thread (via `fork()`, `execve()`, or `pthread_create()`), it can't just "return" to user mode — there's no trap frame on the stack from a previous trap. Instead, the scheduler dispatches the new thread via `context_switch()`, which restores `x30` (the link register) to one of three special assembly labels:

| Return path | Created by | Purpose |
|---|---|---|
| `fork_child_return` (line 225) | `sys_fork_impl()` | Return to user mode in a forked child process |
| `init_thread_return` (line 323) | `kernel_init_process()` | Return to user mode for PID 1 (init) |
| `user_thread_return` (line 364) | `thread_create_user()` | Return to user mode for pthread threads |

All three follow the same pattern:

1. **Switch address space**: Load the process's page table root into `TTBR0_EL1` (the register that controls EL0 address translation). Flush TLB and instruction caches.
2. **Enable interrupts**: `msr daifclr, #0x2` (unmask IRQs)
3. **Restore and eret**: `RESTORE_REGS 0` — restores the synthetic trap frame that was placed on the kernel stack by the creating code, then `eret` drops to EL0.

**`fork_child_return`** is the most complex — it includes extra safety checks (verifying that `ELR` is not a kernel address, which would indicate a corrupt trap frame) and workarounds for cache-coherency timing issues on multi-core systems:

```asm
fork_child_return:
    dsb     sy                       // Ensure page table writes visible
    // Build TTBR0 = pgd | (asid << 48)
    ldr     x0, [x19, #0]           // x19 = pointer to child's vm_space
    ldr     x1, [x19, #8]           // (set by sys_fork_impl via context.x19)
    orr     x0, x0, x1, lsl #48
    msr     ttbr0_el1, x0           // Switch to child's address space
    isb
    tlbi    vmalle1is               // Flush TLB (all cores)
    dsb     ish
    ic      ialluis                 // Flush instruction cache (all cores)
    dsb     ish
    isb
    ...
    msr     daifclr, #0x2           // Enable interrupts
    RESTORE_REGS 0                  // Restore trap frame and eret to EL0
```

> **Why `x19`?** The context switch only saves callee-saved registers (`x19-x30`). `fork()` stores the child's `vm_space` pointer in `context.x19` so it survives the context switch and is available here.

> **`TTBR0_EL1`:** Translation Table Base Register 0. This register points to the root of the page table hierarchy for EL0 (user space). Each process has its own page table, so switching `TTBR0_EL1` switches the entire user address space. The ASID (Address Space ID) in bits [63:48] allows the TLB to cache entries from multiple address spaces simultaneously without full flushes (though Kiseki does a full flush anyway for safety).

> **XNU equivalent:** XNU's `thread_return` in `osfmk/arm64/locore.s` performs the same function — it's the assembly stub that new threads land on when first dispatched by the scheduler.

### 2.4 Context Switching (context_switch.S)

**File:** `kernel/arch/arm64/context_switch.S` (133 lines)

When the scheduler decides to switch from one thread to another, it calls `context_switch(old_ctx, new_ctx)`. This is the most performance-critical code in the kernel — it runs on every 10ms timer tick (100 Hz), on every blocking syscall, and on every `yield()`.

#### What Gets Saved?

A context switch is fundamentally different from a trap. During a trap (syscall, IRQ), the kernel saves *all* registers because it needs to resume user code exactly where it left off. During a context switch, the kernel is switching between two *kernel* call stacks — the switch happens deep inside a C function call chain:

```
Thread A (running)                Thread B (sleeping)
─────────────────                 ─────────────────
  sched_switch()                    sched_switch()
    context_switch(&A.ctx, &B.ctx)    ← was sleeping here
      saves A's regs                  restores B's regs
      ─────────── switch! ──────────►
                                      returns from context_switch()
                                    returns from sched_switch()
                                    continues running...
```

Because both sides of the switch are C functions that follow the **AAPCS64** (ARM Architecture Procedure Call Standard), we only need to save the **callee-saved registers** — the ones a C function promises to preserve:

```
Callee-saved registers (must be preserved across function calls):
  x19-x28    General-purpose
  x29 (FP)   Frame pointer
  x30 (LR)   Link register (return address)
  SP          Stack pointer
  d8-d15     Floating-point / NEON (lower 64 bits of v8-v15)

Caller-saved registers (NOT saved — callers already save them):
  x0-x18     Temporaries, arguments, platform register
  d0-d7      FP arguments / temporaries
  d16-d31    FP temporaries
```

**Why this works:** The C compiler already ensures that any register *not* in the callee-saved set is either not live across the call to `context_switch()` or has been saved by the caller's own code. So we only need to save 14 registers instead of 31.

#### The cpu_context Structure

```c
// Implicit layout (offsets match context_switch.S):
struct cpu_context {
    uint64_t x19;       // offset  0
    uint64_t x20;       // offset  8
    uint64_t x21;       // offset 16
    uint64_t x22;       // offset 24
    uint64_t x23;       // offset 32
    uint64_t x24;       // offset 40
    uint64_t x25;       // offset 48
    uint64_t x26;       // offset 56
    uint64_t x27;       // offset 64
    uint64_t x28;       // offset 72
    uint64_t x29;       // offset 80  (frame pointer)
    uint64_t x30;       // offset 88  (link register / return address)
    uint64_t sp;        // offset 96
    uint64_t d8;        // offset 104
    uint64_t d9;        // offset 112
    uint64_t d10;       // offset 120
    uint64_t d11;       // offset 128
    uint64_t d12;       // offset 136
    uint64_t d13;       // offset 144
    uint64_t d14;       // offset 152
    uint64_t d15;       // offset 160
};                      // Total: 168 bytes
```

Compare with the 816-byte trap frame — the context switch structure is **5× smaller** because it only stores callee-saved state.

#### context_switch() — The Two-Way Switch

```asm
// x0 = &old_thread->context, x1 = &new_thread->context
context_switch:
    // ---- Save old thread's state ----
    stp     x19, x20, [x0, #0]       // Save x19,x20 to old context
    stp     x21, x22, [x0, #16]
    stp     x23, x24, [x0, #32]
    stp     x25, x26, [x0, #48]
    stp     x27, x28, [x0, #64]
    stp     x29, x30, [x0, #80]      // Save FP and LR
    mov     x2, sp
    str     x2, [x0, #96]            // Save SP
    stp     d8,  d9,  [x0, #104]     // Save callee-saved NEON
    stp     d10, d11, [x0, #120]
    stp     d12, d13, [x0, #136]
    stp     d14, d15, [x0, #152]

    // ---- Restore new thread's state ----
    ldp     x19, x20, [x1, #0]       // Restore x19,x20 from new context
    ldp     x21, x22, [x1, #16]
    ldp     x23, x24, [x1, #32]
    ldp     x25, x26, [x1, #48]
    ldp     x27, x28, [x1, #64]
    ldp     x29, x30, [x1, #80]      // Restore FP and LR
    ldr     x2, [x1, #96]
    mov     sp, x2                    // Restore SP ← THIS is the big moment
    ldp     d8,  d9,  [x1, #104]
    ldp     d10, d11, [x1, #120]
    ldp     d12, d13, [x1, #136]
    ldp     d14, d15, [x1, #152]

    ret                               // Return via restored x30 (LR)
```

**The "magic moment"** is `mov sp, x2` — after that instruction, we are on the new thread's stack. The `ret` instruction then jumps to the new thread's saved `x30` (link register), which is the address *inside* `sched_switch()` right after the call to `context_switch()`. The new thread wakes up as if it just returned from `context_switch()` normally.

```
Thread A's view:                   Thread B's view:
  calls context_switch()           (was suspended inside context_switch)
  A's state saved                  B's state restored
  ──── SP switches! ────           B resumes
  (A is now suspended)             ret → back to sched_switch()
                                   continues running
```

> **No TTBR0 switch here:** The context switch does NOT change the user address space. That happens in the scheduler (`sched_switch()` in `sched.c`) before calling `context_switch()`, or in the special return paths (`fork_child_return`, etc.). This keeps the assembly fast and simple.

#### load_context() — The One-Way Switch

```asm
// x0 = &new_thread->context
load_context:
    ldp     x19, x20, [x0, #0]
    ...                               // Same restore sequence as above
    ldp     d14, d15, [x0, #152]
    ret                               // Jump to restored x30
```

`load_context()` is identical to the "restore" half of `context_switch()`, but it **does not save** the old thread's state. The old stack is abandoned forever.

This is used in exactly two places:

1. **`kmain()` (line 343):** After creating the bootstrap thread, core 0 abandons its boot stack and jumps into the bootstrap thread via `load_context()`. The boot stack is never used again.

2. **`secondary_main()` (line 421):** Each secondary core (1, 2, 3) abandons its boot stack and jumps into its idle thread via `load_context()`.

```
Boot Stack (from boot.S)          Bootstrap Thread (PMM-allocated stack)
─────────────────────              ──────────────────────────────────────
  kmain()                            thread_trampoline()
    ...phases 1-17...                  kernel_bootstrap_thread_func()
    load_context(&bootstrap.ctx)         kernel_init_process()
    ── one-way jump ──────────────►      thread_exit()
  (boot stack abandoned forever)
```

#### Debug Validation (lines 54-87)

In debug builds (`#ifdef DEBUG`), `context_switch()` includes a safety check after restoring `x30`:

```asm
    // Verify x30 is a kernel address [0x40000000, 0x80000000)
    mov     x2, #0x4000
    lsl     x2, x2, #16             // x2 = 0x40000000
    cmp     x30, x2
    b.lo    .Lrestore_x30_bad       // x30 < 0x40000000 → corruption!
    mov     x2, #0x8000
    lsl     x2, x2, #16             // x2 = 0x80000000
    cmp     x30, x2
    b.hs    .Lrestore_x30_bad       // x30 >= 0x80000000 → corruption!
```

If the restored link register isn't a kernel address, the thread's context was corrupted — probably a stack overflow or a use-after-free on the thread structure. The check catches this immediately with a diagnostic `kprintf` and `panic()` instead of letting the CPU jump to a garbage address and crash mysteriously.

> **Compiled out in release builds:** The `#ifdef DEBUG` guard ensures zero overhead in production. This is the "crash early, crash clearly" philosophy — debug builds sacrifice a few cycles per context switch for vastly better diagnostics.

#### Summary: Trap Frame vs Context Switch

| | Trap Frame (vectors.S) | Context Switch (context_switch.S) |
|---|---|---|
| **When** | Syscall, IRQ, page fault | Scheduler thread switch |
| **Direction** | EL0↔EL1 (or EL1↔EL1) | Kernel thread ↔ kernel thread |
| **Registers saved** | All 31 GPRs + SP + ELR + SPSR + ESR + FAR + FP/NEON | x19-x30, SP, d8-d15 only |
| **Size** | 816 bytes | 168 bytes |
| **Location** | Top of kernel stack | `thread->context` struct |
| **Return mechanism** | `eret` | `ret` (via restored x30) |

### 2.5 The 17-Phase Kernel Bootstrap (kmain)

**File:** `kernel/kern/main.c` (458 lines)

After `boot.S` drops to EL1, clears BSS, and calls `kmain()`, the kernel must initialise every subsystem in the correct order. Each subsystem depends on ones initialised before it — UART must be up before we can print, the GIC must be up before we can route interrupts, physical memory must be up before virtual memory, etc.

`kmain()` runs on core 0's boot stack. It executes 17 phases sequentially, prints a status message for each, and finishes by creating a bootstrap thread and abandoning the boot stack via `load_context()`.

```
kmain() Bootstrap Timeline (core 0)

 Phase  Function             Subsystem                    Depends on
───────────────────────────────────────────────────────────────────────
  1     uart_init()          PL011 UART (serial console)  (none)
  2     gic_init()           GICv2 interrupt controller   (none)
        gic_init_percpu()    Per-core GIC setup           GIC
        uart_enable_irq()    UART RX interrupts           GIC
  3     pmm_init()           Buddy allocator (phys mem)   (none)
  4     vmm_init()           Page tables + MMU enable     PMM
  5     thread_init()        Thread subsystem             VMM (for stacks)
        sched_init()         MLFQ scheduler               Threads
  6     timer_init(100)      ARM Generic Timer (100 Hz)   GIC
  7     smp_init()           Secondary cores via PSCI     VMM, Sched, Timer
  8     blkdev_init()        VirtIO block device          VMM (MMIO mapping)
  9     buf_init()           Buffer cache (256 × 4KB)     PMM
 10     vfs_init()           Virtual file system          (none)
        tty_init()           Console TTY                  (none)
        pty_init()           Pseudo-terminals             (none)
 11     ext4_fs_init()       Ext4 filesystem driver       (none, just registers)
 12     vfs_mount("ext4")    Mount root on /dev/vda       Block, Buf, VFS, Ext4
        devfs_init()         Device filesystem on /dev    VFS
        buf_start_sync_daemon() Periodic buffer flush     Threads, Buf
 13     ipc_init()           Mach IPC (ports, msgs)       PMM
 14     iokit_init()         IOKit registry + services    IPC
 15     commpage_init()      User-kernel shared page      VMM
        proc_init()          Process subsystem            VMM, IPC
 16     net_init()           TCP/IP stack                 (none)
        virtio_gpu_init()    VirtIO GPU framebuffer       VMM, Block
        io_framebuffer_init_driver() IOFramebuffer        IOKit, GPU
        fbconsole_init()     Framebuffer text console     GPU
        virtio_input_init()  VirtIO keyboard+tablet       VMM
        io_hid_system_init_driver() IOHIDSystem           IOKit, Input
 17     thread_create()      Bootstrap thread             Threads
        load_context()       Abandon boot stack           (one-way jump)
───────────────────────────────────────────────────────────────────────
```

Let's walk through the key phases in detail.

#### Phase 1: Early Console (UART)

```c
uart_init();     // kernel/drivers/uart/pl011.c
```

The PL011 UART is a serial port at MMIO address `0x09000000`. It's the simplest device — just write a byte to a register and it appears on the serial console. This is initialised first because every subsequent phase uses `kprintf()` (which calls `uart_putc()`) to report its status.

At this point the MMU is off, so `0x09000000` is a physical address that directly hits the UART hardware.

#### Phase 2: Interrupt Controller (GIC)

```c
gic_init();          // kernel/drivers/gic/gicv2.c — distributor init
gic_init_percpu();   // Per-CPU interface init
uart_enable_irq();   // Enable UART RX interrupt (for Ctrl+C)
```

The **GICv2** (Generic Interrupt Controller v2) is the interrupt routing hardware. It has two parts:

- **GICD** (Distributor) at `0x08000000` — routes interrupts from devices to cores
- **GICC** (CPU Interface) at `0x08010000` — each core's local interrupt interface

Until the GIC is initialised, no interrupt can reach the CPU. After this phase, the UART can generate interrupts when it receives a character (used for Ctrl+C to interrupt a runaway process).

> **IRQs are still masked** at this point (the `DAIF.I` bit is set). The timer will be programmed in Phase 6, but its interrupt will pend until interrupts are unmasked in the bootstrap thread.

#### Phase 3: Physical Memory Manager (PMM)

```c
pmm_init((uint64_t)&__heap_start, RAM_BASE + RAM_SIZE);
```

The buddy allocator takes ownership of all physical memory from `__heap_start` (end of the kernel image) to `0x140000000` (4 GB). It divides this into 4 KB pages and organises them into power-of-2 free lists (order 0 = 4 KB, order 1 = 8 KB, ... order 10 = 4 MB). This is covered in detail in Chapter 3.

#### Phase 4: Virtual Memory + MMU

```c
vmm_init();    // kernel/kern/vmm.c
```

This is the single most important initialisation step:

1. Allocates page tables from the PMM
2. Identity-maps the kernel (VA = PA for the kernel image)
3. Maps MMIO regions (UART, GIC, VirtIO) as device memory
4. Configures `MAIR_EL1` (memory attributes), `TCR_EL1` (translation control), `TTBR1_EL1` (kernel page table base)
5. **Enables the MMU** (`SCTLR_EL1.M = 1`)

After this point, the CPU does virtual-to-physical translation on every memory access. The identity mapping ensures the kernel continues running at the same addresses. Covered in Chapter 3.

#### Phase 5: Threading and Scheduler

```c
thread_init();   // Creates idle threads for each core
sched_init();    // Initialises the 128-level MLFQ run queues
```

The scheduler creates per-core data structures (`cpu_data`, accessed via `TPIDR_EL1`) and idle threads. Each idle thread has its own PMM-allocated 32 KB stack and runs a WFI (Wait For Interrupt) loop. Covered in Chapter 4.

#### Phase 6: Timer

```c
timer_init(SCHED_HZ);    // SCHED_HZ = 100 → 10ms quantum
```

Programs the ARM Generic Timer to fire an interrupt every 10ms. Each tick calls `sched_tick()`, which decrements the current thread's quantum and potentially triggers a context switch. The timer interrupt is **SPI #27** and is routed through the GIC.

> **Critical note from `main.c:106-116`:** IRQs remain masked here. If we enabled them now, a timer tick could trigger `sched_switch()` while still on the boot stack, which isn't a proper thread stack. The interrupts will be unmasked when the bootstrap thread starts (Phase 17).

#### Phase 7: SMP (Secondary Cores)

```c
smp_init();    // kernel/arch/arm64/smp.c
```

Wakes up cores 1, 2, and 3 using PSCI (Power State Coordination Interface) — a firmware call to start a core at a given entry point. Each secondary core goes through its own EL2→EL1 drop and ends up in `secondary_main()`. See §2.6 for details.

#### Phases 8-12: Storage Stack

```c
blkdev_init();          // Phase 8:  VirtIO block device → /dev/vda
buf_init();             // Phase 9:  Buffer cache (256 × 4KB LRU)
vfs_init();             // Phase 10: VFS + TTY + PTY
ext4_fs_init();         // Phase 11: Register ext4 driver
vfs_mount("ext4", "/"); // Phase 12: Mount root filesystem
devfs_init();           // Phase 12b: Mount /dev
buf_start_sync_daemon();// Phase 12c: Periodic flush thread
```

This brings up the entire storage stack in dependency order:

```
  Block device (VirtIO)
       │
       ▼
  Buffer cache (256 × 4KB, LRU eviction)
       │
       ▼
  VFS (vnode layer, mount table, path resolution)
       │
       ▼
  Ext4 driver (superblock, block groups, extent trees)
       │
       ▼
  Root mount at "/" + devfs at "/dev"
```

After Phase 12, the kernel can `open("/sbin/init")` and read files from the disk image.

#### Phase 13: Mach IPC

```c
ipc_init();    // kernel/mach/ipc.c
```

Initialises the IPC subsystem: 512 port structures, the bootstrap port, and the notification port. Every process will get its own port namespace (256 names). Covered in Chapter 6.

#### Phase 14: IOKit

```c
iokit_init();    // kernel/iokit/io_registry.c (called from iokit_init)
```

Initialises the I/O Registry (a tree of driver objects), the service matching system, and the IOKit Mach port bridge. IOKit is Kiseki's reimplementation of macOS's IOKit in C (instead of C++). Covered in Chapter 10.

#### Phase 15: CommPage and Process Subsystem

```c
commpage_init();    // kernel/kern/commpage.c
proc_init();        // kernel/kern/proc.c
```

The **CommPage** is a read-only page mapped into every user process at a fixed virtual address. It contains the signal trampoline (the code that returns from a signal handler) and time-related data. This is identical to macOS's `__DATA_CONST/__commpage` region.

`proc_init()` initialises the process table (64 slots, matching XNU's `allproc` list).

#### Phase 16: Networking, GPU, Input

```c
net_init();                    // TCP/IP stack, BSD sockets
virtio_gpu_init();             // VirtIO GPU framebuffer (1280×800, B8G8R8X8)
io_framebuffer_init_driver();  // IOFramebuffer IOKit service
fbconsole_init();              // Text console on framebuffer
virtio_input_init();           // VirtIO keyboard + tablet
io_hid_system_init_driver();   // IOHIDSystem IOKit service
```

These are the "optional" subsystems — the kernel can boot without a GPU or network. Each is guarded by an error check:

```c
int gpu_ret = virtio_gpu_init();
if (gpu_ret < 0) {
    kprintf("[boot] No VirtIO GPU found (non-fatal)\n");
}
```

#### Phase 17: Create Bootstrap Thread and Abandon Boot Stack

This is the most architecturally interesting phase:

```c
// Create a kernel thread with its own PMM-allocated stack
struct thread *bootstrap_thread = thread_create(
    "kernel_bootstrap", kernel_bootstrap_thread_func, NULL, PRI_MAX);

// Set bootstrap_thread as current_thread on this CPU
__asm__ volatile("msr daifset, #0x2" ::: "memory");  // Mask IRQs
{
    struct cpu_data *cd;
    __asm__ volatile("mrs %0, tpidr_el1" : "=r"(cd));
    cd->current_thread = bootstrap_thread;
    bootstrap_thread->cpu = 0;
}

// One-way jump — boot stack is never used again
load_context(&bootstrap_thread->context);
```

**Why not just call `kernel_bootstrap_thread_func()` directly?** Because the boot stack is a fixed region defined by the linker script — it's not a proper thread stack allocated by the PMM. If we kept using it, the scheduler would try to save/restore context to it, but it doesn't have a `thread` structure associated with it. By creating a real thread and `load_context()`-ing into it, we ensure every piece of code that runs from here on has a proper thread identity and PMM-allocated stack.

The bootstrap thread function then launches PID 1:

```c
static void kernel_bootstrap_thread_func(void *arg)
{
    kernel_init_process();   // Loads /sbin/init, creates PID 1
    thread_exit();           // This thread is done
}
```

`kernel_init_process()` (in `proc.c`) loads the Mach-O binary for `/sbin/init`, sets up the user stack and arguments, creates a trap frame for the init thread, and enqueues it on the scheduler's run queue. The scheduler will dispatch it to `init_thread_return` (from §2.3), which does the TTBR0 switch and `eret` to EL0.

At this point, the kernel is fully operational and user space takes over.

> **XNU equivalent:** This mirrors XNU's `kernel_bootstrap()` → `kernel_bootstrap_thread()` → `bsd_init()` → `load_init_program()` flow in `osfmk/kern/startup.c` and `bsd/kern/bsd_init.c`.

### 2.6 Secondary Core Bring-Up (SMP)

**Files:** `kernel/arch/arm64/smp.c` (71 lines), `kernel/arch/arm64/boot.S:114-166` (secondary entry)

Kiseki runs on 4 cores. Core 0 runs the full 17-phase bootstrap. Cores 1-3 are woken up in Phase 7 and go through a streamlined per-core initialisation. Let's trace the entire flow.

#### How PSCI Works

**PSCI** (Power State Coordination Interface) is a firmware-level API for controlling CPU cores. It's not an OS feature — it's a standard defined by ARM that firmware (EFI, U-Boot, or QEMU's built-in firmware) implements. The OS calls PSCI functions via `hvc #0` (Hypervisor Call) or `smc #0` (Secure Monitor Call).

The key function is `CPU_ON`:

```c
// smp.c:25 — Start a secondary core
static int64_t psci_cpu_on(uint64_t target_cpu, uint64_t entry_point,
                           uint64_t context_id)
{
    int64_t result;
    __asm__ volatile(
        "mov x0, %1\n"     // x0 = PSCI_CPU_ON_64 = 0xC4000003
        "mov x1, %2\n"     // x1 = target core MPIDR (0, 1, 2, or 3)
        "mov x2, %3\n"     // x2 = entry point (physical address)
        "mov x3, %4\n"     // x3 = context ID (unused, 0)
        "hvc #0\n"          // Call firmware
        "mov %0, x0\n"     // result = return value
        : "=r"(result)
        ...
    );
    return result;
}
```

When PSCI `CPU_ON` succeeds, the target core starts executing at `entry_point` (which is `_secondary_entry` in `boot.S`). The core starts at EL2 with the MMU off — exactly the same state as core 0 at power-on.

#### The Wake-Up Loop

```c
// smp.c:58
void smp_init(void)
{
    for (uint32_t core = 1; core < MAX_CPUS; core++) {
        int64_t ret = psci_cpu_on(core, (uint64_t)_secondary_entry, 0);
        if (ret == 0)
            kprintf("[smp] Core %u: started\n", core);
        else
            kprintf("[smp] Core %u: PSCI CPU_ON failed (err=%ld)\n", core, ret);
    }
}
```

This iterates over cores 1, 2, 3 and wakes each one. Note that the cores were originally spinning in `_secondary_spin` (the `wfe` loop from §2.2), but PSCI doesn't wake them from that loop — it resets them entirely and redirects execution to `_secondary_entry`.

> **Wait, weren't cores 1-3 in `_secondary_spin`?** Yes, from the initial boot. But PSCI `CPU_ON` doesn't send a `sev` (Set Event) to wake them from `wfe`. Instead, it resets the target core's state entirely and starts it fresh at the specified entry point. The `_secondary_spin` loop is a fallback for platforms without PSCI — on QEMU, it's effectively dead code after `smp_init()`.

#### Secondary Core Entry (boot.S:114-166)

Each secondary core starts at `_secondary_entry`:

```asm
_secondary_entry:
    // 1. Read core ID
    mrs     x0, mpidr_el1
    and     x0, x0, #0xFF

    // 2. Drop from EL2 to EL1 (same as primary core)
    mrs     x1, CurrentEL
    and     x1, x1, #0xC
    cmp     x1, #0x8
    b.ne    _secondary_at_el1

    // EL2 → EL1 drop
    mov     x1, #(1 << 31)
    msr     hcr_el2, x1
    mov     x1, #0x3C5
    msr     spsr_el2, x1
    adr     x1, _secondary_at_el1
    msr     elr_el2, x1
    eret

_secondary_at_el1:
    // 3. Re-read core ID (may have been lost in EL drop)
    mrs     x0, mpidr_el1
    and     x0, x0, #0xFF

    // 4. Enable FP/SIMD (must match primary core)
    mov     x1, #(3 << 20)
    msr     cpacr_el1, x1
    isb

    // 5. Set up per-core stack
    //    SP = __stack_top - (core_id * 0x8000)
    ldr     x1, =__stack_top
    mov     x2, #0x8000            // 32 KB per core
    mul     x3, x0, x2
    sub     x1, x1, x3
    mov     sp, x1

    // 6. Install exception vectors
    ldr     x1, =_vectors
    msr     vbar_el1, x1
    isb

    // 7. Call C entry point
    bl      secondary_main
    b       _halt
```

The secondary core boot is simpler than primary — no BSS clearing (already done), no UART init, no `kmain()`. Each core just gets its own stack and jumps to `secondary_main()`.

**Note the stack calculation:** Core 1's SP = `__stack_top - 0x8000`, Core 2's SP = `__stack_top - 0x10000`, Core 3's SP = `__stack_top - 0x18000`.

#### secondary_main() — Per-Core Initialisation

```c
// main.c:391
void secondary_main(uint64_t core_id)
{
    // CRITICAL: Enable MMU first!
    vmm_init_percpu();     // Set TTBR1, MAIR, TCR, enable MMU

    gic_init_percpu();     // Configure per-core GIC interface
    sched_init_percpu();   // Create per-core cpu_data, set TPIDR_EL1
    timer_init_percpu();   // Start per-core timer (100 Hz tick)

    kprintf("[smp] Core %lu online (scheduler + timer ready)\n", core_id);

    // Abandon boot stack → jump to idle thread
    {
        struct cpu_data *cd;
        __asm__ volatile("mrs %0, tpidr_el1" : "=r"(cd));
        load_context(&cd->idle_thread->context);
    }

    __builtin_unreachable();
}
```

**Four per-core inits:**

| Function | Purpose |
|---|---|
| `vmm_init_percpu()` | Sets up this core's page table registers (`TTBR1_EL1`, `MAIR_EL1`, `TCR_EL1`) and enables the MMU. **Must be first** — without the MMU, exclusive monitors (`LDAXR`/`STXR`) for spinlocks may not work, and core 0's memory writes may be invisible. |
| `gic_init_percpu()` | Enables this core's GIC CPU interface so it can receive interrupts. |
| `sched_init_percpu()` | Allocates and installs the per-core `cpu_data` structure in `TPIDR_EL1`, creates this core's idle thread. |
| `timer_init_percpu()` | Programs this core's ARM Generic Timer to fire at 100 Hz. |

After init, the core abandons its boot stack via `load_context()` (exactly as core 0 does in Phase 17) and jumps into its idle thread's `thread_trampoline`. The idle thread enables interrupts (`daifclr #0x2`) and enters a WFI loop, waiting for the scheduler to assign it work.

> **CRITICAL: MMU before spinlocks.** The comment in `main.c:397-398` explains: secondary cores start with the MMU off (PSCI reset value). Without caches, the ARM exclusive monitor mechanism (used by spinlocks, mutexes, and atomic operations) may not work correctly across cores. The MMU must be enabled before touching *any* shared data structure.

#### The Full SMP Timeline

```
Time ──────────────────────────────────────────────────────────────►

Core 0: _start → _at_el1 → kmain()
         │
         ├── Phase 1-6 (UART, GIC, PMM, VMM, Threads, Timer)
         │
         ├── Phase 7: smp_init()
         │      │
         │      ├── psci_cpu_on(1, _secondary_entry)
         │      │       Core 1: ──► _secondary_entry → _secondary_at_el1
         │      │                     → secondary_main(1) → load_context()
         │      │                     → idle thread (WFI loop)
         │      │
         │      ├── psci_cpu_on(2, _secondary_entry)
         │      │       Core 2: ──► (same as core 1)
         │      │
         │      └── psci_cpu_on(3, _secondary_entry)
         │              Core 3: ──► (same as core 1)
         │
         ├── Phases 8-16 (Block, FS, IPC, IOKit, Net, GPU, ...)
         │
         └── Phase 17: load_context() → bootstrap thread
                                          → kernel_init_process()
                                          → thread_exit()

         All cores now running idle threads, waiting for work.
         Scheduler dispatches init (PID 1) → init_thread_return → EL0
```

At this point the entire boot sequence is complete. All 4 cores are online, the kernel is fully initialised, and PID 1 (`/sbin/init`) is about to start executing in user space. The next chapter covers how the physical and virtual memory systems that underpin all of this actually work.

---

## Chapter 3: Physical & Virtual Memory

Every piece of code we've seen so far depends on memory management. The boot code allocates page tables from the PMM. The scheduler allocates thread stacks. `fork()` copies address spaces. `execve()` maps Mach-O segments. The GPU driver maps framebuffers. This chapter explains the two layers that make it all work:

1. **Physical memory management (PMM)** -- how the kernel tracks and allocates raw RAM pages
2. **Virtual memory management (VMM)** -- how the kernel creates the illusion that every process has its own private address space

### 3.1 Why Virtual Memory Exists

Without virtual memory, every program would share a single flat address space. Program A could read Program B's data. A bug in a web browser could corrupt the kernel. Two programs couldn't both use address `0x1000` -- they'd collide.

**Virtual memory** solves all three problems by giving each process its own **private address space**. When Program A accesses address `0x1000`, the **MMU** (Memory Management Unit) translates it to physical address `0x50000`. When Program B accesses the same address `0x1000`, the MMU translates it to physical address `0x80000`. Neither program knows about the other's memory.

```
                Program A                     Program B
              (virtual memory)              (virtual memory)
         +-----------------------+     +-----------------------+
         |                       |     |                       |
0x3000   |  stack                |     |  stack                |  0x3000
         |                       |     |                       |
0x2000   |  heap                 |     |  heap                 |  0x2000
         |                       |     |                       |
0x1000   |  code                 |     |  code                 |  0x1000
         |                       |     |                       |
0x0000   |  (unmapped, SEGFAULT) |     |  (unmapped, SEGFAULT) |  0x0000
         +-----------+-----------+     +----------+------------+
                     |                            |
                     | MMU                        | MMU
                     | translates                 | translates
                     v                            v
         +-------------------------------------------------+
         |         Physical RAM (shared hardware)           |
         |                                                  |
         | 0x50000: A's code   0x80000: B's code            |
         | 0x51000: A's heap   0x81000: B's heap            |
         | 0x52000: A's stack  0x82000: B's stack           |
         |          ....                                    |
         +-------------------------------------------------+
```

The translation happens automatically in hardware, on every memory access, with zero software overhead for the common case. The kernel only gets involved when something goes wrong (page fault) or when it needs to change the mapping (fork, exec, mmap).

### 3.2 The Buddy Allocator (PMM)

**Files:** `kernel/kern/pmm.c` (387 lines), `kernel/include/kern/pmm.h` (101 lines)

The PMM answers the simplest question in memory management: **"Give me N physical pages."** It manages all RAM from `__heap_start` (end of the kernel image) to the end of physical memory (4 GB on QEMU).

#### How the Buddy System Works

The buddy allocator organises free memory into **11 free lists**, one per "order" (power of 2):

```
Order    Block Size     Pages    Free List
------------------------------------------
  0        4 KB           1      order_0 -> [page] -> [page] -> ...
  1        8 KB           2      order_1 -> [page] -> ...
  2       16 KB           4      order_2 -> ...
  3       32 KB           8      order_3 -> ...
  4       64 KB          16      order_4 -> ...
  5      128 KB          32      order_5 -> ...
  6      256 KB          64      order_6 -> ...
  7      512 KB         128      order_7 -> ...
  8        1 MB         256      order_8 -> ...
  9        2 MB         512      order_9 -> ...
 10        4 MB       1,024      order_10 -> ...
```

**Allocation:** To allocate 2^n pages, look at `free_list[n]`. If it's empty, try `free_list[n+1]` and **split** the larger block in half -- one half satisfies the request, the other half goes onto `free_list[n]`. Repeat up the orders until a block is found.

**Freeing:** When a block is freed, check if its **buddy** (the adjacent block of the same size) is also free. If so, **coalesce** them into a single block at the next order up. Repeat until the buddy is in use or we reach the maximum order.

```
Example: Allocate 1 page (order 0) when only order-2 blocks are free

  order_2:  [block: 4 pages at 0x50000]

  Step 1: Split order-2 block into two order-1 blocks
  order_1:  [0x52000 (2 pages)]        <-- put on free list
  order_1:  [0x50000 (2 pages)]        <-- continue splitting

  Step 2: Split order-1 block into two order-0 blocks
  order_0:  [0x51000 (1 page)]         <-- put on free list
  order_0:  [0x50000 (1 page)]         <-- return to caller
```

**Why "buddy"?** Two blocks are buddies if they differ by exactly one bit in their page index. For a block at page index `i` with order `n`, its buddy is at index `i XOR (1 << n)`:

```c
// pmm.c:94 -- Finding a block's buddy
static struct page *buddy_of(struct page *pg, uint32_t order)
{
    uint64_t idx = page_index(pg);
    uint64_t buddy_idx = idx ^ (1UL << order);   // Flip the order-th bit
    if (buddy_idx >= total_pages)
        return NULL;
    return &pages[buddy_idx];
}
```

#### The Page Descriptor Array

Every physical page has a 32-byte descriptor:

```c
// pmm.h:32
struct page {
    uint32_t flags;       // PAGE_FREE, PAGE_USED, PAGE_RESERVED
    uint32_t order;       // Buddy order (if head of free block)
    uint32_t refcount;    // Reference count (for COW sharing)
    uint32_t _pad;
    struct page *next;    // Next in free list (doubly linked)
    struct page *prev;    // Prev in free list
};
```

Kiseki allocates a static array of 262,144 descriptors (`PMM_MAX_PAGES = 256 * 1024`), covering up to 1 GB of RAM. At 32 bytes each, this costs 8 MB of kernel BSS -- a fixed overhead regardless of how much RAM is actually present.

> **Why not dynamic?** At the point the PMM initialises, there is no dynamic allocator yet. The PMM *is* the foundation on which everything else is built. A static array is the simplest bootstrap.

#### Spinlock Protection

All PMM operations (`pmm_alloc_page`, `pmm_free_page`, `pmm_page_ref`, `pmm_page_unref`) are protected by a single spinlock with IRQ save/restore:

```c
// pmm.c:26
static spinlock_t pmm_lock = SPINLOCK_INIT;

// pmm.c:173 (inside pmm_alloc_pages)
spin_lock_irqsave(&pmm_lock, &flags);
// ... allocate ...
spin_unlock_irqrestore(&pmm_lock, flags);
```

`spin_lock_irqsave` disables interrupts before taking the lock. This prevents a timer IRQ from triggering a context switch while the lock is held, which would cause a deadlock if the new thread also tried to allocate memory.

#### Audit Bitmap

In debug builds, the PMM maintains an independent bitmap (`pmm_audit_bitmap[]`) that tracks which pages are allocated. Every allocation checks that the pages aren't already allocated; every free checks that they aren't already free. This catches double-alloc and double-free bugs immediately:

```c
// pmm.c:213 -- Double-alloc detection
if (audit_is_allocated(base_idx + a)) {
    kprintf("[PMM BUG] DOUBLE ALLOC! page idx %lu ...\n", ...);
}
```

#### Reference Counting (for COW)

Each page has a `refcount` field. When a page is first allocated, `refcount = 1`. When `fork()` shares the page between parent and child (copy-on-write), both processes' page tables point to the same physical page, and `refcount` is incremented to 2. When one process writes to the page, the COW handler (`vmm_copy_on_write`) copies it, and the original page's refcount drops back to 1.

```c
// pmm.c:303
void pmm_page_ref(uint64_t paddr)   { pg->refcount++; }

// pmm.c:315
void pmm_page_unref(uint64_t paddr) {
    if (--pg->refcount == 0) {
        pg->flags = PAGE_FREE;
        // ... coalesce with buddy ...
    }
}
```

### 3.3 ARM64 Page Tables

**File:** `kernel/include/kern/vmm.h` (420 lines)

The MMU needs to know how to translate virtual addresses to physical addresses. This mapping is stored in a data structure called a **page table**, which lives in ordinary RAM and is managed by the kernel.

ARM64 uses a **4-level page table** with a **4 KB granule**. A 48-bit virtual address is split into five fields:

```
63    48 47    39 38    30 29    21 20    12 11        0
+-------+--------+--------+--------+--------+----------+
| unused|  L0    |  L1    |  L2    |  L3    |  offset  |
| sign  | index  | index  | index  | index  | in page  |
| extend| 9 bits | 9 bits | 9 bits | 9 bits | 12 bits  |
+-------+--------+--------+--------+--------+----------+
         512       512      512      512       4096
        entries   entries  entries  entries    bytes
```

Each level is a table of **512 entries**, each **8 bytes** (64 bits), fitting exactly in one **4 KB page** (512 x 8 = 4096). The translation walks four levels:

```
TTBR0_EL1 (user) or TTBR1_EL1 (kernel)
     |
     |  bits [47:39]
     v
  +-----+     +-----+     +-----+     +-----+
  | L0  |---->| L1  |---->| L2  |---->| L3  |----> Physical Page
  | PGD |     | PUD |     | PMD |     | PTE |      + offset [11:0]
  +-----+     +-----+     +-----+     +-----+
  512 entries  512 entries  512 entries  512 entries
  (one page)  (one page)  (one page)  (one page)
```

**Concrete example:** Translating virtual address `0x0000000100004000`:

```
VA = 0x0000000100004000

  Bits [47:39] = 0x000  --> L0[0]     (1st entry of L0)
  Bits [38:30] = 0x004  --> L1[4]     (5th entry of L1)
  Bits [29:21] = 0x000  --> L2[0]     (1st entry of L2)
  Bits [20:12] = 0x004  --> L3[4]     (5th entry of L3)
  Bits [11:0]  = 0x000  --> offset 0  (start of page)

  L0[0] -> points to L1 table at PA 0x41000000
  L1[4] -> points to L2 table at PA 0x41001000
  L2[0] -> points to L3 table at PA 0x41002000
  L3[4] -> points to data page at PA 0x50004000

  Final PA = 0x50004000 + 0x000 = 0x50004000
```

> **Index extraction in code** (`vmm.c:59-62`):
> ```c
> #define L0_IDX(va)  (((va) >> 39) & 0x1FF)   // bits [47:39]
> #define L1_IDX(va)  (((va) >> 30) & 0x1FF)   // bits [38:30]
> #define L2_IDX(va)  (((va) >> 21) & 0x1FF)   // bits [29:21]
> #define L3_IDX(va)  (((va) >> 12) & 0x1FF)   // bits [20:12]
> ```

#### Page Table Entry Format

Each 64-bit PTE contains the physical address of the next level (or the data page) plus permission and attribute bits:

```
63  55 54 53 52    48 47            12 11 10  9  8  7  6  5  4  2  1  0
+-----+--+--+-------+----------------+--+--+--+--+--+--+--+----+--+--+
| SW  |XN|PX|  res  | Physical addr  |AF|SH |AP |NS |  AI |Tbl |Vld|
|     |  |N |       | [47:12]        |  |   |   |   |     |    |   |
+-----+--+--+-------+----------------+--+--+--+--+--+--+--+----+--+--+
  |     |  |                           |   |   |         |    |    |
  |     |  +-- Privileged XN           |   |   |         |    |    +-- Valid
  |     +-- User XN (no execute)       |   |   |         |    +-- Table/Page
  |                                    |   |   |         +-- MAIR attr index
  +-- Software bits (COW flag here)    |   |   +-- Access Permission
                                       |   +-- Shareability
                                       +-- Access Flag
```

Kiseki defines these in `vmm.h:29-53`:

| Constant | Bits | Meaning |
|---|---|---|
| `PTE_VALID` | [0] | Entry is valid (hardware checks this) |
| `PTE_TABLE` / `PTE_PAGE` | [1:0] | Table descriptor (L0-L2) or page descriptor (L3) |
| `PTE_AP_RW_ALL` | [6] | Both EL1 and EL0 can read/write |
| `PTE_AP_RO_ALL` | [7:6]=11 | Both EL1 and EL0 can only read |
| `PTE_AF` | [10] | Access flag (must be set or first access faults) |
| `PTE_SH_INNER` | [9:8]=11 | Inner shareable (required for SMP cache coherency) |
| `PTE_PXN` | [53] | Privileged execute never (kernel can't run this code) |
| `PTE_UXN` | [54] | User execute never (user can't run this code) |
| `PTE_COW` | [55] | **Software bit**: marks a page as copy-on-write |

Common combinations used by Kiseki:

| Macro | Used for | Permissions |
|---|---|---|
| `PTE_KERNEL_RWX` | Kernel code | Kernel R/W/X, user no access, cacheable |
| `PTE_KERNEL_RW` | Kernel data | Kernel R/W, no execute, cacheable |
| `PTE_DEVICE` | MMIO (UART, GIC, VirtIO) | Kernel R/W, no execute, no cache |
| `PTE_USER_RWX` | User code+data | User+kernel R/W/X, cacheable |
| `PTE_USER_RW` | User heap/stack | User R/W, no execute, cacheable |
| `PTE_USER_RO` | User read-only data | User R/O, no execute, cacheable |
| `PTE_USER_RX` | User __TEXT segment | User R/X, kernel no exec, cacheable |

### 3.4 Kernel Address Space Setup

**File:** `kernel/kern/vmm.c:224-322` (`vmm_init`)

When `kmain()` calls `vmm_init()` in Phase 4, the MMU is still off -- all addresses are physical. `vmm_init()` builds the kernel page tables and then flips the MMU on. Here's what it does:

**Step 1: Allocate the L0 table.**

```c
kernel_pgd = alloc_pt_page();   // 4KB page, zeroed
```

**Step 2: Identity-map all of RAM.**

```c
for (uint64_t addr = RAM_BASE; addr < ram_end; addr += PAGE_SIZE)
    vmm_map_page(kernel_pgd, addr, addr, PTE_KERNEL_RWX);
```

This maps virtual address `0x40080000` to physical address `0x40080000` (VA == PA) for every page of RAM. The kernel continues running at the same addresses after the MMU is enabled.

> **Why identity mapping?** A higher-half kernel (where kernel VA = `0xFFFF000040080000`) is more elegant but requires carefully writing position-independent code or using a trampoline to jump from the physical address to the virtual address after enabling the MMU. Kiseki takes the simpler approach.

**Step 3: Map MMIO regions as device memory.**

```c
vmm_map_page(kernel_pgd, UART0_BASE, UART0_BASE, PTE_DEVICE);
// ... GIC distributor/CPU interface ...
// ... VirtIO MMIO slots ...
```

Device memory uses `MAIR_DEVICE_nGnRnE` (index 0): no caching, no gathering, no reordering. This ensures that writes to hardware registers happen in program order and are immediately visible to the device.

**Step 4: Configure translation control registers.**

```c
// MAIR_EL1: Memory attribute encodings
//   Index 0: Device-nGnRnE  (0x00)  -- for MMIO
//   Index 1: Normal NC       (0x44)  -- for GPU framebuffer
//   Index 2: Normal WB       (0xFF)  -- for regular RAM
msr mair_el1, mair

// TCR_EL1: Translation Control Register
//   T0SZ=16: 48-bit user VA space (256 TB)
//   T1SZ=16: 48-bit kernel VA space
//   TG0/TG1=4KB: page granule
//   SH0/SH1=Inner Shareable: required for SMP
//   ORGN0/IRGN0=WB-WA: outer/inner write-back write-allocate caching
msr tcr_el1, tcr

// TTBR0_EL1 and TTBR1_EL1: both point to kernel_pgd
msr ttbr0_el1, kernel_pgd
msr ttbr1_el1, kernel_pgd
```

**Step 5: Enable the MMU.**

```c
mrs sctlr, sctlr_el1
sctlr |= (1 << 0)    // M: MMU on
sctlr |= (1 << 2)    // C: Data cache on
sctlr |= (1 << 12)   // I: Instruction cache on
msr sctlr_el1, sctlr
isb
```

After this `isb`, every memory access goes through the page tables. The identity mapping ensures the next instruction (which the CPU fetches from the same physical address) is still reachable.

> **Two TTBRs:** ARM64 has two translation table base registers. `TTBR0_EL1` translates addresses in the **lower half** (bit 63 = 0, i.e., user space: `0x0000...`). `TTBR1_EL1` translates addresses in the **upper half** (bit 63 = 1, i.e., kernel space: `0xFFFF...`). Kiseki currently uses identity mapping with both TTBRs pointing to the same table, but the architecture is designed for the eventual split where user page tables go in TTBR0 and the kernel page table stays in TTBR1.

### 3.5 User Address Spaces

**File:** `kernel/kern/vmm.c:326-434` (`vmm_create_space`)

When `fork()` or `execve()` creates a new process, the kernel calls `vmm_create_space()` to create a fresh user address space. This returns a `vm_space` structure:

```c
// vmm.h:188
struct vm_space {
    pte_t    *pgd;     // L0 page table (physical address)
    uint64_t  asid;    // Address Space ID (for TLB tagging, 1-255)
    struct vm_map *map; // Software region map (sorted linked list)
};
```

The user address space has a carefully designed layout:

```
User Virtual Address Space Layout

0x0000000000000000  +-----------------------------+
                    |  __PAGEZERO (unmapped)       |  Null dereference trap
0x0000000100000000  +-----------------------------+
                    |  Main binary (__TEXT, __DATA) |  Loaded by execve()
                    |  (Mach-O segments)           |
0x0000000200000000  +-----------------------------+
                    |  dyld (dynamic linker)       |  Loaded by execve()
                    |                              |
0x0000000300000000  +-----------------------------+
                    |  mmap region                 |  Anonymous + file-backed
                    |  (grows upward)              |  mappings from mmap()
                    |                              |
                    |          ...                 |
                    |                              |
0x0000000FFFFFC000  +-----------------------------+
                    |  CommPage (4 KB, read-only)  |  Signal trampoline, time
                    |                              |
                    |          ...                 |
                    |                              |
0x00007FFFFFFF0000  +-----------------------------+
                    |  User stack (grows downward) |  8 MB default
0x00007FFFFFFFFFFF  +-----------------------------+
```

**Creating the L0 table** is not as simple as allocating a blank page. The user page table must include the kernel's identity mapping so that when a syscall traps from EL0 to EL1, the kernel code is still accessible. Kiseki handles this by allocating **per-process L1 tables** and copying the kernel's L1 entries into them:

```
Kernel PGD (L0)                   User PGD (L0)
+---------+                       +---------+
| L0[0]   | -> kernel L1         | L0[0]   | -> user L1 (copy of kernel L1 entries)
| L0[1]   | -> (empty)           | L0[1]   | -> (empty)
|  ...    |                       |  ...    |
+---------+                       +---------+

User L1 table:
  - Entries for kernel VAs (MMIO, RAM) -> shared L2/L3 from kernel
  - Entries for user VAs (binary, mmap) -> separate L2/L3 per process
```

This ensures that when `walk_pgd` allocates new L2/L3 tables for user virtual addresses, they go into the **per-process** L1 rather than the kernel's L1. Without this, all processes would share a single L1 table, and mapping user VA `0x100004000` in process A would also make it visible in process B.

**ASIDs** (Address Space IDs) are 8-bit tags (1-255) assigned to each address space. They allow the TLB to cache translations from multiple processes simultaneously. When a context switch changes `TTBR0_EL1`, the new ASID is encoded in bits [63:48] of the TTBR value (`pgd | (asid << 48)`). Stale TLB entries from the old process (with a different ASID) won't match, avoiding the need for a full TLB flush on every context switch. When ASIDs wrap around past 255, Kiseki does a global TLB flush (`tlbi vmalle1is`).

### 3.6 Copy-on-Write (COW)

**File:** `kernel/kern/vmm.c:562-625` (`vmm_copy_on_write`)

When `fork()` creates a child process, copying the entire address space page-by-page would be expensive (a process with 100 MB of data would need to copy 100 MB). **Copy-on-write** avoids this by sharing pages between parent and child, only copying when one of them writes.

The COW flow:

```
1. fork() is called
   +---------------------------+          +---------------------------+
   |  Parent (PID 10)          |          |  Child (PID 11)           |
   |  VA 0x100004000           |          |  VA 0x100004000           |
   |  PTE: PA=0x50000 RW       |          |  PTE: PA=0x50000 RO+COW  |
   +-------------+-------------+          +-------------+-------------+
                 |                                      |
                 +-----------> Physical page 0x50000 <--+
                               refcount = 2

2. Child writes to 0x100004000 --> Data Abort (page fault)!
   The PTE is read-only, so the write faults.

3. Kernel handles the fault:
   - Sees PTE_COW is set --> this is a COW fault, not a bug
   - refcount > 1 --> allocate new page, copy 4 KB
   - Update child's PTE to point to new page (RW, COW cleared)
   - Decrement old page's refcount (now 1)

   +---------------------------+          +---------------------------+
   |  Parent (PID 10)          |          |  Child (PID 11)           |
   |  VA 0x100004000           |          |  VA 0x100004000           |
   |  PTE: PA=0x50000 RW       |          |  PTE: PA=0x60000 RW      |
   +-------------+-------------+          +-------------+-------------+
                 |                                      |
                 v                                      v
        Physical 0x50000                       Physical 0x60000
        refcount = 1                           refcount = 1
        (original data)                        (copied data)
```

The key code in `vmm_copy_on_write()`:

```c
// vmm.c:562
int vmm_copy_on_write(struct vm_space *space, uint64_t va)
{
    pte_t *pte = walk_pgd(space->pgd, va, false);
    uint64_t old_pa = PTE_TO_PHYS(*pte);
    uint32_t refcount = pmm_page_refcount(old_pa);

    // Preserve original flags but change RO -> RW, clear COW bit
    uint64_t orig_flags = *pte & ~PTE_ADDR_MASK;
    uint64_t new_flags = (orig_flags & ~(3UL << 6) & ~PTE_COW) | PTE_AP_RW_ALL;

    if (refcount <= 1) {
        // Sole owner: just make writable in place
        *pte = (old_pa & PTE_ADDR_MASK) | new_flags;
        tlbi vale1is;    // Flush stale TLB entry
        return 0;
    }

    // Multiple owners: copy the page
    uint64_t new_pa = pmm_alloc_page();
    memcpy(new_pa, old_pa, 4096);       // Copy 4 KB

    *pte = (new_pa & PTE_ADDR_MASK) | new_flags;
    pmm_page_unref(old_pa);             // Drop shared reference
    tlbi vale1is;                        // Flush stale TLB entry
    return 0;
}
```

> **Software PTE_COW bit:** ARM64 reserves bits [58:55] in PTEs for software use (the hardware ignores them). Kiseki uses bit 55 (`PTE_COW`) to mark pages that are shared via copy-on-write. When a write fault occurs, the trap handler (`trap.c`) checks this bit to distinguish a COW fault (copy the page) from a genuine permission violation (kill the process with SIGSEGV).

### 3.7 The VM Map

**File:** `kernel/kern/vmm.c:712-` and `kernel/include/kern/vmm.h:99-418`

The page tables (the "pmap" in XNU terminology) are a hardware cache of the kernel's intent. The authoritative record of what is mapped, with what permissions, and how regions behave on fork is the **vm_map** -- a sorted linked list of `vm_map_entry` structures.

```c
// vmm.h:134
struct vm_map_entry {
    struct vm_map_entry *prev, *next;   // Sorted doubly-linked list
    uint64_t  vme_start;               // Region start (page-aligned)
    uint64_t  vme_end;                 // Region end (exclusive)
    uint8_t   protection;              // Current: VM_PROT_READ|WRITE|EXECUTE
    uint8_t   max_protection;          // Ceiling for mprotect()
    uint8_t   inheritance;             // Fork: VM_INHERIT_COPY, SHARE, or NONE
    uint8_t   is_shared : 1;           // MAP_SHARED?
    uint8_t   needs_copy : 1;          // Deferred COW
    uint8_t   wired : 1;              // Pinned (mlock)
    int       backing_fd;              // File descriptor (-1 = anonymous)
    uint64_t  file_offset;             // Offset into backing file
    struct vnode *backing_vnode;        // Vnode (NULL = anonymous)
};

// vmm.h:170
struct vm_map {
    struct vm_map_entry header;        // Sentinel (list head)
    int          nentries;
    uint64_t     min_offset;           // Lowest valid VA
    uint64_t     max_offset;           // Highest valid VA
    uint64_t     hint_addr;            // Hint for next allocation
    spinlock_t   lock;
    struct vm_map_entry entries[512];   // Static pool (no kmalloc needed)
    uint8_t      entry_used[512];
};
```

**Key vm_map operations:**

| Function | Purpose | XNU Equivalent |
|---|---|---|
| `vm_map_enter()` | Create a new region (used by `mmap`, `execve`) | `vm_map_enter` |
| `vm_map_remove()` | Remove regions in a range (used by `munmap`) | `vm_map_remove` |
| `vm_map_lookup_entry()` | Find the entry containing an address | `vm_map_lookup_entry` |
| `vm_map_protect()` | Change protection on a range (used by `mprotect`) | `vm_map_protect` |
| `vm_map_fork()` | Copy the map for `fork()`, respecting inheritance | `vm_map_fork` |

The vm_map uses a **static pool** of 512 entries per process (no dynamic allocation needed). Entries are stored in a sorted doubly-linked list by `vme_start`. XNU also uses an RB-tree for O(log n) lookup; Kiseki uses linear search, which is sufficient for the current scale of ~50-100 entries per process.

**Interaction between vm_map and pmap:**

```
mmap(addr, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0)
  |
  v
vm_map_enter()          <-- Creates vm_map_entry (software record)
  |                         protection = RW, inheritance = COPY
  |                         backing_fd = -1 (anonymous)
  v
(return to user)        <-- No physical pages allocated yet!
  |
  v
User writes to addr     <-- Page fault! (no PTE exists)
  |
  v
trap_sync_el0()
  -> handle_page_fault()
     -> vm_map_lookup_entry()   <-- Find the entry for this VA
     -> pmm_alloc_page()        <-- Allocate physical page
     -> vmm_map_page()          <-- Create PTE in the pmap
     -> return to user          <-- Fault resolved, instruction retries
```

This is **demand paging** -- physical pages are only allocated when first accessed, not when `mmap()` is called. The vm_map records the intent; the pmap is populated lazily on fault.

---

## Chapter 4: Threads, Scheduling & Synchronisation

Everything described so far -- page tables, buddy allocator, address spaces -- is static infrastructure. Nothing actually *runs* until we introduce **threads**: the unit of execution that the CPU schedules. This chapter explains how Kiseki creates threads, picks which one to run next, switches between them, and coordinates them when they need to share data.

### 4.1 What Is a Thread?

**For the systems newcomer:** A program sitting on disk is just bytes. When you launch it, the kernel creates a *process* (a container with its own address space, file descriptors, and permissions) and at least one *thread* inside that process. The thread is what the CPU actually executes -- it has its own:

- **Program counter** (where in the code it is)
- **Stack** (local variables, function call chain)
- **Register state** (the values in x0-x30, SP, NEON registers, etc.)

Multiple threads in the same process share the address space (same page tables), so they can read each other's global variables. Multiple threads in *different* processes cannot (different page tables).

```
Process A (PID 10)                    Process B (PID 11)
+-------------------------------+     +-------------------------------+
|  Address space (TTBR0 = 0x..) |     |  Address space (TTBR0 = 0x..) |
|                               |     |                               |
|  +----------+ +----------+   |     |  +----------+                 |
|  | Thread 1 | | Thread 2 |   |     |  | Thread 1 |                 |
|  | tid=1    | | tid=2    |   |     |  | tid=3    |                 |
|  | SP, PC,  | | SP, PC,  |   |     |  | SP, PC,  |                 |
|  | regs     | | regs     |   |     |  | regs     |                 |
|  +----------+ +----------+   |     |  +----------+                 |
|       (share same memory)     |     |                               |
+-------------------------------+     +-------------------------------+
        Isolated from Process B               Isolated from Process A
```

**Mach threading model:** Like XNU (macOS), Kiseki uses a **1:1 model** -- every user thread maps to exactly one kernel thread. The kernel-side structure (`struct thread`) tracks both the user-space state (saved in the trap frame on syscall entry) and the kernel-space state (saved in `cpu_context` on context switch). Some systems use N:M models (many user threads multiplexed onto fewer kernel threads), but 1:1 is simpler and what macOS uses.

**Key terminology:**
| Term | Meaning |
|------|---------|
| **Thread** | Unit of execution (has its own registers & stack) |
| **Task** | Mach name for a process container (owns address space, IPC ports) |
| **Run queue** | List of threads ready to execute |
| **Quantum** | Time slice -- how many timer ticks a thread runs before the scheduler can preempt it |
| **Context switch** | Saving one thread's registers and loading another's |
| **Wait channel** | An address that a sleeping thread is "waiting on" (BSD `tsleep`/`wakeup` pattern) |

### 4.2 Thread Representation

**File:** `kernel/include/kern/thread.h`

Every thread in Kiseki is a `struct thread` from a **static pool** of 256 entries:

```c
// sched.c:26-28
static struct thread thread_pool[MAX_THREADS];   // MAX_THREADS = 256
static uint64_t next_tid = 1;
static spinlock_t thread_lock = SPINLOCK_INIT;
```

No `malloc` -- thread structures are pre-allocated. `alloc_thread()` scans the pool for a slot with `tid == 0` (never used) or `state == TH_TERM` (terminated, can be recycled). This is the same static-pool pattern used for PMM page descriptors, vm_map entries, and IPC ports throughout Kiseki.

Here is the full thread structure with annotations:

```c
// thread.h:79-127
struct thread {
    /* --- Identity & state --- */
    uint64_t        tid;                // Unique thread ID (1, 2, 3, ...)
    int             state;              // TH_RUN(0), TH_WAIT(1), TH_IDLE(2), TH_TERM(3)
    int             priority;           // Base priority (0-127, higher = more important)
    int             effective_priority; // May be boosted by priority inheritance
    int             sched_policy;       // SCHED_OTHER(0), SCHED_FIFO(1), SCHED_RR(2)
    int             quantum;            // Ticks remaining in current time slice
    int             cpu;                // CPU core currently running on (-1 = never run)
    uint32_t        cpu_affinity;       // Bitmask: 0 = any core, else restrict

    /* --- Saved registers --- */
    struct cpu_context context;         // 168 bytes: x19-x30, SP, d8-d15
    uint64_t        *kernel_stack;      // Base of 32 KB kernel stack
    uint64_t        kernel_stack_size;

    /* --- Process linkage --- */
    struct task     *task;              // Owning Mach task (NULL = pure kernel thread)

    /* --- Sleep/wake --- */
    void            *wait_channel;      // BSD-style: address we're sleeping on
    const char      *wait_reason;       // Debug string ("pipe_read", "mutex_lock", etc.)

    /* --- Queue pointers --- */
    struct thread   *run_next;          // Next thread in same priority's run queue
    struct thread   *wait_next;         // Next thread in a mutex/semaphore wait queue
    struct thread   *sleep_next;        // Next thread in the timed-sleep queue
    struct thread   *task_next;         // Next thread in same task's thread list

    /* --- Mach features --- */
    uint64_t        continuation;       // Stackless continuation (function pointer)
    uint32_t        thread_port;        // Mach port name for thread_self_trap()
    uint64_t        tls_base;           // TPIDR_EL0 (user-space TLS pointer)

    /* --- Timed sleep --- */
    uint64_t        wakeup_tick;        // Tick at which to auto-wake (0 = not timed)

    /* --- pthread join/detach --- */
    bool            detached;
    bool            joined;
    void            *exit_value;        // Return value from pthread_exit()
    struct thread   *join_waiter;       // Thread waiting in pthread_join()
};
```

**Thread states** form a simple state machine:

```
              sched_enqueue()
                  +---+
                  |   v
  thread_create() --> TH_RUN -----> (running on CPU)
                      ^ |               |
                      | |  quantum expires / sched_yield()
                      | |               |
                      | +<--------------+
                      |
   thread_unblock()   |  thread_block() / thread_sleep_on()
         |            |         |
         +--- TH_WAIT <--------+
                  (sleeping on wait_channel or mutex)
                      |
                      |  thread_exit() / thread_terminate()
                      v
                   TH_TERM  (slot can be recycled)
```

| State | Value | Meaning |
|-------|-------|---------|
| `TH_RUN` | 0 | Runnable: either on a run queue or currently executing |
| `TH_WAIT` | 1 | Blocked: sleeping on a wait channel, mutex, condvar, or timer |
| `TH_IDLE` | 2 | The per-CPU idle thread (only runs when nothing else is runnable) |
| `TH_TERM` | 3 | Terminated: waiting to be reaped or slot recycled |

**The Mach task structure** (`struct task`) is the process container:

```c
// thread.h:136-148
struct task {
    pid_t           pid;
    char            name[32];
    struct vm_space *vm_space;       // Virtual address space (page tables + vm_map)
    struct thread   *threads;        // Linked list of threads in this task
    mach_port_t     task_port;       // Mach task port (for task_for_pid, etc.)
    struct ipc_space *ipc_space;     // Mach IPC port namespace
    /* Security credentials */
    uid_t           uid, gid;        // Real user/group ID
    uid_t           euid, egid;      // Effective user/group ID
};
```

In XNU, the `task` and `proc` structures are separate (Mach layer vs BSD layer). Kiseki merges them for simplicity -- `struct task` serves as both the Mach task and the BSD process.

**Per-CPU data** is how each core tracks its own state:

```c
// thread.h:153-168
struct cpu_data {
    uint32_t        cpu_id;
    struct thread   *current_thread;    // Thread currently executing on this core
    struct thread   *idle_thread;       // This core's idle thread

    /* Per-CPU MLFQ run queues */
    spinlock_t      run_lock;           // Protects run_queue[] and run_count
    struct thread   *run_queue[128];    // 128 priority levels, each a linked list
    uint32_t        run_count;          // Total runnable threads on this core

    /* Scheduling state */
    bool            need_resched;       // Set by sched_tick() when quantum expires
    bool            online;             // True once core is fully initialised
    uint64_t        idle_ticks;         // Counter for idle time
    uint64_t        total_ticks;        // Counter for total time
};
```

Each core stores a pointer to its `cpu_data` in the ARM64 system register `TPIDR_EL1` (Thread Pointer ID Register, EL1). This register is per-core and only accessible from kernel mode, so `get_cpu_data()` is a single `mrs` instruction:

```c
// sched.c:46
static inline struct cpu_data *get_cpu_data(void) {
    struct cpu_data *data;
    __asm__ volatile("mrs %0, tpidr_el1" : "=r"(data));
    return data;
}
```

This is the ARM64 equivalent of x86's `gs:` segment prefix for per-CPU data. XNU uses the same pattern (`current_cpu_datap()` reads from `TPIDR_EL1`).

### 4.3 The MLFQ Scheduler

**File:** `kernel/kern/sched.c`

**For the systems newcomer:** A scheduler answers one question: "which thread should the CPU run next?" The simplest answer is round-robin (take turns), but that treats a latency-sensitive GUI thread the same as a background compiler. A **Multilevel Feedback Queue (MLFQ)** solves this by assigning each thread a priority and always running the highest-priority runnable thread first.

Kiseki's MLFQ has **128 priority levels** (0 = lowest, 127 = highest). Each level has a linked list of threads. The scheduler picks the highest non-empty level and runs the first thread in that list.

```
Per-CPU Run Queue (128 priority levels)

  Priority 127: [Thread A] -> [Thread B] -> NULL     (highest)
  Priority 126: NULL
  Priority 125: NULL
      ...
  Priority  64: [Thread C] -> NULL                    (default user priority)
      ...
  Priority   1: NULL
  Priority   0: [Thread D] -> NULL                    (lowest)

  Scheduler picks: Thread A (highest non-empty level)
```

**Three scheduling policies:**

| Policy | Value | Behaviour |
|--------|-------|-----------|
| `SCHED_OTHER` | 0 | Standard timesharing: priority decays when quantum expires, periodically restored |
| `SCHED_FIFO` | 1 | Real-time FIFO: runs until it blocks or a higher-priority thread arrives |
| `SCHED_RR` | 2 | Real-time round-robin: like FIFO but with time slices |

Most threads use `SCHED_OTHER` (the default). The "feedback" in MLFQ comes from the priority decay rule: when a thread uses its entire quantum (10ms = 10 timer ticks at 100Hz), its `effective_priority` drops by 1. CPU-hungry threads gradually sink to lower priorities, while I/O-bound threads (which block often and rarely exhaust their quantum) stay at higher priorities. This naturally gives interactive programs better responsiveness.

#### The Scheduler Tick

**File:** `kernel/kern/sched.c:1024` (`sched_tick`)

The timer fires at 100Hz on every core. Each core's `timer_handler()` calls `sched_tick()`:

```
Timer IRQ (100 Hz, per-core)
  |
  v
timer_handler()                     [kernel/drivers/timer/timer.c:139]
  |
  +-- Rearm timer (write CNTV_TVAL_EL0)
  |
  +-- CPU 0 only: increment tick_count, poll VirtIO-net RX
  |
  +-- sched_tick()                  [kernel/kern/sched.c:1024]
        |
        +-- Wakeup expired sleepers (CPU 0 only)
        |
        +-- If current == idle_thread:
        |     increment idle_ticks
        |     if run_count > 0: set need_resched
        |
        +-- Else (normal thread):
              quantum--
              if quantum <= 0:
                effective_priority-- (SCHED_OTHER only)
                set need_resched
              every 100 ticks:
                restore effective_priority to base (anti-starvation)
```

The `need_resched` flag is checked on return from the IRQ handler. If set, the trap return path calls `sched_switch()` before returning to the interrupted thread.

#### The Context Switch: sched_switch()

**File:** `kernel/kern/sched.c:769` (`sched_switch`)

This is the core of the scheduler. It runs with **interrupts masked** to prevent nested switches:

```
sched_switch()
  |
  +-- Mask IRQs (save DAIF, set daifset #0x2)
  |
  +-- spin_lock(&run_lock)
  |
  +-- If old thread is still TH_RUN: re-enqueue on local run queue
  |
  +-- Pick next: scan run_queue[127] down to run_queue[0]
  |   Take first thread from highest non-empty level
  |   If nothing found: use idle_thread
  |
  +-- spin_unlock(&run_lock)   (IRQs still masked!)
  |
  +-- If new == old: reset quantum, restore priority, unmask IRQs, return
  |
  +-- Set new->cpu, new->quantum = 10, update current_thread
  |
  +-- Switch VM space? If new->task->vm_space != old->task->vm_space:
  |     vmm_switch_space() -- writes TTBR0_EL1 with new ASID
  |
  +-- context_switch(&old->context, &new->context)   [assembly]
  |     Saves x19-x30, SP, d8-d15 to old->context
  |     Loads x19-x30, SP, d8-d15 from new->context
  |     "ret" jumps to new->context.x30 (the new thread's saved LR)
  |
  +-- (We are now running as the RESUMED thread)
  +-- Restore IRQs from this thread's saved DAIF flags
```

**Why IRQs must stay masked across context_switch:** If a timer IRQ fired between releasing the run lock and saving the old context, it would trigger a *nested* `sched_switch()`. The nested switch would save and restore registers at a deeper stack frame, and when the outer switch's `context_switch` returns, the stack would be corrupted. This is the same reason XNU's `machine_switch_context()` runs with interrupts disabled.

**Same-thread optimisation:** When only one thread is runnable, `sched_switch()` detects `new == old` and takes a fast path: reset the quantum and restore the priority (so a sole thread isn't permanently penalised by priority decay), then return without touching `context_switch`.

#### Thread Creation

**File:** `kernel/kern/sched.c:171` (`thread_create`)

```c
struct thread *thread_create(const char *name, void (*entry)(void *),
                             void *arg, int priority)
{
    struct thread *th = alloc_thread();          // Find free slot in pool
    uint64_t stack_pa = pmm_alloc_pages(3);      // 2^3 = 8 pages = 32 KB stack

    th->kernel_stack = (uint64_t *)stack_pa;
    th->priority = priority;
    th->effective_priority = priority;
    th->quantum = 10;                            // 10 ticks = 100ms
    th->state = TH_RUN;

    // Set up initial context so first context_switch enters thread_trampoline
    th->context.sp  = stack_pa + 32768;          // Top of stack
    th->context.x30 = (uint64_t)thread_trampoline;  // "return address"
    th->context.x19 = (uint64_t)entry;           // Saved for trampoline
    th->context.x20 = (uint64_t)arg;             // Saved for trampoline
    th->context.x29 = 0;                         // FP sentinel
    return th;
}
```

The trick is in the initial context setup. A brand-new thread has never been context-switched, so its `cpu_context` is fabricated:

1. `x30` (LR) is set to `thread_trampoline` -- so when `context_switch` does `ret`, it "returns" into the trampoline.
2. `x19` and `x20` hold the entry function and argument -- these are callee-saved registers, so `context_switch` preserves them.
3. `sp` points to the top of a freshly allocated 32 KB kernel stack.

The trampoline (`sched.c:138`) enables interrupts (new threads start with IRQs masked), reads entry/arg from x19/x20, calls `entry(arg)`, and if the function returns, calls `thread_exit()`.

```
First context switch into new thread:

  context_switch(&old->context, &new->context)
    |
    +-- Restore x19 = entry, x20 = arg, x30 = thread_trampoline, SP = stack_top
    +-- ret  -->  thread_trampoline()
                    |
                    +-- Enable IRQs (msr daifclr, #0x2)
                    +-- entry(arg)     // The actual thread function
                    +-- thread_exit()  // If entry() returns
```

#### Sleep and Wakeup

Kiseki implements the classic BSD **wait channel** pattern (also used in XNU as `assert_wait`/`thread_wakeup`):

**Sleeping** (`sched.c:289`, `thread_sleep_on`): A thread sets `wait_channel` to an arbitrary kernel address (typically `&some_struct_field`), transitions to `TH_WAIT`, and calls `sched_switch()`. The scheduler sees `TH_WAIT` and does NOT re-enqueue it.

**Waking** (`sched.c:362`, `thread_wakeup_on`): Scans all 256 thread slots for any thread in `TH_WAIT` whose `wait_channel` matches. Uses atomic CAS (`TH_WAIT` -> `TH_RUN`) to prevent the double-enqueue race where two cores wake the same thread simultaneously.

**The missed-wakeup problem:** There is a classic race condition:

```
Thread A (sleeper)              Thread B (waker)
------------------              ----------------
lock(queue_lock)
check: queue empty? yes
unlock(queue_lock)
                                lock(queue_lock)
                                enqueue(item)
                                unlock(queue_lock)
                                thread_wakeup_on(&queue)  <-- A is not TH_WAIT yet!
set TH_WAIT
sched_switch()                  <-- A sleeps FOREVER (wakeup was lost)
```

`thread_sleep_on_locked()` (`sched.c:330`) solves this by setting `TH_WAIT` *before* releasing the lock:

```c
void thread_sleep_on_locked(void *chan, const char *reason,
                            spinlock_t *lock, uint64_t flags)
{
    th->wait_channel = chan;
    th->state = TH_WAIT;           // Set WAIT while still holding lock
    spin_unlock_irqrestore(lock, flags);  // Now release
    sched_switch();                 // Switch away
}
```

This is the equivalent of XNU's `lck_mtx_sleep()` or FreeBSD's `msleep()`.

#### Timed Sleep

**File:** `kernel/kern/sched.c:393` (`thread_sleep_ticks`)

A **sorted sleep queue** holds threads waiting for a timed wakeup. Threads are inserted in order of `wakeup_tick` so that the wakeup check (`sched_wakeup_sleepers`, called from `sched_tick` on CPU 0) only needs to scan from the front until it finds a thread whose time hasn't come yet:

```
Sleep queue (sorted by wakeup_tick):

  sleep_queue -> [tid=5, wake@150] -> [tid=8, wake@200] -> [tid=3, wake@350] -> NULL

  Current tick: 155
  --> Wake tid=5 (150 <= 155), stop at tid=8 (200 > 155)
```

### 4.4 SMP Load Balancing

**File:** `kernel/kern/sched.c:539-738`

With 4 CPU cores, the scheduler must distribute threads across them. Kiseki uses three mechanisms:

**1. Least-loaded placement** (`sched_find_least_loaded_cpu`, `sched.c:554`): When a new thread is first enqueued (`th->cpu == -1`), it goes to the CPU with the lowest `run_count`. This spreads new work across cores.

**2. Cache-affinity stickiness**: When an existing thread is re-enqueued (e.g., after waking from sleep), it stays on the same CPU it last ran on. This preserves warm caches (the thread's data is likely still in that core's L1/L2 cache).

**3. Work stealing** (`sched_steal_work`, `sched.c:648`): When a core's run queue is empty, its idle thread tries to steal work from the busiest core. It finds the core with the highest `run_count`, takes the lock, and removes the lowest-priority thread:

```
CPU 0 (busy)                        CPU 2 (idle)
+---------------------+            +---------------+
| run_count=4         |            | run_count=0   |
| [A]->[B]->[C]->[D]  |            | (empty)       |
+---------------------+            +---------------+
                                         |
                        idle_thread_func:
                        stolen = sched_steal_work(2)
                        --> Scans CPUs, finds CPU 0 has max load
                        --> Locks CPU 0's run_lock
                        --> Removes thread D (lowest pri)
                        --> Enqueues D on CPU 2
                                         |
                                         v
CPU 0                               CPU 2
+---------------------+            +---------------+
| run_count=3         |            | run_count=1   |
| [A]->[B]->[C]       |            | [D]           |
+---------------------+            +---------------+
```

**IPI-driven wakeup:** When a thread is enqueued on a remote CPU (e.g., CPU 0 unblocks a thread assigned to CPU 2), an **Inter-Processor Interrupt** (IPI) is sent via the GIC (`gic_send_sgi(IPI_RESCHEDULE, 1 << cpu_id)`). This wakes the target CPU from WFI (Wait For Interrupt) so it can schedule the new thread immediately rather than waiting for its next timer tick.

```
CPU 0                                    CPU 2
  |                                        |
  | thread_unblock(th)                     | (idle, in WFI)
  | --> sched_enqueue(th)                  |
  |     --> target = CPU 2 (th->cpu)       |
  |     --> sched_enqueue_cpu(th, 2, true) |
  |         --> add to CPU 2's run_queue   |
  |         --> need_resched = true         |
  |         --> gic_send_sgi(0, 1<<2) --IPI-->  (wakes from WFI)
  |                                        |  sched_yield()
  |                                        |  --> picks th from run_queue
  |                                        |  --> context_switch to th
```

**QEMU-specific considerations:** The work-stealing code has a double-check optimisation: it reads `run_count` without the lock first, and only takes the lock if the count is >= 2. This avoids lock contention in QEMU TCG mode (where all 4 virtual CPUs share one host thread). Without this, three idle CPUs would all compete for one busy CPU's `run_lock` on every timer tick.

### 4.5 Spinlocks, Mutexes & Condition Variables

**File:** `kernel/kern/sync.c` (410 lines), `kernel/include/kern/sync.h`

**For the systems newcomer:** When two threads (possibly on different CPU cores) access shared data, they need synchronisation to avoid corruption. There are two fundamental approaches:

1. **Spin** -- keep trying in a tight loop (busy-wait). Fast for very short critical sections.
2. **Sleep** -- put the thread to sleep and wake it when the resource is free. Better for longer waits.

Kiseki provides four synchronisation primitives, matching XNU's:

| Primitive | Spin or Sleep? | IRQs disabled? | XNU Equivalent |
|-----------|---------------|----------------|----------------|
| Spinlock | Spin | Yes (when using `_irqsave`) | `hw_lock_t`, `lck_spin_t` |
| Mutex | Adaptive (spin then sleep) | No | `lck_mtx_t` |
| Semaphore | Sleep | No | Mach `semaphore_t` |
| Condition variable | Sleep | No | `pthread_cond_t` (via `condvar_wait`) |

#### Spinlocks

**File:** `kernel/kern/sync.c:37` (`spin_lock`)

```c
typedef struct {
    volatile uint32_t locked;   // 0 = free, 1 = held
    uint32_t _pad;
} spinlock_t;
```

The implementation uses ARM64 **exclusive load/store** instructions (`LDAXR`/`STXR`) for atomic compare-and-swap:

```asm
// sync.c:58-70  (simplified)
1:  ldaxr   w0, [lock]       // Exclusive load with acquire semantics
    cbnz    w0, 2f           // If locked != 0, go to spin
    stxr    w0, #1, [lock]   // Try to store 1 (exclusively)
    cbnz    w0, 1b           // If store failed (contention), retry
    b       3f               // Success!
2:  yield                    // Hint: we're spinning
    b       1b               // Retry
3:                           // Lock acquired
```

**Why LDAXR/STXR instead of a simple compare-and-swap?** ARM64 uses a **Load-Link / Store-Conditional (LL/SC)** model. `LDAXR` marks the cache line as "exclusively owned" by this core. `STXR` only succeeds if no other core has touched that cache line since the `LDAXR`. If another core wrote to the same line (even a different word in the same 64-byte cache line), `STXR` fails and we retry. This is more efficient than x86's `LOCK CMPXCHG` on workloads with low contention.

**Unlock** uses `STLR` (Store with Release semantics) to ensure all writes inside the critical section are visible to other cores before the lock appears free:

```asm
// sync.c:75-81
stlr    w0, [lock]       // Store 0 with release barrier
sev                      // Send Event (wake cores in WFE)
```

**IRQ-saving variants:** `spin_lock_irqsave()` saves the DAIF register (which controls interrupt masking) and disables IRQs before acquiring the lock. `spin_unlock_irqrestore()` releases the lock and restores the saved IRQ state. This prevents deadlock: if a timer IRQ fired while holding a spinlock, and the IRQ handler tried to acquire the same lock, the core would deadlock (spinning forever on a lock it already holds, with the unlock code unable to run because IRQs are masked).

```
DEADLOCK scenario without irqsave:

  Thread on CPU 0:
    spin_lock(&run_lock)
    ... modifying run queue ...
    |
    +-- Timer IRQ fires! (interrupts NOT disabled)
        |
        +-- sched_tick()
            |
            +-- spin_lock(&run_lock)  <-- DEADLOCK!
                (CPU 0 already holds this lock, IRQ handler
                 can't return until it gets the lock,
                 but the lock holder can't release until
                 the IRQ handler returns)
```

**YIELD vs WFE:** Earlier versions used `WFE` (Wait For Event) in the spin loop, which on real hardware puts the core into a low-power state until another core sends `SEV`. But on QEMU TCG (where all vCPUs share one host thread), WFE blocks the *entire* emulated system -- the lock holder can't run to release the lock. `YIELD` is a polite hint that the loop is spinning, allowing QEMU to schedule other vCPUs.

#### Mutexes

**File:** `kernel/kern/sync.c:146` (`mutex_lock`)

```c
typedef struct {
    volatile uint32_t locked;
    volatile uint32_t _pad;
    struct thread *owner;             // For priority inheritance
    spinlock_t wait_lock;             // Protects the waiter queue
    struct thread *waiters_head;      // FIFO queue of blocked threads
    struct thread *waiters_tail;
} mutex_t;
```

Mutexes use **adaptive spinning**: try to acquire atomically (fast path), spin up to 100 iterations (medium path), then add to wait queue and sleep (slow path):

```
mutex_lock(mtx):
  |
  +-- mutex_trylock(mtx)?  --> yes: set owner, return     (FAST: < 10 ns)
  |
  +-- Spin 100 times:
  |     mutex_trylock(mtx)?  --> yes: set owner, return   (MEDIUM: < 1 us)
  |
  +-- spin_lock_irqsave(&mtx->wait_lock)
  |   append current thread to waiters_tail
  |   spin_unlock_irqrestore(&mtx->wait_lock)
  |
  +-- thread_block("mutex_lock")  --> sleep               (SLOW: context switch)
  |
  +-- (woken by mutex_unlock)
  +-- mtx->owner = current_thread
```

**Unlock with direct handoff** (`sync.c:194`): Instead of setting `locked = 0` and letting waiters race for it, `mutex_unlock` checks the wait queue *before* releasing:

```c
void mutex_unlock(mutex_t *mtx) {
    spin_lock_irqsave(&mtx->wait_lock, &flags);
    struct thread *waiter = mtx->waiters_head;
    if (waiter) {
        // Direct handoff: transfer ownership without unlocking
        mtx->waiters_head = waiter->wait_next;
        mtx->owner = waiter;    // locked stays 1
        spin_unlock_irqrestore(&mtx->wait_lock, flags);
        thread_unblock(waiter);
    } else {
        // No waiters: actually release
        mtx->owner = NULL;
        mtx->locked = 0;
        spin_unlock_irqrestore(&mtx->wait_lock, flags);
    }
}
```

This prevents the **thundering herd** problem where multiple waiters all wake up and race for the lock, with all but one immediately going back to sleep. Direct handoff also prevents a third core from stealing the lock in the gap between `locked = 0` and the woken waiter's `mutex_trylock`.

#### Semaphores

**File:** `kernel/kern/sync.c:248`

```c
typedef struct {
    volatile int32_t count;     // Current count (> 0 means resources available)
    uint32_t _pad;
    spinlock_t lock;
    struct thread *waiters_head;
    struct thread *waiters_tail;
} semaphore_t;
```

A counting semaphore with wait and signal operations. `semaphore_wait()` blocks if `count <= 0`; `semaphore_signal()` increments the count and wakes one waiter. These map to Mach's `semaphore_wait_trap` and `semaphore_signal_trap` system calls.

#### Condition Variables

**File:** `kernel/kern/sync.c:326`

```c
typedef struct {
    struct thread *waiters_head;
    struct thread *waiters_tail;
    spinlock_t lock;
} condvar_t;
```

The classic monitor pattern: `condvar_wait(cv, mtx)` atomically releases the mutex and sleeps on the condition variable's wait queue. When woken by `condvar_signal()` or `condvar_broadcast()`, it re-acquires the mutex before returning.

```
condvar_wait(cv, mtx):
  +-- Append current thread to cv->waiters
  +-- mutex_unlock(mtx)              // Release before sleeping
  +-- thread_block("condvar_wait")   // Sleep
  +-- (woken by condvar_signal)
  +-- mutex_lock(mtx)                // Re-acquire before returning
```

`condvar_signal()` wakes one waiter (FIFO order). `condvar_broadcast()` wakes all waiters. These are used throughout the kernel -- for example, the TTY subsystem uses them for waiting on input, and the IPC message queue uses them for blocking receives.

**Comparison with XNU synchronisation:**

| Kiseki | XNU | Notes |
|--------|-----|-------|
| `spin_lock` | `hw_lock_lock`, `lck_spin_lock` | Both use LDAXR/STXR on ARM64 |
| `spin_lock_irqsave` | `splhigh` + `hw_lock_lock` | Kiseki combines them |
| `mutex_lock` | `lck_mtx_lock` | Both do adaptive spinning + sleep |
| `semaphore_wait/signal` | `semaphore_wait_trap`/`signal_trap` | Mach trap interface |
| `condvar_wait` | `cv_wait` (BSD), `thread_block` (Mach) | Similar semantics |
| `thread_sleep_on` | `assert_wait` + `thread_block` | BSD `tsleep` pattern |
| `thread_wakeup_on` | `thread_wakeup_prim` | BSD `wakeup` pattern |

### 4.6 The Timer Driver

**File:** `kernel/drivers/timer/timer.c` (182 lines)

The timer is the heartbeat of the scheduler. Without it, a CPU-bound thread would run forever and no other thread would get a chance. Kiseki uses the **ARM Generic Timer** -- a hardware counter built into every ARM64 core.

**Key hardware registers:**

| Register | Full Name | Purpose |
|----------|-----------|---------|
| `CNTFRQ_EL0` | Counter Frequency | Clock speed of the counter (set by firmware, read-only). Typically 62.5 MHz on QEMU virt |
| `CNTVCT_EL0` | Virtual Counter | Monotonically increasing tick counter (read-only). Like an always-on stopwatch |
| `CNTV_TVAL_EL0` | Timer Value | Countdown register. When it reaches 0, the timer fires an IRQ |
| `CNTV_CTL_EL0` | Timer Control | Enable/disable the timer and mask/unmask its interrupt |

**Initialisation** (`timer.c:70`, `timer_init`):

```c
void timer_init(uint32_t hz)    // hz = 100 (10ms tick period)
{
    uint64_t freq = read_cntfrq();              // e.g., 62,500,000 Hz
    timer_interval = freq / hz;                  // e.g., 625,000 counter ticks
    tick_count = 0;

    // Enable EL0 access to CNTVCT_EL0 (for commpage mach_absolute_time)
    cntkctl |= (1 << 1) | (1 << 0);            // EL0VCTEN | EL0PCTEN

    gic_enable_irq(27);                          // Enable PPI 27 (virtual timer)
    write_cntv_tval(timer_interval);             // Set countdown
    write_cntv_ctl(CTL_ENABLE);                  // Start!
}
```

The counter ticks at 62.5 MHz. We want a 100 Hz scheduler tick, so we set `CNTV_TVAL = 62,500,000 / 100 = 625,000`. When the countdown reaches zero, IRQ 27 fires.

**Per-core timers:** Each CPU core has its **own** ARM Generic Timer. Secondary cores call `timer_init_percpu()` to arm their local timer. This means each core gets independent 100Hz ticks -- critical for SMP scheduling, where each core's `sched_tick()` independently decrements its current thread's quantum.

**Timer handler** (`timer.c:139`):

```c
void timer_handler(void)
{
    write_cntv_tval(timer_interval);    // Rearm for next tick
    write_cntv_ctl(CTL_ENABLE);         // Clear pending status

    // CPU 0 only: increment global tick counter + poll network
    if (cd->cpu_id == 0) {
        tick_count++;
        virtio_net_recv();              // NAPI-style RX polling
    }

    sched_tick();                        // Per-core scheduler tick
}
```

**Why only CPU 0 increments `tick_count`?** The variable is a plain `volatile uint64_t`, not an atomic. If all 4 cores did `tick_count++` simultaneously, they would read the same value and write back the same value plus one, losing 3 increments. Rather than adding atomic overhead, Kiseki designates CPU 0 as the timekeeper. The sleep queue and `timer_get_ticks()` all use this single counter.

**EL0 access to the counter:** The `CNTKCTL_EL1` register is configured to allow user-space reads of `CNTVCT_EL0`. This lets the CommPage's `mach_absolute_time()` implementation read the hardware counter directly from EL0 without a syscall -- the same optimisation used by macOS, where `mach_absolute_time()` resolves to a single `mrs x0, cntvct_el0` instruction via the commpage.

```
Timer flow on a 4-core system:

  Core 0           Core 1           Core 2           Core 3
    |                |                |                |
    v                v                v                v
  IRQ 27           IRQ 27           IRQ 27           IRQ 27
    |                |                |                |
  timer_handler()  timer_handler()  timer_handler()  timer_handler()
    |                |                |                |
  rearm timer      rearm timer      rearm timer      rearm timer
  tick_count++     (skip)           (skip)           (skip)
  virtio_net_recv  (skip)           (skip)           (skip)
  sched_tick()     sched_tick()     sched_tick()     sched_tick()
    |                |                |                |
  check quantum    check quantum    check quantum    check quantum
  on this core's   on this core's   on this core's   on this core's
  current thread   current thread   current thread   current thread
```

**Utility functions:**

- `timer_get_ticks()` -- returns the global tick counter (used by `thread_sleep_ticks`)
- `timer_get_freq()` -- returns `CNTFRQ_EL0` (used by CommPage to compute nanoseconds)
- `timer_delay_us(us)` -- busy-wait by polling `CNTVCT_EL0`. Used for short delays during driver initialisation (e.g., VirtIO device reset)

---

## Chapter 5: Processes -- Fork, Exec, Exit

Chapters 2-4 built the foundations: memory management, threads, and scheduling. This chapter assembles them into **processes** -- the user-visible unit of isolation that contains an address space, file descriptors, credentials, and one or more threads.

### 5.1 The Process Structure

**Files:** `kernel/include/kern/proc.h`, `kernel/kern/proc.c`

Like threads, processes live in a **static table** of 256 entries:

```c
// proc.c:76-77
struct proc  proc_table[PROC_MAX];     // PROC_MAX = 256
spinlock_t   proc_table_lock = SPINLOCK_INIT;
```

PIDs map 1:1 to table indices (`proc_table[pid]`), so `proc_find(pid)` is O(1). PID 0 is the kernel "process" (owns the boot thread), PID 1 is init.

The `struct proc` is large -- it is the BSD-layer process descriptor that contains everything a Unix process needs:

```c
// proc.h:63-121 (abridged, with annotations)
struct proc {
    /* --- Identity --- */
    pid_t           p_pid;              // Process ID
    pid_t           p_ppid;             // Parent PID
    char            p_comm[32];         // Process name (e.g., "/sbin/init")
    int             p_state;            // PROC_RUNNING, PROC_ZOMBIE, etc.

    /* --- Mach layer --- */
    struct task     *p_task;            // Mach task (threads + VM space)
    struct vm_space *p_vmspace;         // Page tables + vm_map

    /* --- BSD layer --- */
    struct ucred    p_ucred;            // Credentials (uid, gid, euid, egid)
    struct filedesc p_fd;               // File descriptor table (64 slots)
    struct sigacts  p_sigacts;          // Signal handlers + pending mask

    /* --- Process tree --- */
    struct proc     *p_parent;          // Parent process
    struct proc     *p_children;        // First child (linked list head)
    struct proc     *p_sibling;         // Next sibling (same parent)

    /* --- Exit/wait --- */
    int             p_exitstatus;       // Status for wait4()
    bool            p_exited;
    condvar_t       p_waitcv;           // Parent sleeps here in wait4()
    mutex_t         p_waitmtx;

    /* --- Filesystem --- */
    struct vnode    *p_cwd;             // Current working directory
    char            p_cwd_path[256];    // CWD path string
    mode_t          p_umask;            // File creation mask (default 022)

    /* --- Process group / session --- */
    pid_t           p_pgrp;             // Process group ID
    pid_t           p_session;          // Session ID
    bool            p_session_leader;   // Controls the TTY
};
```

**Process states:**

```
              proc_create()
                  |
                  v
  PROC_UNUSED --> PROC_EMBRYO --> PROC_RUNNING
                                     |    ^
                         all threads |    | thread wakes up
                         blocked     |    |
                                     v    |
                               PROC_SLEEPING
                                     |
                          proc_exit()|
                                     v
                               PROC_ZOMBIE ----> PROC_UNUSED
                                          (parent calls wait4, reaps)
```

| State | Value | Meaning |
|-------|-------|---------|
| `PROC_UNUSED` | 0 | Slot is free (can be allocated) |
| `PROC_EMBRYO` | 1 | Being created (between `proc_create` and setup completion) |
| `PROC_RUNNING` | 2 | Active: has at least one runnable thread |
| `PROC_SLEEPING` | 3 | All threads are blocked |
| `PROC_STOPPED` | 4 | Stopped by SIGSTOP/SIGTSTP |
| `PROC_ZOMBIE` | 5 | Exited but not yet reaped by parent's `wait4()` |

**Relationship between proc, task, and thread:**

```
struct proc (BSD layer)                struct task (Mach layer)
+---------------------------+          +-------------------------+
| p_pid = 10                |          | pid = 10                |
| p_comm = "Finder"         |   +----->| vm_space = 0x...        |
| p_task -------------------+---+      | threads -> th1 -> th2   |
| p_vmspace = 0x...         |          | ipc_space = 0x...       |
| p_ucred (uid/gid)         |          | task_port = 0x...       |
| p_fd (file descriptors)   |          +-------------------------+
| p_sigacts (signals)        |
| p_parent -> proc[1]       |
| p_children -> proc[15]    |
+---------------------------+
```

In XNU, `proc` and `task` are strictly separate structures in different layers (BSD and Mach). Kiseki keeps both because they serve different purposes: `proc` holds Unix-visible state (PIDs, credentials, signals, file descriptors), while `task` holds Mach-visible state (threads, VM space, IPC ports). The `p_task` pointer bridges them.

### 5.2 Fork

**File:** `kernel/kern/proc.c:711` (`sys_fork_impl`)

`fork()` creates a copy of the calling process. The child is almost identical to the parent -- same code, same data, same open files -- but is a separate process with its own PID. The parent gets the child's PID returned; the child gets 0.

**Fork steps (8 phases):**

```
sys_fork_impl(trap_frame)
  |
  1. proc_create(parent_name, parent)
  |    --> Allocate PID, create fresh vm_space, init fd table, link into tree
  |
  2. vmm_copy_space(child_vmspace, parent_vmspace)
  |    --> Walk parent's page tables, copy every user page
  |        (deep copy: allocates new physical pages for each mapped VA)
  |
  3. fd_dup_table(&child_fd, &parent_fd)
  |    --> Copy all 64 fd slots, increment refcount on each open file
  |        (parent and child share the same struct file -- like Unix)
  |
  4. Create Mach task for child
  |    --> Set pid, vm_space, credentials, IPC space
  |
  5. thread_create("fork_child", NULL, NULL, PRI_DEFAULT)
  |    --> Allocate kernel thread with 32 KB stack
  |
  6. Copy parent's trap frame to top of child's kernel stack
  |    --> child_tf = memcpy(parent_tf), then child_tf->regs[0] = 0
  |                                                    ^
  |                                              child returns 0 from fork()
  |
  7. Set child thread's saved context:
  |    context.x30 = fork_child_return  (assembly trampoline)
  |    context.sp  = &child_trap_frame  (where RESTORE_REGS will read)
  |    context.x19 = child_vmspace      (for TTBR0 switch)
  |
  8. DSB SY barrier + sched_enqueue(child_thread)
  |    --> Child is now runnable; parent returns with child PID
```

**The fork_child_return trampoline** (in `vectors.S`) is the assembly code that a freshly forked child runs after its first context switch:

```
context_switch saves parent, restores child
  --> "ret" jumps to fork_child_return (was set as x30)
      |
      +-- Switch TTBR0 to child's page tables (from x19 = vm_space)
      +-- RESTORE_REGS from trap frame on stack
      +-- eret to user mode
          --> child resumes at the instruction after the fork() syscall
              with x0 = 0 (child's return value)
```

**Why deep copy instead of COW?** The comment in `proc.c:692-706` says "Full-copy fork (not COW -- simpler for now)". While Section 3.6 described the COW machinery (`vmm_copy_on_write`, `PTE_COW` bit, reference counting), the current `sys_fork_impl` uses `vmm_copy_space()` which does a full deep copy of every page. The COW infrastructure exists but is used for specific optimisations, not the main fork path. This trades memory efficiency for simplicity.

**Memory barrier before enqueue:** Line 928 has `dsb sy` -- a full Data Synchronisation Barrier. This ensures all writes to the child's page tables, trap frame, and thread context are visible to other CPU cores before the child thread appears on any run queue. Without this, another core could start executing the child and see stale/partial page tables.

### 5.3 Exec

**File:** `kernel/kern/proc.c:1020` (`sys_execve_impl`)

`execve()` replaces the current process's program with a new one. It keeps the same PID, file descriptors (except `FD_CLOEXEC`), and credentials (unless SUID), but replaces the address space entirely.

```
sys_execve_impl(tf, "/bin/ls", argv, envp)
  |
  1. Copy path, argv, envp into kernel scratch buffer (16 KB from PMM)
  |   (Must copy BEFORE destroying old VM -- these pointers are in user memory!)
  |
  2. Stat the executable (for SUID/SGID check later)
  |
  3. Destroy old VM space, create fresh one
  |   --> msr ttbr0_el1, kernel_pgd  (switch to kernel page tables first!)
  |   --> vmm_destroy_space(old)
  |   --> vmm_create_space()  --> new empty user address space
  |
  4. macho_load(path, new_vmspace, &result)
  |   --> Parse Mach-O headers, map segments, load dyld if needed
  |   --> Returns: entry_point, mach_header, dyld info
  |
  5. Handle SUID/SGID (set euid/egid to file owner if S_ISUID/S_ISGID)
  |
  6. Allocate user stack (1 MB, guard page at bottom)
  |   --> Map pages from stack_bottom+4KB to stack_top
  |
  7. Build user stack layout:
  |   +-------------------------------------------+  <-- stack_top
  |   | (256 bytes headroom)                      |
  |   | argv string data ("bin/ls\0", "-la\0")    |
  |   | envp string data ("PATH=/bin\0", ...)     |
  |   | apple string data ("executable_path=...") |
  |   +-------------------------------------------+
  |   | apple[0] pointer, NULL                    |
  |   | envp[0], envp[1], ..., NULL               |
  |   | argv[0], argv[1], ..., NULL               |
  |   | argc (integer)                            |
  |   | mach_header pointer (if dyld loaded)      |  <-- sp
  |   +-------------------------------------------+
  |
  8. Map CommPage into new address space
  |
  9. Close FD_CLOEXEC file descriptors
  |
  10. Reset caught signal handlers to SIG_DFL (POSIX requirement)
  |
  11. Switch to new VM space (vmm_switch_space)
  |
  12. Set trap frame: tf->elr = entry_point, tf->sp = sp
  |    --> Return from syscall will eret to the new program
```

**The scratch buffer trick:** User-space pointers (path, argv, envp) point into the old address space. If we destroyed the old VM first and then tried to read argv, we'd get garbage or a page fault. So step 1 copies everything into a 16 KB kernel buffer (allocated from PMM), and step 3 destroys the old VM.

**Stack layout for dyld:** When the binary uses a dynamic linker, the kernel pushes the main binary's `mach_header` address at `[sp]`, then `argc` at `[sp+8]`. This is an XNU convention that dyld's `_start` function relies on to locate the main executable.

**The load_result_t on the heap:** The `load_result_t` structure (returned by `macho_load`) is ~17 KB (it contains `dylib_paths[64][256]`). This is larger than the 32 KB kernel stack's safe margin, so it's allocated from PMM (32 KB, order 3) and freed after use. Stack overflow in the kernel is a hard panic -- there's no guard page in kernel space.

### 5.4 Exit

**File:** `kernel/kern/proc.c:446` (`proc_exit`)

When a process calls `exit()` (or is killed by a signal), `proc_exit` cleans up:

```
proc_exit(p, status)
  |
  1. fd_close_all(p)
  |   --> Close all 64 file descriptors
  |       Decrement refcount on each struct file
  |       If refcount hits 0: release vnode, close pipe end, free PTY
  |
  2. Release current working directory vnode
  |
  3. Reparent children to init (PID 1)
  |   --> For each child of p:
  |       child->p_parent = init_proc
  |       Link into init's child list
  |       If child is already ZOMBIE: wake init to reap it
  |
  4. Destroy VM space
  |   --> Switch TTBR0 to kernel PGD first!
  |       (Otherwise TLB misses walk freed page tables --> corruption)
  |   --> vmm_destroy_space: free all user page tables + mapped pages
  |
  5. Destroy IPC space (release all Mach port rights)
  |
  6. Transition to PROC_ZOMBIE
  |   p->p_exitstatus = status
  |   p->p_state = PROC_ZOMBIE
  |
  7. Wake parent (condvar_signal(&parent->p_waitcv))
  |   --> Parent unblocks from wait4() and reaps this zombie
```

**Why reparent to init?** Every process must have a parent to call `wait4()` and reap it. If the parent exits before the child, the child becomes an orphan. Reparenting to PID 1 (init) ensures every zombie eventually gets reaped. This is the same Unix convention used since the original V6 Unix.

**The TTBR0 switch before destroy:** Line 500-501 explicitly switches to the kernel page table before freeing the user page table. This is a subtle but critical safety measure. Even though we're in kernel mode (EL1), the hardware might still have TTBR0 pointing to the user page table. If a TLB miss occurs for a low-half address (even for kernel identity-mapped regions stored in TTBR0's table), the MMU would walk the freed page -- which might have been reallocated for something else, causing silent corruption.

### 5.5 Wait

**File:** `kernel/kern/proc.c:535` (`proc_wait`)

`wait4()` blocks the calling process until a child exits:

```
proc_wait(parent, wait_pid, &status, options)
  |
  retry:
  |
  +-- mutex_lock(&parent->p_waitmtx)
  |
  +-- spin_lock(&parent->p_lock)
  |   Scan parent->p_children for a zombie matching wait_pid
  |   (wait_pid == -1 means any child)
  |
  +-- Found zombie?
  |     YES --> Remove from child list, pid_free(child_pid)
  |             Return child PID + exit status
  |     NO  --> Has any children at all?
  |               NO  --> Return -ECHILD (no children to wait for)
  |               YES --> WNOHANG set?
  |                         YES --> Return 0 (non-blocking, nothing ready)
  |                         NO  --> condvar_wait(&parent->p_waitcv, &mtx)
  |                                 --> Sleep until child exits
  |                                 --> goto retry
```

The `condvar_wait` / `condvar_signal` pair solves the classic producer-consumer problem: the child "produces" a zombie state, the parent "consumes" it. The mutex prevents the race where a child exits between the parent's zombie-scan and the `condvar_wait`.

### 5.6 The First User Process (PID 1)

**File:** `kernel/kern/proc.c:1525` (`kernel_init_process`)

After the 17-phase kernel bootstrap completes, `kernel_init_process()` launches the first user-space program. This is a special case because there's no parent process to fork from -- the kernel must construct the process from scratch:

```
kernel_init_process()
  |
  1. proc_create("init", &proc_table[0])   // Parent = kernel (PID 0)
  |
  2. Try loading init binary in order:
  |   /sbin/init, /bin/hello, /bin/bash, /bin/sh, /sbin/launchd
  |   --> macho_load(path, vmspace, &result)
  |   --> Panic if nothing loads
  |
  3. Allocate & map user stack (1 MB)
  |
  4. Build user stack: argc=1, argv={"/sbin/init"}, envp={PATH, HOME, ...}
  |   Push mach_header if dyld loaded
  |
  5. Map CommPage
  |
  6. Create Mach task + IPC space for PID 1
  |
  7. thread_create("init", NULL, NULL, PRI_DEFAULT)
  |   Place trap frame at top of kernel stack
  |   context.x30 = init_thread_return (assembly trampoline)
  |   context.sp  = trap_frame address
  |   context.x19 = vmspace (for TTBR0 switch)
  |
  8. DSB SY + sched_enqueue(init_thread)
  |   --> Return to caller (kernel_bootstrap_thread)
  |       Scheduler will pick up init_thread and dispatch it
  |
  Eventually:
  |
  context_switch into init_thread
    --> "ret" to init_thread_return
        --> Switch TTBR0 to init's page tables
        --> RESTORE_REGS (load ELR, SP, x0-x30 from trap frame)
        --> eret to EL0
            --> init starts executing at dyld's entry point
```

**Why scheduler-dispatched instead of direct eret?** An earlier version of Kiseki had `kernel_init_process()` directly eret to user mode from the boot path. This was replaced with the current approach (set up a thread, enqueue it, let the scheduler dispatch it) because:

1. It ensures the boot CPU's idle thread is properly established
2. The context switch machinery is exercised from the very first user transition
3. It matches XNU's approach (`kernel_bootstrap_thread` -> `bsd_init` -> `load_init_program`)

**The three assembly trampolines** in `vectors.S` are all variations of the same pattern (switch TTBR0, restore trap frame, eret):

| Trampoline | Used By | Purpose |
|------------|---------|---------|
| `init_thread_return` | PID 1 bootstrap | First user process entry |
| `fork_child_return` | `sys_fork_impl` | Child process after fork |
| `user_thread_return` | `thread_create_user` | New pthread after `bsdthread_create` |

All three work identically: read `vm_space` from `x19` (callee-saved), call `vmm_switch_space()`, then fall through to `RESTORE_REGS` + `eret`. The difference is only in how the trap frame was set up (by `kernel_init_process`, `sys_fork_impl`, or `thread_create_user`).

### 5.7 File Descriptors

**File:** `kernel/kern/proc.c:149-245`

Each process has a file descriptor table with 64 slots:

```c
// proc.h:49-54
struct filedesc {
    struct file     *fd_ofiles[64];     // Pointers to open file structs
    uint8_t         fd_oflags[64];      // Per-FD flags (FD_CLOEXEC)
    uint32_t        fd_nfiles;          // Number of allocated slots
    spinlock_t      fd_lock;            // SMP protection
};
```

**`fd_alloc()`** finds the lowest free slot (returns the index). **`fd_dup_table()`** copies the parent's table during fork, incrementing each file's reference count. **`fd_close_all()`** is called from `proc_exit` -- it decrements every file's refcount and releases the underlying resource (vnode, pipe, PTY) when the count hits zero.

```
After fork, parent and child share the same struct file:

Parent (PID 10)               Child (PID 11)
+-----------+                 +-----------+
| fd[0] ----+------+          | fd[0] ----+------+
| fd[1] ----+-+    |          | fd[1] ----+-+    |
| fd[2] ----+ |    |          | fd[2] ----+ |    |
+-----------+ |    |          +-----------+ |    |
              |    |                        |    |
              v    v                        v    v
         struct file (stdout)          (same struct file)
         f_refcount = 2                f_refcount is shared!
         f_vnode = /dev/pty0           Writes from either process
         f_flags = O_WRONLY            go to the same file offset
```

Console stdin/stdout/stderr are static `struct file` objects initialised at boot (`console_files_init`). The first process (init) gets these as fd 0/1/2. Forked children inherit them via `fd_dup_table`, but init-created processes get fresh console stubs via `setup_stdio()`.

---

## Chapter 6: Mach IPC

Inter-Process Communication (IPC) is how processes talk to each other and to the kernel. On macOS/XNU, the primary IPC mechanism is **Mach messages** -- structured data sent through **ports**. WindowServer, IOKit, launchd, and virtually every system service communicates via Mach IPC. Kiseki implements a faithful subset of this system.

### 6.1 Core Concepts

**For the systems newcomer:** Unix traditionally uses pipes and signals for IPC. Mach (the microkernel that forms XNU's core) uses a different model based on **ports** and **messages**:

- A **port** is a kernel-managed message queue with a single receiver and potentially many senders. Think of it like a mailbox: anyone with the address can drop a letter in, but only the owner reads from it.
- A **right** is a capability to use a port. There are three kinds:
  - **Send right**: can enqueue messages (many processes can hold send rights to the same port)
  - **Receive right**: can dequeue messages (exactly one process holds this -- the "owner")
  - **Send-once right**: can send exactly one message, then the right is consumed
- A **message** is a structured blob of data sent from one port to another. It contains a header (destination, reply port, message ID) and a body (inline data and/or out-of-line memory descriptors).
- An **IPC space** is a per-task namespace that maps integer names (like file descriptors) to kernel port objects.

```
Task A (sender)                         Task B (receiver)
+------------------------+              +------------------------+
| IPC Space              |              | IPC Space              |
| name 1 -> port X (send)|              | name 5 -> port X (recv)|
| name 2 -> port Y (recv)|              | name 6 -> port Y (send)|
+------------------------+              +------------------------+
           |                                       ^
           | mach_msg(SEND to name 1)              |
           |                                       |
           v                                       |
     +-----------+                                 |
     | Port X    |   ---- message queue ---->      |
     | (kernel)  |   [msg1] [msg2] [msg3]    mach_msg(RCV from name 5)
     +-----------+
```

**Why ports instead of pipes?** Ports support **capability-based security**: you can only send to a port if you hold a send right. Rights can be transferred in messages (so process A can give process B the ability to talk to process C). This is how macOS implements `task_for_pid`, `bootstrap_look_up`, and IOKit service connections.

### 6.2 Kernel Data Structures

**File:** `kernel/include/mach/ipc.h`, `kernel/mach/ipc.c`

#### The Port Object

```c
// ipc.h:364-390
struct ipc_port {
    bool            active;             // Port is alive
    uint32_t        refs;               // Reference count
    struct task     *receiver;          // Task holding receive right

    // Message ring buffer (fixed-size circular queue)
    struct ipc_msg  queue[64];          // PORT_MSG_QUEUE_SIZE = 64
    uint32_t        queue_head;         // Next slot to dequeue from
    uint32_t        queue_tail;         // Next slot to enqueue to
    uint32_t        queue_count;        // Messages currently queued

    spinlock_t      lock;
    semaphore_t     msg_available;      // Wakes receivers when msg enqueued

    // IOKit kobject linkage
    void            *kobject;           // Kernel object pointer (or NULL)
    uint32_t        kobject_type;       // IKOT_* type (0 = IKOT_NONE)
};
```

512 ports live in a static pool. Each port has a 64-slot ring buffer. When a message is sent, it's copied into the next `queue_tail` slot; when received, it's copied out from `queue_head`. The semaphore `msg_available` coordinates sleeping receivers with senders.

#### The IPC Space

```c
// ipc.h:408-412
struct ipc_space {
    struct ipc_port_entry  table[256];   // TASK_PORT_TABLE_SIZE = 256
    uint32_t               next_name;    // Hint for next free slot
    spinlock_t             lock;
};

struct ipc_port_entry {
    struct ipc_port    *port;            // Kernel port object (or NULL)
    mach_port_type_t   type;             // Rights held: SEND, RECEIVE, SEND_ONCE
};
```

Each task gets its own IPC space (allocated from a pool of 64). Port names are indices into the table (0 = `MACH_PORT_NULL`, reserved). When a task calls `mach_port_allocate`, the kernel finds a free slot, creates a port, and inserts it with the requested right.

#### The Queued Message

```c
// ipc.h:348-356
struct ipc_msg {
    uint32_t             size;          // Total message size
    struct ipc_port      *reply_port;   // Translated reply port (kernel obj)
    mach_msg_type_name_t reply_type;    // Post-copyin type (PORT_SEND_ONCE etc.)
    mach_msg_type_name_t dest_type;     // Post-copyin type (PORT_SEND etc.)
    uint32_t             ool_count;     // Number of OOL descriptors
    struct ipc_kmsg_ool  ool_descs[16]; // OOL descriptor storage
    uint8_t              data[4096];    // Raw message bytes
};
```

### 6.3 The Message Header

Every Mach message starts with a 24-byte header:

```c
// ipc.h:98-105
typedef struct {
    mach_msg_bits_t     msgh_bits;          // Flags + port dispositions
    mach_msg_size_t     msgh_size;          // Total message size
    mach_port_name_t    msgh_remote_port;   // Destination port (sender's name)
    mach_port_name_t    msgh_local_port;    // Reply port (sender's name)
    uint32_t            msgh_voucher_port;  // Unused (XNU compat)
    mach_msg_id_t       msgh_id;            // User-defined message ID
} mach_msg_header_t;
```

The `msgh_bits` field encodes the **disposition** of port rights being transferred:

```
msgh_bits layout:
  bits [7:0]   = remote disposition (how to transfer the dest port right)
  bits [15:8]  = local disposition (how to transfer the reply port right)
  bit  [31]    = MACH_MSGH_BITS_COMPLEX (message has OOL descriptors)

Common dispositions:
  MACH_MSG_TYPE_COPY_SEND      (19) = Copy a send right (sender keeps theirs)
  MACH_MSG_TYPE_MAKE_SEND_ONCE (21) = Create a send-once right from receive
  MACH_MSG_TYPE_MOVE_SEND      (17) = Transfer sender's send right to message
```

### 6.4 The mach_msg_trap Flow

**File:** `kernel/mach/ipc.c:1321` (`mach_msg_trap`)

The `mach_msg` system call (Mach trap -31) is the single IPC entry point. It can send, receive, or both (send-then-receive for RPC):

```
User calls: mach_msg(&header, MACH_SEND_MSG | MACH_RCV_MSG,
                      send_size, rcv_size, rcv_name, timeout, ...)
  |
  v
svc #0x80 (x16 = -31)
  |
  v
mach_msg_trap(trap_frame)
  |
  +------ SEND PHASE (if MACH_SEND_MSG) ------+
  |                                             |
  | 1. Read header from user buffer             |
  | 2. Extract dest_name, reply_name, bits      |
  |                                             |
  | 3. Copyin dest port:                        |
  |    ipc_port_lookup(space, dest_name)         |
  |    Validate sender has send right            |
  |    Bump reference for in-flight message      |
  |                                             |
  | 4. Copyin reply port (if non-NULL):          |
  |    ipc_port_lookup(space, reply_name)         |
  |    ipc_object_copyin_type(disp) --> type     |
  |    Bump reference                            |
  |                                             |
  | 5. IOKit interception:                       |
  |    If dest->kobject_type != IKOT_NONE:       |
  |      iokit_kobject_server(dest, msg, reply)  |
  |      --> Handle synchronously, skip queue    |
  |                                             |
  | 6. OOL copyin (if COMPLEX):                  |
  |    ipc_kmsg_copyin_body()                    |
  |    --> For each OOL descriptor:              |
  |        Alloc kernel pages, copy sender data  |
  |        Create vm_map_copy object             |
  |                                             |
  | 7. port_enqueue(dest_port, msg, reply_port,  |
  |                 ool_descs)                   |
  |    --> Copy bytes to ring buffer slot        |
  |    --> semaphore_signal (wake receiver)       |
  +---------------------------------------------+
  |
  +------ RECEIVE PHASE (if MACH_RCV_MSG) -----+
  |                                             |
  | 1. Determine receive port (rcv_name)         |
  |    Verify caller holds receive right         |
  |                                             |
  | 2. port_dequeue(rcv_port, ...)               |
  |    --> semaphore_wait (block until msg)       |
  |    --> Or semaphore_trywait (non-blocking)    |
  |    --> Or timed poll (MACH_RCV_TIMEOUT)       |
  |    --> Copy bytes to user buffer             |
  |    --> Return kernel port ptrs + OOL descs   |
  |                                             |
  | 3. Copyout reply port:                       |
  |    Insert send-once right into receiver's    |
  |    IPC space -> new name                     |
  |                                             |
  | 4. Copyout dest port:                        |
  |    Receiver already has it (receive right)    |
  |    Use existing name                         |
  |                                             |
  | 5. Swap remote/local in header:              |
  |    msgh_remote_port = reply_name (new)       |
  |    msgh_local_port  = dest_name (existing)   |
  |    Swap bits accordingly                     |
  |                                             |
  | 6. OOL copyout (if COMPLEX):                 |
  |    ipc_kmsg_copyout_body()                   |
  |    --> For each OOL descriptor:              |
  |        Alloc VA in receiver's space          |
  |        Map kernel pages into receiver        |
  |        Update descriptor with new user VA    |
  |                                             |
  | 7. Append trailer to user buffer             |
  +---------------------------------------------+
  |
  v
Return MACH_MSG_SUCCESS in x0
```

**The remote/local swap** is a key detail that confuses newcomers. When the sender creates a message:
- `msgh_remote_port` = destination (where to send)
- `msgh_local_port` = reply port (where to receive the reply)

After the receiver dequeues, the kernel rewrites:
- `msgh_remote_port` = the reply port (where to send the reply)
- `msgh_local_port` = the port the receiver owns (where they received)

This makes the header immediately usable for an RPC reply: the receiver can fill in the response and send it to `msgh_remote_port`.

### 6.5 Out-of-Line (OOL) Memory

**File:** `kernel/mach/ipc.c:493-853`

For small messages, inline data in the 4 KB message buffer suffices. But WindowServer needs to transfer entire framebuffer regions (e.g., a 1280x800 window = ~4 MB). This is where **OOL descriptors** come in.

A complex message (bit 31 set in `msgh_bits`) contains a `mach_msg_body_t` followed by an array of descriptors:

```
Complex message layout:

+------------------------+
| mach_msg_header_t      |  24 bytes
+------------------------+
| mach_msg_body_t        |  4 bytes (descriptor_count)
+------------------------+
| OOL descriptor 0       |  16 bytes: address, size, type, flags
+------------------------+
| OOL descriptor 1       |  16 bytes
+------------------------+
| ... inline data ...    |
+------------------------+
```

Each OOL descriptor carries:

```c
// ipc.h:171-178
typedef struct {
    uint64_t                    address;     // User VA of data (sender side)
    uint32_t                    deallocate : 8;  // Unmap from sender after copy?
    mach_msg_copy_options_t     copy       : 8;  // PHYSICAL or VIRTUAL
    uint32_t                    pad1       : 8;
    mach_msg_descriptor_type_t  type       : 8;  // MACH_MSG_OOL_DESCRIPTOR
    mach_msg_size_t             size;        // Byte count
} mach_msg_ool_descriptor_t;
```

**OOL data flow:**

```
Sender (Task A)                 Kernel                    Receiver (Task B)
                                                          
 User buffer at VA 0x200000     vm_map_copy object        VA allocated by
 (window pixel data, 240 pages) (page list: PA array)     vm_map_enter()
                                                          
 [copyin]                                                 [copyout]
 For each page:                                           For each page:
   translate VA -> PA            PA array                   map PA into receiver
   alloc kernel page           [PA0, PA1, PA2, ...]        at new user VA
   copy 4KB to kernel page                                
                                                          
 Result: 240 kernel pages        Queued in ipc_msg        Result: 240 pages
 holding pixel data              until receiver dequeues   visible at new VA
                                                          in receiver's space
```

Kiseki uses a **page list** approach (`VM_MAP_COPY_PAGE_LIST`) for OOL transfers. Instead of allocating one contiguous buddy region (which would fail for 240 pages due to fragmentation), it allocates individual pages and stores their physical addresses in an array. During copyout, these pages are mapped directly into the receiver's address space -- a zero-copy transfer from the kernel staging area to the receiver.

### 6.6 IOKit Kobject Dispatch

**File:** `kernel/mach/ipc.c:1491`

Some ports represent **kernel objects** (kobjects) rather than user message queues. When a message is sent to a kobject port, the IPC layer intercepts it and dispatches synchronously to the appropriate kernel handler instead of queuing:

```
mach_msg_trap send phase:
  |
  +-- dest_port->kobject_type != IKOT_NONE ?
        |
        YES --> iokit_kobject_server(dest_port, msg, reply_port, task)
        |       --> Decode msgh_id (IOKit selector)
        |       --> Call IOFramebuffer/IOHIDSystem method
        |       --> Send reply directly to reply_port
        |       --> Return true (message handled)
        |
        NO  --> Normal port_enqueue() path
```

This is how user-space IOKit calls work: `IOServiceOpen()` gives the user a send right to an IOKit port. When the user sends a message with a specific `msgh_id`, the kernel routes it to the driver's external method handler. Chapter 10 covers IOKit in detail.

### 6.7 Bootstrap Services

**File:** `kernel/mach/ipc.c` (bootstrap traps)

On macOS, service discovery (finding WindowServer's port, for example) goes through `bootstrap_look_up()`, which sends a message to launchd's bootstrap port. Kiseki simplifies this with kernel-managed traps:

```c
// Three bootstrap traps:
bootstrap_register_trap()    // Server registers: "com.apple.windowserver" -> port
bootstrap_look_up_trap()     // Client looks up: "com.apple.windowserver" -> send right
bootstrap_check_in_trap()    // Daemon claims a pre-registered service port
```

A static registry of 64 name-to-port mappings is maintained in the kernel. `bootstrap_register_kernel()` is also available for kernel-mode registration (used by IOKit drivers during boot to register their service ports before any user process starts).

**How WindowServer uses bootstrap:**

```
1. WindowServer starts, calls:
     bootstrap_check_in("com.apple.windowserver", &port)
     --> Kernel creates port, gives WindowServer receive+send rights

2. Finder starts, calls:
     bootstrap_look_up("com.apple.windowserver", &port)
     --> Kernel finds the port, inserts send right into Finder's IPC space
     --> Finder now has a send right to WindowServer's port

3. Finder sends window creation request:
     mach_msg(SEND to windowserver_port, id=MSG_CREATE_WINDOW, ...)
     --> Message queued on WindowServer's port

4. WindowServer receives:
     mach_msg(RCV from port, ...)
     --> Dequeues Finder's request, creates window, sends reply
```

### 6.8 Mach Traps Summary

Kiseki implements 12 Mach traps (negative syscall numbers, matching XNU's convention):

| Trap # | Name | Purpose |
|--------|------|---------|
| -26 | `mach_reply_port` | Allocate a fresh reply port (receive + send-once) |
| -27 | `task_self_trap` | Return calling task's port name |
| -28 | `thread_self_trap` | Return calling thread's port name |
| -31 | `mach_msg_trap` | Send and/or receive a message |
| -36 | `mach_port_allocate` | Create a new port with given rights |
| -37 | `mach_port_deallocate` | Release a port right |
| -39 | `mach_port_mod_refs` | Modify reference count on a port right |
| -40 | `bootstrap_register` | Register a service name -> port |
| -41 | `bootstrap_look_up` | Look up a service by name |
| -42 | `bootstrap_check_in` | Daemon claims a pre-registered service |
| -43 | `semaphore_signal_trap` | Signal a Mach semaphore |
| -44 | `semaphore_wait_trap` | Wait on a Mach semaphore |

The trap number is passed in `x16` (following the XNU ARM64 syscall convention). Negative numbers distinguish Mach traps from BSD syscalls (positive numbers). The dispatch table in `trap.c` routes each trap to its handler.

---

## Chapter 7: BSD Syscalls & POSIX Interface

The previous chapter covered Mach IPC (the microkernel side). This chapter covers the **BSD syscall layer** -- the POSIX-compatible interface that user programs actually use for file I/O, process management, networking, and signals. On XNU, the BSD layer sits on top of Mach, and Kiseki follows the same architecture.

### 7.1 The Trap Handler

**File:** `kernel/kern/trap.c` (839 lines)

When user code executes `svc #0x80`, the CPU traps from EL0 to EL1, entering the vector table's synchronous EL0 handler. After saving the full trap frame (816 bytes), control reaches `trap_sync_el0()`:

```
User executes: svc #0x80
  |
  v
Vector table (vectors.S) -> SAVE_REGS -> trap_sync_el0(trap_frame)
  |
  +-- Extract Exception Class: ec = (ESR >> 26) & 0x3F
  |
  +-- Switch on ec:
  |     EC_SVC_A64 (0x15) --> syscall_handler(tf)
  |     EC_DABT_LOWER (0x24) --> handle_page_fault(tf)  [demand paging, COW]
  |     EC_IABT_LOWER (0x20) --> handle_instruction_abort(tf)
  |     EC_SP_ALIGN (0x26) --> kill process (SIGBUS)
  |     EC_PC_ALIGN (0x22) --> kill process (SIGBUS)
  |     EC_BRK (0x3C) --> kill process (SIGTRAP)
  |
  +-- signal_check(thread, tf)   [deliver pending signals before eret]
  |
  +-- Sanity checks: verify SPSR=EL0t, ELR is user address, TTBR0 matches process
  |
  +-- RESTORE_REGS -> eret to EL0
```

**The dual-personality dispatch** in `syscall_handler()`:

```c
// syscalls.c (simplified)
void syscall_handler(struct trap_frame *tf)
{
    int64_t callnum = (int64_t)tf->regs[16];  // x16 = syscall number

    if (callnum < 0) {
        // Negative: Mach trap
        mach_trap_dispatch(tf, (int32_t)callnum);
    } else {
        // Non-negative: BSD syscall
        switch ((uint32_t)callnum) {
            case SYS_read:    ... break;
            case SYS_write:   ... break;
            case SYS_fork:    ... break;
            // ... 92 more cases
            default: syscall_error(tf, ENOSYS);
        }
    }
}
```

**Calling convention (XNU ARM64 compatible):**

| Register | Purpose |
|----------|---------|
| `x16` | Syscall number (signed). Positive = BSD, negative = Mach |
| `x0`-`x5` | Arguments (up to 6) |
| `x0` | Return value |
| SPSR bit 29 (carry flag) | Set on error; `x0` then holds positive errno |

```c
// Success: clear carry, return value in x0
static void syscall_return(struct trap_frame *tf, uint64_t retval) {
    tf->regs[0] = retval;
    tf->spsr &= ~(1UL << 29);   // Clear carry
}

// Error: set carry, errno in x0
static void syscall_error(struct trap_frame *tf, int err) {
    tf->regs[0] = (uint64_t)err;
    tf->spsr |= (1UL << 29);    // Set carry
}
```

User-space libSystem checks the carry flag after `svc` returns. If set, it stores `x0` into `errno` and returns -1. This matches XNU's convention exactly.

### 7.2 BSD Syscall Catalogue

**File:** `kernel/bsd/syscalls.c` (5,416 lines)

Kiseki implements **92 BSD syscalls** (plus `_nocancel` variants). Here's the complete catalogue grouped by category:

#### Process Lifecycle (13 syscalls)

| # | Name | Purpose |
|---|------|---------|
| 1 | `exit` | Terminate process, set exit status |
| 2 | `fork` | Create child process (deep-copy address space) |
| 7 | `wait4` | Wait for child, reap zombie |
| 20 | `getpid` | Return current PID |
| 39 | `getppid` | Return parent PID |
| 24 | `getuid` | Return real user ID |
| 25 | `geteuid` | Return effective user ID |
| 23 | `setuid` | Set user ID (SUID handling) |
| 47 | `getgid` | Return real group ID |
| 43 | `getegid` | Return effective group ID |
| 181 | `setgid` | Set group ID |
| 59 | `execve` | Replace process image with Mach-O binary |
| 327 | `issetugid` | Check if process is SUID/SGID |

#### File I/O (22 syscalls)

| # | Name | # | Name |
|---|------|---|------|
| 5 | `open` | 398 | `open_nocancel` |
| 6 | `close` | 399 | `close_nocancel` |
| 3 | `read` | 396 | `read_nocancel` |
| 4 | `write` | 397 | `write_nocancel` |
| 173 | `pread` | 174 | `pwrite` |
| 199 | `lseek` | 41 | `dup` |
| 90 | `dup2` | 42 | `pipe` |
| 92 | `fcntl` | 406 | `fcntl_nocancel` |
| 153 | `fstat` | 189 | `fstat64` |
| 338 | `stat` | 340 | `lstat` |
| 10 | `unlink` | 58 | `readlink` |
| 9 | `link` | 95 | `fsync` |
| 200 | `truncate` | 201 | `ftruncate` |

#### Filesystem / Directory (11 syscalls)

| # | Name | Purpose |
|---|------|---------|
| 12 | `chdir` | Change working directory |
| 13 | `fchdir` | Change working directory (by fd) |
| 304 | `getcwd` | Get current working directory |
| 136 | `mkdir` | Create directory |
| 137 | `rmdir` | Remove directory |
| 128 | `rename` | Rename file/directory |
| 15 | `chmod` | Change file permissions |
| 124 | `fchmod` | Change file permissions (by fd) |
| 16 | `chown` | Change file ownership |
| 33 | `access` | Check file access permissions |
| 196 | `getdirentries` | Read directory entries |

#### Memory Management (3 syscalls)

| # | Name | Purpose |
|---|------|---------|
| 197 | `mmap` | Map pages (anonymous or file-backed) |
| 73 | `munmap` | Unmap pages |
| 74 | `mprotect` | Change page protection |

#### Signals (5 syscalls)

| # | Name | Purpose |
|---|------|---------|
| 37 | `kill` | Send signal to process |
| 46 | `sigaction` | Set signal handler |
| 48 | `sigprocmask` | Block/unblock signals |
| 184 | `sigreturn` | Return from signal handler |
| 286 | `pthread_kill` | Send signal to specific thread |

#### Network / Sockets (12 syscalls)

| # | Name | # | Name |
|---|------|---|------|
| 97 | `socket` | 104 | `bind` |
| 106 | `listen` | 30 | `accept` |
| 98 | `connect` | 133 | `sendto` |
| 29 | `recvfrom` | 134 | `shutdown` |
| 105 | `setsockopt` | 118 | `getsockopt` |
| 31 | `getpeername` | 32 | `getsockname` |

#### Threading (4 syscalls)

| # | Name | Purpose |
|---|------|---------|
| 360 | `bsdthread_create` | Create user thread (pthread_create backend) |
| 361 | `bsdthread_terminate` | Terminate user thread |
| 366 | `bsdthread_register` | Register thread entry point & stack info |
| 372 | `thread_selfid` | Return current thread ID |

#### System / Misc (12 syscalls)

| # | Name | Purpose |
|---|------|---------|
| 54 | `ioctl` | Device I/O control |
| 202 | `sysctl` | Query/set kernel parameters |
| 55 | `reboot` | Reboot the system |
| 93 | `select` | I/O multiplexing |
| 240 | `nanosleep` | Sleep for specified time |
| 36 | `sync` | Flush all filesystems |
| 116 | `gettimeofday` | Get wall clock time |
| 122 | `settimeofday` | Set wall clock time |
| 157 | `statfs` | Get filesystem statistics |
| 158 | `fstatfs` | Get filesystem statistics (by fd) |
| 336 | `proc_info` | Query process information |
| 60 | `umask` | Set file creation mask |

#### Kiseki Extensions (2 syscalls)

| # | Name | Purpose |
|---|------|---------|
| 500 | `getentropy` | Fill buffer with random bytes |
| 501 | `openpty` | Allocate pseudo-terminal pair |

### 7.3 How a Syscall Works End-to-End

Let's trace a `write(1, "hello", 5)` call from user space through the kernel:

```
User code: write(1, "hello", 5)
  |
  libSystem's write() wrapper:
    mov x0, #1          // fd
    mov x1, <buf_ptr>   // buffer
    mov x2, #5          // count
    mov x16, #4         // SYS_write = 4
    svc #0x80           // trap to kernel
  |
  v
EL0 -> EL1 transition
  |
  SAVE_REGS (816-byte trap frame: x0-x30, SP, ELR, SPSR, ESR, FAR, NEON)
  |
  trap_sync_el0(tf)
    ec = (ESR >> 26) = 0x15 (EC_SVC_A64)
    --> syscall_handler(tf)
          x16 = 4 (positive = BSD)
          --> case SYS_write:
                fd = tf->regs[0] = 1   (stdout)
                buf = tf->regs[1]      (user pointer)
                count = tf->regs[2] = 5
                |
                p = proc_current()
                fp = p->p_fd.fd_ofiles[1]  (stdout file)
                vp = fp->f_vnode
                |
                +-- Console write?
                |     --> kprintf or fbconsole_write  (output to screen/UART)
                +-- TTY write?
                |     --> tty_write (line discipline, echo, etc.)
                +-- VFS write?
                      --> vfs_write -> ext4_write (write to filesystem)
                |
                syscall_return(tf, 5)  // wrote 5 bytes, clear carry
  |
  signal_check(thread, tf)  // deliver any pending signals
  |
  RESTORE_REGS -> eret to EL0
  |
  v
User code resumes after svc:
  Check carry flag: clear -> success
  Return value in x0 = 5
```

### 7.4 Path Resolution

**File:** `kernel/bsd/syscalls.c` (`resolve_user_path`)

When a syscall receives a file path like `"../Documents/file.txt"`, the kernel must resolve it to an absolute path:

1. If the path starts with `/`, it's already absolute -- use as-is.
2. Otherwise, prepend the process's current working directory (`p->p_cwd_path`).
3. Call `canonicalize_path()` to resolve `.` and `..` components.

```
Process CWD: "/home/user"
User passes: "../Documents/file.txt"

resolve_user_path():
  relative -> prepend CWD: "/home/user/../Documents/file.txt"

canonicalize_path():
  /home/user/../Documents/file.txt
  ^    ^     ^     ^
  /home/user  [.. pops "user"]  -> /home
  /home/Documents/file.txt

Result: "/home/Documents/file.txt"
```

### 7.5 Signal Delivery

**Files:** `kernel/include/bsd/signal.h` (213 lines), signal handling in `trap.c` and `syscalls.c`

Kiseki implements 31 signals with Darwin-compatible numbering (SIGHUP=1 through SIGUSR2=31).

**Per-process signal state:**

```c
struct sigacts {
    struct sigaction actions[32];    // Per-signal handler + flags
    uint32_t        pending;        // Bitmask of pending signals
    uint32_t        blocked;        // Bitmask of blocked signals
    uint64_t        altstack_sp;    // Alternate stack pointer
    uint64_t        altstack_size;  // Alternate stack size
    bool            altstack_active;
};
```

**Signal delivery flow** (called from `signal_check()` on every return-to-user path):

```
signal_check(thread, tf):
  |
  pending_unblocked = sa->pending & ~sa->blocked
  if none: return
  |
  Find lowest-numbered pending signal
  Clear from pending set
  |
  +-- Handler == SIG_DFL?
  |     SIGKILL/SIGTERM/etc: proc_exit(p, W_EXITCODE(0, signo))
  |     SIGSTOP: set PROC_STOPPED
  |     SIGCONT: resume
  |     SIGCHLD/SIGWINCH: ignore (default-ignore signals)
  |
  +-- Handler == SIG_IGN?
  |     Discard signal, continue
  |
  +-- Handler == user function?
        Push signal frame onto user stack:
          Save current tf->elr, tf->sp, tf->spsr, tf->regs[0..30]
          onto user stack as a "signal context"
        Rewrite trap frame:
          tf->elr = handler address (user function)
          tf->sp  = new stack (with saved context below)
          tf->regs[0] = signo (first argument to handler)
          tf->regs[30] = commpage sigreturn trampoline
        When eret fires: user starts executing the signal handler
        When handler returns: x30 -> sigreturn trampoline -> svc SYS_sigreturn
          sigreturn restores original tf from saved context
```

The CommPage contains a `sigreturn_trampoline` that executes `mov x16, #184; svc #0x80` (SYS_sigreturn). This is how the kernel regains control after the user signal handler returns.

### 7.6 Demand Paging in the Trap Handler

**File:** `kernel/kern/trap.c` (data abort handler)

When a user program accesses an address that has a vm_map entry but no physical page yet (demand paging), or writes to a COW page, the trap handler resolves it:

```
User writes to VA 0x100008000 (mapped in vm_map but no PTE yet)
  |
  Data Abort! (Translation fault, level 3)
  |
  trap_sync_el0(tf)
    ec = EC_DABT_LOWER (0x24)
    --> handle_page_fault(tf)
          FAR = 0x100008000   (faulting address)
          DFSC = 0x07          (level 3 translation fault)
          WnR = 1              (write)
          |
          +-- vm_map_lookup_entry(map, FAR)
          |   Found entry: [0x100000000..0x100010000] RW, anonymous
          |
          +-- Translation fault?
          |     Allocate page: pa = pmm_alloc_page()
          |     Zero the page
          |     Map: vmm_map_page(pgd, 0x100008000, pa, PTE_USER_RW)
          |     Return (instruction retries, succeeds now)
          |
          +-- Permission fault + PTE_COW set?
          |     vmm_copy_on_write(space, FAR)
          |     (See Section 3.6)
          |     Return (instruction retries with RW page)
          |
          +-- No vm_map entry?
                Send SIGSEGV to process
```

This is also how kernel-mode accesses to user buffers work. When the kernel reads from a user pointer (e.g., copying a filename from user space), and the page hasn't been faulted in yet, `trap_sync_el1` handles the translation fault by demand-paging the page, then letting the kernel instruction retry.

### 7.7 Security: DAC Permission Checks

**File:** `kernel/bsd/security.c` (247 lines)

**Credential structure:**

```c
struct ucred {
    uid_t   cr_uid, cr_ruid, cr_svuid;     // Effective, real, saved UIDs
    gid_t   cr_gid, cr_rgid, cr_svgid;     // Effective, real, saved GIDs
    int     cr_ngroups;                      // Number of supplementary groups
    gid_t   cr_groups[16];                   // Supplementary group list
    int     cr_ref;                          // Reference count
};
```

Credentials are managed from a pool of 128 `ucred` structs (no dynamic allocation).

**Permission check:** `vfs_access(vnode, mode, cred)` implements standard Unix DAC:

1. **Root (UID 0)**: bypasses all checks.
2. **Owner match** (`cred->cr_uid == vnode->v_uid`): check bits 8-6 (owner triad).
3. **Group match** (effective GID or supplementary groups): check bits 5-3 (group triad).
4. **Other**: check bits 2-0 (other triad).

**SUID/SGID handling:** During `execve`, if the executable has `S_ISUID` set, the process's effective UID becomes the file's owner UID (and the old effective UID is saved in `cr_svuid`). This is how `su` and `sudo` work.

---

## Chapter 8: Filesystem -- VFS, Ext4, Buffer Cache

User programs think in terms of files and directories. The kernel's job is to translate `open("/etc/hosts")` into block reads from a disk device. Kiseki uses a three-layer filesystem architecture matching BSD/XNU:

```
User space:  open(), read(), write(), close(), mkdir(), stat(), ...
                |
  ========== Kernel boundary (svc #0x80) ==========
                |
                v
  +------ VFS Layer (vfs.c) ------+    Uniform API: vnodes, mounts
  |   vnode_ops dispatch table    |    Path resolution, fd management
  +-------------------------------+
                |
    +-----------+-----------+
    |                       |
    v                       v
  ext4 driver           devfs driver      (one driver per FS type)
  (ext4.c)              (devfs.c)
    |                       |
    v                       |
  Buffer Cache (buf.c)      |
    |                  (in-memory only)
    v
  VirtIO Block Device
    |
    v
  QEMU disk image (ext4.img)
```

### 8.1 The VFS Layer

**Files:** `kernel/fs/vfs.c` (1,454 lines), `kernel/include/fs/vfs.h` (799 lines)

**For the systems newcomer:** A **Virtual Filesystem Switch (VFS)** is an abstraction that lets the kernel support multiple filesystem formats (ext4, FAT32, NFS) behind a single API. Programs don't need to know which format the disk uses -- they just call `read()` and the VFS dispatches to the right driver.

The central abstraction is the **vnode** (virtual node) -- an in-memory representation of a file or directory:

```c
// vfs.h (abridged)
struct vnode {
    enum vtype      v_type;         // VREG, VDIR, VLNK, VCHR, etc.
    uint32_t        v_refcount;     // How many references (open fds, lookups)
    uint64_t        v_ino;          // Inode number (unique within filesystem)
    uint64_t        v_size;         // File size in bytes
    mode_t          v_mode;         // Permission bits (rwxrwxrwx)
    uid_t           v_uid;          // Owner user ID
    gid_t           v_gid;          // Owner group ID
    nlink_t         v_nlink;        // Hard link count
    void            *v_data;        // FS-private data (ext4_vnode_data, etc.)
    struct vnode_ops *v_ops;        // Per-FS operation table
    struct mount    *v_mount;       // Which filesystem this vnode belongs to
    spinlock_t      v_lock;
};
```

Each filesystem registers an **operation table** that the VFS calls for file operations:

```c
struct vnode_ops {
    int (*lookup)(struct vnode *dir, const char *name, uint32_t namelen,
                  struct vnode **result);
    int (*read)(struct vnode *vp, void *buf, uint64_t offset, uint64_t count);
    int (*write)(struct vnode *vp, const void *buf, uint64_t offset, uint64_t count);
    int (*readdir)(struct vnode *dir, void *buf, uint64_t *offset, uint64_t count);
    int (*create)(struct vnode *dir, const char *name, uint32_t namelen,
                  mode_t mode, struct vnode **result);
    int (*mkdir)(struct vnode *dir, const char *name, uint32_t namelen,
                 mode_t mode, struct vnode **result);
    int (*unlink)(struct vnode *dir, const char *name, uint32_t namelen);
    int (*getattr)(struct vnode *vp, struct stat *st);
    int (*setattr)(struct vnode *vp, struct stat *st);
    int (*readlink)(struct vnode *vp, char *buf, uint64_t buflen);
};
```

**Static pools:**

| Pool | Size | Purpose |
|------|------|---------|
| Vnodes | 1,024 | In-memory file/directory representations |
| Files | 512 | System-wide open file descriptions |
| Mounts | 16 | Simultaneously mounted filesystems |
| FS types | 8 | Registered filesystem drivers |

**Path resolution** (`vfs_lookup`): Given a path like `/usr/bin/ls`:

1. Find the mount whose prefix best matches the path (longest prefix wins).
2. Start at the mount's root vnode.
3. For each path component (`usr`, `bin`, `ls`): verify current vnode is a directory, check execute permission, call `v_ops->lookup()`.
4. Return the final vnode.

**The open file table** is two-level, matching Unix:

```
Per-process fd table              System-wide file pool
+--------+                       +------------------+
| fd[0] -+----> file_pool[42]    | file_pool[42]    |
| fd[1] -+----> file_pool[7]     |   f_vnode = ...  |
| fd[2] -+----> file_pool[7]     |   f_offset = 100 |
| fd[3] -+----> file_pool[91]    |   f_refcount = 2 |  <-- fd[1] and fd[2] share!
|  ...   |                       +------------------+
+--------+
```

Multiple fds can point to the same `struct file` (via `dup()` or `fork()`), sharing the offset. This is why `dup2(fd, STDOUT_FILENO)` redirects output -- both fds share the same file position.

### 8.2 The Ext4 Filesystem Driver

**Files:** `kernel/fs/ext4/ext4.c` (2,836 lines), `kernel/include/fs/ext4.h` (544 lines)

Ext4 is the primary on-disk filesystem. Kiseki implements full read-write ext4 with extent trees, indirect blocks, block/inode allocation, and directory operations.

**On-disk layout** (simplified for a small disk):

```
Disk layout (1024-byte blocks):

Block 0:    Boot sector (unused by ext4)
Block 1:    Superblock (1024 bytes at byte offset 1024)
Block 2-N:  Block Group Descriptor Table
...
Block Group 0:
  +-- Block bitmap (1 block = tracks 32,768 blocks)
  +-- Inode bitmap (1 block = tracks 32,768 inodes)
  +-- Inode table (N blocks, each inode = 256 bytes)
  +-- Data blocks
Block Group 1:
  +-- (same structure)
...
```

**Key on-disk structures:**

```c
struct ext4_super_block {     // 1024 bytes at disk offset 1024
    uint32_t s_inodes_count;
    uint32_t s_blocks_count_lo;
    uint32_t s_free_blocks_count_lo;
    uint32_t s_free_inodes_count;
    uint32_t s_first_data_block;
    uint32_t s_log_block_size;   // block_size = 1024 << this
    uint32_t s_blocks_per_group;
    uint32_t s_inodes_per_group;
    uint16_t s_magic;            // Must be 0xEF53
    uint16_t s_inode_size;       // Typically 256
    // ... many more fields
};

struct ext4_inode {           // 128+ bytes (s_inode_size = 256 typically)
    uint16_t i_mode;           // File type + permissions
    uint16_t i_uid;
    uint32_t i_size_lo;
    uint32_t i_atime, i_ctime, i_mtime;
    uint16_t i_gid;
    uint16_t i_links_count;
    uint32_t i_blocks_lo;
    uint32_t i_flags;          // EXT4_EXTENTS_FL if extent-based
    uint32_t i_block[15];      // 60 bytes: block map OR extent tree root
};
```

**Block mapping -- two strategies:**

The `i_block[15]` field (60 bytes) stores either a traditional block map or an extent tree, depending on the `EXT4_EXTENTS_FL` flag:

```
Strategy 1: Extent tree (modern, efficient for contiguous files)

  i_block[0..59] = ext4_extent_header + ext4_extent entries
  
  Header: magic=0xF30A, entries, max, depth
  
  If depth==0 (leaf): entries are ext4_extent
    { logical_block, length, physical_start }
    "Blocks 0-99 of this file map to disk blocks 50000-50099"
  
  If depth>0 (internal): entries are ext4_extent_idx
    { logical_block, child_block_ptr }
    Points to another block containing the next level

Strategy 2: Legacy indirect blocks (small files, writes)

  i_block[0..11]  = direct block pointers (12 blocks)
  i_block[12]     = single indirect (points to block of pointers)
  i_block[13]     = double indirect
  i_block[14]     = triple indirect
```

**Mount process** (`ext4_fs_mount`):

1. Read superblock from byte offset 1024.
2. Verify magic (`0xEF53`).
3. Compute derived values: `block_size = 1024 << s_log_block_size`.
4. Check incompatible feature flags (supports: FILETYPE, EXTENTS, 64BIT, FLEX_BG).
5. Read entire group descriptor table into memory (up to 256 KB buffer).
6. Read root inode (inode 2), create root vnode.

**Block allocation** (`ext4_alloc_block`): Linear scan of block bitmaps starting from a preferred group, wrapping around. Finds first free bit, marks it, updates group descriptor and superblock free counts.

### 8.3 The Buffer Cache

**File:** `kernel/fs/buf.c` (416 lines)

**For the systems newcomer:** Disk I/O is slow (even virtualised). The buffer cache keeps recently-used disk blocks in memory so repeated reads don't hit the disk. It's a fixed-size pool of 4 KB buffers with LRU (Least Recently Used) eviction and write-back (dirty buffers are only flushed when evicted or explicitly synced).

```c
struct buf {
    uint32_t    flags;          // B_VALID, B_DIRTY, B_BUSY
    uint32_t    dev;            // Device number
    uint64_t    block_no;       // Block number (4 KB units)
    uint32_t    refcount;
    uint8_t     *data;          // Pointer to 4 KB data area
    struct buf  *lru_next, *lru_prev;  // LRU doubly-linked list
    struct buf  *hash_next;            // Hash bucket chain
};
```

**Pool:** 256 buffers x 4 KB = **1 MB** total cache.

**Operations:**

```
buf_read(dev, block_no):
  |
  +-- Hash lookup: O(1) by (dev, block_no)
  |     Hit?  -> return cached buffer (move to LRU head)
  |     Miss? -> Evict LRU tail victim:
  |                If dirty: flush to disk first
  |                Reconfigure for new (dev, block_no)
  |                Read from disk via VirtIO block device
  |                Return fresh buffer
  |
  +-- Buffer is returned LOCKED (B_BUSY)

buf_write(bp):
  +-- Mark B_DIRTY (actual disk write deferred)

buf_release(bp):
  +-- Clear B_BUSY, move to LRU head
  +-- Wake threads sleeping on this buffer (biowait pattern)

buf_sync():
  +-- Flush all dirty, non-busy buffers to disk
```

**Background sync daemon:** A kernel thread (`bufsync`) runs at low priority, sleeping for ~30 seconds between passes. It flushes all dirty buffers to disk, similar to BSD's `syncer` or Linux's `pdflush`.

### 8.4 The Device Filesystem (devfs)

**File:** `kernel/fs/devfs.c` (548 lines)

Devfs is a synthetic (in-memory) filesystem mounted at `/dev`. It exposes hardware devices as files:

| Path | Type | Behaviour |
|------|------|-----------|
| `/dev/console` | TTY | Serial console (UART read/write) |
| `/dev/tty` | TTY | Alias for controlling terminal |
| `/dev/null` | Special | Writes succeed, reads return EOF |
| `/dev/zero` | Special | Reads return zero bytes, writes discarded |
| `/dev/fbcon0` | TTY | Framebuffer console |

Devfs nodes are created during boot (up to 16 device slots). Each device vnode has `v_type = VCHR` (character device) and a devfs-specific operation table that routes reads/writes to the appropriate driver (TTY subsystem, UART, framebuffer console).

### 8.5 How It All Fits Together

Let's trace `cat /etc/hosts` through all layers:

```
1. Shell calls: execve("/bin/cat", ["/bin/cat", "/etc/hosts"], envp)

2. cat calls: fd = open("/etc/hosts", O_RDONLY)
     |
     vfs_open("/etc/hosts", O_RDONLY, 0)
       mount_find("/etc/hosts") --> ext4 mount at "/"
       resolve_path("/etc/hosts", root_vnode)
         lookup(root, "etc") --> vnode for /etc/
         lookup(/etc/, "hosts") --> vnode for /etc/hosts
       Allocate fd, create struct file { vnode, offset=0 }
       Return fd=3

3. cat calls: n = read(3, buf, 4096)
     |
     vfs_read(3, buf, 4096)
       fp = proc->p_fd.fd_ofiles[3]
       vp = fp->f_vnode
       vp->v_ops->read(vp, buf, fp->f_offset, 4096)
         ext4_vop_read(vp, buf, 0, 4096)
           ext4_bmap(vp, logical_block=0) --> physical_block=50042
           buf_read(dev, 50042) --> buffer cache
             Hash miss --> read from VirtIO block device
           Copy data from buffer to user buf
       fp->f_offset += n

4. cat calls: write(1, buf, n)
     |
     vfs_write(1, buf, n)
       fp = proc->p_fd.fd_ofiles[1]   (stdout)
       fp->f_vnode is console/PTY device
       --> tty_write or fbconsole_write
       --> Characters appear on screen

 5. cat calls: close(3)
     |
     vfs_close(3)
       Decrement file refcount
       If refcount == 0: release vnode
```

---

## Chapter 9: Networking -- TCP/IP Stack

Kiseki includes a complete, from-scratch networking stack that speaks real TCP/IP over a
VirtIO virtual NIC. Userland programs can `socket()`, `bind()`, `listen()`, `accept()`,
`connect()`, `send()`, and `recv()` just like on any POSIX system -- the difference is
that every byte of the implementation lives in roughly 4,000 lines of kernel C, with no
code borrowed from lwIP, musl, or any other existing stack.

### 9.1 Stack Overview

#### 9.1.1 What *Is* a Networking Stack?

If you have never worked below the `socket()` API, here is the one-paragraph version:
an application calls `send(fd, "hello", 5)`. The kernel wraps those five bytes in a
**TCP segment** (adding sequence numbers and checksums), wraps *that* in an **IP packet**
(adding source/destination addresses and a TTL), wraps *that* in an **Ethernet frame**
(adding MAC addresses), and hands the resulting ~70-byte blob to the network hardware.
On the receiving end the process runs in reverse: the NIC delivers a frame, the kernel
peels off headers layer by layer, and deposits the five payload bytes into the
destination socket's receive buffer for `recv()` to read.

Each "wrap" step is called **encapsulation**; each "peel" step is **decapsulation**.
The layers are numbered bottom-to-top:

```
  Layer   Protocol(s)         Kiseki Source File     Header Size
  -----   ------------------  ---------------------  -----------
    4     TCP / UDP           tcp.c, udp.c           20 / 8 B
    3     IPv4, ICMP          ip.c, icmp.c           20 B
    2     Ethernet, ARP       eth.c                  14 B
    1     VirtIO-net (HW)     virtio_net.c           10 B (*)

  (*) The 10-byte virtio_net_hdr is a hypervisor envelope, not a
      real wire header.  It is stripped before eth_input() sees
      the frame.
```

#### 9.1.2 Architecture & Static Resource Pools

Every data structure in the networking stack is **statically allocated** -- there are no
`kmalloc()` calls. This is a deliberate design choice: bounded memory usage, no
fragmentation, no allocation failure paths. The pools are:

| Resource              | Pool Size | Unit Size   | Total Memory |
|-----------------------|-----------|-------------|--------------|
| Sockets               | 64        | ~8.3 KB     | ~530 KB      |
| TCP control blocks    | 64        | ~80 B       | ~5 KB        |
| ARP cache entries     | 32        | ~12 B       | ~384 B       |
| ARP pending queue     | 4         | ~1.5 KB     | ~6 KB        |
| RX buffers (VirtIO)   | 16        | 2,048 B     | 32 KB        |
| TX buffer (VirtIO)    | 1         | 2,048 B     | 2 KB         |
| Unix PCBs             | 64        | ~112 B      | ~7 KB        |

#### 9.1.3 Packet Flow Overview

**Receive path** -- a packet arrives from the virtual NIC and travels up:

```
 +---------------------+
 | VirtIO used ring    |   virtio_net_recv()  [virtio_net.c:261]
 +---------------------+
           |
           | strip 10-byte virtio_net_hdr
           v
 +---------------------+
 | eth_input()         |   [eth.c:315]
 | Check dest MAC,     |
 | strip 14-byte header|
 +-----+-------+-------+
       |               |
  EtherType          EtherType
  0x0806 (ARP)       0x0800 (IP)
       |               |
       v               v
 arp_input()      ip_input()         [ip.c:178]
 Update cache     Validate checksum,
 Reply if ours    strip 20-byte header
                       |
          +------------+------------+
          |            |            |
      proto 1      proto 6      proto 17
      (ICMP)       (TCP)        (UDP)
          |            |            |
          v            v            v
    icmp_input()  tcp_input()  udp_input()
    Ping reply    State mach.  --> socket rcv buf
    or deliver    Data -> buf  --> or dhcp_input()
    to socket
```

**Transmit path** -- a `send()` syscall travels down:

```
  Userland: sendto(fd, buf, len, ...)
       |
       v
  sys_sendto()              [syscalls.c:4747]
  fd -> socket index
       |
       +--- TCP: sockbuf_write(so_snd) -> tcp_output()
       |
       +--- UDP: udp_output()
       |
       +--- ICMP: ip_output() directly
       |
       v
  ip_output()               [ip.c:263]
  Build 20-byte IP header
  Route: on-link or gateway
       |
       v
  eth_output()              [eth.c:448]
  ARP lookup for next-hop
  Build 14-byte Ethernet header
       |
       v
  nic_send() -> virtio_net_send()   [virtio_net.c:343]
  Prepend 10-byte virtio_net_hdr
  Submit to TX virtqueue
  Poll for completion
```

#### 9.1.4 Initialisation Sequence

Networking is initialised in phase 15 of `kmain()` via `net_init()` (`socket.c:200`):

```
net_init()
  |
  +-- memset(socket_table, 0, ...)   Clear 64 socket slots
  |
  +-- tcp_init()                     Zero 64 TCB pool slots
  |
  +-- eth_init()                     Clear 32 ARP cache entries
  |
  +-- virtio_net_init()              Probe VirtIO MMIO bus:
  |     |                              - Find device_id == 1 (net)
  |     +-- Reset -> ACKNOWLEDGE -> DRIVER
  |     +-- Negotiate VIRTIO_NET_F_MAC only
  |     +-- Read MAC from config space offset 0x100
  |     +-- Setup RX queue (queue 0) + TX queue (queue 1)
  |     +-- DRIVER_OK
  |     +-- Fill RX ring with 16 buffers
  |     +-- Enable IRQ via GIC
  |
  +-- dhcp_configure()               DHCP handshake:
        |                              - Up to 5 DISCOVER attempts
        +-- On success: eth_set_ip(), ip_set_netmask(), ip_set_gateway()
        +-- On failure: static fallback 192.168.64.10/24, gw .1
```

### 9.2 Ethernet & ARP

**Source**: `kernel/net/eth.c` (555 lines)

#### 9.2.1 Ethernet Framing

Ethernet is the **Layer 2** protocol -- it gets packets from one machine to the next
machine on the same physical (or virtual) network segment. Every Ethernet frame looks
like this:

```
  0                   6                   12     14
  +-------------------+-------------------+------+-----------+
  | Destination MAC   | Source MAC        | Type | Payload   |
  | (6 bytes)         | (6 bytes)         | (2B) | (46-1500) |
  +-------------------+-------------------+------+-----------+
  |<------------ 14-byte header --------->|
  |<------------ up to 1514 bytes total ----------------->|
```

The **EtherType** field identifies what is inside the payload:

| EtherType | Value    | Meaning        |
|-----------|----------|----------------|
| IP        | `0x0800` | IPv4 packet    |
| ARP       | `0x0806` | ARP message    |
| IPv6      | `0x86DD` | IPv6 packet    |

The kernel defines these structures in `eth.c` (file-local, not in a header):

```c
struct eth_hdr {                   /* eth.c:37 */
    uint8_t     eth_dst[6];        /* Destination MAC address */
    uint8_t     eth_src[6];        /* Source MAC address */
    uint16_t    eth_type;          /* EtherType (network byte order) */
} __packed;
```

**MAC addresses** are 6-byte hardware identifiers. Kiseki's default MAC is
`52:54:00:12:34:56` (the QEMU convention), overridden by the actual device MAC read
during VirtIO probe. The broadcast MAC `FF:FF:FF:FF:FF:FF` means "deliver to everyone".

#### 9.2.2 Module State

```c
/* eth.c:86-99 */
static uint8_t  local_mac[6] = { 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 };
static uint32_t local_ip     = 0;      /* Set by DHCP or static config */
static uint8_t  broadcast_mac[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static uint8_t    eth_tx_buf[1514];    /* Shared transmit buffer */
static spinlock_t eth_tx_lock;         /* Protects eth_tx_buf */

static struct arp_entry   arp_cache[32];         /* ARP cache */
static spinlock_t         arp_lock;              /* Protects ARP cache */
static struct arp_pending arp_pending_queue[4];   /* Packets awaiting ARP */
static spinlock_t         arp_pending_lock;
```

#### 9.2.3 Receiving Frames: `eth_input()`

`eth_input()` (`eth.c:315`) is the **main entry point** for all received data. The VirtIO
driver calls it after stripping the 10-byte `virtio_net_hdr`.

```
eth_input(frame, len)
  |
  +-- len < 14?  Drop (runt frame)
  |
  +-- Check destination MAC:
  |     - Our MAC?         Accept
  |     - Broadcast?       Accept
  |     - Multicast (bit 0 of byte 0 set)?  Accept
  |     - Other?           Drop (not for us)
  |
  +-- Strip 14-byte eth_hdr, extract EtherType
  |
  +-- Dispatch:
        0x0800  -->  ip_input(payload, payload_len)
        0x0806  -->  arp_input(payload, payload_len)
        other   -->  silently dropped
```

#### 9.2.4 Transmitting Frames: `eth_output()`

`eth_output()` (`eth.c:448`) is called by `ip_output()` to send an IP packet. It must
resolve the **next-hop IP** to a **MAC address** via ARP before it can build the frame.

```
eth_output(dst_ip, ethertype, data, len)
  |
  +-- len > 1500 (MTU)?  Return -E2BIG
  |
  +-- Is dst_ip broadcast (0xFFFFFFFF)?
  |     Yes --> use broadcast MAC
  |     No  --> arp_lookup(dst_ip, mac)
  |               |
  |               +-- Found?  Build frame and send
  |               |
  |               +-- Miss?   arp_enqueue_pending(dst_ip, data, len)
  |                           arp_send(ARP_REQUEST, broadcast, dst_ip)
  |                           return 0  (queued, will send after reply)
  |
  +-- Build Ethernet frame in eth_tx_buf (under eth_tx_lock):
  |     [dst_mac | local_mac | ethertype | payload]
  |
  +-- nic_send(eth_tx_buf, 14 + len)
```

#### 9.2.5 ARP -- Address Resolution Protocol

ARP answers one question: "what is the MAC address for IP address X?" It works by
broadcasting a request and waiting for the owner of that IP to reply.

**ARP message format** (28 bytes for IPv4-over-Ethernet):

```
  0     2     4   5   6     8        14       20        26
  +-----+-----+---+---+-----+--------+--------+--------+--------+
  | HRD | PRO |HLN|PLN| OP  | Sender | Sender | Target | Target |
  |(0001|0800)| 6 | 4 |     | MAC    | IP     | MAC    | IP     |
  +-----+-----+---+---+-----+--------+--------+--------+--------+
  |<--- 8-byte fixed header ------->| |<-- 20 bytes for Ethernet/IPv4 -->|
```

**ARP cache** -- 32 entries, each storing an (IP, MAC, valid) triple. Lookup is a linear
scan under `arp_lock`. When the cache is full, slot 0 is overwritten (simple eviction):

```c
struct arp_entry {             /* eth.c:73 */
    uint32_t ip_addr;          /* IPv4 address (network order) */
    uint8_t  mac_addr[6];      /* Resolved MAC address */
    bool     valid;            /* Entry is populated */
};
```

**ARP pending queue** -- when a packet must be sent but the MAC is unknown, the packet
is stored (up to 4 pending) while an ARP request is broadcast:

```c
struct arp_pending {           /* eth.c:110 */
    uint8_t  data[1514];      /* Saved IP payload */
    uint32_t len;              /* Payload length */
    uint32_t dst_ip;           /* IP we are resolving */
    uint16_t ethertype;        /* EtherType to use when sending */
    bool     valid;
};
```

**Key ARP functions**:

| Function | Line | Purpose |
|----------|------|---------|
| `arp_lookup()` | 166 | Search cache for IP -> MAC mapping |
| `arp_update()` | 189 | Insert or update cache entry |
| `arp_send()` | 233 | Build and transmit an ARP request or reply |
| `arp_input()` | 278 | Process incoming ARP: update cache, reply if targeted at us |
| `arp_enqueue_pending()` | 358 | Queue a packet awaiting ARP resolution |
| `arp_drain_pending()` | 400 | Check cache and send any resolved pending packets |

**ARP resolution flow**:

```
  Application calls send()
       |
       v
  eth_output() -- ARP cache miss for 10.0.0.5
       |
       +-- Save packet in arp_pending_queue[slot]
       |
       +-- arp_send(ARP_REQUEST, broadcast, 10.0.0.5)
       |     |
       |     v
       |   Ethernet frame:  [FF:FF:FF:FF:FF:FF | our_mac | 0x0806]
       |   ARP payload:     "Who has 10.0.0.5? Tell <our_ip>"
       |
       v
  (later) NIC receives ARP reply
       |
       v
  eth_input() --> arp_input()
       |
       +-- arp_update(10.0.0.5, responder_mac)
       |
       +-- arp_drain_pending()
             |
             +-- pending[slot].dst_ip matches cache? Yes!
             +-- Build Ethernet frame with resolved MAC
             +-- nic_send()  -- original packet finally goes out
```

### 9.3 IPv4 & ICMP

**Source**: `kernel/net/ip.c` (319 lines), `kernel/net/icmp.c` (152 lines)

#### 9.3.1 IPv4 Header

IP (Internet Protocol) is the **Layer 3** workhorse -- it routes packets across networks
using 32-bit addresses. Every IP packet starts with a 20-byte header:

```
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |Version|  IHL  |    TOS        |         Total Length          |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |       Identification          |Flags|    Fragment Offset      |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |  TTL  |  Protocol             |       Header Checksum         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Source IP Address                           |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                 Destination IP Address                         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

```c
struct ip_hdr {                    /* ip.c:48 */
    uint8_t  ip_vhl;               /* Version (4) | IHL (5) = 0x45 */
    uint8_t  ip_tos;               /* Type of service (always 0) */
    uint16_t ip_len;               /* Total length (network order) */
    uint16_t ip_id;                /* Identification (incrementing) */
    uint16_t ip_off;               /* Flags + fragment offset */
    uint8_t  ip_ttl;               /* Time to live (64) */
    uint8_t  ip_proto;             /* Protocol: 1=ICMP, 6=TCP, 17=UDP */
    uint16_t ip_sum;               /* Header checksum */
    uint32_t ip_src;               /* Source address */
    uint32_t ip_dst;               /* Destination address */
} __packed;
```

Key constants:

| Constant | Value | Meaning |
|----------|-------|---------|
| `IP_VHL_V4` | `0x45` | IPv4, 5 DWORDs (20 bytes), no options |
| `IP_DF` | `0x4000` | "Don't Fragment" flag |
| `IP_DEFAULT_TTL` | 64 | Hop limit before packet is discarded |
| `IP_MAX_PACKET` | 1500 | Maximum IP packet size (MTU) |

#### 9.3.2 The IP Checksum (RFC 1071)

The IP checksum is a **one's-complement sum** of the header's 16-bit words. If the header
is correct, re-computing the checksum over the entire header (including the checksum field
itself) yields zero. This is used for IP, TCP, UDP, and ICMP.

```c
uint16_t ip_checksum(const void *data, uint32_t len) {  /* ip.c:95 */
    const uint16_t *words = data;
    uint32_t sum = 0;
    while (len > 1) { sum += *words++; len -= 2; }
    if (len == 1) sum += *(const uint8_t *)words;  /* odd trailing byte */
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);  /* fold carry */
    return (uint16_t)~sum;
}
```

#### 9.3.3 Receiving IP Packets: `ip_input()`

`ip_input()` (`ip.c:178`) validates and demultiplexes incoming packets:

```
ip_input(data, len)
  |
  +-- Validate:
  |     len >= 20?                (minimum IP header)
  |     version == 4?             (we only speak IPv4)
  |     IHL >= 5, IHL*4 <= len?   (header length sane)
  |     ip_len <= len?            (total length sane)
  |     ip_checksum() == 0?       (header not corrupted)
  |
  +-- Destination check:
  |     Our IP?        Accept
  |     Broadcast?     Accept
  |     local_ip == 0? Accept (DHCP bootstrap -- no IP yet)
  |     Other?         Drop
  |
  +-- Strip IP header (20+ bytes), extract protocol number
  |
  +-- Dispatch by ip_proto:
        IPPROTO_ICMP (1)  -->  icmp_input(src, dst, payload, len)
        IPPROTO_TCP  (6)  -->  tcp_input(src, dst, payload, len)
        IPPROTO_UDP  (17) -->  udp_input(src, dst, payload, len)
        other             -->  log and drop
```

**Note**: There is no IP fragmentation/reassembly. Kiseki always sets the **Don't Fragment**
flag on outgoing packets, and drops incoming fragments. This is fine for a VM environment
where the MTU is consistent.

#### 9.3.4 Sending IP Packets: `ip_output()`

`ip_output()` (`ip.c:263`) constructs an IP header and routes the packet:

```c
int ip_output(uint32_t src, uint32_t dst, uint8_t proto,
              const void *data, uint32_t len)
```

1. Build header in `ip_tx_buf` with `ip_vhl = 0x45`, `ip_ttl = 64`, `ip_off = IP_DF`
2. Set `ip_id` from incrementing counter (`ip_id_counter++`)
3. If `src == 0`, use `local_ip_addr`
4. Compute header checksum
5. Copy payload after header
6. **Routing decision** (simple next-hop):
   - If `dst` is broadcast: next_hop = dst
   - If `(dst & subnet_mask) != (local_ip_addr & subnet_mask)`: **off-link** -> next_hop = gateway
   - Otherwise: **on-link** -> next_hop = dst
7. Call `eth_output(next_hop, ETHERTYPE_IP, ip_tx_buf, total_len)`

#### 9.3.5 ICMP -- Internet Control Message Protocol

ICMP (`icmp.c`, 152 lines) handles only **echo request** (ping) and **echo reply**:

```c
struct icmp_hdr {              /* icmp.c:27 */
    uint8_t  icmp_type;        /* 8 = echo request, 0 = echo reply */
    uint8_t  icmp_code;        /* 0 for echo */
    uint16_t icmp_cksum;       /* ICMP checksum (same algorithm as IP) */
    uint16_t icmp_id;          /* Identifier (set by sender) */
    uint16_t icmp_seq;         /* Sequence number (set by sender) */
};
```

**Kernel ping responder**: when `icmp_input()` receives an ECHO_REQUEST (type 8), it
copies the entire ICMP message, changes the type to ECHO_REPLY (0), recomputes the
checksum, and sends it back via `ip_output()` with swapped source/destination addresses.
This all happens in kernel context -- no userland process is involved.

**Userland ping**: when `icmp_input()` receives an ECHO_REPLY (type 0), it delivers the
full ICMP packet to the first socket with `so_protocol == IPPROTO_ICMP` via
`icmp_deliver_to_socket()` (`icmp.c:68`). The `ping` utility creates a raw socket
(`socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)`) to send echo requests and receive replies.

### 9.4 UDP & DHCP

**Source**: `kernel/net/udp.c` (148 lines), `kernel/net/dhcp.c` (399 lines)

#### 9.4.1 UDP -- User Datagram Protocol

UDP is the simplest transport protocol: no connection state, no retransmission, no flow
control. Each datagram is independently addressed and delivered (or lost).

```
  0      2      4      6      8
  +------+------+------+------+------------ - -
  | Src  | Dst  | Len  | Csum | Payload ...
  | Port | Port |      |      |
  +------+------+------+------+------------ - -
  |<---- 8-byte UDP header --->|
```

```c
struct udp_hdr {               /* udp.c:23 */
    uint16_t uh_sport;         /* Source port */
    uint16_t uh_dport;         /* Destination port */
    uint16_t uh_len;           /* Length (header + data) */
    uint16_t uh_sum;           /* Checksum (set to 0 -- optional in IPv4) */
} __packed;
```

**Note**: Kiseki does not compute UDP checksums (`uh_sum = 0`). This is legal in IPv4
(RFC 768 makes UDP checksum optional). In a VM environment with no real wire corruption,
this is a reasonable simplification.

**`udp_input()`** (`udp.c:62`):
1. Validate minimum size (8 bytes)
2. **DHCP shortcut**: if `dport == 68`, call `dhcp_input()` directly (before socket lookup)
3. Scan `socket_table` for a matching socket (`so_protocol == IPPROTO_UDP` and
   `so_local.sin_port == dport`)
4. Store sender info in `so_remote` (for `recvfrom()`)
5. Deliver payload to `so_rcv` buffer

**`udp_output()`** (`udp.c:123`):
1. Build 8-byte UDP header (checksum = 0)
2. Copy payload after header
3. Call `ip_output()` with `IPPROTO_UDP`

#### 9.4.2 DHCP Client

DHCP (Dynamic Host Configuration Protocol) runs over UDP and automatically configures
the OS's IP address, subnet mask, gateway, and DNS server at boot time.

**The DHCP handshake** (a "DORA" exchange):

```
  Kiseki (client)                          DHCP Server
       |                                        |
       |--- DHCPDISCOVER (broadcast) ---------->|  "I need an IP"
       |                                        |
       |<-- DHCPOFFER -------------------------+|  "How about 192.168.64.5?"
       |                                        |
       |--- DHCPREQUEST (broadcast) ----------->|  "Yes, I want 192.168.64.5"
       |                                        |
       |<-- DHCPACK ---------------------------+|  "It's yours, here's the config"
       |                                        |
```

All DHCP messages are sent as UDP: client port 68, server port 67. During DISCOVER, the
client has no IP address yet, so it sends from `0.0.0.0` to `255.255.255.255` (broadcast).

**DHCP message structure** (548+ bytes, `dhcp.c:67`):

```
  +-------+-------+-------+------+-------+
  | op(1) |htype  | hlen  | hops | xid   |    Fixed header: 236 bytes
  |       |(1)    | (6)   | (0)  | (4B)  |
  +-------+-------+-------+------+-------+
  | secs  | flags | ciaddr       |yiaddr |    Your IP (offered by server)
  +-------+-------+--------------+-------+
  |siaddr |giaddr | chaddr (16)  | sname |    Client MAC in chaddr
  +-------+-------+--------------+-------+
  | file (128)    | magic cookie (4)     |    0x63825363
  +---------------+----------------------+
  | options (variable, TLV-encoded)      |    Type-Length-Value chain
  +--------------------------------------+
```

**DHCP options** use TLV (type-length-value) encoding. Important option types:

| Code | Name | Length | Meaning |
|------|------|--------|---------|
| 1 | Subnet Mask | 4 | e.g., 255.255.255.0 |
| 3 | Router | 4 | Default gateway IP |
| 6 | DNS | 4+ | DNS server IP |
| 50 | Requested IP | 4 | Client requests specific IP |
| 51 | Lease Time | 4 | Seconds until address expires |
| 53 | Message Type | 1 | DISCOVER(1), OFFER(2), REQUEST(3), ACK(5) |
| 54 | Server ID | 4 | DHCP server's own IP |
| 55 | Param Request | N | List of options client wants |
| 255 | End | 0 | Terminates option chain |

**`dhcp_configure()`** (`dhcp.c:322`) -- the boot-time entry point:

```
dhcp_configure()
  |
  +-- Set IP to 0 (no address yet)
  +-- Brief busy-wait for vmnet init (~500K iterations)
  |
  +-- for attempt in 1..5:
  |     |
  |     +-- dhcp_state = 1 (DISCOVERING)
  |     +-- dhcp_send(DHCPDISCOVER, 0, 0)
  |     |     Build: op=1, broadcast flag, our MAC in chaddr
  |     |     Options: [53:DISCOVER] [55:1,3,6] [255:END]
  |     |     Send via ip_output(0.0.0.0, 255.255.255.255, UDP)
  |     |
  |     +-- Poll for ~3 seconds (300 iterations):
  |           virtio_net_recv()  -- pump the NIC
  |           if g_dhcp_complete: break
  |
  +-- if complete:
  |     eth_set_ip(offered_ip)
  |     ip_set_netmask(mask)       (defaults /24 if none offered)
  |     ip_set_gateway(gateway)
  |     return 0
  |
  +-- if timeout after 5 attempts:
        return -1  (caller uses static fallback)
```

The DHCP state machine in `dhcp_input()` (`dhcp.c:255`):
- **State 1 + OFFER**: Record offered IP, server IP, subnet, gateway. Send DHCPREQUEST.
- **State 2 + ACK**: Record final config. Set `g_dhcp_complete = 1`.
- **State 2 + NAK**: Reset to state 0 (start over).

### 9.5 TCP

**Source**: `kernel/net/tcp.c` (785 lines), `kernel/include/net/tcp.h` (187 lines)

TCP (Transmission Control Protocol) is **the** reliable, ordered, byte-stream protocol.
It is far more complex than UDP because it must handle: connection setup (3-way
handshake), reliable delivery (sequence numbers + ACKs), flow control (window
advertisements), and connection teardown (4-way close).

#### 9.5.1 TCP Segment Header

```
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |          Source Port          |       Destination Port        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                        Sequence Number                        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Acknowledgment Number                      |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | Offset| Rsvd  |U|A|P|R|S|F|       Window Size                |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |           Checksum            |        Urgent Pointer         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Options (if Offset > 5)                    |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

```c
struct tcp_hdr {                   /* tcp.h:36 */
    uint16_t th_sport;             /* Source port */
    uint16_t th_dport;             /* Destination port */
    uint32_t th_seq;               /* Sequence number */
    uint32_t th_ack;               /* Acknowledgment number */
    uint8_t  th_off_rsvd;          /* Data offset (high 4 bits) */
    uint8_t  th_flags;             /* TCP flags (FIN|SYN|RST|PSH|ACK|URG) */
    uint16_t th_win;               /* Window size */
    uint16_t th_sum;               /* Checksum */
    uint16_t th_urp;               /* Urgent pointer */
} __packed;

/* Flag bits */
#define TH_FIN   0x01
#define TH_SYN   0x02
#define TH_RST   0x04
#define TH_PUSH  0x08
#define TH_ACK   0x10
#define TH_URG   0x20
```

#### 9.5.2 The TCP Control Block (TCB)

Each TCP connection has a **TCB** -- a per-connection state block that tracks sequence
numbers, windows, and retransmission state:

```c
struct tcpcb {                     /* tcp.h:85 */
    enum tcp_state t_state;        /* Current state (CLOSED..TIME_WAIT) */
    bool           t_active;       /* Slot allocated in pool */

    /* Sequence number bookkeeping */
    uint32_t snd_una;              /* Oldest unACKed byte we sent */
    uint32_t snd_nxt;              /* Next sequence number to send */
    uint32_t snd_wnd;              /* Send window (from remote) */
    uint32_t rcv_nxt;              /* Next byte we expect to receive */
    uint32_t rcv_wnd;              /* Our receive window (= SOCKBUF_SIZE = 4096) */

    uint32_t iss;                  /* Initial Send Sequence number */
    uint32_t irs;                  /* Initial Receive Sequence number */

    /* Endpoint cache (copied from socket) */
    uint32_t local_addr, remote_addr;   /* IP addresses */
    uint16_t local_port, remote_port;   /* Ports */

    struct socket *t_socket;       /* Back-pointer to owning socket */

    /* Retransmission (simplified) */
    uint32_t t_rxtcur;            /* RTO in ms (starts at 1000) */
    uint32_t t_rxtshift;          /* Backoff exponent */

    spinlock_t t_lock;            /* Per-connection lock */
};
```

The TCB pool is a static array of 64 entries (`tcpcb_pool[TCP_MAX_CONNECTIONS]`).

#### 9.5.3 TCP State Machine

TCP connections move through 11 states. Here is the complete state diagram:

```
                              +------------+
                              |   CLOSED   |
                              +-----+------+
                   active open      |      passive open
                   (send SYN)       |      (listen)
                         +----------+---------+
                         v                    v
                  +-----------+         +-----------+
                  | SYN_SENT  |         |  LISTEN   |
                  +-----+-----+         +-----+-----+
                        |                     |
               recv SYN-ACK              recv SYN
               send ACK                  send SYN-ACK
                        |                     |
                        v                     v
                  +-----+-----+         +-----------+
                  |ESTABLISHED|<--------|  SYN_RCVD |
                  +-----+-----+ recv ACK+-----+-----+
                        |                     |
            +-----------+-----------+         |
            |                       |         |
       close (send FIN)      recv FIN    recv RST
            |               send ACK         |
            v                   v            v
      +-----------+      +-----------+  +--------+
      |FIN_WAIT_1 |      |CLOSE_WAIT |  | CLOSED |
      +-----+-----+      +-----+-----+  +--------+
            |                   |
      +-----+-----+      close (send FIN)
      |           |             |
   recv ACK   recv FIN          v
      |       send ACK    +-----------+
      v           |       | LAST_ACK  |
+-----------+     |       +-----+-----+
|FIN_WAIT_2 |     v             |
+-----+-----+ +--------+  recv ACK
      |        |CLOSING |       |
   recv FIN    +---+----+       v
   send ACK        |       +--------+
      |        recv ACK    | CLOSED |
      v            |       +--------+
 +-----------+     v
 | TIME_WAIT |<----+
 +-----------+
      |
   (timeout)  *Kiseki: immediate
      |
      v
 +--------+
 | CLOSED |
 +--------+
```

**Kiseki simplification**: TIME_WAIT immediately transitions to CLOSED (no 2MSL timer).
This means old duplicate segments could confuse a new connection on the same port, but
in a controlled VM environment this is acceptable.

#### 9.5.4 TCP Checksum

TCP uses a **pseudo-header checksum** that covers the IP addresses (protecting against
misdelivered packets) plus the entire TCP segment:

```c
struct tcp_pseudo_hdr {        /* tcp.c:219 */
    uint32_t src_addr;         /* Source IP from IP header */
    uint32_t dst_addr;         /* Destination IP from IP header */
    uint8_t  zero;             /* Reserved (must be 0) */
    uint8_t  protocol;         /* Always 6 (IPPROTO_TCP) */
    uint16_t tcp_len;          /* TCP segment length (network order) */
} __packed;
```

The `tcp_checksum()` function (`tcp.c:227`) sums the pseudo-header words, then the TCP
segment words, folds to 16 bits, and returns the one's complement -- same RFC 1071
algorithm used for IP.

#### 9.5.5 Connection Setup: The Three-Way Handshake

**Active open** (client calls `connect()`):

```
  Client (tcp_connect)                  Server (tcp_input/LISTEN)
       |                                      |
  1.   |--- SYN (seq=ISS_C) ----------------->|
       |    t_state = SYN_SENT                 |
       |                                       |
       |                           tcp_accept_alloc() creates child socket
       |                           child TCB: irs=ISS_C, rcv_nxt=ISS_C+1
       |                           child generates ISS_S
       |                                       |
  2.   |<-- SYN+ACK (seq=ISS_S, ack=ISS_C+1) -|
       |    snd_una = ISS_C+1                  |
       |    irs = ISS_S                        |  child t_state = SYN_RCVD
       |    rcv_nxt = ISS_S + 1                |
       |    t_state = ESTABLISHED              |
       |                                       |
  3.   |--- ACK (seq=ISS_C+1, ack=ISS_S+1) -->|
       |                                       |  child snd_una = ISS_S+1
       |                                       |  child t_state = ESTABLISHED
       |                                       |  child socket: SS_CONNECTED
```

**ISS generation**: `tcp_new_iss()` (`tcp.c:108`) increments a global counter by 64,000
per connection. This is a simplification -- production systems use RFC 6528 (SipHash) to
prevent sequence number prediction attacks.

**MSS option**: During SYN and SYN-ACK, Kiseki includes a TCP MSS (Maximum Segment Size)
option: kind=2, length=4, MSS=1460 (= 1500 MTU - 20 IP - 20 TCP). This tells the peer
not to send segments larger than 1460 bytes of data.

#### 9.5.6 Data Transfer

Once ESTABLISHED, data flows via `tcp_output()` (`tcp.c:275`):

```
net_send(sockfd, buf, len)           [socket.c:551]
  |
  +-- Write data into so_snd circular buffer (sockbuf_write)
  |     caps at SOCKBUF_SIZE = 4096 bytes
  |
  +-- tcp_output(tp)
        |
        +-- Pull data from so_snd (up to TCP_MAX_SEGMENT = 1460 bytes)
        +-- Build TCP header:
        |     th_seq = tp->snd_nxt
        |     th_ack = tp->rcv_nxt
        |     th_flags = TH_ACK | TH_PUSH (if data present)
        |     th_win = tp->rcv_wnd (4096)
        +-- Advance snd_nxt by data_len
        +-- Compute TCP checksum (pseudo-header + segment)
        +-- ip_output(local_addr, remote_addr, IPPROTO_TCP, ...)
```

On the receive side, `tcp_input()` in ESTABLISHED state (`tcp.c:688`):
1. If RST: immediately CLOSED
2. If ACK: advance `snd_una` (the remote has consumed bytes up to `seg_ack`)
3. If payload present: write to `so_rcv` buffer, set `rcv_nxt = seg_seq + data_len`
4. If FIN: transition to CLOSE_WAIT, set socket SS_DISCONNECTED
5. Send ACK back via `tcp_output()`

**What Kiseki does NOT implement** (compared to a production TCP):
- No congestion control (slow start, AIMD, cubic)
- No Nagle algorithm (small segments are sent immediately)
- No selective acknowledgments (SACK)
- No window scaling (max window = 65535 bytes)
- No kernel-driven retransmission timer -- retransmission is done by the caller's
  busy-wait loop in `net_connect()` for SYN retransmits only
- No out-of-order segment reassembly

#### 9.5.7 Connection Teardown

Closing a TCP connection (`tcp_close()`, `tcp.c:166`) is state-dependent:

| Current State | Action | New State |
|---------------|--------|-----------|
| CLOSED / LISTEN | Free TCB immediately | CLOSED |
| SYN_SENT / SYN_RCVD | Abort (free TCB) | CLOSED |
| ESTABLISHED | Send FIN+ACK | FIN_WAIT_1 |
| CLOSE_WAIT | Send FIN+ACK | LAST_ACK |

The full graceful close:

```
  Client (initiator)                    Server (responder)
       |                                      |
  1.   |--- FIN+ACK ---------------------------->|
       |    FIN_WAIT_1                            |
       |                                          |
  2.   |<-- ACK ---------------------------------+|  CLOSE_WAIT
       |    FIN_WAIT_2                            |
       |                                          |
  3.   |<-- FIN+ACK -----------------------------+|  LAST_ACK
       |                                          |
  4.   |--- ACK --------------------------------->|
       |    TIME_WAIT --> CLOSED (immediate)       |  CLOSED
```

#### 9.5.8 Connection Lookup: `tcp_find_tcb()`

When a segment arrives, the kernel must find the matching TCB. `tcp_find_tcb()`
(`tcp.c:427`) does a **two-pass search**:

1. **Exact 4-tuple match**: scan all 64 TCBs for one where
   `(local_addr == dst || local_addr == 0) && local_port == dst_port &&
    remote_addr == src && remote_port == src_port`
2. **Listening wildcard**: scan for any TCB in `TCPS_LISTEN` where
   `local_port == dst_port && (local_addr == 0 || local_addr == dst_addr)`

The exact match takes priority. This allows a server to have one listening TCB plus
many established connections on the same port.

#### 9.5.9 RST Handling

If `tcp_input()` receives a segment for which **no TCB exists** (`tcp.c:476`), it
sends a RST (reset) back:

- If the incoming segment has ACK: RST with `seq = their_ack`
- If no ACK: RST+ACK with `seq = 0`, `ack = their_seq + payload + SYN?1:0 + FIN?1:0`

This tells the remote side that no connection exists and it should clean up.

### 9.6 BSD Sockets

**Source**: `kernel/net/socket.c` (1,021 lines)

The socket layer is the **userland-facing API**. It maps file descriptors to socket
objects and dispatches operations to the appropriate protocol (TCP, UDP, ICMP, or
AF_UNIX).

#### 9.6.1 The Socket Structure

```c
struct socket {                    /* net.h:184 */
    int  so_type;                  /* SOCK_STREAM, SOCK_DGRAM, SOCK_RAW */
    int  so_protocol;              /* IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP */
    int  so_family;                /* AF_INET, AF_UNIX */
    int  so_state;                 /* SS_UNCONNECTED .. SS_DISCONNECTED */
    int  so_error;                 /* Pending error */
    int  so_options;               /* SO_REUSEADDR etc. */
    int  so_sflags;                /* Shutdown flags */
    bool so_active;                /* Slot in use */

    struct sockaddr_in so_local;   /* Local address/port */
    struct sockaddr_in so_remote;  /* Remote address/port */

    struct sockbuf so_snd;         /* Send buffer (4 KB circular) */
    struct sockbuf so_rcv;         /* Receive buffer (4 KB circular) */

    void *so_pcb;                  /* Protocol control block */
                                   /*   TCP: struct tcpcb * */
                                   /*   UNIX: struct unpcb * */

    int  so_qlimit;                /* Listen backlog limit */
    int  so_qlen;                  /* Current backlog count */
    int  so_listener;              /* Parent listener index (-1 if none) */
    bool so_accepted;              /* accept() has returned this socket */

    spinlock_t so_lock;
};
```

The **socket table** is a global array of 64 sockets (`socket_table[NET_MAX_SOCKETS]`).
Each socket occupies ~8.3 KB due to the two 4 KB circular buffers embedded inline.

#### 9.6.2 Circular Send/Receive Buffers

Each socket has two `sockbuf` -- one for sending, one for receiving. They are simple
circular (ring) buffers:

```
  sockbuf (4096 bytes):

  +---+---+---+---+---+---+---+---+---+---+---+
  |   |   | D | A | T | A |   |   |   |   |   |
  +---+---+---+---+---+---+---+---+---+---+---+
            ^               ^
            head (read)     tail (write)
            sb_len = 4

  sockbuf_write(): writes bytes at tail, advances tail, increments sb_len
  sockbuf_read():  reads bytes at head, advances head, decrements sb_len
  Both wrap around modulo SOCKBUF_SIZE (4096).
  Both are protected by sb_lock (spinlock).
```

#### 9.6.3 Socket API Implementation

| Function | Line | Operation |
|----------|------|-----------|
| `net_socket()` | 260 | Allocate socket slot, validate domain/type/protocol |
| `net_bind()` | 322 | Copy local address into socket, set SS_BOUND |
| `net_listen()` | 352 | Allocate listening TCB, set SS_LISTENING |
| `net_accept()` | 395 | Poll for child socket in SS_CONNECTED, return it |
| `net_connect()` | 458 | TCP: send SYN, poll for SYN-ACK; UDP: just record remote |
| `net_send()` | 551 | TCP: write to so_snd + tcp_output; UDP: udp_output directly |
| `net_recv()` | 595 | Read from so_rcv; return -EAGAIN if empty, 0 if EOF |
| `net_close()` | 640 | TCP: send FIN via tcp_close; mark socket inactive |

**Blocking model**: Kiseki uses **busy-wait polling** rather than sleep/wakeup:

- `net_accept()`: polls up to 50,000 times, calling `virtio_net_recv()` + `sched_yield()`
  each iteration, looking for a child socket
- `net_connect()`: polls up to 3,000 times (~30s) for the TCP handshake to complete,
  retransmitting SYN every ~100 polls (5 retries max)
- `sys_recvfrom()`: retries up to 500 times with `virtio_net_recv()` pumping between
  attempts (~500ms total)

This is simpler than implementing proper wait channels but wastes CPU. The
`sched_yield()` calls ensure other threads can run during the busy-wait.

#### 9.6.4 AF_UNIX -- Unix Domain Sockets

Unix domain sockets (`socket.c:668-1021`) provide IPC between processes on the same
machine, bypassing the entire network stack. Data written by one process appears directly
in the peer's receive buffer -- a pure memory copy.

**Key differences from AF_INET**:

| Aspect | AF_INET | AF_UNIX |
|--------|---------|---------|
| Addressing | IP + port | Filesystem path (up to 104 chars) |
| Data path | Through TCP/IP + NIC | Direct memory copy to peer's buffer |
| PCB | `struct tcpcb` | `struct unpcb` (peer index + path) |
| Connect | Three-way handshake | Find listener by path, link peers |

```c
struct unpcb {                     /* net.h:111 */
    int  unp_peer;                 /* Peer socket index (-1 if none) */
    char unp_path[104];            /* Bound path */
    bool unp_bound;                /* bind() was called */
};
```

**AF_UNIX connect flow** (`unix_connect()`, `socket.c:827`):
1. Find a listening socket with matching path
2. Check backlog (`qlen < qlimit`)
3. Allocate a child socket + unpcb
4. Link peers bidirectionally: `connector->unp_peer = child`, `child->unp_peer = connector`
5. Both sockets transition to SS_CONNECTED

**AF_UNIX send** (`unix_send()`, `socket.c:921`): writes data directly into the
**peer's** `so_rcv` buffer. No headers, no checksums, no protocol machinery.

#### 9.6.5 Syscall Integration

Userland socket calls are translated by syscall wrappers in `syscalls.c` (lines
4616-4914). Each wrapper:

1. Reads arguments from trap frame registers (`x0`-`x5`)
2. Translates the file descriptor to a socket index via `vfs_get_sockidx(fd)`
3. Calls the corresponding `net_*()` function
4. Returns the result via `syscall_return()`

The networking syscall numbers (from `syscall.h`):

| Syscall | Number | Handler |
|---------|--------|---------|
| `SYS_socket` | 97 | `sys_socket` |
| `SYS_connect` | 98 | `sys_connect_sc` |
| `SYS_bind` | 104 | `sys_bind` |
| `SYS_setsockopt` | 105 | `sys_setsockopt` (stub) |
| `SYS_listen` | 106 | `sys_listen_sc` |
| `SYS_accept` | 30 | `sys_accept_sc` |
| `SYS_sendto` | 133 | `sys_sendto` |
| `SYS_recvfrom` | 29 | `sys_recvfrom` |
| `SYS_shutdown` | 134 | `sys_shutdown_sc` |

**Interesting detail**: `sys_sendto()` calls `virtio_net_recv()` *before* sending, to
pump the NIC for any pending ARP replies. Similarly, `sys_connect_sc()` pre-polls for
the same reason. This ensures the ARP cache is warm before the first packet goes out.

#### 9.6.6 Comparison with XNU/macOS

| Feature | Kiseki | XNU/macOS |
|---------|--------|-----------|
| Socket allocation | Static 64-slot array | Dynamic `zalloc()` from socket zone |
| Buffer management | 4 KB embedded circular buffer | `mbuf` chains, variable size |
| TCP connections | Static 64-slot TCB pool | Dynamic, limited by system memory |
| ARP | 32-entry linear-scan cache | Hash table with timeout/aging |
| Fragmentation | None (DF always set) | Full reassembly with 60s timeout |
| Blocking model | Busy-wait polling | `msleep()`/`wakeup()` wait channels |
| UDP checksum | Disabled (= 0) | Mandatory computation |
| TCP congestion | None | NewReno / CUBIC |
| Multicast | Accept frames only | Full IGMP group management |
| IPv6 | Header constants only | Full dual-stack |

---

## Chapter 10: IOKit & Device Drivers

Kiseki reimplements Apple's IOKit driver framework in **plain C** (macOS uses C++ with
libkern). This chapter covers the framework's object model, the I/O Registry, driver
matching, user-client bridging, and every hardware driver: VirtIO GPU, block, network,
input; GICv2 interrupt controller; PL011 UART; TTY/PTY subsystem; and framebuffer
console.

### 10.1 What Is IOKit?

On macOS, **IOKit** is the kernel framework through which all hardware drivers are
written. It provides:

1. An **object-oriented runtime** with reference counting and RTTI
2. An **I/O Registry** -- a live tree of device/driver objects
3. A **matching system** that pairs devices with drivers automatically
4. **IOUserClient** -- a bridge that lets userland talk to kernel drivers via Mach ports
5. **Work loops** for serialised, interrupt-safe driver execution

Kiseki implements all of these in C using embedded structs and function-pointer vtables
instead of C++ virtual methods. The framework lives in 11 source files (~4,900 lines)
under `kernel/iokit/`.

**Why IOKit matters**: when the WindowServer wants to draw pixels, it opens an
IOFramebuffer user client, maps the GPU's VRAM into its address space, and calls
external methods to flush regions. When it wants mouse/keyboard events, it opens an
IOHIDSystem user client and maps the HID event ring buffer. All of this happens through
the IOKit framework.

### 10.2 The IOKit Object Model

#### 10.2.1 Class Hierarchy

IOKit uses a single-inheritance hierarchy implemented via struct embedding:

```
  io_object                 Base: vtable, refcount, RTTI
      |
      +-- io_registry_entry     Registry node: name, properties, plane links
              |
              +-- io_service        Driver: probe/start/stop, matching, work loop
                      |
                      +-- io_user_client   Userland bridge: external methods, memory mapping
                      |
                      +-- io_framebuffer   GPU driver service
                      |
                      +-- io_hid_system    Input event service
```

Each level adds fields *after* its parent's fields, so a pointer to `io_service` can be
safely cast to `io_registry_entry *` or `io_object *` -- the parent struct is always at
offset 0. This is the C equivalent of C++ inheritance.

#### 10.2.2 RTTI -- Runtime Type Information

Every class has a **class metadata** descriptor:

```c
struct io_class_meta {             /* io_object.h:35 */
    const char *class_name;        /* "IOService", "IOFramebuffer", etc. */
    const struct io_class_meta *super_meta;  /* Parent class metadata */
    uint32_t instance_size;        /* sizeof(struct io_framebuffer) etc. */
};
```

Type checking walks the `super_meta` chain:

```c
bool io_object_is_class(struct io_object *obj,
                        const struct io_class_meta *target_meta) {
    const struct io_class_meta *m = obj->meta;
    while (m) {
        if (m == target_meta) return true;
        m = m->super_meta;
    }
    return false;
}
```

This is equivalent to `dynamic_cast` in C++ -- it checks whether an object's class is
the target class or any subclass of it.

#### 10.2.3 Reference Counting

Every `io_object` has an atomic `retain_count`:

```c
struct io_object {                 /* io_object.h:69 */
    const struct io_object_vtable *vtable;
    const struct io_class_meta *meta;
    volatile int32_t retain_count; /* Atomic refcount */
    uint32_t _pad;
    struct ipc_port *iokit_port;   /* Mach port for userland access */
};
```

- `io_object_retain()`: atomically increments `retain_count`
- `io_object_release()`: atomically decrements; if it reaches zero, calls
  `vtable->free(obj)` to destroy the object

All IOKit objects are allocated from **static pools** (no `kmalloc`):

| Pool | Size | Purpose |
|------|------|---------|
| `io_object` pool | 256 | Base objects |
| `io_registry_entry` pool | 256 | Registry nodes |
| `io_service` pool | 256 | Driver instances |
| `io_user_client` pool | 64 | User-client connections |
| `io_work_loop` pool | 32 | Work loops |
| `io_event_source` pool | 64 | Event sources |
| `io_interrupt_event_source` pool | 32 | IRQ event sources |
| `io_command_gate` pool | 32 | Command gates |
| `io_memory_descriptor` pool | 64 | Memory descriptors |
| `io_memory_map` pool | 64 | Memory mappings |

#### 10.2.4 Vtables

Each class level defines a vtable struct that extends the parent's:

```c
struct io_object_vtable {                    /* io_object.h:47 */
    void (*free)(struct io_object *obj);
};

struct io_registry_entry_vtable {            /* io_registry_entry.h:61 */
    struct io_object_vtable base;            /* Inherits free() */
    const struct io_prop_value *(*getProperty)(...);
    IOReturn (*setProperty)(...);
};

struct io_service_vtable {                   /* io_service.h:37 */
    struct io_registry_entry_vtable base;    /* Inherits above */
    struct io_service *(*probe)(...);        /* Can this driver handle provider? */
    bool (*start)(...);                      /* Initialise driver on provider */
    void (*stop)(...);                       /* Tear down driver */
    struct io_work_loop *(*getWorkLoop)(...);
    IOReturn (*message)(...);
    IOReturn (*newUserClient)(...);          /* Create user-client for this service */
};

struct io_user_client_vtable {               /* io_user_client.h:82 */
    struct io_service_vtable base;           /* Inherits above */
    IOReturn (*externalMethod)(...);         /* Handle method call from userland */
    IOReturn (*clientMemoryForType)(...);    /* Provide memory for mapping */
    IOReturn (*clientClose)(...);            /* User closed connection */
};
```

When the kernel needs to call, say, `start()` on a driver, it does:

```c
((struct io_service_vtable *)service->entry.obj.vtable)->start(service, provider);
```

### 10.3 The I/O Registry

The I/O Registry is a **live tree** of all devices and drivers in the system. It is
organised into **planes** -- different views of the same objects:

| Plane ID | Name | Purpose |
|----------|------|---------|
| `IO_PLANE_SERVICE` (0) | IOService | Driver attachment hierarchy |
| `IO_PLANE_DEVICE_TREE` (1) | IODeviceTree | Hardware device tree |
| `IO_PLANE_POWER` (2) | IOPower | Power management |

Each registry entry tracks its parent and children in each plane:

```c
struct io_plane_link {                 /* io_registry_entry.h:48 */
    struct io_registry_entry *parent;
    struct io_registry_entry *children[32];  /* Max 32 children per plane */
    uint32_t child_count;
};

struct io_registry_entry {             /* io_registry_entry.h:95 */
    struct io_object obj;              /* Base object (vtable, refcount) */
    uint32_t entry_id;                 /* Unique ID assigned by registry */
    char name[64];                     /* e.g., "Root", "VirtIOGPU" */
    char location[64];                 /* e.g., "0x0a000000" */
    struct io_prop_table prop_table;   /* Key-value properties */
    struct io_plane_link planes[3];    /* One link per plane */
    mutex_t arb_lock;                  /* Arbitration lock */
    /* ... pool management fields */
};
```

#### 10.3.1 Property Tables

Instead of XNU's `OSDictionary` (a C++ dictionary class), Kiseki uses flat arrays:

```c
struct io_prop_value {                 /* io_property.h:50 */
    io_prop_type_t type;               /* STRING, NUMBER, BOOL, DATA */
    union {
        char     string[128];
        uint64_t number;
        bool     boolean;
        struct { uint8_t bytes[256]; uint32_t length; } data;
    } u;
};

struct io_prop_entry {                 /* io_property.h:75 */
    char key[64];
    struct io_prop_value value;
};

struct io_prop_table {                 /* io_property.h:87 */
    struct io_prop_entry entries[64];  /* Max 64 properties per object */
    uint32_t count;
};
```

Properties are how drivers advertise capabilities and how the matching system finds
drivers. For example, a framebuffer driver sets `IOClass = "IOFramebuffer"` and
`IOProviderClass = "IOService"`.

#### 10.3.2 The Global Registry

```c
struct io_registry {                   /* io_registry.h:77 */
    struct io_registry_entry *root;    /* Root of the tree */
    struct io_driver_personality catalogue[64];  /* Driver catalogue */
    uint32_t catalogue_count;
    mutex_t lock;
    uint32_t next_entry_id;           /* Auto-incrementing */
    bool initialised;
    struct ipc_port *master_port;      /* IOKit master Mach port */
};

extern struct io_registry g_io_registry;   /* Single global instance */
```

### 10.4 Driver Matching & Lifecycle

#### 10.4.1 Driver Personalities

Each driver registers one or more **personalities** in the catalogue. A personality
describes what hardware the driver can handle:

```c
struct io_driver_personality {         /* io_registry.h:55 */
    bool active;
    char class_name[64];               /* "IOFramebuffer" */
    char provider_class[64];           /* "IOService" -- what I attach to */
    int32_t probe_score;               /* Higher = preferred */
    char match_category[64];           /* For priority grouping */
    struct io_prop_table match_properties;  /* Must-match properties */
    io_driver_init_fn init_fn;         /* Factory function */
};
```

#### 10.4.2 The Matching Algorithm

When a new service registers (`io_service_register()`), the framework calls
`io_catalogue_start_matching()`. This implements XNU's matching algorithm:

```
io_catalogue_start_matching(provider)
  |
  +-- io_catalogue_find_drivers_for_service(provider)
  |     |
  |     +-- For each personality in catalogue:
  |     |     1. Filter by IOProviderClass -- personality's provider_class must
  |     |        match a class in provider's meta chain
  |     |     2. Filter by IOPropertyMatch -- all match_properties must exist
  |     |        in provider's property table with equal values
  |     |     3. Collect matching personalities
  |     |
  |     +-- Sort by IOProbeScore (descending)
  |     +-- Group by IOMatchCategory (only highest score per category wins)
  |
  +-- For each winning personality:
        1. Call init_fn(provider) -- creates driver instance
        2. Call driver->probe(driver, provider, &score)
        3. If probe succeeds and score is highest:
             Call driver->start(driver, provider)
             Attach driver to provider in IOService plane
             Register driver (triggers recursive matching for its children)
```

#### 10.4.3 Initialisation Sequence

`iokit_init()` (`io_registry.c`) runs during `kmain()` phase 14:

```
iokit_init()
  |
  +-- io_registry_init()            Create root entry, init catalogue
  |
  +-- Create master port             ipc_port_alloc() with IKOT_MASTER_DEVICE
  |   Register as "uk.co.avltree9798.iokit" in bootstrap
  |
  +-- io_framebuffer_init_driver()  Register IOFramebuffer personality
  |     Sets: IOClass="IOFramebuffer", IOProviderClass="IOService"
  |     init_fn creates io_framebuffer, links to VirtIO GPU
  |
  +-- io_hid_system_init_driver()   Register IOHIDSystem personality
  |     Sets: IOClass="IOHIDSystem", IOProviderClass="IOService"
  |     init_fn creates io_hid_system, links to HID event ring
  |
  +-- io_catalogue_start_matching(root)  Trigger matching for registered drivers
```

### 10.5 IOUserClient & External Methods

IOUserClient is the bridge between userland and kernel drivers. When a user process
wants to talk to a driver, it:

1. Finds the service via `IOServiceGetMatchingService()` (Mach message to master port)
2. Opens a connection via `IOServiceOpen()` -> calls `service->newUserClient()`
3. Calls methods via `IOConnectCallMethod()` -> dispatched through external method table
4. Maps memory via `IOConnectMapMemory()` -> maps driver memory into user address space

#### 10.5.1 External Method Dispatch

Each user client has a **dispatch table** -- an array of method descriptors:

```c
struct io_external_method_dispatch {       /* io_user_client.h:68 */
    io_external_method_fn function;        /* The actual handler */
    uint32_t checkScalarInputCount;        /* Expected # of input scalars */
    uint32_t checkStructureInputSize;      /* Expected input struct size */
    uint32_t checkScalarOutputCount;       /* Expected # of output scalars */
    uint32_t checkStructureOutputSize;     /* Expected output struct size */
};
```

When userland calls `IOConnectCallMethod(connection, selector, ...)`, the kernel:

1. Validates `selector < dispatch_table_count`
2. Validates scalar/structure counts against the dispatch entry
3. Calls `dispatch[selector].function(client, NULL, args)`

Arguments are passed in a unified structure:

```c
struct io_external_method_args {           /* io_user_client.h:37 */
    const uint64_t *scalarInput;           /* Up to 16 scalar inputs */
    uint32_t scalarInputCount;
    const void *structureInput;            /* Up to 4096 bytes */
    uint32_t structureInputSize;
    uint64_t *scalarOutput;                /* Up to 16 scalar outputs */
    uint32_t scalarOutputCount;
    void *structureOutput;                 /* Up to 4096 bytes */
    uint32_t structureOutputSize;
};
```

#### 10.5.2 Memory Mapping

`IOConnectMapMemory()` maps driver-owned physical memory into the calling process:

```
io_user_client_map_memory(client, type, task, ...)
  |
  +-- vtable->clientMemoryForType(client, type, &options, &mem_desc)
  |     Driver returns an io_memory_descriptor for the requested type
  |     (e.g., type 0 = VRAM for IOFramebuffer, event ring for IOHIDSystem)
  |
  +-- io_memory_descriptor_map(mem_desc, task, ...)
  |     1. vm_map_enter() -- allocate VA range in task's address space
  |     2. For each physical page in descriptor:
  |          vmm_map_page(task->vm_map.pml4, va, pa, prot, cache_mode)
  |     3. Return io_memory_map with virtual address
  |
  +-- Store mapping in client->mappings[] (up to 16)
  +-- Return virtual address to caller
```

Cache modes for ARM64 PTE attributes:

| IOKit Mode | ARM64 PTE | Use Case |
|------------|-----------|----------|
| `kIOMapInhibitCache` | Device-nGnRnE (MAIR index 1) | MMIO registers |
| `kIOMapWriteCombineCache` | Normal Non-Cacheable (MAIR index 2) | GPU VRAM |
| `kIOMapCopybackCache` | Normal Write-Back (MAIR index 0) | Regular memory |

#### 10.5.3 Mach IPC Integration

IOKit operations arrive as Mach messages on IOKit ports. The kernel-side dispatcher is
`iokit_kobject_server()` (`iokit_mach.c`), which handles messages based on `msgh_id`:

| Message ID | Operation | Port Type |
|------------|-----------|-----------|
| 2804 | `GetMatchingServices` | `IKOT_MASTER_DEVICE` |
| 2873 | `GetMatchingService` | `IKOT_MASTER_DEVICE` |
| 2812 | `GetProperty` | `IKOT_IOKIT_OBJECT` |
| 2828 | `SetProperty` | `IKOT_IOKIT_OBJECT` |
| 2862 | `ServiceOpen` | `IKOT_IOKIT_OBJECT` |
| 2816 | `ServiceClose` | `IKOT_IOKIT_CONNECT` |
| 2863 | `MapMemory` | `IKOT_IOKIT_CONNECT` |
| 2864 | `UnmapMemory` | `IKOT_IOKIT_CONNECT` |
| 2865 | `CallMethod` | `IKOT_IOKIT_CONNECT` |

The handler allocates reply/scratch buffers from PMM (8 pages = 32 KB) to avoid stack
overflow, validates all user-supplied string lengths and scalar counts, and dispatches
to the appropriate IOKit function.

### 10.6 IOFramebuffer -- The GPU Driver

**Source**: `kernel/iokit/io_framebuffer.c`

IOFramebuffer wraps the VirtIO GPU device and exposes it through the IOKit framework.

#### 10.6.1 Data Structures

```c
struct io_framebuffer {                /* io_framebuffer.h:60 */
    struct io_service service;         /* Inherits from io_service */
    uint64_t fb_phys_addr;            /* Physical address of VRAM */
    uint32_t fb_width, fb_height;     /* Display resolution */
    uint32_t fb_pitch;                /* Bytes per scanline */
    uint32_t fb_bpp;                  /* Bits per pixel (32) */
    uint32_t fb_format;               /* Pixel format */
    bool fb_active;
    struct io_memory_descriptor *fb_mem_desc;  /* For memory mapping */
};

struct io_framebuffer_user_client {    /* io_framebuffer.h:81 */
    struct io_user_client uc;          /* Inherits from io_user_client */
    struct io_framebuffer *framebuffer;
};
```

#### 10.6.2 External Methods

The framebuffer exposes 3 methods to userland:

| Selector | Name | Inputs | Action |
|----------|------|--------|--------|
| 0 | `GetInfo` | None | Returns width, height, pitch, bpp, format as 5 scalars |
| 1 | `FlushRect` | 4 scalars: x, y, w, h | Calls `virtio_gpu_flush(x, y, w, h)` |
| 2 | `FlushAll` | None | Calls `virtio_gpu_flush_all()` |

**Memory type 0** (`kIOFBMemoryTypeVRAM`): returns the framebuffer's `fb_mem_desc`,
which describes the contiguous physical VRAM. The WindowServer maps this into its
address space with `kIOMapWriteCombineCache` and draws directly into it.

**Important side effect**: when `newUserClient()` is called (WindowServer opening the
framebuffer), `fbconsole_disable()` is called to stop the text console from painting
over the GUI. When `clientClose()` is called, `fbconsole_enable()` re-enables it.

### 10.7 IOHIDSystem -- Input Events

**Source**: `kernel/iokit/io_hid_system.c`

IOHIDSystem exposes the HID event ring buffer to userland processes (the WindowServer).

#### 10.7.1 The HID Event Ring

```c
struct hid_event {                     /* hid_event.h:60 */
    uint32_t type;                     /* KEY_DOWN, KEY_UP, MOUSE_MOVE, etc. */
    uint32_t keycode;                  /* Linux keycode or button ID */
    uint32_t abs_x, abs_y;            /* Absolute tablet coordinates */
    uint32_t buttons;                  /* Button state bitmask */
    uint32_t flags;                    /* Modifier flags (shift/ctrl/alt/caps) */
    uint64_t timestamp;                /* Timer tick count */
};

struct hid_event_ring {                /* hid_event.h:81 */
    volatile uint32_t write_idx;       /* Producer (IRQ handler) */
    volatile uint32_t read_idx;        /* Consumer (WindowServer) */
    uint32_t size;                     /* 256 */
    uint32_t _pad;
    struct hid_event events[256];      /* Ring buffer */
};
```

This is a **single-producer, single-consumer (SPSC)** lock-free ring buffer:
- **Producer**: VirtIO input IRQ handler writes events and advances `write_idx`
- **Consumer**: WindowServer reads events and advances `read_idx`
- No locks needed because there is exactly one writer and one reader, and the indices
  are `volatile` (compiler barrier) with natural ARM64 release/acquire semantics

**Event types**:

| Type | Value | Meaning |
|------|-------|---------|
| `HID_EVENT_KEY_DOWN` | 1 | Key pressed |
| `HID_EVENT_KEY_UP` | 2 | Key released |
| `HID_EVENT_MOUSE_MOVE` | 3 | Cursor moved (abs_x, abs_y updated) |
| `HID_EVENT_MOUSE_DOWN` | 4 | Mouse button pressed |
| `HID_EVENT_MOUSE_UP` | 5 | Mouse button released |
| `HID_EVENT_SCROLL` | 6 | Scroll wheel event |

**Memory type 0** (`kIOHIDMemoryTypeEventRing`): maps the entire `hid_event_ring`
structure (header + 256 events) into the WindowServer's address space. The WindowServer
polls `write_idx != read_idx` to check for new events.

### 10.8 VirtIO Transport Layer

VirtIO is a standard para-virtualised device interface. Instead of emulating real
hardware (e.g., an Intel E1000 NIC), the hypervisor exposes a simple, efficient
abstraction. Kiseki uses the **MMIO transport** (memory-mapped I/O), which QEMU's
`-machine virt` provides.

#### 10.8.1 MMIO Device Discovery

QEMU places up to 32 VirtIO devices at fixed MMIO addresses:

```
  Base address:  VIRTIO_MMIO_BASE   = 0x0A000000
  Stride:        VIRTIO_MMIO_STRIDE = 0x200  (512 bytes per slot)
  IRQ base:      VIRTIO_MMIO_IRQ_BASE = 48   (SPI 48, 49, 50, ...)
  Count:         32 slots

  Slot i:  base = 0x0A000000 + i * 0x200
           IRQ  = 48 + i
```

Each slot has a 512-byte register region. A driver probes by reading:
- `VIRTIO_MMIO_MAGIC` (offset 0x000): must be `0x74726976` ("virt")
- `VIRTIO_MMIO_DEVICE_ID` (offset 0x008): device type (0 = empty slot)

#### 10.8.2 VirtIO MMIO Registers

Key registers (all 32-bit, at offsets from slot base):

```
  Offset  Register              Direction  Purpose
  ------  --------------------  ---------  ---------------------------
  0x000   MagicValue            R          Must be 0x74726976
  0x004   Version               R          1=legacy, 2=modern (v1.0+)
  0x008   DeviceID              R          1=net, 2=blk, 16=GPU, 18=input
  0x010   DeviceFeatures        R          Features device supports
  0x014   DeviceFeaturesSel     W          Select feature word (0 or 1)
  0x020   DriverFeatures        W          Features driver accepts
  0x024   DriverFeaturesSel     W          Select feature word
  0x030   QueueSel              W          Select queue by index
  0x034   QueueNumMax           R          Max descriptors for selected queue
  0x038   QueueNum              W          Set actual queue size
  0x044   QueueReady            W          Mark queue as ready (modern)
  0x050   QueueNotify           W          Notify device of new buffers
  0x060   InterruptStatus       R          Pending interrupt bits
  0x064   InterruptACK          W          Acknowledge (clear) interrupts
  0x070   Status                R/W        Device status register
  0x080   QueueDescLow/High     W          Descriptor table phys addr (modern)
  0x090   QueueAvailLow/High    W          Available ring phys addr (modern)
  0x0A0   QueueUsedLow/High     W          Used ring phys addr (modern)
```

#### 10.8.3 Device Initialisation Protocol

Every VirtIO device follows this sequence:

```
1. Reset:       Write 0 to Status register
2. ACKNOWLEDGE: Set status bit 0 -- "I see you"
3. DRIVER:      Set status bit 1 -- "I know how to drive you"
4. Negotiate:   Read DeviceFeatures, AND with driver features,
                write to DriverFeatures
5. FEATURES_OK: Set status bit 3 -- "We agree on features" (modern only)
6. Queue setup: For each virtqueue:
                  - Select queue (QueueSel)
                  - Read QueueNumMax
                  - Allocate descriptor/avail/used ring memory
                  - Write addresses to QueueDesc/Avail/Used registers
                  - Set QueueReady = 1
7. DRIVER_OK:   Set status bit 2 -- "I'm ready to operate"
```

#### 10.8.4 Virtqueues

A **virtqueue** is a pair of ring buffers shared between driver and device:

```
  +-------------------------------------------+
  | Descriptor Table                          |
  | (array of virtq_desc, each 16 bytes)      |
  |  +------+------+-------+------+------+    |
  |  | addr | len  | flags | next | ...  |    |
  |  +------+------+-------+------+------+    |
  +-------------------------------------------+
  | Available Ring (driver -> device)          |
  |  flags | idx | ring[0] | ring[1] | ...    |
  +-------------------------------------------+
  | Used Ring (device -> driver)               |
  |  flags | idx | {id,len}[0] | {id,len}[1]  |
  +-------------------------------------------+
```

```c
struct virtq_desc {                /* virtio.h:111, 16 bytes */
    uint64_t addr;                 /* Physical address of buffer */
    uint32_t len;                  /* Buffer length */
    uint16_t flags;                /* NEXT=1, WRITE=2, INDIRECT=4 */
    uint16_t next;                 /* Next descriptor in chain */
} __packed;
```

**How it works**:

1. **Driver posts a request**: allocates descriptor(s) from the free list, fills in
   buffer addresses, chains them with `VIRTQ_DESC_F_NEXT` + `next`. Writes the head
   descriptor index to `avail->ring[avail->idx % num]`, increments `avail->idx`,
   writes to `QueueNotify`.

2. **Device processes the request**: reads from the available ring, follows the
   descriptor chain, reads/writes the buffers, then posts the completed descriptor head
   to `used->ring[used->idx % num]` with total bytes written, increments `used->idx`.

3. **Driver collects the response**: compares `used->idx` with its `last_used_idx`.
   For each new entry: processes the result, frees descriptors back to the free list.

Free descriptors are managed as a **singly-linked list** through the `next` field,
with `free_head` tracking the list head and `num_free` the count.

#### 10.8.5 Shared VirtIO Helpers

`kernel/drivers/virtio/virtio_blk.c` contains shared initialisation functions used by
all VirtIO drivers:

| Function | Line | Purpose |
|----------|------|---------|
| `virtio_init_device()` | -- | Reset, ACKNOWLEDGE, DRIVER status |
| `virtio_negotiate_features()` | -- | Read device features, AND with driver, write back |
| `virtio_alloc_queue()` | -- | Allocate and set up a virtqueue (descriptors + rings) |

### 10.9 VirtIO GPU Protocol

**Source**: `kernel/drivers/virtio/virtio_gpu.c` (1,137 lines),
`kernel/include/drivers/virtio_gpu.h` (294 lines)

#### 10.9.1 GPU Architecture

The VirtIO GPU is a **2D display controller**. It does not do 3D rendering (that would
require the VirGL extension, which Kiseki does not use). The driver allocates a
**host resource** (a rectangle of pixels), attaches **backing storage** (physical pages
that serve as VRAM), and tells the GPU to scanout (display) that resource.

```
  +---------------------------+
  | Guest Physical Memory     |
  | (VRAM backing pages)      |  <-- CPU writes pixels here
  +---------------------------+
           |
           | TRANSFER_TO_HOST_2D
           v
  +---------------------------+
  | Host Resource (GPU-side)  |  <-- GPU's internal copy
  +---------------------------+
           |
           | RESOURCE_FLUSH
           v
  +---------------------------+
  | Display Output            |  <-- What you see on screen
  +---------------------------+
```

#### 10.9.2 Framebuffer Info

```c
struct framebuffer_info {              /* virtio_gpu.h:228 */
    uint64_t phys_addr;               /* Physical address of VRAM */
    uint32_t width, height;           /* Resolution (e.g., 1024x768) */
    uint32_t pitch;                   /* Bytes per row (width * 4) */
    uint32_t bpp;                     /* Bits per pixel (32) */
    uint32_t format;                  /* VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM */
    bool active;
};
```

#### 10.9.3 GPU Command Protocol

All commands go through the **controlq** (queue 0). Each command is a request-response
pair: the driver builds a request struct, posts it as a descriptor, and the GPU writes
a response struct to a second descriptor.

Key command types:

| Command | ID | Purpose |
|---------|----|---------|
| `GET_DISPLAY_INFO` | 0x0100 | Query available displays and resolutions |
| `RESOURCE_CREATE_2D` | 0x0101 | Allocate a GPU-side pixel buffer |
| `RESOURCE_ATTACH_BACKING` | 0x0106 | Link guest physical pages to resource |
| `SET_SCANOUT` | 0x0103 | Assign resource to a display output |
| `TRANSFER_TO_HOST_2D` | 0x0105 | Copy pixels from guest to host resource |
| `RESOURCE_FLUSH` | 0x0104 | Push host resource to display |

#### 10.9.4 GPU Initialisation

```
virtio_gpu_init()
  |
  +-- Scan MMIO slots for device_id == 16 (GPU)
  +-- Standard VirtIO init (reset, negotiate, queue setup)
  |     Features: none requested (2D only, no VirGL)
  |
  +-- GET_DISPLAY_INFO
  |     Response contains display resolution (e.g., 1024x768)
  |
  +-- Allocate VRAM backing pages:
  |     pmm_alloc_pages(order)  -- contiguous physical pages
  |     Remap as Non-Cacheable (ARM64 Normal-NC) for DMA coherence
  |
  +-- RESOURCE_CREATE_2D (resource_id=1, format=B8G8R8X8, width, height)
  |
  +-- RESOURCE_ATTACH_BACKING (resource_id=1, backing pages as scatter-gather)
  |     Uses 3-descriptor chain: [request | page_list | response]
  |     Each entry: { phys_addr, length }
  |
  +-- SET_SCANOUT (scanout=0, resource_id=1, rect=full screen)
  |
  +-- Initial TRANSFER_TO_HOST_2D + RESOURCE_FLUSH (display initial content)
  |
  +-- Fill framebuffer_info struct
  +-- Enable IRQ via GIC
```

#### 10.9.5 Flush Operation

When the WindowServer (or fbconsole) modifies pixels in VRAM:

```
virtio_gpu_flush(x, y, width, height)       [virtio_gpu.c]
  |
  +-- Build TRANSFER_TO_HOST_2D command
  |     rect = {x, y, width, height}
  |     offset = y * pitch + x * 4
  |     resource_id = 1
  |
  +-- Post to controlq, notify device
  |
  +-- Poll for response (busy-wait on used ring)
  |
  +-- Build RESOURCE_FLUSH command
  |     rect = {x, y, width, height}
  |     resource_id = 1
  |
  +-- Post to controlq, notify device
  |
  +-- Poll for response
```

**QEMU TCG compatibility note**: the GPU driver uses `spin_lock_irqsave` but
**re-enables IRQs** during the poll loop. QEMU's TCG (Tiny Code Generator) is
single-threaded, so if IRQs are disabled during the poll, the virtual device can never
complete the request -- deadlock. The re-enable window lets timer ticks and other IRQs
fire during the wait.

### 10.10 VirtIO Block, Network & Input

#### 10.10.1 VirtIO Block Device

**Source**: `kernel/drivers/virtio/virtio_blk.c` (582 lines)

The block device provides sector-level read/write access to a virtual disk. It uses
a single virtqueue (queue 0) with 3-descriptor chains:

```
  Descriptor 0 (device-read):    struct virtio_blk_req header
  Descriptor 1 (device-read or   Data buffer (sector data)
                device-write):
  Descriptor 2 (device-write):   1-byte status (0=OK, 1=IOERR, 2=UNSUPP)
```

```c
struct virtio_blk_req {            /* virtio.h:170 */
    uint32_t type;                 /* VIRTIO_BLK_T_IN (read) or _OUT (write) */
    uint32_t reserved;
    uint64_t sector;               /* Starting sector (512 bytes each) */
} __packed;
```

For reads: desc 0 flags = `F_NEXT`, desc 1 flags = `F_NEXT | F_WRITE`, desc 2 = `F_WRITE`
For writes: desc 0 flags = `F_NEXT`, desc 1 flags = `F_NEXT`, desc 2 = `F_WRITE`

The driver is **polling-based** (no IRQ-driven completion) -- after submitting a request,
it busy-waits on the used ring with `spin_lock` (IRQs enabled during poll for TCG compat).

The block device registers with the block device abstraction layer (`blkdev_register()`),
which provides a uniform `blkdev_read()` / `blkdev_write()` interface used by the ext4
filesystem.

#### 10.10.2 VirtIO Network Device

Covered in detail in Chapter 9 (section 9.1). Key points:
- Device ID 1, two queues (RX=0, TX=1)
- 10-byte `virtio_net_hdr` prepended to every packet
- RX uses drain-then-ACK-then-recheck pattern for level-triggered IRQs
- TX is polling-based; deliberately does NOT ACK shared ISR to avoid clearing RX IRQs

#### 10.10.3 VirtIO Input Device

**Source**: `kernel/drivers/virtio/virtio_input.c` (959 lines)

The VirtIO input device emulates Linux `evdev` events. Kiseki probes for **two** input
devices: a **keyboard** and a **tablet** (absolute pointing device), distinguished by
querying the config space `EV_BITS`:

```
virtio_input_init()
  |
  +-- For each MMIO slot with device_id == 18 (INPUT):
  |     Write VIRTIO_INPUT_CFG_EV_BITS with subsel=EV_KEY to config space
  |     Read back: if bitmap has any KEY_* bits -> keyboard
  |     Write VIRTIO_INPUT_CFG_EV_BITS with subsel=EV_ABS to config space
  |     Read back: if bitmap has ABS_X bit -> tablet
  |
  +-- Keyboard: standard VirtIO init, eventq (queue 0), pre-post 32 buffers
  +-- Tablet: same setup on separate device
```

**Event processing** (IRQ handler):

```
virtio_input_irq_handler()
  |
  +-- Drain used ring (completed event buffers)
  |
  +-- For each event:
  |     struct virtio_input_event { type, code, value }
  |
  +-- type == EV_KEY?
  |     +-- Modifier tracking: track shift/ctrl/alt/capslock state
  |     +-- keycode_to_ascii[code] lookup (US QWERTY keymap)
  |     +-- Apply shift/capslock transformations
  |     +-- Push HID_EVENT_KEY_DOWN or KEY_UP to hid_event_ring
  |     +-- Feed character to fbconsole TTY: tty_input_char_tp()
  |
  +-- type == EV_SYN? (tablet batches ABS_X + ABS_Y + SYN)
  |     +-- Push HID_EVENT_MOUSE_MOVE with abs_x, abs_y
  |
  +-- Re-post buffer to eventq for next event
```

The keyboard driver includes a **full US QWERTY keymap** with shifted variants (e.g.,
`KEY_A` -> 'a' / 'A', `KEY_1` -> '1' / '!') and recognises escape sequences for
function keys, arrows, home/end/etc.

### 10.11 GICv2 -- The Interrupt Controller

**Source**: `kernel/drivers/gic/gicv2.c` (150 lines),
`kernel/include/drivers/gic.h` (71 lines)

#### 10.11.1 What Is the GIC?

The **Generic Interrupt Controller** (GIC) is ARM's standard interrupt controller. It
routes hardware interrupts from peripherals to CPU cores. GICv2 has two components:

```
  +-----------------+          +------------------+
  | Distributor     |          | CPU Interface    |
  | (GICD)          |          | (GICC)           |
  | 0x08000000      |          | 0x08010000       |
  |                 |          |                  |
  | - Enable/disable|          | - Acknowledge    |
  |   individual    |  ------> |   interrupt      |
  |   IRQs          |          | - Signal EOI     |
  | - Set priority  |          | - Priority mask  |
  | - Route to CPU  |          |                  |
  +-----------------+          +------------------+
```

#### 10.11.2 Interrupt Types

| Type | Range | Scope | Examples |
|------|-------|-------|---------|
| SGI (Software Generated) | 0-15 | Per-CPU, triggered by software | IPI_RESCHEDULE(0), IPI_TLB_FLUSH(1), IPI_HALT(2) |
| PPI (Private Peripheral) | 16-31 | Per-CPU, hardware | Timer(27) |
| SPI (Shared Peripheral) | 32+ | Shared, routed to any CPU | UART(33), VirtIO(48+) |

#### 10.11.3 GIC Initialisation

```
gic_init()                   -- Called once on boot CPU
  |
  +-- Disable distributor (GICD_CTLR = 0)
  +-- Set all SPIs to:
  |     - Priority 0xA0 (medium)
  |     - Target CPU 0 (route all to core 0)
  |     - Level-triggered
  |     - Disabled by default
  +-- Enable distributor (GICD_CTLR = 1)
  +-- Enable CPU interface (GICC_CTLR = 1)
  +-- Set priority mask = 0xFF (accept all priorities)

gic_init_percpu()            -- Called on each secondary CPU
  |
  +-- Enable CPU interface
  +-- Set priority mask = 0xFF
```

#### 10.11.4 Interrupt Handling Flow

When a hardware interrupt fires:

```
1. CPU takes IRQ exception -> vectors.S -> el1_irq_handler
2. gic_acknowledge() -- read GICC_IAR, returns interrupt ID
3. Dispatch by ID:
     ID < 16:        SGI (IPI) -> handle_ipi()
     ID == 27:       Timer     -> timer_handler()
     ID == 33:       UART      -> uart_irq_handler()
     ID == 48+:      VirtIO    -> virtio_*_irq_handler()
4. gic_end_of_interrupt(id) -- write GICC_EOIR
```

#### 10.11.5 Inter-Processor Interrupts (IPI)

IPIs are sent via SGIs (Software Generated Interrupts):

```c
void gic_send_sgi(uint32_t sgi_id, uint32_t target_cpu);
```

This writes to `GICD_SGIR` with the target CPU in the target list field. Used for:

| IPI | ID | Purpose | Sender |
|-----|----|---------|--------|
| `IPI_RESCHEDULE` | 0 | Wake idle CPU for work stealing | `sched_wakeup()` |
| `IPI_TLB_FLUSH` | 1 | Cross-CPU TLB invalidation | `vmm_switch_address_space()` |
| `IPI_HALT` | 2 | Stop CPU for panic/shutdown | `panic()` |

### 10.12 PL011 UART

**Source**: `kernel/drivers/uart/pl011.c` (174 lines)

The PL011 is ARM's standard UART (serial port). On QEMU virt, it is at `0x09000000`
(SPI IRQ 33). It provides the lowest-level I/O channel -- the first thing that works
during boot, before the framebuffer or any other device.

Key functions:

| Function | Purpose |
|----------|---------|
| `uart_init()` | Configure baud rate, enable FIFOs, enable RX interrupt |
| `uart_putc(c)` | Spin-wait for TX FIFO not full, write character |
| `uart_getc()` | Spin-wait for RX FIFO not empty, read character |
| `uart_irq_handler()` | Drain RX FIFO, feed each character to `tty_input_char()` |

The UART is the **primary debug output** (`kprintf()` writes here) and also serves as
the console TTY's backing device. When the fbconsole is active, output goes to both
UART and framebuffer.

### 10.13 TTY Subsystem

**Source**: `kernel/kern/tty.c` (801 lines), `kernel/include/kern/tty.h` (315 lines)

#### 10.13.1 What Is a TTY?

A TTY (teletypewriter) is the kernel's abstraction for a text I/O channel. It sits
between a **device** (UART, framebuffer, PTY) and **user processes**, providing:

- **Line discipline**: buffered editing (backspace, kill line) in canonical mode
- **Raw mode**: unbuffered character-at-a-time I/O for programs like `vi`
- **Signal generation**: Ctrl-C -> SIGINT, Ctrl-\ -> SIGQUIT, Ctrl-Z -> SIGTSTP
- **Echo**: optionally reflect typed characters back to the display
- **Output processing**: convert `\n` to `\r\n` for the terminal

#### 10.13.2 The termios Structure

```c
struct termios {                   /* tty.h:34, matches macOS arm64 layout */
    tcflag_t c_iflag;              /* Input flags (ICRNL, IGNCR, etc.) */
    tcflag_t c_oflag;              /* Output flags (OPOST, ONLCR) */
    tcflag_t c_cflag;              /* Control flags (baud, parity, etc.) */
    tcflag_t c_lflag;              /* Local flags (ICANON, ECHO, ISIG, etc.) */
    cc_t     c_cc[20];            /* Control characters (VEOF, VINTR, etc.) */
    speed_t  c_ispeed;            /* Input baud rate */
    speed_t  c_ospeed;            /* Output baud rate */
};
```

Note: `tcflag_t` is `uint64_t` on macOS arm64 (not `uint32_t` as on Linux). Kiseki
matches the macOS layout exactly so that userland headers are compatible.

Key `c_lflag` bits:

| Flag | Value | Meaning |
|------|-------|---------|
| `ECHO` | 0x00000008 | Echo input characters |
| `ECHOE` | 0x00000002 | Echo backspace as `\b \b` |
| `ECHOK` | 0x00000004 | Echo kill as newline |
| `ICANON` | 0x00000100 | Canonical (line-buffered) mode |
| `ISIG` | 0x00000080 | Generate signals (SIGINT etc.) |
| `IEXTEN` | 0x00000400 | Extended processing |
| `NOFLSH` | 0x80000000 | Don't flush after signal |

Key control characters (`c_cc` indices):

| Index | Name | Default | Meaning |
|-------|------|---------|---------|
| 0 | `VEOF` | Ctrl-D | End of file |
| 8 | `VINTR` | Ctrl-C | Generate SIGINT |
| 9 | `VQUIT` | Ctrl-\ | Generate SIGQUIT |
| 10 | `VSUSP` | Ctrl-Z | Generate SIGTSTP |
| 3 | `VERASE` | DEL(0x7F) | Erase one character |
| 5 | `VKILL` | Ctrl-U | Kill entire line |
| 14 | `VWERASE` | Ctrl-W | Erase one word |

#### 10.13.3 The TTY Structure

```c
struct tty {                       /* tty.h:194 */
    struct termios t_termios;      /* Current terminal settings */
    struct winsize t_winsize;      /* Window size (rows x cols) */
    pid_t t_pgrp;                  /* Foreground process group */
    pid_t t_session;               /* Session leader PID */
    uint32_t t_flags;              /* TTY_OPENED, TTY_CTTY */
    void (*t_putc)(char c);        /* Output function (device-specific) */
    void *t_devprivate;            /* Device-specific private data */
    char t_linebuf[1024];          /* Canonical mode line buffer */
    int t_linepos;                 /* Current position in line buffer */
    int t_lineout;                 /* Read position for user reads */
    char t_rawbuf[256];            /* Raw mode ring buffer */
    int t_rawhead, t_rawtail, t_rawcount;
};
```

#### 10.13.4 Canonical vs Raw Mode

**Canonical mode** (`ICANON` set -- default):
- Characters are buffered in `t_linebuf` until newline or EOF
- Backspace (`VERASE`) deletes the last character (with `\b \b` echo if `ECHOE`)
- Kill (`VKILL`) discards the entire line
- Word-erase (`VWERASE`) deletes back to the last space
- `tty_read()` blocks (via `thread_sleep_on()`) until a complete line is available

**Raw mode** (`ICANON` clear):
- Characters are delivered immediately to `t_rawbuf` ring
- No editing (backspace is just another character)
- `tty_read()` returns as soon as `VMIN` characters are available or `VTIME` expires

#### 10.13.5 Signal Generation

When `ISIG` is set and a control character is typed:

| Character | Signal | Default Action |
|-----------|--------|----------------|
| `VINTR` (Ctrl-C) | `SIGINT` | Terminate process |
| `VQUIT` (Ctrl-\) | `SIGQUIT` | Terminate + core dump |
| `VSUSP` (Ctrl-Z) | `SIGTSTP` | Stop (suspend) process |

The signal is sent to the **foreground process group** (`t_pgrp`) via `kill_pg()`.

### 10.14 Pseudo-Terminals (PTY)

**Source**: `kernel/kern/pty.c` (604 lines), `kernel/include/kern/pty.h` (158 lines)

#### 10.14.1 What Is a PTY?

A **pseudo-terminal** is a pair of virtual devices that emulate a serial connection:

```
  +-----------+                    +-----------+
  | Terminal  |  <-- user I/O -->  | Shell/App |
  | Emulator  |                    |           |
  | (master)  |                    | (slave)   |
  +-----+-----+                    +-----+-----+
        |                                |
  master fd                         slave fd
        |                                |
        v                                v
  +-----+-------------------------------+-----+
  |           PTY Pair (kernel)               |
  |                                           |
  |  m2s ring buf (4096B)  --->  slave TTY    |
  |  (master write -> slave read)             |
  |                                           |
  |  s2m ring buf (4096B)  <---  slave TTY    |
  |  (slave write -> master read)             |
  +-------------------------------------------+
```

The **Terminal.app** opens the master side, the **shell** runs on the slave side.
Characters typed by the user flow: Terminal -> master write -> m2s buffer -> slave
read. Characters output by the shell flow: slave write -> s2m buffer -> master read ->
Terminal displays them.

#### 10.14.2 PTY Data Structure

```c
struct pty {                       /* pty.h:39 */
    bool pt_active;                /* Pair is allocated */
    int pt_index;                  /* PTY number (0-15) */
    struct tty pt_slave_tty;       /* Full TTY with line discipline */

    /* Master -> Slave ring buffer */
    uint8_t pt_m2s[4096];
    uint32_t pt_m2s_head, pt_m2s_tail, pt_m2s_count;
    spinlock_t pt_m2s_lock;

    /* Slave -> Master ring buffer */
    uint8_t pt_s2m[4096];
    uint32_t pt_s2m_head, pt_s2m_tail, pt_s2m_count;
    spinlock_t pt_s2m_lock;

    int pt_master_open;            /* Master open count */
    int pt_slave_open;             /* Slave open count */
};
```

Kiseki has a pool of **16 PTY pairs** (`PTY_MAX = 16`). The slave side has a full
`struct tty` with line discipline, so canonical mode editing (backspace, kill, etc.)
works through the PTY just as it does through the console.

#### 10.14.3 PTY Operations

| Function | Direction | Description |
|----------|-----------|-------------|
| `pty_master_write()` | Terminal -> Shell | Write to m2s ring, feed to slave TTY's `tty_input_char_tp()` |
| `pty_slave_read()` | Shell reads | Sleep on `&pp->pt_m2s_count` until data available in m2s |
| `pty_slave_write()` | Shell -> Terminal | Process through slave TTY's OPOST (e.g., `\n` -> `\r\n`), write to s2m |
| `pty_master_read()` | Terminal reads | Sleep on `&pp->pt_s2m_count` until data available in s2m |

### 10.15 Framebuffer Console

**Source**: `kernel/kern/fbconsole.c` (1,116 lines)

The framebuffer console renders text onto the GPU framebuffer using an embedded 8x16
bitmap font. It is the kernel's primary visual output before the WindowServer starts.

#### 10.15.1 Architecture

```
  kprintf("Hello")
       |
       v
  fbconsole_putc('H')
       |
       +-- VT100/ANSI escape sequence parser
       |     Handles: cursor movement (\e[A/B/C/D), erase (\e[J/K),
       |     SGR colours (\e[31m), DEC private modes (\e[?25h cursor show)
       |
       +-- Render glyph from font8x16[] bitmap
       |     Each character: 16 bytes (16 rows of 8 pixels)
       |     Write 32-bit ARGB pixels directly to VRAM
       |
       +-- Dirty region tracking
       |     Track bounding box of modified cells
       |     virtio_gpu_flush() only the dirty region
       |
       +-- Scroll: memmove entire framebuffer up by font_height pixels
```

#### 10.15.2 VT100/ANSI Support

The fbconsole parses VT100/ANSI escape sequences for full terminal emulation:

| Sequence | Action |
|----------|--------|
| `\e[nA` | Cursor up n lines |
| `\e[nB` | Cursor down n lines |
| `\e[nC` | Cursor forward n columns |
| `\e[nD` | Cursor backward n columns |
| `\e[H` | Cursor to home (0,0) |
| `\e[n;mH` | Cursor to row n, column m |
| `\e[J` | Erase from cursor to end of screen |
| `\e[2J` | Erase entire screen |
| `\e[K` | Erase from cursor to end of line |
| `\e[nm` | SGR: set text attributes (30-37 = fg colour, 40-47 = bg colour, 0 = reset) |
| `\e[?25h` | Show cursor |
| `\e[?25l` | Hide cursor |
| `\e[s` | Save cursor position |
| `\e[u` | Restore cursor position |

ANSI colour palette (8 colours):

```
  30/40: Black     31/41: Red       32/42: Green    33/43: Yellow
  34/44: Blue      35/45: Magenta   36/46: Cyan     37/47: White
```

#### 10.15.3 Disable/Enable for WindowServer

When the WindowServer opens the IOFramebuffer user client:
- `fbconsole_disable()` -- stops rendering to framebuffer (but continues to serial)
- The WindowServer now owns the framebuffer and draws its own content

When the WindowServer exits (or crashes):
- `fbconsole_enable()` -- resumes framebuffer rendering, redraws screen

### 10.16 Comparison with XNU/macOS IOKit

| Feature | Kiseki | macOS/XNU |
|---------|--------|-----------|
| Language | C (struct embedding + vtables) | C++ (libkern classes) |
| Object allocation | Static pools | Zone-based `OSObject::operator new` |
| Properties | Flat 64-entry array | `OSDictionary` with hash table |
| Matching | Linear catalogue scan | `IOCatalogue` with personality dictionaries |
| Work loops | Kernel thread + event chain | `IOWorkLoop` (same pattern, C++ API) |
| User client | External method dispatch table | Same (`IOExternalMethodDispatch`) |
| Memory mapping | `vmm_map_page()` direct | `IOMemoryDescriptor::createMappingInTask()` |
| Mach integration | MIG-style message IDs (2800-2873) | Same message ID range |
| Master port | `"uk.co.avltree9798.iokit"` | `kIOMasterPortDefault` |
| Kobject types | `IKOT_IOKIT_OBJECT/CONNECT/MASTER_DEVICE` | Same (identical values) |
| Error codes | `kIOReturn*` values match XNU | `<IOKit/IOReturn.h>` |

---

## Chapter 11: Userland -- dyld, libSystem, crt0

Every user process in Kiseki starts the same way: the kernel maps the Mach-O executable
into memory, maps the dynamic linker (`/usr/lib/dyld`), and jumps to dyld's entry point.
dyld resolves all dynamic library dependencies, patches relocations, runs initialisers,
and finally calls `main()`. This chapter covers that entire pipeline, plus the C library
(`libSystem.B.dylib`) that provides POSIX and Mach APIs to every program.

### 11.1 The Mach-O Binary Format

Mach-O (Mach Object) is the binary format used by macOS, iOS, and Kiseki. Every
executable, dylib, and the dynamic linker itself are Mach-O files.

#### 11.1.1 File Structure

```
  +---------------------------+
  | Mach-O Header (32 bytes)  |   magic, cputype, filetype, ncmds
  +---------------------------+
  | Load Command 1            |   LC_SEGMENT_64 "__TEXT"
  | Load Command 2            |   LC_SEGMENT_64 "__DATA"
  | Load Command 3            |   LC_SEGMENT_64 "__LINKEDIT"
  | Load Command 4            |   LC_LOAD_DYLIB "/usr/lib/libSystem.B.dylib"
  | Load Command 5            |   LC_DYLD_INFO_ONLY (or LC_DYLD_CHAINED_FIXUPS)
  | Load Command 6            |   LC_SYMTAB
  | Load Command 7            |   LC_MAIN
  | ...                       |
  +---------------------------+
  | __TEXT Segment             |   Code, string constants, export trie
  +---------------------------+
  | __DATA Segment             |   Global variables, GOT, lazy pointers
  +---------------------------+
  | __LINKEDIT Segment         |   Symbol table, string table, fixup opcodes
  +---------------------------+
```

The **Mach-O header** (`dyld.c:262`):

```c
struct mach_header_64 {
    uint32_t magic;         /* 0xFEEDFACF (MH_MAGIC_64) */
    uint32_t cputype;       /* CPU_TYPE_ARM64 (0x0100000C) */
    uint32_t cpusubtype;
    uint32_t filetype;      /* MH_EXECUTE=2, MH_DYLIB=6, MH_DYLINKER=7 */
    uint32_t ncmds;         /* Number of load commands */
    uint32_t sizeofcmds;    /* Total size of load commands */
    uint32_t flags;         /* MH_PIE = 0x00200000 */
    uint32_t reserved;
};
```

#### 11.1.2 Key Load Commands

| Command | ID | Purpose |
|---------|------|---------|
| `LC_SEGMENT_64` | 0x19 | Maps a segment (text, data, etc.) into memory |
| `LC_LOAD_DYLIB` | 0x0C | Names a required dynamic library |
| `LC_MAIN` | 0x80000028 | Specifies offset of `main()` from `__TEXT` base |
| `LC_SYMTAB` | 0x02 | Location of symbol + string tables |
| `LC_DYLD_INFO_ONLY` | 0x80000022 | Rebase/bind/lazy-bind/export opcode streams |
| `LC_DYLD_CHAINED_FIXUPS` | 0x80000034 | Modern chained fixup format |
| `LC_DYLD_EXPORTS_TRIE` | 0x80000033 | Compressed export symbol trie |

### 11.2 dyld -- The Dynamic Linker

**Source**: `userland/dyld/dyld.c` (2,438 lines), `userland/dyld/start.S` (110 lines)

dyld is a fully **freestanding** program -- it defines its own types, its own syscall
wrappers, its own string functions, and its own Mach-O parser. It has zero library
dependencies. It is compiled as an `MH_DYLINKER` binary.

#### 11.2.1 The Boot-to-main() Pipeline

```
  Kernel (proc.c: execve)
       |
       | Maps main binary's segments into user address space
       | Maps /usr/lib/dyld into user address space
       | Pushes stack: [mach_header_ptr, argc, argv[], 0, envp[], 0, apple[], 0]
       | Sets ELR_EL1 = dyld's _start (from LC_UNIXTHREAD)
       |
       v
  dyld/start.S :: _start
       |
       | Extract: x0=mach_header, x1=argc, x2=argv, x3=envp, x4=apple
       |
       v
  dyld/dyld.c :: dyld_main()          [line 1947]
       |
       | Phase 1: Parse main binary
       |   - Validate MH_MAGIC_64 and MH_EXECUTE
       |   - Compute ASLR slide = (runtime addr) - (linked vmaddr of __TEXT)
       |   - Walk all load commands, extract segment/symbol/fixup info
       |
       | Phase 2: Load required dylibs
       |   - For each LC_LOAD_DYLIB: load_dylib(path)
       |   - read_file() reads entire Mach-O from disk
       |   - mmap anonymous region, copy segments, compute slide
       |   - Recursively load transitive dependencies
       |
       | Phase 3: Process fixups (for main binary AND all dylibs)
       |   - If LC_DYLD_CHAINED_FIXUPS: process_chained_fixups()
       |   - Else if LC_DYLD_INFO_ONLY:
       |       process_rebases()      -- slide internal pointers
       |       process_all_binds()    -- resolve external symbols
       |
       | Phase 4: Patch GOT
       |   - Fill any remaining zero slots with dyld_stub_binder trap
       |
       | Phase 5: Set environ
       |   - Find "_environ" symbol in loaded images, write envp pointer
       |
       | Phase 5.5: Run initialisers (__mod_init_func)
       |   - Bottom-up: dependencies first, then main binary
       |   - Calls ObjC +load, __attribute__((constructor)), CF type registration
       |
       | Phase 6: Jump to main()
       |   - entry = text_base + LC_MAIN.entryoff
       |   - Call entry(argc, argv, envp, apple)
       |   - On return: look up _exit, call it (flushes stdio)
       |
       v
  Application :: main(argc, argv, envp)
```

#### 11.2.2 ASLR Slide Computation

The kernel can load a PIE (Position-Independent Executable) at any address. dyld
computes the **slide** -- the difference between where the binary was linked and where
it actually landed:

```
slide = (uint64_t)main_mh - __TEXT_segment.vmaddr
```

Every internal pointer in the binary was computed at link time assuming `__TEXT` starts
at its linked `vmaddr`. The slide is added to each pointer during rebase processing.

#### 11.2.3 Symbol Resolution

`resolve_symbol()` (`dyld.c:1010`) resolves an external symbol name using a priority
order:

1. **Special case**: `dyld_stub_binder` -> return the assembly trap address
2. **Ordinal-based targeted lookup** (ordinal > 0): search the specific dylib indicated
   by the ordinal. Try the **export trie** first (fast, O(symbol-length)), then fall back
   to **nlist linear scan** (slow, O(n))
3. **Flat namespace fallback**: search all loaded images in order

**Ordinal semantics**: in Mach-O, each `LC_LOAD_DYLIB` is numbered 1, 2, 3, ... in order.
When a bind opcode says "ordinal 2", it means "look in the 2nd LC_LOAD_DYLIB".

#### 11.2.4 The Export Trie

The export trie is a **compressed prefix trie** stored in `__LINKEDIT`. It encodes all
exported symbols with their addresses. Walking the trie for symbol `_printf`:

```
  Root node
    |
    +-- "_" --> child node
                  |
                  +-- "p" --> child node
                                |
                                +-- "rintf" --> TERMINAL: flags=0, addr=0x1234
                                |
                                +-- "uts" --> TERMINAL: flags=0, addr=0x5678
```

Each node: `[term_size: ULEB128] [if terminal: flags, addr] [child_count] [for each:
edge_label\0, child_offset: ULEB128]`. The algorithm (`dyld.c:906`) matches the symbol
character by character, descending through children until it reaches a terminal node or
fails.

#### 11.2.5 Chained Fixups

Modern Mach-O binaries use **chained fixups** (`LC_DYLD_CHAINED_FIXUPS`) instead of
separate rebase/bind opcode streams. In this format, each pointer in `__DATA` is
**overwritten at link time** with a packed value that encodes:

- Bit 63: 0 = rebase, 1 = bind
- For **rebase**: bits[0:35] = target address (or offset), bits[36:43] = high8,
  bits[44:51] = next pointer delta (in 4-byte units)
- For **bind**: bits[0:23] = import ordinal, bits[24:31] = addend,
  bits[52:62] = next pointer delta

dyld walks each page's chain (linked list via the `next` field), fixing up each pointer
in place. Chain terminates when `next == 0`.

#### 11.2.6 Eager Lazy Binding

Kiseki dyld **eagerly resolves ALL symbols at load time**, including lazy bindings. There
is no runtime lazy resolution -- the `dyld_stub_binder` function is defined in `start.S`
as a trap that calls `dyld_fatal()`. This simplifies the design at the cost of slightly
longer startup times.

### 11.3 libSystem.B.dylib -- The C Library

**Source**: `userland/libsystem/libSystem.c` (7,948 lines)

Kiseki's C library is a **single monolithic file** that provides the complete POSIX C
standard library, Mach IPC wrappers, POSIX threads, the Objective-C ABI support layer,
and more -- roughly 280 exported functions.

#### 11.3.1 Syscall Interface

All system calls go through a single inline assembly function (`libSystem.c:189`):

```c
static long __syscall(long number, long a0, long a1, long a2,
                      long a3, long a4, long a5) {
    register long x16 __asm__("x16") = number;
    register long x0 __asm__("x0") = a0;
    /* ... x1-x5 ... */
    __asm__ volatile("svc #0x80"
        : "+r"(x0) : "r"(x16), "r"(x1), "r"(x2),
          "r"(x3), "r"(x4), "r"(x5) : "memory", "cc");
    /* Check carry flag for error */
    unsigned long flags;
    __asm__ volatile("mrs %0, nzcv" : "=r"(flags));
    if (flags & (1UL << 29))  /* Carry set = error */
        return -x0;           /* Return negative errno */
    return x0;
}
```

This matches the macOS ARM64 syscall convention exactly: `x16` = syscall number,
`x0`-`x5` = arguments, `svc #0x80` traps to kernel. On error, the kernel sets PSTATE
carry flag and `x0` = positive errno.

#### 11.3.2 Per-Thread errno

errno is **per-thread** using the ARM64 `TPIDR_EL0` register. Each `struct __pthread`
has `errno_val` at offset 60. The `__error()` function (`libSystem.c:262`) reads
`TPIDR_EL0` to find the current thread's pthread struct and returns `&pt->errno_val`.
Falls back to a global `_errno_fallback` during early boot before threads are set up.

#### 11.3.3 malloc -- Free-List Allocator

```c
typedef struct block_header {       /* libSystem.c:754 */
    size_t              size;       /* Usable payload size */
    struct block_header *next;      /* Next in free-list */
    uint32_t            magic;      /* 0xA110CA7E ("ALLOCATE") */
    uint32_t            free;       /* 1 = free, 0 = allocated */
    uint64_t            _pad;       /* Pad to 32 bytes */
} block_header_t;
```

**Algorithm**:
- **Backend**: `mmap(MAP_PRIVATE | MAP_ANON)` in 64 KB minimum chunks
- **Allocation**: first-fit search of the free-list. If no fit, mmap a new chunk.
  Split the block if the remainder >= 48 bytes (header + 16 min)
- **Free**: validate the magic cookie (`0xA110CA7E`), mark as free, coalesce adjacent
  free blocks (only if physically contiguous -- prevents cross-mmap corruption)
- **Realloc**: in-place if the block is large enough, or try merging with the next free
  block, else malloc+copy+free
- All allocations are 16-byte aligned (ARM64 requirement)

#### 11.3.4 stdio -- FILE-Based I/O

```c
typedef struct _kiseki_FILE {       /* libSystem.c:1105 */
    int     fd;                     /* Underlying file descriptor */
    int     flags;                  /* _F_READ, _F_WRITE, _F_UNBUF, etc. */
    char    *buf;                   /* I/O buffer (1024 bytes) */
    size_t  bufsiz;                 /* Buffer capacity */
    size_t  buf_pos;                /* Write position */
    size_t  buf_len;                /* Valid read bytes */
    int     ungetc_buf;             /* Single ungetc character (or EOF) */
} FILE;
```

Standard streams: `stdin` (fd 0, line-buffered), `stdout` (fd 1, line-buffered),
`stderr` (fd 2, unbuffered). Up to 64 FILE objects in a static table.

The **printf engine** (`libSystem.c:1573`) uses a callback-based design: `_fmt_core()`
parses the format string and calls a `putch` callback for each output character. This
lets the same parser drive `fprintf` (to FILE), `sprintf` (to string), and `dprintf`
(to fd) with different callbacks.

Supported format specifiers: `%d`, `%i`, `%u`, `%x`, `%X`, `%o`, `%p`, `%s`, `%c`,
`%%`, `%n`, with all standard flags (`-`, `0`, `+`, ` `, `#`), width, precision, and
length modifiers (`h`, `hh`, `l`, `ll`, `z`, `j`, `t`).

#### 11.3.5 POSIX Threads (pthreads)

```c
struct __pthread {                  /* libSystem.c:5974 */
    unsigned long tid;              /* Kernel thread ID */
    void *stack_base;               /* mmap'd 2 MB stack */
    size_t stack_size;
    void *(*start_routine)(void *);
    void *arg;
    void *retval;
    int   detached, joined, exited;
    int   errno_val;                /* Per-thread errno (offset 60) */
    void *tls[128];                 /* Thread-local storage keys */
    struct __pthread *joiner;       /* Thread waiting to join */
};
```

- `pthread_create()` (`libSystem.c:6100`): mmaps a 2 MB stack, calls
  `SYS_bsdthread_create` (360) which creates a kernel thread
- Mutexes: spinlock-based with support for NORMAL, RECURSIVE, and ERRORCHECK types
- Condition variables: busy-wait on `signal_count` with mutex unlock/relock
- Read-write locks: reader/writer counting with spinlock protection
- Thread-local storage: 128 keys with destructor support

#### 11.3.6 Mach IPC Wrappers

libSystem provides the userland Mach API used by all framework code:

```c
/* Mach traps use negative x16 values */
kern_return_t mach_msg(msg, option, send_size, rcv_size,
                       rcv_name, timeout, notify);    /* trap -31 */
mach_port_t mach_task_self(void);                     /* trap -28, cached */
mach_port_t mach_reply_port(void);                    /* trap -26 */
kern_return_t mach_port_allocate(task, right, name);  /* trap -36 */
kern_return_t mach_port_deallocate(task, name);       /* trap -37 */
```

The `mach_msg()` wrapper (`libSystem.c:7226`) retries on `MACH_SEND_INTERRUPTED` and
`MACH_RCV_INTERRUPTED`, making it robust against signal delivery during IPC.

**Bootstrap services**:

```c
kern_return_t bootstrap_register(bp, service_name, sp);  /* trap -40 */
kern_return_t bootstrap_look_up(bp, service_name, sp);   /* trap -41 */
kern_return_t bootstrap_check_in(bp, service_name, sp);  /* trap -42 */
```

#### 11.3.7 DNS Resolution via Mach IPC

`getaddrinfo()` (`libSystem.c:7612`) resolves hostnames by:
1. Trying numeric parse first (`inet_pton`)
2. Sending a Mach message to the mDNSResponder service
   (`"uk.co.avltree9798.mDNSResponder"`, message ID 1000)
3. The reply contains up to 8 IPv4 addresses
4. Each address is wrapped in a `struct addrinfo` chain

#### 11.3.8 C++ ABI Support

libSystem provides the C++ ABI symbols that clang expects, even though Kiseki apps
are primarily C and Objective-C:

- `operator new`/`delete` (mangled `_Znwm`/`_ZdlPv`) -- delegate to malloc/free
- `__cxa_atexit` / `__cxa_guard_acquire/release` -- static local initialisation
- `__cxa_throw` -- aborts (no exception unwinding support)
- `__gxx_personality_v0`, `_Unwind_*` -- stubs that abort

#### 11.3.9 Summary of Major Subsystems

| Subsystem | Functions | Lines | Notes |
|-----------|-----------|-------|-------|
| String/memory | 22+ (strlen, strcmp, memcpy, ...) | 314-560 | Word-aligned fast paths |
| malloc | malloc, free, realloc, calloc | 743-969 | Free-list, 0xA110CA7E magic |
| stdio | 35+ (fopen, fprintf, fgets, ...) | 1091-1600 | Callback-based printf engine |
| Process control | fork, exec*, wait*, kill | 654-741 | Full exec family (execvp, execl, ...) |
| Filesystem | 30+ (open, stat, mkdir, ...) | 562-651, 3367-3483 | All via BSD syscalls |
| Network | 18+ (socket, connect, send, ...) | 4026-4232 | Plus getaddrinfo via Mach IPC |
| Signals | signal, sigaction, raise | 2463-2509 | Per-process handlers |
| Time | 20+ (time, gmtime, strftime, ...) | 4234-5398 | Full UTC conversion |
| pthreads | 45+ (create, mutex, cond, rwlock) | 5962-7022 | 2 MB stack per thread |
| Mach IPC | 10 traps + bootstrap | 7079-7355 | mach_msg with retry |
| ctype | 12 + RuneLocale | 2093-2281 | macOS ABI compatible |
| C++ ABI | 20+ symbols | 2617-2873 | new/delete, guards, unwind stubs |
| Math | 25 (sin, cos, sqrt, log, ...) | 7733-7943 | Taylor series / Newton-Raphson |
| termcap | tgetent, tgoto, tputs | 4540-4725 | Hardcoded VT100 |

### 11.4 crt0 and Program Startup

**Source**: `userland/libsystem/crt0.S` (61 lines)

`crt0.S` is the C runtime startup file linked into every executable. It provides
`_start`, the very first function called in a new process.

#### 11.4.1 Stack Layout on Entry

When the kernel creates a process, it pushes the following onto the user stack:

```
  High address
  +------------------+
  | apple[N]         |   (Apple-specific strings)
  | ...              |
  | apple[0]         |
  | NULL             |   (apple terminator)
  | envp[N]          |   (environment strings)
  | ...              |
  | envp[0]          |
  | NULL             |   (envp terminator)
  | argv[argc-1]     |
  | ...              |
  | argv[0]          |   (program name)
  | argc             |   <-- SP points here
  +------------------+
  Low address
```

#### 11.4.2 The _start Sequence

```asm
_start:
    mov  x29, #0            ; Clear frame pointer (clean backtrace end)
    mov  x30, #0            ; Clear link register

    ldr  x0, [sp]           ; x0 = argc
    add  x1, sp, #8         ; x1 = argv

    add  x2, x0, #1         ; x2 = argc + 1
    lsl  x2, x2, #3         ;    * 8 (pointer size)
    add  x2, x1, x2         ; x2 = envp = argv + (argc+1)*8

    adrp x3, environ         ; Store envp in global 'environ'
    str  x2, [x3, :lo12:environ]

    and  sp, sp, #~0xF       ; Align stack to 16 bytes (ARM64 ABI)

    bl   main                ; Call main(argc, argv, envp)
    bl   exit                ; Call exit(return_value)

    mov  x16, #1             ; SYS_exit fallback
    svc  #0x80
```

The key steps before `main()`:
1. **FP/LR cleared** -- ensures stack unwinders terminate cleanly
2. **envp computed** by walking past argv's NULL terminator
3. **`environ` global set** -- used by `getenv()`/`setenv()`
4. **Stack 16-byte aligned** -- ARM64 ABI requirement
5. After main returns, `exit()` runs atexit handlers and flushes stdio

### 11.5 The Objective-C Runtime (libobjc)

Kiseki's Objective-C runtime is covered in Chapter 13 (Framework Stack), as it is
tightly integrated with Foundation and AppKit. The key point for this chapter: the
runtime is minimal -- it supports `objc_msgSend`, class registration, method addition,
and selector lookup, but does **not** support categories, protocols, associated objects,
or the full Apple runtime ABI.

---

## Chapter 12: WindowServer & GUI Architecture

Kiseki's graphical desktop is orchestrated by a single user-space process called
**WindowServer** -- the direct equivalent of macOS's `WindowServer` (historically
known as the Quartz Compositor, now SkyLight). Every pixel on screen passes through
this process: it owns the framebuffer, receives raw HID events from the kernel,
composites windows in z-order, and dispatches input events to the correct client
application via Mach IPC.

```
+------------------------------------------------------------------+
|                       User's Screen                              |
|  +------------------------------------------------------------+  |
|  | Menu Bar  [ KisekiOS   File  Edit  View ]       [ 10:42 ]  |  |
|  +------------------------------------------------------------+  |
|  |                                                            |  |
|  |  +--Window A (Finder)------+  +--Window B (Terminal)----+  |  |
|  |  | Title Bar          [X]  |  | Title Bar         [X]  |  |  |
|  |  |--------------------------+  |------------------------+  |  |
|  |  |  content (backing store) |  | content (backing store)|  |  |
|  |  |                          |  |                        |  |  |
|  |  +--------------------------+  +------------------------+  |  |
|  |                                                            |  |
|  |                    Desktop Background                      |  |
|  +------------------------------------------------------------+  |
|                            cursor ^                              |
+------------------------------------------------------------------+
           |                |                |
           v                v                v
    +------------+   +------------+   +------------+
    | IOFrame-   |   | IOHIDSystem|   | Mach IPC   |
    | buffer     |   | event ring |   | to clients |
    | (VRAM map) |   | (shared)   |   | (ports)    |
    +------------+   +------------+   +------------+
           |                |
           v                v
    +------------------------------+
    |     Kernel (IOKit drivers)   |
    | VirtIO GPU    VirtIO Input   |
    +------------------------------+
```

### 12.1 WindowServer Overview

**Source**: `userland/sbin/WindowServer.c` (1,854 lines)

WindowServer is a standard Mach-O user-space binary launched by `init` (PID 1) via a
LaunchDaemon plist. It runs as root and is the first GUI process to start. Its
responsibilities:

| Responsibility | How |
|---|---|
| Framebuffer access | IOKit: `IOServiceOpen("IOFramebuffer")` then `IOConnectMapMemory64` maps VRAM |
| HID input | IOKit: `IOServiceOpen("IOHIDSystem")` then `IOConnectMapMemory64` maps the event ring |
| Client connections | Mach service port `"uk.co.avltree9798.WindowServer"` registered at bootstrap |
| Window management | Up to 64 windows (`struct ws_window`), 16 clients (`struct ws_client`) |
| Compositing | Painter's algorithm: desktop fill, then windows back-to-front, then menu bar, then cursor |
| Event routing | HID ring events translated and forwarded to the key window's client via Mach IPC |

**Boot sequence**:

```
main()
  |
  +-> signal(SIGPIPE, SIG_IGN)        -- ignore broken pipe (client disconnect)
  +-> bootstrap_check_in(WS_SERVICE_NAME)  -- claim pre-created Mach port
  |     or allocate + bootstrap_register() as fallback
  +-> open_framebuffer()               -- IOKit: find + open + getinfo + map VRAM
  +-> open_hid()                       -- IOKit: find + open + map HID event ring
  +-> cur_x = fb_w/2; cur_y = fb_h/2  -- initial cursor at screen centre
  +-> composite() + cursor_draw() + flush_fb()  -- paint initial desktop
  +-> event loop (forever)
        |
        +-> drain IPC messages (non-blocking poll, timeout=0)
        +-> cursor_restore() + process_hid()
        +-> composite() if dirty
        +-> cursor_save() + cursor_draw()
        +-> flush_fb() if any work done
        +-> if idle: blocking receive with 50ms timeout (yield CPU)
```

**Comparison with macOS**: On macOS, WindowServer is `/System/Library/PrivateFrameworks/SkyLight.framework`
linked into a thin host binary. It uses IOKit for framebuffer access (IOFramebuffer)
and HID access (IOHIDSystem) -- exactly what Kiseki does. The major difference: macOS
WindowServer uses hardware-accelerated compositing (Metal/OpenGL) and Core Animation
layers, while Kiseki composites entirely in software with direct pixel blitting.

### 12.2 The IPC Protocol

WindowServer uses a custom Mach IPC protocol with three message families:

| Family | Direction | ID Range | Purpose |
|---|---|---|---|
| Requests | Client --> Server | 1000-1099 | Create/destroy windows, draw pixels, set menus |
| Replies | Server --> Client | 2000-2099 | Synchronous responses to requests |
| Events | Server --> Client | 3000-3099 | Asynchronous input events (keys, mouse, window state) |

#### Client-to-Server Messages

```
ID      Name                Struct                      Description
----    ----                ------                      -----------
1000    CONNECT             ws_msg_connect_t            Register as client
1001    DISCONNECT          ws_msg_destroy_window_t     Disconnect, destroy all windows
1010    CREATE_WINDOW        ws_msg_create_window_t      Create window with position/size/style
1011    DESTROY_WINDOW       ws_msg_destroy_window_t     Destroy one window
1012    ORDER_WINDOW         ws_msg_order_window_t       Change visibility/z-order
1013    SET_TITLE            ws_msg_set_title_t          Change window title
1014    SET_FRAME            ws_msg_set_frame_t          Move/resize window
1020    DRAW_RECT            ws_msg_draw_rect_t          Blit pixels (OOL Mach msg)
1030    SET_MENU             ws_msg_set_menu_t           Set menu bar items
```

#### Server-to-Client Events

```
ID      Name                    Struct              Description
----    ----                    ------              -----------
3000    KEY_DOWN                ws_event_key_t      Key press (keycode + ASCII + modifiers)
3001    KEY_UP                  ws_event_key_t      Key release
3010    MOUSE_DOWN              ws_event_mouse_t    Mouse button press
3011    MOUSE_UP                ws_event_mouse_t    Mouse button release
3012    MOUSE_MOVED             ws_event_mouse_t    Cursor moved (no button)
3013    MOUSE_DRAGGED           ws_event_mouse_t    Cursor moved while button down
3020    WINDOW_ACTIVATE         ws_event_window_t   Window became key (focused)
3021    WINDOW_DEACTIVATE       ws_event_window_t   Window lost key status
3022    WINDOW_CLOSE            ws_event_window_t   Close button clicked
3023    WINDOW_RESIZE           ws_event_window_t   Window resized
3030    SCROLL                  ws_event_scroll_t   Scroll wheel event
```

#### Connection Handshake

The CONNECT message establishes a client-server relationship. The client sends its
application name and PID. Crucially, the client's **event port** is passed as the
Mach message's `msgh_local_port` with `MACH_MSG_TYPE_MAKE_SEND` -- this gives
WindowServer a send right to push events back to the client:

```
Client (e.g., Finder.app)                    WindowServer
  |                                              |
  |  [1] bootstrap_look_up("...WindowServer")    |
  |--------------------------------------------->|
  |  [2] mach_port_allocate(RECEIVE) -> event_port
  |                                              |
  |  [3] WS_MSG_CONNECT (SEND|RCV)              |
  |  msgh_remote_port = service_port             |
  |  msgh_local_port  = event_port               |
  |  msgh_id = 1000                              |
  |  body: { app_name="Finder", pid=42 }         |
  |--------------------------------------------->|
  |                                              | [4] alloc ws_client slot
  |                                              |     save event_port
  |                                              |     assign conn_id
  |                                              |
  |  [5] WS_REPLY_CONNECT                       |
  |  { conn_id=3, result=KERN_SUCCESS }          |
  |<---------------------------------------------|
  |                                              |
  | (Client now uses conn_id=3 for all requests) |
  | (Server sends events to event_port)          |
```

Key implementation detail (`WindowServer.c:886`): After kernel `copyout`, Mach ports
are swapped per XNU convention -- `msgh_remote_port` on receive becomes the sender's
reply port (the client's event port). WindowServer saves this as `c->event_port` for
all future event delivery.

#### DRAW_RECT -- The Pixel Blit Path

The most complex message is DRAW_RECT, which transfers pixel data using Mach OOL
(out-of-line) memory. This avoids copying pixel data inline in the message body:

```c
/* WindowServer.c:144-153 -- OOL draw message */
typedef struct {
    mach_msg_header_t           header;
    mach_msg_body_t             body;           /* complex message marker */
    mach_msg_ool_descriptor_t   surface_desc;   /* pixel data descriptor */
    int32_t                     conn_id;
    int32_t                     window_id;
    uint32_t                    dst_x, dst_y;   /* dest offset in window */
    uint32_t                    width, height;  /* blit dimensions */
    uint32_t                    src_rowbytes;   /* source pitch in bytes */
} ws_msg_draw_rect_t;
```

When the kernel delivers this message, it maps the OOL pages into WindowServer's
address space. WindowServer then copies pixels from the mapped region into the
window's backing store (`WindowServer.c:1210-1214`):

```c
for (uint32_t row = 0; row < bh; row++) {
    const uint32_t *srow = src_pixels + row * src_stride;
    uint32_t *drow = w->backing + (dy + row) * w->backing_stride + dx;
    memcpy(drow, srow, bw * sizeof(uint32_t));
}
```

After the copy, the OOL memory is freed via `munmap()` (`WindowServer.c:1156-1166`)
to prevent leaking mapped pages on every draw.

**Pixel format**: All pixels are BGRA 32bpp (VirtIO GPU `B8G8R8X8_UNORM`), matching
the framebuffer format. The `rgb()` helper packs bytes as
`B | (G << 8) | (R << 16) | (0xFF << 24)`.

### 12.3 Window Compositing

#### Data Structures

Each window has a **backing store** -- a heap-allocated pixel buffer that clients
draw into via DRAW_RECT:

```c
/* WindowServer.c:387-402 */
struct ws_window {
    bool            active;
    int32_t         window_id;
    int32_t         conn_id;        /* owning client */
    int32_t         x, y;           /* screen position of content area */
    uint32_t        width, height;  /* content dimensions */
    uint32_t        style_mask;     /* WS_STYLE_TITLED | WS_STYLE_CLOSABLE */
    char            title[64];
    bool            visible;
    bool            is_key;         /* frontmost focused window */
    int32_t         level;          /* <0=desktop, 0=normal, >0=floating */
    uint32_t       *backing;        /* BGRA pixel buffer */
    uint32_t        backing_stride; /* pixels per row */
};
```

Z-ordering is tracked by a global array (`z_order[MAX_WINDOWS]`), where index 0 is
the frontmost window. Three operations manipulate it:

- `z_bring_to_front(id)` -- removes from current position, inserts at index 0
- `z_send_to_back(id)` -- removes from current position, appends at end
- `z_remove(id)` -- removes from the array entirely

Window ordering also has the concept of **levels**: `level < 0` means desktop-level
(e.g., Dock's desktop gradient window), which is never raised on click.
`level >= 0` is a normal window that can become the key window.

#### The Compositor

The `composite()` function (`WindowServer.c:1282-1416`) repaints the entire screen.
It is called whenever `compositor_dirty` is set (by any window operation, mouse
movement that causes dragging, or key window changes):

```
composite()
  |
  +-- [1] Fill entire screen with COL_DESKTOP (steel blue, #3A6EA5)
  |
  +-- [2] For each window in z_order, BACK to FRONT:
  |     |
  |     +-- Skip if !visible or !backing
  |     +-- Draw 1px shadow (right + bottom edges)
  |     +-- If TITLED:
  |     |     Draw title bar background (grey, lighter if is_key)
  |     |     Draw separator line at bottom of title bar
  |     |     Draw close button (red circle, radius 5)
  |     |     Draw centred title text
  |     +-- Blit backing store pixels into framebuffer
  |
  +-- [3] Draw menu bar on top of everything:
  |     Fill 22px bar at top with COL_MENUBAR
  |     Draw "KisekiOS" at left
  |     Draw active client's menu items
  |
  +-- [4] Clear compositor_dirty flag
```

The compositor uses a classic **painter's algorithm**: later draws overwrite earlier
ones. Windows are drawn from `z_order[z_count-1]` (backmost) to `z_order[0]`
(frontmost), so the frontmost window is always fully visible.

Title bars are 22 pixels tall (`TITLEBAR_H`), matching the macOS title bar height.
The close button is drawn as a filled circle approximation (radius 5, colour #FF5F57
-- matching macOS's red traffic light button):

```c
/* WindowServer.c:1354-1366 -- close button circle */
for (int dy = 0; dy < 12; dy++) {
    for (int dx = 0; dx < 12; dx++) {
        int cx = dx - 5, cy = dy - 5;
        if (cx*cx + cy*cy <= 25)  /* r^2 = 25 */
            put_pixel(bx + dx, by + dy, COL_CLOSE_BTN);
    }
}
```

#### The Cursor

The cursor is a 12x18 pixel bitmap defined as a literal array
(`WindowServer.c:459-478`), with values: 0=transparent, 1=black (outline),
2=white (fill). It forms the classic arrow pointer shape.

The cursor is drawn **outside** the compositor -- it uses a save/restore pattern
to avoid recompositing the entire screen on every mouse move:

1. `cursor_restore()` -- writes back the saved pixel rectangle under the old cursor
2. Process HID events (update `cur_x`, `cur_y`)
3. If compositor dirty, run `composite()` (full repaint)
4. `cursor_save(cur_x, cur_y)` -- saves the rectangle of pixels that will be covered
5. `cursor_draw(cur_x, cur_y)` -- draws the cursor bitmap on top

This means cursor movement never triggers a full recomposite unless something else
changed. On macOS, the cursor is composited by the GPU as a hardware overlay -- same
principle (don't redraw everything just because the cursor moved), different mechanism.

#### GPU Flush

After compositing + cursor draw, WindowServer calls `flush_fb()`, which invokes
`IOConnectCallScalarMethod(fb_conn, kIOFBMethodFlushAll, ...)`. This triggers the
kernel's IOFramebuffer driver to issue a VirtIO GPU `TRANSFER_TO_HOST_2D` +
`RESOURCE_FLUSH` sequence, pushing the framebuffer pixels to the QEMU display.

### 12.4 Input Event Dispatch

WindowServer reads raw HID events from the kernel's shared-memory event ring
(mapped via IOKit). The ring is a single-producer (kernel) single-consumer
(WindowServer) lock-free queue:

```c
/* WindowServer.c:255-261 -- must match kernel hid_event.h */
struct hid_event_ring {
    volatile uint32_t write_idx;    /* kernel increments */
    volatile uint32_t read_idx;     /* WindowServer increments */
    uint32_t size;                  /* HID_EVENT_RING_SIZE = 256 */
    uint32_t _pad;
    struct hid_event events[256];
};
```

The `process_hid()` function (`WindowServer.c:1535-1717`) drains all available events:

```
while (read_idx != write_idx):
    dmb ish                    -- memory barrier (ARM acquire semantics)
    event = ring->events[read_idx % 256]
    dmb ish                    -- ensure event fields are fully read
    read_idx++

    switch (event.type):
        MOUSE_MOVE:
            - Scale tablet absolute coords (0-32767) to screen pixels
            - If dragging a title bar: update window position
            - Send MOUSE_MOVED or MOUSE_DRAGGED to key window's client

        MOUSE_DOWN:
            - Double-click detection (30 ticks window, 10px radius)
            - Hit-test: find topmost window under cursor
            - If close button hit: send WINDOW_CLOSE event
            - If title bar hit: start drag (save offset)
            - If content hit: bring to front + send MOUSE_DOWN to client

        MOUSE_UP:
            - Clear drag state
            - Send MOUSE_UP to key window's client

        KEY_DOWN / KEY_UP:
            - Translate keycode to ASCII via US QWERTY keymap
              (handles shift, capslock, ctrl modifiers)
            - Send to key window's client

        SCROLL:
            - Hit-test: find window under cursor (NOT key window)
            - Send SCROLL event to that window's client
```

**Key window** (`key_window_id`) is the frontmost visible window with `level >= 0`.
Keyboard events always go to the key window. Mouse events go to the window under the
cursor (for clicks) or the key window (for moves/drags). Scroll events go to the
window under the cursor (matching macOS behaviour where scrolling targets the window
under the cursor, not the focused window).

**Title bar dragging** (`WindowServer.c:1558-1565`): When a MOUSE_DOWN lands in a
title bar, WindowServer records the drag offset (`cur_x - w->x`, `cur_y - w->y`).
On subsequent MOUSE_MOVE events while `mouse_is_down`, the window position is
updated to `cur_x - offset_x`, `cur_y - offset_y`, and `compositor_dirty` is set.

**Double-click detection** (`WindowServer.c:1589-1605`): A counter `loop_counter`
increments every main-loop iteration. If a MOUSE_DOWN occurs within 30 ticks and
10 pixels of the previous click, `click_count` increments (otherwise resets to 1).
The count is passed to the client in the mouse event, enabling double-click file
opening in Finder.

### 12.5 loginwindow -- Session Management

**Source**: `userland/sbin/loginwindow.c` (980 lines)

On macOS, `/System/Library/CoreServices/loginwindow.app` is the process that presents
the login screen and manages the user session. Kiseki faithfully reproduces this
architecture. loginwindow is launched by init as a LaunchDaemon and performs:

1. **Connect to WindowServer** via Mach IPC (`bootstrap_look_up` + `WS_MSG_CONNECT`)
2. **Create a borderless window** centred on screen (360x260 pixels)
3. **Render the login UI** with username/password fields and a "Log In" button
4. **Authenticate** against `/etc/passwd` + `/etc/shadow`
5. **Launch the GUI session** (Dock, Finder, SystemUIServer, Terminal)
6. **Monitor children** and relaunch critical apps on crash

#### The Login UI

loginwindow renders its own pixels using software rendering into a pixel buffer
(`g_pixels`, 360x260x4 bytes), then blits it to WindowServer via `ws_draw_rect()`.
The UI layout:

```
+--------------------------------------+
|          Kiseki OS                    |    <- Title at y=20
|    Enter your credentials            |    <- Subtitle at y=42
|                                      |
|  Username:                           |    <- Label at y=72
|  +------------------------------+    |    <- Field at y=90, 240x24
|  | root_                        |    |
|  +------------------------------+    |
|  Password:                           |    <- Label at y=126
|  +------------------------------+    |    <- Field at y=144, 240x24
|  | *****                        |    |
|  +------------------------------+    |
|  [ Incorrect password ]              |    <- Error at y=178 (if any)
|                                      |
|         +----------+                 |    <- Button at y=200, 100x28
|         |  Log In  |                 |
|         +----------+                 |
+--------------------------------------+
```

The active field gets a blue highlight line at its bottom edge. Passwords display
as 5x5 filled squares (bullets). Tab switches between fields.

#### Authentication

loginwindow parses `/etc/passwd` (colon-delimited, 7 fields) to look up the user:

```c
/* loginwindow.c:522-564 -- /etc/passwd parsing */
/* Format: name:x:uid:gid:gecos:home:shell */
typedef struct {
    char name[32];
    int  uid, gid;
    char home[64];
    char shell[32];
} passwd_entry_t;
```

Then checks `/etc/shadow` for the password hash (`loginwindow.c:566-599`). Three
hash formats are supported:

| Format | Meaning |
|---|---|
| (empty) | No password required |
| `!` or `*` | Account locked |
| `plain:password` | Plaintext comparison |
| (anything else) | Direct `strcmp()` |

No real cryptographic hashing is implemented -- this is a development/educational OS.

#### Session Launch

On successful authentication, `launch_gui_session()` (`loginwindow.c:710-738`) forks
and execs four applications in order:

```
1. /System/Library/CoreServices/Dock.app/Dock
2. /System/Library/CoreServices/Finder.app/Finder
3. /System/Library/CoreServices/SystemUIServer.app/SystemUIServer
4. /Applications/Terminal.app/Terminal
```

Each child:
- Gets environment variables set from the authenticated user's passwd entry
  (`HOME`, `USER`, `LOGNAME`, `SHELL`, `PATH`, `TERM`)
- Drops privileges via `setgid()` then `setuid()` (GID before UID -- standard Unix
  practice since you can't change GID after dropping root UID)
- Calls `execve()` with the application path

After launching, loginwindow hides its window (`ws_order_window(WS_ORDER_OUT)`) and
enters a child-monitoring loop. It calls `waitpid(-1, WNOHANG)` to reap exited
children. If Dock, Finder, or SystemUIServer crash, they are automatically relaunched.
Terminal is NOT relaunched (the user may have intentionally closed it).

This matches macOS loginwindow's behaviour: it monitors and relaunches the "core
services" (Dock, Finder, SystemUIServer) but not user-launched applications.

### 12.6 init -- The launchd-Style PID 1

**Source**: `userland/sbin/init.c` (978 lines)

Kiseki's init is a faithful reimplementation of macOS's `launchd` -- the first
user-space process (PID 1). It manages system daemons using Apple-format XML plist
configuration files.

#### Boot Sequence

```
init main()
  |
  +-> [Phase 1] Load plist configs
  |     scan /System/Library/LaunchDaemons/*.plist
  |     scan /Library/LaunchDaemons/*.plist
  |     parse XML plists into job descriptors
  |
  +-> [Phase 2] Pre-create Mach service ports
  |     For each job's MachServices:
  |       mach_port_allocate(RECEIVE) -> port
  |       bootstrap_register(name, port)
  |
  +-> [Phase 3] Launch all daemons
  |     For each job:
  |       fork() + execve(job->program)
  |
  +-> [Phase 4] Spawn getty on /dev/console
  |     (or skip fbcon0 if WindowServer is configured)
  |
  +-> [Phase 5] Main loop
        for (;;):
          spawn_getty("/dev/console")
          wait4(-1) in a loop:
            if getty exited: break (respawn in outer loop)
            if fbcon0 getty exited: respawn it
            if daemon exited: handle_daemon_exit()
```

#### Plist Parsing

init includes a minimal XML parser (`init.c:115-520`) that handles the subset of
Apple plist XML used by LaunchDaemon configurations:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "...">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>uk.co.avltree9798.WindowServer</string>
    <key>ProgramArguments</key>
    <array>
        <string>/sbin/WindowServer</string>
    </array>
    <key>MachServices</key>
    <dict>
        <key>uk.co.avltree9798.WindowServer</key>
        <true/>
    </dict>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

The parser recognises: `<dict>`, `<array>`, `<string>`, `<key>`, `<true/>`,
`<false/>`, `<integer>`, `<?xml?>`, `<!DOCTYPE>`, `<plist>`. Unknown tags are
skipped with depth tracking for nested containers.

Parsed fields per job:

```c
/* init.c:67-83 */
struct launchd_job {
    int     active;
    char    label[128];             /* "uk.co.avltree9798.WindowServer" */
    char    program[256];           /* "/sbin/WindowServer" */
    int     num_services;           /* Number of MachServices */
    char    service_names[8][128];  /* Service name strings */
    unsigned int service_ports[8];  /* Allocated port names */
    int     keep_alive;             /* KeepAlive flag */
    int     pid;                    /* Child PID (-1 if not running) */
    int     crash_count;            /* Consecutive rapid crashes */
    long    last_exit_time;         /* time() of last exit */
};
```

#### Mach Service Pre-Creation

The critical innovation borrowed from macOS launchd is **service port pre-creation**
(`init.c:632-671`). Before any daemon is launched, init:

1. Allocates a receive port: `mach_port_allocate(task_self, RECEIVE, &port)`
2. Registers it: `bootstrap_register(NULL, service_name, port)`

This solves a race condition: clients can `bootstrap_look_up()` a service name
immediately, even before the daemon has started. The kernel's bootstrap registry
holds the port until the daemon calls `bootstrap_check_in()` to claim it.

```
init                          Kernel Bootstrap          WindowServer
  |                                |                        |
  | mach_port_allocate             |                        |
  |-----> port=5                   |                        |
  | bootstrap_register("...WS", 5)|                        |
  |------------------------------->| name="...WS", port=5   |
  |                                |                        |
  | fork+exec WindowServer         |                        |
  |----------------------------------------------->|        |
  |                                |               |        |
  | (client does bootstrap_look_up)|               |        |
  |<-------(finds port 5)----------|               |        |
  |                                |               |        |
  |                                | bootstrap_check_in     |
  |                                |<----------------------|
  |                                | (transfers receive right to WS)
```

#### KeepAlive and Crash-Loop Throttling

When a daemon with `KeepAlive=true` exits, init relaunches it
(`init.c:837-876`). However, to prevent crash-looping daemons from burning CPU,
init implements **throttle detection**:

- If a daemon exits within `KEEPALIVE_THROTTLE_SEC` (10 seconds) of its last
  exit, `crash_count` increments
- After `KEEPALIVE_MAX_RAPID_CRASHES` (5) consecutive rapid crashes, init sleeps
  for `KEEPALIVE_PENALTY_SEC` (10 seconds) before relaunching
- If a daemon runs for more than 10 seconds before exiting, `crash_count` resets

This mirrors macOS launchd's `ThrottleInterval` mechanism.

#### getty and WindowServer Coexistence

init detects whether WindowServer is configured (`init.c:912-918`) by searching
the loaded job labels for "WindowServer". If present, it skips spawning a getty
on `/dev/fbcon0` to prevent two processes writing to the framebuffer simultaneously.
The serial console getty (`/dev/console`) always runs regardless, providing a
fallback text interface.

---

## Chapter 13: Framework Stack -- CoreFoundation through AppKit

Kiseki reproduces macOS's layered framework architecture in miniature. Each layer
builds on the one below, culminating in AppKit -- the Objective-C framework that
applications actually use to create windows, draw text, and handle events.

```
+-------------------------------------------------------+
|  Applications (Dock, Finder, Terminal, SystemUIServer) |
+-------------------------------------------------------+
|  AppKit.m          (3,410 lines)   Objective-C         |
|  NSWindow, NSView, NSApplication, NSEvent, NSColor,    |
|  NSFont, NSTextField, NSButton, NSMenu, NSResponder    |
+-------------------------------------------------------+
|  Foundation.m      (1,616 lines)   Objective-C         |
|  NSObject, NSString, NSArray, NSDictionary, NSNumber,  |
|  NSRunLoop, NSNotificationCenter, NSAutoreleasePool    |
+-------------------------------------------------------+
|  libobjc (GNUstep) (82 files)      C/C++/ASM          |
|  objc_msgSend, class registration, ARC, dispatch table |
+-------------------------------------------------------+
|  CoreText.c        (1,961 lines)   C (freestanding)    |
|  CTFont, CTLine, CTRun, CTFrame, CTFramesetter         |
+-------------------------------------------------------+
|  CoreGraphics.c    (3,162 lines)   C (freestanding)    |
|  CGContext, CGImage, CGColor, CGPath, software raster   |
+-------------------------------------------------------+
|  CoreFoundation.c  (4,841 lines)   C (freestanding)    |
|  CFString, CFArray, CFDictionary, CFRunLoop, CFRuntime  |
+-------------------------------------------------------+
|  IOKitLib.c        (977 lines)     C (freestanding)    |
|  IOServiceOpen, IOConnectCallMethod, IOConnectMapMemory |
+-------------------------------------------------------+
|  libSystem.c / crt0.S              C/ASM               |
|  (covered in Chapter 11)                                |
+-------------------------------------------------------+
```

Every framework except libobjc uses a **freestanding pattern**: the `.c` or `.m`
file contains zero `#include` directives for system headers. All types (`uint32_t`,
`size_t`, `bool`, etc.) are typedef'd from scratch. All library functions (`malloc`,
`strlen`, `memcpy`, etc.) are declared as bare `extern` prototypes. All Mach IPC
structures are hand-defined to match the kernel's exact layout. This lets each
framework compile with minimal dependencies -- the only link-time requirement is
`libSystem.B.dylib`.

### 13.1 The Freestanding Pattern

Why avoid `#include`? On macOS, frameworks include Apple SDK headers that pull in
hundreds of transitive dependencies. Kiseki has no macOS SDK -- it has its own kernel
and its own libSystem. Rather than recreate hundreds of headers, each framework
defines exactly what it needs inline.

Here is the pattern, shown from CoreFoundation.c:

```c
/* Step 1: Primitive types from scratch (CoreFoundation.c:22-49) */
typedef _Bool bool;
typedef unsigned long uint64_t;
typedef unsigned long size_t;
typedef __builtin_va_list va_list;
#define va_start(ap, last) __builtin_va_start(ap, last)

/* Step 2: Library functions as bare externs (CoreFoundation.c:55-101) */
extern void *malloc(size_t size);
extern void *memcpy(void *dst, const void *src, size_t n);
extern size_t strlen(const char *s);
extern int snprintf(char *buf, size_t size, const char *fmt, ...);

/* Step 3: Mach IPC structures hand-defined (CoreFoundation.c:123-164) */
typedef unsigned int mach_port_t;
typedef struct {
    mach_msg_bits_t   msgh_bits;
    mach_msg_size_t   msgh_size;
    mach_port_name_t  msgh_remote_port;
    mach_port_name_t  msgh_local_port;
    mach_port_name_t  msgh_voucher_port;
    mach_msg_id_t     msgh_id;
} mach_msg_header_t;

/* Step 4: Visibility control */
#define EXPORT __attribute__((visibility("default")))
#define HIDDEN __attribute__((visibility("hidden")))
```

At link time, the `extern` symbols resolve against `libSystem.B.dylib`. The
`EXPORT`/`HIDDEN` macros control which functions appear in the dylib's symbol table.

Math functions use compiler builtins (`__builtin_sin`, `__builtin_cos`,
`__builtin_sqrt`, `__builtin_inf`, `__builtin_nan`) rather than linking `libm`.
The only `#include` anywhere is for embedded font data files
(`font8x16.inc` / `cg_font8x16.inc`).

### 13.2 CoreFoundation

**Source**: `userland/CoreFoundation/CoreFoundation.c` (4,841 lines, freestanding C)

CoreFoundation (CF) is the lowest framework layer -- a pure C library of
reference-counted, polymorphic container types. It is the macOS equivalent of a
"standard library for Apple platforms." Kiseki's implementation matches Apple's
CF-1153.18 API surface and is built as `CoreFoundation.framework`.

#### CFRuntime -- The Object System

Every CF object begins with a `CFRuntimeBase` header. Additionally, a hidden
`intptr_t` refcount is stored at offset -8 (before the pointer), matching
GNUstep libobjc2's object layout for toll-free bridging:

```
Memory layout of a CF object:

     addr - 8:   intptr_t  refcount     (hidden, matches libobjc obj[-1])
     addr + 0:   uintptr_t _cfisa       (ObjC isa for toll-free bridging)
     addr + 8:   uint64_t  _cfinfoa     (packed type ID + marker flags)
     addr + 16:  ...                    (type-specific fields)

_cfinfoa bit layout:
     Bits 0-7:   info flags (bit 7 = 0x80 = "is CF object" marker)
     Bits 8-23:  type ID (up to 65535 registered types)
     Bits 24-63: reserved
```

Types are registered via `_CFRuntimeRegisterClass()`, which assigns sequential IDs
from a 256-slot table. Each type provides a `CFRuntimeClass` descriptor with
callbacks for `init`, `finalize`, `equal`, `hash`, and `copyDescription`.

Instance creation (`_CFRuntimeCreateInstance()`, line 550):

1. Allocates `sizeof(intptr_t) + sizeof(CFRuntimeBase) + extraBytes` via `calloc`
2. Sets `raw[0] = 1` (initial refcount in the hidden word)
3. Object pointer = `raw + 1` (past the hidden refcount)
4. Sets `_cfinfoa` with type ID and marker flag
5. If toll-free bridging is active, sets `_cfisa` to the ObjC class pointer
6. Calls the class `init` callback if provided

`CFRetain`/`CFRelease` use GCC atomic builtins on the hidden refcount word.
Static singletons (`kCFNull`, `kCFBooleanTrue`, etc.) use an immortal sentinel
(`0x7FFFFFFFFFFFFFF`) that is never incremented or decremented.

#### Implemented Types

15 types are registered in `__CFInitialize()` (constructor, line 4781):

| Type | Internal Storage | Key Detail |
|---|---|---|
| CFAllocator | Function pointer table | 3 singletons: SystemDefault, Malloc, Null |
| CFNull | Empty struct | Single `kCFNull` singleton |
| CFBoolean | `Boolean _value` | `kCFBooleanTrue` / `kCFBooleanFalse` singletons |
| CFNumber | `int64_t` or `double` union | All integers stored as int64, all floats as double |
| CFData | Heap `uint8_t *_bytes` | Mutable variant, doubling growth from min 16 |
| CFString | Heap `char *_buf` (UTF-8) | DJB2 hash, 1024-slot CFSTR interning table |
| CFArray | Heap `const void **_values` | Insertion sort (qsort lacks context ptr) |
| CFDictionary | Open-addressing hash table | Power-of-2 capacity, 70% load rehash, linear probing |
| CFSet | Open-addressing hash table | Same strategy as CFDictionary, keys only |
| CFDate | `double _time` (CFAbsoluteTime) | Seconds since 2001-01-01, via `gettimeofday()` |
| CFAttributedString | CFStringRef + single CFDictionaryRef | Simplified: one attribute dict for entire string |
| CFRunLoop | Mach port + mode arrays | Faithful to Apple's 12-step run loop |
| CFRunLoopSource | Callback-based (version 0 only) | Signaled/fired pattern |
| CFRunLoopTimer | Fire date + interval + callout | Repeating timers skip missed intervals |
| CFRunLoopObserver | Activity mask + callout | Entry/BeforeTimers/BeforeSources/BeforeWaiting/AfterWaiting/Exit |

**CFString** always stores UTF-8 internally, but exposes a UTF-16 `CFIndex _length`
for API compatibility. Encoding conversion between UTF-8 and UTF-16 is done by
manual codepoint walking (handling surrogate pairs for characters above U+FFFF).
`CFStringGetCStringPtr()` returns a direct pointer only for UTF-8/ASCII encodings.
Case-insensitive comparison is ASCII-only (A-Z + 32).

**CFDictionary** uses parallel `_keys[]` and `_values[]` arrays with sentinel values
(`NULL` = empty, `0xDEAD` = deleted). CFSet uses the same approach with a `0xBEEF`
deleted sentinel.

#### CFRunLoop

The run loop is the most complex subsystem -- it provides the blocking wait
mechanism for GUI applications. Each thread lazily gets a run loop via pthread TLS.

Per-mode storage (fixed arrays, max 8 modes):
- Up to 64 sources, 32 timers, 32 observers per mode
- Common modes: adding a source/timer to `kCFRunLoopCommonModes` copies it to all
  registered common modes

The core loop (`__CFRunLoopRun`, line 3984) faithfully implements Apple's 12-step
algorithm:

```
[1]  If mode is empty -> return kCFRunLoopRunFinished
[2]  Notify observers: kCFRunLoopEntry
[3]  Loop:
       [3a] Notify kCFRunLoopBeforeTimers
       [3b] Notify kCFRunLoopBeforeSources
       [3c] Fire signaled version-0 sources
       [3d] Check stopped flag
       [3e] Compute sleep = min(next timer, deadline)
       [3f] Notify kCFRunLoopBeforeWaiting
       [3g] Sleep via mach_msg(MACH_RCV_MSG | MACH_RCV_TIMEOUT)
            on the run loop's wakeup port
       [3h] Notify kCFRunLoopAfterWaiting
       [3i] Fire timers
       [3j] Fire newly-signaled sources
       [3k] Check: stopped, timed out, mode empty -> break
[4]  Notify observers: kCFRunLoopExit
```

`CFRunLoopWakeUp()` sends a zero-size Mach message to the wakeup port, unblocking
the `mach_msg` receive. If Mach port allocation failed at init time, a `nanosleep()`
fallback is used instead.

**Notable limitations vs Apple CF**: No version-1 (Mach port-based) run loop sources.
No block-based timer/observer creation (ObjC blocks runtime unavailable).
`CFAutorelease` is a no-op. `CFStringCreateWithFormat` passes the format to C
`vsnprintf` (no `%@` support). Array sort uses O(n^2) insertion sort.

### 13.3 CoreGraphics

**Source**: `userland/CoreGraphics/CoreGraphics.c` (3,162 lines, freestanding C)

CoreGraphics (CG, also known as Quartz 2D on macOS) is a pure software 2D
rasteriser. It provides bitmap contexts, drawing primitives, colour management,
path construction, and image handling. It has **no connection to WindowServer** --
it operates entirely on in-memory pixel buffers. The caller (typically AppKit)
creates a `CGBitmapContext`, draws into it, then blits the pixels to WindowServer
via Mach IPC.

#### Implemented Types

| Type | Lines | Description |
|---|---|---|
| CGColorSpace | 542-624 | Colour model (4 immortal singletons: DeviceRGB, DeviceGray, DeviceCMYK, sRGB) |
| CGColor | 632-737 | Up to 5 components (CMYK+A), custom refcounting |
| CGDataProvider | 746-807 | Wraps raw data or CFData for deferred pixel access |
| CGImage | 813-888 | Metadata (width/height/format) + CGDataProvider |
| CGPath | 907-1328 | Dynamic array of path elements (move/line/quad/cubic/close/arc) |
| CGContext | 1456-1475 | Bitmap context with graphics state stack |
| CGGradient | 3027-3054 | **Stub** -- create returns NULL |
| CGLayer | 3075-3106 | **Stub** -- all functions return NULL |

Each type uses a simple `__CGRefCounted` header (`int32_t _refCount`, immortal
sentinel `0x7FFFFFFF`).

#### The Graphics State

Every CGContext maintains a linked-list stack of graphics states. `CGContextSaveGState`
pushes a copy; `CGContextRestoreGState` pops and frees:

```c
/* CoreGraphics.c:1351-1395 -- graphics state */
struct __CGGState {
    CGFloat fillColor[4];           /* RGBA */
    CGFloat strokeColor[4];
    CGAffineTransform ctm;          /* current transform matrix */
    CGRect clipRect;                /* single-rect clip (simplified) */
    CGFloat lineWidth;              /* default 1.0 */
    CGLineCap lineCap;
    CGLineJoin lineJoin;
    CGFloat miterLimit;             /* default 10.0 */
    CGBlendMode blendMode;          /* Normal, Copy, Clear only */
    CGFloat alpha;                  /* global alpha, default 1.0 */
    bool shouldAntialias;           /* stored but NOT used */
    CGTextDrawingMode textDrawingMode;
    CGFloat characterSpacing;
    CGPoint textPosition;
    CGSize shadowOffset;            /* stored but NOT rendered */
    CGFloat shadowBlur;
    struct __CGGState *_prev;       /* linked-list for save/restore */
};
```

#### Pixel Format

Both BGRA and RGBA 32bpp formats are supported, detected at runtime:

- **BGRA** (macOS native): `kCGBitmapByteOrder32Little` + `kCGImageAlphaPremultipliedFirst`
  -- byte order `[B, G, R, A]`. This is what WindowServer and VirtIO GPU expect.
- **RGBA**: `kCGImageAlphaPremultipliedLast` -- byte order `[R, G, B, A]`.

Always 8 bits per component, 4 bytes per pixel. `CGBitmapContextCreate` rejects
anything other than 8 bpc.

#### Drawing Primitives

The rasteriser is entirely software-based, operating on the bitmap context's pixel
buffer:

| Primitive | Algorithm |
|---|---|
| `CGContextFillRect` | Transform corners by CTM, clip, fast-path `memset`-style for opaque fills |
| `CGContextStrokeRect` | Four thin edge rectangles |
| `CGContextClearRect` | `memset` to zero |
| `CGContextStrokeLineSegments` | **Bresenham's line algorithm** with width stamping |
| `CGContextFillPath` | **Scanline rasteriser**: flatten curves to edges, compute x-intersections per scanline, sort, fill between pairs |
| `CGContextStrokePath` | Walk path elements, Bresenham each segment |
| `CGContextFillEllipseInRect` | Build ellipse path, then scanline fill |
| `CGContextDrawImage` | **Nearest-neighbour scaling**, handles BGRA/RGBA source |
| `CGContextShowTextAtPoint` | Embedded 8x16 VGA bitmap font, per-pixel blit |

Pixel compositing (`__CGContextBlendPixel`, line 2151) implements source-over
Porter-Duff: `out = src + dst * (1 - srcA)`. Only three blend modes are
functional: Normal/SourceAtop, Copy, and Clear.

**Clipping** is simplified to a single rectangle. `CGContextClip()` uses the
current path's bounding box (not the actual path shape). This means complex
clip regions are approximated as their bounding rectangle.

**Curves** in path fills are simplified: quadratic and cubic Bezier segments are
flattened to a straight line from start to end during scanline rasterisation.
The curve control points are ignored during fill -- only path stroke walks
the actual curve via Bresenham.

**Notable omissions**: No anti-aliasing (stored but never consulted). No dashed
lines. No gradients (stub returns NULL). No shadows (stored but never rendered).
No colour management (sRGB = DeviceRGB = DisplayP3). No PDF generation.

### 13.4 CoreText

**Source**: `userland/CoreText/CoreText.c` (1,961 lines, freestanding C)

CoreText provides text layout and rendering. On macOS, it is the low-level text
engine that shapes glyphs using TrueType/OpenType fonts. Kiseki's implementation
is greatly simplified -- it uses a single embedded 8x16 bitmap font with integer
scaling -- but faithfully reproduces the API surface (66 exported functions).

#### Types

| Type | Internal | Description |
|---|---|---|
| CTFont | Manual refcount, scale factor | Wraps the embedded bitmap font at a requested size |
| CTRun | Parallel glyph/position/advance arrays | A contiguous run of glyphs with uniform attributes |
| CTLine | Array of CTRuns | A single line of laid-out text |
| CTFramesetter | Owns a CFAttributedString | Factory for CTFrames |
| CTFrame | Array of CTLines + line origins | Multi-line text laid out within a rectangle |
| CTParagraphStyle | Alignment, line break mode, spacing | Paragraph-level formatting |
| CTFontDescriptor | Stub (all functions return NULL) | |
| CTFontCollection | Stub (all functions return NULL) | |

Note: CTFont/CTRun/CTLine/CTFrame use manual `intptr_t _refCount` fields, NOT
CFRuntime. They are not toll-free bridged.

#### Font Rendering

All font names resolve to the same embedded CP437/VGA 8x16 bitmap
(`__CTBitmapFontData`, 256 glyphs x 16 rows). Font size is mapped to an integer
scale: `scale = max(1, round(size / 16))`. A 32pt font renders at 2x scale
(16x32 pixels per glyph). There is no anti-aliasing, hinting, or subpixel
rendering.

The rendering path goes through `CTRunDraw()` -> `__CTRunDrawGlyph()`, which
directly accesses the CGContext's internal struct fields (`ctx->_data`,
`ctx->_width`, `ctx->_bytesPerRow`, `ctx->_bitmapInfo`) to write pixels. This
tight coupling means CoreText and CoreGraphics must have exactly matching struct
layouts.

#### Text Layout

`CTLineCreateWithAttributedString()` creates a single CTRun for the entire string
(no splitting at attribute boundaries). Each character gets the same fixed-width
advance (`glyphWidth`). Layout is a simple linear walk:

```
For each character in the attributed string:
    glyph_index = (codepoint < 256) ? codepoint : 0
    position[i] = (i * glyphWidth, 0)
    advance[i]  = glyphWidth
    -> one CTRun -> one CTLine
```

`CTFramesetterCreateFrame()` performs word-wrapping by iterating through the string
and breaking lines when the accumulated width exceeds the frame rectangle. A simple
heuristic tries to break at the last space character. No Unicode line-break
algorithm or hyphenation is implemented.

### 13.5 Foundation

**Source**: `userland/Foundation/Foundation.m` (1,616 lines, freestanding Objective-C)

Foundation is the Objective-C bridge layer. It provides the `NS*` classes that
applications use (`NSString`, `NSArray`, `NSDictionary`, etc.) as thin wrappers
around CoreFoundation types, connected via toll-free bridging.

#### Implemented Classes

| Class | Lines | Bridges To | Key Methods |
|---|---|---|---|
| NSObject | 298-482 | -- (root class) | alloc, init, retain, release, dealloc, isKindOfClass: |
| NSString | 492-719 | CFString | stringWithUTF8String:, length, UTF8String, isEqualToString: |
| NSMutableString | 725-748 | CFMutableString | appendString: (stub) |
| NSNumber | 754-829 | CFNumber | numberWithInt:, intValue, doubleValue, boolValue |
| NSArray | 835-898 | CFArray | array, arrayWithObjects:count:, count, objectAtIndex: |
| NSMutableArray | 904-953 | CFMutableArray | addObject:, removeObjectAtIndex: (stub) |
| NSDictionary | 959-1013 | CFDictionary | dictionary, objectForKey:, allKeys |
| NSMutableDictionary | 1019-1053 | CFMutableDictionary | setObject:forKey:, removeObjectForKey: |
| NSData | 1059-1089 | CFData | (mostly stubs) |
| NSRunLoop | 1098-1146 | CFRunLoop | currentRunLoop, run, runUntilDate: |
| NSAutoreleasePool | 1154-1196 | -- | init, drain (ARC no-ops) |
| NSNotificationCenter | 1223-1299 | -- | defaultCenter, addObserver:, postNotificationName: |
| NSProcessInfo | 1321-1356 | -- | processInfo, processName |
| NSThread | 1362-1389 | -- | isMainThread (always YES) |
| NSDate | 1395-1437 | CFDate | date, timeIntervalSinceReferenceDate |
| NSBundle | 1443-1479 | -- | mainBundle, bundleIdentifier |
| NSTimer | 1485-1532 | -- | (all stubs returning nil) |

#### Toll-Free Bridging

The central architectural pattern is that NS collection methods cast `self` to
the corresponding CF type and call CF functions directly:

```objc
/* Foundation.m:540 -- NSString length delegates to CFString */
- (unsigned long)length {
    return CFStringGetLength((CFStringRef)self);
}

/* Foundation.m:864 -- NSArray count delegates to CFArray */
- (long)count {
    return CFArrayGetCount((CFArrayRef)self);
}
```

Creation methods return CF objects cast to `id`:

```objc
/* Foundation.m:523 */
+ (id)stringWithUTF8String:(const char *)s {
    return (id)CFStringCreateWithCString(NULL, s, 0x08000100 /*UTF8*/);
}
```

This works because CF objects and ObjC objects share the same memory layout:

```
        CF object                       ObjC object (GNUstep libobjc2)
   -8:  intptr_t refcount          -8:  intptr_t refcount
    0:  uintptr_t _cfisa (= isa)    0:  Class isa
    8:  uint64_t _cfinfoa            8:  (instance variables)
   16:  (type fields)               ...
```

The `_cfisa` field at offset 0 in CFRuntimeBase IS the ObjC `isa` pointer. When
Foundation initialises, it registers a bridge ISA lookup function with CF:

```c
/* Foundation.m:1567-1581 -- bridge callback */
static uintptr_t __FoundationBridgeISALookup(CFTypeID typeID) {
    if (typeID == CFStringGetTypeID())     return (uintptr_t)objc_getClass("NSString");
    if (typeID == CFArrayGetTypeID())      return (uintptr_t)objc_getClass("NSArray");
    if (typeID == CFDictionaryGetTypeID()) return (uintptr_t)objc_getClass("NSDictionary");
    if (typeID == CFNumberGetTypeID())     return (uintptr_t)objc_getClass("NSNumber");
    if (typeID == CFDataGetTypeID())       return (uintptr_t)objc_getClass("NSData");
    if (typeID == CFDateGetTypeID())       return (uintptr_t)objc_getClass("NSDate");
    return 0;
}
```

This is called by `_CFRuntimeCreateInstance()` whenever a new CF object is
allocated. The returned class pointer is stored in `_cfisa`, making the CF object
a valid ObjC object that responds to messages like `-length`, `-count`, etc.

#### NSObject Memory Management

NSObject's `+alloc` mirrors CF's layout exactly (`Foundation.m:337`):

```objc
+ (id)alloc {
    size_t size = class_getInstanceSize(self);
    intptr_t *raw = calloc(1, sizeof(intptr_t) + size);
    raw[0] = 1;              /* hidden refcount = 1 */
    id obj = (id)(raw + 1);  /* object starts past hidden word */
    obj->isa = self;
    return obj;
}

- (void)dealloc {
    free(((intptr_t *)self) - 1);  /* free from hidden word */
}
```

`-retain` and `-release` increment/decrement the hidden word at `((intptr_t *)self)[-1]`,
exactly matching `CFRetain`/`CFRelease`. This means `CFRetain` works on NSObjects
and `[cfObj retain]` works on CF objects -- full bidirectional bridging.

### 13.6 AppKit

**Source**: `userland/AppKit/AppKit.m` (3,410 lines, freestanding Objective-C)

AppKit is the top of the framework stack -- the Objective-C toolkit that applications
use to create windows, handle events, draw content, and build menus. It connects to
WindowServer via Mach IPC and orchestrates the entire GUI application lifecycle.

#### Implemented Classes (15)

| Class | Lines | Role |
|---|---|---|
| NSGraphicsContext | 712-781 | Wraps CGContextRef, manages current context |
| NSColor | 792-905 | RGBA colour values, 14 named colours (systemRed, etc.) |
| NSFont | 917-1021 | Wraps CTFont, font metrics |
| NSEvent | 1086-1176 | Keyboard/mouse/scroll events from WindowServer |
| NSResponder | 1621-1695 | Base class for event handling, responder chain |
| NSView | 1715-1909 | Rectangular drawable area, subview tree (max 32) |
| NSWindow | 1931-2355 | WindowServer-backed window with backing store |
| NSMenuItem | 2366-2439 | Menu item (title, action, key equivalent) |
| NSMenu | 2453-2566 | Menu container, syncs to WindowServer menu bar |
| NSApplication | 2593-2939 | Singleton app object, main event loop |
| NSCell | 2968-3019 | Base for controls (title, enabled, target/action) |
| NSControl | 3030-3097 | Clickable control, sends action on mouse-up |
| NSTextField | 3108-3230 | Text label/field with drawRect: |
| NSButton | 3259-3393 | Push button with drawRect: |

#### WindowServer Connection

AppKit communicates with WindowServer through 10 static C functions that build
and send Mach IPC messages:

```
_WSConnect(appName)        -- bootstrap_look_up + CONNECT handshake
_WSDisconnect()            -- send DISCONNECT message
_WSCreateWindow(...)       -- send CREATE_WINDOW, get window_id reply
_WSDestroyWindow(id)       -- send DESTROY_WINDOW
_WSOrderWindow(id, order)  -- send ORDER_WINDOW (FRONT/BACK/OUT)
_WSSetTitle(id, title)     -- send SET_TITLE
_WSSetFrame(id, rect)      -- send SET_FRAME
_WSDrawRect(id, pixels...) -- send DRAW_RECT with OOL pixel data
_WSSetMenu(items)          -- send SET_MENU
_WSPollEvent(buf, timeout) -- mach_msg(MACH_RCV_MSG | MACH_RCV_TIMEOUT)
```

The pixel blit path (`_WSDrawRect`) uses Mach OOL descriptors for zero-copy
transfer of the window's backing store to WindowServer:

```c
/* AppKit.m:1512-1523 -- OOL pixel transfer */
msg.header.msgh_bits = MACH_MSGH_BITS(COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
msg.body.msgh_descriptor_count = 1;
msg.surface_desc.address = pixels;
msg.surface_desc.size = rowbytes * height;
msg.surface_desc.copy = MACH_MSG_VIRTUAL_COPY;
msg.surface_desc.type = MACH_MSG_OOL_DESCRIPTOR;
```

If `mach_msg` returns `MACH_SEND_NO_BUFFER`, the send is retried up to 5 times
with 1ms sleeps between attempts.

#### NSWindow and the Backing Store

Each NSWindow maintains a pixel buffer (the "backing store") as a CGBitmapContext:

```
NSWindow
  |
  +-- _windowNumber    (int32_t from WindowServer)
  +-- _backingData     (calloc'd pixel buffer, BGRA 32bpp)
  +-- _backingContext  (CGBitmapContextCreate wrapping _backingData)
  +-- _contentView     (NSView tree root)
```

The display cycle (`-display`, line 2198):

```
[window display]
  |
  +-- Get/create NSGraphicsContext wrapping _backingContext
  +-- Set as current context
  +-- Clear to window background colour (grey)
  +-- [_contentView display]
  |     |
  |     +-- CGContextSaveGState
  |     +-- CGContextClipToRect(_bounds)
  |     +-- Draw background if set
  |     +-- [self drawRect:_bounds]    <-- subclass override point
  |     +-- For each subview (back to front):
  |     |     [subview display]        <-- recursive
  |     +-- CGContextRestoreGState
  |
  +-- Clear current context
  +-- [self flushWindow]
        |
        +-- _WSDrawRect(pixels -> WindowServer via Mach OOL)
```

#### Event Dispatch and the Responder Chain

The main event loop lives in `[NSApplication run]` (line 2722):

```
-[NSApplication run]
  |
  +-- [self finishLaunching]
  |     +-- _WSConnect(appName)
  |     +-- sync menu to WindowServer
  |     +-- [delegate applicationDidFinishLaunching:]
  |
  +-- while (_isRunning):
        |
        +-- _WSPollEvent(&buf, 100ms timeout)
        +-- [self _processWSEvent:&buf]
        |     |
        |     +-- Switch on mach_msg_id_t:
        |     |   KEY_DOWN/UP -> create NSEvent -> [self sendEvent:]
        |     |   MOUSE_DOWN/UP/MOVED/DRAGGED -> create NSEvent -> [self sendEvent:]
        |     |   SCROLL -> create NSEvent -> [self sendEvent:]
        |     |   WINDOW_ACTIVATE -> set _isKeyWindow on target
        |     |   WINDOW_CLOSE -> [targetWindow close]
        |     |   WINDOW_RESIZE -> [targetWindow setFrame:display:]
        |     +--
        |
        +-- For each window: [window displayIfNeeded]
        +-- CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.0, YES)
            (fires ready timers/sources without blocking)
```

`-[NSApplication sendEvent:]` looks up the target NSWindow by `windowNumber` in
a global `__allWindows[]` array (max 16 windows), then forwards via
`-[NSWindow sendEvent:]`. The window dispatches based on event type:

- **Key events** -> `_firstResponder` (the view with keyboard focus)
- **Mouse down** -> hit-test the content view tree, make the hit view the first
  responder if it accepts, call `[hitView mouseDown:event]`
- **Scroll** -> hit-test, call `[hitView scrollWheel:event]`

The **responder chain** follows: NSView -> superview -> ... -> NSWindow ->
NSApplication. Unhandled events propagate up via `-nextResponder`.

NSEvent objects are reused via a single static cache (Bug 28 optimisation) --
safe because events are consumed synchronously within a single iteration.

### 13.7 The Objective-C Runtime (libobjc)

**Source**: `userland/libobjc/` (82 files, ported from GNUstep libobjc2)

Kiseki's ObjC runtime is a port of the GNUstep libobjc2 runtime, built as
`/usr/lib/libobjc.A.dylib`. All `.m`/`.mm` files have been converted to pure
C/C++ for Mach-O compatibility. It provides `objc_msgSend`, class registration,
method dispatch, ARC, and the non-fragile ABI.

#### Class Structure

```c
/* libobjc/class.h -- struct objc_class (LP64, 136 bytes) */
offset  0:  Class isa               /* metaclass pointer */
offset  8:  Class super_class
offset 16:  const char *name
offset 24:  long version
offset 32:  unsigned long info       /* class flags bitfield */
offset 40:  long instance_size
offset 48:  struct objc_ivar_list *ivars
offset 56:  struct objc_method_list *methods   /* linked list */
offset 64:  void *dtable             /* SparseArray dispatch table */
offset 72:  Class subclass_list      /* intrusive linked list */
offset 80:  IMP cxx_construct
offset 88:  IMP cxx_destruct
offset 96:  Class sibling_class
offset 104: struct objc_protocol_list *protocols
offset 112: struct reference_list *extra_data
offset 120: long abi_version
offset 128: struct objc_property_list *properties
```

The dispatch table at offset 64 is a **sparse array** (up to 3 levels of 256-entry
arrays) that maps selector indices to method IMPs. This is the data structure
that makes `objc_msgSend` fast.

#### objc_msgSend -- The Fast Path

`objc_msgSend` is the most performance-critical function in the runtime. It is
implemented in AArch64 assembly (`objc_msgSend.aarch64.S`, 325 lines):

```
objc_msgSend(id self, SEL _cmd, ...):
  |
  +-- [1] Nil check: if self == NULL, return 0
  +-- [2] Small object check: extract low 3 bits of self
  |        If non-zero -> load class from SmallObjectClasses[tag]
  +-- [3] Load isa: x9 = [self + 0]  (Class pointer)
  +-- [4] Load dtable: x9 = [x9 + 64]  (DTABLE_OFFSET)
  +-- [5] Load selector index: w10 = [_cmd + 0]
  +-- [6] Sparse array traversal (1-3 levels based on shift value):
  |        level = dtable->data[(index >> shift) & 0xFF]
  |        ... repeat until shift == 0 ...
  +-- [7] Load IMP: x9 = [slot + 0]  (SLOT_OFFSET)
  +-- [8] If slot is NULL -> slow path (spill regs, call C lookup)
  +-- [9] br x9  (tail-call the method implementation)
```

The fast path is 5-10 instructions for a cache hit. The slow path
(`objc_msg_lookup_internal` in `sendmsg2.c`) handles:

- **Lazy dispatch table installation**: First message to a class triggers
  `+initialize` and dispatch table creation
- **Untyped selector fallback**: Retries lookup without type information
- **Proxy forwarding**: Can change the receiver and retry
- **Message forwarding**: Falls back to `__objc_msg_forward2()`

#### Class Registration Lifecycle

```
[1] dyld loads ObjC module
      -> __objc_load() called per module
      -> Register selectors, load classes into hash table
      -> dtable = uninstalled_dtable (lazy)

[2] First message to class
      -> objc_send_initialize() triggered
      -> Resolve superclass chain
      -> Create dispatch table (copy super + install own methods)
      -> Call +initialize
      -> Install real dtable

[3] Dynamic creation (optional)
      -> objc_allocateClassPair() + add methods/ivars
      -> objc_registerClassPair()
```

#### Kiseki-Specific Adaptations

- **No TLS support**: `__thread` replaced with `static` (safe for single-threaded
  GUI apps; noted as a known limitation for multi-threaded use)
- **All ObjC sources converted to C/C++**: Avoids Mach-O COMDAT section
  incompatibility with GNUstep's ObjC ABI
- **v2 ABI method list conversion**: The compiler emits method lists in a different
  layout; `upgradeV2MethodList()` in `loader.c` converts them to the runtime's
  expected format at load time

#### IOKitLib -- The User-Space IOKit Client

**Source**: `userland/IOKit/IOKitLib.c` (977 lines, freestanding C)

IOKitLib provides the user-space API for interacting with kernel IOKit drivers.
Every function is a synchronous Mach RPC to the kernel's IOKit subsystem (message
IDs in the 2800-2873 range, matching XNU's MIG-generated stubs):

| Function | Mach msg ID | Purpose |
|---|---|---|
| `IOMasterPort()` | bootstrap_look_up | Get IOKit master port |
| `IOServiceGetMatchingService()` | 2873 | Find first matching driver |
| `IOServiceOpen()` | 2862 | Open user client connection |
| `IOServiceClose()` | 2816 | Close connection |
| `IOConnectCallMethod()` | 2865 | Call external method on driver |
| `IOConnectCallScalarMethod()` | (wraps above) | Scalar-only convenience |
| `IOConnectMapMemory64()` | 2863 | Map driver memory into task |
| `IORegistryEntryGetProperty()` | 2812 | Read property from I/O Registry |
| `IOObjectRelease()` | -- | `mach_port_deallocate()` |

Each RPC allocates a one-shot reply port via `mach_reply_port()`, sends a
combined SEND+RCV `mach_msg`, parses the reply, and deallocates the reply port.
This is the mechanism WindowServer uses to open the framebuffer and HID event ring
(see Chapter 12), and that applications use indirectly through CoreGraphics and
AppKit.

---

## Chapter 14: Applications

Kiseki ships four GUI applications that together form the desktop experience:
**Dock.app**, **Finder.app**, **Terminal.app**, and **SystemUIServer.app**.
All four follow an identical architectural pattern: they are Objective-C programs
compiled as arm64 Mach-O executables, linked against AppKit (and transitively
against Foundation, CoreFoundation, CoreGraphics, CoreText, libobjc, and
libSystem).  They communicate with WindowServer over Mach IPC and receive HID
events through the same channel.

This chapter examines every application in detail -- not just what it does, but
how it is built, what patterns it shares with the others, and how each one
exercises different parts of the framework stack.

### 14.1  Application Architecture -- Common Patterns

All four applications share a set of architectural patterns that emerge from the
constraints of Kiseki's freestanding Objective-C environment.

#### Dynamic ObjC Class Creation

None of the applications use `@interface` / `@implementation` blocks to define
custom classes.  Instead, they create classes at runtime using the C API:

```c
/* From Dock.m:255-260 */
Class DockAppDelegate = objc_allocateClassPair(
    [NSObject class], "DockAppDelegate", 0);
class_addMethod(DockAppDelegate,
                @selector(applicationDidFinishLaunching:),
                (IMP)_dockAppDidFinishLaunching, "v@:@");
objc_registerClassPair(DockAppDelegate);
```

This three-step pattern -- `objc_allocateClassPair()`, one or more
`class_addMethod()` calls, `objc_registerClassPair()` -- appears in every
application.  The reason is pragmatic: each `.m` file is compiled in isolation
with `-fobjc-runtime=gnustep-1.9`, and the COMDAT-stripping pipeline (see
Chapter 15) means that normal ObjC class metadata emitted by the compiler would
reference weak-linkage COMDAT sections that Mach-O cannot represent.  Dynamic
registration side-steps the issue entirely.

Every application creates at least two dynamic classes:

| Application    | Classes Created                            |
|----------------|--------------------------------------------|
| Dock.app       | DockAppDelegate, DesktopView, DockView     |
| Finder.app     | FinderAppDelegate, FinderView              |
| Terminal.app   | TerminalAppDelegate, TerminalView          |
| SystemUIServer | SystemUIServerDelegate, ClockView          |

All custom view classes subclass `NSView` and override `drawRect:` with a C
function that receives `(id self, SEL _cmd, CGRect dirtyRect)`.  All delegate
classes subclass `NSObject` and override `applicationDidFinishLaunching:`.

#### The _safe_fprintf_stderr Workaround

Every application contains an identical `_safe_fprintf_stderr()` function that
bypasses libSystem's `FILE*`-based `fprintf`.  The function formats into a
256-byte stack buffer with `vsnprintf`, then writes directly via an inline
`svc #0x80` syscall (x16=4 for `write`, fd=2 for stderr):

```c
/* Dock.m:38-59, Finder.m:44-65, Terminal.m:46-67, SystemUIServer.m:36-57 */
static int _safe_fprintf_stderr(const char *fmt, ...) {
    char _buf[256];
    __builtin_va_list ap;
    __builtin_va_start(ap, fmt);
    int n = vsnprintf(_buf, sizeof(_buf), fmt, ap);
    __builtin_va_end(ap);
    if (n > 0) {
        unsigned long len = (unsigned long)n;
        if (len > sizeof(_buf) - 1) len = sizeof(_buf) - 1;
        long r;
        __asm__ volatile(
            "mov x0, #2\n"      /* fd = stderr           */
            "mov x1, %1\n"      /* buf                   */
            "mov x2, %2\n"      /* count                 */
            "mov x16, #4\n"     /* SYS_write             */
            "svc #0x80\n"       /* BSD syscall trap       */
            "mov %0, x0"
            : "=r"(r) : "r"(_buf), "r"(len)
            : "x0","x1","x2","x16","memory");
    }
    return n;
}
#define fprintf(stream, ...) _safe_fprintf_stderr(__VA_ARGS__)
```

This exists because the applications are linked against libSystem via TBD stubs
(see Chapter 15), and the `FILE*` for `stderr` is a data symbol that may not be
correctly resolved at link time in the freestanding environment.  The inline
syscall ensures logging always works regardless of `FILE*` state.

#### Application Startup Sequence

Every application follows the same startup sequence in `main()`:

```
1. objc_autoreleasePoolPush()
2. [NSApplication sharedApplication]     -- creates NSApp singleton
3. Create delegate class dynamically     -- objc_allocateClassPair + methods
4. objc_registerClassPair()
5. id delegate = [DelegateClass new]
6. [NSApp setDelegate:delegate]
7. [NSApp run]  (or custom run loop)     -- enters event loop
8. objc_autoreleasePoolPop(pool)         -- never reached in practice
```

Step 7 varies: Dock.app and Finder.app use `[NSApp run]` (the standard AppKit
run loop), while Terminal.app and SystemUIServer.app implement custom run loops
to interleave I/O polling with event dispatch.

#### Window Backing Store Flow

When an application creates an `NSWindow`, the following chain creates the
backing pixel buffer and connects it to WindowServer:

```
   NSWindow -initWithContentRect:styleMask:backing:defer:
       |
       +---> calloc(width * height * 4)          backing store (BGRA)
       +---> CGBitmapContextCreate()             wraps pixel buffer
       +---> _WSCreateWindow(x, y, w, h)         Mach IPC to WindowServer
       |         |
       |         +---> WS allocates window slot
       |         +---> Returns window_id
       |
       +---> Stores window_id for future IPC
```

When the view tree is dirty, the display cycle is:

```
   [window displayIfNeeded]
       |
       +---> [contentView drawRect:bounds]
       |         |
       |         +---> [NSGraphicsContext currentContext]
       |         +---> [ctx CGContext]   --> backing CGBitmapContext
       |         +---> CG drawing calls write to pixel buffer
       |
       +---> _WSDrawRect(window_id, 0, 0, w, h, pixels, size)
                  |
                  +---> Mach OOL message with pixel data
                  +---> WindowServer composites into framebuffer
```

---

### 14.2  Dock.app -- Desktop & Dock Bar

**Source**: `userland/apps/Dock.app/Dock.m` (271 lines)

On macOS, the Dock process serves a dual purpose: it renders the desktop
background (via `CGSSetDesktopBackground`) and the dock bar at the bottom of the
screen.  Kiseki's Dock.app faithfully replicates this two-window architecture.

#### Two-Window Architecture

Dock.app creates exactly two borderless windows:

```
+------------------------------------------------------------------+
|                                                                  |  Window 1: "Desktop"
|                                                                  |  Frame: (0, 0, 1280, 800)
|                  Desktop Background                              |  Style: Borderless
|                  (Blue-teal gradient)                             |  Z-order: orderBack (behind all)
|                                                                  |
|                                                                  |
|                                                                  |
+------------------------------------------------------------------+
| [  Finder  ] [  Terminal ] [  System  ]                          |  Window 2: "Dock"
+------------------------------------------------------------------+  Frame: (0, 746, 1280, 54)
                                                                      Style: Borderless
                                                                      Z-order: Front
```

The **desktop window** is fullscreen (1280x800) and sent to the back via
`[desktopWindow orderBack:nil]`, which sends a `WS_ORDER_BACK` message to
WindowServer.  This mirrors macOS, where the desktop window uses
`kCGDesktopWindowLevel`.

The **dock bar window** is a 54-pixel-tall strip at the bottom of the screen
(y=746, since SCREEN_HEIGHT - DOCK_HEIGHT = 800 - 54 = 746), brought to front
via `[dockWindow makeKeyAndOrderFront:nil]`.

#### Desktop Gradient Rendering

The desktop is not a flat colour -- `_DesktopDrawRect` simulates a gradient
by drawing 200 horizontal bands (4 pixels each), interpolating RGB values
from top to bottom (`Dock.m:167-174`):

```c
for (int y = 0; y < SCREEN_HEIGHT; y += 4) {
    CGFloat t = (CGFloat)y / (CGFloat)SCREEN_HEIGHT;  /* 0.0 -> 1.0 */
    CGFloat r = 0.05 + t * 0.10;   /* 0.05 -> 0.15 */
    CGFloat g = 0.20 + t * 0.15;   /* 0.20 -> 0.35 */
    CGFloat b = 0.40 + t * 0.15;   /* 0.40 -> 0.55 */
    CGContextSetRGBFillColor(ctx, r, g, b, 1.0);
    CGContextFillRect(ctx, CGRectMake(0, y, SCREEN_WIDTH, 4));
}
```

This produces a dark teal gradient reminiscent of macOS Big Sur's default
wallpaper, using only `CGContextFillRect` calls -- since Kiseki's CoreGraphics
has no gradient API.

#### Dock Bar Icon Rendering

The dock bar displays three icons as coloured squares with text labels,
defined in a static array (`Dock.m:84-88`):

| Icon     | Colour       | RGB                |
|----------|--------------|--------------------|
| Finder   | Blue         | (0.25, 0.55, 0.95) |
| Terminal | Dark grey    | (0.15, 0.15, 0.15) |
| System   | Light grey   | (0.70, 0.70, 0.70) |

Icons are 40x40 pixels, centred horizontally with 8-pixel padding between them.
Each icon is a filled rectangle with a 0.3-alpha white border (via
`CGContextStrokeRect`) and a text label rendered inside using
`CGContextShowTextAtPoint` -- truncated to 5 characters maximum.

The dock bar itself has a dark translucent background (RGBA 0.15, 0.15, 0.15,
0.85) with a subtle 1-pixel top separator line in lighter grey.

#### macOS Comparison

| Feature           | macOS Dock              | Kiseki Dock.app       |
|-------------------|-------------------------|-----------------------|
| Desktop rendering | CGSSetDesktopImage      | Manual gradient fill  |
| Dock position     | Bottom/Left/Right       | Bottom only           |
| Icon source       | Bundle icons            | Coloured rectangles   |
| Magnification     | Yes                     | No                    |
| App launching     | LaunchServices          | Not implemented       |
| Window level      | kCGDesktopWindowLevel   | orderBack             |
| Spaces            | Multiple                | Single                |

---

### 14.3  Finder.app -- File Browser

**Source**: `userland/apps/Finder.app/Finder.m` (925 lines)

Finder.app is the largest and most interactive of the four applications.  It is
a fully functional file browser that reads the real filesystem via POSIX
`opendir`/`readdir`/`stat` syscalls and displays files with type-specific icons.

#### Layout

The Finder window is divided into three regions:

```
+-----+---------------------------------------------+
|     |  < Back            /Users                    |  Header (28px)
+-----+---------------------------------------------+
|Fav- |  [D] Applications                       --  |
|our- |  [D] System                              --  |
|ites |  [D] bin                                 --  |
|     |  [F] hello                           4 KB   |
|  /  |  [X] test_libc                       12 KB  |
| App |  [L] sh -> bash                          --  |
| Sys |                                              |
| Usr |                                              |
| bin |                                              |
| sbin|                                              |
| etc |                                              |
| tmp |                                              |
+-----+---------------------------------------------+
  120px                    380px
```

- **Header** (28px tall): Back button (if not at root), current path display
- **Sidebar** (120px wide): 8 hardcoded favourite paths
- **Content area**: Scrollable file listing with Name and Size columns

#### Directory Reading

`finder_read_directory()` (`Finder.m:234-325`) scans the current directory:

1. `opendir(g_current_path)` opens the directory
2. `readdir()` loop fills up to 128 `FinderEntry` structs
3. `.` and `..` are skipped
4. `stat()` on each entry determines mode, size, and type flags
5. `.app` bundles detected by checking if a directory name ends in ".app"
6. Entries are sorted: directories first, then alphabetically within each group
   (bubble sort -- adequate for <= 128 entries)

Each `FinderEntry` carries classification flags:

```c
/* Finder.m:186-196 */
typedef struct {
    char        name[256];
    uint8_t     d_type;
    mode_t      mode;
    off_t       size;
    BOOL        is_dir;
    BOOL        is_symlink;
    BOOL        is_executable;
    BOOL        is_device;
    BOOL        is_app_bundle;
} FinderEntry;
```

#### Type-Specific Icons

Each file type gets a distinctive coloured icon (16x16 pixels):

| Type          | Colour                  | Indicator   |
|---------------|-------------------------|-------------|
| .app bundle   | Dark slate (0.40,0.40)  | White "A"   |
| Directory     | Blue (0.30,0.60,0.95)   | Tab shape   |
| Symlink       | Cyan (0.30,0.80,0.80)   | White "@"   |
| Device        | Orange (0.90,0.60,0.20) | Solid block |
| Executable    | Green (0.30,0.75,0.30)  | Solid block |
| Regular file  | White with grey border  | Empty       |

Directory icons have an additional 3-pixel "tab" above the left portion,
mimicking the folder tab appearance.

#### Navigation

Three navigation mechanisms are supported:

- **Double-click**: Enters directories or launches executables/apps
- **Sidebar click**: Jumps to one of 8 favourite paths
- **Back button**: `finder_navigate_parent()` strips the last path component
- **Keyboard**: Up/Down arrows move selection, Enter opens, Backspace goes up
- **Scroll wheel**: Adjusts `g_scroll_offset` by +/-3 entries per scroll event

Path construction (`Finder.m:340-350`) handles trailing-slash ambiguity:

```c
static void finder_navigate_into(const char *name) {
    char newpath[PATH_MAX];
    size_t plen = strlen(g_current_path);
    if (plen > 0 && g_current_path[plen - 1] == '/')
        snprintf(newpath, PATH_MAX, "%s%s", g_current_path, name);
    else
        snprintf(newpath, PATH_MAX, "%s/%s", g_current_path, name);
    finder_navigate_to(newpath);
}
```

#### Application Launching

Double-clicking an executable or `.app` bundle triggers `finder_open_item()`
(`Finder.m:484-510`):

For **.app bundles**, the convention is that `Foo.app/Foo` is the executable
(matching the disk layout created by `mkdisk.sh`).
`finder_resolve_app_executable()` strips the `.app` suffix to derive the binary
name:

```
/Applications/Terminal.app  -->  /Applications/Terminal.app/Terminal
```

For **plain executables**, the full path is used directly.

The launch itself (`Finder.m:440-478`) follows the Unix pattern:

```
fork()
  |
  +--- Child:
  |      setsid()                     -- new session
  |      Build envp from getenv()     -- HOME, USER, PATH, TERM, etc.
  |      execve(exe_path, argv, envp) -- replace with target
  |      _exit(127)                   -- only reached on failure
  |
  +--- Parent:
         returns immediately           -- no waitpid (fire and forget)
```

The child inherits the environment from the parent (Finder itself was launched
by loginwindow with proper HOME, USER, etc.), constructing environment strings
on the stack before calling `execve`.

#### Finder State Management

All state is in global variables:

| Variable          | Type              | Purpose                  |
|-------------------|-------------------|--------------------------|
| `g_current_path`  | `char[1024]`      | Current directory path   |
| `g_entries`       | `FinderEntry[128]`| Directory listing cache  |
| `g_entry_count`   | `int`             | Number of entries        |
| `g_selected_idx`  | `int`             | Selected row (-1=none)   |
| `g_scroll_offset` | `int`             | Scroll position          |
| `g_finderView`    | `NSView*`         | Cached for setNeedsDisplay |
| `g_finderWindow`  | `NSWindow*`       | Cached for operations    |

This single-window, single-directory design means Finder.app supports only one
browser window at a time -- a simplification compared to macOS Finder's
multi-window, multi-tab model.

---

### 14.4  Terminal.app -- VT100 Terminal Emulator

**Source**: `userland/apps/Terminal.app/Terminal.m` (1,071 lines)

Terminal.app is the most complex application in Kiseki.  It allocates a
pseudo-terminal (PTY) pair, forks a shell process (`/bin/bash`), and runs a
full VT100/ANSI terminal emulator with 8-colour SGR support.

#### Architecture Overview

```
+-------------------------------------------------------+
|  Terminal.app (parent process)                         |
|                                                        |
|  +-------------+    +------------------+               |
|  | Custom Run  |    | VT100 Emulator   |               |
|  | Loop        |--->| (5-state parser) |               |
|  |             |    | 80x24 cell grid  |               |
|  | 1. Poll WS  |    +--------+---------+               |
|  | 2. Read PTY |             |                         |
|  | 3. Display  |    +--------v---------+               |
|  +------+------+    | TerminalView     |               |
|         |           | (drawRect:)      |               |
|         |           +------------------+               |
|         |                                              |
+---------|----------------------------------------------+
          | PTY master fd (non-blocking read/write)
          |
  ========|================ kernel PTY layer =============
          |
+---------|----------------------------------------------+
|  /bin/bash (child process)                             |
|         |                                              |
|    stdin/stdout/stderr = PTY slave                     |
|    setsid() + TIOCSCTTY (controlling terminal)         |
+--------------------------------------------------------+
```

#### PTY Setup

`term_setup_pty()` (`Terminal.m:635-723`) establishes the terminal connection:

1. `openpty(&master, &slave, NULL, NULL, NULL)` -- allocates a PTY pair
2. `fcntl(master, F_SETFL, O_NONBLOCK)` -- master fd is non-blocking
3. `fork()` -- splits into parent and child
4. **Child process**:
   - `close(master)` -- child only needs the slave side
   - `setsid()` -- create new session (detach from parent's terminal)
   - `ioctl(slave, TIOCSCTTY, 0)` -- make slave the controlling terminal
   - `ioctl(slave, TIOCSWINSZ, &ws)` -- set window size (80x24, 640x384)
   - `dup2(slave, 0/1/2)` -- redirect stdin/stdout/stderr to slave
   - `execve(shell, argv, envp)` -- replace with shell
   - Falls back: user's shell -> /bin/bash -> /bin/sh -> `_exit(127)`
5. **Parent**: closes slave fd, stores master fd and child PID

The child's environment includes `TERM=vt100`, `COLUMNS=80`, `LINES=24`.

#### VT100 Emulator -- 5-State Parser

The terminal emulator is a character-at-a-time state machine matching the
implementation in WindowServer's built-in terminal (which itself follows XNU's
`gc_putchar` in `osfmk/console/video_console.c`).

```
                  ESC
  +--------+   (0x1B)   +--------+     '['     +-----------+
  | NORMAL |----------->|  ESC   |------------>| CSI_INIT  |
  +---+----+            +---+----+             +-----+-----+
      |                     |                        |
      | printable           | c,D,M,7,8              | clears params,
      | char: write         | (special ESC           | falls through to
      | to cell grid        |  commands)              | CSI_PARS
      |                     v                        v
      |                 (back to              +-----------+
      |                  NORMAL)              | CSI_PARS  |<--+
      |                                       +-----+-----+   |
      |                                  digit|     |';'      |
      |                              (accum   |     |(next    |
      |                               param)  +-----+ param)  |
      |                                       |               |
      |                         '?'           | letter        |
      |                    +-----------+      | (dispatch)    |
      |                    | DEC_PRIV  |      v               |
      |                    +-----+-----+  (back to            |
      |                          |         NORMAL)            |
      |                     h/l  |                            |
      |                     (DECAWM                           |
      |                      toggle)                          |
      v                          v                            |
 (cell grid                 (back to                          |
  update)                    NORMAL)                          |
```

The five states and their transitions:

| State     | Entered When         | Processes                                   |
|-----------|----------------------|---------------------------------------------|
| NORMAL    | Default / after CSI  | Printable chars, control chars (BS,TAB,LF,CR,ESC) |
| ESC       | ESC (0x1B) received  | `[` -> CSI_INIT; `c` -> reset; `D` -> index down; `M` -> reverse index; `7`/`8` -> save/restore cursor |
| CSI_INIT  | `[` after ESC        | Clears params, falls through to CSI_PARS    |
| CSI_PARS  | Digit/`;` in CSI     | Accumulates numeric params; letter dispatches CSI command |
| DEC_PRIV  | `?` in CSI           | Handles DEC private modes (DECAWM via `?7h`/`?7l`) |

#### CSI Command Support

`term_csi_dispatch()` (`Terminal.m:333-484`) handles these CSI sequences:

| CSI Code | Name                      | Effect                              |
|----------|---------------------------|-------------------------------------|
| `A`      | Cursor Up                 | Move cursor up N rows               |
| `B`      | Cursor Down               | Move cursor down N rows             |
| `C`      | Cursor Forward            | Move cursor right N columns         |
| `D`      | Cursor Backward           | Move cursor left N columns          |
| `H`/`f`  | Cursor Position           | Move to (row, col) -- 1-based       |
| `G`      | Cursor Horizontal Abs     | Move to column N                    |
| `d`      | Cursor Vertical Abs       | Move to row N                       |
| `J`      | Erase in Display          | 0=below, 1=above, 2=all            |
| `K`      | Erase in Line             | 0=right, 1=left, 2=entire line      |
| `X`      | Erase Characters          | Clear N chars from cursor           |
| `P`      | Delete Characters         | Delete N chars, shift left          |
| `L`      | Insert Lines              | Insert N blank lines at cursor      |
| `M`      | Delete Lines              | Delete N lines, scroll up           |
| `m`      | SGR (colours/attributes)  | See below                           |
| `r`      | Set Scrolling Region      | (Simplified: resets cursor to 0,0)  |

#### SGR Colour and Attribute Support

The `m` command (`Terminal.m:457-475`) processes Select Graphic Rendition:

| SGR Code  | Effect                        |
|-----------|-------------------------------|
| 0         | Reset all attributes          |
| 1         | Bold on                       |
| 4         | Underline on                  |
| 7         | Reverse video on              |
| 22        | Bold off                      |
| 24        | Underline off                 |
| 27        | Reverse off                   |
| 30-37     | Set foreground (8 ANSI colours)|
| 39        | Default foreground            |
| 40-47     | Set background (8 ANSI colours)|
| 49        | Default background            |

Colours are stored as 3-bit indices into two lookup tables
(`Terminal.m:197-203`): normal and bright (used when bold is active).  The
8-colour ANSI palette:

| Index | Normal          | Bright          |
|-------|-----------------|-----------------|
| 0     | Black (0,0,0)   | Dark grey       |
| 1     | Red             | Bright red      |
| 2     | Green           | Bright green    |
| 3     | Yellow/brown    | Bright yellow   |
| 4     | Blue            | Bright blue     |
| 5     | Magenta         | Bright magenta  |
| 6     | Cyan            | Bright cyan     |
| 7     | Light grey      | White           |

#### Cell Grid and Rendering

The terminal state is a struct-of-arrays for 80x24 = 1,920 cells:

```c
/* Terminal.m:211-244 */
static struct {
    unsigned char   cells[24][80];       /* ASCII character       */
    uint8_t         cell_fg[24][80];     /* Foreground colour idx */
    uint8_t         cell_bg[24][80];     /* Background colour idx */
    uint8_t         cell_attr[24][80];   /* ATTR_BOLD/UNDERLINE/REVERSE */

    uint32_t        cur_col, cur_row;    /* Cursor position       */
    int             vt_state;            /* Parser state          */
    uint32_t        vt_par[16];          /* CSI parameters        */
    uint32_t        vt_numpars;          /* Number of params      */
    uint8_t         vt_attr;             /* Current attributes    */
    uint8_t         vt_fg_idx, vt_bg_idx;/* Current colours       */
    int             vt_wrap_mode;        /* DECAWM                */

    /* Saved cursor state (DECSC/DECRC via ESC 7 / ESC 8) */
    uint32_t        saved_col, saved_row;
    uint8_t         saved_attr, saved_fg_idx, saved_bg_idx;

    int             dirty;               /* Needs redraw flag     */
} term;
```

`_TerminalDrawRect` (`Terminal.m:756-854`) renders every cell on each
redraw:

1. For each of the 1,920 cells:
   - Compute foreground/background RGB from colour index + bold/reverse flags
   - Fill background rectangle (8x16 pixels)
   - If character is printable (0x21-0x7E), draw with `CGContextShowTextAtPoint`
   - If underline flag set, draw a 1-pixel line at the bottom
2. Draw block cursor at `(cur_col, cur_row)` with inverted colours

The total rendering area is 640x384 pixels (80 * 8 x 24 * 16).

#### Custom Run Loop with PTY Polling

Terminal.app cannot use `[NSApp run]` because it needs to interleave PTY reads
with event processing.  Instead, `main()` implements a custom event loop
(`Terminal.m:1049-1067`):

```c
/* Step 1: finishLaunching (sends applicationDidFinishLaunching:) */
[NSApp finishLaunching];

/* Step 2: Interleaved event loop */
for (;;) {
    /* 2a. Poll WindowServer for one event (10ms timeout) */
    NSEvent *event = [NSApp nextEventMatchingMask:0xFFFFFFFF
                                        untilDate:nil
                                           inMode:CFSTR("kCFRunLoopDefaultMode")
                                          dequeue:YES];
    if (event) [NSApp sendEvent:event];

    /* 2b. Non-blocking read from PTY master, feed VT100 parser */
    term_poll_and_redraw();

    /* 2c. Push dirty pixels to WindowServer */
    if (g_window) [g_window displayIfNeeded];
}
```

`term_poll_and_redraw()` (`Terminal.m:935-956`) does:
1. `read(master_fd, buf, 4096)` -- non-blocking (returns EAGAIN if no data)
2. Feed each byte through `term_putc()` (the VT100 state machine)
3. If `term.dirty`, mark the view for redraw
4. `waitpid(shell_pid, WNOHANG)` to detect shell exit

#### Keyboard Input

`_TerminalKeyDown` (`Terminal.m:861-929`) translates WindowServer key events
into bytes written to the PTY master:

- **Arrow keys**: Send VT100 escape sequences (`\033[A`/`B`/`C`/`D`)
- **Home/End**: `\033[H` / `\033[F`
- **Delete**: `\033[3~`
- **Page Up/Down**: `\033[5~` / `\033[6~`
- **Ctrl+letter**: Converts to control character (ch - 'a' + 1)
- **Regular ASCII**: Written as single bytes

Key codes are Linux-style HID keycodes matching WindowServer's VirtIO input
driver (e.g., KEY_UP=103, KEY_DOWN=108).

---

### 14.5  SystemUIServer.app -- Menu Bar Clock

**Source**: `userland/apps/SystemUIServer.app/SystemUIServer.m` (289 lines)

SystemUIServer.app is the simplest of the four applications.  On macOS,
SystemUIServer manages the right side of the menu bar: clock, Wi-Fi, battery,
volume, Spotlight, etc.  Kiseki's version displays only a clock.

#### Window Placement

SystemUIServer creates a single borderless window positioned to overlap the
menu bar area that WindowServer renders:

```
+--------------------------------------------------+--[HH:MM]--+
|  [App Name]  File  Edit  View                    |            |
+--------------------------------------------------+            |
|                                                   | 160 x 22  |
|                         (desktop)                 | at (1120,0)|
                                                    +------------+
```

The window is 160x22 pixels at position (1120, 0), which places it in the
top-right corner of the 1280x800 screen.  The 22-pixel height matches the
menu bar height.  The background colour (0.96, 0.96, 0.96) exactly matches
WindowServer's menu bar rendering, so the clock blends seamlessly.

#### Time Computation

`_clockGetTimeString()` (`SystemUIServer.m:82-111`) derives HH:MM from
`CFAbsoluteTimeGetCurrent()`:

```c
CFAbsoluteTime now = CFAbsoluteTimeGetCurrent();

/* Convert to seconds-of-day (UTC) */
double day_seconds = now - (double)((long)(now / 86400.0)) * 86400.0;
if (day_seconds < 0.0) day_seconds += 86400.0;

int total_minutes = (int)(day_seconds / 60.0);
int hours   = (total_minutes / 60) % 24;
int minutes = total_minutes % 60;
```

`CFAbsoluteTime` is seconds since 2001-01-01 00:00:00 UTC.  The code
extracts the time-of-day by computing `now mod 86400`.  If the kernel has
no real-time clock (which is the case on QEMU without RTC passthrough), the
function falls back to displaying "12:00".

The time string is always exactly 5 characters ("HH:MM"), formatted
character-by-character without any printf-family function:

```c
buf[0] = '0' + (hours / 10);
buf[1] = '0' + (hours % 10);
buf[2] = ':';
buf[3] = '0' + (minutes / 10);
buf[4] = '0' + (minutes % 10);
buf[5] = '\0';
```

#### Minute-Based Update Polling

Like Terminal.app, SystemUIServer uses a custom run loop rather than
`[NSApp run]`.  A static variable `g_lastMinuteDrawn` tracks the last
displayed minute.  `_clockNeedsUpdate()` (`SystemUIServer.m:209-224`)
compares the current minute-of-day to the last drawn value:

```c
static BOOL _clockNeedsUpdate(void) {
    CFAbsoluteTime now = CFAbsoluteTimeGetCurrent();
    if (now <= 0.0) return NO;

    /* ... compute current_minute (0..1439) ... */

    if (current_minute != g_lastMinuteDrawn) {
        g_lastMinuteDrawn = current_minute;
        return YES;
    }
    return NO;
}
```

This ensures the clock view redraws only when the minute changes, not on every
event loop iteration.  The event loop polls WindowServer with no timeout
(`untilDate:nil`), processes any events, checks the clock, and calls
`displayIfNeeded`.

#### macOS Comparison

| Feature            | macOS SystemUIServer          | Kiseki SystemUIServer    |
|--------------------|-------------------------------|--------------------------|
| Clock update       | CFRunLoopTimer (60s)          | Polling on every iteration|
| Menu extras        | NSStatusItem API              | None                     |
| Wi-Fi/BT/Battery   | IOKit power assertions        | Not implemented          |
| Spotlight          | Search field                  | Not implemented          |
| Time zone          | ICU / NSTimeZone              | UTC only                 |
| Window level       | NSStatusWindowLevel           | Regular borderless       |

---

## Chapter 15: Build System & Toolchain

Kiseki's build system produces a bootable system from source using two
completely separate toolchains: a bare-metal GCC cross-compiler for the kernel
and macOS Clang for the Mach-O userland.  This chapter walks through the entire
pipeline from `make world` to a running QEMU instance.

### 15.1  Build Overview -- `make world`

The top-level `Makefile` (359 lines) provides a single command to build
everything:

```
$ make world
```

This executes three phases in order:

```
  make world
    |
    +---> make all        [1] Build kernel (ELF)
    |       |
    |       +---> check-toolchain     Verify aarch64-*-gcc exists
    |       +---> Compile .S files    boot.S, vectors.S, context_switch.S
    |       +---> Compile .c files    50 kernel C files
    |       +---> Link kiseki.elf     Static ELF with custom linker script
    |       +---> objcopy kiseki.bin  Flat binary for QEMU -kernel
    |
    +---> make userland   [2] Build userland (Mach-O)
    |       |
    |       +---> dyld                MH_DYLINKER binary
    |       +---> libSystem           MH_DYLIB (libSystem.B.dylib)
    |       +---> IOKit               MH_DYLIB framework
    |       +---> libobjc             MH_DYLIB (libobjc.A.dylib)
    |       +---> CoreFoundation      MH_DYLIB framework
    |       +---> CoreGraphics        MH_DYLIB framework
    |       +---> CoreText            MH_DYLIB framework
    |       +---> Foundation          MH_DYLIB framework (ObjC)
    |       +---> AppKit              MH_DYLIB framework (ObjC)
    |       +---> sbin                MH_EXECUTE (init, getty, WindowServer...)
    |       +---> apps                MH_EXECUTE (Dock, Finder, Terminal, SystemUIServer)
    |       +---> bash                MH_EXECUTE
    |       +---> coreutils           MH_EXECUTE (50+ programs)
    |       +---> nettools            MH_EXECUTE (ifconfig, ping, nc, curl, ntpdate)
    |       +---> tcc                 MH_EXECUTE (Tiny C Compiler)
    |       +---> tests               MH_EXECUTE (test_libc, etc.)
    |
    +---> make disk       [3] Create ext4 disk image
            |
            +---> scripts/mkdisk.sh   Creates 64MB ext4 image
            +---> Installs all binaries, configs, LaunchDaemons
```

### 15.2  Kernel Build -- Bare-Metal ELF

#### Toolchain Detection

The Makefile auto-detects the cross-compiler by trying prefixes in order
(`Makefile:20-25`):

1. `aarch64-none-elf-gcc` (ARM official toolchain)
2. `aarch64-elf-gcc` (Homebrew on macOS)
3. `aarch64-linux-gnu-gcc` (Debian/Ubuntu packages)
4. `aarch64-unknown-elf-gcc` (custom builds)

If none is found, `make` fails with installation instructions for macOS
(Homebrew), Debian, and Arch Linux.

#### Compiler Flags

```makefile
CFLAGS := -Wall -Wextra -Werror \
          -ffreestanding -fno-builtin -fno-stack-protector \
          -nostdinc -nostdlib \
          -mcpu=cortex-a72 -mgeneral-regs-only -mno-outline-atomics \
          -std=gnu11 -O2 -g \
          $(PLATFORM_DEF) $(DEBUG_DEF) $(INCLUDES)
```

Key flags explained:

| Flag                     | Purpose                                              |
|--------------------------|------------------------------------------------------|
| `-ffreestanding`         | No hosted environment; compiler won't assume libc exists |
| `-fno-builtin`           | Don't replace patterns like memcpy loops with calls  |
| `-fno-stack-protector`   | No stack canaries (no `__stack_chk_guard` available) |
| `-nostdinc -nostdlib`    | No system headers or libraries                       |
| `-mcpu=cortex-a72`       | ARMv8.0 instruction set, Cortex-A72 scheduling       |
| `-mgeneral-regs-only`    | Forbid FP/NEON in kernel code (avoids saving q0-q31) |
| `-mno-outline-atomics`   | Inline atomics (no `__aarch64_ldadd4_acq_rel` calls) |
| `-std=gnu11`             | C11 with GNU extensions (asm labels, attributes)     |

The `-mgeneral-regs-only` flag is critical: it prevents the compiler from using
NEON/FP registers in kernel code, so the kernel only needs to save/restore GPRs
during context switches.  FP/NEON state is only saved on traps from EL0 (user
mode), where the full 816-byte trap frame includes q0-q31.

#### Source Organisation

The kernel is compiled from 50 C files and 3 assembly files, organised by
subsystem:

| Category    | Source Directory              | Files | Description              |
|-------------|-------------------------------|-------|--------------------------|
| Boot/Arch   | `kernel/arch/arm64/`          | 4     | boot.S, vectors.S, context_switch.S, smp.c |
| Kernel Core | `kernel/kern/`                | 14    | main, pmm, vmm, sched, sync, proc, trap, tty, pty, fbconsole, macho, commpage, kprintf, font8x16 |
| Drivers     | `kernel/drivers/`             | 10    | PL011, GICv2, timer, VirtIO (blk/gpu/input/net), eMMC, blkdev |
| BSD         | `kernel/bsd/`                 | 2     | syscalls, security       |
| Mach        | `kernel/mach/`                | 1     | ipc                      |
| IOKit       | `kernel/iokit/`               | 11    | Object model, registry, services, framebuffer, HID |
| Filesystem  | `kernel/fs/`                  | 4     | vfs, ext4, buf, devfs    |
| Networking  | `kernel/net/`                 | 7     | socket, tcp, ip, eth, icmp, udp, dhcp |

Assembly sources are ordered carefully: `boot.S` must be first because the
linker script places `*boot.o(.text)` at the entry point address.

#### Linker Script

`kernel/arch/arm64/linker-qemu.ld` (95 lines) defines the kernel memory layout:

```
ENTRY(_start)
KERNEL_PHYS_BASE = 0x40080000;

MEMORY {
    RAM (rwx) : ORIGIN = 0x40080000, LENGTH = 960M
}
```

QEMU's virt machine loads the kernel at 0x40080000 (RAM starts at 0x40000000,
first 512KB is reserved for DTB/firmware).  The sections are:

```
  0x40080000  +------------------+  __text_start
              |  .text           |  boot.S first, then vectors.S, then all .text
              +------------------+  __text_end
              |  .rodata (4K)    |  Read-only data (aligned to page boundary)
              +------------------+
              |  .data (4K)      |  Initialised data
              +------------------+
              |  .bss (4K)       |  Zero-initialised data
              +------------------+  __kernel_end
              |  .stack (NOLOAD) |  Per-CPU stacks: 32KB * 4 cores = 128KB
              +------------------+  __stack_top
              |                  |  __heap_start: buddy allocator starts here
              v  (free memory)   v
```

The linker script exports symbols used by kernel code:
- `__bss_start` / `__bss_end` -- zeroed by boot.S
- `__stack_top` -- initial SP; each core uses `__stack_top - core_id * 0x8000`
- `__heap_start` -- PMM starts allocating from here
- `__kernel_end` -- used to calculate kernel image size

Per-CPU stacks are 32KB each (`KERNEL_STACK_SIZE = 0x8000`), placed in a
NOLOAD section (no data in the ELF, just address reservations).

#### Linking and Output

```makefile
$(KERNEL_ELF): $(ALL_OBJS) $(LDSCRIPT)
    $(LD) -nostdlib -static -T $(LDSCRIPT) -Map=$(KERNEL_MAP) $(ALL_OBJS) -o $@

$(KERNEL_BIN): $(KERNEL_ELF)
    $(OBJCOPY) -O binary $< $@
```

The kernel links statically into a single ELF binary, then `objcopy` strips it
to a flat binary.  QEMU's `-kernel` flag accepts ELF directly, so `kiseki.elf`
is what actually boots.

### 15.3  Userland Build -- Mach-O with macOS Clang

The entire userland is compiled on macOS using the host `clang` with
`-target arm64-apple-macos11`.  This produces genuine arm64 Mach-O binaries
that Kiseki's dyld can load.

#### Why macOS Clang?

Kiseki's userland uses real Mach-O binaries -- the same binary format as macOS.
Using macOS `clang` as the cross-compiler means:

1. The linker (`ld64`) produces correct Mach-O with LC_LOAD_DYLIB, LC_MAIN,
   chained fixups, and all standard load commands
2. TBD (text-based definition) stubs work natively for declaring library exports
3. Framework install names (`-install_name`) are handled correctly
4. The ObjC compiler supports `-fobjc-runtime=gnustep-1.9` for the non-Apple
   ObjC ABI

The key difference from a real macOS build is that every binary uses
`-nostdlib -ffreestanding` and links against custom TBD stubs instead of
the system libraries.

#### TBD Stub Linking

Text-Based Definition (TBD) files are YAML documents that describe a dynamic
library's exported symbols without containing any code.  They tell the linker
"this library exists at this install path and exports these symbols", so it can
generate the correct LC_LOAD_DYLIB and fixup records.

Example (`userland/AppKit/libSystem.tbd`, 22 lines):

```yaml
--- !tapi-tbd
tbd-version:     4
targets:         [ arm64-macos ]
install-name:    '/usr/lib/libSystem.B.dylib'
current-version: 1.0.0
exports:
  - targets:     [ arm64-macos ]
    symbols:     [ _malloc, _calloc, _free, _memcpy, _strlen,
                   _printf, _fprintf, ___stderrp, ___stdoutp,
                   _pthread_mutex_init, _pthread_mutex_lock,
                   _mach_msg, _mach_task_self_,
                   _bootstrap_look_up, _bootstrap_register,
                   ___stack_chk_fail, ___stack_chk_guard ]
```

Each userland component has its own set of TBD files for the libraries it
depends on.  This is how the link-time dependency graph is established without
needing the actual dylib binaries during compilation.

#### Build Dependency Order

The userland Makefile (`userland/Makefile:36`) specifies a build order that
respects the framework dependency chain:

```
dyld -> libSystem -> IOKit -> libobjc -> CoreFoundation -> CoreGraphics
     -> CoreText -> Foundation -> AppKit -> sbin -> apps -> bash
     -> coreutils -> nettools -> tcc -> tests
```

Each component is built by delegating to its own sub-Makefile:

```makefile
dyld:
    @$(MAKE) -C dyld

libsystem:
    @$(MAKE) -C libSystem dylib

appkit:
    @$(MAKE) -C AppKit
```

#### Component Build Modes

Different userland components use different build pipelines:

| Component       | Language | Pipeline                              | Output Type   |
|-----------------|----------|---------------------------------------|---------------|
| dyld            | C + ASM  | clang -ffreestanding -> ld -dylinker  | MH_DYLINKER   |
| libSystem       | C        | clang -shared -> dylib                | MH_DYLIB      |
| IOKit/CF/CG/CT  | C        | clang -shared -> framework dylib      | MH_DYLIB      |
| libobjc         | C/C++    | clang -shared -> dylib                | MH_DYLIB      |
| Foundation      | ObjC     | COMDAT pipeline -> framework dylib    | MH_DYLIB      |
| AppKit          | ObjC     | COMDAT pipeline -> framework dylib    | MH_DYLIB      |
| sbin programs   | C        | clang -> executable                   | MH_EXECUTE    |
| GUI apps        | ObjC     | COMDAT pipeline -> executable         | MH_EXECUTE    |
| bash/coreutils  | C        | clang -> executable                   | MH_EXECUTE    |

#### dyld Build

dyld is special: it must be completely self-contained with no dynamic library
dependencies.  Its linker flags (`userland/dyld/Makefile:85-91`):

```makefile
LDFLAGS := -target arm64-apple-macos11 \
           -nostdlib -static \
           -Wl,-dylinker \              # MH_DYLINKER filetype (7)
           -Wl,-e,_start \              # Entry point
           -Wl,-dylinker_install_name,/usr/lib/dyld
```

The `-static` flag ensures no LC_LOAD_DYLIB commands.  The `make verify`
target checks this:

```makefile
verify:
    @if otool -l $(TARGET) | grep -q LC_LOAD_DYLIB; then
        echo "ERROR: dyld must not have LC_LOAD_DYLIB!"; exit 1; fi
    @if ! otool -h $(TARGET) | grep -qE '\s7\s'; then
        echo "ERROR: dyld must be MH_DYLINKER filetype (7)!"; exit 1; fi
```

#### libSystem Build

libSystem.B.dylib is a single-file compilation (`libSystem.c`, 7,948 lines)
producing a shared library:

```makefile
DYLIB_LDFLAGS := -target arm64-apple-macos11 \
                 -nostdlib -shared \
                 -Wl,-dylib \
                 -Wl,-install_name,/usr/lib/libSystem.B.dylib
```

It links against `dyld.tbd` to resolve the `dyld_stub_binder` symbol -- the
same circular dependency that exists in real macOS (dyld provides the lazy
binding stub resolver, but libSystem needs to reference it).

#### CPU Target: cortex-a53 vs cortex-a72

A subtle difference: the kernel is compiled with `-mcpu=cortex-a72` but the
userland uses `-mcpu=cortex-a53`.  Both are ARMv8.0, but cortex-a53 is more
conservative with atomics -- it uses `LDXR`/`STXR` (load-exclusive/store-
exclusive) loops instead of ARMv8.1 LSE atomics (`SWPAL`, `LDADD`, etc.).
This matters because QEMU TCG (software emulation) may have subtle differences
in LSE atomic behaviour, and the kernel's `-mno-outline-atomics` flag
separately ensures inline atomic operations.

### 15.4  The COMDAT-Stripping Pipeline

Objective-C code compiled with `-fobjc-runtime=gnustep-1.9` generates LLVM IR
that uses COMDAT groups for ObjC metadata (selector name strings, class
references, etc.).  COMDAT is an ELF feature that allows the linker to
deduplicate identical sections across translation units.  Mach-O has no COMDAT
support -- it uses a different mechanism (weak definitions) that Clang's
GNUstep runtime codegen does not emit correctly.

Kiseki solves this with a three-stage pipeline:

```
  .m source file
       |
       | Stage 1: clang -S -emit-llvm
       v
  .ll file (LLVM IR with COMDAT groups)
       |
       | Stage 2: sed transformations
       |   - linkonce_odr constant -> private constant
       |   - Remove "$.objc_sel_name.* = comdat any" lines
       |   - Remove ", comdat" suffixes
       v
  .clean.ll file (LLVM IR without COMDATs)
       |
       | Stage 3: llc -filetype=obj
       v
  .o file (valid Mach-O object)
       |
       | Stage 4: clang -Wl,-dylib (or -Wl,-e,_main)
       v
  Mach-O framework dylib (or executable)
```

The `sed` command (`AppKit/Makefile:65`):

```bash
sed 's/linkonce_odr constant/private constant/g;
     /^\$\.objc_sel_name.* = comdat any$/d;
     s/, comdat//g' \
    input.ll > output.clean.ll
```

Three transformations:
1. **`linkonce_odr constant` -> `private constant`**: ObjC selector name
   strings were `linkonce_odr` (deduplicated across TUs).  Since each framework
   is a single `.m` file, there is only one TU, so `private` is safe.
2. **Delete COMDAT group declarations**: Lines like
   `$.objc_sel_name.drawRect: = comdat any` are pure ELF metadata with no
   Mach-O equivalent.
3. **Remove `, comdat` suffixes**: Global definitions that referenced COMDAT
   groups (e.g., `@selector = ... , comdat`) need the reference stripped.

The cleaned IR is then compiled to a Mach-O object file by `llc` (from LLVM,
installed via Homebrew at `/opt/homebrew/opt/llvm/bin/llc`).

This pipeline is used by: Foundation.framework, AppKit.framework, Dock.app,
Finder.app, Terminal.app, and SystemUIServer.app -- every ObjC component.

### 15.5  Disk Image Creation -- mkdisk.sh

`scripts/mkdisk.sh` (835 lines) creates a bootable ext4 filesystem image and
populates it with the entire userland.

#### Image Creation

```bash
dd if=/dev/zero of=build/disk.img bs=1M count=64
mkfs.ext4 -q -b 4096 -L "kiseki-root" -O extents,dir_index build/disk.img
```

The image is 64MB with 4KB block size, ext4 extent trees, and directory
indexing.  The 4KB block size is important: it matches the kernel's page size
and ensures files larger than 48KB (12 direct blocks * 4KB) work correctly with
extent trees.

#### Platform-Specific Population

The script detects the host OS and uses different strategies:

- **Linux**: Loop-mounts the image (`mount -o loop`), copies files with `cp`,
  then unmounts.  Requires `sudo`.
- **macOS**: Uses `debugfs` from e2fsprogs (no mount needed).  Builds a command
  script with `write`, `mkdir`, and `symlink` directives, then runs
  `debugfs -w -f commands.txt disk.img`.

#### Filesystem Layout

The script creates the complete Unix directory hierarchy and installs all
binaries:

```
/
+-- bin/                 Essential commands (bash, cat, ls, grep, ...)
|   +-- sh -> bash       Symlink
+-- sbin/                System admin (init, getty, WindowServer, ...)
+-- usr/
|   +-- bin/             Non-essential (find, xargs, tcc, ...)
|   +-- lib/
|   |   +-- dyld                    Dynamic linker
|   |   +-- libSystem.B.dylib       C library
|   |   +-- libobjc.A.dylib         ObjC runtime
|   +-- include/         C headers (for TCC on-device compilation)
|       +-- stdio.h, stdlib.h, ...
|       +-- sys/, mach/, arpa/, netinet/, servers/
+-- System/
|   +-- Library/
|       +-- Frameworks/
|       |   +-- IOKit.framework/Versions/A/IOKit
|       |   +-- CoreFoundation.framework/Versions/A/CoreFoundation
|       |   +-- CoreGraphics.framework/Versions/A/CoreGraphics
|       |   +-- CoreText.framework/Versions/A/CoreText
|       |   +-- Foundation.framework/Versions/A/Foundation
|       |   +-- AppKit.framework/Versions/A/AppKit
|       +-- CoreServices/
|       |   +-- Dock.app/Dock
|       |   +-- Finder.app/Finder
|       |   +-- SystemUIServer.app/SystemUIServer
|       +-- LaunchDaemons/
|           +-- *.plist              Daemon configurations
+-- Applications/
|   +-- Terminal.app/Terminal
+-- Library/
|   +-- LaunchDaemons/               Third-party daemons
+-- etc/
|   +-- passwd                       root:x:0:0:root:/root:/bin/bash
|   +-- shadow                       root:toor:19000:...
|   +-- group                        root, wheel, sudo, daemon, users
|   +-- hostname                     "kiseki"
|   +-- fstab                        /dev/vda / ext4 defaults
|   +-- profile                      PATH, TERM, PS1
|   +-- sudoers                      root NOPASSWD, %sudo ALL
|   +-- epoch                        Boot time (Unix timestamp)
|   +-- resolv.conf                  8.8.8.8, 1.1.1.1
|   +-- issue                        ASCII art login banner
|   +-- skel/                        New user dotfiles
+-- root/
|   +-- .bashrc                      Root prompt, aliases
|   +-- .profile                     Sources .bashrc
+-- home/                            User home directories
+-- Users/                           macOS-style user directory
+-- dev/   proc/   sys/   tmp/       Standard directories
+-- var/log/   var/run/              Volatile state
```

#### Special File Permissions

The script sets SUID bits on privileged binaries:

```bash
# Via debugfs:
sif /bin/su mode 0104755        # SUID root
sif /sbin/sudo mode 0104755     # SUID root

# Via mount:
chmod 4755 /bin/su
chmod 4755 /sbin/sudo
```

The shadow file gets mode 0600 (readable only by root).

#### Configuration Files

The script generates `/etc/passwd`, `/etc/shadow`, `/etc/group`, and other
configuration files inline.  The default root password is `toor` (stored
in plaintext in `/etc/shadow` -- see Chapter 16 for security implications).
The DNS resolver is configured with Google (8.8.8.8) and Cloudflare (1.1.1.1).

### 15.6  QEMU Launch

The `make run` target launches QEMU with a comprehensive set of VirtIO devices:

```makefile
QEMU_FLAGS := -M virt              # ARM virt machine
              -accel tcg            # Software emulation (not HVF)
              -cpu cortex-a72       # ARMv8.0 CPU model
              -smp 4                # 4 CPU cores
              -m 4G                 # 4GB RAM
              -display cocoa        # macOS native window
              -kernel kiseki.elf    # Kernel image
              -serial mon:stdio     # Serial console on terminal
```

Plus the following devices:

| Device                      | Purpose                                |
|-----------------------------|----------------------------------------|
| `virtio-blk-device`        | Block storage (disk.img, raw format)   |
| `virtio-net-device`        | Network (vmnet-shared, real LAN IP)    |
| `virtio-gpu-device`        | Framebuffer (1280x800 display)         |
| `virtio-keyboard-device`   | HID keyboard input                     |
| `virtio-tablet-device`     | Absolute pointer (mouse) input         |

#### Why TCG, Not HVF?

The Makefile explicitly uses `-accel tcg` (software CPU emulation) instead of
`-accel hvf` (Apple Hypervisor Framework).  The comment in `Makefile:219-222`
explains:

> HVF on Apple Silicon has stricter cache coherency requirements that cause
> External Aborts during instruction fetch after fork.

When Kiseki's `fork()` copies page tables and the child process begins
executing, the CPU must see the new page table mappings.  Under TCG, the
software TLB handles this correctly.  Under HVF, the hardware TLB on Apple
Silicon requires explicit cache maintenance that Kiseki's VMM does not yet
perform, causing External Data Aborts (ESR class 0x25) on the first
instruction fetch in the child.

#### Networking

The network uses `vmnet-shared` -- macOS's native networking framework that
gives the guest a real IP on the host's local network.  This requires `sudo`
(the vmnet framework needs root privileges).  The guest's static IP is
192.168.64.10, with the host/gateway at 192.168.64.1.

### 15.7  Debug and Test Targets

#### Debug Mode

`make world DEBUG=1` sets `-DDEBUG=1` across both kernel and userland builds,
enabling verbose logging in:
- Kernel: `kprintf`-based debug output for boot stages, VMM operations, IPC
- dyld: Detailed library loading and fixup tracing
- Various subsystems: Additional diagnostic output

#### Unit Tests

Two test pathways exist:

**Host-side tests** (`make test`):
```makefile
$(BUILDDIR)/tests/%: $(TESTDIR)/unit/%.c
    $(HOST_CC) -Wall -Wextra -g -I$(SRCDIR)/include -DUNIT_TEST -o $@ $<
```

Kernel unit tests are compiled with the host compiler (native macOS `cc`) and
run directly on the build machine.  The `-DUNIT_TEST` flag allows kernel
headers to be included in a hosted environment by providing stub definitions.

**On-target tests** (`make test-kiseki`):
This boots Kiseki in QEMU (with user-mode networking, no `sudo`) and runs
`/bin/test_libc` inside the OS.  An expect-like script automates login:

```bash
{ sleep 4; echo "root"; sleep 1; echo "toor"; sleep 2;
  echo "/bin/test_libc"; sleep 15; echo "exit";
} | timeout 90 qemu-system-aarch64 $QEMU_TEST_FLAGS
```

The output is captured to `build/test_output.log` and checked for the string
"All tests PASSED".

### 15.8  Build Output Summary

After `make world`, the `build/` directory contains:

```
build/
+-- kiseki.elf           Kernel ELF (bootable by QEMU)
+-- kiseki.bin           Kernel flat binary
+-- kiseki.map           Linker map (symbol addresses)
+-- disk.img             64MB ext4 filesystem image
+-- userland/
    +-- dyld/dyld        Dynamic linker (MH_DYLINKER)
    +-- lib/
    |   +-- libSystem.B.dylib    C library
    |   +-- libobjc.A.dylib      ObjC runtime
    +-- System/Library/Frameworks/
    |   +-- IOKit.framework/Versions/A/IOKit
    |   +-- CoreFoundation.framework/Versions/A/CoreFoundation
    |   +-- CoreGraphics.framework/Versions/A/CoreGraphics
    |   +-- CoreText.framework/Versions/A/CoreText
    |   +-- Foundation.framework/Versions/A/Foundation
    |   +-- AppKit.framework/Versions/A/AppKit
    +-- System/Library/CoreServices/
    |   +-- Dock.app/Dock
    |   +-- Finder.app/Finder
    |   +-- SystemUIServer.app/SystemUIServer
    +-- Applications/
    |   +-- Terminal.app/Terminal
    +-- bin/              50+ command-line programs
    +-- sbin/             System daemons and servers
    +-- obj/              Intermediate object files
```

---

## Chapter 16: Security Audit & Hardening

This chapter is an honest security assessment of Kiseki OS.  As an educational
operating system designed for clarity rather than production use, Kiseki makes
many simplifications that have security implications.  Understanding these gaps
is valuable both for learning what production operating systems must do and for
identifying areas where Kiseki could be hardened.

The audit is organised by attack surface, from hardware up through the
application layer.  Each section identifies the vulnerability, explains why it
matters, describes what production systems (macOS/XNU in particular) do
differently, and suggests a remediation path.

### 16.1  Memory Safety

#### No Stack Canaries

The kernel is compiled with `-fno-stack-protector` (`Makefile:75`), and all
userland binaries are compiled with `-fno-stack-protector`.  This means there
are no stack canaries (`__stack_chk_guard`) to detect buffer overflows.

**Impact**: A stack buffer overflow in any kernel or userland function can
overwrite the return address and redirect control flow.  This is the classic
exploitation primitive for arbitrary code execution.

**macOS comparison**: XNU and all macOS userland are compiled with stack
protectors.  The `__stack_chk_guard` value is randomised at boot (kernel) and
per-process (userland via dyld).  A stack smash triggers `__stack_chk_fail`,
which calls `abort()`.

**Remediation**: Enable `-fstack-protector-strong` for both kernel and userland.
Requires implementing `__stack_chk_guard` (a random value per context) and
`__stack_chk_fail` (a panic/abort handler).

#### No ASLR

All user processes are loaded at the same virtual addresses:

- The main binary's Mach-O segments are mapped at the addresses specified in
  their LC_SEGMENT_64 commands (typically starting at 0x100000000)
- dyld is always mapped at its fixed address
- libSystem.B.dylib and frameworks are always at the same addresses
- The user stack is always at the same location

**Impact**: An attacker who discovers a vulnerability in any process knows the
exact address of every function, every ROP gadget, and every data structure.
Combined with the lack of stack canaries, this makes exploitation trivial.

**macOS comparison**: macOS implements full ASLR:
- Main binary slide: random offset applied to all segments
- dyld slide: independently randomised
- Shared library slide: DYLD_SHARED_CACHE has its own slide
- Stack randomisation: random offset below the stack top
- Heap randomisation: mmap returns randomised addresses

**Remediation**: Implement a random slide in `proc_execve()` when mapping the
main binary, and in dyld when mapping shared libraries.  The kernel needs a
random number source (ARM generic timer counter, or VirtIO RNG device).

#### No W^X Enforcement

The kernel VMM does not enforce Write XOR Execute: a page can simultaneously
be writable and executable.  The `vm_map_protect()` function does not check
for `PROT_WRITE | PROT_EXEC` combinations.

**Impact**: An attacker who can write to a memory page can inject shellcode and
execute it directly, without needing ROP or JIT tricks.

**macOS comparison**: macOS enforces W^X system-wide.  `mprotect()` with
`PROT_WRITE | PROT_EXEC` fails with EPERM on code-signed processes.  The
hardware page tables use the PXN/UXN bits to prevent execution of writable
pages.  JIT compilers (JavaScriptCore) use special `MAP_JIT` and
`pthread_jit_write_protect_np()` to toggle between write and execute.

**Remediation**: Add W^X enforcement in `vm_map_protect()` and `vm_map_enter()`.
Reject `PROT_WRITE | PROT_EXEC` unless a process has a special entitlement.

### 16.2  Access Control

#### DAC-Only Security Model

Kiseki implements only traditional Unix Discretionary Access Control (DAC):
UID/GID-based file permission checks in `bsd/security.c`.  There is no
Mandatory Access Control (MAC), no sandboxing, no capabilities, and no
entitlements.

The security checks are:

```
Root (UID 0): bypass all permission checks
Owner match:  check user permission bits (rwx)
Group match:  check group permission bits (rwx)
Otherwise:    check other permission bits (rwx)
```

**Impact**: Any process running as root has unrestricted access to the entire
system.  There is no defence-in-depth: a vulnerability in a root-running
daemon (like WindowServer, init, or any sbin program) gives the attacker
complete control.

**macOS comparison**: macOS layers multiple security mechanisms:
- DAC (Unix permissions)
- MAC (TrustedBSD mandatory access control framework)
- App Sandbox (via Seatbelt profiles)
- Entitlements (per-binary capability grants)
- System Integrity Protection (SIP) -- even root cannot modify /System
- Signed System Volume (SSV) -- cryptographic seal on the boot volume

**Remediation**: Implement a MAC framework (e.g., a simplified TrustedBSD
policy) that restricts what operations processes can perform based on labels
or profiles, regardless of UID.

#### Root-Running Services

Several critical daemons run as root with no privilege separation:

| Service         | Runs As | Risk                                      |
|-----------------|---------|-------------------------------------------|
| init            | root    | PID 1, full system control                |
| WindowServer    | root    | Framebuffer access, all HID input         |
| mDNSResponder   | root    | Network-facing, parses DNS packets        |
| sshd            | root    | Network-facing, handles authentication    |
| loginwindow     | root    | Handles passwords, spawns user sessions   |

**Impact**: A buffer overflow in mDNSResponder's DNS packet parser (which
processes untrusted network data) would give the attacker root access to the
entire system.

**macOS comparison**: macOS runs most daemons as dedicated unprivileged users
(`_mdnsresponder`, `_windowserver`, etc.) and uses sandbox profiles to further
restrict their capabilities.  WindowServer runs as `_windowserver:_windowserver`
with a tight Seatbelt profile.

**Remediation**: Create dedicated service accounts and drop privileges after
binding to privileged resources (ports, devices).  loginwindow already drops
privileges for user sessions (`Finder.m` inherits the dropped UID/GID from
loginwindow's `setuid`/`setgid` calls).

### 16.3  Authentication

#### Plaintext Passwords

Passwords in `/etc/shadow` are stored in plaintext:

```
root:toor:19000:0:99999:7:::
```

The `toor` string is the actual password, not a hash.  The login process
(`loginwindow.c`, `login.c`) compares the user's input directly against this
plaintext value.

**Impact**: Anyone who can read `/etc/shadow` (which is mode 0600, so only
root) can see all passwords.  More importantly, there is no protection against
rainbow table attacks, brute force, or password reuse analysis -- because the
passwords are not hashed at all.

**macOS comparison**: macOS stores password hashes in `/var/db/dslocal/` using
PBKDF2-HMAC-SHA512 with per-user random salts and configurable iteration
counts (typically 30,000+).  The hash files are readable only by root and the
directory services daemon.

**Remediation**: Implement SHA-512 crypt (`$6$`) or bcrypt hashing in
libSystem and update login/passwd to use it.  At minimum, use SHA-256 with a
random salt.

#### No Authentication Rate Limiting

There is no lockout or delay after failed login attempts.  An attacker with
console or SSH access can attempt unlimited passwords.

**Remediation**: Implement exponential backoff after failed attempts (e.g.,
1s, 2s, 4s, 8s...) or account lockout after N failures.

### 16.4  Network Security

#### No Firewall

There is no packet filtering at any layer.  All incoming packets are processed
by the TCP/IP stack regardless of source, destination, or port.

**Impact**: Any network service that is listening is accessible from any host on
the network.  There is no way to restrict access to specific ports or IPs.

**macOS comparison**: macOS includes `pf` (packet filter) in the kernel and
the Application Firewall in userland.  By default, incoming connections are
blocked unless the user or an MDM profile explicitly allows them.

#### No TCP Congestion Control

The TCP implementation (`kernel/net/tcp.c`) has no congestion control -- no
slow start, no congestion avoidance, no fast retransmit, no fast recovery.
While this is primarily a reliability/performance issue, it has security
implications: the system will flood the network in response to packet loss,
potentially participating in or amplifying denial-of-service attacks.

#### Simplified TIME_WAIT

TCP's TIME_WAIT state (which prevents old duplicate segments from being
accepted by new connections) is simplified.  This could allow connection
hijacking in certain scenarios.

#### No TLS/SSL

There is no cryptographic transport layer.  All network communication
(including the `curl` utility and any HTTP traffic) is in plaintext.

**Remediation**: Implement a TLS library (e.g., a minimal TLS 1.3 handshake
using a lightweight crypto library) or port BearSSL/mbedTLS.

### 16.5  Kernel Attack Surface

#### No System Call Argument Validation

While the BSD syscall handler (`bsd/syscalls.c`) performs basic validation
(e.g., checking file descriptor ranges, null pointer checks), there are gaps:

- Path buffers are copied from user space without guaranteed null termination
  length checks in some paths
- `ioctl` commands are not validated against a whitelist -- any command code
  is passed through
- Mach IPC messages are parsed with minimal validation of field sizes

**Impact**: Malformed syscall arguments could trigger kernel buffer overflows
or information leaks.

**macOS comparison**: XNU uses `copyin()`/`copyout()` with strict size limits,
validates every argument range, and uses MIG (Mach Interface Generator) for
type-safe Mach message parsing.

#### Kernel Runs with Full Permissions

The kernel runs at EL1 with full access to all hardware.  There is no EL2
hypervisor providing additional isolation.  On macOS, the Secure Enclave
Processor and the PPL (Page Protection Layer, running at a higher privilege
within the kernel) protect critical data structures.

#### Static Pool Exhaustion

Many kernel subsystems use fixed-size static pools:

| Resource           | Pool Size | Exhaustion Effect            |
|--------------------|-----------|------------------------------|
| Processes          | 256       | Cannot fork()                |
| Mach ports         | 512       | Cannot allocate ports        |
| Port names/space   | 256       | Cannot name ports            |
| Open files (global)| 512       | Cannot open files            |
| Vnodes             | 1024      | Cannot access files          |
| Mounts             | 16        | Cannot mount filesystems     |
| TCP connections    | 64 TCBs   | Cannot accept connections    |
| Sockets            | 64        | Cannot create sockets        |
| Buffer cache       | 256       | I/O stalls, LRU eviction     |
| vm_map entries     | 512       | Cannot mmap                  |

**Impact**: Any unprivileged user can exhaust these pools by creating many
processes, opening many files, or establishing many connections.  This is a
denial-of-service vector with no per-user resource limits.

**macOS comparison**: XNU uses dynamic allocation for most resources (zones/
kalloc), with per-process and per-user resource limits enforced by
`setrlimit()`/launchd.

**Remediation**: Add per-user resource limits (struct rlimit) and enforce them
in the syscall paths.

### 16.6  Information Disclosure

#### Kernel Memory Leaks to Userspace

The trap frame saves 816 bytes of register state on every syscall/exception.
When a new process is created via `fork()`, the child's trap frame is a copy
of the parent's -- including all 32 NEON registers and control registers.  If
the kernel fails to zero unused fields before returning to user mode, register
contents from the parent (or from kernel operations) could leak to the child.

Similarly, the `fork_child_return` path may not zero all general-purpose
registers, potentially leaking parent register state to the child.

**macOS comparison**: XNU zeroes the child's register state in
`thread_dup()` and `act_thread_csave()`, ensuring no register contents leak
across fork boundaries.

#### Predictable Initial Sequence Numbers

TCP initial sequence numbers (ISS) are incremented by a fixed value (64000)
on each new connection (`tcp_new_iss` in `kernel/net/tcp.c`).  This makes
ISN prediction trivial.

**Impact**: An off-path attacker can predict ISNs and inject forged TCP
segments, enabling connection hijacking or RST attacks.

**macOS comparison**: XNU uses a random ISN algorithm (RFC 6528) based on a
keyed hash of the connection 4-tuple.

**Remediation**: Use a cryptographic hash (e.g., SipHash) of the 4-tuple
plus a secret key to generate ISNs.

### 16.7  Physical and Side-Channel Attacks

#### No Secure Boot

The kernel is loaded directly by QEMU's `-kernel` flag with no verification.
There is no chain of trust, no signed boot, no measured boot.

**macOS comparison**: Apple Silicon Macs implement a full secure boot chain:
Boot ROM -> iBoot -> kernel -> kexts, with each stage verified by the previous
stage's signature check.

#### No Spectre/Meltdown Mitigations

The kernel does not implement any speculative execution mitigations:
- No KPTI (Kernel Page Table Isolation)
- No speculative barrier instructions (`CSDB`, `SB`)
- No retpoline-style indirect branch mitigations

**Impact on ARM64**: ARM64 is less affected than x86 by Spectre/Meltdown, but
Cortex-A72 (the QEMU CPU model) is vulnerable to Spectre variant 2.  In a
multi-user scenario, one user could potentially read another user's memory
via speculative side channels.

**macOS comparison**: macOS on Apple Silicon includes hardware mitigations
(KTRR, PPL) and software mitigations where needed.

### 16.8  Security Hardening Roadmap

The following table summarises all identified issues and suggested
remediations, ordered by impact and implementation difficulty:

| Priority | Issue                    | Difficulty | Remediation                    |
|----------|--------------------------|------------|--------------------------------|
| Critical | Plaintext passwords      | Easy       | Implement SHA-512 crypt        |
| Critical | No stack canaries        | Easy       | Enable -fstack-protector-strong|
| Critical | No ASLR                  | Medium     | Random slide in execve + dyld  |
| High     | Root-running daemons     | Medium     | Dedicated UIDs, privilege drop |
| High     | No W^X enforcement       | Easy       | Reject WRITE+EXEC in VMM      |
| High     | Predictable TCP ISNs     | Easy       | SipHash-based ISN generation   |
| High     | No resource limits       | Medium     | Per-user rlimits               |
| Medium   | No MAC/sandboxing        | Hard       | TrustedBSD-style MAC framework |
| Medium   | No TLS                   | Hard       | Port mbedTLS or BearSSL        |
| Medium   | No firewall              | Medium     | Simple packet filter in IP layer|
| Medium   | No syscall audit         | Medium     | Validate all arg ranges        |
| Low      | No secure boot           | Hard       | Requires UEFI or custom loader |
| Low      | No Spectre mitigations   | Medium     | Barrier instructions + KPTI    |
| Low      | Static pool exhaustion   | Medium     | Dynamic allocation + limits    |
| Low      | Register state leaks     | Easy       | Zero trap frame on fork        |

The "Critical" items are straightforward to implement and would dramatically
improve the security posture.  The "High" items require moderate refactoring.
The "Medium" and "Low" items represent significant architectural work that
would bring Kiseki closer to production-grade security.

It is worth emphasising that Kiseki's current security model is entirely
appropriate for its purpose as an educational operating system.  The
simplifications documented here are deliberate design choices that prioritise
code clarity over security hardening.  A reader who understands these gaps
understands what real operating systems must do -- and why operating system
security is so complex.

---

*End of Kiseki Internals Book*
