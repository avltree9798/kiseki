# Kiseki OS

A hybrid kernel operating system for ARM64 that runs **unmodified macOS Mach-O binaries** on non-Apple hardware.

Kiseki implements the Darwin/XNU kernel-user ABI — Mach traps, BSD syscalls, Mach-O loading, dyld — from scratch in C and ARM64 assembly. You compile a program on your Mac with `clang -target arm64-apple-macos11`, copy the binary to a Kiseki disk image, and it runs.

## Why "Kiseki"?

奇跡 (kiseki) is the Japanese word for **miracle**.

Running native macOS binaries on bare-metal non-Apple hardware — without Apple's kernel, without Apple's bootloader, without any of Apple's code — is the kind of thing that shouldn't be possible. The Mach-O format, the XNU syscall conventions, the Darwin ABI — these were designed for a vertically integrated stack. Reproducing enough of that stack to make real binaries think they're on macOS, on a QEMU virt machine or a Raspberry Pi, is an act of unreasonable ambition.

The name is also a nod to the project's origin: the miracle of starting with nothing — no operating system, no standard library, no file system — just a UART printing characters to a serial console — and ending up with a multi-user Unix system running bash, 60+ coreutils, a TCP/IP stack, and an SSH server.

Every working syscall is a small miracle. Every binary that loads and runs is another. The project is the sum of these miracles.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Userland (Mach-O)                   │
│  bash, ls, cat, grep, awk, sed, curl, nc, ssh...    │
│          libSystem.B.dylib  ←  dyld                 │
├─────────────────────────────────────────────────────┤
│             svc #0x80 (syscall gate)                │
│         x16 > 0 → BSD    x16 < 0 → Mach            │
├────────────────────┬────────────────────────────────┤
│   BSD Personality   │      Mach Microkernel         │
│  POSIX syscalls     │  IPC, tasks, threads          │
│  VFS, processes     │  ports, messages              │
│  signals, pipes     │  semaphores                   │
├────────────────────┴────────────────────────────────┤
│                  Kernel Core                         │
│  Scheduler (MLFQ) · SMP (4 cores) · VMM (4K pages) │
│  PMM · TTY · PTY · Synchronisation primitives        │
├─────────────────────────────────────────────────────┤
│                    Drivers                           │
│  PL011 UART · GICv2 · ARM Timer · VirtIO-blk       │
│  VirtIO-net · eMMC (RPi) · Raspberry Pi UART        │
├─────────────────────────────────────────────────────┤
│                  Filesystems                         │
│  Ext4 (read/write) · devfs · Buffer cache           │
├─────────────────────────────────────────────────────┤
│                   Networking                         │
│  Ethernet · ARP · IPv4 · TCP · UDP · ICMP           │
│  BSD socket API · VirtIO-net driver                  │
└─────────────────────────────────────────────────────┘
```

**Kernel type:** Hybrid (Mach microkernel + BSD personality), following the XNU architecture.

**Binary format:** Mach-O 64-bit exclusively. No ELF. Normal macOS ARM64 binaries run unmodified.

**Syscall interface:** `svc #0x80`, syscall number in `x16`. Positive = BSD, negative = Mach trap. Error convention: carry flag set in PSTATE, positive errno in `x0`.

## Features

### Kernel
- 4-core SMP with per-CPU run queues and IPI support
- Pre-emptive multitasking with multilevel feedback queue scheduler
- Full virtual memory management (4K pages, per-process page tables)
- Demand paging with copy-on-write fork
- Mach-O binary loader with LC_SEGMENT_64, LC_MAIN, LC_LOAD_DYLINKER support
- Custom dyld (dynamic linker) resolving libSystem symbols at load time
- 100+ BSD syscalls (fork, exec, pipe, dup2, select, mmap, signals, sockets...)
- Mach traps (task_self, mach_msg, semaphore operations, thread_self)
- CommPage at `0xFFFFFFFFFFFFC000` with optimised gettimeofday
- Full termios/TTY subsystem with canonical and raw modes
- Pseudo-terminal (PTY) subsystem for remote shell sessions
- UART RX interrupts with proper signal delivery (Ctrl-C, Ctrl-\, Ctrl-Z)

### Filesystems
- Ext4 read/write with extents, directory indexing, block groups
- VFS layer with mount points, path resolution, file descriptor management
- devfs for `/dev/console`, `/dev/null`, `/dev/zero`, `/dev/urandom`
- 64MB root filesystem with standard Unix directory hierarchy

### Networking
- Full TCP/IP stack (not a stub — real implementations)
- VirtIO-net driver for QEMU, planned genet for Raspberry Pi
- Ethernet framing with ARP cache and neighbour resolution
- IPv4 routing with configurable gateway and netmask
- TCP: full state machine, three-way handshake, active and passive open, FIN/RST, retransmission
- UDP: connectionless datagram support
- ICMP: echo request/reply (ping)
- BSD socket API: socket, bind, listen, accept, connect, send, recv, shutdown, close

### Userland
- **68 Mach-O binaries** on the root filesystem
- Full bash shell with job control, pipelines, redirections, `time` keyword
- 59 coreutils: ls, cat, grep, awk, sed, sort, find, wc, cut, head, tail, tr, xargs, and more
- System daemons: init, getty, login (with /etc/passwd authentication)
- Network tools: curl, nc, ping, ifconfig, ntpdate
- User management: adduser, su, sudo, whoami, id
- Power management: halt, reboot, shutdown
- libSystem.B.dylib: complete freestanding C library (~3,100 lines)

### Security
- Multi-user with UID/GID enforcement (Unix discretionary access control)
- File permissions (rwx owner/group/other)
- SUID/SGID support
- `/etc/passwd` and `/etc/shadow` authentication
- Process credentials (real/effective UID/GID)
- Default root password: `toor`

## Building

### Prerequisites

- macOS host (for Mach-O userland compilation)
- `aarch64-elf-gcc` cross-compiler (kernel)
- QEMU with `qemu-system-aarch64`
- Xcode Command Line Tools (provides macOS SDK)

```bash
# Install cross-compiler (macOS)
brew install aarch64-elf-gcc

# Install QEMU
brew install qemu
```

### Build Commands

```bash
# Build kernel only
make -j4

# Build all userland (dyld + libSystem + 68 binaries)
make -C userland all

# Create root filesystem disk image
./scripts/mkdisk.sh build/disk.img

# Boot in QEMU
make run

# Build everything at once
make world
```

### QEMU Configuration

The default QEMU invocation uses:
- `virt` machine with Cortex-A72 CPU, 4 cores, 1GB RAM
- VirtIO block device for the root filesystem
- VirtIO network device with user-mode networking
- Guest IP: `10.0.2.15`, Gateway: `10.0.2.2`
- Host port 2222 forwarded to guest port 22 (for SSH)

## Boot Sequence

```
Power On
  → boot.S: Set up EL1, MMU, stack, wake secondary cores via PSCI
  → main.c: Initialize subsystems in order:
      GIC → UART → PMM → VMM → Timer → Scheduler → SMP →
      TTY → PTY → Ext4 → devfs → VFS mount → Network →
      Load /sbin/init from Mach-O
  → init: Mount root, spawn getty per TTY
  → getty: Open /dev/console, print login prompt
  → login: Authenticate user, set UID/GID, exec shell
  → bash: Interactive shell session
```

## Project Structure

```
kiseki/
├── Makefile                        # Top-level build (kernel + QEMU)
├── README.md
├── docs/
│   └── spec.md                     # Full architecture specification
├── scripts/
│   └── mkdisk.sh                   # Root filesystem image builder
├── kernel/
│   ├── arch/arm64/
│   │   ├── boot.S                  # Entry point, EL2→EL1, MMU setup
│   │   ├── vectors.S               # Exception vector table
│   │   ├── context_switch.S        # Thread context save/restore
│   │   └── smp.c                   # Secondary core bringup (PSCI)
│   ├── kern/
│   │   ├── main.c                  # Kernel main, boot sequence
│   │   ├── proc.c                  # Process management, fork, exec
│   │   ├── sched.c                 # MLFQ scheduler
│   │   ├── vmm.c                   # Virtual memory, page tables
│   │   ├── pmm.c                   # Physical memory allocator
│   │   ├── trap.c                  # Exception/interrupt dispatch
│   │   ├── tty.c                   # Terminal line discipline
│   │   ├── pty.c                   # Pseudo-terminal pairs
│   │   ├── sync.c                  # Spinlocks, mutexes
│   │   ├── macho.c                 # Mach-O binary loader
│   │   ├── commpage.c              # CommPage population
│   │   └── kprintf.c              # Kernel printf
│   ├── bsd/
│   │   ├── syscalls.c              # BSD syscall dispatch (~4700 lines)
│   │   └── security.c             # Credential checks, SUID
│   ├── mach/
│   │   └── ipc.c                   # Mach IPC, port management
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
│   │   ├── uart/raspi_uart.c       # Mini UART (Raspberry Pi)
│   │   ├── gic/gicv2.c             # ARM GIC interrupt controller
│   │   ├── timer/timer.c           # ARM generic timer
│   │   ├── virtio/virtio_blk.c     # VirtIO block device
│   │   ├── net/virtio_net.c        # VirtIO network device
│   │   ├── emmc/emmc.c             # eMMC (Raspberry Pi)
│   │   └── blkdev/blkdev.c         # Block device abstraction
│   └── include/                    # Kernel headers (26 files)
├── userland/
│   ├── Makefile                    # Userland master build
│   ├── dyld/                       # Dynamic linker (Mach-O)
│   ├── libsystem/
│   │   ├── libSystem.c             # Freestanding C library (~3100 lines)
│   │   └── include/                # Userland syscall headers
│   ├── bin/                        # 59 coreutils + bash
│   │   ├── bash/                   # Full bash implementation
│   │   ├── awk/                    # AWK interpreter
│   │   ├── sed/                    # Stream editor
│   │   ├── grep/                   # Pattern matcher
│   │   ├── curl/                   # HTTP client
│   │   └── ...                     # ls, cat, cp, mv, rm, etc.
│   └── sbin/
│       ├── init.c                  # PID 1 process
│       ├── getty.c                 # Terminal login prompt
│       ├── login.c                 # User authentication
│       └── halt.c                  # System shutdown/reboot
└── tests/                          # Unit test framework
```

## Code Statistics

| Component | Files | Lines |
|-----------|-------|-------|
| Kernel (C + ASM) | 37 | ~21,000 |
| Kernel headers | 26 | ~4,800 |
| Userland | 70+ | ~40,000 |
| **Total** | **130+** | **~70,000** |

## Roadmap

- [x] Hybrid kernel (Mach + BSD)
- [x] Mach-O loader + dyld
- [x] Ext4 filesystem (read/write)
- [x] SMP (4 cores)
- [x] Pre-emptive multitasking
- [x] Full bash shell
- [x] 60+ coreutils
- [x] TCP/IP networking stack
- [x] PTY subsystem
- [ ] SSH server (in progress)
- [ ] vim text editor
- [ ] Lua interpreter
- [ ] Python interpreter
- [ ] Framebuffer graphics / graphical shell

## License

This project is a research and educational endeavour in operating system construction.
