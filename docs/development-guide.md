# Kiseki OS Development Guide

This document covers the development philosophy, conventions, and practical workflows for contributing to Kiseki OS.

---

## 1. Development Philosophy

### 1.1. Accuracy to XNU/macOS Over Everything

Kiseki's primary goal is to run unmodified macOS Mach-O binaries. Every design decision must prioritise **accuracy to how XNU/macOS actually works** over simplicity, performance, or cleverness.

When faced with two choices:
1. A quick shortcut that "works but isn't how macOS does it"
2. A faithful reimplementation of the XNU approach

**Always choose option 2.** Never take shortcuts.

Examples of this principle in practice:
- Mach IPC port right translation follows `ipc_kmsg_copyin_header()`/`ipc_kmsg_copyout_header()` from XNU's `osfmk/ipc/ipc_kmsg.c`, not a simplified scheme.
- Per-task IPC spaces match XNU's `ipc_space_create()`/`ipc_space_destroy()` from `osfmk/ipc/ipc_space.c`.
- launchd pre-creates service ports before daemons start, exactly as macOS does.
- Struct layouts match the macOS ARM64 SDK to the byte. A single byte of padding difference causes binary incompatibility.

### 1.2. Reference Source

The authoritative reference for all kernel interfaces is the **official XNU source**:
- https://github.com/apple-oss-distributions/xnu

When implementing or debugging a feature, find the corresponding XNU code first. Understand how Apple does it, then implement the same semantics in Kiseki.

### 1.3. No Stubs

Every feature is implemented properly or not at all. A syscall that returns `ENOSYS` is preferable to one that silently does nothing. When a subsystem is built, it handles edge cases, error paths, and concurrent access correctly.

### 1.4. Correctness Over Performance

A correct implementation that runs slowly is more valuable than a fast one that corrupts memory. Optimisations are added after the system works, not before.

---

## 2. Build System

### 2.1. Prerequisites

- **macOS host** — required for compiling Mach-O userland binaries
- **aarch64-elf-gcc** — cross-compiler for the kernel (`brew install aarch64-elf-gcc`)
- **QEMU** — for testing (`brew install qemu`)
- **Xcode Command Line Tools** — provides the macOS SDK for userland compilation

### 2.2. Build Commands

```bash
# Full build: kernel + userland + disk image
make clean && make world

# Kernel only
make -j4

# Userland only
make -C userland all

# Disk image only
./scripts/mkdisk.sh build/disk.img

# Boot in QEMU (requires sudo for vmnet networking)
sudo make run

# Run unit tests (user-mode networking, no sudo)
make test-kiseki
```

### 2.3. Kernel Compilation

The kernel is cross-compiled with `aarch64-elf-gcc`:
- Flags: `-ffreestanding -fno-builtin -fno-stack-protector -nostdinc -nostdlib -mcpu=cortex-a72 -mgeneral-regs-only -std=gnu11 -O2 -g -Werror`
- Output: ELF binary at `build/kiseki.elf`
- Linked via `linker-qemu.ld` (QEMU) or `linker-raspi4.ld` (Raspberry Pi)

### 2.4. Userland Compilation

Userland binaries are compiled with macOS `clang`:
- Flags: `-target arm64-apple-macos11 -isysroot $(xcrun --show-sdk-path) -Wall -Wextra -O2`
- Links dynamically against `/usr/lib/libSystem.B.dylib`
- Produces standard Mach-O 64-bit executables

### 2.5. Disk Image

`scripts/mkdisk.sh` creates a 64 MB ext4 image with the complete Unix hierarchy. It installs all binaries, libraries, configuration files, launchd plists, Mach headers for TCC, and system files.

### 2.6. Debugging Tools

```bash
# Disassemble kernel binary
/opt/homebrew/bin/aarch64-elf-objdump -d build/kiseki.elf

# Look up symbol addresses
/opt/homebrew/bin/aarch64-elf-nm build/kiseki.elf | grep <symbol>

# Disassemble with source interleaving
/opt/homebrew/bin/aarch64-elf-objdump -S build/kiseki.elf
```

---

## 3. How to Add a New BSD Syscall

See `docs/implementing-syscalls.md` for the full guide. Summary:

1. **Find the syscall number** from XNU's `bsd/kern/syscalls.master` or the macOS SDK.
2. **Add a forward declaration** in `kernel/bsd/syscalls.c`.
3. **Add to the dispatch table** in `syscall_handler()`.
4. **Implement the handler** — signature is `static int sys_xxx(struct proc *p, struct trapframe *tf)`. Arguments from `tf->regs[0]` through `tf->regs[5]`.
5. **Add the userland wrapper** in `userland/libsystem/libSystem.c` (see Section 6 below for conventions).
6. **Add the prototype** to the appropriate header in `userland/libsystem/include/`.

**Error convention:** Return positive errno from the kernel handler. The syscall dispatcher sets the carry flag and places the errno in `x0`. Never return negative values (that's Linux, not Darwin).

---

## 4. How to Add a New Mach Trap

Mach traps use **negative** `x16` values. The trap number is negated before dispatch.

### 4.1. Files to Edit

| File | Purpose |
|------|---------|
| `kernel/mach/ipc.c` | Trap implementation |
| `kernel/include/mach/ipc.h` | Declarations, constants |
| `userland/libsystem/libSystem.c` | Userland wrapper |
| `userland/libsystem/include/mach/*.h` | Userland headers |

### 4.2. Implementation Steps

1. **Find the trap number** from XNU's `osfmk/mach/syscall_sw.h` or `osfmk/mach/mach_traps.h`.

2. **Add the handler** in `kernel/mach/ipc.c`:
   ```c
   static int trap_your_trap_name(struct proc *p, struct trapframe *tf)
   {
       /* Arguments in tf->regs[0] through tf->regs[5] */
       /* Return value in tf->regs[0] */
       return KERN_SUCCESS;
   }
   ```

3. **Add to the dispatch** in `mach_trap_handler()` (called from `syscall_handler` when `x16 < 0`):
   ```c
   case 42:  /* trap -42 */
       return trap_your_trap_name(p, tf);
   ```

4. **Add the userland wrapper** in `libSystem.c` using `__mach_trap()`:
   ```c
   EXPORT kern_return_t your_trap(mach_port_t port)
   {
       return (kern_return_t)__mach_trap(-42, (long)port, 0, 0, 0, 0, 0);
   }
   ```

**Important:** `__mach_trap()` does NOT check the carry flag (unlike `__syscall()` for BSD syscalls). Mach traps return `kern_return_t` directly in `x0`.

---

## 5. How to Add a New Daemon (launchd Pattern)

Kiseki's init is a launchd-style process manager. Adding a new daemon follows the macOS pattern exactly.

### 5.1. Create the Daemon Source

Add the source file in `userland/sbin/<daemon_name>.c`.

### 5.2. Add to sbin Makefile

Edit `userland/sbin/Makefile` to include your daemon in the `PROGS` list so it gets compiled.

### 5.3. Create a launchd Plist

Create `config/LaunchDaemons/uk.co.avltree9798.<daemon_name>.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>uk.co.avltree9798.<daemon_name></string>
	<key>ProgramArguments</key>
	<array>
		<string>/sbin/<daemon_name></string>
	</array>
	<key>MachServices</key>
	<dict>
		<key>uk.co.avltree9798.<daemon_name></key>
		<true/>
	</dict>
	<key>KeepAlive</key>
	<true/>
</dict>
</plist>
```

**Key fields:**
- `Label` — Unique reverse-DNS identifier. Use `uk.co.avltree9798.` prefix (NOT `com.apple.`).
- `ProgramArguments` — Array of strings: executable path followed by arguments.
- `MachServices` — Dictionary of Mach service names the daemon provides. Init pre-creates receive ports for each service name and registers them via `bootstrap_register()` **before** the daemon starts. This eliminates race conditions.
- `KeepAlive` — If `<true/>`, init auto-relaunches the daemon if it exits.

### 5.4. Install to Disk Image

Edit `scripts/mkdisk.sh` to:
1. Copy the binary to `/sbin/` on the disk image.
2. Copy the plist to `/System/Library/LaunchDaemons/` (or `/Library/LaunchDaemons/` for non-system daemons).

### 5.5. Daemon Startup Code

The daemon claims its pre-created service port using `bootstrap_check_in()`:

```c
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main(void)
{
    mach_port_t service_port;
    kern_return_t kr;

    /* Claim the port that init pre-created for us */
    kr = bootstrap_check_in(bootstrap_port,
                            "uk.co.avltree9798.<daemon_name>",
                            &service_port);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "bootstrap_check_in failed: %d\n", kr);
        return 1;
    }

    /* Main service loop: receive requests, send replies */
    for (;;) {
        char buf[4096];
        mach_msg_header_t *hdr = (mach_msg_header_t *)buf;

        hdr->msgh_size = sizeof(buf);
        hdr->msgh_local_port = service_port;

        kr = mach_msg(hdr,
                      MACH_RCV_MSG,
                      0,                /* send_size (not sending) */
                      sizeof(buf),      /* rcv_size */
                      service_port,     /* rcv_name */
                      MACH_MSG_TIMEOUT_NONE,
                      MACH_PORT_NULL);
        if (kr != KERN_SUCCESS)
            continue;

        /* Process request, build reply... */
        /* After receive: msgh_remote_port = reply port (send-once right) */
    }

    return 0;
}
```

**Important:** After `mach_msg` receive, the reply port is in `msgh_remote_port` (not `msgh_local_port`). This is the XNU convention — remote/local are swapped during copyout so the receiver can reply directly to `msgh_remote_port`.

### 5.6. Never Use Sleep Hacks

Do NOT use `sleep()` or `usleep()` to wait for a service to become available. The launchd pre-creation pattern ensures service ports exist before clients run:

1. init reads the plist and pre-creates the Mach port via `bootstrap_register()`
2. Clients can `bootstrap_look_up()` the service immediately (they get a send right)
3. The daemon starts later, calls `bootstrap_check_in()` to claim the receive right
4. Any messages sent before the daemon starts queue on the port and are delivered when the daemon calls `mach_msg(MACH_RCV_MSG)`

---

## 6. libSystem.c Conventions

`userland/libsystem/libSystem.c` is the C library implementation. It follows strict conventions that **must not be violated**.

### 6.1. Completely Freestanding

libSystem.c is ~7,400 lines of self-contained C. It does NOT `#include` any headers — not even standard C headers. Every type, constant, and struct is defined inline within the file.

```c
/* Types are defined inline, not from headers */
typedef unsigned long size_t;
typedef long ssize_t;
typedef int pid_t;
/* ... */
```

### 6.2. Export Conventions

Public functions use `void *` and primitive types for struct pointer parameters:

```c
/* In libSystem.c — uses void * for struct params */
EXPORT int stat(const char *path, void *buf)
{
    long ret = __syscall(338, (long)path, (long)buf, 0, 0, 0, 0);
    if (ret < 0) { errno = (int)(-ret); return -1; }
    return 0;
}
```

The properly-typed prototypes are in the public headers:

```c
/* In userland/libsystem/include/sys/stat.h — properly typed */
int stat(const char *path, struct stat *buf);
```

This pattern exists because libSystem.c cannot reference the structs defined in the public headers (since it includes nothing). Client programs include the headers and get proper type checking.

### 6.3. Syscall Wrappers

Two primitives for invoking the kernel:

```c
/* BSD syscalls — checks carry flag for errors */
static inline long __syscall(long num, long a, long b, long c,
                             long d, long e, long f);

/* Mach traps — returns x0 directly, no carry flag check */
static inline long __mach_trap(long num, long a, long b, long c,
                               long d, long e, long f);
```

- `__syscall()`: For positive syscall numbers. After `svc #0x80`, checks the carry flag in NZCV. If set, negates the return value to make it negative (errno). The wrapper function then checks `ret < 0`, sets `errno`, and returns -1.
- `__mach_trap()`: For negative trap numbers. Returns `x0` directly without carry flag manipulation. Mach traps return `kern_return_t` (0 = success, positive = error code).

### 6.4. Adding New Functions

When adding a new function to libSystem:

1. Define any required types/structs inline in libSystem.c (if not already present).
2. Implement the function using `EXPORT` macro and `void *` for struct pointers.
3. Add the properly-typed prototype to the appropriate header in `userland/libsystem/include/`.
4. The `EXPORT` macro ensures the symbol is visible for dynamic linking.

---

## 7. Naming Conventions

### 7.1. Reverse-DNS Prefix

Use **`uk.co.avltree9798`** as the reverse-DNS prefix for all Kiseki services, plists, and bundle identifiers. Never use `com.apple.`.

Examples:
- Service name: `uk.co.avltree9798.mDNSResponder`
- Plist label: `uk.co.avltree9798.mDNSResponder`
- Plist file: `uk.co.avltree9798.mDNSResponder.plist`

### 7.2. File Naming

- Kernel source: lowercase with underscores (`syscalls.c`, `ipc.c`, `virtio_net.c`)
- Userland daemons: match macOS naming when applicable (`mDNSResponder.c`, `sshd.c`, `init.c`)
- Headers: match macOS SDK paths where possible (`mach/port.h`, `sys/stat.h`)

### 7.3. Kernel Function Naming

- BSD syscall handlers: `sys_<name>` (e.g., `sys_fork_impl`, `sys_sendto`)
- Mach trap handlers: `trap_<name>` (e.g., `trap_mach_msg`)
- IPC functions: `ipc_<subsystem>_<action>` (e.g., `ipc_port_alloc`, `ipc_space_create`)
- VFS functions: `vfs_<action>` (e.g., `vfs_open`, `vfs_lookup`)

---

## 8. Testing Methodology

### 8.1. Boot-Log-Fix Cycle

Kiseki cannot be tested interactively by the development agent. The workflow is:

1. **Build**: `make clean && make world`
2. **User boots** the OS in QEMU and exercises the feature
3. **User provides crash logs** (serial output, panic messages, register dumps)
4. **Agent analyses** the logs, cross-references with disassembly (`aarch64-elf-objdump`), and fixes the code
5. Repeat

### 8.2. Automated Tests

```bash
make test-kiseki
```

This boots QEMU with user-mode networking (no sudo), auto-logs in, runs `/bin/test_libc`, and checks for "All tests PASSED".

### 8.3. Debugging a Crash

When the user provides a crash log with a PC address:

```bash
# Find which function the PC is in
/opt/homebrew/bin/aarch64-elf-nm build/kiseki.elf | sort | grep -B1 <address>

# Disassemble around the crash site
/opt/homebrew/bin/aarch64-elf-objdump -d build/kiseki.elf | grep -A 20 <address>
```

Common crash patterns:
- **Data abort at EL1**: Null pointer dereference or bad kernel address. Check the FAR (Fault Address Register) in the crash dump.
- **SError**: Usually a bad MMIO access or alignment fault.
- **Hang/no output**: Check if interrupts are masked (DAIF) or if a spinlock deadlock occurred.

---

## 9. Key Architectural Decisions

### 9.1. Why Per-Task IPC Spaces?

On XNU, every task has its own IPC space (`ipc_space_t`). Port names are local to a task — name 1283 in task A is a completely different port from name 1283 in task B. When messages cross task boundaries, `ipc_kmsg_copyin_header()` translates names to kernel objects, and `ipc_kmsg_copyout_header()` creates new names in the receiver's space.

Kiseki implements this faithfully. A simpler global namespace would be easier but would not match macOS semantics, and real macOS binaries assume per-task port name isolation.

### 9.2. Why Pre-Created Service Ports?

On macOS, launchd pre-creates service ports listed in `MachServices` plist entries. The port exists in the bootstrap registry before the daemon starts. Clients can `bootstrap_look_up()` immediately — if the daemon hasn't started yet, messages simply queue.

This design eliminates race conditions without sleep hacks. Kiseki init implements the same pattern.

### 9.3. Why Freestanding libSystem?

libSystem.c includes no headers because:
1. The kernel is cross-compiled with `aarch64-elf-gcc` which has different system headers than the macOS SDK.
2. The userland is compiled with macOS `clang` against the macOS SDK.
3. libSystem.c is the bridge between these two worlds. It must define types that match both the kernel's expectations (for syscall arguments) and the macOS SDK's expectations (for client programs).
4. Including any headers would pull in definitions that might conflict with the kernel's or the SDK's layouts.

### 9.4. Why `void *` in libSystem Exports?

Functions in libSystem.c use `void *` for struct parameters because the struct definitions don't exist inside libSystem.c (they're only in the public headers). The public headers provide the properly-typed prototypes that client programs see. At link time, the symbol names match regardless of parameter types.

### 9.5. Why Static Pools?

The kernel uses static pools for ports (512), IPC spaces (64), processes (256), sockets (64), threads (256), and buffers (256). A real XNU uses zone allocators. Static pools are simpler to debug and sufficient for the current scale. They can be replaced with zone allocators later without changing the API.

---

## 10. QEMU Configuration

### 10.1. Default Setup

```
QEMU_FLAGS := -M virt -acpi tcg -cpu cortex-a72 -smp 4 -m 1G -nographic
              -kernel build/kiseki.elf -serial mon:stdio
Network:      -netdev vmnet-shared,id=net0 -device virtio-net-device,netdev=net0
Run:          sudo make run  (vmnet requires sudo)
```

### 10.2. Network Modes

- **vmnet-shared** (default, requires sudo): Real network access, guest gets DHCP address on host's network. Required for DNS, ping, SSH from external hosts.
- **user-mode** (no sudo): NAT with port forwarding. Used by `make test-kiseki`. Guest IP: `10.0.2.15`, gateway `10.0.2.2`, host port 2222 → guest port 22.

---

## 11. Further Reading

- `docs/spec.md` — Full architecture specification
- `docs/implementing-syscalls.md` — Step-by-step guide for adding BSD syscalls
- `docs/porting-software.md` — Guide to porting software to Kiseki
- Apple XNU source: https://github.com/apple-oss-distributions/xnu
