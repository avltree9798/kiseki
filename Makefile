# ============================================================================
# Kiseki Operating System - Top-Level Makefile
# Target: ARM64 (AArch64)
# Platforms: QEMU virt, Raspberry Pi 4/5
#
# Debug mode: make world DEBUG=1
#   - Enables verbose debug output in kernel, dyld, etc.
# ============================================================================

# --- Configuration -----------------------------------------------------------
ARCH        := aarch64
PLATFORM    ?= qemu
DEBUG       ?= 0

# Export DEBUG for sub-makefiles
export DEBUG

# Cross-compiler toolchain detection
# Try common prefixes in order of preference
CROSS_COMPILE ?= $(shell \
    if command -v aarch64-none-elf-gcc >/dev/null 2>&1; then echo aarch64-none-elf-; \
    elif command -v aarch64-elf-gcc >/dev/null 2>&1; then echo aarch64-elf-; \
    elif command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then echo aarch64-linux-gnu-; \
    elif command -v aarch64-unknown-elf-gcc >/dev/null 2>&1; then echo aarch64-unknown-elf-; \
    else echo "TOOLCHAIN_NOT_FOUND"; fi)

CC          := $(CROSS_COMPILE)gcc
AS          := $(CROSS_COMPILE)gcc
LD          := $(CROSS_COMPILE)ld
OBJCOPY     := $(CROSS_COMPILE)objcopy
OBJDUMP     := $(CROSS_COMPILE)objdump
SIZE        := $(CROSS_COMPILE)size

# Host compiler for unit tests
HOST_CC     := cc

# --- Directories -------------------------------------------------------------
SRCDIR      := kernel
ARCHDIR     := $(SRCDIR)/arch/arm64
BOOTDIR     := boot
BUILDDIR    := build
OBJDIR      := $(BUILDDIR)/obj
DEPDIR      := $(BUILDDIR)/dep
TESTDIR     := tests
SCRIPTDIR   := scripts

# --- Output ------------------------------------------------------------------
KERNEL_ELF  := $(BUILDDIR)/kiseki.elf
KERNEL_BIN  := $(BUILDDIR)/kiseki.bin
KERNEL_MAP  := $(BUILDDIR)/kiseki.map

# --- Linker Script -----------------------------------------------------------
ifeq ($(PLATFORM),qemu)
    LDSCRIPT := $(ARCHDIR)/linker-qemu.ld
    PLATFORM_DEF := -DPLATFORM_QEMU
    QEMU_BASE_ADDR := 0x40080000
else ifeq ($(PLATFORM),raspi4)
    LDSCRIPT := $(ARCHDIR)/linker-raspi4.ld
    PLATFORM_DEF := -DPLATFORM_RASPI4
else
    $(error Unknown PLATFORM: $(PLATFORM). Use 'qemu' or 'raspi4')
endif

# --- Compiler Flags ----------------------------------------------------------
INCLUDES    := -I$(SRCDIR)/include -Iinclude

# Debug flags
ifeq ($(DEBUG),1)
    DEBUG_DEF := -DDEBUG=1
else
    DEBUG_DEF :=
endif

CFLAGS      := -Wall -Wextra -Werror \
               -ffreestanding -fno-builtin -fno-stack-protector \
               -nostdinc -nostdlib \
               -mcpu=cortex-a72 -mgeneral-regs-only \
               -std=gnu11 -O2 -g \
               $(PLATFORM_DEF) \
               $(DEBUG_DEF) \
               $(INCLUDES)

ASFLAGS     := $(PLATFORM_DEF) $(INCLUDES) -D__ASSEMBLER__

LDFLAGS     := -nostdlib -static -T $(LDSCRIPT) \
               -Map=$(KERNEL_MAP)

# --- Source Files ------------------------------------------------------------
# Assembly sources (boot must be first for entry point)
ASM_SRCS    := $(ARCHDIR)/boot.S \
               $(ARCHDIR)/vectors.S \
               $(ARCHDIR)/context_switch.S

# C sources - Kernel core
KERN_SRCS   := $(SRCDIR)/kern/main.c \
               $(SRCDIR)/kern/kprintf.c \
               $(SRCDIR)/kern/trap.c \
               $(SRCDIR)/kern/pmm.c \
               $(SRCDIR)/kern/vmm.c \
               $(SRCDIR)/kern/sync.c \
               $(SRCDIR)/kern/sched.c \
               $(SRCDIR)/kern/macho.c \
               $(SRCDIR)/kern/proc.c \
               $(SRCDIR)/kern/commpage.c \
               $(SRCDIR)/kern/tty.c \
               $(SRCDIR)/kern/pty.c

# C sources - Architecture specific
ARCH_SRCS   := $(ARCHDIR)/smp.c

# C sources - Drivers
DRV_SRCS    := $(SRCDIR)/drivers/uart/pl011.c \
               $(SRCDIR)/drivers/uart/raspi_uart.c \
               $(SRCDIR)/drivers/gic/gicv2.c \
               $(SRCDIR)/drivers/timer/timer.c \
               $(SRCDIR)/drivers/virtio/virtio_blk.c \
               $(SRCDIR)/drivers/emmc/emmc.c \
               $(SRCDIR)/drivers/blkdev/blkdev.c \
               $(SRCDIR)/drivers/net/virtio_net.c

# C sources - BSD layer
BSD_SRCS    := $(SRCDIR)/bsd/syscalls.c \
               $(SRCDIR)/bsd/security.c

# C sources - Mach layer
MACH_SRCS   := $(SRCDIR)/mach/ipc.c

# C sources - Filesystem
FS_SRCS     := $(SRCDIR)/fs/buf.c \
               $(SRCDIR)/fs/vfs.c \
               $(SRCDIR)/fs/ext4/ext4.c \
               $(SRCDIR)/fs/devfs.c

# C sources - Networking
NET_SRCS    := $(SRCDIR)/net/socket.c \
               $(SRCDIR)/net/tcp.c \
               $(SRCDIR)/net/ip.c \
               $(SRCDIR)/net/eth.c \
               $(SRCDIR)/net/icmp.c \
               $(SRCDIR)/net/udp.c \
               $(SRCDIR)/net/dhcp.c

# All sources
C_SRCS      := $(KERN_SRCS) $(ARCH_SRCS) $(DRV_SRCS) $(BSD_SRCS) $(MACH_SRCS) $(FS_SRCS) $(NET_SRCS)

# --- Object Files ------------------------------------------------------------
ASM_OBJS    := $(patsubst %.S,$(OBJDIR)/%.o,$(ASM_SRCS))
C_OBJS      := $(patsubst %.c,$(OBJDIR)/%.o,$(C_SRCS))
ALL_OBJS    := $(ASM_OBJS) $(C_OBJS)
DEPS        := $(patsubst %.c,$(DEPDIR)/%.d,$(C_SRCS))

# --- Targets -----------------------------------------------------------------
.PHONY: all clean run run-debug test check-toolchain info disk userland world

all: check-toolchain $(KERNEL_BIN)
	@echo ""
	@echo "=== Kernel Build Complete ==="
	@$(SIZE) $(KERNEL_ELF)

# Build everything: kernel + userland + disk image
world: all userland disk
	@echo ""
	@echo "=== Full System Build Complete ==="
	@echo "  Kernel:   $(KERNEL_ELF)"
	@echo "  Userland: $(BUILDDIR)/userland/bin/"
	@echo "  Disk:     $(DISK_IMG)"
	@echo ""
	@echo "  Run: make run"

# Build userland (Mach-O: dyld + libSystem + sbin + bash + coreutils)
userland:
	@echo ""
	@echo "=== Building Userland (Mach-O) ==="
	@$(MAKE) -C userland all
	@echo ""
	@echo "=== Userland Build Complete ==="
	@echo "  Binaries: $$(ls $(BUILDDIR)/userland/bin/ $(BUILDDIR)/userland/sbin/ 2>/dev/null | wc -l | tr -d ' ') programs"

$(KERNEL_BIN): $(KERNEL_ELF)
	@echo "  OBJCOPY  $@"
	@$(OBJCOPY) -O binary $< $@

$(KERNEL_ELF): $(ALL_OBJS) $(LDSCRIPT)
	@echo "  LD       $@"
	@mkdir -p $(dir $@)
	@$(LD) $(LDFLAGS) $(ALL_OBJS) -o $@

# Compile C sources
$(OBJDIR)/%.o: %.c
	@echo "  CC       $<"
	@mkdir -p $(dir $@) $(dir $(DEPDIR)/$*.d)
	@$(CC) $(CFLAGS) -MMD -MP -MF $(DEPDIR)/$*.d -c $< -o $@

# Assemble .S sources
$(OBJDIR)/%.o: %.S
	@echo "  AS       $<"
	@mkdir -p $(dir $@)
	@$(AS) $(ASFLAGS) -c $< -o $@

# --- QEMU Targets ------------------------------------------------------------
QEMU        := qemu-system-aarch64
QEMU_FLAGS  := -M virt -cpu cortex-a72 -smp 4 -m 1G \
               -nographic \
               -kernel $(KERNEL_ELF) \
               -serial mon:stdio

# Add disk image if it exists (use virtio-blk-device for MMIO transport)
DISK_IMG    := $(BUILDDIR)/disk.img
ifneq ($(wildcard $(DISK_IMG)),)
    QEMU_FLAGS += -drive id=hd0,file=$(DISK_IMG),format=raw,if=none \
                  -device virtio-blk-device,drive=hd0
endif

# Add virtio-net device
# vmnet-shared: macOS native networking, guest gets a real LAN IP.
# Requires running QEMU with sudo (for vmnet framework access).
# The guest static IP is 192.168.64.10, host/gateway is 192.168.64.1.
QEMU_FLAGS += -netdev vmnet-shared,id=net0 \
              -device virtio-net-device,netdev=net0

run: all
	@echo ""
	@if [ -f "$(DISK_IMG)" ]; then \
		echo "  Booting with disk image: $(DISK_IMG)"; \
	else \
		echo "  WARNING: No disk image. Run 'make disk' first for root filesystem."; \
	fi
	@echo "  Network: vmnet-shared (guest 192.168.64.10, requires sudo)"
	@echo ""
	sudo $(QEMU) $(QEMU_FLAGS)

run-debug: all
	sudo $(QEMU) $(QEMU_FLAGS) -s -S &
	@echo "GDB server started on :1234. Attach with:"
	@echo "  $(CROSS_COMPILE)gdb -ex 'target remote :1234' $(KERNEL_ELF)"

# --- Test Targets -------------------------------------------------------------
TEST_SRCS   := $(wildcard $(TESTDIR)/unit/*.c)
TEST_BINS   := $(patsubst $(TESTDIR)/unit/%.c,$(BUILDDIR)/tests/%,$(TEST_SRCS))

test: $(TEST_BINS)
	@echo "=== Running Unit Tests ==="
	@for t in $(TEST_BINS); do \
		echo "--- Running $$t ---"; \
		$$t || exit 1; \
	done
	@echo "=== All Tests Passed ==="

# Run libSystem tests on Kiseki (boots QEMU, runs test_libc, exits)
# Uses user-mode networking (no sudo needed) for CI compatibility
QEMU_TEST_FLAGS := -M virt -cpu cortex-a72 -smp 4 -m 1G \
                   -nographic \
                   -kernel $(KERNEL_ELF) \
                   -serial mon:stdio \
                   -drive id=hd0,file=$(DISK_IMG),format=raw,if=none \
                   -device virtio-blk-device,drive=hd0 \
                   -netdev user,id=net0 \
                   -device virtio-net-device,netdev=net0

# Build disk with tests included
disk-test: userland
	@echo ""
	@echo "  MKDISK   $(DISK_IMG) (with tests)"
	@INCLUDE_TESTS=1 $(SCRIPTDIR)/mkdisk.sh $(DISK_IMG)

test-kiseki: all disk-test
	@echo "=== Running Kiseki libSystem Tests ==="
	@echo "Booting Kiseki and running /bin/test_libc..."
	@{ \
		sleep 4; \
		echo "root"; \
		sleep 1; \
		echo "toor"; \
		sleep 2; \
		echo "/bin/test_libc"; \
		sleep 15; \
		echo "exit"; \
	} | timeout 90 $(QEMU) $(QEMU_TEST_FLAGS) 2>&1 | tee $(BUILDDIR)/test_output.log; \
	if grep -q "All tests PASSED" $(BUILDDIR)/test_output.log; then \
		echo ""; \
		echo "=== Kiseki libSystem Tests PASSED ==="; \
	else \
		echo ""; \
		echo "=== Kiseki libSystem Tests FAILED ==="; \
		grep -E "(FAIL|tests failed)" $(BUILDDIR)/test_output.log || true; \
		exit 1; \
	fi

$(BUILDDIR)/tests/%: $(TESTDIR)/unit/%.c
	@echo "  HOST_CC  $<"
	@mkdir -p $(dir $@)
	@$(HOST_CC) -Wall -Wextra -g -I$(SRCDIR)/include -DUNIT_TEST -o $@ $<

# --- Disk Image ---------------------------------------------------------------
disk: userland
	@echo ""
	@echo "  MKDISK   $(DISK_IMG)"
	@$(SCRIPTDIR)/mkdisk.sh $(DISK_IMG)

# --- Utility Targets ----------------------------------------------------------
check-toolchain:
	@if [ "$(CROSS_COMPILE)" = "TOOLCHAIN_NOT_FOUND" ]; then \
		echo "ERROR: No aarch64 cross-compiler found."; \
		echo "Install one of:"; \
		echo "  brew install aarch64-elf-gcc          (macOS)"; \
		echo "  apt install gcc-aarch64-linux-gnu      (Debian/Ubuntu)"; \
		echo "  pacman -S aarch64-linux-gnu-gcc        (Arch)"; \
		exit 1; \
	fi
	@echo "  TOOLCHAIN $(CROSS_COMPILE)gcc"

info:
	@echo "Platform:       $(PLATFORM)"
	@echo "Cross-compile:  $(CROSS_COMPILE)"
	@echo "CC:             $(CC)"
	@echo "Linker script:  $(LDSCRIPT)"
	@echo "Kernel ELF:     $(KERNEL_ELF)"
	@echo "Kernel BIN:     $(KERNEL_BIN)"
	@echo "Sources (ASM):  $(ASM_SRCS)"
	@echo "Sources (C):    $(C_SRCS)"

clean:
	@echo "  CLEAN"
	@rm -rf $(BUILDDIR)

# --- Dependency Tracking ------------------------------------------------------
-include $(DEPS)
