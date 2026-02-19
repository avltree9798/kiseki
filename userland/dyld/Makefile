# ============================================================================
# Kiseki OS - Dynamic Linker (dyld) Build
# ============================================================================
#
# Builds dyld as a Mach-O MH_DYLINKER binary using the macOS clang
# toolchain. dyld is completely self-contained: no standard library,
# no LC_LOAD_DYLIB, no LC_LOAD_DYLINKER. It uses raw syscalls for
# all I/O and memory allocation.
#
# Output: build/userland/dyld/dyld
#
# Usage:
#   make            - Build dyld
#   make clean      - Remove build artifacts
#   make verify     - Build and verify binary type
# ============================================================================

# --- Toolchain ---------------------------------------------------------------
# We use the host macOS clang to produce an arm64 Mach-O.
CC      := clang
AS      := clang

# --- Directories -------------------------------------------------------------
BUILDDIR := ../../build/userland/dyld
OBJDIR   := $(BUILDDIR)/obj

# --- Output ------------------------------------------------------------------
TARGET   := $(BUILDDIR)/dyld

# --- Sources -----------------------------------------------------------------
C_SRCS   := dyld.c
ASM_SRCS := start.S

C_OBJS   := $(patsubst %.c,$(OBJDIR)/%.o,$(C_SRCS))
ASM_OBJS := $(patsubst %.S,$(OBJDIR)/%.o,$(ASM_SRCS))
ALL_OBJS := $(ASM_OBJS) $(C_OBJS)

# --- Compiler Flags ----------------------------------------------------------
# -target arm64-apple-macos11 : Produce ARM64 Mach-O
# -ffreestanding              : No hosted environment assumptions
# -fno-builtin                : Don't use builtin functions
# -fno-stack-protector        : No stack canary (no libc to provide __stack_chk)
# -nostdinc                   : No standard include paths
# -nostdlib                   : No standard library
# -O2                         : Optimize (important for code size)
# -g                          : Debug info (stripped in release)
# -Wall -Wextra               : Warnings
CFLAGS := \
    -target arm64-apple-macos11 \
    -ffreestanding \
    -fno-builtin \
    -fno-stack-protector \
    -fno-exceptions \
    -fno-unwind-tables \
    -fno-asynchronous-unwind-tables \
    -nostdinc \
    -nostdlib \
    -std=gnu11 \
    -O2 -g \
    -Wall -Wextra -Wno-unused-parameter

ASFLAGS := \
    -target arm64-apple-macos11 \
    -ffreestanding \
    -nostdinc \
    -nostdlib

# --- Linker Flags ------------------------------------------------------------
# -nostdlib                   : No standard library
# -static                     : Static linking (no LC_LOAD_DYLIB)
# -Wl,-dylinker               : Mark output as MH_DYLINKER filetype
# -Wl,-e,_start               : Entry point symbol
# -Wl,-dylinker_install_name,/usr/lib/dyld : Install name for LC_ID_DYLINKER
# -Wl,-dead_strip             : Remove unused code
# -Wl,-no_uuid                : Skip UUID (optional)
LDFLAGS := \
    -target arm64-apple-macos11 \
    -nostdlib \
    -static \
    -Wl,-dylinker \
    -Wl,-e,_start \
    -Wl,-dylinker_install_name,/usr/lib/dyld

# ============================================================================
# Targets
# ============================================================================

.PHONY: all clean verify

all: $(TARGET)
	@echo "  dyld built: $(TARGET)"

$(TARGET): $(ALL_OBJS)
	@echo "  LD       $@"
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -o $@ $^

# Compile C sources
$(OBJDIR)/%.o: %.c
	@echo "  CC       $<"
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# Assemble .S sources
$(OBJDIR)/%.o: %.S
	@echo "  AS       $<"
	@mkdir -p $(dir $@)
	$(AS) $(ASFLAGS) -c $< -o $@

# Verify the resulting binary is correct
verify: $(TARGET)
	@echo "=== Verifying dyld binary ==="
	@file $(TARGET)
	@echo "--- Mach-O header ---"
	@otool -h $(TARGET)
	@echo "--- Load commands (summary) ---"
	@otool -l $(TARGET) | grep -E '(cmd |name |entry)'
	@echo "--- Ensuring no LC_LOAD_DYLIB ---"
	@if otool -l $(TARGET) | grep -q LC_LOAD_DYLIB; then \
		echo "ERROR: dyld must not have LC_LOAD_DYLIB!"; \
		exit 1; \
	fi
	@echo "--- Ensuring MH_DYLINKER filetype (7) ---"
	@if ! otool -h $(TARGET) | grep -qE '^\s+0xfeedfacf.*\s7\s'; then \
		echo "ERROR: dyld must be MH_DYLINKER filetype (7)!"; \
		exit 1; \
	fi
	@echo "=== dyld binary verified OK ==="

clean:
	@echo "  CLEAN    dyld"
	@rm -rf $(OBJDIR) $(TARGET)
