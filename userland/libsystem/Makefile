# ============================================================================
# Kiseki OS - libSystem.B.dylib (Mach-O Dynamic Library)
# ============================================================================
# Builds the userland C library as a Mach-O dynamic library using macOS clang.
# This is the only libSystem target — the old ELF libsystem.a is removed.
#
# Usage:
#   make            - Build libSystem.B.dylib
#   make dylib      - Same as above
#   make clean      - Clean everything
# ============================================================================

# Directories
BUILDDIR := ../../build/userland
LIBDIR   := $(BUILDDIR)/lib

# Output - Mach-O dynamic library
DYLIB   := $(LIBDIR)/libSystem.B.dylib

# Compiler flags for Mach-O dylib (macOS clang)
DYLIB_CC     := clang
DYLIB_CFLAGS := -target arm64-apple-macos11 \
                -nostdlib -ffreestanding -fno-builtin \
                -fno-stack-protector \
                -O2 -Wall -Wextra \
                -Wno-unused-parameter

DYLIB_LDFLAGS := -target arm64-apple-macos11 \
                 -nostdlib -shared \
                 -Wl,-dylib \
                 -Wl,-install_name,/usr/lib/libSystem.B.dylib \
                 -Wl,-compatibility_version,1.0.0 \
                 -Wl,-current_version,1.0.0

# Targets
.PHONY: all dylib clean

all: dylib

dylib: $(DYLIB)
	@echo "  libSystem.B.dylib built successfully"

$(DYLIB): libSystem.c
	@echo "  DYLIB    $@"
	@mkdir -p $(dir $@)
	$(DYLIB_CC) $(DYLIB_CFLAGS) $(DYLIB_LDFLAGS) -o $@ $<

clean:
	@echo "  CLEAN    libSystem"
	@rm -f $(DYLIB)
