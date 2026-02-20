# ============================================================================
# Kiseki OS - libSystem.B.dylib (Mach-O Dynamic Library)
# ============================================================================
# Builds the userland C library as a Mach-O dynamic library using macOS clang.
#
# The dyld_stub_binder symbol is resolved via dyld.tbd (text-based stub),
# which tells the linker that dyld will provide this symbol at runtime.
# This mirrors how macOS handles the circular dependency between libSystem
# and dyld.
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

# Pass DEBUG flag if set
ifdef DEBUG
DYLIB_CFLAGS += -DDEBUG=$(DEBUG)
endif

# Link against dyld.tbd stub to resolve dyld_stub_binder
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

$(DYLIB): libSystem.c dyld.tbd
	@echo "  DYLIB    $@"
	@mkdir -p $(dir $@)
	$(DYLIB_CC) $(DYLIB_CFLAGS) $(DYLIB_LDFLAGS) -o $@ $< dyld.tbd

clean:
	@echo "  CLEAN    libSystem"
	@rm -f $(DYLIB)
