# ============================================================================
# Kiseki OS - CoreGraphics.framework (Mach-O Framework)
# ============================================================================
# Builds the CoreGraphics library as a Mach-O dynamic library.
# Installed at:
#   /System/Library/Frameworks/CoreGraphics.framework/Versions/A/CoreGraphics
#
# CoreGraphics depends on libSystem.B.dylib and CoreFoundation.framework.
#
# Usage:
#   make            - Build CoreGraphics framework dylib
#   make clean      - Clean
# ============================================================================

# Directories
BUILDDIR  := ../../build/userland
FWDIR     := $(BUILDDIR)/System/Library/Frameworks/CoreGraphics.framework/Versions/A

# Output
DYLIB     := $(FWDIR)/CoreGraphics

# CoreFoundation TBD for link-time dependency
CF_TBD    := CoreFoundation.tbd

# Compiler
CC        := clang

CFLAGS    := -target arm64-apple-macos11 \
             -nostdlib -ffreestanding -fno-builtin \
             -fno-stack-protector \
             -mcpu=cortex-a53 \
             -O2 -Wall -Wextra \
             -Wno-unused-parameter \
             -Wno-unused-function \
             -std=gnu11

LDFLAGS   := -target arm64-apple-macos11 \
             -nostdlib -shared \
             -Wl,-dylib \
             -Wl,-install_name,/System/Library/Frameworks/CoreGraphics.framework/Versions/A/CoreGraphics \
             -Wl,-compatibility_version,1.0.0 \
             -Wl,-current_version,1.0.0

.PHONY: all clean

all: $(DYLIB)
	@echo "  CoreGraphics.framework built successfully"

$(DYLIB): CoreGraphics.c cg_font8x16.inc libSystem.tbd dyld.tbd $(CF_TBD)
	@echo "  FRAMEWORK  CoreGraphics.framework"
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ CoreGraphics.c libSystem.tbd dyld.tbd $(CF_TBD)

clean:
	@echo "  CLEAN    CoreGraphics.framework"
	@rm -rf $(BUILDDIR)/System/Library/Frameworks/CoreGraphics.framework
