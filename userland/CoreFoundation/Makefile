# ============================================================================
# Kiseki OS - CoreFoundation.framework (Mach-O Framework)
# ============================================================================
# Builds the CoreFoundation library as a Mach-O dynamic library with the
# standard macOS framework install name. On macOS, this is built from
# Apple's CF sources and installed at:
#   /System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation
#
# CoreFoundation.framework depends on libSystem.B.dylib for memory allocation,
# string operations, and Mach IPC (for CFRunLoop).
#
# This is a freestanding build — no macOS SDK headers are used.
# All types are defined inline in the source files.
#
# Usage:
#   make            - Build CoreFoundation framework dylib
#   make clean      - Clean
# ============================================================================

# Directories
BUILDDIR  := ../../build/userland
FWDIR     := $(BUILDDIR)/System/Library/Frameworks/CoreFoundation.framework/Versions/A

# Output - framework dylib with macOS-standard install name
DYLIB     := $(FWDIR)/CoreFoundation

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
             -Wl,-install_name,/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation \
             -Wl,-compatibility_version,1.0.0 \
             -Wl,-current_version,1153.18

.PHONY: all clean

all: $(DYLIB)
	@echo "  CoreFoundation.framework built successfully"

$(DYLIB): CoreFoundation.c libSystem.tbd dyld.tbd
	@echo "  FRAMEWORK  CoreFoundation.framework"
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ CoreFoundation.c libSystem.tbd dyld.tbd

clean:
	@echo "  CLEAN    CoreFoundation.framework"
	@rm -rf $(BUILDDIR)/System/Library/Frameworks/CoreFoundation.framework
