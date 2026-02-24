# ============================================================================
# Kiseki OS - IOKit.framework (Mach-O Framework)
# ============================================================================
# Builds the IOKit client library as a Mach-O dynamic library with the
# standard macOS framework install name. On macOS, this is built from
# IOKitUser/IOKitLib.c and installed at:
#   /System/Library/Frameworks/IOKit.framework/Versions/A/IOKit
#
# IOKit.framework depends on libSystem.B.dylib for Mach IPC functions
# (mach_msg, mach_reply_port, etc.). This dependency is resolved at
# link time via libSystem.tbd, and at runtime by Kiseki's dyld.
#
# Usage:
#   make            - Build IOKit framework dylib
#   make clean      - Clean
# ============================================================================

# Directories
BUILDDIR  := ../../build/userland
FWDIR     := $(BUILDDIR)/System/Library/Frameworks/IOKit.framework/Versions/A

# Output - framework dylib with macOS-standard install name
DYLIB     := $(FWDIR)/IOKit

# Compiler
CC        := clang

CFLAGS    := -target arm64-apple-macos11 \
             -nostdlib -ffreestanding -fno-builtin \
             -fno-stack-protector \
             -mcpu=cortex-a53 \
             -O2 -Wall -Wextra \
             -Wno-unused-parameter \
             -std=gnu11

LDFLAGS   := -target arm64-apple-macos11 \
             -nostdlib -shared \
             -Wl,-dylib \
             -Wl,-install_name,/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit \
             -Wl,-compatibility_version,1.0.0 \
             -Wl,-current_version,1.0.0

.PHONY: all clean

all: $(DYLIB)
	@echo "  IOKit.framework built successfully"

$(DYLIB): IOKitLib.c libSystem.tbd dyld.tbd
	@echo "  FRAMEWORK  IOKit.framework"
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ IOKitLib.c libSystem.tbd dyld.tbd

clean:
	@echo "  CLEAN    IOKit.framework"
	@rm -rf $(BUILDDIR)/System/Library/Frameworks/IOKit.framework
