# ============================================================================
# Kiseki OS - CoreText.framework (Mach-O Framework)
# ============================================================================
# Software text layout and font management. Provides CTFont, CTLine,
# CTFramesetter for text shaping and rendering into CGContexts.
#
# Depends on: libSystem.B.dylib, CoreFoundation.framework, CoreGraphics.framework
# ============================================================================

BUILDDIR  := ../../build/userland
FWDIR     := $(BUILDDIR)/System/Library/Frameworks/CoreText.framework/Versions/A

DYLIB     := $(FWDIR)/CoreText

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
             -Wl,-install_name,/System/Library/Frameworks/CoreText.framework/Versions/A/CoreText \
             -Wl,-compatibility_version,1.0.0 \
             -Wl,-current_version,1.0.0

.PHONY: all clean

all: $(DYLIB)
	@echo "  CoreText.framework built successfully"

$(DYLIB): CoreText.c libSystem.tbd dyld.tbd CoreFoundation.tbd CoreGraphics.tbd
	@echo "  FRAMEWORK  CoreText.framework"
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ CoreText.c libSystem.tbd dyld.tbd CoreFoundation.tbd CoreGraphics.tbd

clean:
	@echo "  CLEAN    CoreText.framework"
	@rm -rf $(BUILDDIR)/System/Library/Frameworks/CoreText.framework
