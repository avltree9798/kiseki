# ============================================================================
# Kiseki OS - AppKit.framework (Mach-O Framework)
# ============================================================================
# Objective-C application framework providing NSApplication, NSWindow,
# NSView, NSEvent, NSMenu, NSColor, NSFont, NSGraphicsContext, NSTextField,
# NSButton. Connects to WindowServer via Mach IPC.
#
# Uses the COMDAT-stripping pipeline for GNUstep libobjc2 ABI v1:
#   .m → LLVM IR → sed strip COMDATs → llc → .o
#
# Depends on: libSystem.B.dylib, libobjc.A.dylib, CoreFoundation.framework,
#             CoreGraphics.framework, CoreText.framework, Foundation.framework
# ============================================================================

BUILDDIR  := ../../build/userland
FWDIR     := $(BUILDDIR)/System/Library/Frameworks/AppKit.framework/Versions/A
OBJDIR    := $(BUILDDIR)/obj/AppKit

DYLIB     := $(FWDIR)/AppKit

# macOS SDK sysroot (for ObjC language headers)
SYSROOT   := $(shell xcrun --show-sdk-path)

CC        := clang
LLC       := /opt/homebrew/opt/llvm/bin/llc

# Clang flags for emitting LLVM IR from Objective-C
OBJCFLAGS := -target arm64-apple-macos11 \
             -fobjc-runtime=gnustep-1.9 \
             -isysroot $(SYSROOT) \
             -nostdlib -ffreestanding -fno-builtin \
             -fno-stack-protector \
             -mcpu=cortex-a53 \
             -O2 -Wall -Wextra \
             -Wno-unused-parameter \
             -Wno-unused-function \
             -Wno-objc-root-class \
             -Wno-deprecated-objc-isa-usage \
             -std=gnu11

LDFLAGS   := -target arm64-apple-macos11 \
             -nostdlib -shared \
             -Wl,-dylib \
             -Wl,-install_name,/System/Library/Frameworks/AppKit.framework/Versions/A/AppKit \
             -Wl,-compatibility_version,1.0.0 \
             -Wl,-current_version,1.0.0

TBDS      := libSystem.tbd dyld.tbd libobjc.tbd \
             CoreFoundation.tbd CoreGraphics.tbd CoreText.tbd Foundation.tbd

.PHONY: all clean

all: $(DYLIB)
	@echo "  AppKit.framework built successfully"

# COMDAT-stripping pipeline:
#   1. Compile .m to LLVM IR (.ll)
#   2. sed: strip COMDAT groups (linkonce_odr → private, remove comdat directives)
#   3. llc: compile cleaned IR to Mach-O object file
$(OBJDIR)/AppKit.o: AppKit.m
	@echo "  OBJC→IR  AppKit.m"
	@mkdir -p $(dir $@)
	$(CC) $(OBJCFLAGS) -S -emit-llvm $< -o $(OBJDIR)/AppKit.ll
	@echo "  SED      strip COMDATs"
	sed 's/linkonce_odr constant/private constant/g; /^\$$\.objc_sel_name.* = comdat any$$/d; s/, comdat//g' \
		$(OBJDIR)/AppKit.ll > $(OBJDIR)/AppKit.clean.ll
	@echo "  LLC      AppKit.clean.ll → AppKit.o"
	$(LLC) -mtriple=arm64-apple-macos11 -filetype=obj $(OBJDIR)/AppKit.clean.ll -o $@

$(DYLIB): $(OBJDIR)/AppKit.o $(TBDS)
	@echo "  FRAMEWORK  AppKit.framework"
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -o $@ $(OBJDIR)/AppKit.o $(TBDS)

clean:
	@echo "  CLEAN    AppKit.framework"
	@rm -rf $(BUILDDIR)/System/Library/Frameworks/AppKit.framework $(OBJDIR)
