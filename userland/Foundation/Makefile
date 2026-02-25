# ============================================================================
# Kiseki OS - Foundation.framework (Mach-O Framework)
# ============================================================================
# Objective-C bridge over CoreFoundation. Provides NSString, NSDictionary,
# NSArray, NSNumber, NSRunLoop, NSObject, NSAutoreleasePool — all toll-free
# bridged to their CF counterparts.
#
# Uses the COMDAT-stripping pipeline for GNUstep libobjc2 ABI v1:
#   .m → LLVM IR → sed strip COMDATs → llc → .o
#
# Depends on: libSystem.B.dylib, libobjc.A.dylib, CoreFoundation.framework
# ============================================================================

BUILDDIR  := ../../build/userland
FWDIR     := $(BUILDDIR)/System/Library/Frameworks/Foundation.framework/Versions/A
OBJDIR    := $(BUILDDIR)/obj/Foundation

DYLIB     := $(FWDIR)/Foundation

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
             -Wl,-install_name,/System/Library/Frameworks/Foundation.framework/Versions/A/Foundation \
             -Wl,-compatibility_version,1.0.0 \
             -Wl,-current_version,1.0.0

TBDS      := libSystem.tbd dyld.tbd libobjc.tbd CoreFoundation.tbd

.PHONY: all clean

all: $(DYLIB)
	@echo "  Foundation.framework built successfully"

# COMDAT-stripping pipeline:
#   1. Compile .m to LLVM IR (.ll)
#   2. sed: strip COMDAT groups (linkonce_odr → private, remove comdat directives)
#   3. llc: compile cleaned IR to Mach-O object file
$(OBJDIR)/Foundation.o: Foundation.m
	@echo "  OBJC→IR  Foundation.m"
	@mkdir -p $(dir $@)
	$(CC) $(OBJCFLAGS) -S -emit-llvm $< -o $(OBJDIR)/Foundation.ll
	@echo "  SED      strip COMDATs"
	sed 's/linkonce_odr constant/private constant/g; /^\$$\.objc_sel_name.* = comdat any$$/d; s/, comdat//g' \
		$(OBJDIR)/Foundation.ll > $(OBJDIR)/Foundation.clean.ll
	@echo "  LLC      Foundation.clean.ll → Foundation.o"
	$(LLC) -mtriple=arm64-apple-macos11 -filetype=obj $(OBJDIR)/Foundation.clean.ll -o $@

$(DYLIB): $(OBJDIR)/Foundation.o $(TBDS)
	@echo "  FRAMEWORK  Foundation.framework"
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -o $@ $(OBJDIR)/Foundation.o $(TBDS)

clean:
	@echo "  CLEAN    Foundation.framework"
	@rm -rf $(BUILDDIR)/System/Library/Frameworks/Foundation.framework $(OBJDIR)
