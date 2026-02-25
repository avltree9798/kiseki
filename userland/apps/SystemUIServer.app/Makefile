# ============================================================================
# Kiseki OS - SystemUIServer.app
# ============================================================================
# Menu bar extras process — displays clock in top-right of menu bar.
# Uses COMDAT-stripping pipeline for GNUstep libobjc2 ABI v1.
# ============================================================================

BUILDDIR  := ../../../build/userland
APPDIR    := $(BUILDDIR)/Applications/SystemUIServer.app
OBJDIR    := $(BUILDDIR)/obj/SystemUIServer

BINARY    := $(APPDIR)/SystemUIServer

SYSROOT   := $(shell xcrun --show-sdk-path)
CC        := clang
LLC       := /opt/homebrew/opt/llvm/bin/llc

USERLAND  := ../..

OBJCFLAGS := -target arm64-apple-macos11 \
             -fobjc-runtime=gnustep-1.9 \
             -isysroot $(SYSROOT) \
             -I$(USERLAND)/libsystem/include \
             -I$(USERLAND)/libobjc \
             -I$(USERLAND) \
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
             -nostdlib \
             -Wl,-e,_main

TBDS      := libSystem.tbd dyld.tbd libobjc.tbd \
             CoreFoundation.tbd CoreGraphics.tbd Foundation.tbd AppKit.tbd

.PHONY: all clean

all: $(BINARY)
	@echo "  SystemUIServer.app built successfully"

$(OBJDIR)/SystemUIServer.o: SystemUIServer.m
	@echo "  OBJC→IR  SystemUIServer.m"
	@mkdir -p $(dir $@)
	$(CC) $(OBJCFLAGS) -S -emit-llvm $< -o $(OBJDIR)/SystemUIServer.ll
	@echo "  SED      strip COMDATs"
	sed 's/linkonce_odr constant/private constant/g; /^\$$\.objc_sel_name.* = comdat any$$/d; s/, comdat//g' \
		$(OBJDIR)/SystemUIServer.ll > $(OBJDIR)/SystemUIServer.clean.ll
	@echo "  LLC      SystemUIServer.clean.ll → SystemUIServer.o"
	$(LLC) -mtriple=arm64-apple-macos11 -filetype=obj $(OBJDIR)/SystemUIServer.clean.ll -o $@

$(BINARY): $(OBJDIR)/SystemUIServer.o $(TBDS)
	@echo "  APP      SystemUIServer.app"
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -o $@ $(OBJDIR)/SystemUIServer.o $(TBDS)

clean:
	@echo "  CLEAN    SystemUIServer.app"
	@rm -rf $(APPDIR) $(OBJDIR)
