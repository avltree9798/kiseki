# ============================================================================
# Kiseki OS - Terminal.app
# ============================================================================
# Terminal emulator application.
# Uses COMDAT-stripping pipeline for GNUstep libobjc2 ABI v1.
# ============================================================================

BUILDDIR  := ../../../build/userland
APPDIR    := $(BUILDDIR)/Applications/Terminal.app
OBJDIR    := $(BUILDDIR)/obj/Terminal

BINARY    := $(APPDIR)/Terminal

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
	@echo "  Terminal.app built successfully"

$(OBJDIR)/Terminal.o: Terminal.m
	@echo "  OBJC→IR  Terminal.m"
	@mkdir -p $(dir $@)
	$(CC) $(OBJCFLAGS) -S -emit-llvm $< -o $(OBJDIR)/Terminal.ll
	@echo "  SED      strip COMDATs"
	sed 's/linkonce_odr constant/private constant/g; /^\$$\.objc_sel_name.* = comdat any$$/d; s/, comdat//g' \
		$(OBJDIR)/Terminal.ll > $(OBJDIR)/Terminal.clean.ll
	@echo "  LLC      Terminal.clean.ll → Terminal.o"
	$(LLC) -mtriple=arm64-apple-macos11 -filetype=obj $(OBJDIR)/Terminal.clean.ll -o $@

$(BINARY): $(OBJDIR)/Terminal.o $(TBDS)
	@echo "  APP      Terminal.app"
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -o $@ $(OBJDIR)/Terminal.o $(TBDS)

clean:
	@echo "  CLEAN    Terminal.app"
	@rm -rf $(APPDIR) $(OBJDIR)
