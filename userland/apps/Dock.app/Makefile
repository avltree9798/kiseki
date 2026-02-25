# ============================================================================
# Kiseki OS - Dock.app
# ============================================================================
# Desktop wallpaper + dock bar application.
# Uses COMDAT-stripping pipeline for GNUstep libobjc2 ABI v1.
# ============================================================================

BUILDDIR  := ../../../build/userland
APPDIR    := $(BUILDDIR)/Applications/Dock.app
OBJDIR    := $(BUILDDIR)/obj/Dock

BINARY    := $(APPDIR)/Dock

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
	@echo "  Dock.app built successfully"

$(OBJDIR)/Dock.o: Dock.m
	@echo "  OBJC→IR  Dock.m"
	@mkdir -p $(dir $@)
	$(CC) $(OBJCFLAGS) -S -emit-llvm $< -o $(OBJDIR)/Dock.ll
	@echo "  SED      strip COMDATs"
	sed 's/linkonce_odr constant/private constant/g; /^\$$\.objc_sel_name.* = comdat any$$/d; s/, comdat//g' \
		$(OBJDIR)/Dock.ll > $(OBJDIR)/Dock.clean.ll
	@echo "  LLC      Dock.clean.ll → Dock.o"
	$(LLC) -mtriple=arm64-apple-macos11 -filetype=obj $(OBJDIR)/Dock.clean.ll -o $@

$(BINARY): $(OBJDIR)/Dock.o $(TBDS)
	@echo "  APP      Dock.app"
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -o $@ $(OBJDIR)/Dock.o $(TBDS)

clean:
	@echo "  CLEAN    Dock.app"
	@rm -rf $(APPDIR) $(OBJDIR)
