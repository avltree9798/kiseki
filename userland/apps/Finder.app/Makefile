# ============================================================================
# Kiseki OS - Finder.app
# ============================================================================
# File browser / desktop icon host application.
# Uses COMDAT-stripping pipeline for GNUstep libobjc2 ABI v1.
# ============================================================================

BUILDDIR  := ../../../build/userland
APPDIR    := $(BUILDDIR)/Applications/Finder.app
OBJDIR    := $(BUILDDIR)/obj/Finder

BINARY    := $(APPDIR)/Finder

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
	@echo "  Finder.app built successfully"

$(OBJDIR)/Finder.o: Finder.m
	@echo "  OBJC→IR  Finder.m"
	@mkdir -p $(dir $@)
	$(CC) $(OBJCFLAGS) -S -emit-llvm $< -o $(OBJDIR)/Finder.ll
	@echo "  SED      strip COMDATs"
	sed 's/linkonce_odr constant/private constant/g; /^\$$\.objc_sel_name.* = comdat any$$/d; s/, comdat//g' \
		$(OBJDIR)/Finder.ll > $(OBJDIR)/Finder.clean.ll
	@echo "  LLC      Finder.clean.ll → Finder.o"
	$(LLC) -mtriple=arm64-apple-macos11 -filetype=obj $(OBJDIR)/Finder.clean.ll -o $@

$(BINARY): $(OBJDIR)/Finder.o $(TBDS)
	@echo "  APP      Finder.app"
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -o $@ $(OBJDIR)/Finder.o $(TBDS)

clean:
	@echo "  CLEAN    Finder.app"
	@rm -rf $(APPDIR) $(OBJDIR)
