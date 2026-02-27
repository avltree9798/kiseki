# ============================================================================
# Kiseki OS - System Binaries (Mach-O)
# ============================================================================
# Builds /sbin/init, /sbin/getty, /bin/login as arm64 Mach-O executables.
# These run on Kiseki OS via dyld + libSystem.B.dylib.
# ============================================================================

CC      := clang
LD      := clang

# macOS SDK sysroot (needed for Homebrew clang)
SYSROOT := $(shell xcrun --show-sdk-path 2>/dev/null)

# Directories
TOPBUILD := ../../build
BUILDDIR := $(TOPBUILD)/userland
OBJDIR   := $(BUILDDIR)/obj/sbin
BINDIR   := $(BUILDDIR)/sbin

# Our custom userland headers - IOKit framework headers directory
# This directory contains ONLY the IOKit/ subdirectory so that
# #include <IOKit/IOKitLib.h> resolves here, but other system headers
# (#include <stdio.h> etc.) still resolve from the macOS SDK sysroot.
IOKIT_INC := ../IOKit/include

# Compiler flags - arm64 Mach-O
CFLAGS  := -target arm64-apple-macos11 \
           -isysroot $(SYSROOT) \
           -Wall -Wextra \
           -O2 -g \
           -Wno-unused-parameter \
           -Wno-nullability-completeness

# Extra flags for programs that need our custom IOKit headers
# -I adds the IOKit include directory (contains only IOKit/ subdir)
CFLAGS_IOKIT := $(CFLAGS) -I$(IOKIT_INC)

LDFLAGS := -target arm64-apple-macos11 \
           -isysroot $(SYSROOT)

# Programs
PROGS := init getty login halt reboot shutdown sshd mDNSResponder WindowServer loginwindow

TARGETS := $(patsubst %,$(BINDIR)/%,$(PROGS))

.PHONY: all clean

all: $(TARGETS)

# halt, reboot, shutdown are all built from halt.c (argv[0] differentiates)
$(BINDIR)/halt: $(OBJDIR)/halt.o
	@echo "  LD       sbin/halt"
	@mkdir -p $(dir $@)
	@$(LD) $(LDFLAGS) -o $@ $<

$(BINDIR)/reboot: $(OBJDIR)/halt.o
	@echo "  LD       sbin/reboot"
	@mkdir -p $(dir $@)
	@$(LD) $(LDFLAGS) -o $@ $<

$(BINDIR)/shutdown: $(OBJDIR)/halt.o
	@echo "  LD       sbin/shutdown"
	@mkdir -p $(dir $@)
	@$(LD) $(LDFLAGS) -o $@ $<

# WindowServer needs our custom IOKit headers
$(OBJDIR)/WindowServer.o: WindowServer.c
	@echo "  CC       sbin/WindowServer.c (IOKit)"
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS_IOKIT) -c $< -o $@

# WindowServer links against IOKit.framework (via TBD stub)
IOKIT_TBD := ../IOKit/IOKit.tbd
$(BINDIR)/WindowServer: $(OBJDIR)/WindowServer.o
	@echo "  LD       sbin/WindowServer (IOKit)"
	@mkdir -p $(dir $@)
	@$(LD) $(LDFLAGS) -o $@ $< $(IOKIT_TBD)

$(BINDIR)/%: $(OBJDIR)/%.o
	@echo "  LD       sbin/$*"
	@mkdir -p $(dir $@)
	@$(LD) $(LDFLAGS) -o $@ $<

$(OBJDIR)/%.o: %.c
	@echo "  CC       sbin/$<"
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo "  CLEAN    sbin"
	@rm -rf $(OBJDIR) $(TARGETS)
