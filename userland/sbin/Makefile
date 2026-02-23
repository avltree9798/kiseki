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

# Compiler flags - arm64 Mach-O
CFLAGS  := -target arm64-apple-macos11 \
           -isysroot $(SYSROOT) \
           -Wall -Wextra \
           -O2 -g \
           -Wno-unused-parameter \
           -Wno-nullability-completeness

LDFLAGS := -target arm64-apple-macos11 \
           -isysroot $(SYSROOT)

# Programs
PROGS := init getty login halt reboot shutdown sshd mDNSResponder

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
