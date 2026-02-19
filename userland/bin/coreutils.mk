# ============================================================================
# Kiseki OS - Shared Coreutils Build Template (Mach-O)
# ============================================================================
# Builds userland binaries as arm64 Mach-O executables using macOS clang.
# These run on Kiseki OS via dyld + libSystem.B.dylib, identical to how
# a normal macOS binary is structured.
#
# Usage: In each utility's directory, create a Makefile with:
#   PROG := <name>        # Binary name
#   SRCS := <file.c ...>  # Source files
#   include ../coreutils.mk
# ============================================================================

CC      := clang
LD      := clang

# macOS SDK sysroot (needed for Homebrew clang)
SYSROOT := $(shell xcrun --show-sdk-path 2>/dev/null)

# Directories (relative to userland/bin/PROG/)
TOPBUILD := ../../../build
BUILDDIR := $(TOPBUILD)/userland
OBJDIR   := $(BUILDDIR)/obj/$(PROG)
BINDIR   := $(BUILDDIR)/bin

# Output binary
TARGET := $(BINDIR)/$(PROG)

# Compiler flags - produce arm64 Mach-O targeting macOS 11+
# The binary links dynamically against /usr/lib/libSystem.B.dylib
# which our custom dyld resolves at load time on Kiseki OS.
CFLAGS := -target arm64-apple-macos11 \
          -isysroot $(SYSROOT) \
          -Wall -Wextra \
          -O2 -g \
          -Wno-unused-parameter \
          -Wno-nullability-completeness

# Linker flags
LDFLAGS := -target arm64-apple-macos11 \
           -isysroot $(SYSROOT)

# Object files
OBJS := $(patsubst %.c,$(OBJDIR)/%.o,$(SRCS))

# Targets
.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	@echo "  LD       $(PROG)"
	@mkdir -p $(dir $@)
	@$(LD) $(LDFLAGS) -o $@ $(OBJS)

$(OBJDIR)/%.o: %.c
	@echo "  CC       $(PROG)/$<"
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo "  CLEAN    $(PROG)"
	@rm -rf $(OBJDIR) $(TARGET)
