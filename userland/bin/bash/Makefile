# ============================================================================
# Kiseki OS - Bash-compatible Shell (Mach-O)
# ============================================================================
# Built as an arm64 Mach-O binary using macOS clang.
# Runs on Kiseki OS via dyld + libSystem.B.dylib.
# ============================================================================

CC      := clang
LD      := clang

# macOS SDK sysroot (needed for Homebrew clang)
SYSROOT := $(shell xcrun --show-sdk-path 2>/dev/null)

# Directories (relative to userland/bin/bash/)
SRCDIR   := .
TOPBUILD := ../../../build
BUILDDIR := $(TOPBUILD)/userland
OBJDIR   := $(BUILDDIR)/obj/bash
BINDIR   := $(BUILDDIR)/bin

# Output binary
TARGET  := $(BINDIR)/bash

# Compiler flags - arm64 Mach-O
CFLAGS  := -target arm64-apple-macos11 \
           -isysroot $(SYSROOT) \
           -Wall -Wextra \
           -O2 -g \
           -Wno-unused-parameter \
           -Wno-nullability-completeness

# Linker flags
LDFLAGS := -target arm64-apple-macos11 \
           -isysroot $(SYSROOT)

# Source files
SRCS    := main.c \
           lexer.c \
           parser.c \
           expand.c \
           execute.c \
           builtins.c \
           variables.c \
           jobs.c \
           history.c \
           readline.c

# Object files
OBJS    := $(patsubst %.c,$(OBJDIR)/%.o,$(SRCS))

# Targets
.PHONY: all clean

all: $(TARGET)
	@echo "  bash built successfully"

$(TARGET): $(OBJS)
	@echo "  LD       bash"
	@mkdir -p $(dir $@)
	@$(LD) $(LDFLAGS) -o $@ $(OBJS)

# Compile C sources
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@echo "  CC       bash/$<"
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -c $< -o $@

# Header dependencies (all .c files depend on these headers)
$(OBJS): $(SRCDIR)/shell.h $(SRCDIR)/lexer.h $(SRCDIR)/parser.h $(SRCDIR)/expand.h

clean:
	@echo "  CLEAN    bash"
	@rm -rf $(OBJDIR) $(TARGET)
