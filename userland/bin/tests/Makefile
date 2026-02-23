# Kiseki OS - Unit Tests
# These tests are built with the host clang for the Kiseki userland

BUILDDIR := ../../../build/userland
LIBDIR   := $(BUILDDIR)/lib
BINDIR   := $(BUILDDIR)/bin

# Compiler settings (macOS clang targeting Kiseki)
# NOTE: -mcpu=cortex-a53 ensures ARMv8.0 compatible atomics (LDXR/STXR)
CC := clang
CFLAGS := -target arm64-apple-macos11 \
          -nostdlib -ffreestanding -fno-builtin \
          -mcpu=cortex-a53 \
          -I../../libsystem/include \
          -O2 -Wall

LDFLAGS := -target arm64-apple-macos11 \
           -nostdlib \
           -L$(LIBDIR) -lSystem.B \
           ../../libsystem/dyld.tbd \
           -Wl,-e,_main

TESTS := test_libc

.PHONY: all clean

all: $(TESTS:%=$(BINDIR)/%)

$(BINDIR)/test_libc: test_libc.c
	@echo "  CC       $@"
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	@echo "  CLEAN    tests"
	@rm -f $(TESTS:%=$(BINDIR)/%)
