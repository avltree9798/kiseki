# TCC (Tiny C Compiler) - Kiseki ARM64 Mach-O Build
#
# This builds TCC as a cross-compiler that runs on macOS but generates
# ARM64 Mach-O binaries for Kiseki.

SRCDIR = .
ROOTDIR = $(realpath ../../..)
BUILDDIR = $(ROOTDIR)/build/userland/tcc

# Sysroot for cross-compilation (points to Kiseki's filesystem layout)
# Headers are in userland/libsystem/include
KISEKI_SYSROOT = $(ROOTDIR)/sysroot

# Compiler settings
CC = clang
CFLAGS = -O2 -Wall -Wno-unused-parameter -Wno-sign-compare

# TCC source files (ONE_SOURCE mode - all included via libtcc.c)
TCC_SRC = tcc.c

# Output binary (runs on macOS host)
TCC_HOST = $(BUILDDIR)/tcc-host

# Kiseki native binary (runs on Kiseki)
TCC_KISEKI = $(BUILDDIR)/tcc

.PHONY: all clean host kiseki sysroot

all: host

# Create sysroot directory structure for cross-compilation
sysroot:
	@mkdir -p $(KISEKI_SYSROOT)/usr/include
	@mkdir -p $(KISEKI_SYSROOT)/usr/lib
	@# Copy headers from libsystem
	@cp -r $(ROOTDIR)/userland/libsystem/include/* $(KISEKI_SYSROOT)/usr/include/
	@echo "Created sysroot at $(KISEKI_SYSROOT)"

# Build TCC to run on macOS host, targeting Kiseki (cross-compiler)
host: sysroot $(TCC_HOST)

$(TCC_HOST): $(TCC_SRC) libtcc.c tcc.h config.h tccmacho.c arm64-gen.c arm64-link.c tccelf.c tccgen.c tccpp.c elf.h
	@mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) -DONE_SOURCE -DKISEKI_SYSROOT='"$(KISEKI_SYSROOT)"' -o $@ $(TCC_SRC)
	@echo "Built TCC cross-compiler: $@"
	@echo "  Sysroot: $(KISEKI_SYSROOT)"

# Build TCC to run natively on Kiseki
kiseki: sysroot $(TCC_KISEKI)

# Kiseki native build settings
KISEKI_CC = clang
KISEKI_CFLAGS = -target arm64-apple-macos11 \
	-O2 -Wall -Wno-unused-parameter -Wno-sign-compare \
	-ffreestanding -fno-builtin -fno-stack-protector \
	-nostdinc \
	-I$(ROOTDIR)/userland/libsystem/include \
	-DONE_SOURCE

KISEKI_LDFLAGS = -target arm64-apple-macos11 \
	-nostdlib \
	-L$(ROOTDIR)/build/userland/lib \
	-lSystem.B \
	$(ROOTDIR)/userland/libsystem/dyld.tbd \
	-Wl,-e,_main

$(TCC_KISEKI): $(TCC_SRC) libtcc.c tcc.h config.h tccmacho.c arm64-gen.c arm64-link.c tccelf.c tccgen.c tccpp.c elf.h
	@mkdir -p $(BUILDDIR)
	$(KISEKI_CC) $(KISEKI_CFLAGS) -c $(TCC_SRC) -o $(BUILDDIR)/tcc.o
	$(KISEKI_CC) $(KISEKI_LDFLAGS) -o $@ $(BUILDDIR)/tcc.o
	@echo "Built TCC for Kiseki: $@"

clean:
	rm -rf $(BUILDDIR)

# Test the cross-compiler
test: $(TCC_HOST)
	@echo "Testing TCC..."
	@echo 'int main() { return 42; }' > /tmp/test.c
	$(TCC_HOST) -c /tmp/test.c -o /tmp/test.o && echo "Compilation OK" || echo "Compilation FAILED"
	@rm -f /tmp/test.c /tmp/test.o
