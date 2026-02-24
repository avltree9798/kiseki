# ============================================================================
# Kiseki OS - libobjc.A.dylib (GNUstep Objective-C Runtime)
# ============================================================================
# Port of GNUstep libobjc2 to Kiseki OS.
#
# This builds the Objective-C runtime as a Mach-O dynamic library at:
#   /usr/lib/libobjc.A.dylib
#
# The runtime provides:
#   - objc_msgSend (AArch64 assembly fast path)
#   - Class registration and method dispatch
#   - ARC (Automatic Reference Counting)
#   - Blocks runtime
#   - @synchronized support
#   - Property accessors
#
# All .m/.mm files have been converted to pure C/C++ to avoid
# Mach-O COMDAT incompatibility with GNUstep ObjC ABI.
#
# Dependencies:
#   - libSystem.B.dylib (malloc, pthreads, mmap, C stdlib)
#
# Usage:
#   make            - Build libobjc.A.dylib
#   make clean      - Clean
# ============================================================================

# Directories
BUILDDIR := ../../build/userland
LIBDIR   := $(BUILDDIR)/lib
OBJDIR   := $(BUILDDIR)/obj/libobjc

# macOS SDK for C++ standard library headers
SYSROOT  := $(shell xcrun --show-sdk-path)

# Output
DYLIB    := $(LIBDIR)/libobjc.A.dylib

# Compilers
CC       := clang
CXX      := clang++

# Include paths:
#   - . for internal headers (class.h, lock.h, etc.)
#   - ./objc for public headers
#   - ./tsl for vendored robin-map
#
# We do NOT include Kiseki libsystem headers here. The macOS SDK
# (via -isysroot) provides all standard headers (pthread.h, sys/mman.h,
# stdint.h, etc.). At runtime, symbols resolve against Kiseki's
# libSystem.B.dylib — the API is compatible.
INCLUDES := -I. -I./tsl

# Common flags for all languages
ARCH_FLAGS := -target arm64-apple-macos11 \
              -mcpu=cortex-a53

# Defines matching GNUstep CMakeLists.txt
DEFINES := -DGNUSTEP \
           -D__OBJC_RUNTIME_INTERNAL__=1 \
           -DTYPE_DEPENDENT_DISPATCH \
           -DOLDABI_COMPAT=1 \
           -D__OBJC_BOOL \
           -DEMBEDDED_BLOCKS_RUNTIME \
           -D__GNUSTEP_MSGSEND__=1

# C flags
CFLAGS   := $(ARCH_FLAGS) \
            -isysroot $(SYSROOT) \
            $(INCLUDES) \
            $(DEFINES) \
            -O2 -std=gnu11 \
            -fPIC \
            -fno-stack-protector \
            -Wno-unused-parameter \
            -Wno-deprecated-declarations \
            -Wno-tautological-pointer-compare \
            -Wno-unused-variable \
            -Wno-int-conversion \
            -Wno-incompatible-pointer-types \
            -Wno-sign-compare \
            -Wno-missing-field-initializers

# (Objective-C flags removed — all .m files converted to .c)

# C++ flags
CXXFLAGS := $(ARCH_FLAGS) \
            -isysroot $(SYSROOT) \
            $(INCLUDES) \
            $(DEFINES) \
            -O2 -std=c++17 \
            -fPIC \
            -fno-stack-protector \
            -fno-exceptions \
            -fno-rtti \
            -Wno-unused-parameter \
            -Wno-deprecated-declarations \
            -Wno-sign-compare

# (Objective-C++ flags removed — arc.mm converted to arc.cc)

# Assembly flags
ASFLAGS  := $(ARCH_FLAGS) \
            -isysroot $(SYSROOT) \
            $(INCLUDES) \
            $(DEFINES)

# Link flags
LDFLAGS  := -target arm64-apple-macos11 \
            -nostdlib -shared \
            -Wl,-dylib \
            -Wl,-install_name,/usr/lib/libobjc.A.dylib \
            -Wl,-compatibility_version,1.0.0 \
            -Wl,-current_version,2.2.0

# TBD stubs for dependencies
TBDS     := libSystem.tbd dyld.tbd

# ============================================================================
# Source files
# ============================================================================

# Pure C sources (core runtime + converted .m files)
C_SRCS := alias_table.c \
          builtin_classes.c \
          caps.c \
          category_loader.c \
          class_table.c \
          dtable.c \
          encoding2.c \
          gc_none.c \
          hooks.c \
          ivar.c \
          loader.c \
          protocol.c \
          runtime.c \
          sarray2.c \
          sendmsg2.c \
          block_to_imp.c \
          legacy.c \
          statics_loader.c \
          abi_version.c \
          NSBlocks.c \
          associate.c \
          blocks_runtime.c \
          blocks_runtime_np.c \
          properties.c \
          mutation.c \
          fast_paths.c

# C++ sources (selector_table.cc + arc.cc converted from arc.mm)
CXX_SRCS := selector_table.cc \
            arc.cc

# Assembly sources
ASM_SRCS := objc_msgSend.S \
            block_trampolines.S

# ============================================================================
# Object files
# ============================================================================

C_OBJS      := $(patsubst %.c,$(OBJDIR)/%.o,$(C_SRCS))
CXX_OBJS    := $(patsubst %.cc,$(OBJDIR)/%.o,$(CXX_SRCS))
ASM_OBJS    := $(patsubst %.S,$(OBJDIR)/%.o,$(ASM_SRCS))

ALL_OBJS    := $(C_OBJS) $(CXX_OBJS) $(ASM_OBJS)

# ============================================================================
# Rules
# ============================================================================

.PHONY: all clean

all: $(DYLIB)
	@echo "  libobjc.A.dylib built successfully"

$(DYLIB): $(ALL_OBJS) $(TBDS)
	@echo "  DYLIB    libobjc.A.dylib"
	@mkdir -p $(dir $@)
	$(CXX) $(LDFLAGS) -o $@ $(ALL_OBJS) $(TBDS)

# C sources
$(OBJDIR)/%.o: %.c
	@echo "  CC(objc) $<"
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

# C++ sources
$(OBJDIR)/%.o: %.cc
	@echo "  CXX      $<"
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

# Assembly sources
$(OBJDIR)/%.o: %.S
	@echo "  AS(objc) $<"
	@mkdir -p $(dir $@)
	$(CC) $(ASFLAGS) -c -o $@ $<

clean:
	@echo "  CLEAN    libobjc"
	@rm -rf $(OBJDIR) $(DYLIB)
