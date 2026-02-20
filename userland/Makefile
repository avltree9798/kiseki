# ============================================================================
# Kiseki OS - Userland Build (Mach-O)
# ============================================================================
# Builds all userland components as arm64 Mach-O binaries using macOS clang.
# These run on Kiseki OS via dyld + libSystem.B.dylib.
#
# Usage:
#   make              - Build everything
#   make dyld         - Build dynamic linker only
#   make libsystem    - Build libSystem.B.dylib only
#   make bash         - Build bash only
#   make coreutils    - Build all coreutils
#   make sbin         - Build init/getty/login
#   make clean        - Clean all
# ============================================================================

# All coreutil programs (each has a directory under bin/)
COREUTILS := cat cp mv rm ln touch mkdir rmdir \
             echo head tail wc sort uniq cut tr tee \
             grep ls sed awk find xargs \
             ps kill env sleep time timeout clear sync \
             id whoami uname date which hostname \
             chmod chown df du mount umount \
             login su sudo passwd adduser useradd usermod \
             printf test true false yes basename dirname expr \
             vi

# Networking tools
NETTOOLS := ifconfig ping nc curl ntpdate

.PHONY: all dyld libsystem bash coreutils nettools sbin clean $(COREUTILS) $(NETTOOLS)

all: dyld libsystem sbin bash coreutils nettools

dyld:
	@echo "=== Building dyld ==="
	@$(MAKE) -C dyld

libsystem:
	@echo "=== Building libSystem.B.dylib ==="
	@$(MAKE) -C libSystem dylib

sbin:
	@echo "=== Building sbin (init/getty/login) ==="
	@$(MAKE) -C sbin

bash:
	@echo "=== Building bash ==="
	@$(MAKE) -C bin/bash

coreutils: $(COREUTILS)

$(COREUTILS):
	@$(MAKE) -C bin/$@

nettools: $(NETTOOLS)

$(NETTOOLS):
	@$(MAKE) -C bin/$@

clean:
	@$(MAKE) -C dyld clean
	@$(MAKE) -C libSystem clean
	@$(MAKE) -C sbin clean
	@$(MAKE) -C bin/bash clean
	@for prog in $(COREUTILS); do \
		if [ -d bin/$$prog ]; then $(MAKE) -C bin/$$prog clean; fi; \
	done
	@for prog in $(NETTOOLS); do \
		if [ -d bin/$$prog ]; then $(MAKE) -C bin/$$prog clean; fi; \
	done
	@echo "=== Clean complete ==="
