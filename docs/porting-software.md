# Porting Software to Kiseki OS

This guide explains how to port existing software to run on Kiseki OS. Since Kiseki runs unmodified macOS ARM64 Mach-O binaries, many programs can be compiled directly with minimal or no changes.

## Overview

Kiseki provides:
- **100+ BSD syscalls** matching the Darwin/XNU interface
- **libSystem.B.dylib** with standard C library functions
- **Mach-O binary format** (same as macOS)
- **ARM64 ABI** (same as macOS)

## Step 1: Assess Compatibility

### 1.1 Check Syscall Requirements

First, identify what syscalls your software needs:

```bash
# On macOS, trace syscalls used by a program
sudo dtruss ./your_program 2>&1 | grep -E "^[a-z]" | awk '{print $1}' | sort -u
```

Or examine the source code for system call usage:
```bash
grep -rE "open|read|write|fork|exec|socket|mmap" src/
```

### 1.2 Compare Against Kiseki's Supported Syscalls

Check `kernel/bsd/syscalls.c` for the list of implemented syscalls. Key categories:

**Fully Supported:**
- File I/O: open, close, read, write, lseek, pread, pwrite
- File metadata: stat, fstat, lstat, chmod, chown, access
- Directory: mkdir, rmdir, getdirentries, getcwd, chdir
- Process: fork, execve, exit, wait4, getpid, getppid, kill
- Signals: sigaction, sigprocmask, kill
- Memory: mmap, munmap, mprotect
- Networking: socket, bind, listen, accept, connect, send, recv
- Terminal: ioctl (termios), tcgetattr, tcsetattr
- Time: gettimeofday, nanosleep

**Partially Supported:**
- select (basic implementation)
- fcntl (F_GETFL, F_SETFL, F_DUPFD)
- ioctl (common terminal ioctls)

**Not Yet Supported:**
- poll/epoll/kqueue
- Shared memory (shm_open, mmap MAP_SHARED)
- Semaphores (sem_*)
- Message queues
- Advanced signal features (sigqueue, signalfd)

### 1.3 Check Library Dependencies

List dynamic libraries your program needs:

```bash
# On macOS
otool -L ./your_program
```

Kiseki only provides `/usr/lib/libSystem.B.dylib`. If your program needs:
- **libSystem.B.dylib** - Supported
- **libc++.dylib** - Not supported (no C++ runtime)
- **CoreFoundation** - Not supported (no Objective-C/Swift)
- **Other frameworks** - Not supported

## Step 2: Prepare the Source

### 2.1 Include Kiseki Headers

For cross-compilation, point to Kiseki's headers:

```bash
# Headers are in userland/libsystem/include/
ls userland/libsystem/include/
```

Available headers:
- `<stdio.h>` - Standard I/O
- `<stdlib.h>` - Memory allocation, process control
- `<string.h>` - String operations
- `<unistd.h>` - POSIX API
- `<fcntl.h>` - File control
- `<sys/stat.h>` - File status
- `<sys/types.h>` - Type definitions
- `<sys/socket.h>` - Networking
- `<netinet/in.h>` - Internet protocols
- `<arpa/inet.h>` - IP address manipulation
- `<errno.h>` - Error codes
- `<signal.h>` - Signals
- `<termios.h>` - Terminal I/O
- `<dirent.h>` - Directory operations
- `<time.h>` - Time functions
- `<setjmp.h>` - Non-local jumps

### 2.2 Handle Missing Functions

If a function is missing from libSystem, you have options:

**Option A: Implement it in libSystem**
```c
// Add to userland/libsystem/libSystem.c
EXPORT int your_missing_function(...) {
    // Implementation
}
```

**Option B: Provide a local implementation**
```c
// In your program
#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t size) {
    // Implementation
}
#endif
```

**Option C: Use a compatible alternative**
```c
// Instead of strdup (if missing):
char *my_strdup(const char *s) {
    size_t len = strlen(s) + 1;
    char *p = malloc(len);
    if (p) memcpy(p, s, len);
    return p;
}
```

### 2.3 Handle Missing Syscalls

If a syscall is missing:

**Option A: Implement the syscall** (see [implementing-syscalls.md](implementing-syscalls.md))

**Option B: Stub it out**
```c
#ifdef __KISEKI__
int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    // Fall back to select() or busy-wait
    errno = ENOSYS;
    return -1;
}
#endif
```

**Option C: Use conditional compilation**
```c
#ifdef HAVE_KQUEUE
    kq = kqueue();
#else
    // Use select() instead
#endif
```

## Step 3: Compile for Kiseki

### 3.1 Using macOS Cross-Compilation

The standard approach - compile on macOS targeting Kiseki:

```bash
# Basic compilation
clang -target arm64-apple-macos11 \
    -isysroot $(xcrun --show-sdk-path) \
    -I/path/to/kiseki/userland/libsystem/include \
    -nostdlib \
    -o myprogram myprogram.c \
    -L/path/to/kiseki/build/userland/lib -lSystem.B \
    /path/to/kiseki/userland/libsystem/dyld.tbd
```

### 3.2 Using a Makefile

Example Makefile for a Kiseki userland program:

```makefile
# Kiseki userland program Makefile

KISEKI_ROOT := /path/to/kiseki
BUILDDIR := $(KISEKI_ROOT)/build/userland

CC := clang
CFLAGS := -target arm64-apple-macos11 \
          -isysroot $(shell xcrun --show-sdk-path) \
          -I$(KISEKI_ROOT)/userland/libsystem/include \
          -nostdlib -ffreestanding -fno-builtin \
          -O2 -Wall

LDFLAGS := -target arm64-apple-macos11 \
           -nostdlib \
           -L$(BUILDDIR)/lib -lSystem.B \
           $(KISEKI_ROOT)/userland/libsystem/dyld.tbd

PROG := myprogram
SRCS := main.c utils.c
OBJS := $(SRCS:.c=.o)

$(PROG): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(PROG) $(OBJS)

install: $(PROG)
	cp $(PROG) $(BUILDDIR)/bin/
```

### 3.3 Using TCC on Kiseki

For simple programs, compile directly on Kiseki:

```bash
# On Kiseki
tcc -o myprogram myprogram.c
./myprogram
```

TCC limitations:
- No C++ support
- Limited optimization
- Some C99/C11 features may not work
- No inline assembly

## Step 4: Add to Build System

### 4.1 Create Program Directory

```bash
mkdir -p userland/bin/myprogram
```

### 4.2 Create Makefile

```makefile
# userland/bin/myprogram/Makefile
include ../coreutils.mk

PROG := myprogram
SRCS := myprogram.c

$(PROG): $(SRCS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(BUILDDIR)/bin/$(PROG) $<

all: $(PROG)
clean:
	rm -f $(BUILDDIR)/bin/$(PROG)
```

### 4.3 Add to Parent Makefile

Edit `userland/bin/Makefile` to include your program:

```makefile
SUBDIRS += myprogram
```

### 4.4 Add to Disk Image

Edit `scripts/mkdisk.sh` to include your binary:

```bash
BIN_PROGS="... myprogram ..."
```

## Step 5: Test

### 5.1 Build Everything

```bash
make world
```

### 5.2 Boot and Test

```bash
make run
# In Kiseki:
myprogram --help
myprogram arg1 arg2
```

### 5.3 Debug Issues

**Program crashes immediately:**
- Check dyld output for missing symbols
- Verify all required libraries are available

**Syscall returns ENOSYS:**
- The syscall isn't implemented
- Check `kernel/bsd/syscalls.c` for the list

**Wrong behavior:**
- Syscall might be stubbed or partially implemented
- Check the implementation in syscalls.c

**Memory corruption:**
- Struct size mismatch between your code and libSystem
- Use `sizeof()` to verify struct sizes match macOS

## Example: Porting a Simple Program

Let's port a minimal HTTP client:

### Original Code (httpclient.c)

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <ip> <port>\n", argv[0]);
        return 1;
    }
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(argv[2]));
    addr.sin_addr.s_addr = inet_addr(argv[1]);
    
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        return 1;
    }
    
    const char *req = "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n";
    write(sock, req, strlen(req));
    
    char buf[4096];
    ssize_t n;
    while ((n = read(sock, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        printf("%s", buf);
    }
    
    close(sock);
    return 0;
}
```

### Compatibility Check

All required functions are available:
- `socket`, `connect`, `read`, `write`, `close` - ✓
- `inet_addr`, `htons`, `atoi` - ✓
- `printf`, `fprintf`, `perror` - ✓

### Compile and Test

```bash
# Create directory
mkdir -p userland/bin/httpclient

# Create Makefile
cat > userland/bin/httpclient/Makefile << 'EOF'
include ../coreutils.mk
PROG := httpclient
all:
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(BUILDDIR)/bin/$(PROG) httpclient.c
EOF

# Copy source
cp httpclient.c userland/bin/httpclient/

# Build
make world

# Test on Kiseki
# httpclient 93.184.216.34 80
```

## Common Porting Issues and Solutions

| Issue | Cause | Solution |
|-------|-------|----------|
| "symbol not found: _poll" | poll() not implemented | Use select() instead |
| "ENOSYS" from syscall | Syscall not implemented | Implement it or use alternative |
| Segfault on struct access | Struct layout mismatch | Verify sizes with sizeof() |
| "dyld: Library not loaded" | Missing library | Only libSystem.B.dylib is available |
| Infinite loop in select() | select() limitations | Check implementation in syscalls.c |
| Network timeout | No retransmission | TCP is basic; may need patience |
| C++ code fails | No C++ runtime | Rewrite in C or port libc++ |

## Supported Software Categories

**Likely to work with minimal changes:**
- Simple C utilities
- Text processing tools
- Network clients (basic TCP/UDP)
- File manipulation tools
- Math/computation programs

**May require some adaptation:**
- Interactive terminal programs (need termios support)
- Network servers (need proper accept() handling)
- Multi-process programs (fork/exec work, but complex IPC may not)

**Will not work without significant effort:**
- C++ programs (no runtime)
- GUI applications (no graphics)
- Programs using kqueue/epoll (not implemented)
- Programs using shared memory (not implemented)
- Objective-C/Swift programs (no runtime)

## Further Resources

- Kiseki syscall list: `kernel/bsd/syscalls.c`
- libSystem implementation: `userland/libsystem/libSystem.c`
- Example programs: `userland/bin/*/`
- Implementing new syscalls: [implementing-syscalls.md](implementing-syscalls.md)
