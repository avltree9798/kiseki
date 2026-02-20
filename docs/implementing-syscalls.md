# Implementing a New Syscall in Kiseki

This guide explains how to add a new BSD syscall to Kiseki OS. The process involves understanding the Darwin/XNU syscall ABI, finding the correct syscall number, implementing the kernel handler, and exposing the syscall to userland.

## Overview

Kiseki implements the Darwin/XNU syscall interface:
- Syscalls are invoked via `svc #0x80`
- Syscall number is passed in register `x16`
- Positive numbers = BSD syscalls, negative = Mach traps
- Arguments in `x0`–`x5`
- Return value in `x0`
- Error: carry flag set + positive errno in `x0`

## Step 1: Find the Syscall Number

### Option A: Check Apple's Official Headers

The authoritative source is Apple's XNU source code:
- https://opensource.apple.com/source/xnu/

Look for `bsd/kern/syscalls.master` which defines all BSD syscalls:

```
1   AUE_EXIT    ALL { void exit(int rval); }
2   AUE_FORK    ALL { int fork(void); }
3   AUE_NULL    ALL { user_ssize_t read(int fd, user_addr_t cbuf, user_size_t nbyte); }
...
```

### Option B: Check macOS SDK Headers

On a Mac, examine:
```bash
# Syscall numbers
grep -r "SYS_" /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h

# Struct definitions
ls /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/
```

### Option C: Use Our Existing Reference

Check `kernel/bsd/syscalls.c` for syscalls already implemented - they include the correct numbers.

## Step 2: Research the Syscall Semantics

### Understanding the Arguments

For each syscall, you need to know:
1. **Argument types and sizes** - ARM64 passes args in x0-x5 (64-bit each)
2. **Struct layouts** - Must match macOS ARM64 SDK exactly
3. **Return value semantics** - What does success/failure look like?
4. **Error codes** - Which errno values can be returned?

### Example: Researching `fchmodat`

```bash
# On macOS, check the man page
man fchmodat

# Check the prototype
grep fchmodat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/stat.h
```

Result:
```c
int fchmodat(int fd, const char *path, mode_t mode, int flag);
```

Arguments:
- `x0` = fd (int, but passed as 64-bit)
- `x1` = path (user pointer)
- `x2` = mode (mode_t = uint16_t on Darwin)
- `x3` = flag (int, AT_SYMLINK_NOFOLLOW etc)

## Step 3: Add the Syscall Handler

### File: `kernel/bsd/syscalls.c`

This is the main syscall implementation file (~4700 lines). Find the syscall dispatch table and add your handler.

### 3.1 Add a Forward Declaration

Near the top of the file, add:
```c
static int sys_fchmodat(struct proc *p, struct trapframe *tf);
```

### 3.2 Add to Dispatch Table

Find the `syscall_handler` function and add your syscall to the switch statement:

```c
case 470:  /* fchmodat */
    ret = sys_fchmodat(p, tf);
    break;
```

### 3.3 Implement the Handler

```c
/*
 * fchmodat(2) - change mode of file relative to directory fd
 *
 * int fchmodat(int fd, const char *path, mode_t mode, int flag);
 */
static int sys_fchmodat(struct proc *p, struct trapframe *tf)
{
    int fd = (int)tf->regs[0];
    const char *upath = (const char *)tf->regs[1];
    mode_t mode = (mode_t)tf->regs[2];
    int flag = (int)tf->regs[3];
    
    char path[PATH_MAX];
    int err;
    
    /* Copy path from userspace */
    err = copyinstr(upath, path, sizeof(path));
    if (err)
        return err;
    
    /* Handle AT_FDCWD */
    struct vnode *dvp;
    if (fd == AT_FDCWD) {
        dvp = p->p_cwd;
        vnode_ref(dvp);
    } else {
        struct file *fp = fd_get(p, fd);
        if (!fp || fp->f_type != DTYPE_VNODE)
            return EBADF;
        dvp = fp->f_vnode;
        vnode_ref(dvp);
    }
    
    /* Resolve path relative to dvp */
    struct vnode *vp;
    err = vfs_lookupat(dvp, path, &vp, 
                       (flag & AT_SYMLINK_NOFOLLOW) ? LOOKUP_NOFOLLOW : 0);
    vnode_rele(dvp);
    if (err)
        return err;
    
    /* Permission check: must be owner or root */
    if (p->p_ucred->cr_uid != 0 && p->p_ucred->cr_uid != vp->v_uid) {
        vnode_rele(vp);
        return EPERM;
    }
    
    /* Update mode */
    err = VOP_SETATTR(vp, &(struct vattr){ .va_mode = mode });
    vnode_rele(vp);
    
    return err;
}
```

## Step 4: Add Userland Wrapper (libSystem)

### File: `userland/libsystem/libSystem.c`

Add the userland wrapper that invokes the syscall:

```c
EXPORT int fchmodat(int fd, const char *path, mode_t mode, int flag)
{
    long ret = __syscall(470, fd, (long)path, mode, flag, 0, 0);
    if (ret < 0) {
        errno = (int)(-ret);
        return -1;
    }
    return (int)ret;
}
```

### File: `userland/libsystem/include/sys/stat.h`

Add the function prototype:

```c
int fchmodat(int fd, const char *path, mode_t mode, int flag);
```

## Step 5: Define Constants

If your syscall uses flags or constants, add them to the appropriate header.

### File: `userland/libsystem/include/fcntl.h`

```c
#define AT_FDCWD            -2
#define AT_SYMLINK_NOFOLLOW 0x0020
#define AT_REMOVEDIR        0x0080
```

## Step 6: Handle Struct Compatibility

**Critical:** All structs must match macOS ARM64 layout exactly.

### Checking Struct Sizes on macOS

```c
// On macOS, compile and run:
#include <stdio.h>
#include <sys/stat.h>

int main() {
    printf("sizeof(struct stat) = %zu\n", sizeof(struct stat));
    printf("offsetof(st_mode) = %zu\n", offsetof(struct stat, st_mode));
    // etc.
}
```

### Common Struct Sizes (macOS ARM64)

| Struct | Size (bytes) |
|--------|--------------|
| `struct stat` | 144 |
| `struct dirent` | 1048 |
| `struct statfs` | 2168 |
| `struct termios` | 72 |
| `struct timeval` | 16 |
| `struct timespec` | 16 |
| `struct sockaddr` | 16 |
| `struct sockaddr_in` | 16 |

## Step 7: Test the Syscall

### Create a Test Program

```c
// test_fchmodat.c
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>

int main() {
    // Create test file
    FILE *f = fopen("/tmp/test", "w");
    fclose(f);
    
    // Change mode relative to current directory
    int ret = fchmodat(AT_FDCWD, "/tmp/test", 0755, 0);
    if (ret < 0) {
        perror("fchmodat");
        return 1;
    }
    
    printf("fchmodat succeeded\n");
    return 0;
}
```

### Build and Test

```bash
# On macOS host
make world

# On Kiseki
./test_fchmodat
```

## Common Pitfalls

### 1. Wrong Syscall Number

Always verify the syscall number against XNU source. Numbers differ between macOS versions and between x86_64 and ARM64.

### 2. Struct Layout Mismatch

A single byte of padding difference will cause memory corruption. Always verify with `sizeof()` and `offsetof()`.

### 3. Pointer Size Assumptions

ARM64 pointers are 64-bit. Never truncate to 32-bit.

### 4. Error Convention

Darwin uses carry flag + positive errno, not negative return values like Linux:

```c
// WRONG (Linux style)
return -ENOENT;

// CORRECT (Darwin style)
return ENOENT;  // Kernel sets carry flag automatically
```

### 5. Missing Permission Checks

Always check:
- File permissions (read/write/execute)
- Ownership for privileged operations
- Root bypass where appropriate

## Reference: Syscall Categories

| Category | Example Syscalls | Notes |
|----------|------------------|-------|
| Process | fork, execve, exit, wait4 | Process lifecycle |
| File I/O | open, read, write, close | Basic file operations |
| File Metadata | stat, chmod, chown | Requires permission checks |
| Directory | mkdir, rmdir, getdirentries | Directory operations |
| Memory | mmap, munmap, mprotect | Virtual memory |
| Signals | sigaction, kill, sigprocmask | Signal handling |
| Networking | socket, bind, connect, send | BSD sockets |
| Time | gettimeofday, nanosleep | Time operations |
| System | sysctl, reboot | System control |

## Files to Edit Summary

| File | Purpose |
|------|---------|
| `kernel/bsd/syscalls.c` | Main syscall implementations |
| `kernel/include/sys/syscall.h` | Syscall number definitions (optional) |
| `userland/libsystem/libSystem.c` | Userland wrappers |
| `userland/libsystem/include/*.h` | Function prototypes and constants |

## Further Reading

- Apple XNU Source: https://opensource.apple.com/source/xnu/
- Darwin syscall ABI: Search for "Darwin syscall convention ARM64"
- Existing Kiseki syscalls: `kernel/bsd/syscalls.c` (best reference)
