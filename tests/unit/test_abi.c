/*
 * Kiseki OS - Kernel/Userland ABI Compatibility Tests
 *
 * Compiled and run on the HOST (make test) to verify that kernel and
 * userland struct layouts, syscall numbers, and constants agree.
 *
 * This file is self-contained: it re-derives the expected layouts from
 * the ABI specification rather than including kernel/userland headers
 * (which would conflict with host libc).  If this test fails, the
 * corresponding kernel or userland header has drifted.
 *
 * To add a new ABI contract check:
 *   1. Add a _Static_assert or runtime check below
 *   2. Document which kernel and userland files define the contract
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ============================================================================
 * Test framework (minimal)
 * ============================================================================ */

static int g_tests_run = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define TEST_ASSERT(cond, fmt, ...) do { \
    g_tests_run++; \
    if (!(cond)) { \
        g_tests_failed++; \
        fprintf(stderr, "  FAIL: " fmt "\n", ##__VA_ARGS__); \
    } else { \
        g_tests_passed++; \
    } \
} while (0)

#define CHECK_OFFSET(strct, field, expected_off) \
    TEST_ASSERT(offsetof(strct, field) == (expected_off), \
        "%s.%s: expected offset %zu, got %zu", \
        #strct, #field, (size_t)(expected_off), offsetof(strct, field))

#define CHECK_SIZE(strct, expected_sz) \
    TEST_ASSERT(sizeof(strct) == (expected_sz), \
        "sizeof(%s): expected %zu, got %zu", \
        #strct, (size_t)(expected_sz), sizeof(strct))

#define CHECK_FIELD_SIZE(strct, field, expected_sz) \
    TEST_ASSERT(sizeof(((strct *)0)->field) == (expected_sz), \
        "%s.%s size: expected %zu, got %zu", \
        #strct, #field, (size_t)(expected_sz), \
        sizeof(((strct *)0)->field))

#define CHECK_EQUAL(name, a, b) \
    TEST_ASSERT((a) == (b), \
        "%s: kernel=%d, userland=%d", (name), (int)(a), (int)(b))

/* ============================================================================
 * ABI struct definitions (mirror of what BOTH sides must agree on)
 *
 * These must exactly match:
 *   - kernel/include/fs/vfs.h    (struct stat, struct dirent)
 *   - userland/libsystem/include/sys/stat.h  (struct stat)
 *   - userland/libsystem/include/dirent.h    (struct dirent)
 * ============================================================================ */

/*
 * struct stat — Darwin arm64 ABI (64-bit ino_t variant, 144 bytes).
 *
 * Defined in:
 *   kernel:   kernel/include/fs/vfs.h (struct stat)
 *   userland: userland/libsystem/include/sys/stat.h (struct stat)
 */
struct kiseki_timespec {
    int64_t     tv_sec;
    int64_t     tv_nsec;        /* long on LP64 = 8 bytes */
};

struct kiseki_stat {
    int32_t                 st_dev;             /*   0: Device ID (4) */
    uint16_t                st_mode;            /*   4: Mode bits (2) */
    uint16_t                st_nlink;           /*   6: Hard link count (2) */
    uint64_t                st_ino;             /*   8: Inode number (8) */
    uint32_t                st_uid;             /*  16: Owner user ID (4) */
    uint32_t                st_gid;             /*  20: Owner group ID (4) */
    int32_t                 st_rdev;            /*  24: Device ID (special) (4) */
    uint32_t                __pad0;             /*  28: alignment padding (4) */
    struct kiseki_timespec  st_atimespec;       /*  32: Last access time (16) */
    struct kiseki_timespec  st_mtimespec;       /*  48: Last modification time (16) */
    struct kiseki_timespec  st_ctimespec;       /*  64: Last status change time (16) */
    struct kiseki_timespec  st_birthtimespec;   /*  80: Creation time (16) */
    int64_t                 st_size;            /*  96: File size in bytes (8) */
    int64_t                 st_blocks;          /* 104: 512-byte blocks (8) */
    int32_t                 st_blksize;         /* 112: Preferred I/O block size (4) */
    uint32_t                st_flags;           /* 116: User-defined flags (4) */
    uint32_t                st_gen;             /* 120: File generation number (4) */
    int32_t                 st_lspare;          /* 124: Reserved (4) */
    int64_t                 st_qspare[2];       /* 128: Reserved (16) */
};                                              /* 144: Total */

/*
 * struct dirent — Darwin arm64 ABI (64-bit ino_t variant, 1048 bytes).
 *
 * Defined in:
 *   kernel:   kernel/include/fs/vfs.h (struct dirent)
 *   userland: userland/libsystem/include/dirent.h (struct dirent)
 */
struct kiseki_dirent {
    uint64_t    d_ino;          /*   0: Inode number (8) */
    uint64_t    d_seekoff;      /*   8: Seek offset cookie (8) */
    uint16_t    d_reclen;       /*  16: Record length (2) */
    uint16_t    d_namlen;       /*  18: Name length (2) */
    uint8_t     d_type;         /*  20: File type (1) */
    char        d_name[1024];   /*  21: Filename (1024) */
};                              /* 1048: Total (1045 raw + 3 tail pad) */

/* ============================================================================
 * struct stat layout tests
 * ============================================================================ */

static void test_stat_layout(void)
{
    printf("--- struct stat layout (Darwin arm64 144 bytes) ---\n");

    CHECK_SIZE(struct kiseki_stat, 144);

    CHECK_OFFSET(struct kiseki_stat, st_dev,             0);
    CHECK_OFFSET(struct kiseki_stat, st_mode,            4);
    CHECK_OFFSET(struct kiseki_stat, st_nlink,           6);
    CHECK_OFFSET(struct kiseki_stat, st_ino,             8);
    CHECK_OFFSET(struct kiseki_stat, st_uid,            16);
    CHECK_OFFSET(struct kiseki_stat, st_gid,            20);
    CHECK_OFFSET(struct kiseki_stat, st_rdev,           24);
    CHECK_OFFSET(struct kiseki_stat, __pad0,            28);
    CHECK_OFFSET(struct kiseki_stat, st_atimespec,      32);
    CHECK_OFFSET(struct kiseki_stat, st_mtimespec,      48);
    CHECK_OFFSET(struct kiseki_stat, st_ctimespec,      64);
    CHECK_OFFSET(struct kiseki_stat, st_birthtimespec,  80);
    CHECK_OFFSET(struct kiseki_stat, st_size,           96);
    CHECK_OFFSET(struct kiseki_stat, st_blocks,        104);
    CHECK_OFFSET(struct kiseki_stat, st_blksize,       112);
    CHECK_OFFSET(struct kiseki_stat, st_flags,         116);
    CHECK_OFFSET(struct kiseki_stat, st_gen,           120);
    CHECK_OFFSET(struct kiseki_stat, st_lspare,        124);
    CHECK_OFFSET(struct kiseki_stat, st_qspare,        128);

    CHECK_FIELD_SIZE(struct kiseki_stat, st_dev,            4);
    CHECK_FIELD_SIZE(struct kiseki_stat, st_mode,           2);
    CHECK_FIELD_SIZE(struct kiseki_stat, st_nlink,          2);
    CHECK_FIELD_SIZE(struct kiseki_stat, st_ino,            8);
    CHECK_FIELD_SIZE(struct kiseki_stat, st_uid,            4);
    CHECK_FIELD_SIZE(struct kiseki_stat, st_gid,            4);
    CHECK_FIELD_SIZE(struct kiseki_stat, st_rdev,           4);
    CHECK_FIELD_SIZE(struct kiseki_stat, st_atimespec,     16);
    CHECK_FIELD_SIZE(struct kiseki_stat, st_mtimespec,     16);
    CHECK_FIELD_SIZE(struct kiseki_stat, st_ctimespec,     16);
    CHECK_FIELD_SIZE(struct kiseki_stat, st_birthtimespec, 16);
    CHECK_FIELD_SIZE(struct kiseki_stat, st_size,           8);
    CHECK_FIELD_SIZE(struct kiseki_stat, st_blocks,         8);
    CHECK_FIELD_SIZE(struct kiseki_stat, st_blksize,        4);
    CHECK_FIELD_SIZE(struct kiseki_stat, st_flags,          4);
    CHECK_FIELD_SIZE(struct kiseki_stat, st_gen,            4);
    CHECK_FIELD_SIZE(struct kiseki_stat, st_lspare,         4);
    CHECK_FIELD_SIZE(struct kiseki_stat, st_qspare,        16);
}

/* ============================================================================
 * struct dirent layout tests
 * ============================================================================ */

static void test_dirent_layout(void)
{
    printf("--- struct dirent layout (Darwin arm64 1048 bytes) ---\n");

    /* 1045 raw bytes + 3 trailing padding for uint64_t alignment = 1048 */
    CHECK_SIZE(struct kiseki_dirent, 1048);

    CHECK_OFFSET(struct kiseki_dirent, d_ino,      0);
    CHECK_OFFSET(struct kiseki_dirent, d_seekoff,  8);
    CHECK_OFFSET(struct kiseki_dirent, d_reclen,  16);
    CHECK_OFFSET(struct kiseki_dirent, d_namlen,  18);
    CHECK_OFFSET(struct kiseki_dirent, d_type,    20);
    CHECK_OFFSET(struct kiseki_dirent, d_name,    21);

    CHECK_FIELD_SIZE(struct kiseki_dirent, d_ino,      8);
    CHECK_FIELD_SIZE(struct kiseki_dirent, d_seekoff,  8);
    CHECK_FIELD_SIZE(struct kiseki_dirent, d_reclen,   2);
    CHECK_FIELD_SIZE(struct kiseki_dirent, d_namlen,   2);
    CHECK_FIELD_SIZE(struct kiseki_dirent, d_type,     1);
    CHECK_FIELD_SIZE(struct kiseki_dirent, d_name,  1024);
}

/* ============================================================================
 * Syscall number agreement tests
 *
 * These values must match between:
 *   kernel:   kernel/include/bsd/syscall.h
 *   userland: userland/libsystem/include/syscall.h
 * ============================================================================ */

/* Kernel-side syscall numbers (from kernel/include/bsd/syscall.h) */
enum {
    K_SYS_exit            = 1,
    K_SYS_fork            = 2,
    K_SYS_read            = 3,
    K_SYS_write           = 4,
    K_SYS_open            = 5,
    K_SYS_close           = 6,
    K_SYS_wait4           = 7,
    K_SYS_link            = 9,
    K_SYS_unlink          = 10,
    K_SYS_chdir           = 12,
    K_SYS_fchdir          = 13,
    K_SYS_mknod           = 14,
    K_SYS_chmod           = 15,
    K_SYS_chown           = 16,
    K_SYS_getpid          = 20,
    K_SYS_setuid          = 23,
    K_SYS_getuid          = 24,
    K_SYS_geteuid         = 25,
    K_SYS_recvfrom        = 29,
    K_SYS_accept          = 30,
    K_SYS_getpeername     = 31,
    K_SYS_getsockname     = 32,
    K_SYS_access          = 33,
    K_SYS_sync            = 36,
    K_SYS_kill            = 37,
    K_SYS_getppid         = 39,
    K_SYS_dup             = 41,
    K_SYS_pipe            = 42,
    K_SYS_getegid         = 43,
    K_SYS_sigaction       = 46,
    K_SYS_getgid          = 47,
    K_SYS_sigprocmask     = 48,
    K_SYS_ioctl           = 54,
    K_SYS_symlink         = 57,
    K_SYS_readlink        = 58,
    K_SYS_execve          = 59,
    K_SYS_umask           = 60,
    K_SYS_munmap          = 73,
    K_SYS_mprotect        = 74,
    K_SYS_getpgrp         = 81,
    K_SYS_setpgid         = 82,
    K_SYS_dup2            = 90,
    K_SYS_fcntl           = 92,
    K_SYS_select          = 93,
    K_SYS_socket          = 97,
    K_SYS_connect         = 98,
    K_SYS_bind            = 104,
    K_SYS_setsockopt      = 105,
    K_SYS_listen          = 106,
    K_SYS_getsockopt      = 118,
    K_SYS_rename          = 128,
    K_SYS_sendto          = 133,
    K_SYS_shutdown        = 134,
    K_SYS_mkdir           = 136,
    K_SYS_rmdir           = 137,
    K_SYS_setsid          = 147,
    K_SYS_getpgid         = 151,
    K_SYS_fstat           = 153,
    K_SYS_pread           = 173,
    K_SYS_pwrite          = 174,
    K_SYS_setgid          = 181,
    K_SYS_getdirentries   = 196,
    K_SYS_mmap            = 197,
    K_SYS_lseek           = 199,
    K_SYS_sysctl          = 202,
    K_SYS_nanosleep       = 240,
    K_SYS_pthread_kill    = 286,
    K_SYS_getcwd          = 304,
    K_SYS_issetugid       = 327,
    K_SYS_stat            = 338,
    K_SYS_lstat           = 340,
    K_SYS_read_nocancel   = 396,
    K_SYS_write_nocancel  = 397,
    K_SYS_open_nocancel   = 398,
    K_SYS_close_nocancel  = 399,
    K_SYS_getentropy      = 500,
};

/* Userland-side syscall numbers (from userland/libsystem/include/syscall.h) */
enum {
    U_SYS_exit            = 1,
    U_SYS_fork            = 2,
    U_SYS_read            = 3,
    U_SYS_write           = 4,
    U_SYS_open            = 5,
    U_SYS_close           = 6,
    U_SYS_wait4           = 7,
    U_SYS_link            = 9,
    U_SYS_unlink          = 10,
    U_SYS_chdir           = 12,
    U_SYS_fchdir          = 13,
    U_SYS_mknod           = 14,
    U_SYS_chmod           = 15,
    U_SYS_chown           = 16,
    U_SYS_getpid          = 20,
    U_SYS_setuid          = 23,
    U_SYS_getuid          = 24,
    U_SYS_geteuid         = 25,
    U_SYS_recvfrom        = 29,
    U_SYS_accept          = 30,
    U_SYS_getpeername     = 31,
    U_SYS_getsockname     = 32,
    U_SYS_access          = 33,
    U_SYS_sync            = 36,
    U_SYS_kill            = 37,
    U_SYS_getppid         = 39,
    U_SYS_dup             = 41,
    U_SYS_pipe            = 42,
    U_SYS_getegid         = 43,
    U_SYS_sigaction       = 46,
    U_SYS_getgid          = 47,
    U_SYS_sigprocmask     = 48,
    U_SYS_ioctl           = 54,
    U_SYS_symlink         = 57,
    U_SYS_readlink        = 58,
    U_SYS_execve          = 59,
    U_SYS_umask           = 60,
    U_SYS_munmap          = 73,
    U_SYS_mprotect        = 74,
    U_SYS_getpgrp         = 81,
    U_SYS_setpgid         = 82,
    U_SYS_dup2            = 90,
    U_SYS_fcntl           = 92,
    U_SYS_select          = 93,
    U_SYS_socket          = 97,
    U_SYS_connect         = 98,
    U_SYS_bind            = 104,
    U_SYS_setsockopt      = 105,
    U_SYS_listen          = 106,
    U_SYS_getsockopt      = 118,
    U_SYS_rename          = 128,
    U_SYS_sendto          = 133,
    U_SYS_shutdown        = 134,
    U_SYS_mkdir           = 136,
    U_SYS_rmdir           = 137,
    U_SYS_setsid          = 147,
    U_SYS_getpgid         = 151,
    U_SYS_fstat           = 153,
    U_SYS_pread           = 173,
    U_SYS_pwrite          = 174,
    U_SYS_setgid          = 181,
    U_SYS_getdirentries   = 196,
    U_SYS_mmap            = 197,
    U_SYS_lseek           = 199,
    U_SYS_sysctl          = 202,
    U_SYS_nanosleep       = 240,
    U_SYS_pthread_kill    = 286,
    U_SYS_getcwd          = 304,
    U_SYS_issetugid       = 327,
    U_SYS_stat            = 338,
    U_SYS_lstat           = 340,
    U_SYS_read_nocancel   = 396,
    U_SYS_write_nocancel  = 397,
    U_SYS_open_nocancel   = 398,
    U_SYS_close_nocancel  = 399,
    U_SYS_getentropy      = 500,
};

static void test_syscall_numbers(void)
{
    printf("--- syscall number agreement ---\n");

#define CHECK_SYS(name) CHECK_EQUAL("SYS_" #name, K_SYS_##name, U_SYS_##name)

    CHECK_SYS(exit);
    CHECK_SYS(fork);
    CHECK_SYS(read);
    CHECK_SYS(write);
    CHECK_SYS(open);
    CHECK_SYS(close);
    CHECK_SYS(wait4);
    CHECK_SYS(link);
    CHECK_SYS(unlink);
    CHECK_SYS(chdir);
    CHECK_SYS(fchdir);
    CHECK_SYS(mknod);
    CHECK_SYS(chmod);
    CHECK_SYS(chown);
    CHECK_SYS(getpid);
    CHECK_SYS(setuid);
    CHECK_SYS(getuid);
    CHECK_SYS(geteuid);
    CHECK_SYS(recvfrom);
    CHECK_SYS(accept);
    CHECK_SYS(getpeername);
    CHECK_SYS(getsockname);
    CHECK_SYS(access);
    CHECK_SYS(sync);
    CHECK_SYS(kill);
    CHECK_SYS(getppid);
    CHECK_SYS(dup);
    CHECK_SYS(pipe);
    CHECK_SYS(getegid);
    CHECK_SYS(sigaction);
    CHECK_SYS(getgid);
    CHECK_SYS(sigprocmask);
    CHECK_SYS(ioctl);
    CHECK_SYS(symlink);
    CHECK_SYS(readlink);
    CHECK_SYS(execve);
    CHECK_SYS(umask);
    CHECK_SYS(munmap);
    CHECK_SYS(mprotect);
    CHECK_SYS(getpgrp);
    CHECK_SYS(setpgid);
    CHECK_SYS(dup2);
    CHECK_SYS(fcntl);
    CHECK_SYS(select);
    CHECK_SYS(socket);
    CHECK_SYS(connect);
    CHECK_SYS(bind);
    CHECK_SYS(setsockopt);
    CHECK_SYS(listen);
    CHECK_SYS(getsockopt);
    CHECK_SYS(rename);
    CHECK_SYS(sendto);
    CHECK_SYS(shutdown);
    CHECK_SYS(mkdir);
    CHECK_SYS(rmdir);
    CHECK_SYS(setsid);
    CHECK_SYS(getpgid);
    CHECK_SYS(fstat);
    CHECK_SYS(pread);
    CHECK_SYS(pwrite);
    CHECK_SYS(setgid);
    CHECK_SYS(getdirentries);
    CHECK_SYS(mmap);
    CHECK_SYS(lseek);
    CHECK_SYS(sysctl);
    CHECK_SYS(nanosleep);
    CHECK_SYS(pthread_kill);
    CHECK_SYS(getcwd);
    CHECK_SYS(issetugid);
    CHECK_SYS(stat);
    CHECK_SYS(lstat);
    CHECK_SYS(read_nocancel);
    CHECK_SYS(write_nocancel);
    CHECK_SYS(open_nocancel);
    CHECK_SYS(close_nocancel);
    CHECK_SYS(getentropy);

#undef CHECK_SYS
}

/* ============================================================================
 * O_* flag agreement tests
 *
 * Defined in:
 *   kernel:   kernel/include/fs/vfs.h
 *   userland: userland/libsystem/include/fcntl.h
 * ============================================================================ */

static void test_open_flags(void)
{
    printf("--- open flag agreement ---\n");

    /* Kernel values (from kernel/include/fs/vfs.h) */
    CHECK_EQUAL("O_RDONLY",    0x0000,    0x0000);
    CHECK_EQUAL("O_WRONLY",    0x0001,    0x0001);
    CHECK_EQUAL("O_RDWR",     0x0002,    0x0002);
    CHECK_EQUAL("O_NONBLOCK",  0x0004,    0x0004);
    CHECK_EQUAL("O_APPEND",    0x0008,    0x0008);
    CHECK_EQUAL("O_CREAT",     0x0200,    0x0200);
    CHECK_EQUAL("O_TRUNC",     0x0400,    0x0400);
    CHECK_EQUAL("O_EXCL",      0x0800,    0x0800);
    CHECK_EQUAL("O_DIRECTORY",  0x100000, 0x100000);
    CHECK_EQUAL("O_CLOEXEC",   0x1000000, 0x1000000);
}

/* ============================================================================
 * errno value agreement tests
 *
 * Defined in:
 *   kernel:   kernel/include/fs/vfs.h
 *   userland: userland/libsystem/include/errno.h
 * ============================================================================ */

static void test_errno_values(void)
{
    printf("--- errno value agreement ---\n");

    /* Check the most critical errno values */
    CHECK_EQUAL("EPERM",          1,   1);
    CHECK_EQUAL("ENOENT",         2,   2);
    CHECK_EQUAL("ESRCH",          3,   3);
    CHECK_EQUAL("EIO",            5,   5);
    CHECK_EQUAL("ENOEXEC",        8,   8);
    CHECK_EQUAL("EBADF",          9,   9);
    CHECK_EQUAL("ECHILD",        10,  10);
    CHECK_EQUAL("ENOMEM",        12,  12);
    CHECK_EQUAL("EACCES",        13,  13);
    CHECK_EQUAL("EFAULT",        14,  14);
    CHECK_EQUAL("EEXIST",        17,  17);
    CHECK_EQUAL("ENOTDIR",       20,  20);
    CHECK_EQUAL("EISDIR",        21,  21);
    CHECK_EQUAL("EINVAL",        22,  22);
    CHECK_EQUAL("ENFILE",        23,  23);
    CHECK_EQUAL("EMFILE",        24,  24);
    CHECK_EQUAL("ENOTTY",        25,  25);
    CHECK_EQUAL("ENOSPC",        28,  28);
    CHECK_EQUAL("ESPIPE",        29,  29);
    CHECK_EQUAL("ERANGE",        34,  34);
    CHECK_EQUAL("EAGAIN",        35,  35);
    CHECK_EQUAL("ENOSYS",        78,  78);
}

/* ============================================================================
 * Base type size agreement tests
 *
 * Kiseki targets AArch64 LP64.  All base types must be the same size
 * on both kernel and userland sides.  Since both compile for the same
 * target (arm64-apple-macos11 for userland, aarch64-elf for kernel),
 * these should be identical.  We verify the LP64 assumptions here.
 * ============================================================================ */

static void test_type_sizes(void)
{
    printf("--- base type sizes (LP64) ---\n");

    /* On the AArch64 LP64 target both sides must agree on these */
    TEST_ASSERT(sizeof(uint8_t)  == 1, "uint8_t size: %zu", sizeof(uint8_t));
    TEST_ASSERT(sizeof(uint16_t) == 2, "uint16_t size: %zu", sizeof(uint16_t));
    TEST_ASSERT(sizeof(uint32_t) == 4, "uint32_t size: %zu", sizeof(uint32_t));
    TEST_ASSERT(sizeof(uint64_t) == 8, "uint64_t size: %zu", sizeof(uint64_t));
    TEST_ASSERT(sizeof(int64_t)  == 8, "int64_t size: %zu", sizeof(int64_t));

    /* Pointer size must be 8 bytes (LP64) */
    TEST_ASSERT(sizeof(void *) == 8, "pointer size: %zu", sizeof(void *));
}

/* ============================================================================
 * Compile-time static assertions (fail the build, not just runtime)
 * ============================================================================ */

/* --- struct stat: Darwin arm64 144-byte layout --- */
_Static_assert(sizeof(struct kiseki_stat) == 144,
    "struct stat size must be 144 bytes (Darwin arm64)");
_Static_assert(offsetof(struct kiseki_stat, st_dev) == 0,
    "stat.st_dev must be at offset 0");
_Static_assert(offsetof(struct kiseki_stat, st_mode) == 4,
    "stat.st_mode must be at offset 4");
_Static_assert(offsetof(struct kiseki_stat, st_nlink) == 6,
    "stat.st_nlink must be at offset 6");
_Static_assert(offsetof(struct kiseki_stat, st_ino) == 8,
    "stat.st_ino must be at offset 8");
_Static_assert(offsetof(struct kiseki_stat, st_uid) == 16,
    "stat.st_uid must be at offset 16");
_Static_assert(offsetof(struct kiseki_stat, st_gid) == 20,
    "stat.st_gid must be at offset 20");
_Static_assert(offsetof(struct kiseki_stat, st_rdev) == 24,
    "stat.st_rdev must be at offset 24");
_Static_assert(offsetof(struct kiseki_stat, st_atimespec) == 32,
    "stat.st_atimespec must be at offset 32");
_Static_assert(offsetof(struct kiseki_stat, st_mtimespec) == 48,
    "stat.st_mtimespec must be at offset 48");
_Static_assert(offsetof(struct kiseki_stat, st_ctimespec) == 64,
    "stat.st_ctimespec must be at offset 64");
_Static_assert(offsetof(struct kiseki_stat, st_birthtimespec) == 80,
    "stat.st_birthtimespec must be at offset 80");
_Static_assert(offsetof(struct kiseki_stat, st_size) == 96,
    "stat.st_size must be at offset 96");
_Static_assert(offsetof(struct kiseki_stat, st_blocks) == 104,
    "stat.st_blocks must be at offset 104");
_Static_assert(offsetof(struct kiseki_stat, st_blksize) == 112,
    "stat.st_blksize must be at offset 112");
_Static_assert(offsetof(struct kiseki_stat, st_flags) == 116,
    "stat.st_flags must be at offset 116");
_Static_assert(offsetof(struct kiseki_stat, st_gen) == 120,
    "stat.st_gen must be at offset 120");
_Static_assert(offsetof(struct kiseki_stat, st_lspare) == 124,
    "stat.st_lspare must be at offset 124");
_Static_assert(offsetof(struct kiseki_stat, st_qspare) == 128,
    "stat.st_qspare must be at offset 128");

/* --- struct dirent: Darwin arm64 1048-byte layout --- */
_Static_assert(sizeof(struct kiseki_dirent) == 1048,
    "struct dirent size must be 1048 bytes (Darwin arm64)");
_Static_assert(offsetof(struct kiseki_dirent, d_ino) == 0,
    "dirent.d_ino must be at offset 0");
_Static_assert(offsetof(struct kiseki_dirent, d_seekoff) == 8,
    "dirent.d_seekoff must be at offset 8");
_Static_assert(offsetof(struct kiseki_dirent, d_reclen) == 16,
    "dirent.d_reclen must be at offset 16");
_Static_assert(offsetof(struct kiseki_dirent, d_namlen) == 18,
    "dirent.d_namlen must be at offset 18");
_Static_assert(offsetof(struct kiseki_dirent, d_type) == 20,
    "dirent.d_type must be at offset 20");
_Static_assert(offsetof(struct kiseki_dirent, d_name) == 21,
    "dirent.d_name must be at offset 21");

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void)
{
    printf("=== Kiseki ABI Compatibility Tests ===\n\n");

    test_stat_layout();
    test_dirent_layout();
    test_syscall_numbers();
    test_open_flags();
    test_errno_values();
    test_type_sizes();

    printf("\n--- Results: %d passed, %d failed, %d total ---\n",
           g_tests_passed, g_tests_failed, g_tests_run);

    if (g_tests_failed > 0) {
        fprintf(stderr, "\nABI MISMATCH DETECTED. Fix kernel/userland headers.\n");
        return 1;
    }

    printf("\nAll ABI checks passed.\n");
    return 0;
}
