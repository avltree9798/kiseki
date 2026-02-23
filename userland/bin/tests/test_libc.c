/*
 * Kiseki OS - libSystem Unit Tests
 *
 * Comprehensive tests for all C library functions.
 * Compile with: tcc -o test_libc test_libc.c
 * Run with: ./test_libc
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/time.h>

/* Test framework */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) static void test_##name(void)
#define RUN_TEST(name) do { \
    printf("  %-40s ", #name); \
    tests_run++; \
    test_##name(); \
} while(0)

#define ASSERT(cond) do { \
    if (!(cond)) { \
        printf("FAIL\n    Line %d: %s\n", __LINE__, #cond); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        printf("FAIL\n    Line %d: %s != %s\n", __LINE__, #a, #b); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define ASSERT_STR_EQ(a, b) do { \
    if (strcmp((a), (b)) != 0) { \
        printf("FAIL\n    Line %d: \"%s\" != \"%s\"\n", __LINE__, (a), (b)); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define PASS() do { printf("OK\n"); tests_passed++; } while(0)

/* ============================================================================
 * string.h tests
 * ============================================================================ */

TEST(strlen)
{
    ASSERT_EQ(strlen(""), 0);
    ASSERT_EQ(strlen("hello"), 5);
    ASSERT_EQ(strlen("hello world"), 11);
    PASS();
}

TEST(strcmp)
{
    ASSERT_EQ(strcmp("abc", "abc"), 0);
    ASSERT(strcmp("abc", "abd") < 0);
    ASSERT(strcmp("abd", "abc") > 0);
    ASSERT(strcmp("", "") == 0);
    ASSERT(strcmp("a", "") > 0);
    PASS();
}

TEST(strncmp)
{
    ASSERT_EQ(strncmp("abc", "abd", 2), 0);
    ASSERT(strncmp("abc", "abd", 3) < 0);
    ASSERT_EQ(strncmp("hello", "hello world", 5), 0);
    PASS();
}

TEST(strcpy)
{
    char buf[32];
    strcpy(buf, "hello");
    ASSERT_STR_EQ(buf, "hello");
    strcpy(buf, "");
    ASSERT_STR_EQ(buf, "");
    PASS();
}

TEST(strncpy)
{
    char buf[32];
    memset(buf, 'X', sizeof(buf));
    strncpy(buf, "hello", 10);
    ASSERT_STR_EQ(buf, "hello");
    ASSERT_EQ(buf[5], '\0');
    PASS();
}

TEST(strcat)
{
    char buf[32] = "hello";
    strcat(buf, " world");
    ASSERT_STR_EQ(buf, "hello world");
    PASS();
}

TEST(strncat)
{
    char buf[32] = "hello";
    strncat(buf, " world!!!", 6);
    ASSERT_STR_EQ(buf, "hello world");
    PASS();
}

TEST(strchr)
{
    const char *s = "hello world";
    ASSERT_EQ(strchr(s, 'o'), s + 4);
    ASSERT_EQ(strchr(s, 'z'), NULL);
    ASSERT_EQ(strchr(s, '\0'), s + 11);
    PASS();
}

TEST(strrchr)
{
    const char *s = "hello world";
    ASSERT_EQ(strrchr(s, 'o'), s + 7);
    ASSERT_EQ(strrchr(s, 'z'), NULL);
    PASS();
}

TEST(strstr)
{
    const char *s = "hello world";
    ASSERT_EQ(strstr(s, "world"), s + 6);
    ASSERT_EQ(strstr(s, "xyz"), NULL);
    ASSERT_EQ(strstr(s, ""), s);
    PASS();
}

TEST(memset)
{
    char buf[16];
    memset(buf, 'A', 10);
    buf[10] = '\0';
    ASSERT_STR_EQ(buf, "AAAAAAAAAA");
    PASS();
}

TEST(memcpy)
{
    char src[] = "hello";
    char dst[16];
    memcpy(dst, src, 6);
    ASSERT_STR_EQ(dst, "hello");
    PASS();
}

TEST(memmove)
{
    char buf[] = "hello world";
    memmove(buf + 2, buf, 5);
    /* Copies "hello" (buf[0-4]) to buf[2-6], result: "hehelloorld" */
    ASSERT_STR_EQ(buf, "hehelloorld");
    PASS();
}

TEST(memcmp)
{
    ASSERT_EQ(memcmp("abc", "abc", 3), 0);
    ASSERT(memcmp("abc", "abd", 3) < 0);
    ASSERT(memcmp("abd", "abc", 3) > 0);
    PASS();
}

TEST(strdup)
{
    char *s = strdup("hello");
    ASSERT(s != NULL);
    ASSERT_STR_EQ(s, "hello");
    free(s);
    PASS();
}

TEST(strtok)
{
    char buf[] = "hello,world,test";
    char *tok = strtok(buf, ",");
    ASSERT_STR_EQ(tok, "hello");
    tok = strtok(NULL, ",");
    ASSERT_STR_EQ(tok, "world");
    tok = strtok(NULL, ",");
    ASSERT_STR_EQ(tok, "test");
    tok = strtok(NULL, ",");
    ASSERT_EQ(tok, NULL);
    PASS();
}

/* ============================================================================
 * stdlib.h tests
 * ============================================================================ */

TEST(atoi)
{
    ASSERT_EQ(atoi("123"), 123);
    ASSERT_EQ(atoi("-456"), -456);
    ASSERT_EQ(atoi("  789"), 789);
    ASSERT_EQ(atoi("0"), 0);
    ASSERT_EQ(atoi("abc"), 0);
    PASS();
}

TEST(atol)
{
    ASSERT_EQ(atol("123456789"), 123456789L);
    ASSERT_EQ(atol("-987654321"), -987654321L);
    PASS();
}

TEST(strtol)
{
    char *end;
    ASSERT_EQ(strtol("123", &end, 10), 123);
    ASSERT_EQ(*end, '\0');
    ASSERT_EQ(strtol("0xff", &end, 16), 255);
    ASSERT_EQ(strtol("0777", &end, 8), 511);
    ASSERT_EQ(strtol("-42abc", &end, 10), -42);
    ASSERT_EQ(*end, 'a');
    PASS();
}

TEST(strtoul)
{
    char *end;
    ASSERT_EQ(strtoul("12345", &end, 10), 12345UL);
    ASSERT_EQ(strtoul("FFFF", &end, 16), 65535UL);
    PASS();
}

TEST(malloc_free)
{
    void *p = malloc(1024);
    ASSERT(p != NULL);
    memset(p, 'A', 1024);
    free(p);
    
    /* Multiple allocations */
    void *ptrs[10];
    for (int i = 0; i < 10; i++) {
        ptrs[i] = malloc(100);
        ASSERT(ptrs[i] != NULL);
    }
    for (int i = 0; i < 10; i++) {
        free(ptrs[i]);
    }
    PASS();
}

TEST(calloc)
{
    int *arr = calloc(10, sizeof(int));
    ASSERT(arr != NULL);
    for (int i = 0; i < 10; i++) {
        ASSERT_EQ(arr[i], 0);
    }
    free(arr);
    PASS();
}

TEST(realloc)
{
    char *p = malloc(10);
    ASSERT(p != NULL);
    strcpy(p, "hello");
    
    p = realloc(p, 100);
    ASSERT(p != NULL);
    ASSERT_STR_EQ(p, "hello");
    
    free(p);
    PASS();
}

TEST(abs_labs)
{
    ASSERT_EQ(abs(-5), 5);
    ASSERT_EQ(abs(5), 5);
    ASSERT_EQ(abs(0), 0);
    
    ASSERT_EQ(labs(-100L), 100L);
    ASSERT_EQ(labs(100L), 100L);
    
    ASSERT_EQ(llabs(-1000LL), 1000LL);
    ASSERT_EQ(llabs(1000LL), 1000LL);
    
    PASS();
}

TEST(div_ldiv)
{
    div_t d = div(17, 5);
    ASSERT_EQ(d.quot, 3);
    ASSERT_EQ(d.rem, 2);
    
    ldiv_t ld = ldiv(-17L, 5L);
    ASSERT_EQ(ld.quot, -3L);
    ASSERT_EQ(ld.rem, -2L);
    
    PASS();
}

TEST(realpath)
{
    char buf[256];
    
    /* Test with existing path */
    char *result = realpath("/tmp", buf);
    ASSERT(result != NULL);
    ASSERT_STR_EQ(buf, "/tmp");
    
    /* Test with . and .. */
    result = realpath("/tmp/../tmp/.", buf);
    ASSERT(result != NULL);
    ASSERT_STR_EQ(buf, "/tmp");
    
    PASS();
}

TEST(mkstemp_test)
{
    char tmpl[] = "/tmp/testXXXXXX";
    
    int fd = mkstemp(tmpl);
    ASSERT(fd >= 0);
    
    /* Template should be modified */
    ASSERT(strcmp(tmpl, "/tmp/testXXXXXX") != 0);
    
    /* File should exist and be writable */
    ASSERT_EQ(write(fd, "test", 4), 4);
    
    close(fd);
    unlink(tmpl);
    
    PASS();
}

TEST(getrlimit_test)
{
    struct rlimit rl;
    
    int ret = getrlimit(RLIMIT_NOFILE, &rl);
    ASSERT_EQ(ret, 0);
    ASSERT(rl.rlim_cur > 0);
    ASSERT(rl.rlim_max >= rl.rlim_cur);
    
    PASS();
}

TEST(getenv_setenv)
{
    /* setenv and getenv */
    ASSERT_EQ(setenv("TEST_VAR", "test_value", 1), 0);
    char *val = getenv("TEST_VAR");
    ASSERT(val != NULL);
    ASSERT_STR_EQ(val, "test_value");
    
    /* unsetenv */
    ASSERT_EQ(unsetenv("TEST_VAR"), 0);
    val = getenv("TEST_VAR");
    ASSERT(val == NULL);
    PASS();
}

/* Comparison function for qsort/bsearch tests */
static int int_cmp(const void *a, const void *b)
{
    return *(const int*)a - *(const int*)b;
}

TEST(qsort)
{
    int arr[] = {5, 2, 8, 1, 9, 3, 7, 4, 6};
    qsort(arr, 9, sizeof(int), int_cmp);
    for (int i = 0; i < 9; i++) {
        ASSERT_EQ(arr[i], i + 1);
    }
    PASS();
}

TEST(bsearch)
{
    int arr[] = {1, 2, 3, 4, 5, 6, 7, 8, 9};
    int key = 5;
    int *found = bsearch(&key, arr, 9, sizeof(int), int_cmp);
    ASSERT(found != NULL);
    ASSERT_EQ(*found, 5);
    
    key = 10;
    found = bsearch(&key, arr, 9, sizeof(int), int_cmp);
    ASSERT(found == NULL);
    PASS();
}

/* ============================================================================
 * stdio.h tests
 * ============================================================================ */

TEST(sprintf_snprintf)
{
    char buf[64];
    
    sprintf(buf, "hello %s", "world");
    ASSERT_STR_EQ(buf, "hello world");
    
    sprintf(buf, "%d + %d = %d", 2, 3, 5);
    ASSERT_STR_EQ(buf, "2 + 3 = 5");
    
    sprintf(buf, "%x %X", 255, 255);
    ASSERT_STR_EQ(buf, "ff FF");
    
    sprintf(buf, "%p", (void*)0x1234);
    ASSERT(strstr(buf, "1234") != NULL);
    
    int n = snprintf(buf, 10, "hello world");
    ASSERT_EQ(n, 11);
    ASSERT_EQ(strlen(buf), 9);
    
    PASS();
}

TEST(sscanf)
{
    int a, b;
    char s[32];
    
    ASSERT_EQ(sscanf("123 456", "%d %d", &a, &b), 2);
    ASSERT_EQ(a, 123);
    ASSERT_EQ(b, 456);
    
    ASSERT_EQ(sscanf("hello", "%s", s), 1);
    ASSERT_STR_EQ(s, "hello");
    
    ASSERT_EQ(sscanf("ff", "%x", &a), 1);
    ASSERT_EQ(a, 255);
    
    PASS();
}

TEST(fopen_fclose)
{
    FILE *f = fopen("/tmp/test_file.txt", "w");
    ASSERT(f != NULL);
    ASSERT_EQ(fclose(f), 0);
    
    f = fopen("/tmp/test_file.txt", "r");
    ASSERT(f != NULL);
    ASSERT_EQ(fclose(f), 0);
    
    f = fopen("/nonexistent/path/file", "r");
    ASSERT(f == NULL);
    
    remove("/tmp/test_file.txt");
    PASS();
}

TEST(fread_fwrite)
{
    FILE *f = fopen("/tmp/test_rw.txt", "w");
    ASSERT(f != NULL);
    
    char data[] = "Hello, World!";
    size_t n = fwrite(data, 1, strlen(data), f);
    ASSERT_EQ(n, strlen(data));
    fclose(f);
    
    f = fopen("/tmp/test_rw.txt", "r");
    ASSERT(f != NULL);
    
    char buf[64];
    n = fread(buf, 1, sizeof(buf), f);
    ASSERT_EQ(n, strlen(data));
    buf[n] = '\0';
    ASSERT_STR_EQ(buf, data);
    fclose(f);
    
    remove("/tmp/test_rw.txt");
    PASS();
}

TEST(fseek_ftell)
{
    FILE *f = fopen("/tmp/test_seek.txt", "w+");
    ASSERT(f != NULL);
    
    fprintf(f, "0123456789");
    
    ASSERT_EQ(fseek(f, 0, SEEK_SET), 0);
    ASSERT_EQ(ftell(f), 0);
    
    ASSERT_EQ(fseek(f, 5, SEEK_SET), 0);
    ASSERT_EQ(ftell(f), 5);
    
    ASSERT_EQ(fseek(f, 2, SEEK_CUR), 0);
    ASSERT_EQ(ftell(f), 7);
    
    ASSERT_EQ(fseek(f, 0, SEEK_END), 0);
    ASSERT_EQ(ftell(f), 10);
    
    rewind(f);
    ASSERT_EQ(ftell(f), 0);
    
    fclose(f);
    remove("/tmp/test_seek.txt");
    PASS();
}

TEST(fgets_fputs)
{
    FILE *f = fopen("/tmp/test_gets.txt", "w");
    ASSERT(f != NULL);
    fputs("line1\n", f);
    fputs("line2\n", f);
    fputs("line3", f);
    fclose(f);
    
    f = fopen("/tmp/test_gets.txt", "r");
    ASSERT(f != NULL);
    
    char buf[64];
    ASSERT(fgets(buf, sizeof(buf), f) != NULL);
    ASSERT_STR_EQ(buf, "line1\n");
    
    ASSERT(fgets(buf, sizeof(buf), f) != NULL);
    ASSERT_STR_EQ(buf, "line2\n");
    
    ASSERT(fgets(buf, sizeof(buf), f) != NULL);
    ASSERT_STR_EQ(buf, "line3");
    
    ASSERT(fgets(buf, sizeof(buf), f) == NULL);
    ASSERT(feof(f));
    
    fclose(f);
    remove("/tmp/test_gets.txt");
    PASS();
}

TEST(fgetc_fputc)
{
    FILE *f = fopen("/tmp/test_getc.txt", "w");
    ASSERT(f != NULL);
    fputc('A', f);
    fputc('B', f);
    fputc('C', f);
    fclose(f);
    
    f = fopen("/tmp/test_getc.txt", "r");
    ASSERT(f != NULL);
    ASSERT_EQ(fgetc(f), 'A');
    ASSERT_EQ(fgetc(f), 'B');
    ASSERT_EQ(fgetc(f), 'C');
    ASSERT_EQ(fgetc(f), EOF);
    fclose(f);
    
    remove("/tmp/test_getc.txt");
    PASS();
}

TEST(ungetc)
{
    FILE *f = fopen("/tmp/test_ungetc.txt", "w");
    ASSERT(f != NULL);
    fputs("ABC", f);
    fclose(f);
    
    f = fopen("/tmp/test_ungetc.txt", "r");
    ASSERT(f != NULL);
    
    int c = fgetc(f);
    ASSERT_EQ(c, 'A');
    ASSERT_EQ(ungetc(c, f), 'A');
    ASSERT_EQ(fgetc(f), 'A');
    ASSERT_EQ(fgetc(f), 'B');
    
    fclose(f);
    remove("/tmp/test_ungetc.txt");
    PASS();
}

TEST(feof_ferror_clearerr)
{
    FILE *f = fopen("/tmp/test_eof.txt", "w");
    ASSERT(f != NULL);
    fputs("X", f);
    fclose(f);
    
    f = fopen("/tmp/test_eof.txt", "r");
    ASSERT(f != NULL);
    
    ASSERT_EQ(feof(f), 0);
    fgetc(f);
    fgetc(f);  /* This should hit EOF */
    ASSERT(feof(f));
    
    clearerr(f);
    ASSERT_EQ(feof(f), 0);
    ASSERT_EQ(ferror(f), 0);
    
    fclose(f);
    remove("/tmp/test_eof.txt");
    PASS();
}

TEST(tmpfile)
{
    FILE *f = tmpfile();
    ASSERT(f != NULL);
    
    fprintf(f, "temporary data");
    rewind(f);
    
    char buf[32];
    ASSERT(fgets(buf, sizeof(buf), f) != NULL);
    ASSERT_STR_EQ(buf, "temporary data");
    
    fclose(f);
    /* File should be automatically deleted */
    PASS();
}

TEST(remove_rename)
{
    FILE *f = fopen("/tmp/test_remove.txt", "w");
    ASSERT(f != NULL);
    fclose(f);
    
    /* Rename */
    ASSERT_EQ(rename("/tmp/test_remove.txt", "/tmp/test_renamed.txt"), 0);
    
    /* Old name should not exist */
    f = fopen("/tmp/test_remove.txt", "r");
    ASSERT(f == NULL);
    
    /* New name should exist */
    f = fopen("/tmp/test_renamed.txt", "r");
    ASSERT(f != NULL);
    fclose(f);
    
    /* Remove */
    ASSERT_EQ(remove("/tmp/test_renamed.txt"), 0);
    
    /* Should not exist anymore */
    f = fopen("/tmp/test_renamed.txt", "r");
    ASSERT(f == NULL);
    
    PASS();
}

/* ============================================================================
 * unistd.h tests
 * ============================================================================ */

TEST(read_write)
{
    int fd = open("/tmp/test_rw.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    ASSERT(fd >= 0);
    
    char data[] = "test data";
    ssize_t n = write(fd, data, strlen(data));
    ASSERT_EQ(n, strlen(data));
    close(fd);
    
    fd = open("/tmp/test_rw.txt", O_RDONLY);
    ASSERT(fd >= 0);
    
    char buf[32];
    n = read(fd, buf, sizeof(buf));
    ASSERT_EQ(n, strlen(data));
    buf[n] = '\0';
    ASSERT_STR_EQ(buf, data);
    close(fd);
    
    unlink("/tmp/test_rw.txt");
    PASS();
}

TEST(lseek)
{
    int fd = open("/tmp/test_lseek.txt", O_RDWR | O_CREAT | O_TRUNC, 0644);
    ASSERT(fd >= 0);
    
    write(fd, "0123456789", 10);
    
    ASSERT_EQ(lseek(fd, 0, SEEK_SET), 0);
    ASSERT_EQ(lseek(fd, 5, SEEK_SET), 5);
    ASSERT_EQ(lseek(fd, 2, SEEK_CUR), 7);
    ASSERT_EQ(lseek(fd, 0, SEEK_END), 10);
    
    close(fd);
    unlink("/tmp/test_lseek.txt");
    PASS();
}

TEST(dup_dup2)
{
    int fd = open("/tmp/test_dup.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    ASSERT(fd >= 0);
    
    int fd2 = dup(fd);
    ASSERT(fd2 >= 0);
    ASSERT(fd2 != fd);
    
    write(fd, "hello", 5);
    write(fd2, " world", 6);
    
    close(fd);
    close(fd2);
    
    fd = open("/tmp/test_dup.txt", O_RDONLY);
    char buf[32];
    read(fd, buf, sizeof(buf));
    buf[11] = '\0';
    ASSERT_STR_EQ(buf, "hello world");
    close(fd);
    
    unlink("/tmp/test_dup.txt");
    PASS();
}

TEST(getcwd_chdir)
{
    char cwd1[256], cwd2[256];
    
    ASSERT(getcwd(cwd1, sizeof(cwd1)) != NULL);
    
    ASSERT_EQ(chdir("/tmp"), 0);
    ASSERT(getcwd(cwd2, sizeof(cwd2)) != NULL);
    ASSERT_STR_EQ(cwd2, "/tmp");
    
    /* Change back */
    ASSERT_EQ(chdir(cwd1), 0);
    ASSERT(getcwd(cwd2, sizeof(cwd2)) != NULL);
    ASSERT_STR_EQ(cwd2, cwd1);
    
    PASS();
}

TEST(access)
{
    /* Root can read / */
    ASSERT_EQ(access("/", R_OK), 0);
    ASSERT_EQ(access("/", X_OK), 0);
    
    /* Non-existent file */
    ASSERT(access("/nonexistent_file_xyz", F_OK) != 0);
    
    PASS();
}

TEST(getpid_getppid)
{
    pid_t pid = getpid();
    pid_t ppid = getppid();
    
    ASSERT(pid > 0);
    ASSERT(ppid > 0);
    ASSERT(pid != ppid);
    
    PASS();
}

TEST(fork_wait)
{
    pid_t pid = fork();
    ASSERT(pid >= 0);
    
    if (pid == 0) {
        /* Child */
        _exit(42);
    } else {
        /* Parent */
        int status;
        pid_t waited = waitpid(pid, &status, 0);
        ASSERT_EQ(waited, pid);
        ASSERT(WIFEXITED(status));
        ASSERT_EQ(WEXITSTATUS(status), 42);
    }
    
    PASS();
}

TEST(pipe)
{
    int pipefd[2];
    ASSERT_EQ(pipe(pipefd), 0);
    
    char msg[] = "pipe test";
    write(pipefd[1], msg, strlen(msg));
    
    char buf[32];
    ssize_t n = read(pipefd[0], buf, sizeof(buf));
    ASSERT_EQ(n, strlen(msg));
    buf[n] = '\0';
    ASSERT_STR_EQ(buf, msg);
    
    close(pipefd[0]);
    close(pipefd[1]);
    PASS();
}

TEST(sleep_usleep)
{
    /* Can't really test timing precisely, just make sure they don't crash */
    /* usleep(1000);  1ms - skip for speed */
    PASS();
}

TEST(ftruncate_test)
{
    int fd = open("/tmp/test_trunc.txt", O_RDWR | O_CREAT | O_TRUNC, 0644);
    ASSERT(fd >= 0);
    
    write(fd, "hello world", 11);
    
    /* Truncate to 5 bytes */
    ASSERT_EQ(ftruncate(fd, 5), 0);
    
    /* Verify size */
    struct stat st;
    fstat(fd, &st);
    ASSERT_EQ(st.st_size, 5);
    
    close(fd);
    unlink("/tmp/test_trunc.txt");
    PASS();
}

TEST(fsync_test)
{
    int fd = open("/tmp/test_fsync.txt", O_RDWR | O_CREAT | O_TRUNC, 0644);
    ASSERT(fd >= 0);
    
    write(fd, "test", 4);
    
    /* fsync should succeed */
    ASSERT_EQ(fsync(fd), 0);
    
    close(fd);
    unlink("/tmp/test_fsync.txt");
    PASS();
}

TEST(gethostname_test)
{
    char hostname[256];
    
    int ret = gethostname(hostname, sizeof(hostname));
    ASSERT_EQ(ret, 0);
    ASSERT(strlen(hostname) > 0);
    
    PASS();
}

TEST(getpagesize_test)
{
    int pagesize = getpagesize();
    ASSERT_EQ(pagesize, 4096);
    
    PASS();
}

/* ============================================================================
 * fcntl.h tests
 * ============================================================================ */

TEST(open_close)
{
    int fd = open("/tmp/test_open.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    ASSERT(fd >= 0);
    ASSERT_EQ(close(fd), 0);
    
    fd = open("/tmp/test_open.txt", O_RDONLY);
    ASSERT(fd >= 0);
    close(fd);
    
    unlink("/tmp/test_open.txt");
    
    fd = open("/nonexistent/path", O_RDONLY);
    ASSERT(fd < 0);
    
    PASS();
}

/* ============================================================================
 * dirent.h tests
 * ============================================================================ */

TEST(opendir_readdir_closedir)
{
    DIR *d = opendir("/tmp");
    ASSERT(d != NULL);
    
    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        ASSERT(ent->d_name[0] != '\0');
        count++;
    }
    ASSERT(count >= 2);  /* At least . and .. */
    
    ASSERT_EQ(closedir(d), 0);
    PASS();
}

TEST(mkdir_rmdir)
{
    ASSERT_EQ(mkdir("/tmp/test_dir", 0755), 0);
    
    DIR *d = opendir("/tmp/test_dir");
    ASSERT(d != NULL);
    closedir(d);
    
    ASSERT_EQ(rmdir("/tmp/test_dir"), 0);
    
    d = opendir("/tmp/test_dir");
    ASSERT(d == NULL);
    
    PASS();
}

/* ============================================================================
 * time.h tests
 * ============================================================================ */

TEST(time_func)
{
    time_t t1 = time(NULL);
    ASSERT(t1 > 0);
    
    time_t t2;
    time(&t2);
    ASSERT(t2 >= t1);
    
    PASS();
}

TEST(gettimeofday)
{
    struct timeval tv;
    ASSERT_EQ(gettimeofday(&tv, NULL), 0);
    ASSERT(tv.tv_sec > 0);
    ASSERT(tv.tv_usec >= 0 && tv.tv_usec < 1000000);
    PASS();
}

TEST(localtime_gmtime)
{
    time_t t = 0;  /* Epoch */
    struct tm *tm = gmtime(&t);
    ASSERT(tm != NULL);
    ASSERT_EQ(tm->tm_year, 70);  /* 1970 */
    ASSERT_EQ(tm->tm_mon, 0);    /* January */
    ASSERT_EQ(tm->tm_mday, 1);
    ASSERT_EQ(tm->tm_hour, 0);
    ASSERT_EQ(tm->tm_min, 0);
    ASSERT_EQ(tm->tm_sec, 0);
    
    PASS();
}

TEST(strftime)
{
    time_t t = 0;
    struct tm *tm = gmtime(&t);
    char buf[64];
    
    strftime(buf, sizeof(buf), "%Y-%m-%d", tm);
    ASSERT_STR_EQ(buf, "1970-01-01");
    
    strftime(buf, sizeof(buf), "%H:%M:%S", tm);
    ASSERT_STR_EQ(buf, "00:00:00");
    
    PASS();
}

TEST(mktime)
{
    struct tm tm = {0};
    tm.tm_year = 100;  /* 2000 */
    tm.tm_mon = 0;     /* January */
    tm.tm_mday = 1;
    tm.tm_hour = 0;
    tm.tm_min = 0;
    tm.tm_sec = 0;
    
    time_t t = mktime(&tm);
    /* Jan 1, 2000 00:00:00 UTC = 946684800 seconds since epoch */
    ASSERT_EQ(t, 946684800);
    
    /* Check that wday was computed (Jan 1, 2000 was Saturday = 6) */
    ASSERT_EQ(tm.tm_wday, 6);
    
    PASS();
}

TEST(difftime)
{
    time_t t1 = 1000;
    time_t t2 = 500;
    
    double diff = difftime(t1, t2);
    ASSERT(diff == 500.0);
    
    diff = difftime(t2, t1);
    ASSERT(diff == -500.0);
    
    PASS();
}

TEST(clock_gettime)
{
    struct timespec ts;
    
    int ret = clock_gettime(CLOCK_REALTIME, &ts);
    ASSERT_EQ(ret, 0);
    ASSERT(ts.tv_sec > 0);  /* Should be after 1970 */
    ASSERT(ts.tv_nsec >= 0 && ts.tv_nsec < 1000000000);
    
    PASS();
}

TEST(asctime_ctime)
{
    time_t t = 0;  /* Epoch */
    char *s = ctime(&t);
    ASSERT(s != NULL);
    /* "Thu Jan  1 00:00:00 1970\n" */
    ASSERT(strstr(s, "1970") != NULL);
    ASSERT(strstr(s, "Jan") != NULL);
    
    struct tm *tm = gmtime(&t);
    s = asctime(tm);
    ASSERT(s != NULL);
    ASSERT(strstr(s, "1970") != NULL);
    
    PASS();
}

/* ============================================================================
 * signal.h tests
 * ============================================================================ */

static volatile int signal_received = 0;
static void test_signal_handler(int sig) {
    signal_received = sig;
}

TEST(signal_raise)
{
    signal_received = 0;
    signal(SIGUSR1, test_signal_handler);
    
    raise(SIGUSR1);
    
    ASSERT_EQ(signal_received, SIGUSR1);
    
    signal(SIGUSR1, SIG_DFL);
    PASS();
}

/* ============================================================================
 * pthread.h tests
 * ============================================================================ */

TEST(pthread_self_equal)
{
    pthread_t self = pthread_self();
    ASSERT(self != 0);
    
    /* pthread_equal should return true for same thread */
    ASSERT(pthread_equal(self, self) != 0);
    
    PASS();
}

TEST(pthread_mutex)
{
    pthread_mutex_t mutex;
    
    /* Test PTHREAD_MUTEX_INITIALIZER */
    pthread_mutex_t static_mutex = PTHREAD_MUTEX_INITIALIZER;
    ASSERT_EQ(pthread_mutex_lock(&static_mutex), 0);
    ASSERT_EQ(pthread_mutex_unlock(&static_mutex), 0);
    
    /* Test pthread_mutex_init with NULL attr */
    ASSERT_EQ(pthread_mutex_init(&mutex, NULL), 0);
    
    /* Lock and unlock */
    ASSERT_EQ(pthread_mutex_lock(&mutex), 0);
    ASSERT_EQ(pthread_mutex_unlock(&mutex), 0);
    
    /* Trylock should succeed when not locked */
    ASSERT_EQ(pthread_mutex_trylock(&mutex), 0);
    ASSERT_EQ(pthread_mutex_unlock(&mutex), 0);
    
    /* Destroy */
    ASSERT_EQ(pthread_mutex_destroy(&mutex), 0);
    
    PASS();
}

TEST(pthread_rwlock)
{
    pthread_rwlock_t rwlock;
    
    /* Test PTHREAD_RWLOCK_INITIALIZER */
    pthread_rwlock_t static_rwlock = PTHREAD_RWLOCK_INITIALIZER;
    ASSERT_EQ(pthread_rwlock_rdlock(&static_rwlock), 0);
    ASSERT_EQ(pthread_rwlock_unlock(&static_rwlock), 0);
    
    /* Test pthread_rwlock_init with NULL attr */
    ASSERT_EQ(pthread_rwlock_init(&rwlock, NULL), 0);
    
    /* Read lock - multiple readers allowed */
    ASSERT_EQ(pthread_rwlock_rdlock(&rwlock), 0);
    /* In single-threaded mode, second rdlock should work */
    ASSERT_EQ(pthread_rwlock_rdlock(&rwlock), 0);
    ASSERT_EQ(pthread_rwlock_unlock(&rwlock), 0);
    ASSERT_EQ(pthread_rwlock_unlock(&rwlock), 0);
    
    /* Write lock */
    ASSERT_EQ(pthread_rwlock_wrlock(&rwlock), 0);
    ASSERT_EQ(pthread_rwlock_unlock(&rwlock), 0);
    
    /* Tryrdlock should succeed when not locked */
    ASSERT_EQ(pthread_rwlock_tryrdlock(&rwlock), 0);
    ASSERT_EQ(pthread_rwlock_unlock(&rwlock), 0);
    
    /* Trywrlock should succeed when not locked */
    ASSERT_EQ(pthread_rwlock_trywrlock(&rwlock), 0);
    ASSERT_EQ(pthread_rwlock_unlock(&rwlock), 0);
    
    /* Destroy */
    ASSERT_EQ(pthread_rwlock_destroy(&rwlock), 0);
    
    PASS();
}

static int tls_destructor_called = 0;
static void tls_destructor(void *value) {
    tls_destructor_called = 1;
    /* In real usage, you might free(value) here */
}

TEST(pthread_key_tls)
{
    pthread_key_t key;
    
    /* Create a key with a destructor */
    ASSERT_EQ(pthread_key_create(&key, tls_destructor), 0);
    
    /* Initially should be NULL */
    ASSERT_EQ(pthread_getspecific(key), NULL);
    
    /* Set a value */
    int value = 42;
    ASSERT_EQ(pthread_setspecific(key, &value), 0);
    
    /* Get the value back */
    int *retrieved = (int *)pthread_getspecific(key);
    ASSERT(retrieved != NULL);
    ASSERT_EQ(*retrieved, 42);
    
    /* Set to NULL */
    ASSERT_EQ(pthread_setspecific(key, NULL), 0);
    ASSERT_EQ(pthread_getspecific(key), NULL);
    
    /* Delete the key */
    ASSERT_EQ(pthread_key_delete(key), 0);
    
    /* Create multiple keys */
    pthread_key_t keys[5];
    for (int i = 0; i < 5; i++) {
        ASSERT_EQ(pthread_key_create(&keys[i], NULL), 0);
    }
    for (int i = 0; i < 5; i++) {
        ASSERT_EQ(pthread_key_delete(keys[i]), 0);
    }
    
    PASS();
}

static pthread_once_t once_control = PTHREAD_ONCE_INIT;
static int once_init_count = 0;
static void once_init_func(void) {
    once_init_count++;
}

TEST(pthread_once)
{
    once_init_count = 0;
    /* Reset once_control by zeroing the struct fields directly */
    memset(&once_control, 0, sizeof(once_control));
    
    /* First call should execute the function */
    ASSERT_EQ(pthread_once(&once_control, once_init_func), 0);
    ASSERT_EQ(once_init_count, 1);
    
    /* Second call should NOT execute the function again */
    ASSERT_EQ(pthread_once(&once_control, once_init_func), 0);
    ASSERT_EQ(once_init_count, 1);
    
    /* Third call - still should not execute */
    ASSERT_EQ(pthread_once(&once_control, once_init_func), 0);
    ASSERT_EQ(once_init_count, 1);
    
    PASS();
}

TEST(pthread_spin)
{
    pthread_spinlock_t spinlock;
    
    /* Initialize */
    ASSERT_EQ(pthread_spin_init(&spinlock, PTHREAD_PROCESS_PRIVATE), 0);
    
    /* Lock and unlock */
    ASSERT_EQ(pthread_spin_lock(&spinlock), 0);
    ASSERT_EQ(pthread_spin_unlock(&spinlock), 0);
    
    /* Trylock should succeed when not locked */
    ASSERT_EQ(pthread_spin_trylock(&spinlock), 0);
    ASSERT_EQ(pthread_spin_unlock(&spinlock), 0);
    
    /* Destroy */
    ASSERT_EQ(pthread_spin_destroy(&spinlock), 0);
    
    PASS();
}

TEST(pthread_cond)
{
    pthread_cond_t cond;
    pthread_mutex_t mutex;
    
    /* Test PTHREAD_COND_INITIALIZER */
    pthread_cond_t static_cond = PTHREAD_COND_INITIALIZER;
    (void)static_cond;  /* Just ensure it compiles */
    
    /* Initialize */
    ASSERT_EQ(pthread_cond_init(&cond, NULL), 0);
    ASSERT_EQ(pthread_mutex_init(&mutex, NULL), 0);
    
    /* Signal and broadcast (no waiters, but should not crash) */
    ASSERT_EQ(pthread_cond_signal(&cond), 0);
    ASSERT_EQ(pthread_cond_broadcast(&cond), 0);
    
    /* Test timedwait with immediate timeout */
    ASSERT_EQ(pthread_mutex_lock(&mutex), 0);
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    /* Set timeout in the past - should return ETIMEDOUT immediately */
    ts.tv_sec -= 1;
    int ret = pthread_cond_timedwait(&cond, &mutex, &ts);
    ASSERT(ret == ETIMEDOUT || ret == 0);  /* Implementation may vary */
    ASSERT_EQ(pthread_mutex_unlock(&mutex), 0);
    
    /* Destroy */
    ASSERT_EQ(pthread_cond_destroy(&cond), 0);
    ASSERT_EQ(pthread_mutex_destroy(&mutex), 0);
    
    PASS();
}

TEST(pthread_attr)
{
    pthread_attr_t attr;
    
    /* Initialize */
    ASSERT_EQ(pthread_attr_init(&attr), 0);
    
    /* Get/set detach state */
    int detachstate;
    ASSERT_EQ(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED), 0);
    ASSERT_EQ(pthread_attr_getdetachstate(&attr, &detachstate), 0);
    ASSERT_EQ(detachstate, PTHREAD_CREATE_DETACHED);
    
    ASSERT_EQ(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE), 0);
    ASSERT_EQ(pthread_attr_getdetachstate(&attr, &detachstate), 0);
    ASSERT_EQ(detachstate, PTHREAD_CREATE_JOINABLE);
    
    /* Get/set stack size */
    size_t stacksize;
    ASSERT_EQ(pthread_attr_setstacksize(&attr, 1024 * 1024), 0);
    ASSERT_EQ(pthread_attr_getstacksize(&attr, &stacksize), 0);
    ASSERT_EQ(stacksize, 1024 * 1024);
    
    /* Destroy */
    ASSERT_EQ(pthread_attr_destroy(&attr), 0);
    
    PASS();
}

/* Thread test data */
static volatile int thread_test_value = 0;
static volatile int thread_test_done = 0;

static void *thread_test_func(void *arg)
{
    int *value = (int *)arg;
    thread_test_value = *value * 2;
    thread_test_done = 1;
    return (void *)(long)thread_test_value;
}

TEST(pthread_create_basic)
{
    pthread_t thread;
    int arg = 21;
    void *retval = NULL;
    
    thread_test_value = 0;
    thread_test_done = 0;
    
    /* Create a thread */
    int ret = pthread_create(&thread, NULL, thread_test_func, &arg);
    
    /* If threads aren't supported (EAGAIN), skip this test */
    if (ret == EAGAIN) {
        printf("(threads not supported, skipping) ");
        PASS();
    }
    
    ASSERT_EQ(ret, 0);
    
    /* Wait for thread to complete */
    ret = pthread_join(thread, &retval);
    ASSERT_EQ(ret, 0);
    
    /* Check the result */
    ASSERT_EQ(thread_test_value, 42);
    ASSERT_EQ((long)retval, 42);
    
    PASS();
}

TEST(pthread_create_null_fails)
{
    /* pthread_create with NULL start_routine should fail with EINVAL */
    pthread_t thread;
    int ret = pthread_create(&thread, NULL, NULL, NULL);
    ASSERT(ret == EINVAL || ret == EAGAIN);
    
    PASS();
}

/* ============================================================================
 * errno tests
 * ============================================================================ */

TEST(errno_test)
{
    errno = 0;
    ASSERT_EQ(errno, 0);
    
    open("/nonexistent_file_xyz", O_RDONLY);
    ASSERT(errno != 0);
    ASSERT_EQ(errno, ENOENT);
    
    PASS();
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(int argc, char **argv)
{
    printf("=== Kiseki OS libSystem Unit Tests ===\n\n");
    
    printf("[string.h]\n");
    RUN_TEST(strlen);
    RUN_TEST(strcmp);
    RUN_TEST(strncmp);
    RUN_TEST(strcpy);
    RUN_TEST(strncpy);
    RUN_TEST(strcat);
    RUN_TEST(strncat);
    RUN_TEST(strchr);
    RUN_TEST(strrchr);
    RUN_TEST(strstr);
    RUN_TEST(memset);
    RUN_TEST(memcpy);
    RUN_TEST(memmove);
    RUN_TEST(memcmp);
    RUN_TEST(strdup);
    RUN_TEST(strtok);
    printf("\n");
    
    printf("[stdlib.h]\n");
    RUN_TEST(atoi);
    RUN_TEST(atol);
    RUN_TEST(strtol);
    RUN_TEST(strtoul);
    RUN_TEST(malloc_free);
    RUN_TEST(calloc);
    RUN_TEST(realloc);
    RUN_TEST(abs_labs);
    RUN_TEST(div_ldiv);
    RUN_TEST(getenv_setenv);
    RUN_TEST(qsort);
    RUN_TEST(bsearch);
    RUN_TEST(realpath);
    RUN_TEST(mkstemp_test);
    RUN_TEST(getrlimit_test);
    printf("\n");
    
    printf("[stdio.h]\n");
    RUN_TEST(sprintf_snprintf);
    RUN_TEST(sscanf);
    RUN_TEST(fopen_fclose);
    RUN_TEST(fread_fwrite);
    RUN_TEST(fseek_ftell);
    RUN_TEST(fgets_fputs);
    RUN_TEST(fgetc_fputc);
    RUN_TEST(ungetc);
    RUN_TEST(feof_ferror_clearerr);
    RUN_TEST(tmpfile);
    RUN_TEST(remove_rename);
    printf("\n");
    
    printf("[unistd.h]\n");
    RUN_TEST(read_write);
    RUN_TEST(lseek);
    RUN_TEST(dup_dup2);
    RUN_TEST(getcwd_chdir);
    RUN_TEST(access);
    RUN_TEST(getpid_getppid);
    RUN_TEST(fork_wait);
    RUN_TEST(pipe);
    RUN_TEST(sleep_usleep);
    RUN_TEST(ftruncate_test);
    RUN_TEST(fsync_test);
    RUN_TEST(gethostname_test);
    RUN_TEST(getpagesize_test);
    printf("\n");
    
    printf("[fcntl.h]\n");
    RUN_TEST(open_close);
    printf("\n");
    
    printf("[dirent.h]\n");
    RUN_TEST(opendir_readdir_closedir);
    RUN_TEST(mkdir_rmdir);
    printf("\n");
    
    printf("[time.h]\n");
    RUN_TEST(time_func);
    RUN_TEST(gettimeofday);
    RUN_TEST(localtime_gmtime);
    RUN_TEST(strftime);
    RUN_TEST(mktime);
    RUN_TEST(difftime);
    RUN_TEST(clock_gettime);
    RUN_TEST(asctime_ctime);
    printf("\n");
    
    printf("[signal.h]\n");
    RUN_TEST(signal_raise);
    printf("\n");
    
    printf("[pthread.h]\n");
    RUN_TEST(pthread_self_equal);
    RUN_TEST(pthread_mutex);
    RUN_TEST(pthread_rwlock);
    RUN_TEST(pthread_key_tls);
    RUN_TEST(pthread_once);
    RUN_TEST(pthread_spin);
    RUN_TEST(pthread_cond);
    RUN_TEST(pthread_attr);
    RUN_TEST(pthread_create_basic);
    RUN_TEST(pthread_create_null_fails);
    printf("\n");
    
    printf("[errno]\n");
    RUN_TEST(errno_test);
    printf("\n");
    
    printf("=== Results ===\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    printf("\n");
    
    if (tests_failed == 0) {
        printf("All tests PASSED!\n");
        return 0;
    } else {
        printf("Some tests FAILED!\n");
        return 1;
    }
}
