/*
 * writetest - Test file I/O to diagnose truncation issues
 *
 * Usage: writetest <filename> <size_in_bytes>
 *
 * Writes a test pattern to a file and verifies the written size.
 * Tests both buffered (fwrite) and unbuffered (write) I/O.
 *
 * Kiseki OS diagnostic utility
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

static void test_buffered_write(const char *filename, size_t size)
{
    printf("=== Buffered write test (fwrite) ===\n");
    printf("Writing %zu bytes to %s\n", size, filename);

    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        printf("ERROR: fopen failed: %s\n", strerror(errno));
        return;
    }

    /* Write test pattern: repeating 0x00-0xFF */
    size_t written = 0;
    unsigned char byte = 0;
    
    for (size_t i = 0; i < size; i++) {
        int ret = fputc(byte, fp);
        if (ret == EOF) {
            printf("ERROR: fputc failed at byte %zu: %s\n", i, strerror(errno));
            break;
        }
        written++;
        byte++;
    }

    printf("fputc loop wrote %zu bytes\n", written);

    int flush_ret = fflush(fp);
    printf("fflush returned %d (errno=%d: %s)\n", flush_ret, errno, strerror(errno));

    long pos = ftell(fp);
    printf("ftell reports position: %ld\n", pos);

    int close_ret = fclose(fp);
    printf("fclose returned %d (errno=%d: %s)\n", close_ret, errno, strerror(errno));

    /* Verify file size */
    struct stat st;
    if (stat(filename, &st) == 0) {
        printf("stat reports file size: %lld bytes\n", (long long)st.st_size);
        if ((size_t)st.st_size != size) {
            printf("WARNING: Expected %zu bytes, got %lld bytes!\n", size, (long long)st.st_size);
        } else {
            printf("SUCCESS: File size matches expected size\n");
        }
    } else {
        printf("ERROR: stat failed: %s\n", strerror(errno));
    }
}

static void test_unbuffered_write(const char *filename, size_t size)
{
    printf("\n=== Unbuffered write test (write syscall) ===\n");
    printf("Writing %zu bytes to %s\n", size, filename);

    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        printf("ERROR: open failed: %s\n", strerror(errno));
        return;
    }

    /* Create a buffer with test pattern */
    unsigned char *buf = malloc(size);
    if (!buf) {
        printf("ERROR: malloc failed\n");
        close(fd);
        return;
    }

    for (size_t i = 0; i < size; i++) {
        buf[i] = (unsigned char)(i & 0xFF);
    }

    /* Write in chunks to see where it fails */
    size_t total_written = 0;
    size_t chunk_size = 4096;  /* Write 4KB at a time */
    
    while (total_written < size) {
        size_t to_write = size - total_written;
        if (to_write > chunk_size)
            to_write = chunk_size;

        ssize_t ret = write(fd, buf + total_written, to_write);
        if (ret < 0) {
            printf("ERROR: write failed at offset %zu: %s (errno=%d)\n", 
                   total_written, strerror(errno), errno);
            break;
        }
        if (ret == 0) {
            printf("WARNING: write returned 0 at offset %zu\n", total_written);
            break;
        }
        
        printf("write(%zu bytes) at offset %zu returned %zd\n", 
               to_write, total_written, ret);
        total_written += ret;
    }

    printf("Total written: %zu bytes\n", total_written);

    int close_ret = close(fd);
    printf("close returned %d (errno=%d: %s)\n", close_ret, errno, strerror(errno));

    free(buf);

    /* Verify file size */
    struct stat st;
    if (stat(filename, &st) == 0) {
        printf("stat reports file size: %lld bytes\n", (long long)st.st_size);
        if ((size_t)st.st_size != size) {
            printf("WARNING: Expected %zu bytes, got %lld bytes!\n", size, (long long)st.st_size);
        } else {
            printf("SUCCESS: File size matches expected size\n");
        }
    } else {
        printf("ERROR: stat failed: %s\n", strerror(errno));
    }
}

static void test_seek_and_write(const char *filename, size_t size)
{
    printf("\n=== Seek and write test (fseek + fwrite) ===\n");
    printf("Writing %zu bytes with seeks to %s\n", size, filename);

    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        printf("ERROR: fopen failed: %s\n", strerror(errno));
        return;
    }

    /* This simulates what TCC does: seek to an offset and write */
    
    /* First, write header at offset 0 */
    unsigned char header[32];
    memset(header, 0xAA, sizeof(header));
    size_t ret = fwrite(header, 1, sizeof(header), fp);
    printf("fwrite header (32 bytes) returned %zu\n", ret);
    
    /* Seek to offset 4096 (like TCC seeking to __TEXT segment) */
    printf("Seeking to offset 4096...\n");
    int seek_ret = fseek(fp, 4096, SEEK_SET);
    printf("fseek returned %d (errno=%d: %s)\n", seek_ret, errno, strerror(errno));
    
    /* Write some code */
    unsigned char code[256];
    memset(code, 0xBB, sizeof(code));
    ret = fwrite(code, 1, sizeof(code), fp);
    printf("fwrite code (256 bytes) at 4096 returned %zu\n", ret);
    
    long pos = ftell(fp);
    printf("ftell reports position: %ld\n", pos);
    
    /* Seek further to offset 8192 */
    printf("Seeking to offset 8192...\n");
    seek_ret = fseek(fp, 8192, SEEK_SET);
    printf("fseek returned %d (errno=%d: %s)\n", seek_ret, errno, strerror(errno));
    
    /* Write more data */
    unsigned char data[256];
    memset(data, 0xCC, sizeof(data));
    ret = fwrite(data, 1, sizeof(data), fp);
    printf("fwrite data (256 bytes) at 8192 returned %zu\n", ret);
    
    pos = ftell(fp);
    printf("ftell reports position: %ld\n", pos);

    /* Now seek to the end and write something there */
    size_t final_offset = size - 256;
    printf("Seeking to offset %zu...\n", final_offset);
    seek_ret = fseek(fp, final_offset, SEEK_SET);
    printf("fseek returned %d (errno=%d: %s)\n", seek_ret, errno, strerror(errno));
    
    unsigned char tail[256];
    memset(tail, 0xDD, sizeof(tail));
    ret = fwrite(tail, 1, sizeof(tail), fp);
    printf("fwrite tail (256 bytes) at %zu returned %zu\n", final_offset, ret);
    
    pos = ftell(fp);
    printf("ftell reports position: %ld (expected %zu)\n", pos, size);

    int flush_ret = fflush(fp);
    printf("fflush returned %d (errno=%d: %s)\n", flush_ret, errno, strerror(errno));

    int close_ret = fclose(fp);
    printf("fclose returned %d (errno=%d: %s)\n", close_ret, errno, strerror(errno));

    /* Verify file size */
    struct stat st;
    if (stat(filename, &st) == 0) {
        printf("stat reports file size: %lld bytes\n", (long long)st.st_size);
        if ((size_t)st.st_size != size) {
            printf("WARNING: Expected %zu bytes, got %lld bytes!\n", size, (long long)st.st_size);
        } else {
            printf("SUCCESS: File size matches expected size\n");
        }
    } else {
        printf("ERROR: stat failed: %s\n", strerror(errno));
    }
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <filename> <size>\n", argv[0]);
        fprintf(stderr, "  Writes <size> bytes to <filename> using various methods\n");
        fprintf(stderr, "  and reports any issues.\n");
        return 1;
    }

    const char *filename = argv[1];
    size_t size = (size_t)atol(argv[2]);

    if (size == 0) {
        fprintf(stderr, "Error: size must be > 0\n");
        return 1;
    }

    printf("File I/O diagnostic test\n");
    printf("Target file: %s\n", filename);
    printf("Target size: %zu bytes\n\n", size);

    /* Test 1: Buffered fwrite */
    char testfile1[256];
    snprintf(testfile1, sizeof(testfile1), "%s.buffered", filename);
    test_buffered_write(testfile1, size);

    /* Test 2: Unbuffered write syscall */
    char testfile2[256];
    snprintf(testfile2, sizeof(testfile2), "%s.unbuffered", filename);
    test_unbuffered_write(testfile2, size);

    /* Test 3: Seek and write (simulates TCC) */
    char testfile3[256];
    snprintf(testfile3, sizeof(testfile3), "%s.seekwrite", filename);
    test_seek_and_write(testfile3, size);

    printf("\n=== Summary ===\n");
    struct stat st;
    
    if (stat(testfile1, &st) == 0)
        printf("%s: %lld bytes\n", testfile1, (long long)st.st_size);
    
    if (stat(testfile2, &st) == 0)
        printf("%s: %lld bytes\n", testfile2, (long long)st.st_size);
    
    if (stat(testfile3, &st) == 0)
        printf("%s: %lld bytes\n", testfile3, (long long)st.st_size);

    return 0;
}
