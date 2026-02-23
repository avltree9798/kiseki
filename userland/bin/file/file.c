/*
 * file - determine file type
 *
 * Kiseki OS coreutils
 * Unix-compliant file type identification utility
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

static const char *progname = "file";

/* Mach-O magic numbers */
#define MH_MAGIC_64     0xfeedfacf  /* 64-bit Mach-O */
#define MH_CIGAM_64     0xcffaedfe  /* 64-bit Mach-O, byte-swapped */
#define MH_MAGIC        0xfeedface  /* 32-bit Mach-O */
#define MH_CIGAM        0xcefaedfe  /* 32-bit Mach-O, byte-swapped */
#define FAT_MAGIC       0xcafebabe  /* Universal binary */
#define FAT_CIGAM       0xbebafeca  /* Universal binary, byte-swapped */

/* ELF magic */
#define ELF_MAGIC       0x464c457f  /* "\x7fELF" as little-endian u32 */

/* Mach-O file types */
#define MH_OBJECT       0x1
#define MH_EXECUTE      0x2
#define MH_DYLIB        0x6
#define MH_DYLINKER     0x7
#define MH_BUNDLE       0x8
#define MH_DSYM         0xa

/* Mach-O CPU types */
#define CPU_TYPE_ARM64  0x0100000c
#define CPU_TYPE_X86_64 0x01000007
#define CPU_TYPE_ARM    0x0000000c
#define CPU_TYPE_X86    0x00000007

/* Script magic */
#define SCRIPT_MAGIC    0x2123      /* "#!" */

/* Archive magic */
#define AR_MAGIC        "!<arch>\n"

/* Compression magic */
#define GZIP_MAGIC      0x8b1f
#define BZIP2_MAGIC     0x5a42      /* "BZ" */
#define XZ_MAGIC        0x587a      /* "xz" (partial) */

/* Image magic */
#define PNG_MAGIC       0x474e5089  /* "\x89PNG" */
#define JPEG_MAGIC      0xe0ffd8ff  /* JPEG SOI + APP0 */
#define GIF_MAGIC       0x38464947  /* "GIF8" */

/* PDF magic */
#define PDF_MAGIC       0x46445025  /* "%PDF" */

static void usage(void)
{
    fprintf(stderr, "Usage: %s [-bhi] file...\n", progname);
    fprintf(stderr, "Determine type of FILE(s).\n\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -b    brief mode (don't prepend filenames)\n");
    fprintf(stderr, "  -h    don't follow symlinks\n");
    fprintf(stderr, "  -i    output MIME type strings\n");
    fprintf(stderr, "  --help display this help and exit\n");
}

static const char *get_macho_type(uint32_t filetype)
{
    switch (filetype) {
    case MH_OBJECT:    return "object file";
    case MH_EXECUTE:   return "executable";
    case MH_DYLIB:     return "dynamic library";
    case MH_DYLINKER:  return "dynamic linker";
    case MH_BUNDLE:    return "bundle";
    case MH_DSYM:      return "dSYM companion file";
    default:           return "Mach-O file";
    }
}

static const char *get_cpu_type(uint32_t cputype)
{
    switch (cputype) {
    case CPU_TYPE_ARM64:  return "arm64";
    case CPU_TYPE_X86_64: return "x86_64";
    case CPU_TYPE_ARM:    return "arm";
    case CPU_TYPE_X86:    return "i386";
    default:              return "unknown arch";
    }
}

static int is_text_file(const unsigned char *buf, size_t len)
{
    /* Check if content is mostly printable ASCII */
    size_t printable = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = buf[i];
        if ((c >= 0x20 && c <= 0x7e) || c == '\n' || c == '\r' || c == '\t')
            printable++;
        else if (c == 0)
            return 0;  /* NUL byte = not text */
    }
    /* Consider text if >90% printable */
    return (printable * 100 / len) > 90;
}

static const char *identify_text_type(const unsigned char *buf, size_t len)
{
    /* Check for various text file types */
    if (len >= 2 && buf[0] == '#' && buf[1] == '!') {
        /* Script - try to identify interpreter */
        const char *line = (const char *)buf;
        if (strstr(line, "/bin/sh") || strstr(line, "/bin/bash"))
            return "Bourne-Again shell script, ASCII text executable";
        if (strstr(line, "/bin/zsh"))
            return "zsh script, ASCII text executable";
        if (strstr(line, "python"))
            return "Python script, ASCII text executable";
        if (strstr(line, "perl"))
            return "Perl script, ASCII text executable";
        if (strstr(line, "ruby"))
            return "Ruby script, ASCII text executable";
        if (strstr(line, "node") || strstr(line, "nodejs"))
            return "Node.js script, ASCII text executable";
        return "script, ASCII text executable";
    }
    
    /* Check for XML/HTML */
    if (len >= 5 && strncmp((const char *)buf, "<?xml", 5) == 0)
        return "XML document, ASCII text";
    if (len >= 6 && (strncmp((const char *)buf, "<html", 5) == 0 ||
                     strncmp((const char *)buf, "<!DOC", 5) == 0))
        return "HTML document, ASCII text";
    
    /* Check for C source */
    if (strstr((const char *)buf, "#include") || 
        strstr((const char *)buf, "int main"))
        return "C source, ASCII text";
    
    /* Check for JSON */
    if ((buf[0] == '{' || buf[0] == '[') && 
        (strchr((const char *)buf, ':') || strchr((const char *)buf, ',')))
        return "JSON data, ASCII text";
    
    /* Check for Makefile */
    if (strstr((const char *)buf, "make") || 
        strstr((const char *)buf, ":=") ||
        strstr((const char *)buf, "$("))
        return "makefile, ASCII text";
    
    return "ASCII text";
}

static int identify_file(const char *path, int brief, int mime, int nofollow)
{
    struct stat st;
    int ret;
    
    /* Get file info */
    if (nofollow)
        ret = lstat(path, &st);
    else
        ret = stat(path, &st);
    
    if (ret < 0) {
        if (!brief)
            printf("%s: ", path);
        printf("cannot open '%s' (No such file or directory)\n", path);
        return 1;
    }
    
    if (!brief)
        printf("%s: ", path);
    
    /* Handle non-regular files */
    if (S_ISDIR(st.st_mode)) {
        if (mime)
            printf("inode/directory\n");
        else
            printf("directory\n");
        return 0;
    }
    
    if (S_ISLNK(st.st_mode)) {
        if (mime) {
            printf("inode/symlink\n");
        } else {
            char link[256];
            ssize_t len = readlink(path, link, sizeof(link) - 1);
            if (len > 0) {
                link[len] = '\0';
                printf("symbolic link to %s\n", link);
            } else {
                printf("symbolic link\n");
            }
        }
        return 0;
    }
    
    if (S_ISCHR(st.st_mode)) {
        if (mime)
            printf("inode/chardevice\n");
        else
            printf("character special\n");
        return 0;
    }
    
    if (S_ISBLK(st.st_mode)) {
        if (mime)
            printf("inode/blockdevice\n");
        else
            printf("block special\n");
        return 0;
    }
    
    if (S_ISFIFO(st.st_mode)) {
        if (mime)
            printf("inode/fifo\n");
        else
            printf("fifo (named pipe)\n");
        return 0;
    }
    
    if (S_ISSOCK(st.st_mode)) {
        if (mime)
            printf("inode/socket\n");
        else
            printf("socket\n");
        return 0;
    }
    
    /* Empty file */
    if (st.st_size == 0) {
        if (mime)
            printf("inode/x-empty\n");
        else
            printf("empty\n");
        return 0;
    }
    
    /* Read file header */
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        printf("cannot open '%s' (%s)\n", path, strerror(errno));
        return 1;
    }
    
    unsigned char buf[512];
    ssize_t nread = read(fd, buf, sizeof(buf));
    close(fd);
    
    if (nread < 0) {
        printf("cannot read '%s' (%s)\n", path, strerror(errno));
        return 1;
    }
    
    if (nread < 4) {
        if (mime)
            printf("application/octet-stream\n");
        else
            printf("data\n");
        return 0;
    }
    
    /* Get first 4 bytes as magic number */
    uint32_t magic = *(uint32_t *)buf;
    uint16_t magic16 = *(uint16_t *)buf;
    
    /* Check for Mach-O */
    if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        if (mime) {
            printf("application/x-mach-binary\n");
        } else {
            /* Parse Mach-O header */
            uint32_t cputype = *(uint32_t *)(buf + 4);
            uint32_t filetype = *(uint32_t *)(buf + 12);
            if (magic == MH_CIGAM_64) {
                /* Byte-swap if needed */
                cputype = __builtin_bswap32(cputype);
                filetype = __builtin_bswap32(filetype);
            }
            printf("Mach-O 64-bit %s %s\n", 
                   get_cpu_type(cputype), get_macho_type(filetype));
        }
        return 0;
    }
    
    if (magic == MH_MAGIC || magic == MH_CIGAM) {
        if (mime) {
            printf("application/x-mach-binary\n");
        } else {
            uint32_t cputype = *(uint32_t *)(buf + 4);
            uint32_t filetype = *(uint32_t *)(buf + 12);
            if (magic == MH_CIGAM) {
                cputype = __builtin_bswap32(cputype);
                filetype = __builtin_bswap32(filetype);
            }
            printf("Mach-O 32-bit %s %s\n",
                   get_cpu_type(cputype), get_macho_type(filetype));
        }
        return 0;
    }
    
    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        if (mime)
            printf("application/x-mach-binary\n");
        else
            printf("Mach-O universal binary with 2+ architectures\n");
        return 0;
    }
    
    /* Check for ELF */
    if (magic == ELF_MAGIC) {
        if (mime) {
            printf("application/x-executable\n");
        } else {
            /* ELF class: buf[4] = 1 for 32-bit, 2 for 64-bit */
            const char *bits = (buf[4] == 2) ? "64-bit" : "32-bit";
            /* ELF type at offset 16: 2=exec, 3=shared */
            uint16_t etype = *(uint16_t *)(buf + 16);
            const char *type = "ELF";
            if (etype == 2) type = "ELF executable";
            else if (etype == 3) type = "ELF shared object";
            printf("%s %s\n", bits, type);
        }
        return 0;
    }
    
    /* Check for archive */
    if (nread >= 8 && memcmp(buf, AR_MAGIC, 8) == 0) {
        if (mime)
            printf("application/x-archive\n");
        else
            printf("current ar archive\n");
        return 0;
    }
    
    /* Check for compressed files */
    if (magic16 == GZIP_MAGIC) {
        if (mime)
            printf("application/gzip\n");
        else
            printf("gzip compressed data\n");
        return 0;
    }
    
    if (buf[0] == 'B' && buf[1] == 'Z' && buf[2] == 'h') {
        if (mime)
            printf("application/x-bzip2\n");
        else
            printf("bzip2 compressed data\n");
        return 0;
    }
    
    if (nread >= 6 && buf[0] == 0xfd && buf[1] == '7' && 
        buf[2] == 'z' && buf[3] == 'X' && buf[4] == 'Z') {
        if (mime)
            printf("application/x-xz\n");
        else
            printf("XZ compressed data\n");
        return 0;
    }
    
    /* Check for images */
    if (magic == PNG_MAGIC) {
        if (mime)
            printf("image/png\n");
        else
            printf("PNG image data\n");
        return 0;
    }
    
    if ((magic & 0xffff) == 0xd8ff) {
        if (mime)
            printf("image/jpeg\n");
        else
            printf("JPEG image data\n");
        return 0;
    }
    
    if (buf[0] == 'G' && buf[1] == 'I' && buf[2] == 'F' && buf[3] == '8') {
        if (mime)
            printf("image/gif\n");
        else
            printf("GIF image data\n");
        return 0;
    }
    
    /* Check for PDF */
    if (buf[0] == '%' && buf[1] == 'P' && buf[2] == 'D' && buf[3] == 'F') {
        if (mime)
            printf("application/pdf\n");
        else
            printf("PDF document\n");
        return 0;
    }
    
    /* Check for text files */
    if (is_text_file(buf, (size_t)nread)) {
        if (mime) {
            printf("text/plain\n");
        } else {
            printf("%s\n", identify_text_type(buf, (size_t)nread));
        }
        return 0;
    }
    
    /* Unknown binary */
    if (mime)
        printf("application/octet-stream\n");
    else
        printf("data\n");
    
    return 0;
}

int main(int argc, char *argv[])
{
    int brief = 0;
    int mime = 0;
    int nofollow = 0;
    int i;
    
    /* Parse options */
    for (i = 1; i < argc && argv[i][0] == '-'; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            usage();
            return 0;
        }
        if (strcmp(argv[i], "--") == 0) {
            i++;
            break;
        }
        for (const char *p = argv[i] + 1; *p; p++) {
            switch (*p) {
            case 'b': brief = 1; break;
            case 'h': nofollow = 1; break;
            case 'i': mime = 1; break;
            default:
                fprintf(stderr, "%s: invalid option -- '%c'\n", progname, *p);
                usage();
                return 1;
            }
        }
    }
    
    if (i >= argc) {
        fprintf(stderr, "%s: missing file operand\n", progname);
        usage();
        return 1;
    }
    
    int ret = 0;
    for (; i < argc; i++) {
        if (identify_file(argv[i], brief, mime, nofollow) != 0)
            ret = 1;
    }
    
    return ret;
}
