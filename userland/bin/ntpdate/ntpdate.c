/*
 * ntpdate - Set the date and time via NTP
 *
 * Queries an NTP server using SNTPv4 (RFC 4330) over UDP port 123,
 * computes the clock offset, and sets the system time via settimeofday().
 *
 * Usage: ntpdate [-q] [-v] [server]
 *
 *   -q       Query only, do not set the clock
 *   -v       Verbose output
 *   server   NTP server IP address (default: 10.0.2.2 — QEMU host gateway)
 *
 * The default server 10.0.2.2 is the QEMU user-mode networking gateway,
 * which forwards UDP packets to the host. For this to work, the host
 * must have an NTP server listening, or we relay through pool.ntp.org
 * via the host's network stack.
 *
 * Since QEMU's user-mode networking does DNS resolution on the host side,
 * we can potentially use a numeric IP. Common public NTP servers:
 *   216.239.35.0   (time.google.com)
 *   162.159.200.1  (time.cloudflare.com)
 *
 * Kiseki OS coreutils
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

/* ============================================================================
 * NTP Packet Structure (48 bytes)
 *
 * RFC 4330 / RFC 5905 simplified:
 *   LI(2) VN(3) Mode(3) | Stratum(8) | Poll(8) | Precision(8)
 *   Root Delay (32)
 *   Root Dispersion (32)
 *   Reference ID (32)
 *   Reference Timestamp (64)
 *   Originate Timestamp (64)
 *   Receive Timestamp (64)
 *   Transmit Timestamp (64)
 * ============================================================================ */

struct ntp_packet {
    uint8_t  li_vn_mode;        /* LI(2), Version(3), Mode(3) */
    uint8_t  stratum;
    uint8_t  poll;
    int8_t   precision;
    uint32_t root_delay;
    uint32_t root_dispersion;
    uint32_t ref_id;
    uint32_t ref_ts_sec;
    uint32_t ref_ts_frac;
    uint32_t orig_ts_sec;
    uint32_t orig_ts_frac;
    uint32_t rx_ts_sec;
    uint32_t rx_ts_frac;
    uint32_t tx_ts_sec;
    uint32_t tx_ts_frac;
};

/* NTP epoch is Jan 1, 1900. Unix epoch is Jan 1, 1970.
 * Difference: 70 years of seconds (including 17 leap years). */
#define NTP_EPOCH_OFFSET 2208988800UL

/* Network byte order helpers (NTP uses big-endian) */
static uint32_t htonl_simple(uint32_t h)
{
    return ((h & 0xFF000000) >> 24) |
           ((h & 0x00FF0000) >> 8)  |
           ((h & 0x0000FF00) << 8)  |
           ((h & 0x000000FF) << 24);
}

static uint16_t htons_simple(uint16_t h)
{
    return (uint16_t)(((h & 0xFF00) >> 8) | ((h & 0x00FF) << 8));
}

#define ntohl_simple htonl_simple

/* Inline syscall for socket operations */
static inline long raw_syscall(long num, long a0, long a1, long a2,
                                long a3, long a4, long a5)
{
    register long x16 __asm__("x16") = num;
    register long x0  __asm__("x0")  = a0;
    register long x1  __asm__("x1")  = a1;
    register long x2  __asm__("x2")  = a2;
    register long x3  __asm__("x3")  = a3;
    register long x4  __asm__("x4")  = a4;
    register long x5  __asm__("x5")  = a5;
    register long nzcv;

    __asm__ volatile(
        "svc    #0x80\n\t"
        "mrs    %[nzcv], nzcv"
        : [nzcv] "=r" (nzcv), "+r" (x0)
        : "r" (x16), "r" (x1), "r" (x2), "r" (x3), "r" (x4), "r" (x5)
        : "memory", "cc"
    );

    if (nzcv & (1L << 29))
        return -x0;
    return x0;
}

/* Socket address structure */
struct sockaddr_in {
    uint8_t     sin_len;
    uint8_t     sin_family;
    uint16_t    sin_port;
    uint32_t    sin_addr;
    uint8_t     sin_zero[8];
};

#define AF_INET     2
#define SOCK_DGRAM  2
#define SYS_socket      97
#define SYS_sendto      133
#define SYS_recvfrom    29
#define SYS_close       6
#define SYS_gettimeofday 116
#define SYS_settimeofday 122
#define SYS_connect     98

/* Parse dotted-decimal IP address */
static uint32_t parse_ip(const char *s)
{
    uint32_t a = 0, b = 0, c = 0, d = 0;
    int i = 0, part = 0;
    uint32_t val = 0;

    while (s[i] || part < 4) {
        if (s[i] == '.' || s[i] == '\0') {
            switch (part) {
            case 0: a = val; break;
            case 1: b = val; break;
            case 2: c = val; break;
            case 3: d = val; break;
            }
            val = 0;
            part++;
            if (s[i] == '\0') break;
        } else {
            val = val * 10 + (uint32_t)(s[i] - '0');
        }
        i++;
    }

    /* Network byte order (big-endian) */
    return (a) | (b << 8) | (c << 16) | (d << 24);
}

static void usage(void)
{
    fprintf(stderr, "Usage: ntpdate [-q] [-v] [server]\n");
    fprintf(stderr, "Set the date and time via NTP.\n\n");
    fprintf(stderr, "  -q       Query only, do not set clock\n");
    fprintf(stderr, "  -v       Verbose output\n");
    fprintf(stderr, "  server   NTP server IP (default: 216.239.35.0)\n");
}

int main(int argc, char *argv[])
{
    int query_only = 0;
    int verbose = 0;
    const char *server = "216.239.35.0";  /* time.google.com */

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            usage();
            return 0;
        }
        if (strcmp(argv[i], "-q") == 0) { query_only = 1; continue; }
        if (strcmp(argv[i], "-v") == 0) { verbose = 1; continue; }
        if (argv[i][0] != '-') { server = argv[i]; continue; }
        fprintf(stderr, "ntpdate: unknown option '%s'\n", argv[i]);
        usage();
        return 1;
    }

    if (verbose)
        printf("ntpdate: querying NTP server %s\n", server);

    /* Create UDP socket */
    int sock = (int)raw_syscall(SYS_socket, AF_INET, SOCK_DGRAM, 0, 0, 0, 0);
    if (sock < 0) {
        fprintf(stderr, "ntpdate: socket: error %d\n", -sock);
        return 1;
    }

    /* Build NTP request packet */
    struct ntp_packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    /* LI=0 (no warning), VN=4 (NTPv4), Mode=3 (client) */
    pkt.li_vn_mode = (0 << 6) | (4 << 3) | 3;

    /* Record our transmit time (T1) for offset calculation */
    struct { long tv_sec; long tv_usec; } t1_tv = { 0, 0 };
    raw_syscall(SYS_gettimeofday, (long)&t1_tv, 0, 0, 0, 0, 0);

    /* Set originate timestamp to T1 (so server echoes it back) */
    uint32_t t1_ntp = (uint32_t)((uint64_t)t1_tv.tv_sec + NTP_EPOCH_OFFSET);
    pkt.orig_ts_sec = htonl_simple(t1_ntp);
    pkt.orig_ts_frac = htonl_simple(
        (uint32_t)(((uint64_t)t1_tv.tv_usec * 0x100000000ULL) / 1000000ULL));

    /* Send to NTP server on port 123 */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_len = sizeof(addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons_simple(123);
    addr.sin_addr = parse_ip(server);

    long ret = raw_syscall(SYS_sendto, sock, (long)&pkt, sizeof(pkt),
                           0, (long)&addr, sizeof(addr));
    if (ret < 0) {
        fprintf(stderr, "ntpdate: sendto: error %d\n", (int)(-ret));
        raw_syscall(SYS_close, sock, 0, 0, 0, 0, 0);
        return 1;
    }

    if (verbose)
        printf("ntpdate: sent NTP request (%ld bytes)\n", ret);

    /* Wait for response — poll with retries */
    struct ntp_packet reply;
    memset(&reply, 0, sizeof(reply));

    int got_reply = 0;
    for (int attempt = 0; attempt < 50; attempt++) {
        /* Small delay between polls */
        struct { long tv_sec; long tv_nsec; } sl = { 0, 100000000L }; /* 100ms */
        raw_syscall(240 /* SYS_nanosleep */, (long)&sl, 0, 0, 0, 0, 0);

        uint32_t fromlen = sizeof(addr);
        ret = raw_syscall(SYS_recvfrom, sock, (long)&reply, sizeof(reply),
                          0, (long)&addr, (long)&fromlen);
        if (ret >= (long)sizeof(reply)) {
            got_reply = 1;
            break;
        }
    }

    /* Record receive time (T4) */
    struct { long tv_sec; long tv_usec; } t4_tv = { 0, 0 };
    raw_syscall(SYS_gettimeofday, (long)&t4_tv, 0, 0, 0, 0, 0);

    raw_syscall(SYS_close, sock, 0, 0, 0, 0, 0);

    if (!got_reply) {
        fprintf(stderr, "ntpdate: no response from %s (timeout after 5s)\n",
                server);
        return 1;
    }

    /* Extract server timestamps */
    uint32_t t2_sec = ntohl_simple(reply.rx_ts_sec);     /* Server receive */
    uint32_t t3_sec = ntohl_simple(reply.tx_ts_sec);     /* Server transmit */

    /* Validate response */
    uint8_t mode = reply.li_vn_mode & 0x07;
    uint8_t stratum = reply.stratum;
    if (mode != 4 && mode != 5) {
        /* mode 4 = server, mode 5 = broadcast */
        fprintf(stderr, "ntpdate: unexpected response mode %d\n", mode);
        return 1;
    }
    if (stratum == 0 || stratum > 15) {
        fprintf(stderr, "ntpdate: server stratum %d (kiss-o'-death or invalid)\n",
                stratum);
        return 1;
    }

    /* Convert NTP timestamps to Unix epoch */
    long t2_unix = (long)(t2_sec - NTP_EPOCH_OFFSET);
    long t3_unix = (long)(t3_sec - NTP_EPOCH_OFFSET);
    long t1_unix = t1_tv.tv_sec;
    long t4_unix = t4_tv.tv_sec;

    /*
     * NTP offset calculation (simplified, seconds only):
     *   offset = ((T2 - T1) + (T3 - T4)) / 2
     * Where:
     *   T1 = client transmit time
     *   T2 = server receive time
     *   T3 = server transmit time
     *   T4 = client receive time
     */
    long offset = ((t2_unix - t1_unix) + (t3_unix - t4_unix)) / 2;

    /* Round-trip delay */
    long delay = (t4_unix - t1_unix) - (t3_unix - t2_unix);

    /* Compute new time = current time + offset */
    long new_sec = t4_tv.tv_sec + offset;

    /* Break down for display */
    long rem = new_sec;
    int year = 1970;
    static const int mdays[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    long days = rem / 86400;
    rem = rem % 86400;
    if (rem < 0) { rem += 86400; days--; }
    int hour = (int)(rem / 3600);
    rem %= 3600;
    int min = (int)(rem / 60);
    int sec = (int)(rem % 60);

    while (days >= (365 + ((year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)) ? 1 : 0))) {
        int leap = (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)) ? 1 : 0;
        days -= (365 + leap);
        year++;
    }
    int mon = 0;
    while (mon < 11) {
        int md = mdays[mon];
        if (mon == 1 && (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)))
            md = 29;
        if (days < md) break;
        days -= md;
        mon++;
    }
    int mday = (int)days + 1;

    static const char *monnames[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };

    printf("%2d %s %04d %02d:%02d:%02d.000000 (+%04ld) %s",
           mday, monnames[mon], year, hour, min, sec,
           offset >= 0 ? offset : -offset, server);

    if (verbose) {
        printf("\n  stratum %d, offset %+ld.000 sec, delay %ld.000 sec",
               stratum, offset, delay);
    }
    printf("\n");

    if (query_only) {
        if (verbose)
            printf("ntpdate: query only, clock not set\n");
        return 0;
    }

    /* Set system time */
    struct { long tv_sec; long tv_usec; } new_tv;
    new_tv.tv_sec = new_sec;
    new_tv.tv_usec = 0;

    ret = raw_syscall(SYS_settimeofday, (long)&new_tv, 0, 0, 0, 0, 0);
    if (ret < 0) {
        fprintf(stderr, "ntpdate: settimeofday: error %d (need root?)\n",
                (int)(-ret));
        return 1;
    }

    printf("ntpdate: adjust time server %s offset %+ld sec\n", server, offset);
    return 0;
}
