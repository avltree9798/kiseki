/*
 * Kiseki OS - mDNSResponder
 *
 * DNS resolution daemon modeled after Apple's mDNSResponder.
 * Receives DNS lookup requests via Mach IPC from libSystem's getaddrinfo(),
 * performs UDP DNS queries to the upstream DNS server (from DHCP), and
 * returns resolved addresses via Mach IPC reply.
 *
 * Architecture (matching macOS):
 *   1. Calls bootstrap_check_in() to claim the pre-created service port
 *      (init/launchd pre-creates this port before launching us)
 *   2. Gets the DNS server IP from /etc/resolv.conf (primary) or
 *      sysctl(CTL_NET, NET_KISEKI_IFDNS) (DHCP fallback)
 *   3. Event loop: receive Mach message -> DNS lookup -> reply
 *
 * Message protocol (Kiseki-specific, simplified from macOS DNSServiceRef):
 *   Request:  mach_msg_header_t + uint32_t msg_id + char hostname[256]
 *   Reply:    mach_msg_header_t + uint32_t msg_id + int32_t error +
 *             uint32_t addr_count + uint32_t addrs[8]
 *
 * Boot chain: init (launchd) -> mDNSResponder (daemon, background)
 *
 * Service port lifecycle (matching macOS launchd):
 *   - init reads /System/Library/LaunchDaemons/uk.co.avltree9798.mDNSResponder.plist
 *   - init pre-creates a Mach port and registers it as our service
 *   - init forks and execs us
 *   - We call bootstrap_check_in() to claim the receive right
 *   - Clients can bootstrap_look_up() at any time — even before we start
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

/* Forward declarations */
static int _try_parse_ip(const char *str, uint32_t *out);

/* ============================================================================
 * Constants
 * ============================================================================ */

#define MDNS_SERVICE_NAME       "uk.co.avltree9798.mDNSResponder"

/* DNS wire format (RFC 1035) */
#define DNS_PORT                53
#define DNS_HEADER_SIZE         12
#define DNS_TYPE_A              1
#define DNS_CLASS_IN            1
#define DNS_FLAG_RD             0x0100  /* Recursion Desired */
#define DNS_FLAG_QR             0x8000  /* Response flag */
#define DNS_FLAG_RCODE_MASK     0x000F

/* sysctl constants */
#define CTL_NET                 4
#define NET_KISEKI_IFDNS        103

/* Message IDs for our IPC protocol */
#define MDNS_MSG_RESOLVE        1000
#define MDNS_MSG_RESOLVE_REPLY  1001

/* Maximum addresses to return */
#define MDNS_MAX_ADDRS          8
#define MDNS_MAX_HOSTNAME       256

/* ============================================================================
 * IPC Message Structures
 *
 * These are the wire format for Mach messages between getaddrinfo() in
 * libSystem and this daemon. They follow the standard Mach message layout:
 * fixed header + inline body.
 * ============================================================================ */

/* Request: "resolve this hostname" */
typedef struct {
    mach_msg_header_t   header;
    uint32_t            msg_id;
    char                hostname[MDNS_MAX_HOSTNAME];
} mdns_request_t;

/* Reply: "here are the addresses" */
typedef struct {
    mach_msg_header_t   header;
    int32_t             error;          /* 0 = success, negative = EAI_* */
    uint32_t            addr_count;     /* Number of IPv4 addresses */
    uint32_t            addrs[MDNS_MAX_ADDRS];  /* Network byte order */
} mdns_reply_t;

/* ============================================================================
 * DNS Wire Protocol
 * ============================================================================ */

static uint16_t _htons(uint16_t x)
{
    return (uint16_t)((x >> 8) | (x << 8));
}

/*
 * Build a DNS A-record query packet.
 * Returns the total packet size, or -1 on error.
 */
static int dns_build_query(const char *hostname, uint16_t txid,
                           uint8_t *buf, int buflen)
{
    if (buflen < DNS_HEADER_SIZE + 256 + 4)
        return -1;

    memset(buf, 0, buflen);

    /* Header */
    buf[0] = (uint8_t)(txid >> 8);
    buf[1] = (uint8_t)(txid & 0xFF);
    /* Flags: RD=1 */
    buf[2] = 0x01;
    buf[3] = 0x00;
    /* QDCOUNT = 1 */
    buf[4] = 0x00;
    buf[5] = 0x01;

    /* QNAME: encode hostname as DNS labels */
    int pos = DNS_HEADER_SIZE;
    const char *p = hostname;
    while (*p) {
        const char *dot = strchr(p, '.');
        int label_len;
        if (dot)
            label_len = (int)(dot - p);
        else
            label_len = (int)strlen(p);

        if (label_len == 0 || label_len > 63)
            return -1;
        if (pos + 1 + label_len >= buflen)
            return -1;

        buf[pos++] = (uint8_t)label_len;
        memcpy(&buf[pos], p, label_len);
        pos += label_len;

        if (dot)
            p = dot + 1;
        else
            break;
    }
    buf[pos++] = 0;    /* Root label */

    /* QTYPE = A (1) */
    buf[pos++] = 0x00;
    buf[pos++] = 0x01;
    /* QCLASS = IN (1) */
    buf[pos++] = 0x00;
    buf[pos++] = 0x01;

    return pos;
}

/*
 * Parse a DNS response and extract A-record addresses.
 * Returns number of addresses found, or -1 on error.
 */
static int dns_parse_response(const uint8_t *buf, int len,
                              uint32_t *addrs, int max_addrs)
{
    if (len < DNS_HEADER_SIZE)
        return -1;

    uint16_t flags = (uint16_t)((buf[2] << 8) | buf[3]);
    if (!(flags & 0x80))        /* QR bit must be set (response) */
        return -1;
    if ((flags & 0x0F) != 0)    /* RCODE must be 0 (no error) */
        return -1;

    uint16_t ancount = (uint16_t)((buf[6] << 8) | buf[7]);

    /* Skip the question section */
    int pos = DNS_HEADER_SIZE;
    uint16_t qdcount = (uint16_t)((buf[4] << 8) | buf[5]);
    for (int q = 0; q < qdcount; q++) {
        while (pos < len) {
            uint8_t llen = buf[pos];
            if (llen == 0) { pos++; break; }
            if ((llen & 0xC0) == 0xC0) { pos += 2; break; }
            pos += 1 + llen;
        }
        pos += 4;   /* QTYPE + QCLASS */
    }

    /* Parse answer records */
    int count = 0;
    for (int a = 0; a < ancount && pos < len && count < max_addrs; a++) {
        /* Skip NAME (may be compressed) */
        if (pos >= len) break;
        if ((buf[pos] & 0xC0) == 0xC0)
            pos += 2;
        else {
            while (pos < len && buf[pos] != 0) {
                if ((buf[pos] & 0xC0) == 0xC0) { pos += 2; goto after_name; }
                pos += 1 + buf[pos];
            }
            pos++;  /* Skip null terminator */
        }
after_name:
        if (pos + 10 > len) break;

        uint16_t rtype = (uint16_t)((buf[pos] << 8) | buf[pos + 1]);
        /* uint16_t rclass = (uint16_t)((buf[pos+2] << 8) | buf[pos+3]); */
        uint16_t rdlength = (uint16_t)((buf[pos + 8] << 8) | buf[pos + 9]);
        pos += 10;

        if (rtype == DNS_TYPE_A && rdlength == 4 && pos + 4 <= len) {
            /* A record: 4 bytes IPv4 address in network byte order */
            uint32_t addr;
            memcpy(&addr, &buf[pos], 4);
            addrs[count++] = addr;
        }
        pos += rdlength;
    }

    return count;
}

/* ============================================================================
 * DNS Query via UDP
 * ============================================================================ */

static int dns_query(uint32_t dns_server, const char *hostname,
                     uint32_t *addrs, int max_addrs)
{
    uint8_t query[512];
    uint8_t response[1024];

    /* Build query packet */
    static uint16_t txid = 0x1234;
    txid++;

    int qlen = dns_build_query(hostname, txid, query, sizeof(query));
    if (qlen < 0)
        return -1;

    /* Create UDP socket */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return -1;

    /* Send to DNS server */
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = _htons(DNS_PORT);
    dest.sin_addr.s_addr = dns_server;

    int sent = (int)sendto(sock, query, qlen, 0,
                           (struct sockaddr *)&dest, sizeof(dest));
    if (sent < 0) {
        close(sock);
        return -1;
    }

    /* Receive response (with timeout via select, or blocking) */
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    int rlen = (int)recvfrom(sock, response, sizeof(response), 0,
                             (struct sockaddr *)&from, &fromlen);
    close(sock);

    if (rlen < DNS_HEADER_SIZE)
        return -1;

    /* Verify transaction ID */
    uint16_t resp_txid = (uint16_t)((response[0] << 8) | response[1]);
    if (resp_txid != txid)
        return -1;

    return dns_parse_response(response, rlen, addrs, max_addrs);
}

/* ============================================================================
 * Parse /etc/resolv.conf for nameserver entries
 *
 * On macOS, DNS resolver configuration is managed by configd/scutil and
 * stored in the System Configuration dynamic store. The resolver library
 * (libresolv) reads /etc/resolv.conf as the traditional Unix fallback.
 *
 * Format (RFC-compliant):
 *   nameserver <IPv4 address>
 *   # comment lines
 *   search <domain>      (ignored for now)
 *   domain <domain>      (ignored for now)
 *
 * We read the first "nameserver" line found.
 * ============================================================================ */

#define RESOLV_CONF_PATH    "/etc/resolv.conf"

static uint32_t parse_resolv_conf(void)
{
    int fd = open(RESOLV_CONF_PATH, 0 /* O_RDONLY */);
    if (fd < 0)
        return 0;

    char buf[512];
    int total = 0;
    int n;

    /* Read the file (it's small — resolv.conf is typically < 200 bytes) */
    while (total < (int)sizeof(buf) - 1) {
        n = (int)read(fd, buf + total, sizeof(buf) - 1 - total);
        if (n <= 0)
            break;
        total += n;
    }
    close(fd);
    buf[total] = '\0';

    /* Parse line by line looking for "nameserver" */
    char *p = buf;
    while (*p) {
        /* Skip leading whitespace */
        while (*p == ' ' || *p == '\t') p++;

        /* Check for "nameserver" keyword */
        if (p[0] == 'n' && p[1] == 'a' && p[2] == 'm' && p[3] == 'e' &&
            p[4] == 's' && p[5] == 'e' && p[6] == 'r' && p[7] == 'v' &&
            p[8] == 'e' && p[9] == 'r' &&
            (p[10] == ' ' || p[10] == '\t')) {

            p += 10;
            /* Skip whitespace after keyword */
            while (*p == ' ' || *p == '\t') p++;

            /* Parse IPv4 address: a.b.c.d */
            uint32_t addr;
            if (_try_parse_ip(p, &addr))
                return addr;
        }

        /* Skip to next line */
        while (*p && *p != '\n') p++;
        if (*p == '\n') p++;
    }

    return 0;
}

/* ============================================================================
 * Get DNS Server — resolv.conf first, sysctl (DHCP) fallback
 *
 * Priority order (matching macOS resolver behavior):
 *   1. /etc/resolv.conf nameserver entry (user-configured)
 *   2. sysctl NET_KISEKI_IFDNS (DHCP-provided DNS server)
 *   3. 0 (no DNS server available)
 * ============================================================================ */

static uint32_t get_dns_server(void)
{
    /* Try /etc/resolv.conf first */
    uint32_t dns_ip = parse_resolv_conf();
    if (dns_ip != 0)
        return dns_ip;

    /* Fall back to DHCP-provided DNS via sysctl */
    int name[2] = { CTL_NET, NET_KISEKI_IFDNS };
    size_t len = sizeof(dns_ip);

    if (sysctl(name, 2, &dns_ip, &len, NULL, 0) < 0)
        return 0;

    return dns_ip;
}

/* ============================================================================
 * Main Event Loop
 * ============================================================================ */

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    fprintf(stderr, "mDNSResponder: starting\n");

    /* Get DNS server from DHCP */
    uint32_t dns_server = get_dns_server();
    if (dns_server == 0) {
        fprintf(stderr, "mDNSResponder: no DNS server configured\n");
        /* Don't exit — retry later or just fail lookups */
    } else {
        unsigned char *ip = (unsigned char *)&dns_server;
        fprintf(stderr, "mDNSResponder: upstream DNS %d.%d.%d.%d\n",
                ip[0], ip[1], ip[2], ip[3]);
    }

    /*
     * Claim our service port from init (launchd).
     *
     * On macOS, launchd pre-creates Mach service ports declared in the
     * daemon's plist before the daemon starts. The daemon calls
     * bootstrap_check_in() to receive the receive right.
     *
     * This is the proper macOS pattern — no self-registration needed.
     * The port is already in the bootstrap namespace, so clients can
     * bootstrap_look_up() at any time.
     */
    mach_port_t service_port = MACH_PORT_NULL;
    kern_return_t kr = bootstrap_check_in(MACH_PORT_NULL,
                                          MDNS_SERVICE_NAME,
                                          &service_port);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "mDNSResponder: bootstrap_check_in failed: %d\n", kr);
        fprintf(stderr, "mDNSResponder: is our plist installed in LaunchDaemons?\n");
        return 1;
    }

    fprintf(stderr, "mDNSResponder: checked in as '%s' (port %u)\n",
            MDNS_SERVICE_NAME, service_port);

    /* Main event loop: receive requests, do DNS, reply */
    for (;;) {
        /* Receive buffer large enough for request + trailer */
        union {
            mdns_request_t  request;
            uint8_t         bytes[sizeof(mdns_request_t) + 64];
        } recv_buf;

        memset(&recv_buf, 0, sizeof(recv_buf));

        /* Receive a request */
        kr = mach_msg(&recv_buf.request.header,
                      MACH_RCV_MSG,
                      0,                            /* send_size (not sending) */
                      sizeof(recv_buf),             /* rcv_size */
                      service_port,                 /* rcv_name */
                      MACH_MSG_TIMEOUT_NONE,        /* timeout */
                      MACH_PORT_NULL);              /* notify */

        if (kr != MACH_MSG_SUCCESS) {
            fprintf(stderr, "mDNSResponder: mach_msg receive error: 0x%x\n", kr);
            continue;
        }

        /* Validate the message */
        if (recv_buf.request.header.msgh_id != MDNS_MSG_RESOLVE) {
            fprintf(stderr, "mDNSResponder: unknown msg_id %d\n",
                    recv_buf.request.header.msgh_id);
            continue;
        }

        /* Null-terminate hostname safely */
        recv_buf.request.hostname[MDNS_MAX_HOSTNAME - 1] = '\0';

        fprintf(stderr, "mDNSResponder: resolving '%s'\n",
                recv_buf.request.hostname);

        /* Build reply */
        mdns_reply_t reply;
        memset(&reply, 0, sizeof(reply));

        /*
         * On XNU, after receive the header is:
         *   msgh_remote_port = reply port (sender's reply port, with
         *                      send-once right in our space)
         *   msgh_local_port  = destination port (our service port)
         *
         * To send the reply, use msgh_remote_port from the request as
         * the destination (MOVE_SEND_ONCE to consume the send-once right).
         */
        reply.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
        reply.header.msgh_size = sizeof(reply);
        reply.header.msgh_remote_port = recv_buf.request.header.msgh_remote_port;
        reply.header.msgh_local_port = MACH_PORT_NULL;
        reply.header.msgh_id = MDNS_MSG_RESOLVE_REPLY;

        /* Check if it's a numeric IP (skip DNS lookup) */
        uint32_t numeric_addr = 0;
        if (_try_parse_ip(recv_buf.request.hostname, &numeric_addr)) {
            reply.error = 0;
            reply.addr_count = 1;
            reply.addrs[0] = numeric_addr;
        } else if (dns_server == 0) {
            /* No DNS server available */
            reply.error = -2;   /* EAI_NONAME */
            reply.addr_count = 0;
        } else {
            /* Perform DNS lookup */
            int count = dns_query(dns_server, recv_buf.request.hostname,
                                  reply.addrs, MDNS_MAX_ADDRS);
            if (count > 0) {
                reply.error = 0;
                reply.addr_count = (uint32_t)count;
            } else {
                reply.error = -2;   /* EAI_NONAME */
                reply.addr_count = 0;
            }
        }

        /* Send reply */
        kr = mach_msg(&reply.header,
                      MACH_SEND_MSG,
                      sizeof(reply),        /* send_size */
                      0,                    /* rcv_size (not receiving) */
                      MACH_PORT_NULL,       /* rcv_name */
                      MACH_MSG_TIMEOUT_NONE,
                      MACH_PORT_NULL);

        if (kr != MACH_MSG_SUCCESS) {
            fprintf(stderr, "mDNSResponder: mach_msg send error: 0x%x\n", kr);
        }

        /* Re-read DNS server in case it changed (DHCP renewal) */
        uint32_t new_dns = get_dns_server();
        if (new_dns != 0)
            dns_server = new_dns;
    }

    return 0;
}

/* ============================================================================
 * Helper: try to parse a numeric IPv4 address
 * Returns 1 if successful, 0 if not numeric.
 * ============================================================================ */

static int _try_parse_ip(const char *str, uint32_t *out)
{
    const char *p = str;
    int parts = 0;
    unsigned int vals[4] = {0, 0, 0, 0};

    for (int i = 0; i < 4; i++) {
        unsigned int val = 0;
        int digits = 0;
        while (*p >= '0' && *p <= '9') {
            val = val * 10 + (*p - '0');
            p++;
            digits++;
            if (digits > 3 || val > 255) return 0;
        }
        if (digits == 0) return 0;
        vals[i] = val;
        parts++;
        if (i < 3) {
            if (*p != '.') return 0;
            p++;
        }
    }
    /* Accept termination by NUL, newline, whitespace, or CR */
    if (parts != 4) return 0;
    if (*p != '\0' && *p != '\n' && *p != '\r' && *p != ' ' && *p != '\t')
        return 0;

    *out = (vals[0]) | (vals[1] << 8) | (vals[2] << 16) | (vals[3] << 24);
    return 1;
}
