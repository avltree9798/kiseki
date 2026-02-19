/*
 * Kiseki OS - IPv4 Layer
 *
 * Basic IPv4 input/output processing. Handles IP header construction,
 * checksum calculation, and demultiplexing to upper-layer protocols
 * (TCP, UDP).
 *
 * Reference: RFC 791, Stevens "TCP/IP Illustrated" Vol 1 Ch. 3
 */

#include <kiseki/types.h>
#include <net/net.h>
#include <net/tcp.h>
#include <kern/kprintf.h>
#include <kern/sync.h>
#include <fs/vfs.h>

/* Forward declarations for ethernet layer */
int eth_output(uint32_t dst_ip, uint16_t ethertype,
               const void *data, uint32_t len);

/* Forward declaration for ICMP */
void icmp_input(uint32_t src_addr, uint32_t dst_addr,
                const void *data, uint32_t len);

/* Forward declaration for UDP */
void udp_input(uint32_t src_addr, uint32_t dst_addr,
               const void *data, uint32_t len);

/* ============================================================================
 * IPv4 Header (RFC 791)
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Version|  IHL  |    DSCP/TOS   |          Total Length         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Identification        |Flags|      Fragment Offset    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Time to Live |    Protocol   |         Header Checksum       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Source Address                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Destination Address                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ============================================================================ */

struct ip_hdr {
    uint8_t     ip_vhl;         /* Version (4 bits) + IHL (4 bits) */
    uint8_t     ip_tos;         /* Type of service / DSCP + ECN */
    uint16_t    ip_len;         /* Total length (header + data) */
    uint16_t    ip_id;          /* Identification */
    uint16_t    ip_off;         /* Flags (3 bits) + Fragment offset (13 bits) */
    uint8_t     ip_ttl;         /* Time to live */
    uint8_t     ip_proto;       /* Protocol (IPPROTO_TCP, IPPROTO_UDP, ...) */
    uint16_t    ip_sum;         /* Header checksum */
    uint32_t    ip_src;         /* Source address (network byte order) */
    uint32_t    ip_dst;         /* Destination address (network byte order) */
} __packed;

/* IP header length helpers */
#define IP_VHL_V4       0x45    /* IPv4, 5 * 4 = 20 byte header */
#define IP_HDRLEN(iph)  (((iph)->ip_vhl & 0x0F) * 4)

/* IP flags */
#define IP_DF           0x4000  /* Don't Fragment */
#define IP_MF           0x2000  /* More Fragments */

/* Default TTL */
#define IP_DEFAULT_TTL  64

/* EtherType for IPv4 */
#define ETHERTYPE_IP    0x0800

/* ============================================================================
 * Module State
 * ============================================================================ */

/* Simple IP identification counter */
static uint16_t ip_id_counter = 1;

/* Our IP address (set during network configuration) */
static uint32_t local_ip_addr = 0;  /* Will be set by net config */

/* Default gateway and subnet mask for routing */
static uint32_t gateway_ip = 0;     /* Network byte order */
static uint32_t subnet_mask = 0;    /* Network byte order */

/* ============================================================================
 * IP Checksum (RFC 1071)
 *
 * One's complement sum of 16-bit words, then one's complement of result.
 * ============================================================================ */

static uint16_t ip_checksum(const void *data, uint32_t len)
{
    const uint16_t *ptr = (const uint16_t *)data;
    uint32_t sum = 0;

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }

    /* Handle odd byte */
    if (len == 1) {
        sum += *(const uint8_t *)ptr;
    }

    /* Fold 32-bit sum to 16 bits */
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)(~sum);
}

/* ============================================================================
 * IP Configuration
 * ============================================================================ */

/*
 * ip_set_addr - Set the local IP address.
 *
 * @addr: IPv4 address in network byte order.
 */
uint32_t ip_get_addr(void)
{
    return local_ip_addr;
}

void ip_set_addr(uint32_t addr)
{
    local_ip_addr = addr;
    kprintf("[ip] local address set to %u.%u.%u.%u\n",
            (ntohl(addr) >> 24) & 0xFF,
            (ntohl(addr) >> 16) & 0xFF,
            (ntohl(addr) >> 8) & 0xFF,
            ntohl(addr) & 0xFF);
}

/*
 * ip_set_gateway - Set the default gateway IP address.
 *
 * @gw: Gateway IPv4 address in network byte order.
 */
void ip_set_gateway(uint32_t gw)
{
    gateway_ip = gw;
    kprintf("[ip] default gateway set to %u.%u.%u.%u\n",
            (ntohl(gw) >> 24) & 0xFF,
            (ntohl(gw) >> 16) & 0xFF,
            (ntohl(gw) >> 8) & 0xFF,
            ntohl(gw) & 0xFF);
}

/*
 * ip_set_netmask - Set the subnet mask.
 *
 * @mask: Subnet mask in network byte order (e.g., 255.255.255.0).
 */
void ip_set_netmask(uint32_t mask)
{
    subnet_mask = mask;
    kprintf("[ip] subnet mask set to %u.%u.%u.%u\n",
            (ntohl(mask) >> 24) & 0xFF,
            (ntohl(mask) >> 16) & 0xFF,
            (ntohl(mask) >> 8) & 0xFF,
            ntohl(mask) & 0xFF);
}

/* ============================================================================
 * IP Input
 *
 * Process an incoming IP datagram. Validates the header, then demuxes
 * to the appropriate upper-layer protocol handler.
 * ============================================================================ */

void ip_input(const void *data, uint32_t len)
{
    if (len < sizeof(struct ip_hdr)) {
        kprintf("[ip] packet too short (%u bytes)\n", len);
        return;
    }

    const struct ip_hdr *iph = (const struct ip_hdr *)data;

    /* Verify IPv4 */
    uint8_t version = (iph->ip_vhl >> 4) & 0x0F;
    if (version != 4) {
        kprintf("[ip] not IPv4 (version=%u)\n", version);
        return;
    }

    /* Verify header length */
    uint32_t hdr_len = IP_HDRLEN(iph);
    if (hdr_len < 20 || hdr_len > len) {
        kprintf("[ip] invalid header length %u\n", hdr_len);
        return;
    }

    /* Verify total length */
    uint16_t total_len = ntohs(iph->ip_len);
    if (total_len > len) {
        kprintf("[ip] total length %u exceeds packet size %u\n",
                total_len, len);
        return;
    }

    /* Verify checksum */
    if (ip_checksum(iph, hdr_len) != 0) {
        kprintf("[ip] bad header checksum\n");
        return;
    }

    /* Check destination address (accept broadcast and our address) */
    if (local_ip_addr != 0 &&
        iph->ip_dst != local_ip_addr &&
        iph->ip_dst != htonl(INADDR_BROADCAST)) {
        /* Not for us - would forward in a router. Drop for now. */
        return;
    }

    /* Compute upper-layer data pointer and length */
    const uint8_t *payload = (const uint8_t *)data + hdr_len;
    uint32_t payload_len = total_len - hdr_len;

    /* Demultiplex to upper-layer protocol */
    switch (iph->ip_proto) {
    case IPPROTO_ICMP:
        icmp_input(iph->ip_src, iph->ip_dst, payload, payload_len);
        break;

    case IPPROTO_TCP:
        tcp_input(iph->ip_src, iph->ip_dst, payload, payload_len);
        break;

    case IPPROTO_UDP:
        udp_input(iph->ip_src, iph->ip_dst, payload, payload_len);
        break;

    default:
        kprintf("[ip] unknown protocol %u\n", iph->ip_proto);
        break;
    }
}

/* ============================================================================
 * IP Output
 *
 * Construct an IP header, compute checksum, and pass to the ethernet
 * layer for transmission.
 * ============================================================================ */

/* Maximum IP packet we can build (header + data).
 * Ethernet MTU is 1500, but we use a static buffer. */
#define IP_MAX_PACKET   1500

static uint8_t ip_tx_buf[IP_MAX_PACKET];
static spinlock_t ip_tx_lock = SPINLOCK_INIT;

int ip_output(uint32_t src, uint32_t dst, uint8_t proto,
              const void *data, uint32_t len)
{
    uint32_t total_len = sizeof(struct ip_hdr) + len;

    if (total_len > IP_MAX_PACKET) {
        kprintf("[ip] packet too large (%u bytes, max %u)\n",
                total_len, IP_MAX_PACKET);
        return -EINVAL;
    }

    uint64_t irq_flags;
    spin_lock_irqsave(&ip_tx_lock, &irq_flags);

    /* Build IP header */
    struct ip_hdr *iph = (struct ip_hdr *)ip_tx_buf;
    iph->ip_vhl   = IP_VHL_V4;
    iph->ip_tos   = 0;
    iph->ip_len   = htons((uint16_t)total_len);
    iph->ip_id    = htons(ip_id_counter++);
    iph->ip_off   = htons(IP_DF);       /* Don't Fragment */
    iph->ip_ttl   = IP_DEFAULT_TTL;
    iph->ip_proto = proto;
    iph->ip_sum   = 0;
    iph->ip_src   = (src != 0) ? src : local_ip_addr;
    iph->ip_dst   = dst;

    /* Compute header checksum */
    iph->ip_sum   = ip_checksum(iph, sizeof(struct ip_hdr));

    /* Copy payload after header */
    const uint8_t *src_data = (const uint8_t *)data;
    uint8_t *dst_data = ip_tx_buf + sizeof(struct ip_hdr);
    for (uint32_t i = 0; i < len; i++)
        dst_data[i] = src_data[i];

    /* Determine the next-hop IP for ARP resolution.
     * If the destination is on our local subnet, ARP for it directly.
     * Otherwise, ARP for the default gateway. */
    uint32_t next_hop = dst;
    if (gateway_ip != 0 && subnet_mask != 0 &&
        dst != htonl(INADDR_BROADCAST)) {
        /* Check if destination is on the local subnet */
        if ((dst & subnet_mask) != (local_ip_addr & subnet_mask)) {
            next_hop = gateway_ip;
        }
    }

    /* Send via ethernet layer.
     * eth_output may copy ip_tx_buf into the ARP pending queue if ARP
     * is not yet resolved, so we must hold the lock until it returns. */
    int ret = eth_output(next_hop, ETHERTYPE_IP, ip_tx_buf, total_len);

    spin_unlock_irqrestore(&ip_tx_lock, irq_flags);

    return ret;
}
