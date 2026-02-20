/*
 * Kiseki OS - UDP Protocol Implementation
 *
 * Implements UDP datagram send/receive with socket integration.
 *
 * Reference: RFC 768
 */

#include <kiseki/types.h>
#include <net/net.h>
#include <kern/kprintf.h>
#include <kern/sync.h>
#include <fs/vfs.h>

/* Forward declarations */
int ip_output(uint32_t src, uint32_t dst, uint8_t proto,
              const void *data, uint32_t len);

/* ============================================================================
 * UDP Header (RFC 768)
 * ============================================================================ */

struct udp_hdr {
    uint16_t    uh_sport;       /* Source port */
    uint16_t    uh_dport;       /* Destination port */
    uint16_t    uh_len;         /* Length (header + data) */
    uint16_t    uh_sum;         /* Checksum (optional in IPv4) */
} __packed;

/* ============================================================================
 * UDP Input
 *
 * Called from ip_input() for IPPROTO_UDP packets.
 * Finds a matching socket and delivers data to its receive buffer.
 * ============================================================================ */

/* Access the socket table from socket.c */
extern struct socket socket_table[];

static uint32_t udp_sockbuf_write(struct sockbuf *sb, const uint8_t *data,
                                   uint32_t len)
{
    uint32_t written = 0;
    uint64_t flags;

    spin_lock_irqsave(&sb->sb_lock, &flags);

    while (written < len && sb->sb_len < SOCKBUF_SIZE) {
        sb->sb_buf[sb->sb_tail] = data[written];
        sb->sb_tail = (sb->sb_tail + 1) % SOCKBUF_SIZE;
        sb->sb_len++;
        written++;
    }

    spin_unlock_irqrestore(&sb->sb_lock, flags);
    return written;
}

/* DHCP client handler (port 68) */
extern void dhcp_input(const void *data, uint32_t len);

void udp_input(uint32_t src_addr, uint32_t dst_addr,
               const void *data, uint32_t len)
{
    (void)dst_addr;

    if (len < sizeof(struct udp_hdr)) {
        kprintf("[udp] packet too short (%u bytes)\n", len);
        return;
    }

    const struct udp_hdr *uh = (const struct udp_hdr *)data;
    uint16_t dport = uh->uh_dport; /* already in network order */
    uint16_t sport = uh->uh_sport;

    /* Check for DHCP client port (68) - handle before socket lookup */
    if (ntohs(dport) == 68) {
        /* Skip UDP header and pass DHCP payload */
        const uint8_t *payload = (const uint8_t *)data + sizeof(struct udp_hdr);
        uint32_t payload_len = len - sizeof(struct udp_hdr);
        dhcp_input(payload, payload_len);
        return;
    }

    /* Find a matching socket */
    struct socket *match = NULL;
    for (int i = 0; i < NET_MAX_SOCKETS; i++) {
        struct socket *so = &socket_table[i];
        if (!so->so_active)
            continue;
        if (so->so_protocol != IPPROTO_UDP)
            continue;
        if (so->so_local.sin_port == dport) {
            match = so;
            break;
        }
    }

    if (match == NULL) {
        /* No matching socket, silently drop */
        return;
    }

    /* Extract payload */
    uint32_t payload_off = sizeof(struct udp_hdr);
    uint32_t payload_len = len - payload_off;
    const uint8_t *payload = (const uint8_t *)data + payload_off;

    /* Store the sender info for recvfrom */
    match->so_remote.sin_addr.s_addr = src_addr;
    match->so_remote.sin_port = sport;

    /* Deliver to socket receive buffer */
    udp_sockbuf_write(&match->so_rcv, payload, payload_len);
}

/* ============================================================================
 * UDP Output
 *
 * Send a UDP datagram from a socket.
 * ============================================================================ */

int udp_output(struct socket *so, const void *data, uint32_t len,
               uint32_t dst_addr, uint16_t dst_port)
{
    uint32_t total = sizeof(struct udp_hdr) + len;
    uint8_t buf[1500];

    if (total > sizeof(buf))
        return -EINVAL;

    /* Build UDP header */
    struct udp_hdr *uh = (struct udp_hdr *)buf;
    uh->uh_sport = so->so_local.sin_port;
    uh->uh_dport = dst_port;
    uh->uh_len   = htons((uint16_t)total);
    uh->uh_sum   = 0;  /* Optional in IPv4 */

    /* Copy payload */
    const uint8_t *src = (const uint8_t *)data;
    uint8_t *dst = buf + sizeof(struct udp_hdr);
    for (uint32_t i = 0; i < len; i++)
        dst[i] = src[i];

    /* Send via IP */
    return ip_output(so->so_local.sin_addr.s_addr, dst_addr,
                     IPPROTO_UDP, buf, total);
}
