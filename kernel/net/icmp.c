/*
 * Kiseki OS - ICMP Protocol Implementation
 *
 * Handles ICMP echo request/reply (ping) and other ICMP messages.
 * Delivers echo replies to ICMP datagram sockets for userspace ping.
 *
 * Reference: RFC 792
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
 * ICMP Header
 * ============================================================================ */

#define ICMP_ECHO_REPLY     0
#define ICMP_ECHO_REQUEST   8

struct icmp_hdr {
    uint8_t     icmp_type;
    uint8_t     icmp_code;
    uint16_t    icmp_cksum;
    uint16_t    icmp_id;
    uint16_t    icmp_seq;
} __packed;

/* ============================================================================
 * Checksum (same algorithm as IP)
 * ============================================================================ */

static uint16_t icmp_checksum(const void *data, uint32_t len)
{
    const uint16_t *ptr = (const uint16_t *)data;
    uint32_t sum = 0;

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len == 1)
        sum += *(const uint8_t *)ptr;

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)(~sum);
}

/* ============================================================================
 * Socket delivery for ICMP echo replies
 *
 * When an ICMP echo reply arrives, we find any ICMP datagram socket
 * and deliver the full ICMP packet (header + payload) to its receive
 * buffer. The userland ping can then read it via recvfrom().
 * ============================================================================ */

/* Access the socket table from socket.c */
extern struct socket socket_table[];

static void icmp_deliver_to_socket(uint32_t src_addr, const void *data,
                                   uint32_t len)
{
    /* Find an ICMP socket to deliver to */
    for (int i = 0; i < NET_MAX_SOCKETS; i++) {
        struct socket *so = &socket_table[i];
        if (!so->so_active)
            continue;
        if (so->so_protocol != IPPROTO_ICMP)
            continue;

        /* Deliver the full ICMP packet (type + code + cksum + id + seq + payload)
         * to the socket's receive buffer */
        const uint8_t *src = (const uint8_t *)data;
        uint64_t flags;
        spin_lock_irqsave(&so->so_rcv.sb_lock, &flags);

        uint32_t written = 0;
        while (written < len && so->so_rcv.sb_len < SOCKBUF_SIZE) {
            so->so_rcv.sb_buf[so->so_rcv.sb_tail] = src[written];
            so->so_rcv.sb_tail = (so->so_rcv.sb_tail + 1) % SOCKBUF_SIZE;
            so->so_rcv.sb_len++;
            written++;
        }

        /* Store the source address so recvfrom can report it */
        so->so_remote.sin_addr.s_addr = src_addr;
        so->so_remote.sin_port = 0;

        spin_unlock_irqrestore(&so->so_rcv.sb_lock, flags);
        return; /* Deliver to first matching ICMP socket */
    }
}

/* ============================================================================
 * ICMP Input
 *
 * Called from ip_input() when protocol == IPPROTO_ICMP.
 * ============================================================================ */

void icmp_input(uint32_t src_addr, uint32_t dst_addr,
                const void *data, uint32_t len)
{
    if (len < sizeof(struct icmp_hdr)) {
        kprintf("[icmp] packet too short (%u bytes)\n", len);
        return;
    }

    const struct icmp_hdr *icmp = (const struct icmp_hdr *)data;

    switch (icmp->icmp_type) {
    case ICMP_ECHO_REQUEST: {
        /* Respond with echo reply */
        kprintf("[icmp] echo request from %u.%u.%u.%u\n",
                (ntohl(src_addr) >> 24) & 0xFF,
                (ntohl(src_addr) >> 16) & 0xFF,
                (ntohl(src_addr) >> 8) & 0xFF,
                ntohl(src_addr) & 0xFF);
        uint8_t reply_buf[1500];
        if (len > sizeof(reply_buf))
            return;

        /* Copy the entire ICMP message */
        const uint8_t *src = (const uint8_t *)data;
        for (uint32_t i = 0; i < len; i++)
            reply_buf[i] = src[i];

        /* Change type to echo reply */
        struct icmp_hdr *rh = (struct icmp_hdr *)reply_buf;
        rh->icmp_type = ICMP_ECHO_REPLY;
        rh->icmp_code = 0;
        rh->icmp_cksum = 0;
        rh->icmp_cksum = icmp_checksum(reply_buf, len);

        /* Send via IP layer — swap src/dst */
        kprintf("[icmp] sending echo reply to %u.%u.%u.%u\n",
                (ntohl(src_addr) >> 24) & 0xFF,
                (ntohl(src_addr) >> 16) & 0xFF,
                (ntohl(src_addr) >> 8) & 0xFF,
                ntohl(src_addr) & 0xFF);
        int ret = ip_output(dst_addr, src_addr, IPPROTO_ICMP, reply_buf, len);
        kprintf("[icmp] ip_output returned %d\n", ret);
        break;
    }

    case ICMP_ECHO_REPLY: {
        /* Deliver to any open ICMP datagram socket */
        kprintf("[icmp] echo reply from %u.%u.%u.%u len=%u\n",
                (ntohl(src_addr) >> 24) & 0xFF,
                (ntohl(src_addr) >> 16) & 0xFF,
                (ntohl(src_addr) >> 8) & 0xFF,
                ntohl(src_addr) & 0xFF, len);
        icmp_deliver_to_socket(src_addr, data, len);
        break;
    }

    default:
        /* Ignore other ICMP types for now */
        break;
    }
}
