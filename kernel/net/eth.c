/*
 * Kiseki OS - Ethernet Framing Layer
 *
 * Handles Ethernet frame construction/parsing and ARP (Address Resolution
 * Protocol) for mapping IPv4 addresses to MAC addresses.
 *
 * Reference: IEEE 802.3, RFC 826 (ARP)
 */

#include <kiseki/types.h>
#include <net/net.h>
#include <kern/kprintf.h>
#include <kern/sync.h>
#include <fs/vfs.h>

/* Forward declarations */
void ip_input(const void *data, uint32_t len);

/* NIC driver send function (provided by virtio_net or platform driver).
 * Weak symbol: returns -EIO if no NIC driver is linked. */
__weak int nic_send(const void *frame, uint32_t len);

/* ============================================================================
 * Ethernet Header
 * ============================================================================ */

#define ETH_ALEN        6       /* MAC address length */
#define ETH_HDRLEN      14      /* Ethernet header length */
#define ETH_MTU         1500    /* Maximum payload */
#define ETH_FRAME_MAX   (ETH_HDRLEN + ETH_MTU)

/* EtherType values */
#define ETHERTYPE_IP    0x0800
#define ETHERTYPE_ARP   0x0806
#define ETHERTYPE_IPV6  0x86DD

struct eth_hdr {
    uint8_t     eth_dst[ETH_ALEN];  /* Destination MAC */
    uint8_t     eth_src[ETH_ALEN];  /* Source MAC */
    uint16_t    eth_type;           /* EtherType (network byte order) */
} __packed;

/* ============================================================================
 * ARP Structures (RFC 826)
 * ============================================================================ */

#define ARP_HRD_ETHER   1       /* Hardware type: Ethernet */
#define ARP_OP_REQUEST   1       /* ARP Request */
#define ARP_OP_REPLY     2       /* ARP Reply */

struct arp_hdr {
    uint16_t    ar_hrd;         /* Hardware type */
    uint16_t    ar_pro;         /* Protocol type (ETHERTYPE_IP) */
    uint8_t     ar_hln;         /* Hardware address length (6 for Ethernet) */
    uint8_t     ar_pln;         /* Protocol address length (4 for IPv4) */
    uint16_t    ar_op;          /* Operation (ARP_OP_REQUEST/REPLY) */
    /* Followed by variable-length addresses; for Ethernet+IPv4: */
    uint8_t     ar_sha[ETH_ALEN];  /* Sender hardware (MAC) address */
    uint32_t    ar_spa;             /* Sender protocol (IP) address */
    uint8_t     ar_tha[ETH_ALEN];  /* Target hardware (MAC) address */
    uint32_t    ar_tpa;             /* Target protocol (IP) address */
} __packed;

/* ============================================================================
 * ARP Cache
 *
 * Simple fixed-size ARP table. Maps IPv4 addresses to MAC addresses.
 * Uses linear search; sufficient for a small kernel with few peers.
 * ============================================================================ */

#define ARP_CACHE_SIZE  32

struct arp_entry {
    uint32_t    ip_addr;                /* IPv4 address (network order) */
    uint8_t     mac_addr[ETH_ALEN];     /* MAC address */
    bool        valid;                  /* Entry is populated */
};

static struct arp_entry arp_cache[ARP_CACHE_SIZE];
static spinlock_t arp_lock = SPINLOCK_INIT;

/* ============================================================================
 * Module State
 * ============================================================================ */

/* Our MAC address (set by NIC driver during init) */
static uint8_t local_mac[ETH_ALEN] = { 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 };

/* Our IP address (set during network configuration) */
static uint32_t local_ip = 0;

/* Broadcast MAC */
static const uint8_t broadcast_mac[ETH_ALEN] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

/* Transmit buffer (protected by eth_tx_lock for SMP safety) */
static uint8_t eth_tx_buf[ETH_FRAME_MAX];
static spinlock_t eth_tx_lock = SPINLOCK_INIT;

/* ============================================================================
 * ARP Pending Packet Queue
 *
 * When an ARP cache miss occurs, we queue the outgoing packet here.
 * When the ARP reply arrives and populates the cache, we drain the queue.
 * ============================================================================ */

#define ARP_PEND_MAX    4

struct arp_pending {
    uint8_t     data[ETH_FRAME_MAX];    /* IP payload (passed to eth_output) */
    uint32_t    len;                    /* Payload length */
    uint32_t    dst_ip;                 /* Destination IP (for ARP lookup) */
    uint16_t    ethertype;              /* EtherType */
    bool        valid;
};

static struct arp_pending arp_pending_queue[ARP_PEND_MAX];
static spinlock_t arp_pending_lock = SPINLOCK_INIT;

/* Forward declarations for ARP pending queue operations */
static void arp_enqueue_pending(uint32_t dst_ip, uint16_t ethertype,
                                const void *data, uint32_t len);
static void arp_drain_pending(void);

/* ============================================================================
 * MAC Address Helpers
 * ============================================================================ */

static void mac_copy(uint8_t *dst, const uint8_t *src)
{
    for (int i = 0; i < ETH_ALEN; i++)
        dst[i] = src[i];
}

static __unused bool mac_equal(const uint8_t *a, const uint8_t *b)
{
    for (int i = 0; i < ETH_ALEN; i++) {
        if (a[i] != b[i])
            return false;
    }
    return true;
}

static bool mac_is_broadcast(const uint8_t *addr)
{
    for (int i = 0; i < ETH_ALEN; i++) {
        if (addr[i] != 0xFF)
            return false;
    }
    return true;
}

/* ============================================================================
 * ARP Cache Operations
 * ============================================================================ */

/*
 * arp_lookup - Look up a MAC address for an IP address.
 *
 * @ip:  IPv4 address (network byte order)
 * @mac: Output buffer for MAC address (ETH_ALEN bytes)
 *
 * Returns true if found, false if not in cache.
 */
static bool arp_lookup(uint32_t ip, uint8_t *mac)
{
    uint64_t flags;
    spin_lock_irqsave(&arp_lock, &flags);

    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (arp_cache[i].valid && arp_cache[i].ip_addr == ip) {
            mac_copy(mac, arp_cache[i].mac_addr);
            spin_unlock_irqrestore(&arp_lock, flags);
            return true;
        }
    }

    spin_unlock_irqrestore(&arp_lock, flags);
    return false;
}

/*
 * arp_update - Update or insert an ARP cache entry.
 *
 * @ip:  IPv4 address (network byte order)
 * @mac: MAC address
 */
static void arp_update(uint32_t ip, const uint8_t *mac)
{
    uint64_t flags;
    spin_lock_irqsave(&arp_lock, &flags);

    /* Check for existing entry */
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (arp_cache[i].valid && arp_cache[i].ip_addr == ip) {
            mac_copy(arp_cache[i].mac_addr, mac);
            spin_unlock_irqrestore(&arp_lock, flags);
            return;
        }
    }

    /* Find a free slot */
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (!arp_cache[i].valid) {
            arp_cache[i].ip_addr = ip;
            mac_copy(arp_cache[i].mac_addr, mac);
            arp_cache[i].valid = true;
            spin_unlock_irqrestore(&arp_lock, flags);
            return;
        }
    }

    /* Cache full: overwrite slot 0 (simple eviction) */
    arp_cache[0].ip_addr = ip;
    mac_copy(arp_cache[0].mac_addr, mac);
    arp_cache[0].valid = true;

    spin_unlock_irqrestore(&arp_lock, flags);
}

/* ============================================================================
 * ARP Processing
 * ============================================================================ */

/*
 * arp_send - Send an ARP request or reply.
 *
 * @op:       ARP_OP_REQUEST or ARP_OP_REPLY
 * @dst_mac:  Target MAC (broadcast for requests)
 * @dst_ip:   Target IP (network order)
 */
static void arp_send(uint16_t op, const uint8_t *dst_mac, uint32_t dst_ip)
{
    uint64_t flags;
    spin_lock_irqsave(&eth_tx_lock, &flags);

    /* Build Ethernet + ARP frame */
    struct eth_hdr *eh = (struct eth_hdr *)eth_tx_buf;
    struct arp_hdr *ah = (struct arp_hdr *)(eth_tx_buf + ETH_HDRLEN);

    /* Ethernet header */
    mac_copy(eh->eth_dst, dst_mac);
    mac_copy(eh->eth_src, local_mac);
    eh->eth_type = htons(ETHERTYPE_ARP);

    /* ARP header */
    ah->ar_hrd = htons(ARP_HRD_ETHER);
    ah->ar_pro = htons(ETHERTYPE_IP);
    ah->ar_hln = ETH_ALEN;
    ah->ar_pln = 4;
    ah->ar_op  = htons(op);

    mac_copy(ah->ar_sha, local_mac);
    ah->ar_spa = local_ip;

    /* For ARP requests, target hardware address is unknown (zero).
     * For ARP replies, it's the requestor's MAC. */
    if (op == ARP_OP_REQUEST) {
        static const uint8_t zero_mac[ETH_ALEN] = {0};
        mac_copy(ah->ar_tha, zero_mac);
    } else {
        mac_copy(ah->ar_tha, dst_mac);
    }
    ah->ar_tpa = dst_ip;

    uint32_t frame_len = ETH_HDRLEN + sizeof(struct arp_hdr);

    kprintf("[arp] sending %s to %02x:%02x:%02x:%02x:%02x:%02x\n",
            op == ARP_OP_REQUEST ? "request" : "reply",
            dst_mac[0], dst_mac[1], dst_mac[2],
            dst_mac[3], dst_mac[4], dst_mac[5]);
    int ret = nic_send(eth_tx_buf, frame_len);
    kprintf("[arp] nic_send returned %d\n", ret);

    spin_unlock_irqrestore(&eth_tx_lock, flags);
}

/*
 * arp_input - Process an incoming ARP frame.
 */
static void arp_input(const void *data, uint32_t len)
{
    if (len < sizeof(struct arp_hdr)) {
        kprintf("[arp] frame too short\n");
        return;
    }

    const struct arp_hdr *ah = (const struct arp_hdr *)data;

    /* Only handle Ethernet/IPv4 ARP */
    if (ntohs(ah->ar_hrd) != ARP_HRD_ETHER || ntohs(ah->ar_pro) != ETHERTYPE_IP)
        return;

    /* Update ARP cache with sender's info */
    arp_update(ah->ar_spa, ah->ar_sha);

    /* Drain any packets that were waiting for this ARP resolution */
    arp_drain_pending();

    uint16_t op = ntohs(ah->ar_op);

    if (op == ARP_OP_REQUEST) {
        uint32_t req_ip = ntohl(ah->ar_tpa);
        uint32_t sender_ip = ntohl(ah->ar_spa);
        kprintf("[arp] request: who-has %u.%u.%u.%u tell %u.%u.%u.%u\n",
                (req_ip >> 24) & 0xFF, (req_ip >> 16) & 0xFF,
                (req_ip >> 8) & 0xFF, req_ip & 0xFF,
                (sender_ip >> 24) & 0xFF, (sender_ip >> 16) & 0xFF,
                (sender_ip >> 8) & 0xFF, sender_ip & 0xFF);
        /* Is this request for our IP? */
        if (local_ip != 0 && ah->ar_tpa == local_ip) {
            kprintf("[arp] replying with our MAC\n");
            arp_send(ARP_OP_REPLY, ah->ar_sha, ah->ar_spa);
        }
    }
    /* ARP_OP_REPLY: cache already updated above, nothing else to do */
}

/* ============================================================================
 * Ethernet Input
 *
 * Called by the NIC driver when a frame is received. Strips the Ethernet
 * header and dispatches to the appropriate protocol handler.
 * ============================================================================ */

void eth_input(const void *frame, uint32_t len)
{
    if (len < ETH_HDRLEN) {
        return;
    }

    const struct eth_hdr *eh = (const struct eth_hdr *)frame;
    uint16_t ethertype = ntohs(eh->eth_type);

    /* Check destination: accept our MAC, broadcast, or multicast */
    if (!mac_is_broadcast(eh->eth_dst) &&
        !mac_equal(eh->eth_dst, local_mac)) {
        /* Not for us (promiscuous mode would accept all) */
        return;
    }

    const uint8_t *payload = (const uint8_t *)frame + ETH_HDRLEN;
    uint32_t payload_len = len - ETH_HDRLEN;

    switch (ethertype) {
    case ETHERTYPE_IP:
        ip_input(payload, payload_len);
        break;

    case ETHERTYPE_ARP:
        arp_input(payload, payload_len);
        break;

    default:
        /* Unknown protocol - silently drop */
        break;
    }
}

/* ============================================================================
 * ARP Pending Queue Operations
 * ============================================================================ */

/*
 * arp_enqueue_pending - Queue a packet waiting for ARP resolution.
 *
 * If the queue is full, the oldest entry is overwritten (slot 0).
 */
static void arp_enqueue_pending(uint32_t dst_ip, uint16_t ethertype,
                                const void *data, uint32_t len)
{
    uint64_t flags;
    spin_lock_irqsave(&arp_pending_lock, &flags);

    /* Find a free slot */
    for (int i = 0; i < ARP_PEND_MAX; i++) {
        if (!arp_pending_queue[i].valid) {
            const uint8_t *src = (const uint8_t *)data;
            for (uint32_t j = 0; j < len; j++)
                arp_pending_queue[i].data[j] = src[j];
            arp_pending_queue[i].len = len;
            arp_pending_queue[i].dst_ip = dst_ip;
            arp_pending_queue[i].ethertype = ethertype;
            arp_pending_queue[i].valid = true;
            spin_unlock_irqrestore(&arp_pending_lock, flags);
            return;
        }
    }

    /* Queue full: overwrite slot 0 */
    const uint8_t *src = (const uint8_t *)data;
    for (uint32_t j = 0; j < len; j++)
        arp_pending_queue[0].data[j] = src[j];
    arp_pending_queue[0].len = len;
    arp_pending_queue[0].dst_ip = dst_ip;
    arp_pending_queue[0].ethertype = ethertype;
    arp_pending_queue[0].valid = true;

    spin_unlock_irqrestore(&arp_pending_lock, flags);
}

/*
 * arp_drain_pending - Send any queued packets whose ARP has now resolved.
 *
 * Called after arp_update() adds a new cache entry. For each queued packet
 * whose destination IP is now in the ARP cache, we send it and free the slot.
 *
 * NOTE: This calls eth_output() which may re-enqueue if it still misses,
 * but since we just populated the cache entry that should not happen.
 */
static void arp_drain_pending(void)
{
    uint64_t flags;
    spin_lock_irqsave(&arp_pending_lock, &flags);

    for (int i = 0; i < ARP_PEND_MAX; i++) {
        if (!arp_pending_queue[i].valid)
            continue;

        uint8_t mac[ETH_ALEN];
        if (arp_lookup(arp_pending_queue[i].dst_ip, mac)) {
            /* ARP resolved — build and send the frame now.
             * Take eth_tx_lock to protect the shared TX buffer. */
            uint64_t tx_flags;
            spin_lock_irqsave(&eth_tx_lock, &tx_flags);

            struct eth_hdr *eh = (struct eth_hdr *)eth_tx_buf;
            mac_copy(eh->eth_dst, mac);
            mac_copy(eh->eth_src, local_mac);
            eh->eth_type = htons(arp_pending_queue[i].ethertype);

            uint8_t *dst = eth_tx_buf + ETH_HDRLEN;
            for (uint32_t j = 0; j < arp_pending_queue[i].len; j++)
                dst[j] = arp_pending_queue[i].data[j];

            uint32_t frame_len = ETH_HDRLEN + arp_pending_queue[i].len;
            arp_pending_queue[i].valid = false;

            /* Release pending lock while sending to avoid deadlock */
            spin_unlock_irqrestore(&arp_pending_lock, flags);
            nic_send(eth_tx_buf, frame_len);
            spin_unlock_irqrestore(&eth_tx_lock, tx_flags);
            spin_lock_irqsave(&arp_pending_lock, &flags);
        }
    }

    spin_unlock_irqrestore(&arp_pending_lock, flags);
}

/* ============================================================================
 * Ethernet Output
 *
 * Wrap data in an Ethernet frame and send to the NIC driver.
 * Resolves the destination MAC via ARP cache; if not found, sends
 * an ARP request and queues the packet for transmission when the
 * ARP reply arrives.
 * ============================================================================ */

int eth_output(uint32_t dst_ip, uint16_t ethertype, const void *data,
               uint32_t len)
{
    if (len > ETH_MTU)
        return -EINVAL;

    uint8_t dst_mac[ETH_ALEN];

    /* Broadcast IP -> broadcast MAC */
    if (dst_ip == htonl(INADDR_BROADCAST)) {
        mac_copy(dst_mac, broadcast_mac);
    } else {
        /* Look up destination MAC in ARP cache */
        if (!arp_lookup(dst_ip, dst_mac)) {
            /* Not in cache: queue packet and send ARP request */
            kprintf("[arp] miss for %u.%u.%u.%u, queuing packet\n",
                    (ntohl(dst_ip) >> 24) & 0xFF,
                    (ntohl(dst_ip) >> 16) & 0xFF,
                    (ntohl(dst_ip) >> 8) & 0xFF,
                    ntohl(dst_ip) & 0xFF);
            arp_enqueue_pending(dst_ip, ethertype, data, len);
            arp_send(ARP_OP_REQUEST, broadcast_mac, dst_ip);
            return 0;  /* Queued; will be sent when ARP resolves */
        }
    }

    /* Build Ethernet frame (lock protects shared eth_tx_buf on SMP) */
    uint64_t flags;
    spin_lock_irqsave(&eth_tx_lock, &flags);

    struct eth_hdr *eh = (struct eth_hdr *)eth_tx_buf;
    mac_copy(eh->eth_dst, dst_mac);
    mac_copy(eh->eth_src, local_mac);
    eh->eth_type = htons(ethertype);

    /* Copy payload */
    const uint8_t *src = (const uint8_t *)data;
    uint8_t *dst = eth_tx_buf + ETH_HDRLEN;
    for (uint32_t i = 0; i < len; i++)
        dst[i] = src[i];

    uint32_t frame_len = ETH_HDRLEN + len;

    kprintf("[eth] TX: dst=%02x:%02x:%02x:%02x:%02x:%02x src=%02x:%02x:%02x:%02x:%02x:%02x type=0x%04x len=%u\n",
            eh->eth_dst[0], eh->eth_dst[1], eh->eth_dst[2],
            eh->eth_dst[3], eh->eth_dst[4], eh->eth_dst[5],
            eh->eth_src[0], eh->eth_src[1], eh->eth_src[2],
            eh->eth_src[3], eh->eth_src[4], eh->eth_src[5],
            ntohs(eh->eth_type), frame_len);

    /* Send via NIC driver */
    int ret = nic_send(eth_tx_buf, frame_len);

    spin_unlock_irqrestore(&eth_tx_lock, flags);

    return ret;
}

/* ============================================================================
 * Ethernet Configuration
 * ============================================================================ */

/*
 * eth_set_mac - Set the local MAC address (called by NIC driver).
 */
void eth_set_mac(const uint8_t *mac)
{
    mac_copy(local_mac, mac);
    kprintf("[eth] MAC address set to %02x:%02x:%02x:%02x:%02x:%02x\n",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/*
 * eth_get_mac - Get the local MAC address.
 */
void eth_get_mac(uint8_t *mac)
{
    mac_copy(mac, local_mac);
}

/* Forward: set IP address in the IP layer too */
void ip_set_addr(uint32_t addr);

/*
 * eth_set_ip - Set the local IP address.
 */
void eth_set_ip(uint32_t ip)
{
    local_ip = ip;
    ip_set_addr(ip);
    kprintf("[eth] IP address set to %u.%u.%u.%u\n",
            (ntohl(ip) >> 24) & 0xFF,
            (ntohl(ip) >> 16) & 0xFF,
            (ntohl(ip) >> 8) & 0xFF,
            ntohl(ip) & 0xFF);
}

/*
 * eth_init - Initialize the Ethernet layer.
 */
void eth_init(void)
{
    /* Clear ARP cache */
    for (int i = 0; i < ARP_CACHE_SIZE; i++)
        arp_cache[i].valid = false;

    kprintf("[eth] Ethernet layer initialized\n");
}

/*
 * nic_send - Weak default NIC send function.
 *
 * Overridden by the actual NIC driver (e.g., virtio_net).
 */
__weak int nic_send(const void *frame, uint32_t len)
{
    (void)frame;
    (void)len;
    return -EIO;    /* No NIC driver loaded */
}
