/*
 * Kiseki OS - DHCP Client Implementation
 *
 * Implements a minimal DHCP client (RFC 2131) to obtain IP configuration
 * from a DHCP server (e.g., vmnet's built-in DHCP server).
 *
 * DHCP message flow:
 *   1. DHCPDISCOVER (broadcast) - Client seeks DHCP servers
 *   2. DHCPOFFER    (unicast)   - Server offers IP configuration
 *   3. DHCPREQUEST  (broadcast) - Client requests offered IP
 *   4. DHCPACK      (unicast)   - Server acknowledges
 */

#include <kiseki/types.h>
#include <net/net.h>
#include <kern/kprintf.h>

/* Kernel-space memset */
static void *kmemset(void *s, int c, size_t n)
{
    uint8_t *p = (uint8_t *)s;
    while (n--)
        *p++ = (uint8_t)c;
    return s;
}

#define memset kmemset

/* Forward declarations */
int ip_output(uint32_t src, uint32_t dst, uint8_t proto,
              const void *data, uint32_t len);
void eth_set_ip(uint32_t ip);
void ip_set_netmask(uint32_t mask);
void ip_set_gateway(uint32_t gw);
void eth_get_mac(uint8_t *mac);

/* DHCP ports */
#define DHCP_SERVER_PORT    67
#define DHCP_CLIENT_PORT    68

/* DHCP message types */
#define DHCP_DISCOVER       1
#define DHCP_OFFER          2
#define DHCP_REQUEST        3
#define DHCP_DECLINE        4
#define DHCP_ACK            5
#define DHCP_NAK            6
#define DHCP_RELEASE        7

/* DHCP options */
#define DHCP_OPT_PAD            0
#define DHCP_OPT_SUBNET_MASK    1
#define DHCP_OPT_ROUTER         3
#define DHCP_OPT_DNS            6
#define DHCP_OPT_HOSTNAME       12
#define DHCP_OPT_REQUESTED_IP   50
#define DHCP_OPT_LEASE_TIME     51
#define DHCP_OPT_MSG_TYPE       53
#define DHCP_OPT_SERVER_ID      54
#define DHCP_OPT_PARAM_REQ      55
#define DHCP_OPT_END            255

/* DHCP magic cookie */
#define DHCP_MAGIC_COOKIE       0x63825363

/* DHCP header structure */
struct dhcp_msg {
    uint8_t     op;         /* Message type: 1=BOOTREQUEST, 2=BOOTREPLY */
    uint8_t     htype;      /* Hardware type: 1=Ethernet */
    uint8_t     hlen;       /* Hardware address length: 6 for Ethernet */
    uint8_t     hops;       /* Hops (client sets to 0) */
    uint32_t    xid;        /* Transaction ID */
    uint16_t    secs;       /* Seconds elapsed */
    uint16_t    flags;      /* Flags (0x8000 = broadcast) */
    uint32_t    ciaddr;     /* Client IP (if known) */
    uint32_t    yiaddr;     /* Your (client) IP (from server) */
    uint32_t    siaddr;     /* Server IP */
    uint32_t    giaddr;     /* Gateway/relay IP */
    uint8_t     chaddr[16]; /* Client hardware address */
    uint8_t     sname[64];  /* Server hostname (optional) */
    uint8_t     file[128];  /* Boot filename (optional) */
    uint32_t    magic;      /* Magic cookie: 0x63825363 */
    uint8_t     options[308]; /* DHCP options */
} __packed;

/* UDP header */
struct udp_hdr {
    uint16_t    uh_sport;
    uint16_t    uh_dport;
    uint16_t    uh_len;
    uint16_t    uh_sum;
} __packed;

/* Global DHCP state */
static uint32_t dhcp_xid = 0x12345678;  /* Transaction ID */
static uint32_t dhcp_server_ip = 0;      /* DHCP server that responded */
static uint32_t dhcp_offered_ip = 0;     /* IP address offered */
static uint32_t dhcp_subnet_mask = 0;
static uint32_t dhcp_gateway = 0;
static volatile int dhcp_state = 0;      /* 0=init, 1=discovering, 2=requesting, 3=bound */

/* Received DHCP configuration (populated by dhcp_input) */
static uint32_t g_dhcp_ip = 0;
static uint32_t g_dhcp_mask = 0;
static uint32_t g_dhcp_gateway = 0;
static volatile int g_dhcp_complete = 0;

/*
 * Build and send a DHCP message
 */
static int dhcp_send(int msg_type, uint32_t requested_ip, uint32_t server_id)
{
    uint8_t packet[sizeof(struct udp_hdr) + sizeof(struct dhcp_msg)];
    struct udp_hdr *udp = (struct udp_hdr *)packet;
    struct dhcp_msg *dhcp = (struct dhcp_msg *)(packet + sizeof(struct udp_hdr));
    
    memset(packet, 0, sizeof(packet));
    
    /* Build DHCP message */
    dhcp->op = 1;           /* BOOTREQUEST */
    dhcp->htype = 1;        /* Ethernet */
    dhcp->hlen = 6;         /* MAC address length */
    dhcp->hops = 0;
    dhcp->xid = htonl(dhcp_xid);
    dhcp->secs = 0;
    dhcp->flags = htons(0x8000);  /* Broadcast flag */
    dhcp->ciaddr = 0;       /* We don't have an IP yet */
    dhcp->yiaddr = 0;
    dhcp->siaddr = 0;
    dhcp->giaddr = 0;
    
    /* Copy MAC address */
    eth_get_mac(dhcp->chaddr);
    
    /* Magic cookie */
    dhcp->magic = htonl(DHCP_MAGIC_COOKIE);
    
    /* Build options */
    uint8_t *opt = dhcp->options;
    
    /* Option 53: DHCP Message Type */
    *opt++ = DHCP_OPT_MSG_TYPE;
    *opt++ = 1;
    *opt++ = msg_type;
    
    if (msg_type == DHCP_REQUEST) {
        /* Option 50: Requested IP Address */
        if (requested_ip != 0) {
            *opt++ = DHCP_OPT_REQUESTED_IP;
            *opt++ = 4;
            *opt++ = (requested_ip >> 24) & 0xFF;
            *opt++ = (requested_ip >> 16) & 0xFF;
            *opt++ = (requested_ip >> 8) & 0xFF;
            *opt++ = requested_ip & 0xFF;
        }
        
        /* Option 54: Server Identifier */
        if (server_id != 0) {
            *opt++ = DHCP_OPT_SERVER_ID;
            *opt++ = 4;
            *opt++ = (server_id >> 24) & 0xFF;
            *opt++ = (server_id >> 16) & 0xFF;
            *opt++ = (server_id >> 8) & 0xFF;
            *opt++ = server_id & 0xFF;
        }
    }
    
    /* Option 55: Parameter Request List */
    *opt++ = DHCP_OPT_PARAM_REQ;
    *opt++ = 3;
    *opt++ = DHCP_OPT_SUBNET_MASK;
    *opt++ = DHCP_OPT_ROUTER;
    *opt++ = DHCP_OPT_DNS;
    
    /* End option */
    *opt++ = DHCP_OPT_END;
    
    /* Build UDP header */
    uint16_t udp_len = sizeof(struct udp_hdr) + sizeof(struct dhcp_msg);
    udp->uh_sport = htons(DHCP_CLIENT_PORT);
    udp->uh_dport = htons(DHCP_SERVER_PORT);
    udp->uh_len = htons(udp_len);
    udp->uh_sum = 0;  /* Optional in IPv4 */
    
    /* Send as broadcast (0.0.0.0 -> 255.255.255.255) */
    return ip_output(0, 0xFFFFFFFF, IPPROTO_UDP, packet, udp_len);
}

/*
 * Parse DHCP options from a received message
 */
static void dhcp_parse_options(const uint8_t *options, int len,
                                int *msg_type, uint32_t *server_id,
                                uint32_t *subnet, uint32_t *router)
{
    *msg_type = 0;
    *server_id = 0;
    *subnet = 0;
    *router = 0;
    
    const uint8_t *p = options;
    const uint8_t *end = options + len;
    
    while (p < end) {
        uint8_t opt = *p++;
        
        if (opt == DHCP_OPT_PAD)
            continue;
        if (opt == DHCP_OPT_END)
            break;
        
        if (p >= end)
            break;
        uint8_t opt_len = *p++;
        
        if (p + opt_len > end)
            break;
        
        switch (opt) {
        case DHCP_OPT_MSG_TYPE:
            if (opt_len >= 1)
                *msg_type = p[0];
            break;
        case DHCP_OPT_SERVER_ID:
            if (opt_len >= 4)
                *server_id = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
            break;
        case DHCP_OPT_SUBNET_MASK:
            if (opt_len >= 4)
                *subnet = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
            break;
        case DHCP_OPT_ROUTER:
            if (opt_len >= 4)
                *router = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
            break;
        }
        
        p += opt_len;
    }
}

/*
 * Handle incoming DHCP packet (called from udp_input for port 68)
 */
void dhcp_input(const void *data, uint32_t len)
{
    kprintf("[dhcp] received packet len=%u\n", len);
    
    if (len < sizeof(struct dhcp_msg)) {
        kprintf("[dhcp] packet too small (%u < %u)\n", len, (uint32_t)sizeof(struct dhcp_msg));
        return;
    }
    
    const struct dhcp_msg *dhcp = (const struct dhcp_msg *)data;
    
    kprintf("[dhcp] op=%u xid=0x%x magic=0x%x\n", dhcp->op, ntohl(dhcp->xid), ntohl(dhcp->magic));
    
    /* Verify this is a reply (BOOTREPLY) */
    if (dhcp->op != 2) {
        kprintf("[dhcp] not BOOTREPLY (op=%u)\n", dhcp->op);
        return;
    }
    
    /* Verify transaction ID */
    if (ntohl(dhcp->xid) != dhcp_xid) {
        kprintf("[dhcp] xid mismatch (got 0x%x, expected 0x%x)\n", ntohl(dhcp->xid), dhcp_xid);
        return;
    }
    
    /* Verify magic cookie */
    if (ntohl(dhcp->magic) != DHCP_MAGIC_COOKIE) {
        kprintf("[dhcp] bad magic cookie\n");
        return;
    }
    
    /* Parse options */
    int msg_type;
    uint32_t server_id, subnet, router;
    dhcp_parse_options(dhcp->options, sizeof(dhcp->options),
                       &msg_type, &server_id, &subnet, &router);
    
    uint32_t offered_ip = ntohl(dhcp->yiaddr);
    
    if (msg_type == DHCP_OFFER && dhcp_state == 1) {
        /* Got an offer, send request */
        kprintf("[dhcp] OFFER: %d.%d.%d.%d from server %d.%d.%d.%d\n",
                (offered_ip >> 24) & 0xFF, (offered_ip >> 16) & 0xFF,
                (offered_ip >> 8) & 0xFF, offered_ip & 0xFF,
                (server_id >> 24) & 0xFF, (server_id >> 16) & 0xFF,
                (server_id >> 8) & 0xFF, server_id & 0xFF);
        
        dhcp_offered_ip = offered_ip;
        dhcp_server_ip = server_id;
        dhcp_subnet_mask = subnet;
        dhcp_gateway = router;
        dhcp_state = 2;
        
        /* Send DHCPREQUEST */
        dhcp_send(DHCP_REQUEST, offered_ip, server_id);
        
    } else if (msg_type == DHCP_ACK && dhcp_state == 2) {
        /* Got ACK, we're bound */
        kprintf("[dhcp] ACK: IP %d.%d.%d.%d\n",
                (offered_ip >> 24) & 0xFF, (offered_ip >> 16) & 0xFF,
                (offered_ip >> 8) & 0xFF, offered_ip & 0xFF);
        
        /* Apply configuration */
        g_dhcp_ip = offered_ip;
        g_dhcp_mask = subnet ? subnet : 0xFFFFFF00;  /* Default /24 */
        g_dhcp_gateway = router ? router : 0;
        
        dhcp_state = 3;
        g_dhcp_complete = 1;
        
    } else if (msg_type == DHCP_NAK) {
        kprintf("[dhcp] NAK received, restarting\n");
        dhcp_state = 0;
    }
}

/* Poll for received network packets */
extern void virtio_net_recv(void);

/*
 * Run DHCP client to obtain IP configuration.
 * Returns 0 on success, -1 on timeout/failure.
 */
int dhcp_configure(void)
{
    kprintf("[dhcp] starting DHCP client...\n");
    
    /* Start with no IP */
    eth_set_ip(0);
    
    /* Send DHCPDISCOVER */
    dhcp_state = 1;
    g_dhcp_complete = 0;
    
    if (dhcp_send(DHCP_DISCOVER, 0, 0) < 0) {
        kprintf("[dhcp] failed to send DISCOVER\n");
        return -1;
    }
    
    kprintf("[dhcp] DISCOVER sent, waiting for OFFER...\n");
    
    /* Wait for DHCP to complete, polling for network packets.
     * ~500 iterations * ~10ms = ~5 seconds timeout */
    for (int i = 0; i < 500 && !g_dhcp_complete; i++) {
        /* Poll for incoming packets */
        virtio_net_recv();
        
        /* Small delay between polls (~10ms each iteration) */
        for (volatile int j = 0; j < 50000; j++)
            ;
    }
    
    if (!g_dhcp_complete) {
        kprintf("[dhcp] timeout waiting for response\n");
        return -1;
    }
    
    /* Apply the obtained configuration */
    kprintf("[dhcp] configured: IP %d.%d.%d.%d mask %d.%d.%d.%d gw %d.%d.%d.%d\n",
            (g_dhcp_ip >> 24) & 0xFF, (g_dhcp_ip >> 16) & 0xFF,
            (g_dhcp_ip >> 8) & 0xFF, g_dhcp_ip & 0xFF,
            (g_dhcp_mask >> 24) & 0xFF, (g_dhcp_mask >> 16) & 0xFF,
            (g_dhcp_mask >> 8) & 0xFF, g_dhcp_mask & 0xFF,
            (g_dhcp_gateway >> 24) & 0xFF, (g_dhcp_gateway >> 16) & 0xFF,
            (g_dhcp_gateway >> 8) & 0xFF, g_dhcp_gateway & 0xFF);
    
    eth_set_ip(htonl(g_dhcp_ip));
    ip_set_netmask(htonl(g_dhcp_mask));
    if (g_dhcp_gateway)
        ip_set_gateway(htonl(g_dhcp_gateway));
    
    return 0;
}

/*
 * Get the current DHCP-assigned IP (for ifconfig, etc.)
 * Returns IP in host byte order, or 0 if not configured.
 */
uint32_t dhcp_get_ip(void)
{
    return g_dhcp_ip;
}

uint32_t dhcp_get_netmask(void)
{
    return g_dhcp_mask;
}

uint32_t dhcp_get_gateway(void)
{
    return g_dhcp_gateway;
}
