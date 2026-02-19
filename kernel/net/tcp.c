/*
 * Kiseki OS - TCP Protocol Implementation
 *
 * Simplified TCP state machine implementing RFC 793 core transitions.
 * This is a framework implementation providing correct state management
 * with stub segment processing. Full TCP (windowing, retransmission,
 * congestion control) will be added incrementally.
 *
 * Reference: RFC 793, RFC 1122, Stevens "TCP/IP Illustrated" Vol 2
 */

#include <kiseki/types.h>
#include <net/net.h>
#include <net/tcp.h>
#include <kern/kprintf.h>
#include <kern/sync.h>
#include <fs/vfs.h>

/* Forward declarations for IP layer */
int ip_output(uint32_t src, uint32_t dst, uint8_t proto,
              const void *data, uint32_t len);

/* ============================================================================
 * TCP Control Block Pool
 * ============================================================================ */

static struct tcpcb tcpcb_pool[TCP_MAX_CONNECTIONS];
static spinlock_t tcp_lock = SPINLOCK_INIT;

/* Simple ISS (Initial Sequence Number) counter.
 * In production this should use a secure hash. */
static uint32_t tcp_iss_counter = 1;

/* ============================================================================
 * Initialization
 * ============================================================================ */

void tcp_init(void)
{
    for (int i = 0; i < TCP_MAX_CONNECTIONS; i++) {
        tcpcb_pool[i].t_active = false;
        tcpcb_pool[i].t_state  = TCPS_CLOSED;
    }

    kprintf("[tcp] TCP subsystem initialized (%d connections max)\n",
            TCP_MAX_CONNECTIONS);
}

/* ============================================================================
 * TCB Allocation
 * ============================================================================ */

struct tcpcb *tcp_alloc(void)
{
    uint64_t flags;
    spin_lock_irqsave(&tcp_lock, &flags);

    for (int i = 0; i < TCP_MAX_CONNECTIONS; i++) {
        if (!tcpcb_pool[i].t_active) {
            struct tcpcb *tp = &tcpcb_pool[i];
            tp->t_active    = true;
            tp->t_state     = TCPS_CLOSED;
            tp->snd_una     = 0;
            tp->snd_nxt     = 0;
            tp->snd_wnd     = 0;
            tp->rcv_nxt     = 0;
            tp->rcv_wnd     = SOCKBUF_SIZE;
            tp->iss         = 0;
            tp->irs         = 0;
            tp->local_addr  = 0;
            tp->local_port  = 0;
            tp->remote_addr = 0;
            tp->remote_port = 0;
            tp->t_socket    = NULL;
            tp->t_rxtcur    = 1000;     /* 1 second initial RTO */
            tp->t_rxtshift  = 0;
            spin_init(&tp->t_lock);

            spin_unlock_irqrestore(&tcp_lock, flags);
            return tp;
        }
    }

    spin_unlock_irqrestore(&tcp_lock, flags);
    kprintf("[tcp] connection pool exhausted\n");
    return NULL;
}

void tcp_free(struct tcpcb *tp)
{
    if (tp == NULL)
        return;

    uint64_t flags;
    spin_lock_irqsave(&tcp_lock, &flags);

    tp->t_active = false;
    tp->t_state  = TCPS_CLOSED;
    tp->t_socket = NULL;

    spin_unlock_irqrestore(&tcp_lock, flags);
}

/* ============================================================================
 * ISS Generation
 * ============================================================================ */

static uint32_t tcp_new_iss(void)
{
    /* Simple incrementing ISS. A real implementation should use
     * RFC 6528 (SipHash-based ISN generation) for security. */
    tcp_iss_counter += 64000;
    return tcp_iss_counter;
}

/* ============================================================================
 * TCP Connection Management
 * ============================================================================ */

/*
 * tcp_connect - Active open: send SYN, transition to SYN_SENT
 */
int tcp_connect(struct socket *so)
{
    if (so == NULL)
        return -EINVAL;

    struct tcpcb *tp = tcp_alloc();
    if (tp == NULL)
        return -ENOMEM;

    /* Link socket and TCB */
    tp->t_socket    = so;
    so->so_pcb      = tp;

    /* Copy endpoint information from socket */
    tp->local_addr  = so->so_local.sin_addr.s_addr;
    tp->local_port  = so->so_local.sin_port;
    tp->remote_addr = so->so_remote.sin_addr.s_addr;
    tp->remote_port = so->so_remote.sin_port;

    /* Generate initial sequence number */
    tp->iss     = tcp_new_iss();
    tp->snd_una = tp->iss;
    tp->snd_nxt = tp->iss + 1;     /* SYN consumes one sequence number */
    tp->snd_wnd = 0;               /* Unknown until SYN-ACK received */
    tp->rcv_wnd = SOCKBUF_SIZE;

    /* Transition to SYN_SENT */
    tp->t_state = TCPS_SYN_SENT;

    kprintf("[tcp] connect: sending SYN (iss=%u)\n", tp->iss);

    /* Send SYN segment */
    int ret = tcp_output(tp);
    if (ret < 0) {
        tcp_free(tp);
        so->so_pcb = NULL;
        return ret;
    }

    return 0;
}

/*
 * tcp_close - Initiate connection teardown
 */
int tcp_close(struct tcpcb *tp)
{
    if (tp == NULL)
        return -EINVAL;

    uint64_t flags;
    spin_lock_irqsave(&tp->t_lock, &flags);

    switch (tp->t_state) {
    case TCPS_CLOSED:
    case TCPS_LISTEN:
        /* No connection to close */
        tp->t_state = TCPS_CLOSED;
        spin_unlock_irqrestore(&tp->t_lock, flags);
        tcp_free(tp);
        return 0;

    case TCPS_SYN_SENT:
    case TCPS_SYN_RCVD:
        /* Abort: send RST */
        tp->t_state = TCPS_CLOSED;
        spin_unlock_irqrestore(&tp->t_lock, flags);
        kprintf("[tcp] close: RST (state was SYN)\n");
        tcp_free(tp);
        return 0;

    case TCPS_ESTABLISHED:
        /* Active close: send FIN */
        tp->t_state = TCPS_FIN_WAIT_1;
        spin_unlock_irqrestore(&tp->t_lock, flags);
        kprintf("[tcp] close: sending FIN (ESTABLISHED -> FIN_WAIT_1)\n");
        tcp_output(tp);
        return 0;

    case TCPS_CLOSE_WAIT:
        /* Remote already closed: send our FIN */
        tp->t_state = TCPS_LAST_ACK;
        spin_unlock_irqrestore(&tp->t_lock, flags);
        kprintf("[tcp] close: sending FIN (CLOSE_WAIT -> LAST_ACK)\n");
        tcp_output(tp);
        return 0;

    default:
        /* Already closing */
        spin_unlock_irqrestore(&tp->t_lock, flags);
        return 0;
    }
}

/* ============================================================================
 * TCP Pseudo-Header Checksum (RFC 793)
 *
 * The TCP checksum covers a pseudo-header (src IP, dst IP, zero, protocol,
 * TCP length) plus the TCP header and data.
 * ============================================================================ */

struct tcp_pseudo_hdr {
    uint32_t    src_addr;
    uint32_t    dst_addr;
    uint8_t     zero;
    uint8_t     protocol;
    uint16_t    tcp_len;
} __packed;

static uint16_t tcp_checksum(uint32_t src_ip, uint32_t dst_ip,
                              const void *tcp_seg, uint32_t tcp_len)
{
    struct tcp_pseudo_hdr pseudo;
    pseudo.src_addr = src_ip;
    pseudo.dst_addr = dst_ip;
    pseudo.zero     = 0;
    pseudo.protocol = IPPROTO_TCP;
    pseudo.tcp_len  = htons((uint16_t)tcp_len);

    /* Sum the pseudo-header */
    const uint16_t *ptr = (const uint16_t *)&pseudo;
    uint32_t sum = 0;
    for (uint32_t i = 0; i < sizeof(pseudo) / 2; i++)
        sum += ptr[i];

    /* Sum the TCP segment (header + data) */
    ptr = (const uint16_t *)tcp_seg;
    uint32_t remaining = tcp_len;
    while (remaining > 1) {
        sum += *ptr++;
        remaining -= 2;
    }
    if (remaining == 1)
        sum += *(const uint8_t *)ptr;

    /* Fold and complement */
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)(~sum);
}

/* ============================================================================
 * TCP Output
 *
 * Construct a TCP segment from the current connection state and send it
 * via the IP layer. The segment type depends on the TCP state:
 *   - SYN_SENT:    send SYN
 *   - ESTABLISHED: send data + ACK (includes payload from send buffer)
 *   - FIN_WAIT_1:  send FIN + ACK
 *   - LAST_ACK:    send FIN + ACK
 *   - etc.
 * ============================================================================ */

/* Maximum TCP segment buffer (header + data) */
#define TCP_MAX_SEGMENT 1460

int tcp_output(struct tcpcb *tp)
{
    if (tp == NULL)
        return -EINVAL;

    /* Buffer for TCP header + payload */
    uint8_t seg_buf[sizeof(struct tcp_hdr) + TCP_MAX_SEGMENT];
    struct tcp_hdr *hdr = (struct tcp_hdr *)seg_buf;
    uint32_t data_len = 0;

    hdr->th_sport    = tp->local_port;
    hdr->th_dport    = tp->remote_port;
    hdr->th_seq      = htonl(tp->snd_nxt);     /* Default: next send seq */
    hdr->th_ack      = htonl(tp->rcv_nxt);
    hdr->th_off_rsvd = (5 << 4);    /* 20-byte header, no options */
    hdr->th_flags    = 0;
    hdr->th_win      = htons((uint16_t)tp->rcv_wnd);
    hdr->th_sum      = 0;
    hdr->th_urp      = 0;

    /* Set flags and prepare data based on state */
    switch (tp->t_state) {
    case TCPS_SYN_SENT:
        /* SYN occupies seq = iss; snd_nxt = iss + 1.
         * Include MSS option (kind=2, len=4, mss=1460). */
        hdr->th_flags = TH_SYN;
        hdr->th_seq   = htonl(tp->iss);
        {
            uint8_t *opts = seg_buf + sizeof(struct tcp_hdr);
            opts[0] = 2;                 /* MSS option kind */
            opts[1] = 4;                 /* MSS option length */
            opts[2] = (1460 >> 8) & 0xFF; /* MSS value high byte */
            opts[3] = 1460 & 0xFF;       /* MSS value low byte */
            data_len = 4;                /* 4 bytes of options */
            hdr->th_off_rsvd = (6 << 4); /* 24-byte header (20 + 4 opts) */
        }
        break;

    case TCPS_SYN_RCVD:
        /* SYN-ACK: seq = iss, include MSS option */
        hdr->th_flags = TH_SYN | TH_ACK;
        hdr->th_seq   = htonl(tp->iss);
        {
            uint8_t *opts = seg_buf + sizeof(struct tcp_hdr);
            opts[0] = 2;
            opts[1] = 4;
            opts[2] = (1460 >> 8) & 0xFF;
            opts[3] = 1460 & 0xFF;
            data_len = 4;
            hdr->th_off_rsvd = (6 << 4);
        }
        break;

    case TCPS_ESTABLISHED:
        hdr->th_flags = TH_ACK;
        /* Pull data from the socket's send buffer */
        if (tp->t_socket != NULL) {
            struct sockbuf *snd = &tp->t_socket->so_snd;
            uint64_t snd_flags;
            spin_lock_irqsave(&snd->sb_lock, &snd_flags);
            uint32_t avail = snd->sb_len;
            if (avail > TCP_MAX_SEGMENT)
                avail = TCP_MAX_SEGMENT;
            uint8_t *dst = seg_buf + sizeof(struct tcp_hdr);
            for (uint32_t i = 0; i < avail; i++) {
                dst[i] = snd->sb_buf[snd->sb_head];
                snd->sb_head = (snd->sb_head + 1) % SOCKBUF_SIZE;
                snd->sb_len--;
            }
            spin_unlock_irqrestore(&snd->sb_lock, snd_flags);
            data_len = avail;
            if (data_len > 0) {
                hdr->th_flags |= TH_PUSH;
                /* seq = snd_nxt (already set above), advance */
                tp->snd_nxt += data_len;
            }
        }
        break;

    case TCPS_FIN_WAIT_1:
    case TCPS_LAST_ACK:
        /* FIN occupies one sequence number at snd_nxt */
        hdr->th_flags = TH_FIN | TH_ACK;
        break;

    case TCPS_CLOSING:
        hdr->th_flags = TH_ACK;
        break;

    default:
        /* No segment to send in other states */
        return 0;
    }

    /* Compute TCP checksum over pseudo-header + header + data.
     * If local_addr is INADDR_ANY (0), use the actual local IP address
     * that ip_output will fill in, to avoid checksum mismatch. */
    uint32_t seg_len = sizeof(struct tcp_hdr) + data_len;
    uint32_t src_ip = tp->local_addr;
    uint32_t dst_ip = tp->remote_addr;

    if (src_ip == 0) {
        extern uint32_t ip_get_addr(void);
        src_ip = ip_get_addr();
    }

    hdr->th_sum = 0;
    hdr->th_sum = tcp_checksum(src_ip, dst_ip, seg_buf, seg_len);

    kprintf("[tcp-out] flags=0x%x seq=%u ack=%u src=%u.%u.%u.%u:%u -> %u.%u.%u.%u:%u len=%u\n",
            hdr->th_flags, ntohl(hdr->th_seq), ntohl(hdr->th_ack),
            (ntohl(src_ip) >> 24) & 0xFF, (ntohl(src_ip) >> 16) & 0xFF,
            (ntohl(src_ip) >> 8) & 0xFF, ntohl(src_ip) & 0xFF,
            ntohs(hdr->th_sport),
            (ntohl(dst_ip) >> 24) & 0xFF, (ntohl(dst_ip) >> 16) & 0xFF,
            (ntohl(dst_ip) >> 8) & 0xFF, ntohl(dst_ip) & 0xFF,
            ntohs(hdr->th_dport), seg_len);

    /* Send via IP layer */
    int ret = ip_output(src_ip, dst_ip, IPPROTO_TCP, seg_buf, seg_len);

    return ret;
}

/* ============================================================================
 * Socket Buffer Helper (TCP-internal)
 *
 * Write data into a socket receive buffer. Duplicate of the sockbuf_write
 * in socket.c, kept here to avoid cross-module static function calls.
 * ============================================================================ */

static uint32_t sockbuf_write_tcp(struct sockbuf *sb,
                                   const uint8_t *data,
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

/* ============================================================================
 * TCP Input
 *
 * Process an incoming TCP segment. Demultiplex to the correct connection
 * and run the state machine.
 * ============================================================================ */

/*
 * tcp_find_tcb - Find a TCB matching the given 4-tuple.
 */
static struct tcpcb *tcp_find_tcb(uint32_t src_addr, uint16_t src_port,
                                   uint32_t dst_addr, uint16_t dst_port)
{
    for (int i = 0; i < TCP_MAX_CONNECTIONS; i++) {
        struct tcpcb *tp = &tcpcb_pool[i];
        if (!tp->t_active)
            continue;

        /* Match on 4-tuple (local_addr == 0 matches any local address) */
        if ((tp->local_addr == dst_addr || tp->local_addr == 0) &&
            tp->local_port == dst_port &&
            tp->remote_addr == src_addr && tp->remote_port == src_port)
            return tp;
    }

    /* Check for listening sockets (wildcard remote) */
    for (int i = 0; i < TCP_MAX_CONNECTIONS; i++) {
        struct tcpcb *tp = &tcpcb_pool[i];
        if (!tp->t_active)
            continue;

        if (tp->t_state == TCPS_LISTEN &&
            tp->local_port == dst_port &&
            (tp->local_addr == 0 || tp->local_addr == dst_addr))
            return tp;
    }

    return NULL;
}

/* External declarations for passive open (used by TCPS_LISTEN handler) */
extern struct socket socket_table[];
extern int tcp_accept_alloc(int listener_idx, uint32_t remote_addr,
                            uint16_t remote_port);

void tcp_input(uint32_t src_addr, uint32_t dst_addr,
               const void *data, uint32_t len)
{
    if (len < sizeof(struct tcp_hdr)) {
        kprintf("[tcp] segment too short (%u bytes)\n", len);
        return;
    }

    const struct tcp_hdr *th = (const struct tcp_hdr *)data;

    kprintf("[tcp-in] %u.%u.%u.%u:%u -> :%u flags=0x%x seq=%u ack=%u len=%u\n",
            (ntohl(src_addr) >> 24) & 0xFF,
            (ntohl(src_addr) >> 16) & 0xFF,
            (ntohl(src_addr) >> 8) & 0xFF,
            ntohl(src_addr) & 0xFF,
            ntohs(th->th_sport), ntohs(th->th_dport),
            th->th_flags, ntohl(th->th_seq), ntohl(th->th_ack), len);

    /* Find matching connection */
    struct tcpcb *tp = tcp_find_tcb(src_addr, th->th_sport,
                                     dst_addr, th->th_dport);
    if (tp == NULL) {
        /* No matching connection — send RST to reject */
        if (!(th->th_flags & TH_RST)) {
            /* Build a RST response */
            struct tcp_hdr rst;
            for (uint64_t zi = 0; zi < sizeof(rst); zi++)
                ((uint8_t *)&rst)[zi] = 0;

            rst.th_sport    = th->th_dport;
            rst.th_dport    = th->th_sport;
            rst.th_off_rsvd = (5 << 4);
            rst.th_flags    = TH_RST;
            rst.th_win      = 0;

            if (th->th_flags & TH_ACK) {
                /* If incoming had ACK, use their ack as our seq */
                rst.th_seq = th->th_ack;
                rst.th_ack = 0;
            } else {
                /* No ACK — set RST|ACK, seq=0, ack=their_seq+data_len */
                uint32_t payload_len = len - (uint32_t)((th->th_off_rsvd >> 4) * 4);
                rst.th_flags |= TH_ACK;
                rst.th_seq = 0;
                rst.th_ack = htonl(ntohl(th->th_seq) + payload_len +
                             ((th->th_flags & TH_SYN) ? 1 : 0) +
                             ((th->th_flags & TH_FIN) ? 1 : 0));
            }

            /* Checksum */
            rst.th_sum = tcp_checksum(dst_addr, src_addr,
                                      &rst, sizeof(rst));

            ip_output(dst_addr, src_addr, IPPROTO_TCP,
                      &rst, sizeof(rst));
        }
        return;
    }

    uint32_t seg_seq = ntohl(th->th_seq);
    uint32_t seg_ack = ntohl(th->th_ack);
    uint8_t seg_flags = th->th_flags;

    uint64_t irq_flags;
    spin_lock_irqsave(&tp->t_lock, &irq_flags);

    /* TCP state machine */
    switch (tp->t_state) {
    case TCPS_LISTEN: {
        /* ================================================================
         * Passive Open: SYN arrives on a listening socket.
         *
         * Per RFC 793 Section 3.4:
         * 1. If RST, discard and return.
         * 2. If ACK, send RST (bad segment for LISTEN state).
         * 3. If SYN, allocate a new child socket + TCB, record IRS,
         *    generate ISS, send SYN-ACK, transition child to SYN_RCVD.
         *
         * The listening TCB stays in TCPS_LISTEN to accept more connections.
         * ================================================================ */

        /* RST in LISTEN state — ignore (RFC 793) */
        if (seg_flags & TH_RST) {
            spin_unlock_irqrestore(&tp->t_lock, irq_flags);
            return;
        }

        /* ACK in LISTEN state — invalid, send RST */
        if (seg_flags & TH_ACK) {
            spin_unlock_irqrestore(&tp->t_lock, irq_flags);
            /* Send RST: seq = seg_ack */
            struct tcp_hdr rst;
            for (uint64_t zi = 0; zi < sizeof(rst); zi++)
                ((uint8_t *)&rst)[zi] = 0;
            rst.th_sport    = th->th_dport;
            rst.th_dport    = th->th_sport;
            rst.th_off_rsvd = (5 << 4);
            rst.th_flags    = TH_RST;
            rst.th_seq      = th->th_ack;
            rst.th_win      = 0;
            rst.th_sum      = tcp_checksum(dst_addr, src_addr,
                                           &rst, sizeof(rst));
            ip_output(dst_addr, src_addr, IPPROTO_TCP,
                      &rst, sizeof(rst));
            return;
        }

        /* Must have SYN to proceed */
        if (!(seg_flags & TH_SYN)) {
            spin_unlock_irqrestore(&tp->t_lock, irq_flags);
            return;
        }

        /* --- SYN received on listening socket --- */

        /* Find the listener's socket index in the socket table */
        struct socket *listen_so = tp->t_socket;
        int listener_idx = -1;
        for (int si = 0; si < NET_MAX_SOCKETS; si++) {
            if (&socket_table[si] == listen_so) {
                listener_idx = si;
                break;
            }
        }

        if (listener_idx < 0) {
            kprintf("[tcp] LISTEN: cannot find listener socket index\n");
            spin_unlock_irqrestore(&tp->t_lock, irq_flags);
            return;
        }

        /* Allocate child socket (also checks backlog) */
        int child_idx = tcp_accept_alloc(listener_idx,
                                          src_addr, th->th_sport);
        if (child_idx < 0) {
            kprintf("[tcp] LISTEN: child socket alloc failed (%d)\n",
                    child_idx);
            spin_unlock_irqrestore(&tp->t_lock, irq_flags);
            return;
        }

        /* Allocate a new TCB for the child connection */
        struct tcpcb *child_tp = tcp_alloc();
        if (child_tp == NULL) {
            kprintf("[tcp] LISTEN: TCB alloc failed\n");
            /* Free the child socket */
            socket_table[child_idx].so_active = false;
            spin_unlock_irqrestore(&tp->t_lock, irq_flags);
            return;
        }

        /* Set up the child TCB */
        struct socket *child_so = &socket_table[child_idx];

        child_tp->t_socket    = child_so;
        child_so->so_pcb      = child_tp;

        /* Endpoints */
        child_tp->local_addr  = dst_addr;
        child_tp->local_port  = th->th_dport;
        child_tp->remote_addr = src_addr;
        child_tp->remote_port = th->th_sport;

        /* Record IRS from the SYN */
        child_tp->irs     = seg_seq;
        child_tp->rcv_nxt = seg_seq + 1;  /* SYN consumes one seq */
        child_tp->rcv_wnd = SOCKBUF_SIZE;

        /* Generate ISS for the child */
        child_tp->iss     = tcp_new_iss();
        child_tp->snd_una = child_tp->iss;
        child_tp->snd_nxt = child_tp->iss + 1;  /* SYN-ACK consumes one seq */
        child_tp->snd_wnd = ntohs(th->th_win);

        /* Transition child to SYN_RCVD */
        child_tp->t_state = TCPS_SYN_RCVD;

        kprintf("[tcp] LISTEN: SYN from %u.%u.%u.%u:%u -> child socket %d, "
                "irs=%u iss=%u\n",
                (ntohl(src_addr) >> 24) & 0xFF,
                (ntohl(src_addr) >> 16) & 0xFF,
                (ntohl(src_addr) >> 8) & 0xFF,
                ntohl(src_addr) & 0xFF,
                ntohs(th->th_sport), child_idx,
                child_tp->irs, child_tp->iss);

        /* Listener stays in LISTEN — unlock listener's TCB lock */
        spin_unlock_irqrestore(&tp->t_lock, irq_flags);

        /* Send SYN-ACK from the child TCB */
        tcp_output(child_tp);
        return;
    }

    case TCPS_SYN_SENT:
        /* Handle RST (connection refused) */
        if (seg_flags & TH_RST) {
            tp->t_state = TCPS_CLOSED;
            kprintf("[tcp] connection refused (RST received in SYN_SENT)\n");
            spin_unlock_irqrestore(&tp->t_lock, irq_flags);
            return;
        }
        /* Expecting SYN-ACK */
        if ((seg_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
            tp->irs     = seg_seq;
            tp->rcv_nxt = seg_seq + 1;
            tp->snd_una = seg_ack;
            tp->snd_wnd = ntohs(th->th_win);
            tp->t_state = TCPS_ESTABLISHED;
            kprintf("[tcp] connection established (SYN_SENT -> ESTABLISHED)\n");
            /* Send ACK */
            spin_unlock_irqrestore(&tp->t_lock, irq_flags);
            tcp_output(tp);
            return;
        }
        break;

    case TCPS_SYN_RCVD:
        /* Handle RST — abort the connection */
        if (seg_flags & TH_RST) {
            tp->t_state = TCPS_CLOSED;
            if (tp->t_socket)
                tp->t_socket->so_state = SS_DISCONNECTED;
            kprintf("[tcp] SYN_RCVD: RST received, aborting\n");
            spin_unlock_irqrestore(&tp->t_lock, irq_flags);
            tcp_free(tp);
            return;
        }
        /* SYN retransmit — peer didn't get our SYN-ACK, resend it */
        if ((seg_flags & TH_SYN) && !(seg_flags & TH_ACK)) {
            kprintf("[tcp] SYN_RCVD: SYN retransmit, resending SYN-ACK\n");
            spin_unlock_irqrestore(&tp->t_lock, irq_flags);
            tcp_output(tp);
            return;
        }
        /* Expecting ACK of our SYN-ACK */
        if (seg_flags & TH_ACK) {
            tp->snd_una = seg_ack;
            tp->t_state = TCPS_ESTABLISHED;
            /* Mark the socket as connected — this is what net_accept() polls for */
            if (tp->t_socket)
                tp->t_socket->so_state = SS_CONNECTED;
            kprintf("[tcp] connection established (SYN_RCVD -> ESTABLISHED)\n");
        }
        break;

    case TCPS_ESTABLISHED:
        /* Handle RST (connection reset) */
        if (seg_flags & TH_RST) {
            tp->t_state = TCPS_CLOSED;
            kprintf("[tcp] connection reset by peer\n");
            if (tp->t_socket)
                tp->t_socket->so_state = SS_DISCONNECTED;
            spin_unlock_irqrestore(&tp->t_lock, irq_flags);
            return;
        }

        /* Process ACK */
        if (seg_flags & TH_ACK) {
            if (seg_ack > tp->snd_una)
                tp->snd_una = seg_ack;
        }

        /* Process incoming data */
        {
            uint32_t data_off = TCP_HDRLEN(th);
            uint32_t data_len = (len > data_off) ? (len - data_off) : 0;

            if (data_len > 0) {
                const uint8_t *payload = (const uint8_t *)data + data_off;

                /* Deliver to socket receive buffer */
                if (tp->t_socket != NULL) {
                    struct sockbuf *rcv = &tp->t_socket->so_rcv;
                    sockbuf_write_tcp(rcv, payload, data_len);
                }

                tp->rcv_nxt = seg_seq + data_len;
            }

            /* Process FIN (may arrive with data in the same segment) */
            if (seg_flags & TH_FIN) {
                tp->rcv_nxt += 1; /* FIN consumes one sequence number */
                tp->t_state = TCPS_CLOSE_WAIT;
                if (tp->t_socket)
                    tp->t_socket->so_state = SS_DISCONNECTED;
                kprintf("[tcp] received FIN (ESTABLISHED -> CLOSE_WAIT)\n");
            }

            /* Send ACK if we received data or FIN */
            if (data_len > 0 || (seg_flags & TH_FIN)) {
                spin_unlock_irqrestore(&tp->t_lock, irq_flags);
                tcp_output(tp);
                return;
            }
        }
        break;

    case TCPS_FIN_WAIT_1:
        if (seg_flags & TH_ACK) {
            tp->snd_una = seg_ack;
            if (seg_flags & TH_FIN) {
                /* Simultaneous close */
                tp->rcv_nxt = seg_seq + 1;
                tp->t_state = TCPS_TIME_WAIT;
                kprintf("[tcp] FIN_WAIT_1 -> TIME_WAIT (simultaneous close)\n");
            } else {
                tp->t_state = TCPS_FIN_WAIT_2;
                kprintf("[tcp] FIN_WAIT_1 -> FIN_WAIT_2\n");
            }
        }
        break;

    case TCPS_FIN_WAIT_2:
        if (seg_flags & TH_FIN) {
            tp->rcv_nxt = seg_seq + 1;
            tp->t_state = TCPS_TIME_WAIT;
            kprintf("[tcp] FIN_WAIT_2 -> TIME_WAIT\n");
            /* Send ACK */
            spin_unlock_irqrestore(&tp->t_lock, irq_flags);
            tcp_output(tp);
            return;
        }
        break;

    case TCPS_LAST_ACK:
        if (seg_flags & TH_ACK) {
            tp->t_state = TCPS_CLOSED;
            kprintf("[tcp] LAST_ACK -> CLOSED\n");
            spin_unlock_irqrestore(&tp->t_lock, irq_flags);
            tcp_free(tp);
            return;
        }
        break;

    case TCPS_TIME_WAIT:
        /* In TIME_WAIT, ACK any segments and wait for timeout.
         * Simplified: immediately transition to CLOSED. */
        tp->t_state = TCPS_CLOSED;
        spin_unlock_irqrestore(&tp->t_lock, irq_flags);
        tcp_free(tp);
        return;

    default:
        break;
    }

    spin_unlock_irqrestore(&tp->t_lock, irq_flags);
}
