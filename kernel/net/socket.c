/*
 * Kiseki OS - BSD Socket Implementation
 *
 * Manages the kernel socket table and implements the BSD socket API.
 * Sockets are allocated from a fixed pool and can be mapped to file
 * descriptors (in the BSD tradition, sockets are vnodes).
 *
 * Currently implements the framework; protocol-specific operations
 * are delegated to TCP (tcp.c) and UDP (future).
 *
 * Reference: XNU bsd/kern/uipc_socket.c, Stevens UNIX Vol 1
 */

#include <kiseki/types.h>
#include <net/net.h>
#include <net/tcp.h>
#include <kern/kprintf.h>
#include <kern/sync.h>
#include <fs/vfs.h>

/* ============================================================================
 * Socket Table
 * ============================================================================ */

struct socket socket_table[NET_MAX_SOCKETS];
static spinlock_t socket_table_lock = SPINLOCK_INIT;

/* ============================================================================
 * Socket Buffer Helpers
 * ============================================================================ */

static void sockbuf_init(struct sockbuf *sb)
{
    sb->sb_head = 0;
    sb->sb_tail = 0;
    sb->sb_len  = 0;
    spin_init(&sb->sb_lock);
}

static uint32_t sockbuf_write(struct sockbuf *sb, const void *data, uint32_t len)
{
    const uint8_t *src = (const uint8_t *)data;
    uint32_t written = 0;
    uint64_t flags;

    spin_lock_irqsave(&sb->sb_lock, &flags);

    while (written < len && sb->sb_len < SOCKBUF_SIZE) {
        sb->sb_buf[sb->sb_tail] = src[written];
        sb->sb_tail = (sb->sb_tail + 1) % SOCKBUF_SIZE;
        sb->sb_len++;
        written++;
    }

    spin_unlock_irqrestore(&sb->sb_lock, flags);
    return written;
}

static uint32_t sockbuf_read(struct sockbuf *sb, void *data, uint32_t len)
{
    uint8_t *dst = (uint8_t *)data;
    uint32_t read_count = 0;
    uint64_t flags;

    spin_lock_irqsave(&sb->sb_lock, &flags);

    while (read_count < len && sb->sb_len > 0) {
        dst[read_count] = sb->sb_buf[sb->sb_head];
        sb->sb_head = (sb->sb_head + 1) % SOCKBUF_SIZE;
        sb->sb_len--;
        read_count++;
    }

    spin_unlock_irqrestore(&sb->sb_lock, flags);
    return read_count;
}

/* ============================================================================
 * Socket Allocation
 * ============================================================================ */

/*
 * socket_alloc - Allocate a socket from the pool.
 *
 * Returns socket index (>= 0) or -1 if pool is exhausted.
 */
static int socket_alloc(void)
{
    uint64_t flags;
    spin_lock_irqsave(&socket_table_lock, &flags);

    for (int i = 0; i < NET_MAX_SOCKETS; i++) {
        if (!socket_table[i].so_active) {
            /* Zero initialize */
            struct socket *so = &socket_table[i];
            so->so_type     = 0;
            so->so_protocol = 0;
            so->so_family   = 0;
            so->so_state    = SS_UNCONNECTED;
            so->so_error    = 0;
            so->so_active   = true;
            so->so_pcb      = NULL;
            so->so_qlimit   = 0;
            so->so_qlen     = 0;
            so->so_listener = -1;
            so->so_accepted = false;
            spin_init(&so->so_lock);
            sockbuf_init(&so->so_snd);
            sockbuf_init(&so->so_rcv);

            spin_unlock_irqrestore(&socket_table_lock, flags);
            return i;
        }
    }

    spin_unlock_irqrestore(&socket_table_lock, flags);
    return -1;
}

/*
 * socket_get - Get socket pointer by descriptor, with validation.
 */
static struct socket *socket_get(int sockfd)
{
    if (sockfd < 0 || sockfd >= NET_MAX_SOCKETS)
        return NULL;

    struct socket *so = &socket_table[sockfd];
    if (!so->so_active)
        return NULL;

    return so;
}

/* ============================================================================
 * Child Socket Allocation (for TCP passive open)
 *
 * Called from tcp_input() when a SYN arrives on a LISTEN TCB.
 * Allocates a new socket pre-linked to the listener.
 * ============================================================================ */

int tcp_accept_alloc(int listener_idx, uint32_t remote_addr,
                     uint16_t remote_port)
{
    struct socket *listener = socket_get(listener_idx);
    if (listener == NULL)
        return -EBADF;

    /* Check backlog */
    if (listener->so_qlen >= listener->so_qlimit) {
        kprintf("[net] accept backlog full (qlen=%d qlimit=%d)\n",
                listener->so_qlen, listener->so_qlimit);
        return -ECONNREFUSED;
    }

    /* Allocate a new socket slot */
    int child_idx = socket_alloc();
    if (child_idx < 0)
        return -ENFILE;

    struct socket *child = &socket_table[child_idx];
    child->so_family   = listener->so_family;
    child->so_type     = listener->so_type;
    child->so_protocol = listener->so_protocol;
    child->so_state    = SS_CONNECTING;  /* Will become SS_CONNECTED after handshake */

    /* Copy local endpoint from listener */
    child->so_local = listener->so_local;

    /* Set remote endpoint */
    child->so_remote.sin_family      = AF_INET;
    child->so_remote.sin_port        = remote_port;
    child->so_remote.sin_addr.s_addr = remote_addr;

    /* Link to parent */
    child->so_listener = listener_idx;
    child->so_accepted = false;

    /* Increment listener's pending count */
    uint64_t flags;
    spin_lock_irqsave(&listener->so_lock, &flags);
    listener->so_qlen++;
    spin_unlock_irqrestore(&listener->so_lock, flags);

    return child_idx;
}

/* ============================================================================
 * Network Subsystem Initialization
 * ============================================================================ */

/* External initialization functions */
void eth_init(void);
int  virtio_net_init(void);
void eth_set_ip(uint32_t ip);
void ip_set_gateway(uint32_t gw);
void ip_set_netmask(uint32_t mask);
int  dhcp_configure(void);

void net_init(void)
{
    /* Clear socket table */
    for (int i = 0; i < NET_MAX_SOCKETS; i++) {
        socket_table[i].so_active = false;
    }

    /* Initialize TCP subsystem */
    tcp_init();

    /* Initialize Ethernet layer (ARP cache, etc.) */
    eth_init();

    /* Probe and initialize VirtIO-net device */
    if (virtio_net_init() == 0) {
        /* Try DHCP first, fall back to static IP if it fails */
        if (dhcp_configure() != 0) {
            kprintf("[net] DHCP failed, using static IP configuration\n");
            /* Fallback: vmnet-shared subnet 192.168.64.0/24, gateway 192.168.64.1 */
            eth_set_ip(htonl(0xC0A8400AU));      /* 192.168.64.10 */
            ip_set_netmask(htonl(0xFFFFFF00U));   /* 255.255.255.0 */
            ip_set_gateway(htonl(0xC0A84001U));   /* 192.168.64.1 */
        }
    }

    kprintf("[net] networking subsystem initialized (%d sockets)\n",
            NET_MAX_SOCKETS);
}

/* ============================================================================
 * Socket API Implementation
 * ============================================================================ */

int net_socket(int domain, int type, int protocol)
{
    /* Validate domain */
    if (domain != AF_INET) {
        kprintf("[net] unsupported address family %d\n", domain);
        return -EINVAL;
    }

    /* Validate type and infer default protocol */
    if (type == SOCK_STREAM) {
        if (protocol == 0)
            protocol = IPPROTO_TCP;
        if (protocol != IPPROTO_TCP)
            return -EINVAL;
    } else if (type == SOCK_DGRAM) {
        if (protocol == 0)
            protocol = IPPROTO_UDP;
        if (protocol != IPPROTO_UDP && protocol != IPPROTO_ICMP)
            return -EINVAL;
    } else {
        kprintf("[net] unsupported socket type %d\n", type);
        return -EINVAL;
    }

    /* Allocate socket */
    int fd = socket_alloc();
    if (fd < 0)
        return -ENFILE;

    struct socket *so = &socket_table[fd];
    so->so_family   = domain;
    so->so_type     = type;
    so->so_protocol = protocol;

    return fd;
}

int net_bind(int sockfd, const struct sockaddr_in *addr)
{
    struct socket *so = socket_get(sockfd);
    if (so == NULL)
        return -EBADF;

    if (addr == NULL)
        return -EINVAL;

    if (so->so_state != SS_UNCONNECTED)
        return -EINVAL;

    uint64_t flags;
    spin_lock_irqsave(&so->so_lock, &flags);

    /* Copy local address */
    so->so_local.sin_family = addr->sin_family;
    so->so_local.sin_port   = addr->sin_port;
    so->so_local.sin_addr   = addr->sin_addr;
    so->so_state = SS_BOUND;

    spin_unlock_irqrestore(&so->so_lock, flags);

    return 0;
}

int net_listen(int sockfd, int backlog)
{
    struct socket *so = socket_get(sockfd);
    if (so == NULL)
        return -EBADF;

    if (so->so_type != SOCK_STREAM)
        return -EINVAL;

    if (so->so_state != SS_BOUND)
        return -EINVAL;

    /* Allocate a TCB in LISTEN state for this socket.
     * tcp_input() uses tcp_find_tcb() which checks TCPS_LISTEN state
     * on the TCB, so we MUST have one. */
    struct tcpcb *tp = tcp_alloc();
    if (tp == NULL)
        return -ENOMEM;

    tp->t_socket    = so;
    tp->local_addr  = so->so_local.sin_addr.s_addr;
    tp->local_port  = so->so_local.sin_port;
    tp->remote_addr = 0;   /* Wildcard — accept from any remote */
    tp->remote_port = 0;
    tp->t_state     = TCPS_LISTEN;
    so->so_pcb      = tp;

    uint64_t flags;
    spin_lock_irqsave(&so->so_lock, &flags);

    so->so_state  = SS_LISTENING;
    so->so_qlimit = (backlog > 0) ? backlog : 1;
    so->so_qlen   = 0;

    spin_unlock_irqrestore(&so->so_lock, flags);

    return 0;
}

int net_accept(int sockfd, struct sockaddr_in *addr)
{
    struct socket *so = socket_get(sockfd);
    if (so == NULL)
        return -EBADF;

    if (so->so_state != SS_LISTENING)
        return -EINVAL;

    /*
     * Block until a connection arrives on the listening socket.
     * tcp_input()'s TCPS_LISTEN handler creates child sockets (via
     * tcp_accept_alloc) and transitions them through SYN_RCVD to
     * SS_CONNECTED once the 3-way handshake completes.
     * We scan the socket table for children of this listener.
     */
    extern void sched_yield(void);
    extern void virtio_net_recv(void);

    /* Poll with yield — wait for a completed connection */
    for (int attempt = 0; attempt < 50000; attempt++) {
        /* Scan for child sockets that have completed the handshake */
        for (int i = 0; i < NET_MAX_SOCKETS; i++) {
            struct socket *child = &socket_table[i];
            if (!child->so_active)
                continue;
            if (child->so_listener != sockfd)
                continue;
            if (child->so_accepted)
                continue;
            if (child->so_state != SS_CONNECTED)
                continue;

            /* Found a connected child socket — mark as accepted */
            child->so_accepted = true;

            /* Decrement listener's pending count */
            uint64_t flags;
            spin_lock_irqsave(&so->so_lock, &flags);
            if (so->so_qlen > 0)
                so->so_qlen--;
            spin_unlock_irqrestore(&so->so_lock, flags);

            if (addr != NULL) {
                *addr = child->so_remote;
            }

            return i;
        }

        /* No connections yet — poll network and yield */
        virtio_net_recv();
        sched_yield();
    }

    /* Timeout — no connections arrived */
    return -EAGAIN;
}

int net_connect(int sockfd, const struct sockaddr_in *addr)
{
    struct socket *so = socket_get(sockfd);
    if (so == NULL)
        return -EBADF;

    if (addr == NULL)
        return -EINVAL;

    if (so->so_state != SS_UNCONNECTED && so->so_state != SS_BOUND)
        return -EISDIR; /* Already connected or invalid state */

    uint64_t flags;
    spin_lock_irqsave(&so->so_lock, &flags);

    /* Set remote address */
    so->so_remote.sin_family = addr->sin_family;
    so->so_remote.sin_port   = addr->sin_port;
    so->so_remote.sin_addr   = addr->sin_addr;

    /* If not yet bound, auto-bind to INADDR_ANY with an ephemeral port */
    if (so->so_state == SS_UNCONNECTED) {
        so->so_local.sin_family    = AF_INET;
        so->so_local.sin_addr.s_addr = htonl(INADDR_ANY);
        /* Simple ephemeral port assignment: 49152 + sockfd */
        so->so_local.sin_port = htons((uint16_t)(49152 + sockfd));
    }

    so->so_state = SS_CONNECTING;

    spin_unlock_irqrestore(&so->so_lock, flags);

    /* For TCP, initiate the three-way handshake */
    if (so->so_type == SOCK_STREAM) {
        int ret = tcp_connect(so);
        if (ret < 0) {
            so->so_state = SS_UNCONNECTED;
            return ret;
        }
        /* Wait for the SYN-ACK and complete the 3-way handshake.
         * Poll virtio_net_recv() until the TCB transitions to ESTABLISHED
         * or we time out. Retransmit SYN every ~1 second (100 poll cycles). */
        struct tcpcb *tp = (struct tcpcb *)so->so_pcb;
        if (tp != NULL) {
            extern void virtio_net_recv(void);
            int syn_retries = 0;
            for (int attempt = 0; attempt < 3000; attempt++) {
                /* Small delay between polls (~10ms each) */
                for (volatile int d = 0; d < 200000; d++)
                    ;
                virtio_net_recv();
                if (tp->t_state == TCPS_ESTABLISHED)
                    break;
                if (tp->t_state == TCPS_CLOSED) {
                    /* Connection refused or reset */
                    so->so_state = SS_UNCONNECTED;
                    return -ECONNREFUSED;
                }
                /* Retransmit SYN every ~100 polls (~1 second).
                 * The first SYN may be queued behind ARP; even after
                 * ARP resolves the SYN is drained from the pending queue.
                 * But if the packet was lost, we need to retransmit. */
                if (attempt > 0 && (attempt % 100) == 0 &&
                    tp->t_state == TCPS_SYN_SENT && syn_retries < 5) {
                    syn_retries++;
                    tcp_output(tp);
                }
            }
            if (tp->t_state != TCPS_ESTABLISHED) {
                /* Timed out waiting for SYN-ACK */
                tcp_close(tp);
                so->so_pcb = NULL;
                so->so_state = SS_UNCONNECTED;
                return -ETIMEDOUT;
            }
        }
        so->so_state = SS_CONNECTED;
    } else {
        /* UDP: "connect" just sets the default destination */
        so->so_state = SS_CONNECTED;
    }

    return 0;
}

/* Forward declaration for UDP output */
int udp_output(struct socket *so, const void *data, uint32_t len,
               uint32_t dst_addr, uint16_t dst_port);

ssize_t net_send(int sockfd, const void *buf, size_t len)
{
    struct socket *so = socket_get(sockfd);
    if (so == NULL)
        return -EBADF;

    if (so->so_state != SS_CONNECTED)
        return -ENOTCONN;

    if (buf == NULL || len == 0)
        return 0;

    /* UDP: send directly via udp_output (datagrams, not buffered) */
    if (so->so_type == SOCK_DGRAM) {
        uint32_t to_send = (len > 1400) ? 1400 : (uint32_t)len;
        int ret = udp_output(so, buf, to_send,
                             so->so_remote.sin_addr.s_addr,
                             so->so_remote.sin_port);
        if (ret < 0)
            return ret;
        return (ssize_t)to_send;
    }

    /* TCP: buffer data and push through tcp_output */
    uint32_t to_send = (len > SOCKBUF_SIZE) ? SOCKBUF_SIZE : (uint32_t)len;

    /* Write data to send buffer */
    uint32_t sent = sockbuf_write(&so->so_snd, buf, to_send);

    if (sent == 0)
        return -EAGAIN;     /* Send buffer full */

    if (so->so_type == SOCK_STREAM && so->so_pcb != NULL) {
        /* Push data from send buffer into TCP segments */
        tcp_output((struct tcpcb *)so->so_pcb);
    }

    return (ssize_t)sent;
}

ssize_t net_recv(int sockfd, void *buf, size_t len)
{
    struct socket *so = socket_get(sockfd);
    if (so == NULL)
        return -EBADF;

    /* Datagram sockets (UDP, ICMP) can recvfrom() without connect() */
    if (so->so_type == SOCK_STREAM) {
        if (so->so_state != SS_CONNECTED && so->so_state != SS_DISCONNECTED)
            return -ENOTCONN;
    }

    if (buf == NULL || len == 0)
        return 0;

    uint32_t to_recv = (len > SOCKBUF_SIZE) ? SOCKBUF_SIZE : (uint32_t)len;

    /* Read data from receive buffer */
    uint32_t recvd = sockbuf_read(&so->so_rcv, buf, to_recv);

    if (recvd == 0) {
        /* No data available */
        if (so->so_state == SS_DISCONNECTED)
            return 0;      /* EOF: remote closed */

        /* For TCP in CLOSE_WAIT, also return EOF */
        if (so->so_type == SOCK_STREAM && so->so_pcb != NULL) {
            struct tcpcb *tp = (struct tcpcb *)so->so_pcb;
            if (tp->t_state == TCPS_CLOSE_WAIT ||
                tp->t_state == TCPS_CLOSED) {
                so->so_state = SS_DISCONNECTED;
                return 0;  /* EOF */
            }
        }

        return -EAGAIN;    /* Would block */
    }

    return (ssize_t)recvd;
}

int net_close(int sockfd)
{
    struct socket *so = socket_get(sockfd);
    if (so == NULL)
        return -EBADF;

    uint64_t flags;
    spin_lock_irqsave(&so->so_lock, &flags);

    /* Close TCP connection if applicable */
    if (so->so_type == SOCK_STREAM && so->so_pcb != NULL) {
        struct tcpcb *tp = (struct tcpcb *)so->so_pcb;
        tcp_close(tp);
        so->so_pcb = NULL;
    }

    so->so_state  = SS_DISCONNECTED;
    so->so_active = false;

    spin_unlock_irqrestore(&so->so_lock, flags);

    return 0;
}
