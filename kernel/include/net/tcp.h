/*
 * Kiseki OS - TCP Protocol
 *
 * TCP header, state machine, and control block definitions.
 * Implements RFC 793 TCP with simplified state transitions.
 *
 * Reference: RFC 793, Stevens "TCP/IP Illustrated" Vol 2
 */

#ifndef _NET_TCP_H
#define _NET_TCP_H

#include <kiseki/types.h>
#include <net/net.h>

/* ============================================================================
 * TCP Header (RFC 793)
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Source Port          |       Destination Port        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Sequence Number                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Acknowledgment Number                     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Data |       |U|A|P|R|S|F|                                  |
 * | Offset|  Res  |R|C|S|S|Y|I|            Window                |
 * |       |       |G|K|H|T|N|N|                                  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Checksum            |         Urgent Pointer        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ============================================================================ */

struct tcp_hdr {
    uint16_t    th_sport;       /* Source port (network byte order) */
    uint16_t    th_dport;       /* Destination port (network byte order) */
    uint32_t    th_seq;         /* Sequence number */
    uint32_t    th_ack;         /* Acknowledgment number */
    uint8_t     th_off_rsvd;    /* Data offset (high 4 bits) + reserved */
    uint8_t     th_flags;       /* TCP flags */
    uint16_t    th_win;         /* Window size */
    uint16_t    th_sum;         /* Checksum */
    uint16_t    th_urp;         /* Urgent pointer */
} __packed;

/* TCP data offset helper: extract header length in bytes */
#define TCP_HDRLEN(th)  (((th)->th_off_rsvd >> 4) * 4)

/* TCP Flags */
#define TH_FIN          0x01
#define TH_SYN          0x02
#define TH_RST          0x04
#define TH_PUSH         0x08
#define TH_ACK          0x10
#define TH_URG          0x20

/* ============================================================================
 * TCP States (RFC 793 state machine)
 * ============================================================================ */

enum tcp_state {
    TCPS_CLOSED         = 0,    /* Closed (initial/final state) */
    TCPS_LISTEN         = 1,    /* Listening for connections */
    TCPS_SYN_SENT       = 2,    /* SYN sent, awaiting SYN-ACK */
    TCPS_SYN_RCVD       = 3,    /* SYN received, sent SYN-ACK */
    TCPS_ESTABLISHED    = 4,    /* Connection established */
    TCPS_FIN_WAIT_1     = 5,    /* FIN sent, awaiting ACK */
    TCPS_FIN_WAIT_2     = 6,    /* FIN ACKed, awaiting remote FIN */
    TCPS_CLOSE_WAIT     = 7,    /* Remote FIN received, awaiting local close */
    TCPS_CLOSING        = 8,    /* Both sides sent FIN simultaneously */
    TCPS_LAST_ACK       = 9,    /* FIN sent after CLOSE_WAIT, awaiting ACK */
    TCPS_TIME_WAIT      = 10,   /* Waiting for stale segments to expire */
};

/* ============================================================================
 * TCP Control Block (tcpcb)
 *
 * Per-connection TCP state. Linked to a socket via so_pcb.
 * ============================================================================ */

#define TCP_MAX_CONNECTIONS 64

struct tcpcb {
    enum tcp_state  t_state;        /* Current TCP state */
    bool            t_active;       /* Slot is allocated */

    /* Sequence number state */
    uint32_t        snd_una;        /* Oldest unacknowledged seq */
    uint32_t        snd_nxt;        /* Next sequence number to send */
    uint32_t        snd_wnd;        /* Send window */
    uint32_t        rcv_nxt;        /* Next expected receive seq */
    uint32_t        rcv_wnd;        /* Receive window */

    /* Initial sequence numbers */
    uint32_t        iss;            /* Initial send sequence number */
    uint32_t        irs;            /* Initial receive sequence number */

    /* Local and remote endpoints (copied from socket for fast access) */
    uint32_t        local_addr;     /* Local IP (network order) */
    uint16_t        local_port;     /* Local port (network order) */
    uint32_t        remote_addr;    /* Remote IP (network order) */
    uint16_t        remote_port;    /* Remote port (network order) */

    /* Back-pointer to owning socket */
    struct socket   *t_socket;

    /* Retransmission state (simplified) */
    uint32_t        t_rxtcur;       /* Current retransmit timeout (ms) */
    uint32_t        t_rxtshift;     /* Exponential backoff shift */

    /* Synchronization */
    spinlock_t      t_lock;
};

/* ============================================================================
 * TCP API (kernel-internal)
 * ============================================================================ */

/*
 * tcp_init - Initialize TCP subsystem.
 *
 * Sets up the tcpcb pool and initial sequence number generator.
 */
void tcp_init(void);

/*
 * tcp_input - Process an incoming TCP segment.
 *
 * @src_addr: Source IP address (network order)
 * @dst_addr: Destination IP address (network order)
 * @data:     TCP segment (header + payload)
 * @len:      Total length of the TCP segment
 *
 * Demultiplexes to the correct connection and runs the TCP state machine.
 */
void tcp_input(uint32_t src_addr, uint32_t dst_addr,
               const void *data, uint32_t len);

/*
 * tcp_output - Generate and send a TCP segment.
 *
 * @tp: TCP control block for the connection.
 *
 * Constructs a TCP segment from the connection state and pending data,
 * then passes it to ip_output.
 *
 * Returns 0 on success, -errno on failure.
 */
int tcp_output(struct tcpcb *tp);

/*
 * tcp_connect - Initiate a TCP connection (active open).
 *
 * @so: Socket to connect.
 *
 * Allocates a tcpcb, sends SYN, transitions to SYN_SENT.
 * Returns 0 on success, -errno on failure.
 */
int tcp_connect(struct socket *so);

/*
 * tcp_close - Close a TCP connection.
 *
 * @tp: TCP control block.
 *
 * Sends FIN and transitions through the close states.
 * Returns 0 on success, -errno on failure.
 */
int tcp_close(struct tcpcb *tp);

/*
 * tcp_alloc - Allocate a TCP control block.
 *
 * Returns a fresh tcpcb, or NULL if the pool is exhausted.
 */
struct tcpcb *tcp_alloc(void);

/*
 * tcp_free - Release a TCP control block.
 *
 * @tp: TCP control block to free.
 */
void tcp_free(struct tcpcb *tp);

#endif /* _NET_TCP_H */
