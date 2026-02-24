/*
 * Kiseki OS - Network Subsystem
 *
 * BSD socket interface and core networking types. Provides the socket
 * abstraction layer that maps to the VFS (sockets are vnodes in BSD).
 *
 * Supported:
 *   AF_INET  - IPv4
 *   AF_INET6 - IPv6 (placeholder)
 *   SOCK_STREAM - TCP
 *   SOCK_DGRAM  - UDP
 *
 * Reference: Stevens, "UNIX Network Programming" Vol 1;
 *            XNU bsd/sys/socket.h
 */

#ifndef _NET_NET_H
#define _NET_NET_H

#include <kiseki/types.h>
#include <kern/sync.h>

/* ============================================================================
 * Address Families
 * ============================================================================ */

#define AF_UNSPEC       0       /* Unspecified */
#define AF_UNIX         1       /* Unix domain (local IPC) */
#define AF_LOCAL        AF_UNIX /* POSIX alias */
#define AF_INET         2       /* IPv4 */
#define AF_INET6        30      /* IPv6 (XNU value) */

/* Protocol family aliases */
#define PF_UNIX         AF_UNIX
#define PF_LOCAL        AF_LOCAL
#define PF_INET         AF_INET
#define PF_INET6        AF_INET6

/* ============================================================================
 * Socket Types
 * ============================================================================ */

#define SOCK_STREAM     1       /* Stream (TCP) */
#define SOCK_DGRAM      2       /* Datagram (UDP) */
#define SOCK_RAW        3       /* Raw IP */

/* ============================================================================
 * IP Protocols
 * ============================================================================ */

#define IPPROTO_IP      0       /* Dummy for IP */
#define IPPROTO_ICMP    1       /* ICMP */
#define IPPROTO_TCP     6       /* TCP */
#define IPPROTO_UDP     17      /* UDP */
#define IPPROTO_RAW     255     /* Raw IP */

/* ============================================================================
 * Socket Address Structures
 * ============================================================================ */

/*
 * Generic socket address (BSD-compatible).
 * All address families begin with sa_family.
 */
struct sockaddr {
    uint8_t     sa_len;         /* Total length */
    uint8_t     sa_family;      /* Address family (AF_INET, etc.) */
    uint8_t     sa_data[14];    /* Address data */
};

/*
 * IPv4 address (32-bit, network byte order)
 */
struct in_addr {
    uint32_t    s_addr;         /* IPv4 address (network byte order) */
};

/*
 * IPv4 socket address
 */
struct sockaddr_in {
    uint8_t         sin_len;        /* sizeof(struct sockaddr_in) */
    uint8_t         sin_family;     /* AF_INET */
    uint16_t        sin_port;       /* Port number (network byte order) */
    struct in_addr  sin_addr;       /* IPv4 address */
    uint8_t         sin_zero[8];    /* Padding to sizeof(struct sockaddr) */
};

/* Special IPv4 addresses */
#define INADDR_ANY          0x00000000U     /* 0.0.0.0 */
#define INADDR_BROADCAST    0xFFFFFFFFU     /* 255.255.255.255 */
#define INADDR_LOOPBACK     0x7F000001U     /* 127.0.0.1 (host order) */

/*
 * Unix domain socket address (XNU bsd/sys/un.h)
 */
#define UNIX_PATH_MAX   104     /* XNU uses 104 (sizeof(struct sockaddr_un) = 106) */

struct sockaddr_un {
    uint8_t     sun_len;                /* Total length */
    uint8_t     sun_family;             /* AF_UNIX */
    char        sun_path[UNIX_PATH_MAX]; /* Path name */
};

/*
 * Unix domain protocol control block
 *
 * Modelled on XNU's struct unpcb (bsd/sys/unpcb.h).
 * Each AF_UNIX socket has one of these as so_pcb.
 */
struct unpcb {
    int         unp_peer;               /* Peer socket index (-1 if none) */
    char        unp_path[UNIX_PATH_MAX]; /* Bound path (empty if unnamed) */
    bool        unp_bound;              /* True if bind() was called */
};

/* ============================================================================
 * Byte Order Conversion (ARM64 is little-endian)
 * ============================================================================ */

static inline __unused uint16_t htons(uint16_t h)
{
    return (uint16_t)((h >> 8) | (h << 8));
}

static inline __unused uint16_t ntohs(uint16_t n)
{
    return htons(n);
}

static inline __unused uint32_t htonl(uint32_t h)
{
    return ((h & 0xFF000000U) >> 24) |
           ((h & 0x00FF0000U) >> 8)  |
           ((h & 0x0000FF00U) << 8)  |
           ((h & 0x000000FFU) << 24);
}

static inline __unused uint32_t ntohl(uint32_t n)
{
    return htonl(n);
}

/* ============================================================================
 * Socket States
 * ============================================================================ */

#define SS_UNCONNECTED  0       /* Not yet connected */
#define SS_BOUND        1       /* Bound to local address */
#define SS_LISTENING    2       /* Listening for connections */
#define SS_CONNECTING   3       /* Connection in progress */
#define SS_CONNECTED    4       /* Connected (data transfer ok) */
#define SS_DISCONNECTED 5       /* Connection closed */

/* Shutdown flags (bit flags, stored in so_sflags, separate from so_state) */
#define SS_CANTRCVMORE  0x01    /* shutdown(SHUT_RD) called */
#define SS_CANTSENDMORE 0x02    /* shutdown(SHUT_WR) called */

/* ============================================================================
 * Socket Buffer
 *
 * Simple circular buffer for socket send/receive data.
 * ============================================================================ */

#define SOCKBUF_SIZE    4096

struct sockbuf {
    uint8_t     sb_buf[SOCKBUF_SIZE];   /* Data buffer */
    uint32_t    sb_head;                /* Read position */
    uint32_t    sb_tail;                /* Write position */
    uint32_t    sb_len;                 /* Current data length */
    spinlock_t  sb_lock;                /* Protects buffer state */
};

/* ============================================================================
 * Socket Structure
 *
 * Represents a BSD socket. In BSD tradition, sockets are vnodes and
 * can be accessed via file descriptors.
 * ============================================================================ */

#define NET_MAX_SOCKETS     64

struct socket {
    int                 so_type;        /* SOCK_STREAM, SOCK_DGRAM, etc. */
    int                 so_protocol;    /* IPPROTO_TCP, IPPROTO_UDP */
    int                 so_family;      /* AF_INET, AF_UNIX, AF_INET6 */
    int                 so_state;       /* SS_UNCONNECTED, SS_CONNECTED, ... */
    int                 so_error;       /* Pending error code */
    int                 so_options;     /* SO_REUSEADDR, SO_KEEPALIVE, etc. */
    int                 so_sflags;      /* Shutdown flags (SS_CANTRCVMORE, etc.) */
    bool                so_active;      /* Slot is allocated */

    /* Local and remote addresses (family-specific) */
    struct sockaddr_in  so_local;       /* AF_INET local address */
    struct sockaddr_in  so_remote;      /* AF_INET remote address */

    /* Data buffers */
    struct sockbuf      so_snd;         /* Send buffer */
    struct sockbuf      so_rcv;         /* Receive buffer */

    /* Protocol control block
     *   AF_INET SOCK_STREAM: points to struct tcpcb
     *   AF_UNIX:             points to struct unpcb */
    void               *so_pcb;

    /* Listening state */
    int                 so_qlimit;      /* Max pending connections (backlog) */
    int                 so_qlen;        /* Current pending connections */
    int                 so_listener;    /* Index of parent listening socket (-1 if none) */
    bool                so_accepted;    /* True once accept() has returned this socket */

    /* Synchronization */
    spinlock_t          so_lock;        /* Protects socket state */
};

/* ============================================================================
 * Socket API (kernel-internal BSD socket layer)
 * ============================================================================ */

/*
 * net_init - Initialize the networking subsystem.
 *
 * Sets up the socket table, protocol handlers, and ARP cache.
 * Called once during kernel startup.
 */
void net_init(void);

/*
 * net_socket - Create a new socket.
 *
 * @domain:   Address family (AF_INET, AF_INET6)
 * @type:     Socket type (SOCK_STREAM, SOCK_DGRAM)
 * @protocol: Protocol (0 for default, or IPPROTO_TCP/IPPROTO_UDP)
 *
 * Returns a socket descriptor (>= 0) on success, -errno on failure.
 */
int net_socket(int domain, int type, int protocol);

/*
 * net_bind - Bind a socket to a local address.
 *
 * @sockfd: Socket descriptor
 * @addr:   Local address to bind to
 *
 * Returns 0 on success, -errno on failure.
 */
int net_bind(int sockfd, const struct sockaddr_in *addr);

/*
 * net_listen - Mark a socket as passive (listening).
 *
 * @sockfd:  Socket descriptor
 * @backlog: Maximum pending connection queue length
 *
 * Returns 0 on success, -errno on failure.
 */
int net_listen(int sockfd, int backlog);

/*
 * net_accept - Accept a connection on a listening socket.
 *
 * @sockfd: Listening socket descriptor
 * @addr:   Filled with remote address on success (may be NULL)
 *
 * Returns a new socket descriptor for the connection, or -errno.
 */
int net_accept(int sockfd, struct sockaddr_in *addr);

/*
 * net_connect - Initiate a connection to a remote address.
 *
 * @sockfd: Socket descriptor
 * @addr:   Remote address to connect to
 *
 * Returns 0 on success, -errno on failure.
 */
int net_connect(int sockfd, const struct sockaddr_in *addr);

/*
 * net_send - Send data on a connected socket.
 *
 * @sockfd: Socket descriptor
 * @buf:    Data to send
 * @len:    Number of bytes to send
 *
 * Returns bytes sent (>= 0), or -errno on error.
 */
ssize_t net_send(int sockfd, const void *buf, size_t len);

/*
 * net_recv - Receive data from a connected socket.
 *
 * @sockfd: Socket descriptor
 * @buf:    Buffer to receive into
 * @len:    Maximum bytes to receive
 *
 * Returns bytes received (>= 0), or -errno on error.
 */
ssize_t net_recv(int sockfd, void *buf, size_t len);

/*
 * net_close - Close a socket.
 *
 * @sockfd: Socket descriptor to close
 *
 * Returns 0 on success, -errno on failure.
 */
int net_close(int sockfd);

/* ============================================================================
 * AF_UNIX Socket Operations (kernel-internal)
 *
 * Modelled on XNU's uipc_usrreq.c (bsd/kern/uipc_usrreq.c).
 * These are called from the generic socket API when so_family == AF_UNIX.
 * ============================================================================ */

int unix_bind(int sockfd, const struct sockaddr_un *addr);
int unix_listen(int sockfd, int backlog);
int unix_accept(int sockfd, struct sockaddr_un *addr);
int unix_connect(int sockfd, const struct sockaddr_un *addr);
ssize_t unix_send(int sockfd, const void *buf, size_t len);
ssize_t unix_recv(int sockfd, void *buf, size_t len);
int unix_close(int sockfd);

/* Access to socket table for AF_UNIX operations */
extern struct socket socket_table[];

#endif /* _NET_NET_H */
