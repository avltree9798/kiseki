/*
 * Kiseki OS - Socket Interface (BSD-compatible)
 */

#ifndef _SYS_SOCKET_H
#define _SYS_SOCKET_H

#include <types.h>

/* Address families */
#define AF_UNSPEC       0
#define AF_UNIX         1       /* Unix domain sockets */
#define AF_LOCAL        AF_UNIX /* POSIX alias */
#define AF_INET         2
#define AF_INET6        30

#define PF_UNSPEC       AF_UNSPEC
#define PF_UNIX         AF_UNIX
#define PF_LOCAL        AF_LOCAL
#define PF_INET         AF_INET
#define PF_INET6        AF_INET6

/* Socket types */
#define SOCK_STREAM     1
#define SOCK_DGRAM      2
#define SOCK_RAW        3

/* IP protocols */
#define IPPROTO_IP      0
#define IPPROTO_ICMP    1
#define IPPROTO_TCP     6
#define IPPROTO_UDP     17
#define IPPROTO_RAW     255

/* Shutdown how */
#define SHUT_RD         0
#define SHUT_WR         1
#define SHUT_RDWR       2

/* Socket options */
#define SOL_SOCKET      0xFFFF
#define SO_DEBUG        0x0001  /* Turn on debugging info recording */
#define SO_ACCEPTCONN   0x0002  /* Socket has had listen() */
#define SO_REUSEADDR    0x0004  /* Allow local address reuse */
#define SO_KEEPALIVE    0x0008  /* Keep connections alive */
#define SO_DONTROUTE    0x0010  /* Just use interface addresses */
#define SO_BROADCAST    0x0020  /* Permit sending of broadcast msgs */
#define SO_USELOOPBACK  0x0040  /* Bypass hardware when possible */
#define SO_LINGER       0x0080  /* Linger on close if data present */
#define SO_OOBINLINE    0x0100  /* Leave received OOB data in line */
#define SO_REUSEPORT    0x0200  /* Allow local address & port reuse */
#define SO_TIMESTAMP    0x0400  /* Timestamp received dgram traffic */
#define SO_SNDBUF       0x1001  /* Send buffer size */
#define SO_RCVBUF       0x1002  /* Receive buffer size */
#define SO_SNDLOWAT     0x1003  /* Send low-water mark */
#define SO_RCVLOWAT     0x1004  /* Receive low-water mark */
#define SO_SNDTIMEO     0x1005  /* Send timeout */
#define SO_RCVTIMEO     0x1006  /* Receive timeout */
#define SO_ERROR        0x1007  /* Get error status and clear */
#define SO_TYPE         0x1008  /* Get socket type */
#define SO_NOSIGPIPE    0x1022  /* Don't SIGPIPE on EPIPE */
#define SO_NREAD        0x1020  /* Get number of bytes in recv buffer */
#define SO_NWRITE       0x1024  /* Get number of bytes in send buffer */

/* msg flags for sendmsg/recvmsg */
#define MSG_OOB         0x0001  /* Process out-of-band data */
#define MSG_PEEK        0x0002  /* Peek at incoming message */
#define MSG_DONTROUTE   0x0004  /* Send without using routing tables */
#define MSG_EOR         0x0008  /* Terminate record (if supported) */
#define MSG_TRUNC       0x0010  /* Data discarded before delivery */
#define MSG_CTRUNC      0x0020  /* Control data lost before delivery */
#define MSG_WAITALL     0x0040  /* Wait for full request or error */
#define MSG_DONTWAIT    0x0080  /* This message should be nonblocking */
#define MSG_EOF         0x0100  /* Data completes connection */
#define MSG_NOSIGNAL    0x80000 /* Do not generate SIGPIPE */

/* Generic socket address */
struct sockaddr {
    unsigned char   sa_len;
    unsigned char   sa_family;
    char            sa_data[14];
};

typedef unsigned int socklen_t;

/* Socket functions */
int     socket(int domain, int type, int protocol);
int     bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int     listen(int sockfd, int backlog);
int     accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int     connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen);
ssize_t send(int sockfd, const void *buf, size_t len, int flags);
ssize_t recv(int sockfd, void *buf, size_t len, int flags);
int     shutdown(int sockfd, int how);
int     setsockopt(int sockfd, int level, int optname, const void *optval,
                   socklen_t optlen);
int     getsockopt(int sockfd, int level, int optname, void *optval,
                   socklen_t *optlen);
int     getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int     getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

#endif /* _SYS_SOCKET_H */
