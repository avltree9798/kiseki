/*
 * Kiseki OS - Socket Interface (BSD-compatible)
 */

#ifndef _SYS_SOCKET_H
#define _SYS_SOCKET_H

#include <types.h>

/* Address families */
#define AF_UNSPEC       0
#define AF_INET         2
#define AF_INET6        30

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
#define SO_REUSEADDR    0x0004
#define SO_KEEPALIVE    0x0008
#define SO_RCVBUF       0x1002
#define SO_SNDBUF       0x1001
#define SO_RCVTIMEO     0x1006
#define SO_SNDTIMEO     0x1005

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
