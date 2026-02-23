/*
 * Kiseki OS - IPv4 Address Structures
 */

#ifndef _NETINET_IN_H
#define _NETINET_IN_H

#include <types.h>
#include <sys/socket.h>

/* IPv4 address */
struct in_addr {
    uint32_t    s_addr;         /* Network byte order */
};

/* IPv4 socket address */
struct sockaddr_in {
    uint8_t         sin_len;
    uint8_t         sin_family;     /* AF_INET */
    uint16_t        sin_port;       /* Network byte order */
    struct in_addr  sin_addr;
    uint8_t         sin_zero[8];
};

/* Special addresses */
#define INADDR_ANY          0x00000000U
#define INADDR_BROADCAST    0xFFFFFFFFU
#define INADDR_LOOPBACK     0x7F000001U
#define INADDR_NONE         0xFFFFFFFFU

/* inet_addr - Convert dotted-decimal string to network byte order address */
uint32_t inet_addr(const char *cp);

/* inet_ntoa - Convert network address to dotted-decimal string */
char *inet_ntoa(struct in_addr in);

/* inet_pton - Convert presentation to numeric */
int inet_pton(int af, const char *src, void *dst);

/* inet_ntop - Convert numeric to presentation */
const char *inet_ntop(int af, const void *src, char *dst, socklen_t size);

#endif /* _NETINET_IN_H */
