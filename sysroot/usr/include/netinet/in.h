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

/* --- IPv6 Structures (Darwin ARM64 ABI) --- */

/* IPv6 address (16 bytes) */
struct in6_addr {
    union {
        uint8_t  __u6_addr8[16];
        uint16_t __u6_addr16[8];
        uint32_t __u6_addr32[4];
    } __u6_addr;
};

/* Access macros for in6_addr union */
#define s6_addr     __u6_addr.__u6_addr8
#define s6_addr16   __u6_addr.__u6_addr16
#define s6_addr32   __u6_addr.__u6_addr32

/* IPv6 socket address (28 bytes - Darwin layout) */
struct sockaddr_in6 {
    uint8_t         sin6_len;       /* Length of this struct (28) */
    uint8_t         sin6_family;    /* AF_INET6 */
    uint16_t        sin6_port;      /* Transport layer port (network order) */
    uint32_t        sin6_flowinfo;  /* IPv6 flow information */
    struct in6_addr sin6_addr;      /* IPv6 address (16 bytes) */
    uint32_t        sin6_scope_id;  /* Scope zone index */
};

/* IPv6 special addresses */
#define IN6ADDR_ANY_INIT        {{ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }}
#define IN6ADDR_LOOPBACK_INIT   {{ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 }}

/* IPv6 address testing macros */
#define IN6_IS_ADDR_UNSPECIFIED(a) \
    (((a)->s6_addr32[0] == 0) && ((a)->s6_addr32[1] == 0) && \
     ((a)->s6_addr32[2] == 0) && ((a)->s6_addr32[3] == 0))

#define IN6_IS_ADDR_LOOPBACK(a) \
    (((a)->s6_addr32[0] == 0) && ((a)->s6_addr32[1] == 0) && \
     ((a)->s6_addr32[2] == 0) && ((a)->s6_addr32[3] == __builtin_bswap32(1)))

#define IN6_IS_ADDR_MULTICAST(a) ((a)->s6_addr[0] == 0xff)

#define IN6_IS_ADDR_LINKLOCAL(a) \
    (((a)->s6_addr[0] == 0xfe) && (((a)->s6_addr[1] & 0xc0) == 0x80))

#define IN6_IS_ADDR_V4MAPPED(a) \
    (((a)->s6_addr32[0] == 0) && ((a)->s6_addr32[1] == 0) && \
     ((a)->s6_addr32[2] == __builtin_bswap32(0xffff)))

/* inet_addr - Convert dotted-decimal string to network byte order address */
uint32_t inet_addr(const char *cp);

/* inet_ntoa - Convert network address to dotted-decimal string */
char *inet_ntoa(struct in_addr in);

/* inet_pton - Convert presentation to numeric */
int inet_pton(int af, const char *src, void *dst);

/* inet_ntop - Convert numeric to presentation */
const char *inet_ntop(int af, const void *src, char *dst, socklen_t size);

#endif /* _NETINET_IN_H */
