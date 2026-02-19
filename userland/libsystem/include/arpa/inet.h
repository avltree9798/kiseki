/*
 * Kiseki OS - Internet Address Manipulation
 */

#ifndef _ARPA_INET_H
#define _ARPA_INET_H

#include <types.h>
#include <netinet/in.h>

/* Byte order conversion (ARM64 is little-endian) */
static inline uint16_t htons(uint16_t h)
{
    return (uint16_t)((h >> 8) | (h << 8));
}

static inline uint16_t ntohs(uint16_t n)
{
    return htons(n);
}

static inline uint32_t htonl(uint32_t h)
{
    return ((h & 0xFF000000U) >> 24) |
           ((h & 0x00FF0000U) >> 8)  |
           ((h & 0x0000FF00U) << 8)  |
           ((h & 0x000000FFU) << 24);
}

static inline uint32_t ntohl(uint32_t n)
{
    return htonl(n);
}

#endif /* _ARPA_INET_H */
