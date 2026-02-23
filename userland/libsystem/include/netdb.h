/*
 * Kiseki OS - netdb.h
 *
 * Network database operations — matches macOS/XNU API.
 * Provides getaddrinfo()/freeaddrinfo() for DNS hostname resolution.
 *
 * On macOS, these functions talk to mDNSResponder via Mach IPC.
 * On Kiseki, the resolver is built into libSystem and sends UDP
 * queries directly to the DNS server obtained from DHCP.
 */

#ifndef _NETDB_H
#define _NETDB_H

#include <sys/socket.h>

/*
 * struct addrinfo — matches macOS arm64 layout
 */
struct addrinfo {
    int              ai_flags;      /* AI_PASSIVE, AI_CANONNAME, etc. */
    int              ai_family;     /* AF_INET, AF_INET6, AF_UNSPEC */
    int              ai_socktype;   /* SOCK_STREAM, SOCK_DGRAM */
    int              ai_protocol;   /* IPPROTO_TCP, IPPROTO_UDP */
    unsigned int     ai_addrlen;    /* Length of ai_addr */
    char            *ai_canonname;  /* Canonical hostname */
    struct sockaddr *ai_addr;       /* Socket address */
    struct addrinfo *ai_next;       /* Next in linked list */
};

/* ai_flags */
#define AI_PASSIVE      0x0001  /* Socket address for bind() */
#define AI_CANONNAME    0x0002  /* Request canonical name */
#define AI_NUMERICHOST  0x0004  /* Don't resolve hostname */
#define AI_NUMERICSERV  0x1000  /* Don't resolve service name */
#define AI_ADDRCONFIG   0x0400  /* Only return addresses matching local config */

/* EAI error codes (matches macOS values) */
#define EAI_AGAIN       2       /* Temporary failure */
#define EAI_BADFLAGS    3       /* Invalid flags */
#define EAI_FAIL        4       /* Non-recoverable failure */
#define EAI_FAMILY      5       /* Address family not supported */
#define EAI_MEMORY      6       /* Memory allocation failure */
#define EAI_NONAME      8       /* Name or service not known */
#define EAI_SERVICE     9       /* Service not supported for socket type */
#define EAI_SOCKTYPE    10      /* Socket type not supported */
#define EAI_SYSTEM      11      /* System error (check errno) */
#define EAI_OVERFLOW    14      /* Argument buffer overflow */

/* NI_* flags for getnameinfo (stub) */
#define NI_NUMERICHOST  0x0002
#define NI_NUMERICSERV  0x0008

/*
 * getaddrinfo - Resolve hostname to socket addresses.
 *
 * Supports both numeric addresses ("1.2.3.4") and hostnames ("example.com").
 * For hostnames, sends a DNS A-record query to the DHCP-provided DNS server.
 *
 * Returns 0 on success, or an EAI_* error code.
 */
int getaddrinfo(const char *hostname, const char *servname,
                const struct addrinfo *hints, struct addrinfo **res);

/*
 * freeaddrinfo - Free addrinfo list returned by getaddrinfo.
 */
void freeaddrinfo(struct addrinfo *ai);

/*
 * gai_strerror - Return string describing EAI_* error code.
 */
const char *gai_strerror(int ecode);

#endif /* _NETDB_H */
