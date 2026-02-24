/*
 * Kiseki OS - Unix Domain Socket Addresses
 *
 * Modelled on XNU bsd/sys/un.h.
 */

#ifndef _SYS_UN_H
#define _SYS_UN_H

#include <sys/socket.h>

/*
 * Unix domain socket address.
 *
 * The sun_path field holds the filesystem path used to identify the
 * socket. XNU uses a 104-byte path buffer (total struct size = 106).
 */

#define UNIX_PATH_MAX   104

struct sockaddr_un {
    unsigned char   sun_len;                /* Total length */
    unsigned char   sun_family;             /* AF_UNIX */
    char            sun_path[UNIX_PATH_MAX]; /* Path name */
};

#endif /* _SYS_UN_H */
