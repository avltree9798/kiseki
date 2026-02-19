/*
 * Kiseki OS - nc (netcat)
 *
 * Simple networking utility for reading/writing TCP and UDP connections.
 *
 * Usage:
 *   nc [-u] [-l] [-p port] <host> <port>    # Connect to host:port
 *   nc -l -p <port>                          # Listen on port
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static void usage(void)
{
    fprintf(stderr, "Usage: nc [-u] [-l] [-p port] [host] [port]\n");
    fprintf(stderr, "  -l        Listen mode\n");
    fprintf(stderr, "  -p port   Local port (for listen mode)\n");
    fprintf(stderr, "  -u        Use UDP instead of TCP\n");
}

int main(int argc, char **argv)
{
    int listen_mode = 0;
    int use_udp = 0;
    int local_port = 0;
    const char *host = NULL;
    int port = 0;
    int i;

    /* Parse arguments */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0) {
            listen_mode = 1;
        } else if (strcmp(argv[i], "-u") == 0) {
            use_udp = 1;
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            local_port = atoi(argv[++i]);
        } else if (!host) {
            host = argv[i];
        } else {
            port = atoi(argv[i]);
        }
    }

    if (listen_mode && local_port == 0) {
        fprintf(stderr, "nc: listen mode requires -p <port>\n");
        usage();
        return 1;
    }

    if (!listen_mode && (!host || port == 0)) {
        fprintf(stderr, "nc: connect mode requires <host> <port>\n");
        usage();
        return 1;
    }

    int sock_type = use_udp ? SOCK_DGRAM : SOCK_STREAM;
    int sockfd = socket(AF_INET, sock_type, 0);
    if (sockfd < 0) {
        fprintf(stderr, "nc: socket() failed\n");
        return 1;
    }

    if (listen_mode) {
        /* Listen mode */
        struct sockaddr_in local_addr;
        memset(&local_addr, 0, sizeof(local_addr));
        local_addr.sin_family = AF_INET;
        local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        local_addr.sin_port = htons((unsigned short)local_port);

        if (bind(sockfd, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0) {
            fprintf(stderr, "nc: bind() failed\n");
            close(sockfd);
            return 1;
        }

        if (!use_udp) {
            if (listen(sockfd, 1) < 0) {
                fprintf(stderr, "nc: listen() failed\n");
                close(sockfd);
                return 1;
            }

            fprintf(stderr, "Listening on port %d...\n", local_port);

            struct sockaddr_in remote;
            socklen_t remotelen = sizeof(remote);
            int connfd = accept(sockfd, (struct sockaddr *)&remote, &remotelen);
            if (connfd < 0) {
                fprintf(stderr, "nc: accept() failed\n");
                close(sockfd);
                return 1;
            }

            close(sockfd);
            sockfd = connfd;
            fprintf(stderr, "Connection accepted\n");
        } else {
            fprintf(stderr, "Listening on UDP port %d...\n", local_port);
        }
    } else {
        /* Connect mode */
        struct sockaddr_in remote;
        memset(&remote, 0, sizeof(remote));
        remote.sin_family = AF_INET;
        remote.sin_port = htons((unsigned short)port);

        if (inet_pton(AF_INET, host, &remote.sin_addr) != 1) {
            fprintf(stderr, "nc: invalid address: %s\n", host);
            close(sockfd);
            return 1;
        }

        if (connect(sockfd, (struct sockaddr *)&remote, sizeof(remote)) < 0) {
            fprintf(stderr, "nc: connect() failed\n");
            close(sockfd);
            return 1;
        }
        fprintf(stderr, "Connected to %s:%d\n", host, port);
    }

    /* Data transfer loop: read from stdin -> send, recv -> stdout */
    char buf[4096];
    for (;;) {
        /* Try to read from stdin (non-blocking would be ideal) */
        ssize_t n = read(0, buf, sizeof(buf));
        if (n > 0) {
            ssize_t sent = send(sockfd, buf, (size_t)n, 0);
            if (sent < 0) {
                fprintf(stderr, "nc: send error\n");
                break;
            }
        } else if (n == 0) {
            /* EOF on stdin */
            break;
        }

        /* Try to receive from socket */
        n = recv(sockfd, buf, sizeof(buf), 0);
        if (n > 0) {
            write(1, buf, (size_t)n);
        } else if (n == 0) {
            /* Connection closed */
            break;
        }
    }

    close(sockfd);
    return 0;
}
