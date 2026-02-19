/*
 * Kiseki OS - ping
 *
 * Send ICMP echo requests to a host.
 * Uses raw sockets (SOCK_DGRAM with IPPROTO_ICMP on Kiseki).
 *
 * Usage: ping [-c count] <host>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ICMP header */
struct icmp_hdr {
    unsigned char   type;
    unsigned char   code;
    unsigned short  checksum;
    unsigned short  id;
    unsigned short  seq;
};

#define ICMP_ECHO_REQUEST   8
#define ICMP_ECHO_REPLY     0

static unsigned short icmp_cksum(const void *data, int len)
{
    const unsigned short *ptr = (const unsigned short *)data;
    unsigned int sum = 0;

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len == 1)
        sum += *(const unsigned char *)ptr;

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (unsigned short)(~sum);
}

int main(int argc, char **argv)
{
    int count = 4;      /* Default: 4 pings */
    const char *host = NULL;
    int i;

    /* Parse arguments */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            count = atoi(argv[++i]);
            if (count <= 0) count = 1;
        } else {
            host = argv[i];
        }
    }

    if (!host) {
        fprintf(stderr, "Usage: ping [-c count] <host>\n");
        return 1;
    }

    /* Resolve host to IP address */
    struct in_addr addr;
    if (inet_pton(AF_INET, host, &addr) != 1) {
        fprintf(stderr, "ping: invalid address: %s\n", host);
        return 1;
    }

    /* Create ICMP datagram socket (IPPROTO_ICMP = 1) */
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (sockfd < 0) {
        fprintf(stderr, "ping: socket() failed\n");
        return 1;
    }

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr = addr;
    dest.sin_port = htons(0);  /* ICMP doesn't use ports */

    unsigned short pid = (unsigned short)getpid();

    printf("PING %s (%s): 56 data bytes\n", host, host);

    int transmitted = 0;
    int received = 0;

    for (i = 0; i < count; i++) {
        /* Build ICMP echo request */
        char pkt[64];
        struct icmp_hdr *icmp = (struct icmp_hdr *)pkt;
        icmp->type = ICMP_ECHO_REQUEST;
        icmp->code = 0;
        icmp->checksum = 0;
        icmp->id = htons(pid);
        icmp->seq = htons((unsigned short)(i + 1));

        /* Fill payload with pattern */
        for (int j = sizeof(struct icmp_hdr); j < 64; j++)
            pkt[j] = (char)(j & 0xFF);

        icmp->checksum = icmp_cksum(pkt, 64);

        /* Send */
        ssize_t sent = sendto(sockfd, pkt, 64, 0,
                              (struct sockaddr *)&dest, sizeof(dest));
        if (sent < 0) {
            fprintf(stderr, "ping: sendto failed\n");
            transmitted++;
            continue;
        }
        transmitted++;

        /* Wait for reply */
        char reply_buf[1500];
        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);

        ssize_t n = recvfrom(sockfd, reply_buf, sizeof(reply_buf), 0,
                             (struct sockaddr *)&from, &fromlen);
        if (n > 0) {
            received++;
            printf("64 bytes from %s: icmp_seq=%d ttl=64\n",
                   host, i + 1);
        } else {
            printf("Request timeout for icmp_seq %d\n", i + 1);
        }

        /* Wait 1 second between pings */
        if (i + 1 < count)
            sleep(1);
    }

    printf("\n--- %s ping statistics ---\n", host);
    printf("%d packets transmitted, %d packets received, %.0f%% packet loss\n",
           transmitted, received,
           transmitted > 0 ? (double)(transmitted - received) * 100.0 / transmitted : 0.0);

    close(sockfd);
    return received > 0 ? 0 : 1;
}
