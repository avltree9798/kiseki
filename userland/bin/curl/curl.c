/*
 * Kiseki OS - curl
 *
 * Minimal HTTP client for fetching URLs via TCP.
 * Supports HTTP/1.1 GET requests only.
 *
 * Usage:
 *   curl <url>
 *   curl http://host[:port]/path
 *   curl -o <file> <url>
 *   curl -I <url>          (HEAD request, headers only)
 *   curl -v <url>          (verbose, show headers)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DEFAULT_PORT    80
#define RECV_BUF_SIZE   4096

static void usage(void)
{
    fprintf(stderr, "Usage: curl [-I] [-v] [-o file] <url>\n");
    fprintf(stderr, "  -I        HEAD request (headers only)\n");
    fprintf(stderr, "  -v        Verbose (show request/response headers)\n");
    fprintf(stderr, "  -o file   Write output to file instead of stdout\n");
}

/*
 * parse_url - Parse an HTTP URL into host, port, path components.
 *
 * Accepts: http://host[:port][/path]
 * If no path given, defaults to "/".
 * If no port given, defaults to 80.
 *
 * Returns 0 on success, -1 on error.
 */
static int parse_url(const char *url, char *host, size_t hostlen,
                     int *port, char *path, size_t pathlen)
{
    const char *p = url;

    /* Skip http:// prefix if present */
    if (strncmp(p, "http://", 7) == 0) {
        p += 7;
    } else if (strncmp(p, "https://", 8) == 0) {
        fprintf(stderr, "curl: HTTPS not supported\n");
        return -1;
    }

    /* Find end of host (either ':', '/', or end of string) */
    const char *host_start = p;
    const char *host_end = p;
    while (*host_end && *host_end != ':' && *host_end != '/')
        host_end++;

    size_t hlen = (size_t)(host_end - host_start);
    if (hlen == 0 || hlen >= hostlen) {
        fprintf(stderr, "curl: invalid host in URL\n");
        return -1;
    }

    memcpy(host, host_start, hlen);
    host[hlen] = '\0';

    /* Parse optional port */
    *port = DEFAULT_PORT;
    p = host_end;
    if (*p == ':') {
        p++;
        *port = atoi(p);
        if (*port <= 0 || *port > 65535) {
            fprintf(stderr, "curl: invalid port\n");
            return -1;
        }
        while (*p && *p != '/')
            p++;
    }

    /* Parse path (default to /) */
    if (*p == '/') {
        size_t plen = strlen(p);
        if (plen >= pathlen) plen = pathlen - 1;
        memcpy(path, p, plen);
        path[plen] = '\0';
    } else {
        path[0] = '/';
        path[1] = '\0';
    }

    return 0;
}

/*
 * find_header_end - Find the end of HTTP headers (\r\n\r\n).
 *
 * Returns pointer to the first byte after headers, or NULL if
 * the header terminator was not found in the buffer.
 */
static const char *find_header_end(const char *buf, size_t len)
{
    for (size_t i = 0; i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i+1] == '\n' &&
            buf[i+2] == '\r' && buf[i+3] == '\n')
            return buf + i + 4;
    }
    return NULL;
}

/*
 * parse_content_length - Extract Content-Length from headers.
 * Returns -1 if not found.
 */
static long parse_content_length(const char *headers, size_t hdr_len)
{
    const char *p = headers;
    const char *end = headers + hdr_len;

    while (p < end) {
        /* Case-insensitive search for Content-Length: */
        if ((end - p > 16) &&
            (p[0] == 'C' || p[0] == 'c') &&
            (p[1] == 'o' || p[1] == 'O') &&
            (p[2] == 'n' || p[2] == 'N') &&
            (p[3] == 't' || p[3] == 'T') &&
            (p[4] == 'e' || p[4] == 'E') &&
            (p[5] == 'n' || p[5] == 'N') &&
            (p[6] == 't' || p[6] == 'T') &&
            p[7] == '-' &&
            (p[8] == 'L' || p[8] == 'l') &&
            (p[9] == 'e' || p[9] == 'E') &&
            (p[10] == 'n' || p[10] == 'N') &&
            (p[11] == 'g' || p[11] == 'G') &&
            (p[12] == 't' || p[12] == 'T') &&
            (p[13] == 'h' || p[13] == 'H') &&
            p[14] == ':') {
            const char *val = p + 15;
            while (val < end && *val == ' ')
                val++;
            return atol(val);
        }
        /* Advance to next line */
        while (p < end && *p != '\n')
            p++;
        if (p < end)
            p++;
    }
    return -1;
}

/*
 * check_chunked - Check if Transfer-Encoding is chunked.
 */
static int check_chunked(const char *headers, size_t hdr_len)
{
    const char *p = headers;
    const char *end = headers + hdr_len;

    while (p < end) {
        if ((end - p > 19) &&
            (p[0] == 'T' || p[0] == 't') &&
            (p[1] == 'r' || p[1] == 'R') &&
            (p[2] == 'a' || p[2] == 'A') &&
            (p[3] == 'n' || p[3] == 'N') &&
            (p[4] == 's' || p[4] == 'S') &&
            (p[5] == 'f' || p[5] == 'F') &&
            (p[6] == 'e' || p[6] == 'E') &&
            (p[7] == 'r' || p[7] == 'R') &&
            p[8] == '-' &&
            (p[9] == 'E' || p[9] == 'e') &&
            (p[10] == 'n' || p[10] == 'N') &&
            (p[11] == 'c' || p[11] == 'C') &&
            (p[12] == 'o' || p[12] == 'O') &&
            (p[13] == 'd' || p[13] == 'D') &&
            (p[14] == 'i' || p[14] == 'I') &&
            (p[15] == 'n' || p[15] == 'N') &&
            (p[16] == 'g' || p[16] == 'G') &&
            p[17] == ':') {
            /* Check if value contains "chunked" */
            const char *val = p + 18;
            while (val < end && *val != '\r' && *val != '\n') {
                if (val + 7 <= end &&
                    (val[0] == 'c' || val[0] == 'C') &&
                    (val[1] == 'h' || val[1] == 'H') &&
                    (val[2] == 'u' || val[2] == 'U') &&
                    (val[3] == 'n' || val[3] == 'N') &&
                    (val[4] == 'k' || val[4] == 'K') &&
                    (val[5] == 'e' || val[5] == 'E') &&
                    (val[6] == 'd' || val[6] == 'D'))
                    return 1;
                val++;
            }
        }
        while (p < end && *p != '\n')
            p++;
        if (p < end)
            p++;
    }
    return 0;
}

int main(int argc, char **argv)
{
    int verbose = 0;
    int head_only = 0;
    const char *output_file = NULL;
    const char *url = NULL;
    int i;

    /* Parse arguments */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-I") == 0) {
            head_only = 1;
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage();
            return 0;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "curl: unknown option: %s\n", argv[i]);
            usage();
            return 1;
        } else {
            url = argv[i];
        }
    }

    if (!url) {
        fprintf(stderr, "curl: no URL specified\n");
        usage();
        return 1;
    }

    /* Parse URL */
    char host[256];
    char path[1024];
    int port;

    if (parse_url(url, host, sizeof(host), &port, path, sizeof(path)) < 0)
        return 1;

    if (verbose)
        fprintf(stderr, "* Connecting to %s port %d...\n", host, port);

    /* Resolve host to IP address.
     * We only support numeric IP addresses (no DNS yet). */
    struct in_addr addr;
    if (inet_pton(AF_INET, host, &addr) != 1) {
        fprintf(stderr, "curl: could not resolve host: %s\n", host);
        fprintf(stderr, "  (DNS not supported; use IP address)\n");
        return 1;
    }

    /* Create TCP socket */
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "curl: socket() failed\n");
        return 1;
    }

    /* Connect to server */
    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons((unsigned short)port);
    server.sin_addr = addr;

    if (connect(sockfd, (struct sockaddr *)&server, sizeof(server)) < 0) {
        fprintf(stderr, "curl: connect to %s:%d failed\n", host, port);
        close(sockfd);
        return 1;
    }

    if (verbose)
        fprintf(stderr, "* Connected to %s (%s) port %d\n", host, host, port);

    /* Build HTTP request */
    char request[2048];
    int reqlen;

    if (head_only) {
        reqlen = snprintf(request, sizeof(request),
            "HEAD %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: curl/kiseki\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n"
            "\r\n",
            path, host);
    } else {
        reqlen = snprintf(request, sizeof(request),
            "GET %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: curl/kiseki\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n"
            "\r\n",
            path, host);
    }

    if (verbose) {
        /* Show request headers */
        const char *p = request;
        while (*p) {
            if (*p == '\r') { p++; continue; }
            if (*p == '\n') {
                fputc('\n', stderr);
                p++;
                if (*p == '\r' || *p == '\0') break;
                fprintf(stderr, "> ");
                continue;
            }
            if (p == request)
                fprintf(stderr, "> ");
            fputc(*p, stderr);
            p++;
        }
        fprintf(stderr, ">\n");
    }

    /* Send HTTP request */
    ssize_t sent = send(sockfd, request, (size_t)reqlen, 0);
    if (sent < 0) {
        fprintf(stderr, "curl: send() failed\n");
        close(sockfd);
        return 1;
    }

    /* Open output file if specified */
    FILE *outfp = stdout;
    if (output_file) {
        outfp = fopen(output_file, "w");
        if (!outfp) {
            fprintf(stderr, "curl: cannot open %s for writing\n", output_file);
            close(sockfd);
            return 1;
        }
    }

    /* Receive response */
    char buf[RECV_BUF_SIZE];
    char header_buf[8192];
    size_t header_len = 0;
    int headers_done = 0;
    long content_length = -1;
    long body_received = 0;
    int is_chunked = 0;

    while (1) {
        ssize_t n = recv(sockfd, buf, sizeof(buf), 0);
        if (n <= 0)
            break;

        if (!headers_done) {
            /* Accumulate headers */
            size_t to_copy = (size_t)n;
            if (header_len + to_copy > sizeof(header_buf) - 1)
                to_copy = sizeof(header_buf) - 1 - header_len;
            memcpy(header_buf + header_len, buf, to_copy);
            header_len += to_copy;
            header_buf[header_len] = '\0';

            const char *body_start = find_header_end(header_buf, header_len);
            if (body_start) {
                headers_done = 1;
                size_t hdr_size = (size_t)(body_start - header_buf);

                /* Parse headers */
                content_length = parse_content_length(header_buf, hdr_size);
                is_chunked = check_chunked(header_buf, hdr_size);

                if (verbose) {
                    /* Print response headers to stderr */
                    fprintf(stderr, "< ");
                    for (size_t j = 0; j < hdr_size; j++) {
                        if (header_buf[j] == '\r')
                            continue;
                        if (header_buf[j] == '\n') {
                            fprintf(stderr, "\n");
                            if (j + 1 < hdr_size && header_buf[j+1] != '\r')
                                fprintf(stderr, "< ");
                            continue;
                        }
                        fputc(header_buf[j], stderr);
                    }
                    fprintf(stderr, "<\n");
                }

                if (head_only) {
                    /* For -I, print headers to stdout */
                    fwrite(header_buf, 1, hdr_size, outfp);
                    break;
                }

                /* Output any body data already received */
                size_t body_in_buf = header_len - hdr_size;
                if (body_in_buf > 0) {
                    fwrite(body_start, 1, body_in_buf, outfp);
                    body_received += (long)body_in_buf;
                }

                /* Check if we've already received all content */
                if (content_length >= 0 && body_received >= content_length)
                    break;
            }
        } else {
            /* Body data */
            fwrite(buf, 1, (size_t)n, outfp);
            body_received += n;

            if (content_length >= 0 && body_received >= content_length)
                break;
        }
    }

    (void)is_chunked; /* Chunked decoding not implemented yet */

    if (output_file && outfp) {
        fclose(outfp);
        if (verbose)
            fprintf(stderr, "* Saved to %s\n", output_file);
    }

    close(sockfd);

    if (verbose)
        fprintf(stderr, "* Connection closed\n");

    return 0;
}
