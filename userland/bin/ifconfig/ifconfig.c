/*
 * Kiseki OS - ifconfig
 *
 * Display network interface configuration.
 * Reads configuration from kernel via sysctl CTL_NET.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <stdint.h>

/* Kiseki-specific sysctl OIDs for network info */
#define CTL_NET             4
#define NET_KISEKI_IFADDR   100
#define NET_KISEKI_IFMASK   101
#define NET_KISEKI_IFGW     102

static void print_ip(uint32_t ip)
{
    printf("%u.%u.%u.%u",
           (ip >> 24) & 0xFF,
           (ip >> 16) & 0xFF,
           (ip >> 8) & 0xFF,
           ip & 0xFF);
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    uint32_t ip = 0, mask = 0, gw = 0;
    size_t len;
    int name[2];

    /* Get IP address */
    name[0] = CTL_NET;
    name[1] = NET_KISEKI_IFADDR;
    len = sizeof(ip);
    if (sysctl(name, 2, &ip, &len, NULL, 0) < 0) {
        ip = 0;
    }

    /* Get netmask */
    name[1] = NET_KISEKI_IFMASK;
    len = sizeof(mask);
    if (sysctl(name, 2, &mask, &len, NULL, 0) < 0) {
        mask = 0xFFFFFF00;  /* Default /24 */
    }

    /* Get gateway */
    name[1] = NET_KISEKI_IFGW;
    len = sizeof(gw);
    if (sysctl(name, 2, &gw, &len, NULL, 0) < 0) {
        gw = 0;
    }

    /* Calculate broadcast address */
    uint32_t broadcast = (ip & mask) | (~mask);

    /* Print eth0 */
    printf("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n");
    printf("        inet ");
    print_ip(ip);
    printf("  netmask ");
    print_ip(mask);
    printf("  broadcast ");
    print_ip(broadcast);
    printf("\n");
    printf("        ether 52:54:00:12:34:56\n");
    if (gw != 0) {
        printf("        gateway ");
        print_ip(gw);
        printf("\n");
    }
    printf("\n");

    /* Print loopback */
    printf("lo0: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n");
    printf("        inet 127.0.0.1  netmask 255.0.0.0\n");
    printf("        loop  txqueuelen 1000\n");
    printf("\n");

    return 0;
}
