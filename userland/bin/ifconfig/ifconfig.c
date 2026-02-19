/*
 * Kiseki OS - ifconfig
 *
 * Display network interface configuration.
 * Since Kiseki currently has a single virtio-net interface with
 * hardcoded configuration, this reads from /proc/net/if or
 * simply displays the known configuration.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    /* Kiseki OS currently has a single interface: eth0
     * IP is configured at boot as 10.0.2.15 (QEMU user-mode default) */

    printf("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n");
    printf("        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255\n");
    printf("        ether 52:54:00:12:34:56\n");
    printf("\n");
    printf("lo0: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n");
    printf("        inet 127.0.0.1  netmask 255.0.0.0\n");
    printf("        loop  txqueuelen 1000\n");
    printf("\n");

    return 0;
}
