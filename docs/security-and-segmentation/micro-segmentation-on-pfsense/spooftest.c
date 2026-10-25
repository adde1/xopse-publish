/*
 * spooftest - minimal IPv4/UDP reachability and anti-spoofing test tool
 *
 * Linux build:  cc -std=c11 -O2 -Wall -Wextra -pedantic spooftest.c -o spooftest
 *
 * Usage:
 *   spooftest receive
 *   spooftest send <destination-ip>
 *   sudo spooftest send <destination-ip> <source-ip>
 *
 * Sends one packet per second until Ctrl+C. Each packet uses a different
 * source port (within a 20,000-port cycle). The receiver prints arrivals.
 *
 * Use only on networks you administer or have permission to test.
 */
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define TEST_PORT 39000
#define FIRST_SOURCE_PORT 40000
#define SOURCE_PORT_COUNT 20000
#define MAX_PACKET 256

static volatile sig_atomic_t stopped = 0;

static void interrupt_handler(int unused)
{
    (void)unused;
    stopped = 1;
}

static void setup_signals(void)
{
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = interrupt_handler;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) < 0 ||
        sigaction(SIGTERM, &action, NULL) < 0) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}

static bool parse_ip(const char *text, struct in_addr *ip)
{
    return inet_pton(AF_INET, text, ip) == 1;
}

static const char *ip_string(struct in_addr ip, char buffer[INET_ADDRSTRLEN])
{
    if (!inet_ntop(AF_INET, &ip, buffer, INET_ADDRSTRLEN)) {
        perror("inet_ntop");
        exit(EXIT_FAILURE);
    }
    return buffer;
}

/* Internet checksum, returning a value suitable for assignment to a header. */
static uint16_t checksum(const uint8_t *data, size_t size)
{
    uint32_t sum = 0;
    while (size >= 2) {
        sum += ((uint16_t)data[0] << 8) | data[1];
        data += 2;
        size -= 2;
    }
    if (size) sum += (uint16_t)data[0] << 8;
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return htons((uint16_t)~sum);
}

static int receiver(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    struct sockaddr_in local = {
        .sin_family = AF_INET,
        .sin_port = htons(TEST_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY)
    };
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        perror("bind receiver"); close(fd); return 1;
    }

    setup_signals();
    printf("spooftest: receiving IPv4/UDP on port %d (Ctrl+C to stop)\n", TEST_PORT);
    unsigned long long count = 0;
    while (!stopped) {
        char payload[MAX_PACKET + 1];
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);
        ssize_t n = recvfrom(fd, payload, MAX_PACKET, 0,
                             (struct sockaddr *)&peer, &peer_len);
        if (n < 0) {
            if (errno == EINTR && stopped) break;
            if (errno == EINTR) continue;
            perror("recvfrom"); close(fd); return 1;
        }
        payload[n] = '\0';
        char src[INET_ADDRSTRLEN];
        ++count;
        printf("Received #%llu from %s:%u (%zd bytes)\n",
               count, ip_string(peer.sin_addr, src), ntohs(peer.sin_port), n);
    }
    printf("Total received: %llu\n", count);
    close(fd);
    return 0;
}

/* For an explicit source IP, keep the outgoing interface chosen by the
 * ordinary destination route; otherwise a forged source could change which
 * interface Linux selects and invalidate the intended firewall test. */
static int destination_interface(struct sockaddr_in dst,
                                 char ifname[IF_NAMESIZE],
                                 struct in_addr *actual_source)
{
    int probe = socket(AF_INET, SOCK_DGRAM, 0);
    if (probe < 0) { perror("route probe socket"); return -1; }
    if (connect(probe, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        perror("route probe connect"); close(probe); return -1;
    }
    struct sockaddr_in local;
    socklen_t local_len = sizeof(local);
    if (getsockname(probe, (struct sockaddr *)&local, &local_len) < 0) {
        perror("route probe getsockname"); close(probe); return -1;
    }
    *actual_source = local.sin_addr;
    close(probe);

    struct ifaddrs *all = NULL;
    if (getifaddrs(&all) < 0) { perror("getifaddrs"); return -1; }
    int found = 0;
    for (const struct ifaddrs *it = all; it; it = it->ifa_next) {
        if (!it->ifa_addr || it->ifa_addr->sa_family != AF_INET ||
            !(it->ifa_flags & IFF_UP)) continue;
        const struct sockaddr_in *a = (const struct sockaddr_in *)it->ifa_addr;
        if (a->sin_addr.s_addr != local.sin_addr.s_addr) continue;
        if (strlen(it->ifa_name) >= IF_NAMESIZE) continue;
        strcpy(ifname, it->ifa_name);
        found = 1;
        break;
    }
    freeifaddrs(all);
    if (!found) {
        fprintf(stderr, "Cannot identify the outgoing interface for destination.\n");
        return -1;
    }
    return 0;
}

/* Ordinary send: one fresh UDP socket and an explicitly changing source port. */
static int send_ordinary(struct sockaddr_in dst, uint16_t *next_port,
                         unsigned long long sequence,
                         struct in_addr *actual_source, uint16_t *used_port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket UDP"); return -1; }
    bool bound = false;
    for (int attempt = 0; attempt < SOURCE_PORT_COUNT; ++attempt) {
        uint16_t port = *next_port;
        *next_port = (uint16_t)(FIRST_SOURCE_PORT +
                  (*next_port - FIRST_SOURCE_PORT + 1) % SOURCE_PORT_COUNT);
        struct sockaddr_in local = {
            .sin_family = AF_INET,
            .sin_port = htons(port),
            .sin_addr.s_addr = htonl(INADDR_ANY)
        };
        if (bind(fd, (struct sockaddr *)&local, sizeof(local)) == 0) {
            *used_port = port;
            bound = true;
            break;
        }
        if (errno != EADDRINUSE) { perror("bind UDP source port"); break; }
    }
    if (!bound) { close(fd); return -1; }
    if (connect(fd, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        perror("connect UDP"); close(fd); return -1;
    }
    struct sockaddr_in local;
    socklen_t local_len = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &local_len) < 0) {
        perror("getsockname"); close(fd); return -1;
    }
    *actual_source = local.sin_addr;
    char payload[64];
    int len = snprintf(payload, sizeof(payload), "SPOOFTEST #%llu", sequence);
    ssize_t n = send(fd, payload, (size_t)len, 0);
    if (n != len) { perror("send UDP"); close(fd); return -1; }
    close(fd);
    return 0;
}

/* Forged send: fully formed IPv4/UDP packet, including UDP pseudo-header
 * checksum. Linux fills/recalculates some IPv4 header fields for IP_HDRINCL. */
static int send_forged(int raw_fd, struct sockaddr_in dst,
                       struct in_addr forged_source, uint16_t source_port,
                       unsigned long long sequence)
{
    uint8_t packet[MAX_PACKET] = {0};
    struct iphdr *ip = (struct iphdr *)packet;
    struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct iphdr));
    char payload[64];
    int payload_len = snprintf(payload, sizeof(payload), "SPOOFTEST #%llu", sequence);
    const size_t udp_len = sizeof(struct udphdr) + (size_t)payload_len;
    const size_t packet_len = sizeof(struct iphdr) + udp_len;
    if (packet_len > sizeof(packet)) return -1;

    memcpy(packet + sizeof(struct iphdr) + sizeof(struct udphdr),
           payload, (size_t)payload_len);
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons((uint16_t)packet_len);
    ip->id = htons((uint16_t)sequence);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->saddr = forged_source.s_addr;
    ip->daddr = dst.sin_addr.s_addr;
    ip->check = 0;
    ip->check = checksum(packet, sizeof(struct iphdr));

    udp->source = htons(source_port);
    udp->dest = htons(TEST_PORT);
    udp->len = htons((uint16_t)udp_len);
    udp->check = 0;

    uint8_t pseudo[12 + sizeof(struct udphdr) + sizeof(payload)] = {0};
    memcpy(pseudo, &ip->saddr, 4);
    memcpy(pseudo + 4, &ip->daddr, 4);
    pseudo[9] = IPPROTO_UDP;
    pseudo[10] = (uint8_t)(udp_len >> 8);
    pseudo[11] = (uint8_t)udp_len;
    memcpy(pseudo + 12, udp, udp_len);
    udp->check = checksum(pseudo, 12 + udp_len);
    if (udp->check == 0) udp->check = htons(0xffff);

    ssize_t sent = sendto(raw_fd, packet, packet_len, 0,
                          (struct sockaddr *)&dst, sizeof(dst));
    if (sent != (ssize_t)packet_len) {
        perror("sendto raw IPv4");
        return -1;
    }
    return 0;
}

static int sender(const char *destination_text, const char *source_text)
{
    struct in_addr destination, source;
    if (!parse_ip(destination_text, &destination) ||
        (source_text && !parse_ip(source_text, &source))) {
        fprintf(stderr, "Expected numeric IPv4 addresses.\n");
        return 2;
    }
    struct sockaddr_in dst = {
        .sin_family = AF_INET,
        .sin_port = htons(TEST_PORT),
        .sin_addr = destination
    };
    int raw_fd = -1;
    char iface[IF_NAMESIZE] = {0};
    if (source_text) {
        struct in_addr routed_source;
        if (destination_interface(dst, iface, &routed_source) != 0) return 1;
        raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (raw_fd < 0) {
            perror("raw socket (use sudo or CAP_NET_RAW)");
            return 1;
        }
        if (setsockopt(raw_fd, SOL_SOCKET, SO_BINDTODEVICE,
                       iface, strlen(iface) + 1) < 0) {
            perror("SO_BINDTODEVICE"); close(raw_fd); return 1;
        }
        char ip_buf[INET_ADDRSTRLEN];
        printf("Outgoing interface: %s (normal route source %s)\n",
               iface, ip_string(routed_source, ip_buf));
    }

    char dst_buf[INET_ADDRSTRLEN];
    printf("spooftest: sending IPv4/UDP to %s:%d, 1 packet/second\n",
           ip_string(destination, dst_buf), TEST_PORT);
    if (source_text) printf("Source IP: %s (explicit/raw)\n", source_text);
    else printf("Source IP: selected by operating system (ordinary UDP)\n");
    puts("Press Ctrl+C to stop.");
    setup_signals();

    uint16_t next_port = FIRST_SOURCE_PORT;
    unsigned long long successful = 0;
    int status = 0;
    while (!stopped) {
        uint16_t port;
        struct in_addr actual_source;
        unsigned long long seq = successful + 1;
        int rc;
        if (source_text) {
            port = next_port;
            next_port = (uint16_t)(FIRST_SOURCE_PORT +
                         (next_port - FIRST_SOURCE_PORT + 1) % SOURCE_PORT_COUNT);
            actual_source = source;
            rc = send_forged(raw_fd, dst, source, port, seq);
        } else {
            rc = send_ordinary(dst, &next_port, seq, &actual_source, &port);
        }
        if (rc != 0) { status = 1; break; }
        ++successful;
        char src_buf[INET_ADDRSTRLEN];
        printf("Sent #%llu: %s:%u -> %s:%d\n",
               successful, ip_string(actual_source, src_buf), port,
               destination_text, TEST_PORT);

        struct timespec remaining = {.tv_sec = 1, .tv_nsec = 0};
        while (!stopped && nanosleep(&remaining, &remaining) < 0) {
            if (errno != EINTR) { perror("nanosleep"); status = 1; stopped = 1; }
        }
    }
    printf("Total sent: %llu\n", successful);
    if (raw_fd >= 0) close(raw_fd);
    return status;
}

static void usage(const char *program)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s receive\n"
            "  %s send <destination-ip>\n"
            "  sudo %s send <destination-ip> <forged-source-ip>\n\n"
            "Explicit source-ip uses raw IPv4 packets (requires sudo/CAP_NET_RAW).\n",
            program, program, program);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc == 2 && strcmp(argv[1], "receive") == 0) return receiver();
    if ((argc == 3 || argc == 4) && strcmp(argv[1], "send") == 0)
        return sender(argv[2], argc == 4 ? argv[3] : NULL);
    usage(argv[0]);
    return 2;
}
