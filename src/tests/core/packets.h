#ifndef BYTEGUARD_PACKETS_H
#define BYTEGUARD_PACKETS_H

#include <stddef.h>
#include <stdint.h>

#define BG_ETH_LEN 14
#define BG_IP_LEN 20
#define BG_UDP_LEN 8
#define BG_DNS_OFFSET (BG_ETH_LEN + BG_IP_LEN + BG_UDP_LEN)

struct bg_packet {
    uint8_t bytes[128];
    size_t len;
    uint32_t source_addr;  /* Same in-memory representation as ip->saddr */
};

int packet_dns_query(struct bg_packet *p, const char *source_ip);
void packet_set_udp_dport(struct bg_packet *p, uint16_t port);
void packet_set_dns_response(struct bg_packet *p);

#endif
