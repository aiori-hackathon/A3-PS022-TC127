#include "packets.h"

#include <arpa/inet.h>
#include <string.h>

static void write_be16(uint8_t *p, uint16_t n)
{
    p[0] = (uint8_t)(n >> 8);
    p[1] = (uint8_t)n;
}

static uint16_t ipv4_checksum(const uint8_t *p, size_t bytes)
{
    uint32_t sum = 0;
    for (size_t i = 0; i < bytes; i += 2)
        sum += ((uint32_t)p[i] << 8) | p[i + 1];
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

int packet_dns_query(struct bg_packet *p, const char *source_ip)
{
    static const uint8_t question[] = {
        7, 'e','x','a','m','p','l','e', 3, 'c','o','m', 0,
        0, 1, 0, 1 /* A IN */
    };
    struct in_addr src, dst;
    if (inet_pton(AF_INET, source_ip, &src) != 1 ||
        inet_pton(AF_INET, "10.10.0.2", &dst) != 1)
        return -1;
    memset(p, 0, sizeof(*p));
    p->source_addr = src.s_addr;
    p->len = BG_DNS_OFFSET + 12 + sizeof(question);

    uint8_t *e = p->bytes;
    /* Ethernet src, dst and IPv4 ethertype. */
    const uint8_t eth[] = {
        0x02,0,0,0,0,2, 0x02,0,0,0,0,1, 0x08,0x00
    };
    memcpy(e, eth, sizeof(eth));

    uint8_t *ip = e + BG_ETH_LEN;
    ip[0] = 0x45;                         /* IPv4 + 5-word header */
    write_be16(ip + 2, (uint16_t)(p->len - BG_ETH_LEN));
    ip[8] = 64;
    ip[9] = 17;                          /* UDP */
    memcpy(ip + 12, &src.s_addr, 4);
    memcpy(ip + 16, &dst.s_addr, 4);
    write_be16(ip + 10, ipv4_checksum(ip, BG_IP_LEN));

    uint8_t *udp = ip + BG_IP_LEN;
    write_be16(udp + 0, 12345);
    write_be16(udp + 2, 53);
    write_be16(udp + 4, (uint16_t)(p->len - BG_ETH_LEN - BG_IP_LEN));
    /* Zero UDP checksum is valid for IPv4. */

    uint8_t *dns = udp + BG_UDP_LEN;
    write_be16(dns + 0, 0x1234);         /* DNS ID */
    write_be16(dns + 2, 0x0100);         /* Standard query, RD */
    write_be16(dns + 4, 1);              /* One question */
    memcpy(dns + 12, question, sizeof(question));
    return 0;
}

void packet_set_udp_dport(struct bg_packet *p, uint16_t port)
{
    write_be16(p->bytes + BG_ETH_LEN + BG_IP_LEN + 2, port);
}

void packet_set_dns_response(struct bg_packet *p)
{
    write_be16(p->bytes + BG_DNS_OFFSET + 2, 0x8180);
}
