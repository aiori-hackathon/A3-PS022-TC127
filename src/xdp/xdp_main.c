#include<linux/bpf.h>
#include<linux/if_ether.h>
#include<bpf/bpf_helpers.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>

#define IPV4_MF       0x2000
#define IPV4_OFFMASK  0x1FFF

#ifdef DEBUG
#define DEBUG_PRINT(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...) do {} while (0)
#endif

struct dns_hdr {
    __be16 id;
    __be16 flags;
    __be16 qdcount;
    __be16 ancount;
    __be16 nscount;
    __be16 arcount;
} __attribute__((packed));

SEC("xdp")
int xdp_main(struct xdp_md *ctx){
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth +1) > data_end) {
        DEBUG_PRINT("invalid lenght of ethernet hdr");
        return XDP_PASS;
    }
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        DEBUG_PRINT("NOT AN ip papcket");
        return XDP_PASS;
    }
    struct iphdr *ip = (struct iphdr*)(void *)(eth+1);
    if((void *)(ip+1) > data_end) {
        DEBUG_PRINT("invalid lenght ipphdr");
        return XDP_PASS;
    }
    if (ip->version != 4)
        return XDP_PASS;

    int ihl = ip->ihl;
    __u16 ip_len = bpf_ntohs(ip->tot_len);
    __u32 hdr_len = ihl * 4;
    if (ip_len < hdr_len) 
        return XDP_PASS;
    if(ihl < 5 || (void *)((char *)(ip) + hdr_len) > data_end) {
        DEBUG_PRINT("invalid length of iphdr after ihl check");
        return XDP_PASS;
    }
    void *ip_end = (void *)((char *)ip + ip_len);
    if (ip_end > data_end)
        return XDP_PASS;
    __u16 frag = bpf_ntohs(ip->frag_off);

    if (frag & (IPV4_MF | IPV4_OFFMASK)) { //Fragmented packet
        DEBUG_PRINT("Fragment packet");
        return XDP_PASS;
    }
    if (ip->protocol != 17) {
        DEBUG_PRINT("NOT an udp packet");
        return XDP_PASS;
    }
    if (ip_len - hdr_len < sizeof(struct udphdr))
        return XDP_PASS;
    
    struct udphdr *udp = (struct udphdr*)((char *)(ip) + hdr_len);
    if ((void *)(udp +1) > data_end) {
        DEBUG_PRINT("invalid lenght udphdr");
        return XDP_PASS;
    }
    __u16 udp_len = bpf_ntohs(udp->len);
    if (udp_len < 8 || udp_len != (ip_len - hdr_len)) {
        DEBUG_PRINT("invalid lenght semantics between ip and udp");
        return XDP_PASS;
    }
    DEBUG_PRINT("UDP packet arrived");
    __u16 dest_port = udp->dest;
    if (dest_port != bpf_htons(53)) {
        DEBUG_PRINT("not dns packet");
        return XDP_PASS;
    }
    if (udp_len < sizeof(struct udphdr) + sizeof(struct dns_hdr)) {
        DEBUG_PRINT("DNS header too short");
        return XDP_PASS;
    }
    struct dns_hdr *dns = (void *)(udp + 1);
    if ((void *)(dns + 1) > data_end) {
        DEBUG_PRINT("Invalid Dns header lenght");
        return XDP_PASS;
    }
    __u16 flags = bpf_ntohs(dns->flags);
    __u16 qdcount = bpf_ntohs(dns->qdcount);
    if (flags & 0x8000) {
        DEBUG_PRINT("DNS response");
        return XDP_PASS;
    }
    if ((flags & 0x7800) != 0) {
        DEBUG_PRINT("Non-standard DNS operation");
        return XDP_PASS;
    }
    if (qdcount == 0) {
        DEBUG_PRINT("DNS queery without question");
        return XDP_PASS;
    }
    DEBUG_PRINT("DNS querry identified");
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
