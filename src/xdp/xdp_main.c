#include<linux/bpf.h>
#include<linux/if_ether.h>
#include<bpf/bpf_helpers.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include<linux/errno.h>

#define IPV4_MF       0x2000
#define IPV4_OFFMASK  0x1FFF
#define MAX_SOURCE    1024

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

#include"gcra.h"
#include"global_bucket.h"

enum {
    DNS_QUERIES,
    SOURCE_HIT,
    SOURCE_INSERT,
    INSERT_RACE,
    MAP_ERROR,
    PACKET_DROP,
    STAT_COUNT
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_SOURCE);
    __type(key, struct source_map_key);
    __type(value, struct source_map_value);
} source_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_COUNT);
    __type(key, __u32);
    __type(value, __u64);
} stat_map SEC(".maps");

static __always_inline void count_stat(__u32 id) {
    __u64 *stat_value = bpf_map_lookup_elem(&stat_map, &id);
    if (stat_value) {
        (*stat_value)++;
    }
    return ;
}

SEC("xdp")
int xdp_main(struct xdp_md *ctx){
    long ret;
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
    count_stat(DNS_QUERIES);
    struct source_map_key key = {
        .saddr = ip->saddr
    };
    struct source_map_value *value = bpf_map_lookup_elem(&source_map, &key);
    if (value) {
        count_stat(SOURCE_HIT);
        __u64 now = bpf_ktime_get_ns();
        int ret = source_eligible(value, now);
        if (ret != SOURCE_SUCCESS) {
            count_stat(PACKET_DROP);
            return XDP_DROP;
        }
        ret = global_reserve(now);
        if (ret != G_SUCCESS) {
            count_stat(PACKET_DROP);
            return XDP_DROP;
        }
        ret = source_commit(value, now);
        if (ret != SOURCE_SUCCESS) {
            global_refund();
            count_stat(PACKET_DROP);
            return XDP_DROP;
        }
        __sync_add_and_fetch(&value->packet_seen, 1);
    }
    else {
        __u64 now = bpf_ktime_get_ns();
        struct source_map_value new_value = {
            .packet_seen = 1,
            .tat_ns = now + INTERVAL_NS
        };
        int ret = global_reserve(now);
        if (ret != G_SUCCESS) {
            count_stat(PACKET_DROP);
            return XDP_DROP;
        }
        ret = bpf_map_update_elem(&source_map, &key, &new_value, BPF_NOEXIST);
        if (ret == 0) {
            count_stat(SOURCE_INSERT);
        }
        else if (ret == -EEXIST) {
            count_stat(INSERT_RACE);
            value = bpf_map_lookup_elem(&source_map, &key);
            if (!value) {
                global_refund();
                count_stat(MAP_ERROR);
                count_stat(PACKET_DROP);
                return XDP_DROP;
            }
            ret = source_commit(value, now);
            if (ret != SOURCE_SUCCESS) {
                global_refund();
                count_stat(PACKET_DROP);
                return XDP_DROP;
            }    
            __sync_add_and_fetch(&value->packet_seen, 1);
        }
        else if (ret != 0) {
            DEBUG_PRINT("ERROR in updating source map");
            global_refund();
            count_stat(MAP_ERROR);
            count_stat(PACKET_DROP);
            return XDP_DROP;
        }
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
