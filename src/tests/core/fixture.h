#ifndef BYTEGUARD_FIXTURE_H
#define BYTEGUARD_FIXTURE_H

#include <stddef.h>
#include <stdint.h>
#include <bpf/libbpf.h>

#define BG_TOKEN_UNIT 1000000000ULL
#define BG_MAX_CREDIT (200ULL * BG_TOKEN_UNIT)
#define BG_INTERVAL_NS 10000000ULL
#define BG_START_NS 1000000000ULL

enum {
    BG_DNS_QUERIES = 0,
    BG_SOURCE_HIT = 1,
    BG_SOURCE_INSERT = 2,
    BG_INSERT_RACE = 3,
    BG_MAP_ERROR = 4,
    BG_PACKET_DROP = 5,
};

struct bg_source_value {
    uint64_t tat_ns;
    uint64_t packet_seen;
};

/* Mirrors the 24-byte BPF map value layout: spinlock, padding, credit, time. */
struct bg_global_value {
    uint32_t lock;
    uint32_t padding;
    uint64_t credit;
    uint64_t last_refill_ns;
};

struct fixture {
    struct bpf_object *obj;
    int prog_fd;
    int source_fd;
    int global_fd;
    int stats_fd;
    int clock_fd;
    int fault_fd;
};

int fixture_open(struct fixture *f, const char *object_path,
                 uint64_t now_ns, uint64_t credit);
void fixture_close(struct fixture *f);
int fixture_set_clock(struct fixture *f, uint64_t now_ns);
int fixture_set_faults(struct fixture *f, uint32_t mask);
int fixture_set_global(struct fixture *f, uint64_t credit, uint64_t last_ns);
int fixture_get_global(struct fixture *f, struct bg_global_value *value);
int fixture_get_source(struct fixture *f, uint32_t network_addr,
                       struct bg_source_value *value);
int fixture_run(struct fixture *f, const void *packet, size_t len,
                uint32_t *action);
int fixture_get_stat(struct fixture *f, uint32_t index, uint64_t *count);

#endif
