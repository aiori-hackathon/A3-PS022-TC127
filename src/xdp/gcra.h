#ifndef GCRA_H
#define GCRA_H

#include<linux/types.h>
#include<bpf/bpf_helpers.h>
#include<stdbool.h>

struct source_map_key {
    __u32 saddr;
};

struct source_map_value {
    __u64 tat_ns;
    __u64 packet_seen;
};

static __always_inline __u64 source_read_tat(
    const struct source_map_value *src)
{
#ifdef __BPF__
    return *(const volatile __u64 *)&src->tat_ns;
#else
    return __atomic_load_n(&src->tat_ns, __ATOMIC_RELAXED);
#endif
}

#define NS_PER_SEC 1000000000ULL

#define SOURCE_RATE 100ULL
#define SOURCE_BURST 10ULL

#define INTERVAL_NS (NS_PER_SEC / SOURCE_RATE)
#define TAU_NS ((SOURCE_BURST - 1) * INTERVAL_NS)
#define max(a,b) (a>b?a:b)

#define SOURCE_SUCCESS 0
#define NO_ELIGIBLE -1
#define CAS_RETRY_EXHAUSTED -2

static __always_inline int source_eligible(
    struct source_map_value *src, __u64 now)
{
    __u64 tat = source_read_tat(src);

    if (tat <= now || (tat - now) <= TAU_NS) {
        return SOURCE_SUCCESS;
    }
    return NO_ELIGIBLE;
}

static __always_inline int source_commit(
    struct source_map_value* src, __u64 now)
{
#pragma unroll //for compiler to unroll the loop for performance optimization
//at the cost of slightly larger binary

    for (int attempt = 0; attempt < 4; attempt++) {
        __u64 old = source_read_tat(src);
        int ret;

        if (old > now && (old - now) > TAU_NS) {
            return NO_ELIGIBLE;
        }
        __u64 base = max(now,old);

        if (base > ~0ULL - INTERVAL_NS) {
            return NO_ELIGIBLE;
        }

        __u64 new = base + INTERVAL_NS;

        ret = __sync_bool_compare_and_swap(&src->tat_ns, old, new);
        if (ret == true) {
            return SOURCE_SUCCESS;
        }
    }
    return CAS_RETRY_EXHAUSTED;
}

#endif
