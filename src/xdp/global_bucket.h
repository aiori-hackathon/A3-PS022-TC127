#ifndef GLOBAL_BUCKET_H
#define GLOBAL_BUCKET_H

#include<linux/types.h>
#include<linux/bpf.h>
#include<bpf/bpf_helpers.h>

#define min(a,b) (a>b?b:a)

#define TOKEN_UNIT 1000000000ULL
#define GLOBAL_RATE 1000ULL
#define GLOBAL_BURST 200ULL
#define MAX_CREDIT (GLOBAL_BURST * TOKEN_UNIT)

#define E_TERROR -1
#define E_NO_EXIST -2
#define G_SUCCESS 0
#define G_FAILURE -3

struct global_state {
    struct bpf_spin_lock lock;
    __u64 credit;
    __u64 last_refill_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct global_state);
} global_map SEC(".maps");

static __always_inline void global_bucket_refill_locked(
    struct global_state* global, __u64 now)
{
    if (now <= global->last_refill_ns) {
        return ;
    }

    __u64 t_diff = (now - global->last_refill_ns);
    __u64 missing = (MAX_CREDIT - global->credit);

    __u64 time_to_full = missing / GLOBAL_RATE + 
                                (missing % GLOBAL_RATE != 0);
    if (time_to_full <= t_diff) {
        global->credit = MAX_CREDIT;
        global->last_refill_ns = now;
        return ;
    }

    __u64 refill = t_diff * GLOBAL_RATE;
    global->credit = min(MAX_CREDIT, global->credit + refill);
    global->last_refill_ns = now;

    return ;
}

static __always_inline int global_reserve(__u64 now)
{
    __u32 key = 0;

    struct global_state *global = bpf_map_lookup_elem(&global_map, &key);
    if (!global) {
        return E_NO_EXIST;
    }

    bpf_spin_lock(&global->lock);

    global_bucket_refill_locked(global, now);

    __u64 credits = global->credit;
    if (credits >= TOKEN_UNIT) {
        global->credit -= TOKEN_UNIT;
        bpf_spin_unlock(&global->lock);
        return G_SUCCESS;
    }

    bpf_spin_unlock(&global->lock);

    return G_FAILURE;
}

static __always_inline void global_refund(void)
{
    __u32 key = 0;
    struct global_state *global = bpf_map_lookup_elem(&global_map, &key);
    if (!global) {
        return ;
    }
    bpf_spin_lock(&global->lock);
    if (global->credit >= (MAX_CREDIT - TOKEN_UNIT)) {
        global->credit = MAX_CREDIT;
        bpf_spin_unlock(&global->lock);
        return ;
    }
    global->credit += TOKEN_UNIT;
    bpf_spin_unlock(&global->lock);
    return ;
}
#endif