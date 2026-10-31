#ifndef BYTEGUARD_TEST_CLOCK_BPF_H
#define BYTEGUARD_TEST_CLOCK_BPF_H

/* Compiled only when BYTEGUARD_TEST is defined. The production build has
 * no test_clock_map and continues using bpf_ktime_get_ns(). */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} test_clock_map SEC(".maps");

static __always_inline __u64 byteguard_test_now_ns(void)
{
    __u32 zero = 0;
    __u64 *now = bpf_map_lookup_elem(&test_clock_map, &zero);
    return now ? *now : bpf_ktime_get_ns();
}
#endif
