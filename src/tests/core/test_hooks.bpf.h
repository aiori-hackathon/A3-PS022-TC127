#ifndef BYTEGUARD_TEST_HOOKS_BPF_H
#define BYTEGUARD_TEST_HOOKS_BPF_H

#ifndef BYTEGUARD_TEST
#error "The fault-injection hooks must never be used in production builds"
#endif

/* Test-only fault injection: triggers paths difficult to reach deterministically
 * with BPF_PROG_TEST_RUN. These are NOT claims of real concurrent races. */
#define BG_TEST_COMMIT_INTERLEAVE (1U << 0)
#define BG_TEST_INSERT_EEXIST    (1U << 1)
#define BG_TEST_INSERT_BLOCKED   (1U << 2)
#define BG_TEST_INSERT_ERROR     (1U << 3)

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} test_fault_map SEC(".maps");

static __always_inline __u32 bg_test_flags(void)
{
    __u32 zero = 0;
    __u32 *flags = bpf_map_lookup_elem(&test_fault_map, &zero);
    return flags ? *flags : 0;
}

/* Simulate a competing commit AFTER the read-only eligibility check and
 * global reservation. The real source_commit() then rechecks GCRA and rejects,
 * executing the real global_refund() failure branch. */
static __always_inline void bg_test_before_source_commit(
    struct source_map_value *src, __u64 now)
{
    if (bg_test_flags() & BG_TEST_COMMIT_INTERLEAVE)
        src->tat_ns = now + 11ULL * INTERVAL_NS;
}

/* Inject a source between the initial NULL lookup and BPF_NOEXIST insertion.
 * Value is not counted as a real admitted packet; it simply forces -EEXIST.
 * The normal BPF_NOEXIST operation and all follow-up code still run. */
static __always_inline long bg_test_source_insert(
    void *map, const struct source_map_key *key,
    const struct source_map_value *new_value, __u64 now)
{
    __u32 flags = bg_test_flags();
    if (flags & BG_TEST_INSERT_ERROR)
        return -ENOMEM;

    if (flags & BG_TEST_INSERT_EEXIST) {
        struct source_map_value competing = {
            .tat_ns = (flags & BG_TEST_INSERT_BLOCKED)
                        ? now + 11ULL * INTERVAL_NS : now,
            .packet_seen = 0,
        };
        bpf_map_update_elem(map, key, &competing, BPF_NOEXIST);
    }
    return bpf_map_update_elem(map, key, new_value, BPF_NOEXIST);
}

#endif
