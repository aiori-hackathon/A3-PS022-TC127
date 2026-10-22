#include "../xdp/global_bucket.h"

SEC("xdp")
int test_global(struct xdp_md *ctx)
{
    __u64 now = bpf_ktime_get_ns();

    int ret = global_reserve(now);

    if (ret == G_SUCCESS)
        return XDP_PASS;

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
