#include "../xdp/global_bucket.h"

SEC("xdp")
int test_refund(struct xdp_md *ctx)
{
    __u64 now = bpf_ktime_get_ns();

    if (global_reserve(now) != G_SUCCESS)
        return XDP_DROP;

    global_refund();
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";