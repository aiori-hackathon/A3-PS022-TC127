#include <stdio.h>
#include "../xdp/gcra.h"

int main(void)
{
    struct source_map_value src = {
        .tat_ns = 0,
        .packet_seen = 0
    };

    __u64 now = NS_PER_SEC;
    int failures = 0;

    printf("Test 1: 11 packets at the same instant\n");
    for (int i = 1; i <= 11; i++) {
        int ret = source_commit(&src, now);
        int expected = ((unsigned long long)i <= SOURCE_BURST)
                       ? SOURCE_SUCCESS : NO_ELIGIBLE;

        printf("packet %2d: %s, tat_ns=%llu\n",
               i, ret == SOURCE_SUCCESS ? "PASS" : "DROP",
               (unsigned long long)src.tat_ns);

        if (ret != expected)
            failures++;
    }

    if (src.tat_ns != now + SOURCE_BURST * INTERVAL_NS)
        failures++;

    printf("\nTest 2: advance time by 50 ms\n");
    now += 50000000ULL;

    for (int i = 1; i <= 6; i++) {
        int ret = source_commit(&src, now);
        int expected = (i <= 5) ? SOURCE_SUCCESS : NO_ELIGIBLE;

        printf("packet %2d: %s, tat_ns=%llu\n",
               i, ret == SOURCE_SUCCESS ? "PASS" : "DROP",
               (unsigned long long)src.tat_ns);

        if (ret != expected)
            failures++;
    }

    printf("\n%s (%d unexpected results)\n",
           failures == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           failures);

    return failures == 0 ? 0 : 1;
}
