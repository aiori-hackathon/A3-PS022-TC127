
#define _GNU_SOURCE
#include <stdio.h>
#include <pthread.h>
#include "../xdp/gcra.h"

#define THREADS 32

static pthread_barrier_t start_barrier;
static struct source_map_value src = {
    .tat_ns = 0,
    .packet_seen = 0
};

static int results[THREADS];
static int ids[THREADS];

static void *worker(void *arg)
{
    int id = *(int *)arg;

    pthread_barrier_wait(&start_barrier);

    results[id] = source_commit(&src, NS_PER_SEC);
    return NULL;
}

int main(void)
{
    pthread_t threads[THREADS];
    int passed = 0, rate_limited = 0;
    int exhausted = 0, unexpected = 0;

    pthread_barrier_init(&start_barrier, NULL, THREADS + 1);

    for (int i = 0; i < THREADS; i++) {
        ids[i] = i;

        if (pthread_create(&threads[i], NULL, worker, &ids[i]) != 0) {
            fprintf(stderr, "pthread_create failed\n");
            return 1;
        }
    }

    pthread_barrier_wait(&start_barrier);

    for (int i = 0; i < THREADS; i++)
        pthread_join(threads[i], NULL);

    for (int i = 0; i < THREADS; i++) {
        if (results[i] == SOURCE_SUCCESS)
            passed++;
        else if (results[i] == NO_ELIGIBLE)
            rate_limited++;
        else if (results[i] == CAS_RETRY_EXHAUSTED)
            exhausted++;
        else
            unexpected++;
    }

    __u64 actual = __atomic_load_n(&src.tat_ns, __ATOMIC_RELAXED);
    __u64 expected = NS_PER_SEC + (__u64)passed * INTERVAL_NS;

    printf("Success: %d, Rate limited: %d, CAS exhausted: %d, Unexpected: %d\n",
           passed, rate_limited, exhausted, unexpected);

    printf("Final TAT: %llu, Expected: %llu\n",
           (unsigned long long)actual,
           (unsigned long long)expected);

    int ok = (passed >= 1 && passed <= (int)SOURCE_BURST &&
              unexpected == 0 && actual == expected);

    printf("%s\n", ok ? "TEST PASSED" : "TEST FAILED");

    pthread_barrier_destroy(&start_barrier);
    return ok ? 0 : 1;
}
