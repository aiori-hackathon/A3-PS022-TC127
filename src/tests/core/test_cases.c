#include "test_cases.h"
#include "fixture.h"
#include "packets.h"

#include <arpa/inet.h>
#include <linux/bpf.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* These must match test_hooks.bpf.h in the test-only XDP object. */
#define BG_TEST_COMMIT_INTERLEAVE (1U << 0)
#define BG_TEST_INSERT_EEXIST    (1U << 1)
#define BG_TEST_INSERT_BLOCKED   (1U << 2)
#define BG_TEST_INSERT_ERROR     (1U << 3)

#define CHECK(c) do {                                                   \
    if (!(c)) {                                                         \
        fprintf(stderr, "    assertion failed: %s (%s:%d)\n",          \
                #c, __FILE__, __LINE__);                                \
        goto out;                                                       \
    }                                                                   \
} while (0)

#define FRESH(f, path, balance)                                          \
    CHECK(fixture_open(&(f), (path), BG_START_NS, (balance)) == 0)

#define SEND(f, p, expected) do {                                        \
    uint32_t action_ = 99;                                              \
    CHECK(fixture_run(&(f), (p).bytes, (p).len, &action_) == 0);          \
    if (action_ != (expected)) {                                         \
        fprintf(stderr, "    expected XDP action %u, got %u\n",         \
                (unsigned)(expected), (unsigned)action_);               \
        goto out;                                                       \
    }                                                                   \
} while (0)

static int get_source(struct fixture *f, const struct bg_packet *p,
                      struct bg_source_value *v)
{
    return fixture_get_source(f, p->source_addr, v);
}

static int test_parser(const char *path)
{
    struct fixture f = {0};
    struct bg_packet p;
    struct bg_global_value global;
    uint64_t dns_count = 999;
    int ok = 0;
    FRESH(f, path, BG_MAX_CREDIT);
    CHECK(packet_dns_query(&p, "10.10.0.1") == 0);

    size_t original_len = p.len;
    p.len = BG_ETH_LEN;                 /* Valid Ethernet, missing IPv4 */
    SEND(f, p, XDP_PASS);
    p.len = original_len;

    packet_set_udp_dport(&p, 80);      /* Non-DNS traffic */
    SEND(f, p, XDP_PASS);
    packet_set_udp_dport(&p, 53);

    packet_set_dns_response(&p);       /* DNS responses bypass queries */
    SEND(f, p, XDP_PASS);
    CHECK(packet_dns_query(&p, "10.10.0.1") == 0);

    p.bytes[BG_DNS_OFFSET + 4] = 0;   /* DNS QDCOUNT=0: parser bypass */
    p.bytes[BG_DNS_OFFSET + 5] = 0;
    SEND(f, p, XDP_PASS);
    CHECK(packet_dns_query(&p, "10.10.0.1") == 0);

    p.bytes[BG_ETH_LEN + 6] = 0x20;  /* Fragmented IPv4 */
    p.bytes[BG_ETH_LEN + 7] = 0;
    SEND(f, p, XDP_PASS);
    CHECK(packet_dns_query(&p, "10.10.0.1") == 0);

    p.bytes[BG_ETH_LEN + BG_IP_LEN + 4] = 0; /* Invalid UDP length */
    p.bytes[BG_ETH_LEN + BG_IP_LEN + 5] = 7;
    SEND(f, p, XDP_PASS);

    CHECK(fixture_get_global(&f, &global) == 0);
    CHECK(global.credit == BG_MAX_CREDIT);
    CHECK(fixture_get_stat(&f, BG_DNS_QUERIES, &dns_count) == 0);
    CHECK(dns_count == 0);
    ok = 1;
out:
    fixture_close(&f);
    return ok;
}

static int test_new_source(const char *path)
{
    struct fixture f = {0};
    struct bg_packet p;
    struct bg_global_value global;
    struct bg_source_value source;
    uint64_t count = 0;
    int ok = 0;
    FRESH(f, path, BG_MAX_CREDIT);
    CHECK(packet_dns_query(&p, "10.10.0.1") == 0);
    SEND(f, p, XDP_PASS);
    CHECK(get_source(&f, &p, &source) == 0);
    CHECK(source.packet_seen == 1);
    CHECK(source.tat_ns == BG_START_NS + BG_INTERVAL_NS);
    CHECK(fixture_get_global(&f, &global) == 0);
    CHECK(global.credit == BG_MAX_CREDIT - BG_TOKEN_UNIT);
    CHECK(fixture_get_stat(&f, BG_SOURCE_INSERT, &count) == 0);
    CHECK(count == 1);
    ok = 1;
out:
    fixture_close(&f);
    return ok;
}

static int test_existing_source(const char *path)
{
    struct fixture f = {0};
    struct bg_packet p;
    struct bg_global_value global;
    struct bg_source_value source;
    int ok = 0;
    FRESH(f, path, BG_MAX_CREDIT);
    CHECK(packet_dns_query(&p, "10.10.0.1") == 0);
    SEND(f, p, XDP_PASS);
    SEND(f, p, XDP_PASS);
    CHECK(get_source(&f, &p, &source) == 0);
    CHECK(source.packet_seen == 2);
    CHECK(source.tat_ns == BG_START_NS + 2 * BG_INTERVAL_NS);
    CHECK(fixture_get_global(&f, &global) == 0);
    CHECK(global.credit == BG_MAX_CREDIT - 2 * BG_TOKEN_UNIT);
    ok = 1;
out:
    fixture_close(&f);
    return ok;
}

static int test_source_burst(const char *path)
{
    struct fixture f = {0};
    struct bg_packet p;
    struct bg_global_value global;
    struct bg_source_value source;
    uint64_t drops = 0;
    int ok = 0;
    FRESH(f, path, BG_MAX_CREDIT);
    CHECK(packet_dns_query(&p, "10.10.0.1") == 0);
    for (int i = 0; i < 10; i++)
        SEND(f, p, XDP_PASS);
    SEND(f, p, XDP_DROP);
    CHECK(get_source(&f, &p, &source) == 0);
    CHECK(source.packet_seen == 10);
    CHECK(source.tat_ns == BG_START_NS + 10 * BG_INTERVAL_NS);
    CHECK(fixture_get_global(&f, &global) == 0);
    CHECK(global.credit == BG_MAX_CREDIT - 10 * BG_TOKEN_UNIT);
    CHECK(fixture_get_stat(&f, BG_PACKET_DROP, &drops) == 0);
    CHECK(drops == 1);
    ok = 1;
out:
    fixture_close(&f);
    return ok;
}

static int test_source_recovery(const char *path)
{
    struct fixture f = {0};
    struct bg_packet p;
    struct bg_source_value source;
    int ok = 0;
    FRESH(f, path, BG_MAX_CREDIT);
    CHECK(packet_dns_query(&p, "10.10.0.1") == 0);
    for (int i = 0; i < 10; i++)
        SEND(f, p, XDP_PASS);
    SEND(f, p, XDP_DROP);
    CHECK(fixture_set_clock(&f, BG_START_NS + 50000000ULL) == 0);
    for (int i = 0; i < 5; i++)
        SEND(f, p, XDP_PASS);
    SEND(f, p, XDP_DROP);
    CHECK(get_source(&f, &p, &source) == 0);
    CHECK(source.packet_seen == 15);
    ok = 1;
out:
    fixture_close(&f);
    return ok;
}

static int test_global_exhaustion(const char *path)
{
    struct fixture f = {0};
    struct bg_packet p;
    struct bg_global_value global;
    uint64_t inserted = 0, drops = 0;
    int ok = 0;
    FRESH(f, path, 3 * BG_TOKEN_UNIT);
    for (int i = 1; i <= 5; i++) {
        char ip[32];
        snprintf(ip, sizeof(ip), "10.20.0.%d", i);
        CHECK(packet_dns_query(&p, ip) == 0);
        if (i <= 3)
            SEND(f, p, XDP_PASS);
        else
            SEND(f, p, XDP_DROP);
    }
    CHECK(fixture_get_global(&f, &global) == 0);
    CHECK(global.credit == 0);
    CHECK(fixture_get_stat(&f, BG_SOURCE_INSERT, &inserted) == 0);
    CHECK(fixture_get_stat(&f, BG_PACKET_DROP, &drops) == 0);
    CHECK(inserted == 3 && drops == 2);
    ok = 1;
out:
    fixture_close(&f);
    return ok;
}

static int test_global_refill(const char *path)
{
    struct fixture f = {0};
    struct bg_packet p;
    struct bg_global_value global;
    int ok = 0;
    FRESH(f, path, 0);
    CHECK(packet_dns_query(&p, "10.20.0.1") == 0);
    SEND(f, p, XDP_DROP);
    /* GLOBAL_RATE=1000/s -> 5 ms regenerates exactly five tokens. */
    CHECK(fixture_set_clock(&f, BG_START_NS + 5000000ULL) == 0);
    for (int i = 1; i <= 6; i++) {
        char ip[32];
        snprintf(ip, sizeof(ip), "10.20.0.%d", i);
        CHECK(packet_dns_query(&p, ip) == 0);
        if (i <= 5)
            SEND(f, p, XDP_PASS);
        else
            SEND(f, p, XDP_DROP);
    }
    CHECK(fixture_get_global(&f, &global) == 0);
    CHECK(global.credit == 0);
    ok = 1;
out:
    fixture_close(&f);
    return ok;
}

static int test_source_rotation(const char *path)
{
    struct fixture f = {0};
    struct bg_packet p;
    struct bg_global_value global;
    uint64_t inserts = 0, drops = 0;
    int ok = 0;
    FRESH(f, path, BG_MAX_CREDIT);
    for (int i = 0; i < 300; i++) {
        char ip[32];
        snprintf(ip, sizeof(ip), "10.20.%d.%d", i / 254, i % 254 + 1);
        CHECK(packet_dns_query(&p, ip) == 0);
        if (i < 200)
            SEND(f, p, XDP_PASS);
        else
            SEND(f, p, XDP_DROP);
    }
    CHECK(fixture_get_stat(&f, BG_SOURCE_INSERT, &inserts) == 0);
    CHECK(fixture_get_stat(&f, BG_PACKET_DROP, &drops) == 0);
    CHECK(fixture_get_global(&f, &global) == 0);
    CHECK(inserts == 200 && drops == 100 && global.credit == 0);
    ok = 1;
out:
    fixture_close(&f);
    return ok;
}

/* Deterministic branch coverage using test-only hooks. These prove actual
 * production failure branches run, but do not prove that a real race occurs. */
static int test_refund_after_commit_change(const char *path)
{
    struct fixture f = {0};
    struct bg_packet p;
    struct bg_global_value before, after;
    struct bg_source_value source;
    uint64_t drops = 0;
    int ok = 0;
    FRESH(f, path, BG_MAX_CREDIT);
    CHECK(packet_dns_query(&p, "10.10.0.1") == 0);
    SEND(f, p, XDP_PASS);
    CHECK(fixture_get_global(&f, &before) == 0);
    CHECK(fixture_set_faults(&f, BG_TEST_COMMIT_INTERLEAVE) == 0);
    SEND(f, p, XDP_DROP);
    CHECK(fixture_get_global(&f, &after) == 0);
    CHECK(before.credit == after.credit);  /* reserve + refund */
    CHECK(get_source(&f, &p, &source) == 0);
    CHECK(source.packet_seen == 1);
    CHECK(source.tat_ns == BG_START_NS + 11 * BG_INTERVAL_NS);
    CHECK(fixture_get_stat(&f, BG_PACKET_DROP, &drops) == 0);
    CHECK(drops == 1);
    ok = 1;
out:
    fixture_close(&f);
    return ok;
}

static int test_injected_insert_race(const char *path)
{
    struct fixture f = {0};
    struct bg_packet p;
    struct bg_source_value source;
    struct bg_global_value global;
    uint64_t races = 0, inserts = 0;
    int ok = 0;
    FRESH(f, path, BG_MAX_CREDIT);
    CHECK(fixture_set_faults(&f, BG_TEST_INSERT_EEXIST) == 0);
    CHECK(packet_dns_query(&p, "10.10.0.1") == 0);
    SEND(f, p, XDP_PASS);
    CHECK(get_source(&f, &p, &source) == 0);
    CHECK(source.packet_seen == 1);
    CHECK(source.tat_ns == BG_START_NS + BG_INTERVAL_NS);
    CHECK(fixture_get_global(&f, &global) == 0);
    CHECK(global.credit == BG_MAX_CREDIT - BG_TOKEN_UNIT);
    CHECK(fixture_get_stat(&f, BG_INSERT_RACE, &races) == 0);
    CHECK(fixture_get_stat(&f, BG_SOURCE_INSERT, &inserts) == 0);
    CHECK(races == 1 && inserts == 0);
    ok = 1;
out:
    fixture_close(&f);
    return ok;
}

static int test_insert_race_refund(const char *path)
{
    struct fixture f = {0};
    struct bg_packet p;
    struct bg_source_value source;
    struct bg_global_value global;
    uint64_t races = 0, drops = 0;
    int ok = 0;
    FRESH(f, path, BG_MAX_CREDIT);
    CHECK(fixture_set_faults(&f,
          BG_TEST_INSERT_EEXIST | BG_TEST_INSERT_BLOCKED) == 0);
    CHECK(packet_dns_query(&p, "10.10.0.1") == 0);
    SEND(f, p, XDP_DROP);
    CHECK(get_source(&f, &p, &source) == 0);
    CHECK(source.packet_seen == 0);  /* Synthetic existing entry */
    CHECK(fixture_get_global(&f, &global) == 0);
    CHECK(global.credit == BG_MAX_CREDIT); /* Full refund */
    CHECK(fixture_get_stat(&f, BG_INSERT_RACE, &races) == 0);
    CHECK(fixture_get_stat(&f, BG_PACKET_DROP, &drops) == 0);
    CHECK(races == 1 && drops == 1);
    ok = 1;
out:
    fixture_close(&f);
    return ok;
}

static int test_insert_error_refund(const char *path)
{
    struct fixture f = {0};
    struct bg_packet p;
    struct bg_source_value source;
    struct bg_global_value global;
    uint64_t errors = 0, drops = 0;
    int ok = 0;
    FRESH(f, path, BG_MAX_CREDIT);
    CHECK(fixture_set_faults(&f, BG_TEST_INSERT_ERROR) == 0);
    CHECK(packet_dns_query(&p, "10.10.0.1") == 0);
    SEND(f, p, XDP_DROP);
    CHECK(get_source(&f, &p, &source) != 0);
    CHECK(fixture_get_global(&f, &global) == 0);
    CHECK(global.credit == BG_MAX_CREDIT);
    CHECK(fixture_get_stat(&f, BG_MAP_ERROR, &errors) == 0);
    CHECK(fixture_get_stat(&f, BG_PACKET_DROP, &drops) == 0);
    CHECK(errors == 1 && drops == 1);
    ok = 1;
out:
    fixture_close(&f);
    return ok;
}

/* LRU turnover; source should be recreated with fresh GCRA state. This is
 * intentionally a LIMITATION test, not a claim that the source stays blocked. */
static int test_lru_eviction(const char *path, unsigned sources)
{
    struct fixture f = {0};
    struct bg_packet p, first;
    struct bg_source_value source;
    struct bg_global_value global;
    uint64_t inserts = 0;
    int ok = 0;
    FRESH(f, path, BG_MAX_CREDIT);
    CHECK(packet_dns_query(&first, "10.50.0.1") == 0);
    for (unsigned i = 0; i < sources; i++) {
        char ip[32];
        snprintf(ip, sizeof(ip), "10.50.%u.%u", i / 254, i % 254 + 1);
        CHECK(packet_dns_query(&p, ip) == 0);
        /* 1ms advances refill by one global token per packet. */
        CHECK(fixture_set_clock(&f, BG_START_NS + (uint64_t)i * 1000000ULL) == 0);
        SEND(f, p, XDP_PASS);
    }
    CHECK(fixture_get_stat(&f, BG_SOURCE_INSERT, &inserts) == 0);
    CHECK(inserts == sources);
    CHECK(get_source(&f, &first, &source) != 0);  /* evicted */
    CHECK(fixture_set_clock(&f,
          BG_START_NS + (uint64_t)sources * 1000000ULL) == 0);
    SEND(f, first, XDP_PASS);
    CHECK(get_source(&f, &first, &source) == 0);
    CHECK(source.packet_seen == 1);              /* fresh history */
    CHECK(fixture_get_stat(&f, BG_SOURCE_INSERT, &inserts) == 0);
    CHECK(inserts == sources + 1);
    CHECK(fixture_get_global(&f, &global) == 0);
    CHECK(global.credit <= BG_MAX_CREDIT);
    printf("    LRU churn=%u; first source evicted and recreated\n", sources);
    ok = 1;
out:
    fixture_close(&f);
    return ok;
}

struct worker_args {
    struct fixture *fixture;
    const struct bg_packet *packet;
    atomic_int *go;
    uint32_t result;
    int error;
};

static void *worker(void *arg)
{
    struct worker_args *a = arg;
    while (!atomic_load_explicit(a->go, memory_order_acquire))
        ;
    a->error = fixture_run(a->fixture, a->packet->bytes,
                           a->packet->len, &a->result);
    return NULL;
}

static int test_concurrent_accounting(const char *path, unsigned workers,
                                      unsigned rounds)
{
    int all_ok = 1;
    for (unsigned round = 0; round < rounds; round++) {
        struct fixture f = {0};
        struct bg_packet p;
        struct bg_source_value source;
        struct bg_global_value global;
        pthread_t *ids = calloc(workers, sizeof(*ids));
        struct worker_args *args = calloc(workers, sizeof(*args));
        atomic_int go = ATOMIC_VAR_INIT(0);
        unsigned created = 0, admitted = 0;
        uint64_t insertions = 0;
        int ok = 1;

        if (!ids || !args ||
            fixture_open(&f, path, BG_START_NS, BG_MAX_CREDIT) ||
            packet_dns_query(&p, "10.10.0.1")) {
            ok = 0;
            goto finish_round;
        }
        for (unsigned i = 0; i < workers; i++) {
            args[i].fixture = &f;
            args[i].packet = &p;
            args[i].go = &go;
            if (pthread_create(&ids[i], NULL, worker, &args[i])) {
                fprintf(stderr, "    pthread_create failed at worker %u\n", i);
                ok = 0;
                break;
            }
            created++;
        }
        atomic_store_explicit(&go, 1, memory_order_release);
        for (unsigned i = 0; i < created; i++)
            pthread_join(ids[i], NULL);
        if (created != workers) ok = 0;
        if (!ok) goto finish_round;

        for (unsigned i = 0; i < workers; i++) {
            if (args[i].error ||
                (args[i].result != XDP_PASS && args[i].result != XDP_DROP))
                ok = 0;
            admitted += args[i].result == XDP_PASS;
        }
        if (fixture_get_source(&f, p.source_addr, &source) ||
            fixture_get_global(&f, &global) ||
            fixture_get_stat(&f, BG_SOURCE_INSERT, &insertions)) {
            ok = 0;
        } else if (insertions != 1 || admitted < 1 || admitted > 10 ||
                   source.packet_seen != admitted ||
                   global.credit != BG_MAX_CREDIT - (uint64_t)admitted * BG_TOKEN_UNIT) {
            ok = 0;
        }
        if (!ok || round == 0 || round + 1 == rounds)
            printf("    round %u/%u: passes=%u drops=%u %s\n",
                   round + 1, rounds, admitted, workers - admitted,
                   ok ? "OK" : "FAILED");
finish_round:
        fixture_close(&f);
        free(ids);
        free(args);
        if (!ok) {
            all_ok = 0;
            break;
        }
    }
    return all_ok;
}

struct testcase {
    const char *name;
    int (*run)(const char *);
};

int run_test_suite(const char *object_path, const struct bg_test_options *opts)
{
    static const struct testcase core[] = {
        {"Parser bypass cases", test_parser},
        {"New source admission", test_new_source},
        {"Existing source commit", test_existing_source},
        {"GCRA 10-packet burst", test_source_burst},
        {"GCRA 50ms recovery", test_source_recovery},
        {"Global exhaustion", test_global_exhaustion},
        {"Global 5ms refill", test_global_refill},
        {"300 rotating sources", test_source_rotation},
        {"Post-reservation GCRA change + refund (injected)",
         test_refund_after_commit_change},
        {"BPF_NOEXIST collision + commit (injected)",
         test_injected_insert_race},
        {"BPF_NOEXIST collision + refund (injected)",
         test_insert_race_refund},
        {"Source insertion error + refund (injected)",
         test_insert_error_refund},
    };
    int passed = 0, failed = 0;
    if (!opts->stress_only) {
        for (size_t i = 0; i < sizeof(core) / sizeof(core[0]); i++) {
            int ok = core[i].run(object_path);
            printf("[%s] %s\n", ok ? "PASS" : "FAIL", core[i].name);
            passed += !!ok;
            failed += !ok;
        }
    } else {
        int ok = test_concurrent_accounting(object_path, opts->workers, opts->rounds);
        printf("[%s] %u-worker accounting x %u rounds\n",
               ok ? "PASS" : "FAIL", opts->workers, opts->rounds);
        passed += !!ok;
        failed += !ok;

        ok = test_lru_eviction(object_path, opts->lru_sources);
        printf("[%s] LRU eviction / history reset (%u sources)\n",
               ok ? "PASS" : "FAIL", opts->lru_sources);
        passed += !!ok;
        failed += !ok;
    }
    printf("\nResult: %d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
