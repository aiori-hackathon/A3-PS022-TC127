#include "test_cases.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int parse_count(const char *arg, unsigned min, unsigned max, unsigned *out)
{
    char *end = NULL;
    errno = 0;
    unsigned long n = strtoul(arg, &end, 10);
    if (errno || arg == end || *end || n < min || n > max)
        return -1;
    *out = (unsigned)n;
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [--stress] [--workers N] [--rounds N] "
            "[--lru-sources N] [BPF_OBJECT]\n"
            "  --workers: 2..256 (default 32)\n"
            "  --rounds: 1..200 (default 1)\n"
            "  --lru-sources: 1025..20000 (default 1300)\n",
            prog);
}

int main(int argc, char **argv)
{
    const char *object = "build/xdp_core_test.bpf.o";
    struct bg_test_options opts = {
        .workers = 32,
        .rounds = 1,
        .lru_sources = 1300,
    };
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--stress") == 0) {
            opts.stress_only = 1;
        } else if (!strcmp(argv[i], "--workers") && i + 1 < argc) {
            if (parse_count(argv[++i], 2, 256, &opts.workers)) goto invalid;
        } else if (!strcmp(argv[i], "--rounds") && i + 1 < argc) {
            if (parse_count(argv[++i], 1, 200, &opts.rounds)) goto invalid;
        } else if (!strcmp(argv[i], "--lru-sources") && i + 1 < argc) {
            if (parse_count(argv[++i], 1025, 20000, &opts.lru_sources)) goto invalid;
        } else if (argv[i][0] == '-') {
            goto invalid;
        } else {
            object = argv[i];
        }
    }
    printf("ByteGuard XDP %s tests\n", opts.stress_only ? "stress" : "core");
    return run_test_suite(object, &opts);
invalid:
    usage(argv[0]);
    return 2;
}
