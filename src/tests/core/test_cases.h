#ifndef BYTEGUARD_TEST_CASES_H
#define BYTEGUARD_TEST_CASES_H

struct bg_test_options {
    int stress_only;
    unsigned workers;
    unsigned rounds;
    unsigned lru_sources;
};

int run_test_suite(const char *object_path, const struct bg_test_options *opts);
#endif
