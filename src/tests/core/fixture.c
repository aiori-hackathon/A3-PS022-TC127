#include "fixture.h"

#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(sizeof(struct bg_global_value) == 24,
               "global map layout must match global_bucket.h");
_Static_assert(sizeof(struct bg_source_value) == 16,
               "source map layout must match gcra.h");

void fixture_close(struct fixture *f)
{
    if (f->obj)
        bpf_object__close(f->obj);
    memset(f, 0, sizeof(*f));
}

static int required_map_fd(struct bpf_object *obj, const char *name)
{
    int fd = bpf_object__find_map_fd_by_name(obj, name);
    if (fd < 0)
        fprintf(stderr, "Missing BPF map '%s': %d\n", name, fd);
    return fd;
}

int fixture_open(struct fixture *f, const char *object_path,
                 uint64_t now_ns, uint64_t credit)
{
    memset(f, 0, sizeof(*f));
    f->obj = bpf_object__open_file(object_path, NULL);
    long err = libbpf_get_error(f->obj);
    if (err) {
        fprintf(stderr, "BPF open failed (%s): %ld\n", object_path, err);
        f->obj = NULL;
        return -1;
    }
    if (bpf_object__load(f->obj) < 0) {
        fprintf(stderr, "BPF verifier/load failed for %s: %s\n",
                object_path, strerror(errno));
        goto fail;
    }

    struct bpf_program *p = bpf_object__find_program_by_name(f->obj, "xdp_main");
    if (!p) {
        fprintf(stderr, "Can't find XDP program 'xdp_main'\n");
        goto fail;
    }
    f->prog_fd = bpf_program__fd(p);
    f->source_fd = required_map_fd(f->obj, "source_map");
    f->global_fd = required_map_fd(f->obj, "global_map");
    f->stats_fd = required_map_fd(f->obj, "stat_map");
    f->clock_fd = required_map_fd(f->obj, "test_clock_map");
    f->fault_fd = required_map_fd(f->obj, "test_fault_map");
    if (f->prog_fd < 0 || f->source_fd < 0 || f->global_fd < 0 ||
        f->stats_fd < 0 || f->clock_fd < 0 || f->fault_fd < 0)
        goto fail;

    if (fixture_set_clock(f, now_ns) ||
        fixture_set_global(f, credit, now_ns) ||
        fixture_set_faults(f, 0))
        goto fail;
    return 0;

fail:
    fixture_close(f);
    return -1;
}

int fixture_set_clock(struct fixture *f, uint64_t now_ns)
{
    uint32_t zero = 0;
    if (bpf_map_update_elem(f->clock_fd, &zero, &now_ns, BPF_ANY)) {
        perror("set test clock");
        return -1;
    }
    return 0;
}

int fixture_set_faults(struct fixture *f, uint32_t mask)
{
    uint32_t zero = 0;
    if (bpf_map_update_elem(f->fault_fd, &zero, &mask, BPF_ANY)) {
        perror("set test faults");
        return -1;
    }
    return 0;
}

int fixture_set_global(struct fixture *f, uint64_t credit, uint64_t last_ns)
{
    uint32_t zero = 0;
    struct bg_global_value v = {
        .credit = credit,
        .last_refill_ns = last_ns,
    };
    if (bpf_map_update_elem(f->global_fd, &zero, &v, BPF_ANY)) {
        perror("set global bucket");
        return -1;
    }
    return 0;
}

int fixture_get_global(struct fixture *f, struct bg_global_value *value)
{
    uint32_t zero = 0;
    if (bpf_map_lookup_elem(f->global_fd, &zero, value)) {
        perror("read global bucket");
        return -1;
    }
    return 0;
}

int fixture_get_source(struct fixture *f, uint32_t network_addr,
                       struct bg_source_value *value)
{
    /* The XDP key is ip->saddr, i.e. the four IPv4 bytes as stored in memory. */
    return bpf_map_lookup_elem(f->source_fd, &network_addr, value);
}

int fixture_run(struct fixture *f, const void *packet, size_t len,
                uint32_t *action)
{
    struct bpf_test_run_opts opts = {
        .sz = sizeof(struct bpf_test_run_opts),
        .data_in = packet,
        .data_size_in = (uint32_t)len,
        .repeat = 1,
    };
    if (bpf_prog_test_run_opts(f->prog_fd, &opts)) {
        perror("BPF_PROG_TEST_RUN");
        return -1;
    }
    *action = opts.retval;
    return 0;
}

int fixture_get_stat(struct fixture *f, uint32_t index, uint64_t *count)
{
    int n = libbpf_num_possible_cpus();
    if (n < 1)
        return -1;
    uint64_t *values = calloc((size_t)n, sizeof(*values));
    if (!values)
        return -1;
    if (bpf_map_lookup_elem(f->stats_fd, &index, values)) {
        perror("read per-CPU statistics");
        free(values);
        return -1;
    }
    *count = 0;
    for (int i = 0; i < n; i++)
        *count += values[i];
    free(values);
    return 0;
}
