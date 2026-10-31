package main

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

type fakeCounterMap struct{ fail bool }

func (m *fakeCounterMap) Lookup(key, out any) error {
	if m.fail {
		return errors.New("test map read failed")
	}
	id := *key.(*uint32)
	values := out.(*[]uint64)
	for cpu := range *values {
		(*values)[cpu] = uint64(id+1) * uint64(cpu+1)
	}
	return nil
}

// Exercise per-CPU aggregation, the real StatsReader, collector registration,
// and the exact HTTP handler used by the controller. No kernel access required.
func TestStatsToMetricsHTTP(t *testing.T) {
	reader := &StatsReader{statMap: &fakeCounterMap{}, cpuCount: 3}
	handler := metricsHandler(reader)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", response.Code, response.Body)
	}
	for _, metric := range []string{
		"byteguard_dns_queries_total 6\n",
		"byteguard_source_hits_total 12\n",
		"byteguard_source_inserts_total 18\n",
		"byteguard_insert_races_total 24\n",
		"byteguard_map_errors_total 30\n",
		"byteguard_packet_drops_total 36\n",
		"byteguard_dns_pass_total 42\n",
		"byteguard_drop_source_limit_total 48\n",
		"byteguard_drop_global_limit_total 54\n",
		"byteguard_drop_source_commit_total 60\n",
		"byteguard_drop_internal_error_total 66\n",
		"byteguard_global_refunds_total 72\n",
	} {
		if !strings.Contains(response.Body.String(), metric) {
			t.Errorf("missing metric %q", metric)
		}
	}
}

func TestMapReadFailureFailsScrape(t *testing.T) {
	reader := &StatsReader{statMap: &fakeCounterMap{fail: true}, cpuCount: 3}
	response := httptest.NewRecorder()
	metricsHandler(reader).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "test map read failed") {
		t.Fatalf("expected visible scrape failure, got %d: %s", response.Code, response.Body)
	}
}

func TestEmbeddedObjectLayout(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObject))
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Programs) != 1 || spec.Programs["xdp_main"] == nil {
		t.Fatal("embedded object must contain production xdp_main")
	}
	stats := spec.Maps["stat_map"]
	if stats == nil || stats.Type != ebpf.PerCPUArray || stats.MaxEntries != statGlobalRefund+1 || stats.KeySize != 4 || stats.ValueSize != 8 {
		t.Fatalf("unexpected stat_map layout: %+v", stats)
	}
	if spec.Maps["source_map"] == nil || spec.Maps["global_map"] == nil || spec.Maps["test_clock_map"] != nil || spec.Maps["test_fault_map"] != nil {
		t.Fatal("expected production maps without test hooks")
	}
	if _, err := NewStatsReader(nil); err == nil {
		t.Fatal("nil stats map accepted")
	}
}
