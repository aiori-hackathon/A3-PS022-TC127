package main

import (
	"log"

	"github.com/prometheus/client_golang/prometheus"
)

type statsProvider interface {
	Read() (Stats, error)
}

type ByteGuardCollector struct {
	reader statsProvider
	descs  []*prometheus.Desc
}

func NewByteGuardCollector(reader statsProvider) *ByteGuardCollector {
	names := []struct {
		name string
		help string
	}{
		{"byteguard_dns_queries_total", "Total DNS packets processed by ByteGuard"},
		{"byteguard_source_hits_total", "Existing source map hits"},
		{"byteguard_source_inserts_total", "Successful source map insertions"},
		{"byteguard_insert_races_total", "Source map insertion races"},
		{"byteguard_map_errors_total", "BPF map errors"},
		{"byteguard_packet_drops_total", "Total packets dropped"},
		{"byteguard_dns_pass_total", "DNS packets admitted by XDP"},
		{"byteguard_drop_source_limit_total", "Packets dropped by source limiter"},
		{"byteguard_drop_global_limit_total", "Packets dropped by global limiter"},
		{"byteguard_drop_source_commit_total", "Packets dropped by source commit failure"},
		{"byteguard_drop_internal_error_total", "Packets dropped by internal errors"},
		{"byteguard_global_refunds_total", "Global token refund calls (not confirmed refund successes)"},
	}

	descs := make([]*prometheus.Desc, 0, len(names))

	for _, metric := range names {
		descs = append(descs, prometheus.NewDesc(
			metric.name,
			metric.help,
			nil,
			nil,
		))
	}

	return &ByteGuardCollector{
		reader: reader,
		descs:  descs,
	}
}

func (c *ByteGuardCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, desc := range c.descs {
		ch <- desc
	}
}

func (c *ByteGuardCollector) Collect(ch chan<- prometheus.Metric) {
	stats, err := c.reader.Read()
	if err != nil {
		log.Printf("failed to collect ByteGuard stats: %v", err)
		// A successful empty scrape hides a failed BPF map read. Make the
		// scrape fail visibly so Prometheus reports up=0 and the HTTP error.
		ch <- prometheus.NewInvalidMetric(c.descs[0], err)
		return
	}

	values := []uint64{
		stats.DNSQueries,
		stats.SourceHits,
		stats.SourceInserts,
		stats.InsertRaces,
		stats.MapErrors,
		stats.PacketDrops,
		stats.DNSPass,
		stats.DropSourceLimit,
		stats.DropGlobalLimit,
		stats.DropSourceCommit,
		stats.DropInternal,
		stats.GlobalRefunds,
	}

	for i, value := range values {
		ch <- prometheus.MustNewConstMetric(
			c.descs[i],
			prometheus.CounterValue,
			float64(value),
		)
	}
}
