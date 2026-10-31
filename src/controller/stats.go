package main

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// Keep these indexes in the same order as the enum in xdp_main.c.
const (
	statDNSQueries uint32 = iota
	statSourceHit
	statSourceInsert
	statInsertRace
	statMapError
	statPacketDrop
	statDNSPass
	statDropSourceLimit
	statDropGlobalLimit
	statDropSourceCommit
	statDropInternalError
	statGlobalRefund
)

type Stats struct {
	DNSQueries       uint64
	SourceHits       uint64
	SourceInserts    uint64
	InsertRaces      uint64
	MapErrors        uint64
	PacketDrops      uint64
	DNSPass          uint64
	DropSourceLimit  uint64
	DropGlobalLimit  uint64
	DropSourceCommit uint64
	DropInternal     uint64
	GlobalRefunds    uint64
}

type StatsReader struct {
	statMap  interface{ Lookup(key, valueOut any) error }
	cpuCount int
}

func NewStatsReader(statMap *ebpf.Map) (*StatsReader, error) {
	if statMap == nil || statMap.Type() != ebpf.PerCPUArray ||
		statMap.KeySize() != 4 || statMap.ValueSize() != 8 ||
		statMap.MaxEntries() != statGlobalRefund+1 {
		return nil, fmt.Errorf("stat_map must be a per-CPU array with 4-byte keys, 8-byte values and %d entries", statGlobalRefund+1)
	}
	cpuCount, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, fmt.Errorf("get possible CPU count: %w", err)
	}

	return &StatsReader{
		statMap:  statMap,
		cpuCount: cpuCount,
	}, nil
}

// readCounter reads one per-CPU counter and returns its total.
func (r *StatsReader) readCounter(id uint32) (uint64, error) {
	perCPUValues := make([]uint64, r.cpuCount)

	if err := r.statMap.Lookup(&id, &perCPUValues); err != nil {
		return 0, fmt.Errorf("read stat index %d: %w", id, err)
	}

	var total uint64
	for _, value := range perCPUValues {
		total += value
	}

	return total, nil
}

func (r *StatsReader) Read() (Stats, error) {
	var stats Stats

	counters := []struct {
		id     uint32
		target *uint64
	}{
		{statDNSQueries, &stats.DNSQueries},
		{statSourceHit, &stats.SourceHits},
		{statSourceInsert, &stats.SourceInserts},
		{statInsertRace, &stats.InsertRaces},
		{statMapError, &stats.MapErrors},
		{statPacketDrop, &stats.PacketDrops},
		{statDNSPass, &stats.DNSPass},
		{statDropSourceLimit, &stats.DropSourceLimit},
		{statDropGlobalLimit, &stats.DropGlobalLimit},
		{statDropSourceCommit, &stats.DropSourceCommit},
		{statDropInternalError, &stats.DropInternal},
		{statGlobalRefund, &stats.GlobalRefunds},
	}

	for _, counter := range counters {
		value, err := r.readCounter(counter.id)
		if err != nil {
			return Stats{}, err
		}

		*counter.target = value
	}

	return stats, nil
}
