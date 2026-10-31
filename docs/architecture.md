# Architecture and project flow

The authoritative implementation is `src/xdp/xdp_main.c`, `gcra.h` and `global_bucket.h`. The [technical report](../reports/ByteGuard_Technical_Report.pdf) contains equations and concurrency reasoning. [Current architecture SVG](../reports/figures/architecture-current.svg) and [future architecture SVG](../reports/figures/architecture-future.svg) are editable vector diagrams; the latter is explicitly unimplemented.

## Packet path

1. Bound-check Ethernet and select untagged IPv4.
2. Validate IPv4 version/IHL/total length and reject fragments from classification by returning early PASS.
3. Bound-check UDP; require matching UDP/IP payload lengths and destination port 53.
4. Require a fixed DNS header, QR=0, opcode=0 and QDCOUNT>0. No QNAME/QTYPE, full message or checksum validation occurs.
5. Increment DNS_QUERIES and look up the source IPv4 address.
6. For an existing source: read-only GCRA eligibility → locked global reservation → bounded source CAS; refund on terminal commit failure.
7. For a new source: locked global reservation → BPF_NOEXIST insertion. On EEXIST, re-lookup and attempt source CAS without reserving twice. Terminal failures refund; successful collision recovery admits.
8. Count one final admission or one final drop reason plus total drops. PASS enters Linux/DNS; DROP stops normal further processing.

Unsupported or failed classification returns early PASS outside DNS admission counters. Thus fragments, IPv6, VLAN frames, TCP and certain malformed packets bypass this limiter. An admitted fixed-header candidate is not proof of a valid DNS question or completed response.

## State and concurrency

| State | Representation | Synchronization |
|---|---|---|
| Source | IPv4 key; TAT and packet_seen u64; 1024-entry shared LRU hash | TAT CAS with four recomputing attempts; atomic packet_seen increment |
| Global | One shared array value, lock/credit/refill timestamp | Spin lock around refill/reserve and refund |
| Statistics | Twelve per-CPU u64 array entries | Per-CPU increments; sums in Go/Python |

Source rate/burst is 100/10: spacing 10 ms and tolerance 90 ms. Global rate/burst is 1000/200, with one token represented by 10^9 credit units. Refill caps before unsafe multiplication; refunds saturate at the cap. GCRA and the bucket are separate maps: compensation is not an atomic cross-map transaction. LRU retention is bounded history, not permanent source identity or trust.

The original reference PDF's “insertion loser always drops” statement is obsolete. Current collision handling can CAS-commit the winner's state and admit. A refund counter records calls, not guaranteed full credits restored.

## Build and controller

`make controller` compiles the protected source, copies its object to the Go embed location and builds `build/byteguard`. The controller selects a named interface/mode, reserves the metrics port before attachment, loads through cilium/ebpf, validates/reads stat_map and holds an XDP link until termination. It logs object SHA-256. Shutdown drains HTTP with a timeout and releases link/collection; map state is fresh on restart.

StatsReader reads all possible-CPU values for each index. The collector registers with the exact private registry served by `/metrics`. A BPF read error causes a failed scrape; it is not silently represented as missing counters. Live reads are not an atomic global snapshot. At quiescence, queries = passes + drops, and total drops = four final reason counters.

## Observation and response path

BPF counters → Go aggregate → Prometheus scrape → provisioned Grafana panels. The dashboard displays real map-derived decisions when a live controller is attached and successfully scraped. It exports no synthetic success/latency/CPU measurement. DNSPerf independently counts actual legitimate responses and NOERROR codes; system sampling reads CPU/device counters.

The demo leaves its server veth/controller in the host namespace to make metrics reachable from Docker. The benchmark puts both veth endpoints and DNS into separate namespaces, loads with bpftool and reads pinned maps directly. See [setup](setup.md) for the topology table. The controller does not need to run alongside the benchmark's separately loaded program.

## Proposed architecture boundary

Section 12 of the report proposes subnet limits, selected source history, userspace profiling, authenticated cookie evidence and protected/discovery/shared capacity. None is implemented. Qualification must not mean “previously passed”; familiarity and valid cookies are not universal proofs of benign behavior. Final order, reservations, borrowing, expiry and class abuse require explicit design and incremental evaluation. No baseline benchmark is labeled as evaluating these candidates.
