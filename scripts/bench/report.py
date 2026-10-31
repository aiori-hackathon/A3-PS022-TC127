"""Generate CSV, Markdown, and optional charts from validated v4 benchmark runs.

Historical v2 results are intentionally excluded: their workload windows
included variable DNS timeout-drain time and are not directly comparable.
Runs are grouped only when workload, duration, and implementation match.
"""
import csv
import json
import statistics
import hashlib
from collections import defaultdict

from bench_common import RUNS_DIR, REPORTS_DIR
from audit import inspect_result

SCHEMA = 4
MEASURES = (
    "success_percent", "legit_noerror_qps", "latency_mean_ms",
    "server_cpu_percent_one_core", "host_busy_percent_all_cores",
    "host_softirq_percent_capacity", "ingress_rx_pps", "ingress_rx_mbps",
    "attack_replay_pps", "filter_admitted", "filter_dropped",
    "filter_drop_source", "filter_drop_global",
)


def write_csv(path, rows):
    if not rows:
        return
    with path.open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def summary_row(result):
    dns = result.get("dns") or {}
    attack = result.get("attack") or {}
    perf = result.get("performance") or {}
    net = perf.get("server_interface") or {}
    xdp = (result.get("xdp_deltas") or {}) if result["mode"] == "xdp" else {}
    nft = (result.get("nft_deltas") or {}) if result["mode"] == "nft" else {}
    mean_latency = dns.get("avg_latency_sec")

    # Source fingerprint is stable even when Clang writes ELF debug paths
    # that vary between runs. Externally provided BPF objects use ELF hash.
    implementation = (
        result.get("xdp_source_sha256") or result.get("xdp_object_sha256") or "none"
    ) if result["mode"] == "xdp" else (
        json.dumps(result.get("nft_config", {}), sort_keys=True)
        if result["mode"] == "nft" else "no-filter"
    )
    original_pcap = result.get("original_attack_pcap_sha256") or "built-in"

    return {
        "run_id": result["run_id"],
        "tag": result.get("run_tag", "default"),
        "mode": result["mode"],
        "scenario": result["scenario"],
        "legit_qps": result["legit_offered_qps"],
        "legit_clients": result["legit_clients"],
        "attack_offered_pps": result["attack_offered_pps"],
        "seed": result["seed"],
        "capture_enabled": result.get("capture_enabled", False),
        "duration_seconds": result["duration_seconds"],
        "outstanding": result.get("outstanding"),
        "source_count": result.get("source_count"),
        "packet_count": result.get("packet_count"),
        "pulse_on_seconds": result.get("pulse_on_seconds", 0),
        "pulse_off_seconds": result.get("pulse_off_seconds", 0),
        "workload_sha256": result.get("workload_sha256", ""),
        "original_attack_pcap_sha256": original_pcap,
        "kernel": result.get("kernel", ""),
        "environment_fingerprint": hashlib.sha256(json.dumps(result.get("environment", {}), sort_keys=True).encode()).hexdigest(),
        "implementation_fingerprint": implementation,
        "xdp_object_sha256": result.get("xdp_object_sha256", ""),
        "queries_sent": dns.get("sent"),
        "queries_completed": dns.get("completed"),
        "noerror": dns.get("noerror"),
        "success_percent": dns.get("success_percent"),
        "legit_sent_qps": dns.get("achieved_legit_sent_qps"),
        "legit_noerror_qps": dns.get("achieved_legit_noerror_qps"),
        "latency_mean_ms": mean_latency * 1000 if mean_latency is not None else None,
        "latency_max_ms": dns["max_latency_sec"] * 1000 if dns.get("max_latency_sec") is not None else None,
        "measurement_seconds": perf.get("measurement_seconds"),
        "server_cpu_percent_one_core": perf.get("dnsmasq_cpu_percent_one_core"),
        "host_busy_percent_all_cores": perf.get("host_cpu_busy_percent_all_cores"),
        "host_softirq_percent_capacity": perf.get("host_softirq_percent_capacity"),
        "ingress_rx_pps": net.get("rx_pps"),
        "ingress_rx_mbps": net.get("rx_mbps"),
        "server_tx_pps": net.get("tx_pps"),
        "attack_sent_packets": attack.get("sent_packets"),
        "attack_replay_pps": attack.get("replay_average_pps"),
        "xdp_pass": xdp.get("DNS_PASS"),
        "xdp_drop": xdp.get("PACKET_DROP"),
        "nft_pass": nft.get("admitted"),
        "nft_drop_source": nft.get("source_limit"),
        "nft_drop_global": nft.get("global_limit"),
        "filter_admitted": xdp.get("DNS_PASS") if result["mode"] == "xdp" else nft.get("admitted"),
        "filter_dropped": xdp.get("PACKET_DROP") if result["mode"] == "xdp" else (
            nft["source_limit"] + nft["global_limit"] if nft else None),
        "filter_drop_source": xdp.get("DROP_SOURCE_LIMIT") if result["mode"] == "xdp" else nft.get("source_limit"),
        "filter_drop_global": xdp.get("DROP_GLOBAL_LIMIT") if result["mode"] == "xdp" else nft.get("global_limit"),
    }


def group_key(row):
    # Seed is omitted on purpose; separate seeded trials are repetitions of
    # the same workload recipe. Actual per-run seeds remain in summary.csv.
    return (
        row["tag"], row["mode"], row["scenario"], row["legit_qps"],
        row["legit_clients"], row["attack_offered_pps"],
        row["duration_seconds"], row["outstanding"],
        row["source_count"], row["packet_count"],
        row["pulse_on_seconds"], row["pulse_off_seconds"],
        row["workload_sha256"], row["original_attack_pcap_sha256"],
        row["kernel"], row["implementation_fingerprint"],
        row["capture_enabled"],
        row["environment_fingerprint"],
    )


def grouped_summary(rows):
    grouped = defaultdict(list)
    for row in rows:
        grouped[group_key(row)].append(row)

    summary = []
    # Sorting serialized tuples avoids comparing mixed None/string values.
    for key in sorted(grouped, key=str):
        samples = grouped[key]
        item = {k: samples[0][k] for k in (
            "tag", "mode", "scenario", "legit_qps", "legit_clients",
            "attack_offered_pps", "duration_seconds", "outstanding",
            "source_count", "packet_count", "pulse_on_seconds", "pulse_off_seconds",
            "workload_sha256", "original_attack_pcap_sha256", "kernel",
            "implementation_fingerprint", "capture_enabled",
            "environment_fingerprint",
        )}
        item["trials"] = len(samples)
        for metric in MEASURES:
            values = [float(row[metric]) for row in samples if row[metric] is not None]
            item[metric + "_mean"] = statistics.mean(values) if values else None
            item[metric + "_stddev"] = statistics.stdev(values) if len(values) > 1 else None
        summary.append(item)
    return summary


def chart(grouped, metric, title, ylabel, filename, output_dir):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    # Every bar is one already-matched group. Categorical conditions avoid
    # implying continuous PPS trends from a single attack intensity.
    ordered = sorted(grouped, key=lambda row: (
        row["tag"], row["scenario"], row["attack_offered_pps"], row["mode"], str(group_key(row))))
    fig, ax = plt.subplots(figsize=(max(9, min(22, len(ordered) * .9)), 5))
    colors = {"none": "#777777", "nft": "#d98c10", "xdp": "#2878b5"}
    labels = []
    seen = set()
    for index, row in enumerate(ordered):
        labels.append(f"{row['mode']}\n{row['scenario']}\n{row['attack_offered_pps']} PPS")
        value = row[metric + "_mean"]
        if value is None:
            continue
        mode = row["mode"]
        ax.bar(index, value, yerr=row[metric + "_stddev"], capsize=3,
               color=colors.get(mode), label=mode if mode not in seen else None)
        seen.add(mode)
    ax.set_xticks(range(len(labels)), labels, rotation=45, ha="right", fontsize="small")
    ax.set(title=title + " (error bars: sample SD)", ylabel=ylabel)
    ax.set_ylim(bottom=0)
    ax.grid(axis="y", alpha=.3)
    ax.set_axisbelow(True)
    if seen:
        ax.legend()
    fig.tight_layout()
    fig.savefig(output_dir / filename, dpi=170)
    plt.close(fig)


def make_report(charts=False, tag=None):
    # Separate reports by tag so re-running one report does not overwrite
    # somebody else's finalized measurements.
    if tag is not None and (not tag or len(tag) > 40 or
                            any(x not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for x in tag)):
        raise ValueError("Report tag must be 1..40 characters (letters, digits, _ or -)")
    output_dir = REPORTS_DIR / (tag if tag is not None else "all")
    rows = []
    legacy_count = 0
    for path in sorted(RUNS_DIR.glob("*/summary.json")):
        result = json.loads(path.read_text())
        if result.get("status") != "completed":
            continue
        if result.get("benchmark_schema_version") != SCHEMA:
            legacy_count += 1
            continue
        if tag is not None and result.get("run_tag", "default") != tag:
            continue
        errors, _ = inspect_result(result)
        if errors:
            print("Excluded invalid run:", path.parent.name, "; ".join(errors))
            continue
        rows.append(summary_row(result))
    if not rows:
        print("No completed v4 runs found" + (f" for tag {tag}" if tag else ""))
        if legacy_count:
            print(f"Skipped {legacy_count} old runs with incompatible measurement windows")
        return
    output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(output_dir / "summary.csv", rows)
    grouped = grouped_summary(rows)
    write_csv(output_dir / "grouped.csv", grouped)
    lines = [
        "# ByteGuard benchmark comparisons (measurement schema v4)", "",
        "Only completed v4 runs are included. Run tags, implementation fingerprints,",
        "kernel, duration, workload hashes and rate settings separate distinct groups.",
        "Different random seeds are counted as repeated trials within one group.",
        "Packet-capture-enabled debug runs are grouped separately from clean performance runs.", "",
        "**Latency is for answered DNS queries only.** Host CPU includes the",
        "traffic generators. These are not filter-only CPU-cycle measurements.",
        "Interface RX is driver accounting, not total offered traffic or DNS-server capacity.",
        "Filter counts combine attack and legitimate queries; they do not identify attack-only drops.",
        "No-filter has no filter counters (shown as unavailable). Charts use sample SD, not confidence intervals.",
        "The synchronized launcher does not guarantee identical first-packet timing.", "",
        "| Tag | Mode | Scenario | Legit QPS | Attack PPS | Trials | Success | Legit replies/s | Mean latency (ms) | dnsmasq CPU (% core) | Host busy (%) | Attack sent PPS | DNS admitted | DNS dropped | Source drops | Global drops |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for item in grouped:
        def fmt(field, digits=2):
            value = item[field + "_mean"]
            return f"{value:.{digits}f}" if value is not None else "—"
        lines.append(
            f"| {item['tag']} | {item['mode']} | {item['scenario']} | "
            f"{item['legit_qps']} | {item['attack_offered_pps']} | {item['trials']} | "
            f"{fmt('success_percent')}% | {fmt('legit_noerror_qps')} | {fmt('latency_mean_ms', 3)} | "
            f"{fmt('server_cpu_percent_one_core')} | {fmt('host_busy_percent_all_cores')} | "
            f"{fmt('attack_replay_pps', 1)} | {fmt('filter_admitted', 1)} | {fmt('filter_dropped', 1)} | "
            f"{fmt('filter_drop_source', 1)} | {fmt('filter_drop_global', 1)} |"
        )
    lines.extend(["", "Full per-run settings and measurements: `summary.csv`.",
                  "Matched-group means and sample standard deviations: `grouped.csv`."])
    (output_dir / "REPORT.md").write_text("\n".join(lines) + "\n")
    for name in ("summary.csv", "grouped.csv", "REPORT.md"):
        print("Saved:", output_dir / name)
    if legacy_count:
        print(f"Excluded {legacy_count} incompatible old-schema runs")
    if charts:
        try:
            import matplotlib  # noqa: F401
        except ImportError:
            print("Warning: matplotlib not installed; CSV and Markdown reports are ready")
            return
        chart(grouped, "success_percent", "Legitimate DNS success", "NOERROR / offered queries (%)", "success_vs_attack_pps.png", output_dir)
        chart(grouped, "latency_mean_ms", "Answered-query latency", "Average latency (ms)", "latency_vs_attack_pps.png", output_dir)
        chart(grouped, "server_cpu_percent_one_core", "dnsmasq process CPU", "CPU (% of one core)", "server_cpu_vs_attack_pps.png", output_dir)
        chart(grouped, "ingress_rx_pps", "Server-interface ingress PPS", "Received packets / second", "ingress_pps_vs_attack_pps.png", output_dir)
        chart(grouped, "legit_noerror_qps", "Legitimate DNS response throughput", "NOERROR responses / offered-window second", "legitimate_throughput.png", output_dir)
        chart(grouped, "host_busy_percent_all_cores", "Host CPU including generators", "CPU busy (% all-core capacity)", "host_cpu.png", output_dir)
        chart(grouped, "filter_dropped", "All DNS queries dropped by the filter", "Dropped queries / run (attack + legitimate)", "filter_drops.png", output_dir)
        print("Wrote 7 PNG charts")
