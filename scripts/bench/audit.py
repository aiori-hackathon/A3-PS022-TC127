"""Sanity checks for actual benchmark outputs (not proof of performance)."""
import json
from pathlib import Path

from bench_common import RUNS_DIR, STATE_FILE


def inspect_result(result):
    errors = []
    warnings = []
    if result.get("benchmark_schema_version") != 4:
        errors.append("Old measurement format; rerun with v4")
    if result.get("status") != "completed":
        errors.append("Run failed: " + str(result.get("error", "unknown error")))
        return errors, warnings
    if result.get("cleanup_status") != "ok":
        errors.append("Cleanup did not report success")
    dns = result.get("dns") or {}
    sent = dns.get("sent")
    completed = dns.get("completed")
    lost = dns.get("lost")
    noerror = dns.get("noerror")
    if any(x is None for x in (sent, completed, lost, noerror)):
        errors.append("DNS output is incomplete")
    elif sent <= 0 or completed + lost != sent or not 0 <= noerror <= completed:
        errors.append("DNS counts inconsistent")

    perf = result.get("performance") or {}
    seconds = perf.get("measurement_seconds")
    duration = result.get("duration_seconds")
    if seconds is None or duration is None:
        errors.append("No performance measurement window")
    elif not duration - 0.3 <= seconds <= duration + 0.5:
        warnings.append(f"Measured window {seconds:.2f}s differs from requested {duration}s")
    net = perf.get("server_interface") or {}
    if net.get("rx_pps") is None:
        errors.append("No received interface PPS measurement")

    if result.get("capture_enabled"):
        evidence = result.get("capture") or {}
        for side in ("client", "server"):
            artifact = evidence.get(side) or {}
            filename = artifact.get("pcap")
            if not filename or not Path(filename).is_file():
                errors.append("Missing " + side + " capture PCAP")
    if result.get("mode") == "xdp":
        checks = result.get("xdp_checks") or {}
        if not checks or any(value is not True for value in checks.values()):
            errors.append("XDP outcome/drop accounting failed or missing")
    if result.get("mode") == "nft":
        counters = result.get("nft_deltas") or {}
        for name in ("source_limit", "global_limit", "admitted"):
            if counters.get(name) is None:
                errors.append("Missing nft counter: " + name)

    attack_pps = result.get("attack_offered_pps", 0)
    if attack_pps > 0:
        actual = (result.get("attack") or {}).get("replay_average_pps")
        if actual is None or actual <= 0:
            errors.append("No measured tcpreplay attack PPS")
        elif abs(actual - attack_pps) / attack_pps > 0.20:
            warnings.append(f"Achieved attack PPS {actual:.1f} differs >20% from requested {attack_pps}")
    return errors, warnings


def verify(tag=None):
    paths = sorted(RUNS_DIR.glob("*/summary.json"))
    examined = failed = warned = 0
    for path in paths:
        result = json.loads(path.read_text())
        if result.get("benchmark_schema_version") != 4:
            continue
        if tag is not None and result.get("run_tag") != tag:
            continue
        examined += 1
        errors, warnings = inspect_result(result)
        if errors:
            failed += 1
        if warnings:
            warned += 1
        label = "FAIL" if errors else "WARN" if warnings else "PASS"
        print(f"{label:4} {result['mode']:4} {result['run_id']} "
              f"{result['scenario']} {result['attack_offered_pps']}PPS")
        for problem in errors:
            print("   ERROR:", problem)
        for problem in warnings:
            print("   WARNING:", problem)
    if STATE_FILE.exists():
        failed += 1
        print("FAIL Active benchmark state remains:", STATE_FILE)
    print(f"Verified {examined} v4 runs: {failed} failures, {warned} warning runs")
    if examined == 0:
        print("No v4 runs to verify")
        return 1
    return 1 if failed else 0
