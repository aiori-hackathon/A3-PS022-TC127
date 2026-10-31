#!/usr/bin/env python3
"""Run isolated DNS mitigation experiments; preserve inputs and measurements."""
import argparse
import copy
import os
import shutil
import subprocess
import sys
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from attack import generate, retarget_custom_pcap, sha256
from capture import start_captures, stop_captures
from profiles import apply_profile
from audit import inspect_result, verify
import hashlib
import platform
from bench_common import (
    ROOT, RUNS_DIR, NS_CLIENT, NS_SERVER, IF_CLIENT, IF_SERVER,
    SERVER_IP, write_json, command_run,
)
from lab_env import (
    active_state, cleanup_lab, compile_xdp, get_mac, load_xdp,
    require_exclusive_lab, setup_network, start_dns, check_dns_ready,
    stop_process, save_state,
)
from metrics import snapshot, summarize
from nft_mode import install_nft, nft_counters
from report import make_report
from stats import read_stats, STAT_NAMES
from traffic import run_traffic


def xdp_source_fingerprint():
    """Identify compiled source independent of the temporary ELF output path."""
    folder = ROOT / "src/xdp"
    paths = sorted(list(folder.glob("*.c")) + list(folder.glob("*.h")))
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.name.encode("utf-8") + b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def tool_version(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=3)
        lines = (result.stdout + result.stderr).strip().splitlines()
        return lines[0] if lines else "unknown"
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"


def environment_metadata():
    cpu_model = "unknown"
    for line in Path("/proc/cpuinfo").read_text().splitlines():
        if line.startswith("model name"):
            cpu_model = line.split(":", 1)[1].strip()
            break
    return {
        "hostname": platform.node(),
        "architecture": platform.machine(),
        "cpu_model": cpu_model,
        "cpu_affinity": sorted(os.sched_getaffinity(0)),
        "logical_cpu_count": os.cpu_count(),
        "git_commit": tool_version(["git", "-C", str(ROOT), "rev-parse", "HEAD"]),
        "clang": tool_version(["clang", "--version"]),
        "bpftool": tool_version(["bpftool", "version"]),
        "dnsperf": tool_version(["dnsperf", "-h"]),
        "dnsmasq": tool_version(["dnsmasq", "--version"]),
        "tcpreplay": tool_version(["tcpreplay", "--version"]),
        "nft": tool_version(["nft", "--version"]),
    }


def check_dependencies(config):
    required = ["ip", "dnsmasq", "dig", "dnsperf", "cat"]
    if config.attack_pps:
        required.append("tcpreplay")
        try:
            import scapy.all
        except ImportError as error:
            raise RuntimeError("Scapy is required to generate or retarget attack PCAPs") from error
    if config.mode == "xdp":
        required.append("bpftool")
        if not config.object_file:
            required.extend(["make", "clang", "cc"])
    if config.mode == "nft":
        required.append("nft")
    if getattr(config, "capture", False):
        required.append("tcpdump")
    missing = [name for name in required if shutil.which(name) is None]
    if missing:
        raise RuntimeError("Missing required commands: " + ", ".join(missing))


def effective_source_count(config):
    if config.scenario == "single":
        return 1
    if config.source_count is not None:
        return config.source_count
    return 254 if config.scenario == "subnet" else 1024


def validate_run(config):
    if not config.tag or len(config.tag) > 40 or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for char in config.tag):
        raise ValueError("--tag must be 1..40 characters, using letters, numbers, _ or -")
    if config.duration < 1 or config.legit_qps < 1 or not 0 <= config.attack_pps <= 200000:
        raise ValueError("duration / legit-qps must be positive; attack-pps 0..200000")
    if config.scenario == "single" and config.source_count not in (None, 1):
        raise ValueError("single-source scenario requires --source-count 1")
    if config.attack_pcap and config.scenario != "custom":
        raise ValueError("--attack-pcap requires --scenario custom")
    if config.scenario == "custom" and config.attack_pps and config.attack_pcap is None:
        raise ValueError("custom scenario requires --attack-pcap")
    if config.attack_pps == 0:
        if config.scenario == "custom":
            raise ValueError("custom scenario requires nonzero --attack-pps")
        config.scenario = "none"  # Ensure a zero-attack run is labeled honestly.
    config.source_count = effective_source_count(config)
    if not 1 <= config.source_count <= 65536 or not 1 <= config.packet_count <= 65536:
        raise ValueError("source-count and packet-count must be 1..65536")
    if config.scenario == "subnet" and config.source_count > 254 and config.attack_pps:
        raise ValueError("subnet has at most 254 addresses")
    if config.attack_pps and config.scenario not in ("custom", "none") and config.source_count > config.packet_count:
        raise ValueError("source-count cannot exceed packet-count in generated workload")
    if config.attack_pps > 0 and config.scenario == "none":
        raise ValueError("Select a scenario when attack-pps > 0")
    if config.attack_pps > 0 and config.scenario == "custom" and not config.attack_pcap:
        raise ValueError("custom attack needs --attack-pcap")
    if not 1 <= config.legit_clients <= 32 or config.legit_clients > config.legit_qps:
        raise ValueError("legit-clients must be 1..32 and <= legit-qps")
    if config.outstanding < 1:
        raise ValueError("outstanding must be positive")
    if getattr(config, "capture_limit", 2500) < 1:
        raise ValueError("capture-limit must be positive")
    if config.scenario == "pulsed" and not config.pulse_on:
        config.pulse_on, config.pulse_off = 2, 2
    if config.pulse_on < 0 or config.pulse_off < 0 or (config.pulse_on and config.pulse_off <= 0):
        raise ValueError("Invalid pulse on/off values")
    if config.scenario != "pulsed" and config.pulse_on > 0:
        raise ValueError("Pulses require --scenario pulsed")
    if not config.workload.is_file():
        raise ValueError("Missing legitimate workload: " + str(config.workload))
    if config.attack_pcap and not config.attack_pcap.is_file():
        raise ValueError("Missing attack PCAP: " + str(config.attack_pcap))
    if config.object_file and not config.object_file.is_file():
        raise ValueError("Missing BPF object: " + str(config.object_file))


def run_one(config):
    if os.geteuid() != 0:
        raise RuntimeError("Run as root with sudo")
    validate_run(config)
    check_dependencies(config)
    require_exclusive_lab()
    if config.mode == "xdp" and not config.object_file and not (ROOT / "src/xdp/xdp_main.c").is_file():
        raise RuntimeError("Missing ByteGuard src/xdp/xdp_main.c")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    # Readable prefix plus collision-resistant suffix; all original parameters
    # are still stored separately in summary.json.
    run_id = (f"{config.tag}__{config.mode}__{config.scenario}__"
              f"{config.attack_pps}pps__{config.legit_qps}qps__"
              f"{timestamp}-{uuid.uuid4().hex[:8]}")
    run_dir = RUNS_DIR / run_id
    run_dir.mkdir(parents=True)
    state = {"owner": "byteguard-bench-kit-v1", "namespaces": [],
             "host_veth_created": False, "pin_dir": None, "run_dir": str(run_dir)}
    dns = None
    captures = []
    results = {
        "benchmark_schema_version": 4,
        "run_tag": config.tag,
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id, "status": "failed", "argv": sys.argv[1:],
        "mode": config.mode, "scenario": config.scenario,
        "duration_seconds": config.duration, "legit_offered_qps": config.legit_qps,
        "legit_clients": config.legit_clients, "attack_offered_pps": config.attack_pps,
        "seed": config.seed, "source_count": config.source_count,
        "packet_count": config.packet_count,
        "outstanding": config.outstanding,
        "capture_enabled": config.capture,
        "capture_limit": config.capture_limit if config.capture else None,
        "effective_config": {
            key: str(getattr(config, key)) if isinstance(getattr(config, key), Path)
                 else getattr(config, key)
            for key in (
                "tag", "mode", "scenario", "legit_qps", "legit_clients",
                "attack_pps", "duration", "seed", "source_count", "packet_count",
                "attack_pcap", "workload", "object_file", "outstanding", "pulse_on",
                "pulse_off", "nft_source_rate", "nft_source_burst",
                "nft_global_rate", "nft_global_burst", "capture", "capture_limit",
            )
        },
        "pulse_on_seconds": config.pulse_on,
        "pulse_off_seconds": config.pulse_off,
        "kernel": command_run(["uname", "-r"], capture=True).strip(),
        "workload": str(config.workload), "workload_sha256": sha256(config.workload),
        "environment": environment_metadata(),
    }
    save_state(state)
    try:
        if config.config is not None:
            # Preserve the profile used to reproduce this run.
            shutil.copyfile(config.config, run_dir / "experiment.toml")
            results["profile_sha256"] = sha256(config.config)
        print("Creating isolated network namespaces...", flush=True)
        setup_network(state, config.legit_clients)
        dns = start_dns(run_dir / "dnsmasq.log")
        check_dns_ready(dns)

        pcap = None
        if config.attack_pps > 0:
            pcap = run_dir / "attack.pcap"
            if config.attack_pcap:
                results["original_attack_pcap_sha256"] = sha256(config.attack_pcap)
                results["attack_packet_count"] = retarget_custom_pcap(
                    config.attack_pcap, pcap, get_mac(NS_CLIENT, IF_CLIENT),
                    get_mac(NS_SERVER, IF_SERVER), SERVER_IP)
            else:
                generate(pcap, config.scenario, config.source_count, config.packet_count,
                         get_mac(NS_CLIENT, IF_CLIENT), get_mac(NS_SERVER, IF_SERVER),
                         SERVER_IP, config.seed)
                results["attack_packet_count"] = config.packet_count
            results["attack_pcap_sha256"] = sha256(pcap)
            results["attack_pcap"] = str(pcap)

        pin_dir = None
        if config.mode == "xdp":
            obj = config.object_file if config.object_file else compile_xdp(run_dir)
            results["xdp_object_sha256"] = sha256(obj)
            results["xdp_source_sha256"] = xdp_source_fingerprint() if not config.object_file else None
            pin_dir = load_xdp(obj, run_id, state)
            filter_before = read_stats(str(pin_dir / "maps/stat_map"))
        elif config.mode == "nft":
            results["nft_ruleset"] = str(install_nft(run_dir, config))
            filter_before = nft_counters()
            results["nft_config"] = {
                "source_rate": config.nft_source_rate, "source_burst": config.nft_source_burst,
                "global_rate": config.nft_global_rate, "global_burst": config.nft_global_burst,
            }
        else:
            filter_before = {}

        if config.capture:
            print("Capturing bounded legitimate DNS packets (debug mode)...", flush=True)
            captures = start_captures(run_dir, config.capture_limit)

        print("Starting synchronized traffic...", flush=True)
        dns_results, attack_results, performance_before, performance_after = run_traffic(
            config, run_dir, pcap,
            on_window_start=lambda: snapshot(dns.pid),
            on_window_end=lambda: snapshot(dns.pid),
        )
        if performance_before is None or performance_after is None:
            raise RuntimeError("No complete traffic-window performance measurements")
        results["performance"] = summarize(performance_before, performance_after)
        results["performance_samples"] = {
            "before": performance_before, "after": performance_after,
        }
        if captures:
            results["capture"] = stop_captures(captures)
            captures = []
            # An empty server capture is possible if XDP drops every query.
            # Preserve it as evidence rather than discarding a valid experiment.
        results["dns"] = dns_results
        results["attack"] = attack_results
        if config.mode == "xdp":
            filter_after = read_stats(str(pin_dir / "maps/stat_map"))
            deltas = {name: filter_after[index] - filter_before[index]
                      for index, name in enumerate(STAT_NAMES)}
            results["xdp_deltas"] = deltas
            results["xdp_checks"] = {
                "outcomes": deltas["DNS_QUERIES"] == deltas["DNS_PASS"] + deltas["PACKET_DROP"],
                "drops": deltas["PACKET_DROP"] == sum(deltas[name] for name in (
                    "DROP_SOURCE_LIMIT", "DROP_GLOBAL_LIMIT", "DROP_SOURCE_COMMIT", "DROP_INTERNAL_ERROR")),
            }
        elif config.mode == "nft":
            filter_after = nft_counters()
            results["nft_deltas"] = {
                name: filter_after[name] - filter_before[name] for name in filter_after
            }
        results["status"] = "completed"
        # Report impossible accounting as a failed run, not a data point.
        prelim_errors, _ = inspect_result({**results, "cleanup_status": "ok"})
        if prelim_errors:
            raise RuntimeError("Benchmark measurements failed checks: " + "; ".join(prelim_errors))
        results["measurement_note"] = (
            "Interface/CPU measurements cover the attack window. DNS success is "
            "collected after dnsperf's timeout drain; first-packet launch skew is not measured."
        )
        print(f"NOERROR success: {dns_results['noerror']}/{dns_results['sent']} "
              f"({dns_results['success_percent']:.2f}%)")
        print(f"Ingress: {results['performance']['server_interface']['rx_pps']:.1f} PPS, "
              f"{results['performance']['server_interface']['rx_mbps']:.2f} Mbps")
        print(f"dnsmasq CPU: {results['performance']['dnsmasq_cpu_percent_one_core']:.1f}% of one core")
        if dns_results["avg_latency_sec"] is not None:
            print(f"Answered-query mean latency: {dns_results['avg_latency_sec'] * 1000:.3f} ms")
    except BaseException as error:
        results["status"] = "failed"
        results["error"] = str(error)
        raise
    finally:
        cleanup_errors = []
        if captures:
            try:
                results["capture"] = stop_captures(captures)
            except Exception as error:
                cleanup_errors.append("capture: " + str(error))
        if dns is not None:
            try:
                stop_process(dns)
            except Exception as error:
                cleanup_errors.append("dns: " + str(error))
        try:
            cleanup_lab(state)
        except Exception as error:
            cleanup_errors.append("lab: " + str(error))
        if cleanup_errors:
            results["status"] = "failed"
            results["cleanup_errors"] = cleanup_errors
            print("WARNING: cleanup failed; run 'harness.py cleanup':", cleanup_errors, file=sys.stderr)
        else:
            results["cleanup_status"] = "ok"
        results["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        write_json(run_dir / "summary.json", results)
    if cleanup_errors:
        raise RuntimeError("Experiment cleanup failed; see " + str(run_dir / "summary.json"))
    print("Saved results in:", run_dir)
    return results


def add_run_options(parser):
    parser.add_argument("--config", type=Path, default=None,
                        help="TOML experiment profile; CLI flags override it")
    parser.add_argument("--capture", dest="capture", action="store_true",
                        help="Capture bounded legitimate DNS queries/replies (adds overhead)")
    parser.add_argument("--no-capture", dest="capture", action="store_false",
                        help="Disable capture, including if enabled by a TOML profile")
    parser.set_defaults(capture=False)
    parser.add_argument("--capture-limit", type=int, default=2500,
                        help="Maximum packets per capture interface (default: 2500)")
    parser.add_argument("--tag", default="default", help="Label experiment series; reports keep tags separate")
    parser.add_argument("--mode", choices=("none", "nft", "xdp"), default="xdp")
    parser.add_argument("--scenario", choices=("none", "single", "subnet", "distributed", "pulsed", "custom"), default="none")
    parser.add_argument("--legit-qps", type=int, default=50)
    parser.add_argument("--legit-clients", type=int, default=1)
    parser.add_argument("--attack-pps", type=int, default=0)
    parser.add_argument("--duration", type=int, default=10)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--source-count", type=int, default=None)
    parser.add_argument("--packet-count", type=int, default=1024)
    parser.add_argument("--attack-pcap", type=Path, default=None)
    parser.add_argument("--workload", type=Path, default=ROOT / "src/tests/workloads/legitimate.txt")
    parser.add_argument("--object-file", type=Path, default=None)
    parser.add_argument("--outstanding", type=int, default=1000)
    parser.add_argument("--pulse-on", type=float, default=0)
    parser.add_argument("--pulse-off", type=float, default=0)
    parser.add_argument("--nft-source-rate", type=int, default=100)
    parser.add_argument("--nft-source-burst", type=int, default=10)
    parser.add_argument("--nft-global-rate", type=int, default=1000)
    parser.add_argument("--nft-global-burst", type=int, default=200)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Local-only ByteGuard comparison harness")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="Execute one fresh experiment")
    add_run_options(run)
    matrix = commands.add_parser("matrix", help="Execute matched mode/scenario/rate trials")
    add_run_options(matrix)
    matrix.add_argument("--modes", default="none,nft,xdp", help="Comma-separated modes")
    matrix.add_argument("--scenarios", default="single,subnet,distributed", help="Comma-separated scenarios")
    matrix.add_argument("--attack-pps-list", default="0,1000,3000", help="Comma-separated offered PPS")
    matrix.add_argument("--repeats", type=int, default=1)
    commands.add_parser("cleanup", help="Remove benchmark-owned active resources")
    latest = commands.add_parser("latest", help="Print the latest saved run folder")
    latest.add_argument("--tag", default=None)
    audit = commands.add_parser("verify", help="Audit completed v4 runs for measurement consistency")
    audit.add_argument("--tag", default=None, help="Only inspect runs carrying this tag")
    report = commands.add_parser("report", help="Build CSV, Markdown and optional PNG")
    report.add_argument("--charts", action="store_true")
    report.add_argument("--tag", default=None,
                        help="Only report v4 runs with this --tag (default: all v4 tags)")
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in ("run", "matrix"):
        apply_profile(run if argv[0] == "run" else matrix, argv[0], argv[1:])
    args = parser.parse_args(argv)
    if args.command in ("run", "matrix"):
        if args.config:
            args.config = args.config.resolve()
        args.workload = args.workload.resolve()
        if args.attack_pcap:
            args.attack_pcap = args.attack_pcap.resolve()
        if args.object_file:
            args.object_file = args.object_file.resolve()
    return args


def csv_values(raw, choices=None):
    values = [x.strip() for x in raw.split(",")]
    if not values or any(not x for x in values):
        raise ValueError("Empty matrix dimension")
    if choices and any(x not in choices for x in values):
        raise ValueError("Unknown matrix choice in " + raw)
    return values


def run_matrix(config):
    modes = csv_values(config.modes, ("none", "nft", "xdp"))
    scenarios = csv_values(config.scenarios, ("single", "subnet", "distributed", "pulsed", "custom"))
    rates = [int(x) for x in csv_values(config.attack_pps_list)]
    if config.repeats < 1:
        raise ValueError("repeats must be positive")
    combinations = [(scenario, rate) for scenario in scenarios for rate in rates
                    if rate != 0 or scenario == scenarios[0]]
    total = len(modes) * len(combinations) * config.repeats
    # Catch invalid later cells before starting an otherwise partial campaign.
    for scenario, rate in combinations:
        for mode in modes:
            current = copy.copy(config)
            current.mode, current.scenario, current.attack_pps = mode, scenario if rate else "none", rate
            validate_run(current)
    print(f"Matrix: {total} experiments (fresh namespaces and maps per run)", flush=True)
    count = 0
    for scenario, rate in combinations:
        for trial in range(config.repeats):
            for mode in modes:
                current = copy.copy(config)
                current.mode = mode
                current.scenario = scenario if rate else "none"
                current.attack_pps = rate
                current.source_count = config.source_count
                current.seed = config.seed + trial
                current.pulse_on = config.pulse_on
                current.pulse_off = config.pulse_off
                count += 1
                print(f"[{count}/{total}] {mode}, {current.scenario}, {rate} PPS, trial {trial + 1}", flush=True)
                run_one(current)
    make_report(False, tag=config.tag)


def main():
    config = parse_args()
    if config.command == "run":
        run_one(config)
    elif config.command == "matrix":
        run_matrix(config)
    elif config.command == "report":
        make_report(config.charts, tag=config.tag)
    elif config.command == "verify":
        sys.exit(verify(config.tag))
    elif config.command == "latest":
        matches = []
        for path in RUNS_DIR.glob("*/summary.json"):
            try:
                data = json.loads(path.read_text())
            except (OSError, ValueError):
                continue
            if config.tag is None or data.get("run_tag") == config.tag:
                matches.append(path)
        if not matches:
            raise RuntimeError("No saved runs" + (" with tag " + config.tag if config.tag else ""))
        recent = max(matches, key=lambda path: path.stat().st_mtime_ns)
        print(recent.parent)
        print("Summary:", recent)
        print("Status:", json.loads(recent.read_text()).get("status"))
    elif config.command == "cleanup":
        if os.geteuid() != 0:
            raise RuntimeError("cleanup needs sudo")
        state = active_state()
        if state is None:
            print("No active benchmark lab")
        else:
            cleanup_lab(state)
            print("Benchmark lab cleaned up")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print("ERROR:", error, file=sys.stderr)
        sys.exit(1)
