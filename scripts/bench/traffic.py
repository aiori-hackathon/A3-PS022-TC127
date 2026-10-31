"""Run local DNS clients and a bounded synthetic attack together.

The offered-load window ends at the specified duration, even when dnsperf
waits an extra second for DNS response timeouts. We preserve its output for
valid response-success calculations after the attack has stopped.
"""
import os
import re
import select
import signal
import subprocess
import sys
import time

from bench_common import NS_CLIENT, IF_CLIENT, SERVER_IP, GATE, command_ns
from lab_env import legitimate_client_ip, stop_process


def start_gated(command, output_path):
    read_fd, write_fd = os.pipe()
    ready_read, ready_write = os.pipe()
    handle = output_path.open("w")
    try:
        process = subprocess.Popen(
            [sys.executable, str(GATE), str(read_fd), str(ready_write), "--"] + command,
            pass_fds=(read_fd, ready_write), stdout=handle,
            stderr=subprocess.STDOUT, start_new_session=True,
        )
    except BaseException:
        for fd in (read_fd, write_fd, ready_read, ready_write):
            os.close(fd)
        raise
    finally:
        handle.close()
    os.close(read_fd)
    os.close(ready_write)
    return process, write_fd, ready_read


def wait_ready(fd, process):
    readable, _, _ = select.select([fd], [], [], 5.0)
    if not readable or os.read(fd, 1) != b"R":
        raise RuntimeError("Workload did not reach its start barrier")
    os.close(fd)
    if process.poll() is not None:
        raise RuntimeError("Workload exited before start")


def release_gate(fd):
    os.write(fd, b"1")
    os.close(fd)


def parse_dnsperf(text):
    numbers = {}
    for key, pattern in (
        ("sent", r"Queries sent:\s*(\d+)"),
        ("completed", r"Queries completed:\s*(\d+)"),
        ("lost", r"Queries lost:\s*(\d+)"),
        ("noerror", r"\bNOERROR\s+(\d+)"),
        ("avg_latency_sec", r"Average Latency \(s\):\s*([\d.]+)"),
        ("latency_stddev_sec", r"Latency StdDev \(s\):\s*([\d.]+)"),
        ("reported_qps", r"Queries per second:\s*([\d.]+)"),
    ):
        match = re.search(pattern, text)
        if match is None and key in ("sent", "completed", "lost"):
            raise RuntimeError("dnsperf output missing '" + key + "'")
        if key == "noerror":
            numbers[key] = int(match.group(1)) if match else 0
        elif key in ("avg_latency_sec", "latency_stddev_sec", "reported_qps"):
            numbers[key] = float(match.group(1)) if match else None
        else:
            numbers[key] = int(match.group(1))
    latency = re.search(r"Average Latency \(s\):\s*[\d.]+ \(min ([\d.]+), max ([\d.]+)\)", text)
    numbers["min_latency_sec"] = float(latency.group(1)) if latency else None
    numbers["max_latency_sec"] = float(latency.group(2)) if latency else None
    numbers["success_percent"] = 100.0 * numbers["noerror"] / numbers["sent"] if numbers["sent"] else 0.0
    return numbers


def parse_tcpreplay(text):
    match = re.search(r"Actual:\s*(\d+) packets .*? in ([\d.]+) seconds", text)
    packets = int(match.group(1)) if match else None
    seconds = float(match.group(2)) if match else None
    return {
        "sent_packets": packets,
        "replay_elapsed_seconds": seconds,
        "replay_average_pps": packets / seconds if packets is not None and seconds else None,
    }


def run_traffic(config, run_dir, pcap, on_window_start=None, on_window_end=None):
    """Run workloads; optional callbacks snapshot measurements at the traffic window.

    Returns (dns_results, attack_results, before_snapshot, after_snapshot).
    The end callback runs AFTER the attacker is stopped but BEFORE dnsperf
    spends any further time draining DNS response timeouts.
    """
    attacker_command = None
    if pcap is not None:
        attacker_command = command_ns(NS_CLIENT, [
            "tcpreplay", "--pps=" + str(config.attack_pps), "--loop=0",
            "--preload-pcap", "-i", IF_CLIENT, str(pcap),
        ])

    legitimate = []
    attack = None
    attack_fd = attack_ready = None
    before_snapshot = after_snapshot = None
    release_span_ms = 0.0
    start = None
    stop_at = None
    try:
        for index in range(config.legit_clients):
            qps = config.legit_qps // config.legit_clients
            if index < config.legit_qps % config.legit_clients:
                qps += 1
            command = command_ns(NS_CLIENT, [
                "dnsperf", "-s", SERVER_IP, "-a", legitimate_client_ip(index),
                "-d", str(config.workload), "-l", str(config.duration),
                "-Q", str(qps), "-q", str(config.outstanding), "-t", "1",
            ])
            log = run_dir / ("dnsperf.log" if config.legit_clients == 1
                             else f"dnsperf_{index}.log")
            process, gate_fd, ready_fd = start_gated(command, log)
            legitimate.append({"process": process, "gate": gate_fd,
                               "ready": ready_fd, "log": log})
        if attacker_command:
            attack, attack_fd, attack_ready = start_gated(attacker_command, run_dir / "attack.log")

        for client in legitimate:
            wait_ready(client["ready"], client["process"])
            client["ready"] = None
        if attack_ready is not None:
            wait_ready(attack_ready, attack)
            attack_ready = None

        # Measurement starts at barrier release, not during launcher creation.
        if on_window_start is not None:
            before_snapshot = on_window_start()
        start = time.monotonic()
        stop_at = start + config.duration
        release_start_ns = time.monotonic_ns()
        if attack_fd is not None:
            release_gate(attack_fd)
            attack_fd = None
        for client in legitimate:
            release_gate(client["gate"])
            client["gate"] = None
        release_span_ms = (time.monotonic_ns() - release_start_ns) / 1_000_000

        attacker_paused = False
        while time.monotonic() < stop_at:
            elapsed = time.monotonic() - start
            for client in legitimate:
                code = client["process"].poll()
                if code is not None and code != 0:
                    raise RuntimeError("dnsperf exited unsuccessfully; see " + str(client["log"]))
            if attack is not None and attack.poll() is not None:
                raise RuntimeError("tcpreplay exited early; inspect attack.log")
            if attack is not None and config.pulse_on > 0:
                period = config.pulse_on + config.pulse_off
                active = (elapsed % period) < config.pulse_on
                try:
                    if active and attacker_paused:
                        os.killpg(attack.pid, signal.SIGCONT)
                        attacker_paused = False
                    elif not active and not attacker_paused:
                        os.killpg(attack.pid, signal.SIGSTOP)
                        attacker_paused = True
                except ProcessLookupError as error:
                    raise RuntimeError("Attack disappeared during pulse") from error
            time.sleep(min(0.02, max(0.0, stop_at - time.monotonic())))

        # The ATTACK STOPS at the requested duration, not after dnsperf drains
        # one-second request timeouts. Otherwise filtered modes run longer.
        stop_process(attack)
        if on_window_end is not None:
            after_snapshot = on_window_end()

        # Allow dnsperf to finish its own scheduled 10s send + timeout drain.
        # Failing/stranded clients are not silently accepted as completed runs.
        for client in legitimate:
            try:
                code = client["process"].wait(timeout=5)
            except subprocess.TimeoutExpired as error:
                raise RuntimeError("dnsperf did not finish within 5s of traffic cutoff") from error
            if code != 0:
                raise RuntimeError("dnsperf exited unsuccessfully; see " + str(client["log"]))
    finally:
        for client in legitimate:
            for fd in (client["gate"], client["ready"]):
                if fd is not None:
                    os.close(fd)
            stop_process(client["process"])
        for fd in (attack_fd, attack_ready):
            if fd is not None:
                os.close(fd)
        stop_process(attack)

    individual = [parse_dnsperf(client["log"].read_text()) for client in legitimate]
    totals = {name: sum(client[name] for client in individual)
              for name in ("sent", "completed", "lost", "noerror")}
    totals["success_percent"] = (100 * totals["noerror"] / totals["sent"] if totals["sent"] else 0)
    totals["client_count"] = config.legit_clients
    totals["by_client"] = individual
    totals["gate_release_span_ms"] = release_span_ms
    totals["offered_window_seconds"] = config.duration
    totals["achieved_legit_sent_qps"] = totals["sent"] / config.duration
    completed_for_latency = sum(client["completed"] for client in individual
                                if client["avg_latency_sec"] is not None)
    totals["avg_latency_sec"] = (
        sum(client["avg_latency_sec"] * client["completed"] for client in individual
            if client["avg_latency_sec"] is not None) / completed_for_latency
        if completed_for_latency else None
    )
    totals["min_latency_sec"] = min(
        (client["min_latency_sec"] for client in individual if client["min_latency_sec"] is not None),
        default=None,
    )
    totals["max_latency_sec"] = max(
        (client["max_latency_sec"] for client in individual if client["max_latency_sec"] is not None),
        default=None,
    )
    totals["latency_stddev_sec"] = individual[0]["latency_stddev_sec"] if len(individual) == 1 else None
    totals["achieved_legit_noerror_qps"] = totals["noerror"] / config.duration
    attack_text = (run_dir / "attack.log").read_text() if attack else ""
    attack_results = parse_tcpreplay(attack_text) if attack else None
    if attack is not None and attack_results["sent_packets"] is None:
        raise RuntimeError("tcpreplay did not report its transmitted packet count; inspect attack.log")
    return totals, attack_results, before_snapshot, after_snapshot
