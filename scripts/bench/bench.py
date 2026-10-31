import argparse
import re
import signal
import subprocess
from pathlib import Path

from stats import read_stats, STAT_NAMES


def run_dnsperf(qps, duration, workload):
    command = [
        "ip", "netns", "exec", "bg-a",
        "dnsperf",
        "-s", "10.10.0.2",
        "-a", "10.10.0.1",
        "-d", str(workload),
        "-l", str(duration),
        "-Q", str(qps),
        "-q", "100",
        "-t", "1"
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print(result.stderr)
        raise RuntimeError("dnsperf failed")

    return result.stdout


def start_attack(pps, pcap, log_file):
    command = [
        "ip", "netns", "exec", "bg-a",
        "tcpreplay",
        "--pps", str(pps),
        "--loop=0",
        "--preload-pcap",
        "-i", "veth-a",
        str(pcap)
    ]

    print("Starting attack traffic...", flush=True)

    process = subprocess.Popen(
        command,
        stdout=log_file,
        stderr=subprocess.STDOUT
    )

    return process


def stop_attack(process):
    if process is None:
        return

    if process.poll() is None:
        process.send_signal(signal.SIGINT)

        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def get_count(output, label):
    for line in output.splitlines():
        line = line.strip()

        if line.startswith(label + ":"):
            value = line.split(":", 1)[1].strip()
            return int(value.split()[0])

    raise ValueError("Missing dnsperf metric: " + label)


def print_results(output, before, after):
    sent = get_count(output, "Queries sent")
    completed = get_count(output, "Queries completed")
    lost = get_count(output, "Queries lost")

    match = re.search(r"\bNOERROR\s+(\d+)", output)
    noerror = int(match.group(1)) if match else 0

    success_rate = 100 * noerror / sent if sent else 0

    print("\nDNS Results")
    print("-" * 40)
    print("Sent:", sent)
    print("Completed:", completed)
    print("Lost:", lost)
    print("NOERROR responses:", noerror)
    print(f"NOERROR success rate: {success_rate:.2f}%")

    print("\nXDP Statistics (this run)")
    print("-" * 40)

    for counter_id in range(len(STAT_NAMES)):
        old_value = before.get(counter_id, 0)
        new_value = after.get(counter_id, 0)
        difference = new_value - old_value

        print(f"{STAT_NAMES[counter_id]:<25} {difference:>10}")


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--legit-qps", type=int, default=50)
    parser.add_argument("--attack-pps", type=int, default=0)
    parser.add_argument("--duration", type=int, default=10)

    parser.add_argument(
        "--pcap",
        default="/tmp/byteguard_bench.pcap"
    )

    parser.add_argument(
        "--map",
        default="/sys/fs/bpf/byteguard_stats_test2/maps/stat_map"
    )

    parser.add_argument(
        "--workload",
        default="src/tests/workloads/legitimate.txt"
    )

    args = parser.parse_args()

    if args.legit_qps <= 0 or args.duration <= 0 or args.attack_pps < 0:
        parser.error("Invalid QPS, PPS or duration")

    if not Path(args.workload).is_file():
        parser.error("Workload file not found")

    if args.attack_pps > 0 and not Path(args.pcap).is_file():
        parser.error("Attack PCAP not found")

    output_dir = Path("build/bench")
    output_dir.mkdir(parents=True, exist_ok=True)

    before = read_stats(args.map)

    attack_process = None
    output = None

    with open(output_dir / "attack.log", "w") as attack_log:
        try:
            if args.attack_pps > 0:
                attack_process = start_attack(
                    args.attack_pps,
                    args.pcap,
                    attack_log
                )

            print("Running legitimate DNS traffic...", flush=True)

            output = run_dnsperf(
                args.legit_qps,
                args.duration,
                args.workload
            )

        finally:
            stop_attack(attack_process)

    after = read_stats(args.map)

    if output is not None:
        (output_dir / "dnsperf.log").write_text(output)
        print_results(output, before, after)

    print("\nLogs saved under build/bench/")


if __name__ == "__main__":
    main()