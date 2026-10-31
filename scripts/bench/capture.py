"""Optional packet-level evidence from the disposable DNS benchmark namespaces.

Capture only the synthetic legitimate clients and their replies. This is a
bounded debug/evidence mode, not a performance measurement configuration.
"""
import subprocess
import time
from pathlib import Path

from bench_common import NS_CLIENT, NS_SERVER, IF_CLIENT, IF_SERVER, SERVER_IP, command_ns
from lab_env import stop_process

# Exclude built-in spoofed attack sources (10.20.0.0 and other ranges).
# A custom PCAP that spoofs a legitimate address can still appear here.
LEGIT_DNS_FILTER = (
    "udp port 53 and ((src net 10.10.0.0/24 and dst host " + SERVER_IP + ")"
    " or (src host " + SERVER_IP + " and dst net 10.10.0.0/24))"
)


def start_captures(run_dir, limit):
    """Start two bounded tcpdump processes and wait for ready messages."""
    captures = []
    try:
        for label, namespace, interface in (
            ("client", NS_CLIENT, IF_CLIENT),
            ("server", NS_SERVER, IF_SERVER),
        ):
            path = run_dir / (label + ".pcap")
            log_path = run_dir / (label + "_tcpdump.log")
            command = command_ns(namespace, [
                "tcpdump", "-i", interface, "-n", "-U", "-s", "0",
                "-c", str(limit), "-w", str(path), LEGIT_DNS_FILTER,
            ])
            with log_path.open("w") as log:
                proc = subprocess.Popen(command, stdout=subprocess.DEVNULL,
                                        stderr=log, start_new_session=True)
            captures.append((label, proc, path, log_path))
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if "listening on" in log_path.read_text(errors="replace"):
                    break
                if proc.poll() is not None:
                    raise RuntimeError("tcpdump failed; inspect " + str(log_path))
                time.sleep(0.05)
            else:
                raise RuntimeError("tcpdump not ready; inspect " + str(log_path))
        return captures
    except BaseException:
        stop_captures(captures, make_traces=False)
        raise


def stop_captures(captures, make_traces=True):
    """Stop tcpdump and optionally decode bounded raw packets to readable text."""
    evidence = {}
    for label, process, path, log_path in captures:
        stop_process(process)
        item = {
            "pcap": str(path),
            "pcap_bytes": path.stat().st_size if path.exists() else 0,
            "tcpdump_log": str(log_path),
        }
        if make_traces and item["pcap_bytes"] > 24:
            text_path = path.with_suffix(".txt")
            # Limit the text preview; the PCAP contains the original raw packets.
            decoded = subprocess.run(
                ["tcpdump", "-nn", "-tttt", "-r", str(path)],
                text=True, capture_output=True, check=True,
            )
            lines = decoded.stdout.splitlines()
            text_path.write_text("\n".join(lines[:200]) + "\n")
            item["preview"] = str(text_path)
            item["preview_packets"] = min(200, len(lines))
        evidence[label] = item
    return evidence
