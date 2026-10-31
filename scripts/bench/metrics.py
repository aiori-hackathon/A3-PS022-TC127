"""Read CPU and interface counters without adding measurement traffic."""
import os
import time

from bench_common import NS_SERVER, IF_SERVER, command_ns, command_run


def process_cpu_ticks(pid):
    # /proc/PID/stat field 2 is a parenthesized comm that can contain spaces.
    text = open(f"/proc/{pid}/stat").read()
    fields = text.rsplit(")", 1)[1].strip().split()
    return int(fields[11]) + int(fields[12])  # utime and stime, fields 14 and 15


def host_cpu_ticks():
    with open("/proc/stat") as file:
        line = file.readline()
    if not line.startswith("cpu "):
        raise RuntimeError("Cannot read /proc/stat CPU aggregate")
    values = [int(x) for x in line.split()[1:9]]
    return {"total": sum(values), "idle": values[3] + values[4],
            "softirq": values[6], "irq": values[5],
            "system": values[2], "user": values[0] + values[1]}


def interface_counters():
    text = command_run(command_ns(NS_SERVER, ["cat", "/proc/net/dev"]), capture=True)
    for line in text.splitlines():
        if ":" not in line:
            continue
        name, numbers = line.split(":", 1)
        if name.strip() != IF_SERVER:
            continue
        parts = [int(value) for value in numbers.split()]
        return {"rx_bytes": parts[0], "rx_packets": parts[1],
                "rx_dropped": parts[3], "tx_bytes": parts[8],
                "tx_packets": parts[9]}
    raise RuntimeError("Could not read server interface counters in /proc/net/dev")


def snapshot(dns_pid):
    return {"time": time.monotonic(), "host": host_cpu_ticks(),
            "dns_ticks": process_cpu_ticks(dns_pid),
            "interface": interface_counters()}


def summarize(before, after):
    seconds = after["time"] - before["time"]
    if seconds <= 0:
        raise RuntimeError("Invalid measurement duration")
    ticks = os.sysconf("SC_CLK_TCK")
    dns_cpu_seconds = (after["dns_ticks"] - before["dns_ticks"]) / ticks
    net_delta = {key: after["interface"][key] - before["interface"][key]
                 for key in before["interface"]}
    cpu_delta = {key: after["host"][key] - before["host"][key]
                 for key in before["host"]}
    total = cpu_delta["total"]
    if total <= 0 or any(value < 0 for value in net_delta.values()):
        raise RuntimeError("Non-monotonic system/network counters")
    return {
        "measurement_seconds": seconds,
        "dnsmasq_cpu_seconds": dns_cpu_seconds,
        "dnsmasq_cpu_percent_one_core": 100.0 * dns_cpu_seconds / seconds,
        "host_cpu_busy_percent_all_cores": 100.0 * (total - cpu_delta["idle"]) / total,
        "host_softirq_percent_capacity": 100.0 * cpu_delta["softirq"] / total,
        "host_irq_percent_capacity": 100.0 * cpu_delta["irq"] / total,
        "host_system_percent_capacity": 100.0 * cpu_delta["system"] / total,
        "host_user_percent_capacity": 100.0 * cpu_delta["user"] / total,
        "server_interface": {
            **net_delta,
            "rx_pps": net_delta["rx_packets"] / seconds,
            "rx_mbps": net_delta["rx_bytes"] * 8 / seconds / 1_000_000,
            "tx_pps": net_delta["tx_packets"] / seconds,
            "tx_mbps": net_delta["tx_bytes"] * 8 / seconds / 1_000_000,
        },
    }
