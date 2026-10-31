"""Create/own/clean ephemeral namespaces, DNS server and XDP pins."""
import json
import os
import signal
import struct
import subprocess
import time
from pathlib import Path

from bench_common import (
    ROOT, STATE_FILE, NS_CLIENT, NS_SERVER, IF_CLIENT, IF_SERVER,
    CLIENT_IP, SERVER_IP, command_run, command_ns, write_json,
)

def active_state():
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return None


def save_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    write_json(STATE_FILE, state)


def namespace_exists(name):
    names = command_run(["ip", "netns", "list"], capture=True)
    return any(line.split()[0] == name for line in names.splitlines() if line.strip())


def require_exclusive_lab():
    if STATE_FILE.exists():
        raise RuntimeError("Previous lab state exists; run 'harness.py cleanup' first")
    for name in (NS_CLIENT, NS_SERVER):
        if namespace_exists(name):
            raise RuntimeError(f"Namespace {name} already exists; will not modify it")
    for interface in (IF_CLIENT, IF_SERVER):
        if subprocess.run(["ip", "link", "show", interface], capture_output=True).returncode == 0:
            raise RuntimeError(f"Host interface {interface} already exists; will not modify it")


def legitimate_client_ip(index):
    if index == 0:
        return CLIENT_IP
    return "10.10.0." + str(100 + index)


def setup_network(state, clients):
    for namespace in (NS_CLIENT, NS_SERVER):
        command_run(["ip", "netns", "add", namespace])
        state["namespaces"].append(namespace)
        save_state(state)

    command_run(["ip", "link", "add", IF_CLIENT, "type", "veth", "peer", "name", IF_SERVER])
    state["host_veth_created"] = True
    save_state(state)

    command_run(["ip", "link", "set", IF_CLIENT, "netns", NS_CLIENT])
    command_run(["ip", "link", "set", IF_SERVER, "netns", NS_SERVER])
    for namespace, interface, address in (
        (NS_CLIENT, IF_CLIENT, CLIENT_IP),
        (NS_SERVER, IF_SERVER, SERVER_IP),
    ):
        command_run(["ip", "-n", namespace, "link", "set", "lo", "up"])
        command_run(["ip", "-n", namespace, "addr", "add", address + "/24", "dev", interface])
        command_run(["ip", "-n", namespace, "link", "set", interface, "up"])
    # Different real sender IPs let us test protection across legitimate clients.
    for index in range(1, clients):
        address = legitimate_client_ip(index)
        command_run(["ip", "-n", NS_CLIENT, "addr", "add", address + "/24",
                     "dev", IF_CLIENT])


def get_mac(namespace, interface):
    raw = command_run(["ip", "-j", "-n", namespace, "link", "show", "dev", interface], capture=True)
    return json.loads(raw)[0]["address"]


def start_dns(log_file):
    command = command_ns(NS_SERVER, [
        "dnsmasq", "--no-daemon", "--conf-file=/dev/null", "--no-resolv",
        "--no-hosts", "--bind-interfaces", "--listen-address=" + SERVER_IP,
        "--port=53", "--address=/bench.test/" + SERVER_IP,
        "--local=/bench.test/",
    ])
    log_handle = log_file.open("w")
    try:
        process = subprocess.Popen(command, stdout=log_handle, stderr=subprocess.STDOUT,
                                   start_new_session=True)
    finally:
        log_handle.close()
    return process


def check_dns_ready(server_process):
    for attempt in range(30):
        if server_process.poll() is not None:
            raise RuntimeError("dnsmasq exited before becoming ready")
        probe = subprocess.run(command_ns(NS_CLIENT, [
            "dig", "@" + SERVER_IP, "www.bench.test", "A", "+short", "+tries=1", "+time=1"
        ]), capture_output=True, text=True)
        if probe.returncode == 0 and SERVER_IP in probe.stdout.splitlines():
            return
        time.sleep(0.15)
    raise RuntimeError("dnsmasq did not answer readiness probe")


def compile_xdp(run_dir):
    obj = run_dir / "xdp.bpf.o"
    # Share compiler flags and distro-specific header paths with the controller.
    output = command_run(["make", "-C", str(ROOT), "BPF_OBJ=" + str(obj), "bpf"], capture=True)
    (run_dir / "xdp-build.log").write_text(output)
    return obj


def load_xdp(object_path, run_id, state):
    pin_dir = Path("/sys/fs/bpf") / ("byteguard_bench_" + run_id)
    if pin_dir.exists():
        raise RuntimeError("Pinned directory already exists: " + str(pin_dir))
    (pin_dir / "maps").mkdir(parents=True)
    state["pin_dir"] = str(pin_dir)
    save_state(state)
    command_run(["bpftool", "prog", "load", str(object_path), str(pin_dir / "program"),
                 "type", "xdp", "pinmaps", str(pin_dir / "maps")])

    # global_state: bpf_spin_lock u32, 4 padding bytes, credit u64, last_refill_ns u64.
    # These initialization constants must match global_bucket.h.
    initial_credit = 200 * 1_000_000_000
    now = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    value = struct.pack("=I4xQQ", 0, initial_credit, now)
    hex_bytes = [f"{byte:02x}" for byte in value]
    command_run(["bpftool", "map", "update", "pinned", str(pin_dir / "maps/global_map"),
                 "key", "hex", "00", "00", "00", "00", "value", "hex"] + hex_bytes)

    # bpffs pins may not be visible through the mount namespace created by
    # ip netns exec. Resolve on the host, then attach by kernel program ID.
    raw = command_run(["bpftool", "-j", "prog", "show", "pinned",
                       str(pin_dir / "program")], capture=True)
    program_id = json.loads(raw)["id"]
    # Deliberately NO overwrite: this is an exclusively owned veth.
    command_run(command_ns(NS_SERVER, ["bpftool", "net", "attach", "xdpdrv",
                            "id", str(program_id), "dev", IF_SERVER]))
    return pin_dir


def stop_process(process):
    if process is None:
        return
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGCONT)
            os.killpg(process.pid, signal.SIGINT)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()


def cleanup_lab(state):
    # The state file must have been created by this harness.
    if state.get("owner") != "byteguard-bench-kit-v1":
        raise RuntimeError("Unrecognized lab state; refusing automatic cleanup")
    for namespace in state.get("namespaces", []):
        if not namespace_exists(namespace):
            continue
        # The harness created these namespaces exclusively. Stop lingering
        # processes inside them, including dnsmasq after a crashed parent.
        text = command_run(["ip", "netns", "pids", namespace], capture=True)
        for pid_text in text.split():
            try:
                os.kill(int(pid_text), signal.SIGTERM)
            except ProcessLookupError:
                pass
    time.sleep(0.2)
    for namespace in state.get("namespaces", []):
        if not namespace_exists(namespace):
            continue
        for pid_text in command_run(["ip", "netns", "pids", namespace], capture=True).split():
            try:
                os.kill(int(pid_text), signal.SIGKILL)
            except ProcessLookupError:
                pass
    if NS_SERVER in state.get("namespaces", []) and namespace_exists(NS_SERVER):
        subprocess.run(command_ns(NS_SERVER, ["bpftool", "net", "detach", "xdpdrv", "dev", IF_SERVER]),
                       capture_output=True, check=False)

    pin_text = state.get("pin_dir")
    if pin_text:
        pin = Path(pin_text)
        if pin.parent != Path("/sys/fs/bpf") or not pin.name.startswith("byteguard_bench_"):
            raise RuntimeError("Unsafe pin_dir in state: " + str(pin))
        if pin.exists():
            for entry in (pin / "maps").glob("*"):
                entry.unlink()
            if (pin / "program").exists():
                (pin / "program").unlink()
            if (pin / "maps").exists():
                (pin / "maps").rmdir()
            pin.rmdir()

    for namespace in reversed(state.get("namespaces", [])):
        if namespace_exists(namespace):
            command_run(["ip", "netns", "del", namespace])
    if state.get("host_veth_created"):
        # Only a partially created host-side veth can still exist here.
        subprocess.run(["ip", "link", "del", IF_CLIENT], capture_output=True, check=False)
    if STATE_FILE.exists():
        STATE_FILE.unlink()
