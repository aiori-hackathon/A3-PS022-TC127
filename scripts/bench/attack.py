"""Generate deterministic DNS traffic for a private veth lab only."""
import hashlib
from pathlib import Path


def source_ip(scenario, index):
    if scenario == "single":
        return "10.20.0.1"
    if scenario == "subnet":
        return "10.20.0." + str(index % 254 + 1)
    if scenario in ("distributed", "pulsed"):
        # Spread successive /24 blocks across separate /16 prefixes.
        second = 20 + (index // 254) % 180
        third = (index // (254 * 180)) % 250
        fourth = index % 254 + 1
        return f"10.{second}.{third}.{fourth}"
    raise ValueError("Unknown built-in scenario: " + scenario)


def generate(path, scenario, source_count, packet_count, client_mac, server_mac,
             server_ip, seed):
    try:
        from scapy.all import DNS, DNSQR, Ether, IP, UDP, wrpcap
    except ImportError as exc:
        raise RuntimeError("Install python-scapy to generate built-in PCAP workloads") from exc

    # Scapy is used to build the frames; traffic injection is restricted to
    # the harness-owned veth pair, not an arbitrary user-supplied interface.
    import random
    rng = random.Random(seed)
    packets = []
    for index in range(packet_count):
        source_index = index % source_count
        source = source_ip(scenario, source_index)
        source_port = 40000 + (index % 20000)
        dns_id = rng.randrange(0, 65536)
        packet = (Ether(src=client_mac, dst=server_mac) /
                  IP(src=source, dst=server_ip) /
                  UDP(sport=source_port, dport=53) /
                  DNS(id=dns_id, qr=0, qd=DNSQR(qname="attack.bench.test.", qtype="A")))
        # Capture bytes/timestamps are deterministic for identical inputs.
        packet.time = index * 0.001
        packets.append(packet)
    wrpcap(str(path), packets)


def retarget_custom_pcap(input_path, output_path, client_mac, server_mac, server_ip):
    """Copy DNS/UDP/IPv4 packets into the lab's addresses and L2 endpoints.

    Original QNAMEs, source IPs and DNS flags are preserved. Non-DNS frames
    are rejected so a benchmark cannot silently exercise another path.
    """
    try:
        from scapy.all import Ether, IP, UDP, rdpcap, wrpcap
    except ImportError as exc:
        raise RuntimeError("Install python-scapy to import custom PCAP workloads") from exc

    packets = rdpcap(str(input_path))
    if not packets:
        raise ValueError("Custom PCAP contains no packets")
    for packet in packets:
        if not (Ether in packet and IP in packet and UDP in packet and packet[UDP].dport == 53):
            raise ValueError("Custom PCAP must contain only Ethernet/IPv4/UDP DNS queries")
        packet[Ether].src = client_mac
        packet[Ether].dst = server_mac
        packet[IP].dst = server_ip
        if hasattr(packet[IP], "chksum"):
            del packet[IP].chksum
        if hasattr(packet[UDP], "chksum"):
            del packet[UDP].chksum
        if hasattr(packet[IP], "len"):
            del packet[IP].len
        if hasattr(packet[UDP], "len"):
            del packet[UDP].len
    wrpcap(str(output_path), packets)
    return len(packets)


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as file:
        while True:
            block = file.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()
