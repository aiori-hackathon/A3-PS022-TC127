"""An nftables netdev-ingress comparison, scoped to the owned server namespace."""
import json
from pathlib import Path

from bench_common import NS_SERVER, IF_SERVER, command_ns, command_run

TABLE = "byteguard_bench"
RULES = ("source_limit", "global_limit", "admitted")


def ruleset(source_rate=100, source_burst=10, global_rate=1000, global_burst=200):
    for value in (source_rate, source_burst, global_rate, global_burst):
        if not isinstance(value, int) or value < 1:
            raise ValueError("All nftables rate/burst values must be positive integers")
    return f'''table netdev {TABLE} {{
    chain ingress {{
        type filter hook ingress device "{IF_SERVER}" priority 0; policy accept;
        ip protocol udp udp dport 53 meter bg_source {{ ip saddr timeout 60s limit rate over {source_rate}/second burst {source_burst} packets }} counter drop comment "source_limit"
        ip protocol udp udp dport 53 limit rate over {global_rate}/second burst {global_burst} packets counter drop comment "global_limit"
        ip protocol udp udp dport 53 counter accept comment "admitted"
    }}
}}
'''


def install_nft(run_dir, config):
    file = Path(run_dir) / "nftables.nft"
    file.write_text(ruleset(config.nft_source_rate, config.nft_source_burst,
                            config.nft_global_rate, config.nft_global_burst))
    # Syntax/kernel check before installing: failures must not be treated as valid benchmark runs.
    command_run(command_ns(NS_SERVER, ["nft", "-c", "-f", str(file)]))
    command_run(command_ns(NS_SERVER, ["nft", "-f", str(file)]))
    return file


def nft_counters():
    raw = command_run(command_ns(NS_SERVER, ["nft", "-j", "list", "table", "netdev", TABLE]), capture=True)
    data = json.loads(raw)
    counts = {name: 0 for name in RULES}
    found = set()
    for item in data.get("nftables", []):
        rule = item.get("rule")
        if rule is None:
            continue
        label = rule.get("comment")
        if label not in counts:
            continue
        for expression in rule.get("expr", []):
            counter = expression.get("counter")
            if isinstance(counter, dict):
                counts[label] = int(counter["packets"])
                found.add(label)
                break
    if found != set(RULES):
        raise RuntimeError("Missing nftables rule counters: " + ", ".join(sorted(set(RULES) - found)))
    counts["total_dns"] = sum(counts[name] for name in RULES)
    return counts
