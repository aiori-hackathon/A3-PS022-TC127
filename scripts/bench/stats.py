import argparse
import json
import subprocess

# keeping order synchronized with xdp_main.c
STAT_NAMES = [
    "DNS_QUERIES",
    "SOURCE_HIT",
    "SOURCE_INSERT",
    "INSERT_RACE",
    "MAP_ERROR",
    "PACKET_DROP",
    "DNS_PASS",
    "DROP_SOURCE_LIMIT",
    "DROP_GLOBAL_LIMIT",
    "DROP_SOURCE_COMMIT",
    "DROP_INTERNAL_ERROR",
    "GLOBAL_REFUND",
]


def decode_number(raw):
    """Convert bpftool's little-endian byte array into an integer."""
    if isinstance(raw, int):
        return raw

    data = bytes(int(byte, 16) for byte in raw)
    return int.from_bytes(data, byteorder="little")


def read_stats(map_path):
    """Read the entire per-CPU BPF map and aggregate every counter."""

    result = subprocess.run(
        ["bpftool", "-j", "map", "dump", "pinned", map_path],
        capture_output=True,
        text=True,
        check=True,
    )

    entries = json.loads(result.stdout)
    counters = {}

    for entry in entries:
        key = decode_number(entry["key"])

        # Every entry contains one value for each possible CPU.
        total = sum(
            decode_number(cpu_entry["value"])
            for cpu_entry in entry["values"]
        )

        counters[key] = total

    return counters


def main():
    parser = argparse.ArgumentParser(
        description="Read ByteGuard XDP statistics"
    )

    parser.add_argument(
        "map_path",
        help="Pinned path of the ByteGuard stat_map",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output machine-readable JSON",
    )

    args = parser.parse_args()
    counters = read_stats(args.map_path)

    named = {
        STAT_NAMES[key] if key < len(STAT_NAMES) else f"UNKNOWN_{key}": value
        for key, value in sorted(counters.items())
    }

    # The new statistics layout includes counter IDs 0 through 11.
    has_new_stats = all(key in counters for key in range(len(STAT_NAMES)))

    checks = {}

    if has_new_stats:
        checks["dns_outcomes"] = (
            counters[0] == counters[6] + counters[5]
        )

        checks["drop_reasons"] = (
            counters[5] == sum(counters[key] for key in (7, 8, 9, 10))
        )

    if args.json:
        print(json.dumps({
            "counters": named,
            "checks": checks,
        }, indent=2))
        return

    print("\nByteGuard XDP Statistics")
    print("-" * 42)

    for name, value in named.items():
        print(f"{name:<25} {value:>15,}")

    print("-" * 42)

    if not has_new_stats:
        print("Older stats map: outcome checks unavailable.")
    else:
        for name, passed in checks.items():
            print(f"{name}: {'PASS' if passed else 'FAIL'}")


if __name__ == "__main__":
    main()