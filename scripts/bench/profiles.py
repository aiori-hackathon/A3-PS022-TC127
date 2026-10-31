"""Read a small TOML experiment profile; explicit CLI flags always win."""
import argparse
import tomllib
from pathlib import Path

from bench_common import ROOT

MATRIX_LISTS = {"modes", "scenarios", "attack_pps_list"}
FILE_OPTIONS = {"attack_pcap", "workload", "object_file"}


def profile_defaults(path, command, subparser):
    """Validate the keys and turn TOML sections into argparse defaults."""
    with Path(path).open("rb") as file:
        document = tomllib.load(file)
    unknown = set(document) - {"common", "run", "matrix"}
    if unknown:
        raise ValueError("Unknown TOML section(s): " + ", ".join(sorted(unknown)))

    options = {}
    for section in ("common", command):
        values = document.get(section, {})
        if not isinstance(values, dict):
            raise ValueError(f"[{section}] must be a TOML table")
        options.update(values)

    accepted = {action.dest for action in subparser._actions if action.dest not in ("help", "config")}
    converted = {}
    for key, value in options.items():
        name = key.replace("-", "_")
        if name not in accepted:
            raise ValueError(f"Unknown profile setting for {command}: {key}")
        if name in MATRIX_LISTS and isinstance(value, list):
            value = ",".join(str(item) for item in value)
        if name in FILE_OPTIONS:
            if not isinstance(value, str):
                raise ValueError(f"{key} must be a filename")
            relative_path = Path(value)
            value = relative_path if relative_path.is_absolute() else ROOT / relative_path
        converted[name] = value
    return converted


def apply_profile(subparser, command, argv):
    """Locate --config before the full parse; defaults never override CLI."""
    probe = argparse.ArgumentParser(add_help=False)
    probe.add_argument("--config", type=Path)
    known, _ = probe.parse_known_args(argv)
    if known.config is not None:
        subparser.set_defaults(**profile_defaults(known.config, command, subparser))
