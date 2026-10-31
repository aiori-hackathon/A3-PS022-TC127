"""Shared, intentionally small definitions for the isolated benchmark lab."""
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNS_DIR = ROOT / "build/bench/runs"
REPORTS_DIR = ROOT / "build/bench/reports"
STATE_FILE = ROOT / "build/bench/active.json"
GATE = Path(__file__).with_name("start_gate.py")
NS_CLIENT = "bgbench-a"
NS_SERVER = "bgbench-b"
IF_CLIENT = "bgc0"
IF_SERVER = "bgs0"
CLIENT_IP = "10.10.0.1"
SERVER_IP = "10.10.0.2"

def command_run(command, capture=False, check=True):
    result = subprocess.run(command, text=True, capture_output=capture, check=check)
    return result.stdout if capture else ""


def command_ns(namespace, command):
    return ["ip", "netns", "exec", namespace] + command


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
