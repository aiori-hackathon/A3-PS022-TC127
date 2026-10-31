import subprocess
import sys
import struct
import time
import json
from pathlib import Path

def initialize_global_map(pin_dir):
    map_path = Path(pin_dir) / "maps" / "global_map"

    global_brust = 200
    token_unit = 1000000000

    credit = global_brust * token_unit
    now = time.clock_gettime_ns(time.CLOCK_MONOTONIC)

    data = struct.pack("=I4xQQ",0,credit,now);

    value_bytes = []

    for byte in data :
        value_bytes.append(format(byte,"02x"))
    
    command = [
        "bpftool", "map", "update",
        "pinned", str(map_path),
        "key", "hex", "00", "00", "00", "00",
        "value", "hex"
    ]
    command.extend(value_bytes)

    run_command(command)

    print("Global bucket initialized successfully")

def run_command(command):
    print("Running:", " ".join(command))
    subprocess.run(command, check=True)

def get_program_id(pin_dir):
    program_path = Path(pin_dir) / "program"

    command = [
        "bpftool", "-j", "prog", "show",
        "pinned", str(program_path)
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=True
    )

    program_info = json.loads(result.stdout)

    return program_info["id"]

def attach_program(pin_dir, namespace, interface):
    program_id = get_program_id(pin_dir)

    command = [
        "ip", "netns", "exec", namespace,
        "bpftool", "net", "attach",
        "xdpdrv",
        "id", str(program_id),
        "dev", interface
    ]

    run_command(command)

    print("XDP program attached successfully")

def load_program(object_path, pin_dir):

    object_file = Path(object_path)
    pin_directory = Path(pin_dir)

    # Check whether the compiled BPF object exists
    if not object_file.is_file():
        raise RuntimeError("BPF object file not found")

    # Never overwrite an existing pinned program or maps
    if pin_directory.exists():
        raise RuntimeError("Pin directory already exists")

    # Create directories for the program and maps
    maps_directory = pin_directory / "maps"
    maps_directory.mkdir(parents=True)

    program_path = pin_directory / "program"

    # Construct the bpftool command
    command = [
        "bpftool",
        "prog",
        "load",
        str(object_file),
        str(program_path),
        "type",
        "xdp",
        "pinmaps",
        str(maps_directory)
    ]

    run_command(command)
    initialize_global_map(pin_directory)

    print("BPF program loaded successfully")


if __name__ == "__main__":

    if len(sys.argv) not in (3, 4):
        print("Usage: sudo python3 load_xdp.py <object> <pin_dir> [--attach]")
        sys.exit(1)

    object_path = sys.argv[1]
    pin_dir = sys.argv[2]

    attach = False

    if len(sys.argv) == 4 :
        if sys.argv[3] != "--attach":
            print("Unknown option:",sys.argv[3])
            sys.exit(1)
        
        attach = True

    load_program(object_path, pin_dir)

    if attach:
        attach_program(pin_dir,"bg-b","veth-b")
