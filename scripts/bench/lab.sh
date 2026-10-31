#!/usr/bin/env bash

set -euo pipefail

# Paths relative to the project root
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUN_DIR="$ROOT/build/bench"

PID_FILE="$RUN_DIR/dnsmasq.pid"
LOG_FILE="$RUN_DIR/dnsmasq.log"

start_lab() {
    mkdir -p "$RUN_DIR"

    # Our existing veth topology must be available.
    ip netns exec bg-a ip link show veth-a > /dev/null
    ip netns exec bg-b ip link show veth-b > /dev/null

    # Avoid starting the same DNS server twice.
    if [ -f "$PID_FILE" ]; then
        echo "Lab PID file already exists. Check status first."
        exit 1
    fi

    echo "Starting DNS server..."

    ip netns exec bg-b dnsmasq \
        --no-daemon \
        --conf-file=/dev/null \
        --no-resolv \
        --no-hosts \
        --bind-interfaces \
        --listen-address=10.10.0.2 \
        --port=53 \
        --address=/bench.test/10.10.0.2 \
        --local=/bench.test/ \
        > "$LOG_FILE" 2>&1 &

    echo $! > "$PID_FILE"

    sleep 1

    if ! kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo "DNS server failed to start:"
        cat "$LOG_FILE"
        rm -f "$PID_FILE"
        exit 1
    fi

    echo "DNS server started."
    echo "Logs: $LOG_FILE"
}

stop_lab() {
    if [ ! -f "$PID_FILE" ]; then
        echo "No lab DNS server PID file found."
        return
    fi

    pid=$(cat "$PID_FILE")

    # Do not kill an unrelated process if a PID was reused.
    if [ "$(ps -p "$pid" -o comm= 2>/dev/null)" = "dnsmasq" ]; then
        kill "$pid"
    fi

    rm -f "$PID_FILE"

    echo "DNS server stopped."
}

case "${1:-}" in
    up)
        start_lab
        ;;
    down)
        stop_lab
        ;;
    *)
        echo "Usage: sudo $0 {up|down}"
        exit 1
        ;;
esac