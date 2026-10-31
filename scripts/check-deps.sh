#!/usr/bin/env bash
set -uo pipefail
missing=0
for tool in make clang cc pkg-config go python3 ip bpftool dnsmasq dig dnsperf tcpreplay nft docker curl; do
    if command -v "$tool" >/dev/null 2>&1; then
        printf 'OK      %s\n' "$tool"
    else
        printf 'MISSING %s\n' "$tool"
        missing=1
    fi
done
pkg-config --exists libbpf || { echo 'MISSING libbpf development headers'; missing=1; }
python3 -c 'import tomllib, importlib.util; assert importlib.util.find_spec("scapy") is not None' || { echo 'MISSING Python 3.11+ or Scapy'; missing=1; }
docker compose version || { echo 'MISSING Docker Compose v2'; missing=1; }
printf '\nKernel: '
uname -r
printf 'Go: '
go version
printf '\nController requires Go 1.27.1+ (or automatic toolchain download).\n'
printf 'Kernel requires BPF, XDP, BPF spin locks, BPF links and network namespaces.\n'
printf 'Runtime capabilities and Docker daemon access require separate live checks.\n'
exit "$missing"
