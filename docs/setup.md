# Setup, reproducibility and troubleshooting

Use the [README quick start](../README.md#quick-start) for the shortest path.

## Supported workflow

Use Linux with a BPF/XDP-enabled kernel and the commands/dependencies in the README. The recorded host uses Arch; Ubuntu 24.04+ commands are provided as a deployment target, not a separately benchmarked environment. Root is the supported namespace/filter operation path. Go 1.27.1, Python 3.11+ and Matplotlib are needed for the complete build/test/report workflow. A fresh machine needs Internet access to install tools, Go modules/toolchain and Docker images; it does not depend on a teammate's laptop.

`make controller` compiles and embeds the intended BPF object. Compare the logged embedded SHA-256 with `sha256sum build/xdp_main.bpf.o`. `go build` directly inside the controller directory needs the generated embed object first. `make clean` preserves `build/bench/`; never replace it with a broad deletion of build evidence.

## Two different networks

| Workflow | Client | Server and attachment | Metrics visibility |
|---|---|---|---|
| Demo | bgdemo-a / bgdemo-c, 10.203.0.1 | Host bgdemo-s, 10.203.0.2; controller on host | Host :9090 reachable from Docker gateway |
| Benchmark | bgbench-a / bgc0, 10.10.0.1 | bgbench-b / bgs0, 10.10.0.2; bpftool native attach | Benchmark reads pinned maps directly; no controller exporter required |

For a conflicting demo subnet, use two distinct host addresses in another unused subnet:

```bash
sudo python3 scripts/demo.py run \
  --client-address 10.204.0.1/24 --server-address 10.204.0.2/24
```

The script checks existing routes/names before mutation. The benchmark intentionally uses fixed private addresses inside its fully isolated namespaces. No public route or remote DNS target is needed.

## Troubleshooting

| Symptom | Investigation / action |
|---|---|
| Missing BPF headers or asm/types.h | Install libbpf/kernel userspace headers, Clang, C compiler and pkg-config. Use root Make so its compiler-derived include path is applied. |
| Clang has no BPF target | Check `clang --print-targets`; install a distribution LLVM build with BPF support. |
| Go cannot build or embed object missing | Use Go 1.27.1+ or allow its toolchain download; run `make controller` from root. Do not launch stale tracked binaries. |
| BPF load/verifier failure | Preserve the exact error/log, kernel version and object hash. Confirm BPF atomics/spin locks, memlock handling and privileges. Compilation alone is not a kernel-load check. |
| Permission denied / sudo needs a password | Run authorized privileged commands in an administrator terminal. Do not use privileged Docker or unrelated host changes as a workaround. |
| Attachment fails / wrong interface | Use the server ingress endpoint. Inspect `ip -details link show bgdemo-s`; native support depends on device/kernel. Demo allows explicit `--mode generic`; harness uses native and does not fall back silently. |
| Namespace/interface already exists | Inspect active state and the actual owners. The scripts refuse reuse; do not delete unrelated namespaces/interfaces. |
| DNS server not running | Read the latest `build/demo/<timestamp>/dnsmasq.log` or the run's dnsmasq.log. dnsmasq must bind the owned server IP and answer bench.test locally. |
| No DNS traffic/counters | Run the query command while the demo is alive; inspect source/destination/interface and `/metrics`. Responses, fragments and unsupported packets are outside DNS_QUERIES. |
| Legitimate queries fail during attack | Inspect client NOERROR/lost counts and filter reason counters. Global competition is possible; PASS is not client success and a missing response has multiple possible causes. |
| Metrics port occupied | The controller fails before attach. Select `--metrics-address :9092` and change a copied Prometheus config's target to the same port. |
| Prometheus target DOWN | Confirm the current controller is alive, metrics bind is bridge-reachable and the exact-case Prometheus.yml mount exists. Inspect target lastError. A bind only to 127.0.0.1 is not Docker-bridge reachable. |
| Target UP but ByteGuard query empty | Inspect raw `/metrics` for all byteguard counters, actual binary path/hash, private registry handler, collection errors and query labels. An HTTP 200 from another process is insufficient. |
| Grafana login fails | Defaults apply when its database is first initialized. Persistent grafana-data retains prior credentials; inspect .env/local state. Do not delete the volume as a default recovery action. |
| Grafana data source errors | Provisioned URL is http://prometheus:9090 inside Compose. A host localhost URL points to the wrong container. |
| WSL/Docker Desktop scrape fails | Verify reachability from Prometheus's network. host.docker.internal may resolve to Windows, not the WSL Linux guest. Configure a local reachable target; do not hardcode that address into shared defaults. |
| Report files are root-owned | Benchmark matrix may write reports as root. Use the documented sudo report command or review a narrowly scoped ownership change; do not run broad chmod/chown over evidence. |

## Shutdown and interrupted state

Ctrl+C in the foreground demo stops controller/dnsmasq and removes its owned veth and namespace. `make monitoring-down` stops this Compose project and leaves persistent volumes intact. No network cleanup is performed by report generation.

After SIGKILL/power loss, inspect `build/demo/active.json`, recorded process IDs, `ip netns list`, and `ip link show bgdemo-s`. Only after confirming ownership should an administrator stop the recorded demo processes and remove the named demo interface/namespace/state. PID reuse means a numeric PID alone is insufficient ownership evidence. No automatic broad cleanup command is recommended.

The benchmark has state-owned recovery:

```bash
sudo python3 scripts/bench/harness.py cleanup
```

Inspect `build/bench/active.json` first. Existing legacy bg-a/bg-b labs and unrelated BPF pins are not its resources. Retain all raw results even if a run failed.

## Rebuild the technical report

```bash
python3 -m venv --system-site-packages /tmp/byteguard-report
/tmp/byteguard-report/bin/pip install -r reports/source/requirements.txt
/tmp/byteguard-report/bin/python scripts/report/prepare_evidence.py
/tmp/byteguard-report/bin/python scripts/report/build_report.py
```

Liberation Serif fonts reproduce the reference typography most closely; standard Times is a fallback. Poppler utilities (`pdfinfo`, `pdftoppm`, `pdftotext`) support independent inspection. Rendering and evidence analysis need no root or traffic generation. The archive is frozen: newer live runs are not silently selected for an already published report.
