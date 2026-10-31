"""Fast unit tests; no root, eBPF, tcpreplay or Scapy needed."""
import sys
from types import SimpleNamespace
from unittest.mock import patch
import tempfile
import unittest
from pathlib import Path

from attack import source_ip, sha256
from traffic import parse_dnsperf, parse_tcpreplay, start_gated, wait_ready, release_gate
from lab_env import legitimate_client_ip
from bench_common import write_json
from stats import decode_number


class HarnessTests(unittest.TestCase):
    def test_percpu_counter_endian(self):
        self.assertEqual(decode_number(["0x2c", "0x1c", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00"]), 7212)

    def test_source_patterns(self):
        self.assertEqual(source_ip("single", 99), "10.20.0.1")
        self.assertEqual(source_ip("subnet", 0), "10.20.0.1")
        self.assertEqual(source_ip("subnet", 253), "10.20.0.254")
        self.assertEqual(source_ip("distributed", 254), "10.21.0.1")

    def test_dnsperf_parsing(self):
        text = """Queries sent: 500
Queries completed: 9 (1.8%)
Queries lost: 491 (98.2%)
Response codes: NOERROR 9 (100%)
Queries per second: 0.9
Average Latency (s): 0.000317 (min 0.000095, max 0.000693)
"""
        stats = parse_dnsperf(text)
        self.assertEqual(stats["sent"], 500)
        self.assertEqual(stats["noerror"], 9)
        self.assertAlmostEqual(stats["success_percent"], 1.8)

    def test_tcpreplay_parsing(self):
        self.assertEqual(parse_tcpreplay("Actual: 10240 packets (727040 bytes) sent in 2.04 seconds")["sent_packets"], 10240)

    def test_client_address_allocation(self):
        self.assertEqual(legitimate_client_ip(0), "10.10.0.1")
        self.assertEqual(legitimate_client_ip(1), "10.10.0.101")
        self.assertEqual(legitimate_client_ip(31), "10.10.0.131")

    def test_start_gate_executable(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "hello.log"
            process, start_fd, ready_fd = start_gated(
                [sys.executable, "-c", "print('gate released')"], output)
            try:
                wait_ready(ready_fd, process)
                self.assertIsNone(process.poll())
                release_gate(start_fd)
                self.assertEqual(process.wait(timeout=5), 0)
                self.assertIn("gate released", output.read_text())
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()

    def test_concurrent_runner_with_fake_generators(self):
        # Exercise process gates and graceful tcpreplay termination without root.
        import traffic
        def fake_ns(namespace, command):
            if command[0] == "dnsperf":
                source = (
                    "import time; time.sleep(0.2); "
                    "print('Queries sent: 10\\nQueries completed: 10\\nQueries lost: 0\\n"
                    "Response codes: NOERROR 10 (100%)\\nAverage Latency (s): 0.0001')"
                )
                return [sys.executable, "-S", "-c", source]
            script = (
                "import signal,sys,time; "
                "signal.signal(signal.SIGINT, lambda a,b: "
                "(print('Actual: 100 packets (7000 bytes) sent in 0.2 seconds',flush=True), "
                "sys.exit(0))); "
                "time.sleep(10)"
            )
            return [sys.executable, "-S", "-c", script]

        with tempfile.TemporaryDirectory() as folder:
            settings = SimpleNamespace(
                legit_clients=2, legit_qps=20, duration=1, outstanding=100,
                workload=Path(folder) / "legitimate.txt", attack_pps=100,
                pulse_on=0, pulse_off=0,
            )
            with patch.object(traffic, "command_ns", side_effect=fake_ns):
                result, attack, before, after = traffic.run_traffic(
                    settings, Path(folder), Path(folder) / "attack.pcap",
                    on_window_start=lambda: {"time": __import__("time").monotonic()},
                    on_window_end=lambda: {"time": __import__("time").monotonic()},
                )
            self.assertIsNotNone(before)
            self.assertIsNotNone(after)
            self.assertTrue(0.96 <= after["time"] - before["time"] < 1.40)
            self.assertEqual(result["sent"], 20)
            self.assertEqual(result["noerror"], 20)
            self.assertEqual(attack["sent_packets"], 100)

    def test_json_result(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "result.json"
            write_json(path, {"ok": True})
            self.assertIn('"ok": true', path.read_text())
            self.assertEqual(len(sha256(path)), 64)


# Additional pure-Python regression checks for the three-mode harness.
class ComparisonTests(unittest.TestCase):
    def test_nft_ruleset(self):
        from nft_mode import ruleset
        text = ruleset(source_rate=100, source_burst=10, global_rate=1000, global_burst=200)
        self.assertIn('hook ingress device "bgs0"', text)
        self.assertIn('limit rate over 100/second burst 10 packets', text)
        self.assertIn('limit rate over 1000/second burst 200 packets', text)
        for marker in ('source_limit', 'global_limit', 'admitted'):
            self.assertIn(f'comment "{marker}"', text)
        with self.assertRaises(ValueError):
            ruleset(source_rate=0)

    def test_nft_rule_counter_json(self):
        import json
        from unittest.mock import patch
        from nft_mode import nft_counters
        sample = {"nftables": [
            {"rule": {"comment": name, "expr": [{"counter": {"packets": count, "bytes": count * 70}}]}}
            for name, count in (("source_limit", 12), ("global_limit", 34), ("admitted", 56))
        ]}
        with patch('nft_mode.command_run', return_value=json.dumps(sample)):
            counters = nft_counters()
        self.assertEqual(counters["total_dns"], 102)
        self.assertEqual(counters["global_limit"], 34)

    def test_metrics_summarize(self):
        from metrics import summarize
        before = {"time": 10, "dns_ticks": 100,
                  "host": {"total": 200, "idle": 100, "softirq": 4, "irq": 2, "system": 30, "user": 40},
                  "interface": {"rx_bytes": 0, "rx_packets": 0, "rx_dropped": 0, "tx_bytes": 0, "tx_packets": 0}}
        after = {"time": 20, "dns_ticks": 200,
                 "host": {"total": 1200, "idle": 600, "softirq": 24, "irq": 12, "system": 130, "user": 440},
                 "interface": {"rx_bytes": 1_000_000, "rx_packets": 20_000,
                               "rx_dropped": 0, "tx_bytes": 500_000, "tx_packets": 10_000}}
        data = summarize(before, after)
        self.assertAlmostEqual(data["server_interface"]["rx_pps"], 2000)
        self.assertAlmostEqual(data["server_interface"]["rx_mbps"], 0.8)
        self.assertAlmostEqual(data["host_cpu_busy_percent_all_cores"], 50)
        self.assertAlmostEqual(data["host_softirq_percent_capacity"], 2)

    def test_report_grouping(self):
        from report import grouped_summary, summary_row

        def result(percent, source_hash, tag="v3"):
            return {
                "run_id": str(percent), "mode": "xdp", "scenario": "single",
                "legit_offered_qps": 50, "legit_clients": 1,
                "attack_offered_pps": 3000, "duration_seconds": 10,
                "outstanding": 100, "source_count": 1, "packet_count": 1024,
                "seed": 42, "run_tag": tag, "workload_sha256": "fixed",
                "kernel": "test-kernel", "xdp_source_sha256": source_hash,
                "dns": {"success_percent": percent, "sent": 500, "noerror": 5,
                        "achieved_legit_noerror_qps": 1, "avg_latency_sec": .0003},
                "performance": {"dnsmasq_cpu_percent_one_core": 10,
                                "host_cpu_busy_percent_all_cores": 20,
                                "host_softirq_percent_capacity": 1,
                                "server_interface": {"rx_pps": 3000, "rx_mbps": 2}},
            }

        grouped = grouped_summary([
            summary_row(result(40, "build-A")),
            summary_row(result(60, "build-A")),
            summary_row(result(90, "build-B")),
            summary_row(result(50, "build-A", "another-tag")),
        ])
        self.assertEqual(len(grouped), 3)
        group_a = next(row for row in grouped if row["implementation_fingerprint"] == "build-A" and row["tag"] == "v3")
        self.assertEqual(group_a["trials"], 2)
        self.assertEqual(group_a["success_percent_mean"], 50)
        self.assertIsNotNone(group_a["success_percent_stddev"])

    def test_report_excludes_old_schema(self):
        import json
        import report
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(report, "RUNS_DIR", Path(folder)):
                legacy = Path(folder) / "legacy"
                legacy.mkdir()
                (legacy / "summary.json").write_text(json.dumps({
                    "status": "completed", "mode": "xdp", "run_id": "old"
                }))
                report.make_report(False)
                self.assertFalse((Path(folder) / "summary.csv").exists())

    def test_duration_not_extended_by_dns_timeout_drain(self):
        import time
        import traffic
        def fake_ns(namespace, command):
            if command[0] == "dnsperf":
                source = (
                    "import time; time.sleep(1.5); "
                    "print('Queries sent: 10\\nQueries completed: 0\\nQueries lost: 10\\n')"
                )
                return [sys.executable, "-S", "-c", source]
            script = (
                "import signal,sys,time; "
                "signal.signal(signal.SIGINT, lambda a,b: "
                "(print('Actual: 100 packets (7000 bytes) sent in 1.0 seconds',flush=True), "
                "sys.exit(0))); "
                "time.sleep(20)"
            )
            return [sys.executable, "-S", "-c", script]

        with tempfile.TemporaryDirectory() as folder:
            settings = SimpleNamespace(
                legit_clients=1, legit_qps=10, duration=1, outstanding=100,
                workload=Path(folder) / "legitimate.txt", attack_pps=100,
                pulse_on=0, pulse_off=0,
            )
            with patch.object(traffic, "command_ns", side_effect=fake_ns):
                before = time.monotonic()
                result, attack, start_data, stop_data = traffic.run_traffic(
                    settings, Path(folder), Path(folder) / "attack.pcap",
                    on_window_start=time.monotonic,
                    on_window_end=time.monotonic,
                )
                end = time.monotonic()
            self.assertLess(stop_data - start_data, 1.4)
            self.assertGreater(end - before, 1.4)
            self.assertEqual(result["lost"], 10)
            self.assertEqual(attack["sent_packets"], 100)

    def test_cli_validation(self):
        from harness import validate_run
        work = Path(__file__)
        args = SimpleNamespace(tag="test", duration=10, legit_qps=50, attack_pps=3000,
                               scenario="distributed", legit_clients=1,
                               source_count=100, packet_count=10, outstanding=1000,
                               pulse_on=0, pulse_off=0, workload=work,
                               attack_pcap=None, object_file=None)
        with self.assertRaises(ValueError):
            validate_run(args)


class AuditTests(unittest.TestCase):
    def test_valid_and_invalid_run_auditing(self):
        from audit import inspect_result
        good = {
            "benchmark_schema_version": 4,
            "status": "completed", "cleanup_status": "ok",
            "mode": "xdp", "duration_seconds": 10,
            "dns": {"sent": 500, "completed": 400, "lost": 100, "noerror": 400},
            "performance": {"measurement_seconds": 10.05,
                            "server_interface": {"rx_pps": 3000}},
            "xdp_checks": {"outcomes": True, "drops": True},
            "attack_offered_pps": 3000,
            "attack": {"replay_average_pps": 2999},
        }
        errors, warnings = inspect_result(good)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])
        broken = dict(good)
        broken["xdp_checks"] = {"outcomes": False, "drops": True}
        self.assertTrue(inspect_result(broken)[0])
        broken = dict(good)
        broken["performance"] = {"measurement_seconds": 11.1,
                                  "server_interface": {"rx_pps": 3000}}
        self.assertTrue(inspect_result(broken)[1])

    def test_custom_attack_requires_custom_scenario(self):
        from harness import validate_run
        args = SimpleNamespace(tag="run1", duration=10, legit_qps=50, attack_pps=3000,
                               scenario="distributed", legit_clients=1,
                               source_count=100, packet_count=1024, outstanding=1000,
                               pulse_on=0, pulse_off=0, workload=Path(__file__),
                               attack_pcap=Path(__file__), object_file=None)
        with self.assertRaisesRegex(ValueError, "--attack-pcap"):
            validate_run(args)


class V4FeaturesTests(unittest.TestCase):
    def test_profile_defaults_cli_override_and_toml_lists(self):
        from harness import parse_args
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "comparison.toml"
            path.write_text('''[common]
tag = "check-config"
legit_qps = 50
capture = true
[matrix]
modes = ["none", "nft", "xdp"]
attack_pps_list = [0, 3000]
repeats = 2
''')
            parsed = parse_args(["matrix", "--config", str(path), "--legit-qps", "60"])
            self.assertEqual(parsed.legit_qps, 60)  # Terminal beats TOML.
            self.assertEqual(parsed.tag, "check-config")
            self.assertTrue(parsed.capture)
            self.assertEqual(parsed.modes, "none,nft,xdp")
            self.assertEqual(parsed.attack_pps_list, "0,3000")
            self.assertEqual(parsed.repeats, 2)

    def test_profile_rejects_unknown_setting(self):
        from harness import parse_args
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "bad.toml"
            path.write_text("[run]\nnot_a_real_setting = 123\n")
            with self.assertRaisesRegex(ValueError, "Unknown profile"):
                parse_args(["run", "--config", str(path)])

    def test_config_run_can_override_capture(self):
        from harness import parse_args
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "one.toml"
            path.write_text("[run]\ntag='evidence'\ncapture=true\n")
            parsed = parse_args(["run", "--config", str(path), "--duration", "7"])
            self.assertTrue(parsed.capture)
            self.assertEqual(parsed.duration, 7)
            overridden = parse_args(["run", "--config", str(path), "--no-capture"])
            self.assertFalse(overridden.capture)

    def test_capture_filter_only_includes_legitimate_sources(self):
        from capture import LEGIT_DNS_FILTER
        self.assertIn("src net 10.10.0.0/24", LEGIT_DNS_FILTER)
        self.assertIn("src host 10.10.0.2", LEGIT_DNS_FILTER)
        self.assertNotIn("10.20.0.", LEGIT_DNS_FILTER)

    def test_capture_saved_preview(self):
        from types import SimpleNamespace
        import capture
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "client.pcap"
            path.write_bytes(b"\x00" * 32)
            log = Path(folder) / "client_tcpdump.log"
            log.write_text("listening on bgc0")
            finished_process = SimpleNamespace(poll=lambda: 0)
            result = SimpleNamespace(returncode=0, stdout="IP 10.10.0.1 > 10.10.0.2: DNS query\n", stderr="")
            with patch.object(capture.subprocess, "run", return_value=result):
                evidence = capture.stop_captures([("client", finished_process, path, log)])
            self.assertEqual(evidence["client"]["pcap_bytes"], 32)
            self.assertTrue(Path(evidence["client"]["preview"]).is_file())

    def test_audit_capture_requires_pcaps(self):
        from audit import inspect_result
        example = {
            "benchmark_schema_version": 4, "status": "completed", "cleanup_status": "ok",
            "mode": "none", "duration_seconds": 10, "capture_enabled": True,
            "dns": {"sent": 5, "completed": 5, "lost": 0, "noerror": 5},
            "performance": {"measurement_seconds": 10, "server_interface": {"rx_pps": 1}},
        }
        errors, _ = inspect_result(example)
        self.assertTrue(any("capture PCAP" in error for error in errors))

    def test_capture_grouped_separately(self):
        from report import summary_row, group_key
        example = {
            "run_id": "run1", "run_tag": "tag", "mode": "none",
            "scenario": "none", "duration_seconds": 10,
            "legit_offered_qps": 50, "legit_clients": 1,
            "attack_offered_pps": 0, "seed": 1,
            "dns": {}, "performance": {},
        }
        run_a = dict(example, capture_enabled=False)
        run_b = dict(example, capture_enabled=True)
        self.assertNotEqual(group_key(summary_row(run_a)), group_key(summary_row(run_b)))


class FailureHandlingTests(unittest.TestCase):
    def exercise_run(self, folder, audit_errors=(), cleanup_error=None):
        from contextlib import ExitStack
        import harness
        config = harness.parse_args(['run', '--mode', 'none', '--duration', '1'])
        dns = {'sent': 50, 'completed': 50, 'lost': 0, 'noerror': 50,
               'success_percent': 100, 'avg_latency_sec': .001}
        perf = {'server_interface': {'rx_pps': 50, 'rx_mbps': .01},
                'dnsmasq_cpu_percent_one_core': 1}
        with ExitStack() as stack:
            stack.enter_context(patch.object(harness, 'RUNS_DIR', Path(folder)))
            stack.enter_context(patch.object(harness.os, 'geteuid', return_value=0))
            for name in ('check_dependencies', 'require_exclusive_lab', 'save_state',
                         'setup_network', 'check_dns_ready', 'stop_process'):
                stack.enter_context(patch.object(harness, name))
            stack.enter_context(patch.object(harness, 'environment_metadata', return_value={}))
            stack.enter_context(patch.object(harness, 'start_dns', return_value=SimpleNamespace(pid=123)))
            stack.enter_context(patch.object(harness, 'run_traffic', return_value=(dns, None, {}, {})))
            stack.enter_context(patch.object(harness, 'summarize', return_value=perf))
            stack.enter_context(patch.object(harness, 'inspect_result', return_value=(list(audit_errors), [])))
            stack.enter_context(patch.object(harness, 'cleanup_lab', side_effect=cleanup_error))
            return harness.run_one(config)

    def test_failed_measurement_cannot_be_saved_as_completed(self):
        import json
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(RuntimeError, 'measurements failed'):
                self.exercise_run(folder, audit_errors=['invalid accounting'])
            result = json.loads(next(Path(folder).glob('*/summary.json')).read_text())
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['cleanup_status'], 'ok')

    def test_cleanup_failure_stops_matrix(self):
        import json
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(RuntimeError, 'cleanup failed'):
                self.exercise_run(folder, cleanup_error=RuntimeError('test cleanup error'))
            result = json.loads(next(Path(folder).glob('*/summary.json')).read_text())
            self.assertEqual(result['status'], 'failed')
            self.assertTrue(result['cleanup_errors'])

    def test_report_excludes_completed_but_invalid_measurements(self):
        import report
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'invalid').mkdir()
            write_json(root / 'invalid/summary.json', {
                'benchmark_schema_version': 4, 'status': 'completed',
                'mode': 'none', 'run_tag': 'bad', 'cleanup_status': 'ok',
            })
            with patch.object(report, 'RUNS_DIR', root), patch.object(report, 'REPORTS_DIR', root / 'reports'):
                report.make_report(False)
            self.assertFalse((root / 'reports').exists())


class CampaignReportTests(unittest.TestCase):
    def test_phase2_profile_has_27_matched_runs(self):
        import harness
        from bench_common import ROOT
        args = harness.parse_args(['matrix', '--config', str(ROOT / 'configs/bench/phase2.toml')])
        observed = []
        with patch.object(harness, 'run_one', side_effect=lambda config: observed.append(
                (config.mode, config.scenario, config.attack_pps, config.seed,
                 config.legit_qps, config.duration))), patch.object(harness, 'make_report'):
            harness.run_matrix(args)
        self.assertEqual(len(observed), 27)
        self.assertEqual({row[1] for row in observed}, {'none', 'single', 'distributed'})
        for scenario in ('none', 'single', 'distributed'):
            for seed in (44, 45, 46):
                self.assertEqual({row[0] for row in observed if row[1] == scenario and row[3] == seed},
                                 {'none', 'nft', 'xdp'})
        self.assertTrue(all(row[4:] == (50, 10) for row in observed))

    def test_invalid_later_matrix_cell_runs_nothing(self):
        import harness
        args = harness.parse_args(['matrix', '--attack-pps-list', '0,3000,-1'])
        with patch.object(harness, 'run_one') as run:
            with self.assertRaises(ValueError):
                harness.run_matrix(args)
        run.assert_not_called()

    def test_report_groups_different_hosts_separately(self):
        from report import summary_row, group_key
        base = {'run_id': 'test', 'mode': 'none', 'scenario': 'none',
                'legit_offered_qps': 50, 'legit_clients': 1, 'attack_offered_pps': 0,
                'duration_seconds': 10, 'seed': 44}
        first = summary_row(dict(base, environment={'hostname': 'host-a'}))
        second = summary_row(dict(base, environment={'hostname': 'host-b'}))
        self.assertNotEqual(group_key(first), group_key(second))

    def test_full_report_and_seven_graphs_from_temporary_test_fixtures(self):
        # Fixtures exercise rendering only; never save them as benchmark results.
        import csv
        import report
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for mode in ('none', 'nft', 'xdp'):
                for trial in range(2):
                    run = root / f'{mode}-{trial}'
                    run.mkdir()
                    fixture = {
                        'benchmark_schema_version': 4, 'status': 'completed', 'cleanup_status': 'ok',
                        'run_id': run.name, 'run_tag': 'unit-test-only', 'mode': mode,
                        'scenario': 'none', 'duration_seconds': 10, 'legit_offered_qps': 50,
                        'legit_clients': 1, 'attack_offered_pps': 0, 'seed': 44 + trial,
                        'dns': {'sent': 500, 'completed': 500, 'lost': 0, 'noerror': 500,
                                'success_percent': 100, 'achieved_legit_noerror_qps': 50,
                                'avg_latency_sec': .0001},
                        'performance': {'measurement_seconds': 10,
                                        'server_interface': {'rx_pps': 50}},
                        'xdp_deltas': {'DNS_PASS': 500, 'PACKET_DROP': 0,
                                       'DROP_SOURCE_LIMIT': 0, 'DROP_GLOBAL_LIMIT': 0},
                        'xdp_checks': {'outcomes': True, 'drops': True},
                        'nft_deltas': {'admitted': 500, 'source_limit': 0, 'global_limit': 0},
                    }
                    write_json(run / 'summary.json', fixture)
            with patch.object(report, 'RUNS_DIR', root), patch.object(report, 'REPORTS_DIR', root / 'reports'):
                report.make_report(charts=True, tag='unit-test-only')
            output = root / 'reports/unit-test-only'
            self.assertEqual(len(list(output.glob('*.png'))), 7)
            with (output / 'grouped.csv').open() as data:
                rows = list(csv.DictReader(data))
            self.assertEqual(len(rows), 3)
            self.assertTrue(all(row['trials'] == '2' for row in rows))
            unfiltered = next(row for row in rows if row['mode'] == 'none')
            self.assertEqual(unfiltered['filter_dropped_mean'], '')
            self.assertIn('Legit replies/s', (output / 'REPORT.md').read_text())


if __name__ == "__main__":
    unittest.main()
