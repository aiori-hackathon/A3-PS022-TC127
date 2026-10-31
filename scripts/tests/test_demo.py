"""Demo lifecycle tests with all network/process mutations mocked."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import demo


class DemoTests(unittest.TestCase):
    def exercise(self, folder, fail_address=False):
        root = Path(folder)
        (root / 'build').mkdir()
        (root / 'build/byteguard').touch()
        calls = []
        def fake_run(command, **kwargs):
            calls.append(command)
            if command[:3] == ['ip', 'link', 'show']:
                return SimpleNamespace(returncode=1)
            if fail_address and command[:3] == ['ip', 'address', 'add']:
                raise subprocess.CalledProcessError(1, command)
            output = '10.203.0.2\n' if 'dig' in command else '[]'
            return SimpleNamespace(returncode=0, stdout=output)
        dns = SimpleNamespace(poll=lambda: None, args=['dnsmasq'])
        controller = SimpleNamespace(poll=lambda: 1, returncode=1, args=['byteguard'])
        options = SimpleNamespace(client_address='10.203.0.1/24',
                                  server_address='10.203.0.2/24', mode='native', metrics_address=':9090')
        state = root / 'build/demo/active.json'
        with patch.object(demo, 'ROOT', root), patch.object(demo, 'STATE', state), \
             patch.object(demo.subprocess, 'run', side_effect=fake_run), \
             patch.object(demo.subprocess, 'Popen', side_effect=[dns, controller]), \
             patch.object(demo, 'stop_process') as stop:
            with self.assertRaises((RuntimeError, subprocess.CalledProcessError)):
                demo.run(options)
        self.assertFalse(state.exists())
        self.assertEqual(calls[-2:], [
            ['ip', 'link', 'del', 'bgdemo-s'],
            ['ip', 'netns', 'del', 'bgdemo-a'],
        ])
        if not fail_address:
            self.assertEqual([item.args[0] for item in stop.call_args_list], [controller, dns])

    def test_controller_failure_cleans_veth_before_namespace(self):
        with tempfile.TemporaryDirectory() as folder:
            self.exercise(folder)

    def test_partial_network_creation_is_cleaned(self):
        with tempfile.TemporaryDirectory() as folder:
            self.exercise(folder, fail_address=True)


if __name__ == '__main__':
    unittest.main()
