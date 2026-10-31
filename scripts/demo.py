#!/usr/bin/env python3
"""Foreground DNS/XDP demo on an owned veth; Ctrl+C removes its resources."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent / 'bench'))
from attack import generate
from bench_common import ROOT
from lab_env import stop_process
from traffic import parse_dnsperf

STATE = ROOT / 'build/demo/active.json'
NS = 'bgdemo-a'
CLIENT_IF = 'bgdemo-c'
SERVER_IF = 'bgdemo-s'


def call(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def ns(args):
    return ['ip', 'netns', 'exec', NS] + args


def read_state():
    data = json.loads(STATE.read_text())
    if data.get('owner') != 'byteguard-demo' or not Path(f"/proc/{data['pid']}").exists():
        raise RuntimeError('Demo is not running; start scripts/demo.py run first')
    return data


def run(args):
    client = ipaddress.ip_interface(args.client_address)
    server = ipaddress.ip_interface(args.server_address)
    if client.version != 4 or client.network != server.network or client.ip == server.ip:
        raise ValueError('Use distinct IPv4 client/server addresses in one subnet')
    for address in (client, server):
        if address.ip in (address.network.network_address, address.network.broadcast_address):
            raise ValueError('Client/server must be usable host addresses')
    if not (ROOT / 'build/byteguard').is_file():
        raise RuntimeError('Build the controller with make controller first')
    if STATE.exists():
        raise RuntimeError('Demo state already exists; inspect build/demo/active.json before cleanup')
    namespaces = call(['ip', '-j', 'netns', 'list'], capture_output=True, text=True)
    if any(item['name'] == NS for item in json.loads(namespaces.stdout)):
        raise RuntimeError(f'{NS} already exists; refusing to modify it')
    for name in (SERVER_IF, CLIENT_IF):
        if subprocess.run(['ip', 'link', 'show', name], capture_output=True).returncode == 0:
            raise RuntimeError(f'{name} already exists; refusing to modify it')
    routes = json.loads(call(['ip', '-j', '-4', 'route', 'show', 'table', 'all'],
                             capture_output=True, text=True).stdout)
    for route in routes:
        destination = route.get('dst', 'default')
        if destination != 'default' and ipaddress.ip_network(destination, strict=False).overlaps(client.network):
            raise RuntimeError(f'Demo subnet overlaps existing route {destination}; choose other addresses')
    processes = []
    created_ns = created_veth = False
    log_dir = ROOT / 'build/demo' / time.strftime('%Y%m%dT%H%M%S')
    log_dir.mkdir(parents=True, exist_ok=False)
    try:
        call(['ip', 'netns', 'add', NS])
        created_ns = True
        call(['ip', 'link', 'add', SERVER_IF, 'type', 'veth', 'peer', 'name', CLIENT_IF])
        created_veth = True
        call(['ip', 'link', 'set', CLIENT_IF, 'netns', NS])
        call(['ip', 'address', 'add', str(server), 'dev', SERVER_IF])
        call(['ip', 'link', 'set', SERVER_IF, 'up'])
        call(['ip', '-n', NS, 'address', 'add', str(client), 'dev', CLIENT_IF])
        call(['ip', '-n', NS, 'link', 'set', CLIENT_IF, 'up'])
        call(['ip', '-n', NS, 'link', 'set', 'lo', 'up'])
        # Explicitly bound local-only DNS: no external resolver or host DNS config.
        with (log_dir / 'dnsmasq.log').open('w') as output:
            dns = subprocess.Popen([
                'dnsmasq', '--no-daemon', '--conf-file=/dev/null', '--no-resolv',
                '--no-hosts', '--bind-interfaces', '--listen-address=' + str(server.ip),
                '--port=53', '--address=/bench.test/' + str(server.ip), '--local=/bench.test/',
            ], stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        processes.append(dns)
        for _ in range(30):
            if dns.poll() is not None:
                raise RuntimeError('dnsmasq failed; inspect ' + str(log_dir / 'dnsmasq.log'))
            result = subprocess.run(ns(['dig', '@' + str(server.ip), 'www.bench.test',
                                       '+short', '+tries=1', '+time=1']), capture_output=True, text=True)
            if result.returncode == 0 and str(server.ip) in result.stdout.splitlines():
                break
            time.sleep(0.1)
        else:
            raise RuntimeError('DNS readiness check failed')
        controller = subprocess.Popen([str(ROOT / 'build/byteguard'), '--interface', SERVER_IF,
                                       '--mode', args.mode, '--metrics-address', args.metrics_address],
                                      start_new_session=True)
        processes.append(controller)
        data = {'owner': 'byteguard-demo', 'pid': os.getpid(), 'client_ip': str(client.ip),
                'server_ip': str(server.ip), 'log_dir': str(log_dir)}
        STATE.write_text(json.dumps(data, indent=2) + '\n')
        print(f'Demo lab: {NS}/{CLIENT_IF} -> host {SERVER_IF}, DNS {server.ip}', flush=True)
        print('Run query/flood in another terminal. Ctrl+C here stops and cleans the lab.', flush=True)
        while True:
            for process in processes:
                if process.poll() is not None:
                    raise RuntimeError(f'Demo process {process.args[0]} exited ({process.returncode})')
            time.sleep(0.2)
    finally:
        for process in reversed(processes):
            stop_process(process)
        if created_veth:
            call(['ip', 'link', 'del', SERVER_IF])
        if created_ns:
            call(['ip', 'netns', 'del', NS])
        if STATE.exists():
            STATE.unlink()


def traffic(args):
    data = read_state()
    if args.action == 'query':
        result = call(ns(['dnsperf', '-s', data['server_ip'], '-a', data['client_ip'],
                          '-d', str(ROOT / 'src/tests/workloads/legitimate.txt'),
                          '-l', str(args.duration), '-Q', str(args.qps), '-t', '1']),
                      capture_output=True, text=True)
        print(result.stdout)
        print(json.dumps(parse_dnsperf(result.stdout), indent=2))
        return
    def mac(namespace, interface):
        command = ['ip', '-j', 'link', 'show', interface]
        return json.loads(call(ns(command) if namespace else command,
                               capture_output=True, text=True).stdout)[0]['address']
    pcap = Path(data['log_dir']) / ('attack-' + str(time.time_ns()) + '.pcap')
    generate(pcap, args.scenario, 1 if args.scenario == 'single' else 1024, 1024,
             mac(True, CLIENT_IF), mac(False, SERVER_IF), data['server_ip'], 44)
    attacker = subprocess.Popen(ns(['tcpreplay', '--pps=' + str(args.pps), '--loop=0',
                                    '--preload-pcap', '-i', CLIENT_IF, str(pcap)]),
                                start_new_session=True)
    try:
        try:
            code = attacker.wait(timeout=args.duration)
        except subprocess.TimeoutExpired:
            return  # Expected: stop the bounded flood in finally.
        raise RuntimeError(f'tcpreplay exited early ({code})')
    finally:
        stop_process(attacker)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    lab = sub.add_parser('run')
    lab.add_argument('--client-address', default='10.203.0.1/24')
    lab.add_argument('--server-address', default='10.203.0.2/24')
    lab.add_argument('--mode', choices=['native', 'generic'], default='native')
    lab.add_argument('--metrics-address', default=':9090')
    for action in ('query', 'flood'):
        child = sub.add_parser(action)
        child.add_argument('--duration', type=int, default=10)
        if action == 'query':
            child.add_argument('--qps', type=int, default=50)
        else:
            child.add_argument('--pps', type=int, default=3000)
            child.add_argument('--scenario', choices=['single', 'distributed'], default='single')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError('This command needs root to manage/enter its owned network namespace')
    if getattr(args, 'duration', 1) < 1 or not 1 <= getattr(args, 'pps', 1) <= 200000 or getattr(args, 'qps', 1) < 1:
        raise ValueError('Use positive duration/QPS and flood PPS 1..200000')
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    run(args) if args.action == 'run' else traffic(args)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
    except (RuntimeError, ValueError, OSError, subprocess.CalledProcessError) as error:
        print('ERROR:', error, file=sys.stderr)
        sys.exit(1)
