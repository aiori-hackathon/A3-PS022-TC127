#!/usr/bin/env python3
"""Freeze/audit existing evidence and derive report data; never run traffic.

First run copies build/bench into a deterministic archive. Later runs read that
archive so a published report does not silently select newer experiments.
"""
import csv
import gzip
import hashlib
import io
import json
from pathlib import Path
import statistics
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'reports/evidence'
FIG = ROOT / 'reports/figures'
ARCHIVE = OUT / 'raw-benchmarks.tar.gz'
sys.path.insert(0, str(ROOT / 'scripts/bench'))
from traffic import parse_dnsperf, parse_tcpreplay
from audit import inspect_result


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load_artifacts():
    if ARCHIVE.exists():
        with tarfile.open(ARCHIVE, 'r:gz') as archive:
            return {m.name: archive.extractfile(m).read() for m in archive.getmembers() if m.isfile()}
    source = ROOT / 'build/bench'
    files = {str(p.relative_to(source)): p.read_bytes() for p in sorted(source.rglob('*')) if p.is_file()}
    if not files:
        raise RuntimeError('No benchmark archive or local artifacts available')
    OUT.mkdir(parents=True, exist_ok=True)
    # Only new archive creation; no deletion, relocation, or overwrite of source.
    with ARCHIVE.open('xb') as output, gzip.GzipFile(filename='', fileobj=output, mode='wb', mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode='w') as archive:
            for name, data in sorted(files.items()):
                entry = tarfile.TarInfo(name)
                entry.size, entry.mode, entry.mtime = len(data), 0o644, 0
                archive.addfile(entry, io.BytesIO(data))
    return files


def save_csv(path, rows):
    with path.open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    FIG.mkdir(parents=True, exist_ok=True)
    files = load_artifacts()
    manifests = [{'path': name, 'bytes': len(data), 'sha256': digest(data)} for name, data in sorted(files.items())]
    (OUT / 'artifact-manifest.json').write_text(json.dumps(manifests, indent=2) + '\n')
    catalogue, selected, diagnostics = [], [], []
    for name, raw in sorted(files.items()):
        if not name.startswith('runs/') or not name.endswith('/summary.json'):
            continue
        d = json.loads(raw)
        tag, schema, captured = d.get('run_tag'), d.get('benchmark_schema_version'), d.get('capture_enabled', False)
        chosen = tag == 'before-tuning' and schema == 4 and d.get('status') == 'completed' and not captured
        kind = ('historical comparative' if chosen else 'capture/debug' if captured else
                'diagnostic XDP-only' if tag == 'phase-check' and schema == 4 else
                'failed exploratory' if d.get('status') != 'completed' else 'incompatible early/schema-' + str(schema))
        catalogue.append({'run_id': d['run_id'], 'tag': tag, 'schema': schema, 'mode': d['mode'],
                          'scenario': d['scenario'], 'status': d['status'], 'capture': captured,
                          'classification': kind, 'main_comparison': chosen, 'summary_sha256': digest(raw)})
        if not chosen and kind != 'diagnostic XDP-only':
            continue
        errors, warnings = inspect_result(d)
        if errors:
            raise RuntimeError(f'{name}: {errors}')
        base = str(Path(name).parent)
        parsed = parse_dnsperf(files[base + '/dnsperf.log'].decode())
        for field in ('sent', 'completed', 'lost', 'noerror', 'avg_latency_sec', 'min_latency_sec', 'max_latency_sec'):
            if parsed[field] != d['dns'][field]:
                raise RuntimeError(f'Raw DNS log mismatch: {name}: {field}')
        if d['attack_offered_pps']:
            assert parse_tcpreplay(files[base + '/attack.log'].decode()) == d['attack']
            assert digest(files[base + '/attack.pcap']) == d['attack_pcap_sha256']
        dns, perf = d['dns'], d['performance']
        assert dns['success_percent'] == 100 * dns['noerror'] / dns['sent']
        assert dns['achieved_legit_noerror_qps'] == dns['noerror'] / d['duration_seconds']
        counters = d.get('xdp_deltas') or d.get('nft_deltas') or {}
        row = {'evidence_id': '', 'run_id': d['run_id'], 'mode': d['mode'], 'scenario': d['scenario'],
               'seed': d['seed'], 'attack_pps': d['attack_offered_pps'], 'duration_s': d['duration_seconds'],
               'sent': dns['sent'], 'noerror': dns['noerror'], 'success_percent': dns['success_percent'],
               'noerror_qps': dns['achieved_legit_noerror_qps'], 'latency_ms': dns['avg_latency_sec'] * 1000,
               'max_latency_ms': dns['max_latency_sec'] * 1000,
               'dns_cpu_percent': perf['dnsmasq_cpu_percent_one_core'],
               'host_busy_percent': perf['host_cpu_busy_percent_all_cores'],
               'softirq_percent': perf['host_softirq_percent_capacity'],
               'rx_pps': perf['server_interface']['rx_pps'], 'window_s': perf['measurement_seconds'],
               'attack_achieved_pps': (d.get('attack') or {}).get('replay_average_pps'),
               'admitted': counters.get('DNS_PASS', counters.get('admitted')),
               'dropped': counters.get('PACKET_DROP', counters.get('total_dns', 0) - counters.get('admitted', 0)) if counters else None,
               'source_drops': counters.get('DROP_SOURCE_LIMIT', counters.get('source_limit')),
               'global_drops': counters.get('DROP_GLOBAL_LIMIT', counters.get('global_limit')),
               'source_inserts': counters.get('SOURCE_INSERT'),
               'workload_sha256': d['workload_sha256'], 'xdp_source_sha256': d.get('xdp_source_sha256'),
               'kernel': d['kernel'], 'summary_path': name, 'summary_sha256': digest(raw), 'warnings': warnings}
        (selected if chosen else diagnostics).append(row)
    assert len(selected) == 12, 'Expected explicit twelve-run historical dataset; investigate selection changes'
    selected.sort(key=lambda r: (r['attack_pps'], ['none', 'nft', 'xdp'].index(r['mode']), r['seed']))
    for i, row in enumerate(selected):
        row['evidence_id'] = f'H{i+1:02d}'
    for i, row in enumerate(diagnostics):
        row['evidence_id'] = f'D{i+1:02d}'
    assert {r['seed'] for r in selected} == {44, 45}
    assert len({r['workload_sha256'] for r in selected}) == 1
    assert len({r['kernel'] for r in selected}) == 1
    groups = []
    metrics = ['success_percent', 'noerror_qps', 'latency_ms', 'dns_cpu_percent',
               'host_busy_percent', 'softirq_percent', 'rx_pps', 'attack_achieved_pps',
               'admitted', 'dropped', 'source_drops', 'global_drops']
    for rate in (0, 3000):
        for mode in ('none', 'nft', 'xdp'):
            rows = [r for r in selected if r['mode'] == mode and r['attack_pps'] == rate]
            assert len(rows) == 2
            item = {'mode': mode, 'attack_pps': rate, 'trials': 2, 'evidence_ids': ', '.join(r['evidence_id'] for r in rows)}
            for metric in metrics:
                values = [r[metric] for r in rows if r[metric] is not None]
                item[metric + '_mean'] = statistics.mean(values) if values else None
                item[metric + '_sd'] = statistics.stdev(values) if len(values) > 1 else None
            groups.append(item)
    save_csv(OUT / 'run-catalogue.csv', catalogue)
    save_csv(OUT / 'trial-results.csv', selected)
    save_csv(OUT / 'grouped-results.csv', groups)
    result = {'label': 'Historical before-tuning, schema v4; NOT final Phase 2',
              'artifact_count': len(files), 'archive_sha256': digest(ARCHIVE.read_bytes()),
              'catalogue_count': len(catalogue), 'main_run_count': len(selected), 'trials': selected,
              'groups': groups, 'diagnostic_trials': diagnostics,
              'final_phase2_runs': sum(r['tag'] == 'phase2-20261031' for r in catalogue)}
    (OUT / 'analysis.json').write_text(json.dumps(result, indent=2) + '\n')
    make_figures(selected)
    print(f'Audited {len(selected)} comparison runs; archived {len(files)} artifacts; final Phase 2 runs: {result["final_phase2_runs"]}')
    for g in groups:
        print(g['mode'], g['attack_pps'], 'success', g['success_percent_mean'], 'goodput', g['noerror_qps_mean'], 'CPU', g['dns_cpu_percent_mean'])


def make_figures(rows):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    plt.rcParams.update({'font.family': 'DejaVu Serif', 'font.size': 9,
                         'axes.edgecolor': 'black', 'text.color': 'black',
                         'axes.labelcolor': 'black', 'savefig.facecolor': 'white'})
    specs = [
        ('availability', [('success_percent', 'NOERROR success (%)'), ('noerror_qps', 'NOERROR throughput (QPS)')]),
        ('latency-cpu', [('latency_ms', 'Answered-query mean latency (ms)'), ('dns_cpu_percent', 'dnsmasq CPU (% of one core)')]),
        ('host-ingress', [('host_busy_percent', 'Host busy (% all-core capacity)'), ('rx_pps', 'Server device RX (PPS)')]),
    ]
    for filename, panels in specs:
        fig, axes = plt.subplots(1, 2, figsize=(7.2, 2.9), constrained_layout=True)
        for ax, (metric, label) in zip(axes, panels):
            for index, mode in enumerate(('none', 'nft', 'xdp')):
                for seed, marker in ((44, 'o'), (45, '^')):
                    samples = sorted((r for r in rows if r['mode'] == mode and r['seed'] == seed), key=lambda r:r['attack_pps'])
                    x = [0, 3000]
                    ax.plot(x, [r[metric] for r in samples], color='black', linestyle=['-', '--', ':'][index],
                            marker=marker, markersize=4, linewidth=.8,
                            label=mode + f', seed {seed}')
            ax.set_xticks([0, 3000], ['0', '3000'])
            ax.set_xlabel('Offered attack PPS (two tested conditions)')
            ax.set_ylabel(label)
            ax.set_ylim(bottom=0)
            ax.grid(axis='y', color='.85', linewidth=.5)
        axes[1].legend(fontsize=6.5, ncol=2, loc='best')
        fig.suptitle('Historical comparison — individual trials, not final Phase 2', fontsize=9)
        for ext in ('pdf', 'png'):
            fig.savefig(FIG / (filename + '.' + ext), dpi=220)
        plt.close(fig)
    # Final graph uses actual final-outcome counters, not inferred attack drops.
    fig, ax = plt.subplots(figsize=(7.2, 2.6), constrained_layout=True)
    chosen = [r for r in rows if r['attack_pps'] == 3000 and r['mode'] in ('nft', 'xdp')]
    for i, row in enumerate(chosen):
        ax.bar(i, row['admitted'], width=.62, color='white', edgecolor='black', hatch='///', label='Admitted' if i==0 else None)
        ax.bar(i, row['dropped'], bottom=row['admitted'], width=.62, color='.75', edgecolor='black', label='Dropped' if i==0 else None)
    ax.set_xticks(range(len(chosen)), [r['mode']+' / seed '+str(r['seed']) for r in chosen])
    ax.set_ylabel('All recognized DNS queries / run')
    ax.legend(fontsize=8, ncol=2)
    ax.set_title('Historical 3000 PPS runs: aggregate admissions and drops (attack + legitimate)', fontsize=9)
    for ext in ('pdf', 'png'):
        fig.savefig(FIG / ('filter-outcomes.' + ext), dpi=220)
    plt.close(fig)


if __name__ == '__main__':
    main()
