# Frozen benchmark evidence

This directory contains exact preserved evidence and audited derivatives for the final technical report. **It contains historical measurements, not a completed final Phase 2 campaign.**

- `raw-benchmarks.tar.gz`: exact bytes of all 245 files from the local `build/bench/` tree at release audit (about 4.55 MB uncompressed, 1.4 MB compressed). Includes raw summaries, logs, PCAP inputs/captures, historical plots/CSVs and BPF objects retained as experiment evidence.
- `artifact-manifest.json`: archive-relative path, byte count and SHA-256 for every file.
- `run-catalogue.csv`: classification of all 42 experiment summaries; no inference from directory recency.
- `trial-results.csv`: twelve selected clean schema-v4 before-tuning runs, cross-checked against raw DNSPerf/tcpreplay logs and PCAP hashes.
- `grouped-results.csv`: six matching groups, two seeds per group; arithmetic means and sample standard deviations.
- `analysis.json`: structured report inputs, archive checksum, evidence IDs, diagnostic trials and explicit missing final-campaign count.

H01–H12 are the main historical comparison. D01–D03 are separate XDP-only phase-check diagnostics. Capture-enabled and old-schema runs remain archived and catalogued but are not pooled. Unit-test fixtures are not in the evidence dataset.

Run from the repository root:

```bash
python3 scripts/report/prepare_evidence.py
python3 scripts/report/build_report.py
python3 scripts/report/validate_release.py
```

Install `reports/source/requirements.txt` first, as described in `docs/setup.md`. Once the archive exists, the evidence script reads it directly. It does not overwrite the archive, extract over local results, rerun experiments or silently select newer data. Original `build/bench/` files remain untouched. Regenerated monochrome report figures are in `reports/figures/`.

Some raw summaries preserve historical absolute paths and lab addresses. Their exact bytes are retained for traceability. Resolve files through archive-relative paths and the manifest; original developer directories are not runtime requirements. The complete raw archive should be retained with any public release that cites these figures. Separate new campaigns require a deliberate new dataset/provenance review.
