# Implementation source

`xdp/` contains the protected packet parser, source GCRA and global bucket. `controller/` contains the Go loader/exporter. `tests/` contains C and kernel tests plus the legitimate DNS workload. Use the [root README](../README.md) and root Make targets for building; the embedded BPF object is generated before the controller build.
