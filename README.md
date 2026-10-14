# ByteGuard — AIORI-3 Hackathon

**Team Code:** A3-PS022-TC127  
**Problem Statement:** PS-022  
**Project:** eBPF/XDP Rate Limiting for DNS Query Floods

## Team Members

- Prashant Sengar
- Janhvi Gokhale

**Faculty Mentor:** Dr. Nitish Andola  
**Institution:** IIITDM Jabalpur

## Level 1 Submission

- [Final Proposal PDF](A3-PS022-TC127_ByteGuard_Proposal.pdf)
- [Team Introduction Video](https://youtu.be/mlLHwwHBs1s)

## Project Overview

ByteGuard is an eBPF/XDP-based DNS admission control system designed to mitigate high-rate DNS query floods.

Our proposed approach combines per-source rate limiting with a global admission budget to constrain both single-source and distributed floods while minimizing packet-processing overhead.

The system will be evaluated against no-filter and nftables baselines, measuring CPU utilization, throughput, packet drops, and legitimate DNS query success.

## Implementation

Source code, testing tools, benchmark results, and deployment instructions will be added as development progresses.
