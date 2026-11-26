# rist-rs against librist 0.2.20, 26 November 2026

Evidence for the `perf-librist-parity` work: rist-rs measured against librist v0.2.20 on
the transport bench, at rist-rs `cbf19d8` (run b) and `82bfc2b` (run a). The full write-up
is [REPORT-rist.md](REPORT-rist.md).

## How it was measured

- **Harness.** The transport bench (`tb`, `lab/bench.py`, `scripts/analyze.py`) on the
  transport-bench branch `rist`. Run a was measured at harness `8b5d493`, run b at `3057c8f`
  (`tb` built at `102779b`), and the report is at `907a511`. That repository has no public
  remote; the branch and commits are named so the method can be traced.
- **Sender and receiver.** `tb --proto rist-rs-next` uses rist-core and rist-mio from this
  repository through the bench's adapter (`src/proto/rist_rs_next.rs`), with the product's
  settings: bandwidth 100 000 kbit/s, `rtt_min` 5 ms, `rtt_max` 500 ms, reorder 15, retries
  6..20, `RecoveryTuning::default()`, delivery through
  `OrderedPayloadBuffer::with_deadline(cap, L)`. librist is v0.2.20, linked statically, with
  `buffer-min = buffer-max = L` and `rtt-min` set to the path RTT. Both use the **Main
  profile** without encryption. Interop cases pair the two (`rist-rs-next:librist` and
  `librist:rist-rs-next`).
- **Media.** 4K H.264 elementary streams at six rungs (2160p5/25/80/160/240/320 = 5.6, 25,
  81, 165, 248 and 334 Mbit/s), 24 fps, 15 s per case (360 frames). A frame counts as lost if
  any of its packets is missing, and late if it completes after the base delay plus L plus
  10 ms.
- **Lab.** Fresh dedicated Linode instances for each run, image `linode/arch`, the same
  types as the baseline: `lon-tx` and `lon-rx` g6-dedicated-16 in `gb-lon` (London), on
  different physical hosts, joined by a private VLAN; `new-rx` g6-dedicated-8 in `us-east`
  (Newark) and `syd-rx` g6-dedicated-8 in `ap-southeast` (Sydney). The sender is always
  `lon-tx`. Memory was warmed on every node and three throw-away cases ran before measuring.
- **Impairments.** The London pair adds RTT/2 delay each way with netem (RTT 1, 30, 100 and
  250 ms) and loss: none, 1 % and 5 % random, Gilbert-Elliott bursts (about 2 % mean), 20 ms
  outages every 2 s, and single outages of 50 ms to 1 s. The New York and Sydney paths are
  real; their RTT is pinned to the baseline's 73 and 257 ms (measured on the day: 67 and
  246 ms) and they add none or 1 % loss. Buffer L is max(4 × RTT, 40 ms) unless the case
  sweeps it (1.5 to 6 × RTT).
- **Cases.** The 94 rist-rs / librist pairs of the bench's T8 table, 8 new cells (RTT 100 at
  1 % for four rungs and 2160p320 on the real paths, where librist ran in the same hour), 44
  interop cells, 16 udp references and 8 jitter and fan-out cells. Cells with any loss above
  zero were repeated.
- **Baseline.** librist and the previous rist-rs come from the bench's run of 24 November
  2026 (`tbench-linode-20261124`), not re-run.

## What it shows

On run b (`cbf19d8`), against librist:

- Frames lost or late over the 102 cells: 63 against 2,111 (the previous rist-rs: 8,927 over
  its 94 cells). Fewer in 34 cells, the same in 67, more in 1 (by one frame).
- Sender CPU per Gbit/s about 0.66–0.71× librist's, receiver about 0.11–0.23× (medians by
  loss class); lower in all 102 cells on both sides.
- Every rung up to 334 Mbit/s carried whole in every condition; librist's highest whole rate
  ranges from 165 Mbit/s up to the top rung.
- Added latency (p99) lower in all 102 cells.
- Interop with librist works both ways in all 44 cells, and no cell is worse than both native
  runs.

## Limits

- **librist's baseline was not re-run in the same hour.** Its figures are from 24 November on
  the same instance types (other physical hosts), except the 8 new cells. udp references
  calibrate the hosts; see the report's Method.
- **One frame behind librist in one cell.** A 2160p160 at RTT 250 ms with burst loss lost one
  frame mid-stream in run b where librist lost none; the same cell lost nothing in run a and
  both repeats. Run a's one miss (frame 0, at RTT 250 with bursts) was fixed in `cbf19d8`.
- **Fan-out to 100 receivers fails** at 2160p25 (2.6 Gbit/s from one host), as it does for
  librist and the previous rist-rs. One sending thread runs out of CPU, so rist-rs loses
  slightly more frames outright there (lost plus late is the same).
- **Wire overhead at 5 % loss.** Up to 6.1 points more bytes on the wire at 5 % loss with
  short buffers and 8.5 points more during a 1 s outage, because some NACKs and late repairs
  are sent twice. The median difference over the 102 cells is zero.
- **Profiles.** The bench measured the Main profile, unencrypted. Simple is covered only by
  the interop test suite; the Advanced profile is not covered.
- **Only librist, on our own bench.** No other RIST implementation, encoder or decoder was
  measured.

## What is here

| path | contents |
|---|---|
| [REPORT-rist.md](REPORT-rist.md) | the full report: verdict per criterion, all 102 pairs, CPU, ceilings, latency, start of stream, interop, local runs, remaining gaps, cost |
| [charts/](charts/) | run b: frames lost (r1), receiver and sender CPU (r2, r3), added p99 (r4), ceilings (r5); local r3 frames lost |
| [run-b/](run-b/), [run-a/](run-a/) | per-case tables (`cases.csv`), the bench's summaries (`summary.md`), and `runs-a-b.csv` with both runs per pair |
| [baseline-20261124/](baseline-20261124/) | the librist, rist-rs, rist-rs-614 and udp rows of the 24 November baseline |
| [manifests/](manifests/) | manifest of each run and repeat and of the baseline (times, code heads, settings, topology, node facts, cost); per-file lists omitted, public addresses redacted |
| [local/](local/) | local netns runs: summaries r2 and r3, the start-of-stream table, and an A/B of `82bfc2b` against `cbf19d8` |

Raw data (per-case and per-frame files, CPU samples, qdisc stats, logs, full manifests) is in
the R2 bucket `needletail-data` under `trist-linode-20261126a*`, `trist-linode-20261126b*`,
`trist-local-*` and `tbench-linode-20261124`. No packet captures were taken.
