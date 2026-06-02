# TODO

Pure Rust RIST parity notes against the upstream `librist` C implementation.

## Protocol And Runtime Parity

- Apply parsed recovery controls to runtime behavior.
  The URL parser accepts `buffer`, `buffer-min`, `buffer-max`, `bandwidth`,
  `return-bandwidth`, `reorder-buffer`, `rtt`, `rtt-min`, `rtt-max`,
  `min-retries`, `max-retries`, and `congestion-control`, but the pure
  transport currently uses a simpler packet-history and immediate-delivery
  model. Add receiver output/reorder buffering, RTT bounded NACK scheduling,
  retry limits, and bitrate-based retry/backlog caps comparable to librist.

- Model Simple profile RTP/RTCP port pairing in the public pure API.
  librist automatically manages the even RTP port plus odd RTCP port pair.
  The Rust interop harness currently has to create/send RTCP traffic manually;
  move that behavior into `rist::pure`/`rist-mio` so Simple profile peers work
  like librist peers.

- Finish URL option parity, or reject unsupported options explicitly.
  Current no-op or partial options include `timing-mode`, `rtp-timestamp`,
  `rtp-ptype`, `stream-id`, `multiplex-mode`, `multiplex-filter`,
  `compression`, and non-IP `miface` values. Avoid silently accepting options
  that do not affect behavior.

- Add AES-192 URL support if we want parser parity.
  The crypto layer supports AES-192, and librist accepts `aes-type=192`, but
  the pure Rust URL parser currently accepts only `0`, `128`, and `256`.

- Decide the explicit Advanced profile policy.
  The pure builders accept `Profile::Advanced` for the Main-compatible subset.
  Either document that as the intentional behavior, reject advanced-only
  controls, or implement the remaining advanced semantics such as long sequence
  queues and advanced timestamp behavior.

- Evaluate librist library-surface parity outside core streaming.
  C librist exposes OOB data and data-fd/tunnel APIs. The pure Rust path does
  not currently provide equivalents.

## Interop And Test Coverage

- Expand Rust/librist interop beyond the current smoke tests.
  Add the upstream matrix for Simple/Main 0%, 10%, and 25% simulated loss,
  Main sender-client and sender-server modes, NPD in both roles, AES-256
  interop, unencrypted/encrypted mismatch failures, SRP negative cases, and
  caller-controlled sequence passthrough.

- Add multicast interop coverage where the host platform supports it.
  The Rust Mio transport has multicast tests, but the librist interop matrix
  should match the upstream non-Darwin multicast loss cases.

- Keep SRP transport tests serial or make the drive loop more robust.
  SRP-over-Mio passed reliably with serial test execution, but concurrent cargo
  test runs exposed timing sensitivity. Remove that sensitivity before relying
  on default parallel execution as a signal.

- Add longer soak and restart coverage.
  The Rust suite has a sender restart regression and sustained sans-I/O loss
  test. Add longer end-to-end transport soak tests with librist on one side.
