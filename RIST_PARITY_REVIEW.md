# `rist-rs` Accuracy, Performance, and librist Parity Review

Review date: 30 July 2026

Reviewed `rist-rs` commit:
`de2dd7b2b16c3a48b4ebabcca3a2e3078b32b9bf`

Official C comparison target:
librist `v0.2.20`, commit
[`4f45ef8f78983892d52ccd52d9f675435b23738f`](https://code.videolan.org/rist/librist/-/commit/4f45ef8f78983892d52ccd52d9f675435b23738f).
At the time of review, the `v0.2.20` tag and current `master` resolved to
that same commit.

Useful upstream references:

- [v0.2.20 release](https://code.videolan.org/rist/librist/-/releases/v0.2.20)
- [NEWS](https://code.videolan.org/rist/librist/-/blob/4f45ef8f78983892d52ccd52d9f675435b23738f/NEWS)
- [README](https://code.videolan.org/rist/librist/-/blob/4f45ef8f78983892d52ccd52d9f675435b23738f/README.md)
- [Public headers](https://code.videolan.org/rist/librist/-/tree/4f45ef8f78983892d52ccd52d9f675435b23738f/include/librist)
- [Test definitions](https://code.videolan.org/rist/librist/-/blob/4f45ef8f78983892d52ccd52d9f675435b23738f/test/rist/meson.build)

## Executive conclusion

`rist-rs` is not yet at librist parity.

The synchronous FFI path can inherit the behavior of whichever librist version
it links against, but the repository does not pin or validate the latest
version and exposes only a fraction of its API. The Tokio FFI layer has
release-blocking lifetime and concurrency risks.

The pure-Rust implementation is a promising Simple/Main prototype, but its
recovery, security, session model, memory bounds, and Advanced support are not
production-ready. `Profile::Advanced` currently selects the Main
implementation rather than implementing Advanced framing.

The fastest safe route is:

1. Repair the build and test graph.
2. Harden and pin the librist-backed wrapper for immediate production parity.
3. Bound and security-harden the pure-Rust engine.
4. Complete Main recovery, session, networking, and multipath behavior.
5. Implement Advanced `Baseline.Direct`.
6. Optimize the Rust implementation beyond C.

The official C target exposes API `4.13.0`, peer configuration version 6, and
statistics version 3. Its Advanced support is TR-06-3 `Baseline.Direct`, not
every Advanced conformance level. DTLS, FEC, and Advanced fragmentation and
reassembly are not implemented in current librist and should not be treated as
initial parity requirements.

## Current parity

| Capability | Current `rist-rs` state | Verdict |
|---|---|---|
| Raw FFI | Generated from any installed librist >=0.2.8; the review host had 0.2.18 | Behavior varies by build host and does not provide a reproducible latest-C target |
| Safe synchronous wrapper | Basic send/receive, logging, options, partial stats, and SRP | Useful but far behind the current public C API |
| Tokio FFI wrapper | Basic async send/read | Unsafe ownership, unproven concurrency, missing async SRP setup, and no proper backpressure |
| Simple profile | RTP/RTCP basics, NACKs, NPD, and smoke interoperability | Partial; missing automatic RTP/RTCP port pairing and has wrap/report defects |
| Main profile | Reduced GRE, AES-CTR, control packets, and partial SRP | Partial; recovery, session, and security behavior differ materially |
| Advanced profile | `Profile::Advanced` instantiates the Main implementation | Not implemented; the API currently overstates support |
| Recovery/congestion | Fixed packet-count history and immediate output | Prototype only; most parsed settings are unused |
| Multipath/session | Basic weighted selection | Missing per-peer state, recovery priority, RTT routing/muting, and safe rebinding |
| Network surface | Basic UDP and IPv4 multicast | Missing several caller/listener roles, robust IPv6, SSM, TTL/local-port behavior, and truncation handling |
| OOB/tunnel/transport/CBR | Not exposed by pure Rust; mostly absent from the safe wrapper | Large API parity gap |
| Testing | Individual unit suites pass | Workspace/CI is broken and does not test the checked-out crates together |

## Release-blocking findings

### 1. The workspace does not test the checked-out crates together

[`rist/Cargo.toml`](rist/Cargo.toml) and
[`rist-mio/Cargo.toml`](rist-mio/Cargo.toml) depend on registry copies rather
than the local crates, while the root [`Cargo.toml`](Cargo.toml) excludes
`rist-sys`.

`cargo metadata` and `cargo tree` show duplicate local and registry
implementations. Consequently, all-feature wrapper tests do not exercise the
checked-out `rist-core` and `rist-mio` together.

The interop test imports `rist`, but `rist-mio` has no corresponding
dev-dependency. Both `cargo test --workspace --no-run` and
`cargo check --workspace --all-features --all-targets` fail with 24
unresolved-`rist` errors. These are the same paths exercised by
[`.github/workflows/ci.yml`](.github/workflows/ci.yml).

The interop suite should be moved into a separate workspace test package rather
than introducing a `rist-mio` to `wavey-rist` dev-dependency cycle.

### 2. Tokio sender cancellation can use a destroyed C context

[`AsyncSender::send`](rist/src/tokio/sender.rs) clones each packet and creates
a `spawn_blocking` task holding only a copied raw context pointer. Cancelling
the future drops the join handle but does not cancel the blocking operation.
The caller can then drop `AsyncSender`, causing `rist_destroy` to run while the
task may still access the context.

Concurrent sends are enabled through an unsafe `Sync` assertion, although the
current C `rist_sender_data_write` path increments its RTP sequence without an
internal lock. Concurrent use has therefore not been shown safe.

The constructor also registers callback userdata before a fallible
`CString::new(url)?`. That early return leaks the C context after dropping the
callback storage, leaving the context with an invalid callback pointer.

Tokio sender and receiver peer creation also omit the SRP-enabling helper used
by the synchronous constructors.

### 3. Pure SRP is neither secure nor compatible with current librist

[`EapSrpClientSession::handle_frame`](rist-core/src/auth.rs) accepts any EAP
Success as authentication without requiring the expected identifier or a
completed proof exchange.

Other issues include:

- No expected EAP identifier/state tracking.
- Repeated START and LOGOFF do not fully clear sensitive session state.
- The initial authenticator identifier is deterministic.
- Network-provided SRP groups have almost no size or strength validation.
- Arbitrarily large groups can trigger expensive `BigUint` exponentiation.
- Proof comparisons are not constant-time.
- Secrets, private ephemerals, and session keys derive `Debug`.
- Sensitive values are cloned extensively and are not zeroized.
- No authentication retry or expensive-operation rate limits exist.

Rust computes the SRP multiplier and scrambler from minimal-length integers in
[`rist-core/src/auth.rs`](rist-core/src/auth.rs). Current librist uses RFC 5054
left-padding by default and exposes `srp-compat=1` for pre-v0.2.16 behavior.
The pure implementation does not parse or implement that option, so default
interoperability with current C should fail.

Current C also supports EAP v4 with AES-256-GCM, HKDF-derived directional keys,
authenticated metadata, monotonic nonces, and replay rejection, with v3/v2
fallback. The Rust implementation only has the earlier AES-CTR passphrase
mechanism.

See librist's current
[SRP implementation](https://code.videolan.org/rist/librist/-/blob/4f45ef8f78983892d52ccd52d9f675435b23738f/src/crypto/srp.c).

### 4. Small malicious NACKs can cause very large allocations and work

[`decode_records`](rist-core/src/packet/rtcp.rs) expands every represented
sequence into a `Vec<u32>` without a per-range or per-packet limit. Arithmetic
can also overflow near `u32::MAX`.

An 812-byte, 200-record release-mode probe expanded to 13,107,200 sequence
entries, took 13.7 ms, and reached 56.3 MB maximum RSS. A maximum-sized UDP
datagram can request billions of entries.

Current librist limits a range to 256 sequences and a packet to 4,096 requests,
then applies age, retry, RTT-spacing, bandwidth, and duplicate-request controls.
See its
[NACK handling](https://code.videolan.org/rist/librist/-/blob/4f45ef8f78983892d52ccd52d9f675435b23738f/src/rist-common.c#L1995).

### 5. Receiver memory grows forever

[`MissingTracker`](rist-core/src/recovery.rs) retains every delivered sequence
in a `BTreeSet`, even with zero loss. Missing entries also never expire, and a
large gap is materialized one sequence at a time.

Release-mode probes reached:

- 14.7 MB maximum RSS after 1,000,000 sequential packets.
- 66.8 MB maximum RSS after 5,000,000 sequential packets.

The measured linear slope projects to roughly 10 GB/day at approximately 9,500
packets/s. Feedback also collects the entire missing set every 20 ms and then
copies, sorts, and deduplicates it again.

### 6. Recovery breaks after the 16-bit RTP sequence wraps

Missing packets are tracked as extended `u32` values, but
[`encode_nack`](rist-core/src/packet/rtcp.rs) truncates them to `u16` and never
emits the supported sequence-extension RTCP record.

Sender history remains keyed by `u32`, so post-wrap NACKs miss the correct
history cycle or can identify a packet from an older cycle. Existing tests do
not cover this transition.

History eviction is also based on the numerically smallest key. After full
`u32` rollover, newly inserted low sequence numbers are treated as the oldest
entries.

### 7. Socket backpressure creates phantom transmissions

[`SimpleSenderCore::send_payload`](rist-core/src/simple.rs) consumes a sequence,
inserts history, and records statistics before Mio attempts the UDP send in
[`rist-mio/src/lib.rs`](rist-mio/src/lib.rs).

`WouldBlock` or `ENOBUFS` therefore leaves an unsent packet marked as sent and
recoverable. Calling `send_payload` again creates a new sequence rather than
retrying the original encoded datagram. Retransmission and multi-peer batches
can also stop halfway through.

The reviewed local commit correctly normalizes `ENOBUFS` to `WouldBlock`, but
does not yet add a pending-send queue or transactional protocol state.

### 8. PSK handling permits rekey CPU exhaustion

Every changed nonce immediately runs PBKDF2 in
[`PskKey::set_nonce`](rist-core/src/crypto.rs). Decryption also clones the
packet and reconstructs the AES-CTR object per packet.

A release-mode probe with a 1,340-byte input measured:

- Stable nonce: 13.5 microseconds/packet.
- New nonce every packet: 459 microseconds/packet.

The changed-nonce path was approximately 34 times slower and could process only
about 2,180 packets/s/core.

Rust also accepts zero nonces, rotates nonces predictably, exposes
password/key material through `Debug`, and does not zeroize secrets.

Current librist rejects zero nonces, rate-limits abusive PBKDF2, uses random
rotation nonces, caches expanded AES state, and tracks bad decrypts. See the
current
[PSK implementation](https://code.videolan.org/rist/librist/-/blob/4f45ef8f78983892d52ccd52d9f675435b23738f/src/crypto/psk.c).

## Other important accuracy gaps

### Advanced profile

[`Profile::Advanced`](rist/src/pure.rs) silently selects the Main sender and
receiver implementations.

Current C Advanced `Baseline.Direct` includes:

- Main-to-Advanced capability negotiation.
- Native control-plane keepalive, echo/RTT, and NACKs.
- 32-bit media sequences.
- 1 MHz source timestamps with wrap-safe reconstruction/dejitter.
- Type 8 Main GRE encapsulation.
- Flow-ID outer/inner/sub mapping.
- JSON flow attributes.
- LZ4 compression.
- PSK mode 1 and future-nonce announcement.
- EAP v4 authenticated passphrase exchange.
- Configurable Advanced recovery depth.

See upstream [`adv.c`](https://code.videolan.org/rist/librist/-/blob/4f45ef8f78983892d52ccd52d9f675435b23738f/src/adv.c)
and [`adv_ctrl.c`](https://code.videolan.org/rist/librist/-/blob/4f45ef8f78983892d52ccd52d9f675435b23738f/src/adv_ctrl.c).

### Datagram demultiplexing and session isolation

Specialized `try_recv_*` methods each call `recv_datagram` directly. Calling the
wrong helper can consume and discard a valid payload or control datagram.

[`MainMioReceiver`](rist-mio/src/lib.rs) has one global core, `last_peer`,
timer set, and SRP session for all UDP sources. Authentication and liveness are
therefore not isolated per peer. Feedback is sent to the most recently observed
address, and the multi-sender can accept feedback from an arbitrary source and
send retransmissions back to it.

Peer activity is recorded before packet validity/authentication, allowing
garbage traffic to keep a session alive.

### Recovery and output semantics

Recovery controls are parsed but mostly unused, as already noted in
[`TODO.md`](TODO.md). Missing behavior includes:

- Reorder delay and receiver output deadlines.
- RTT-aware delayed/repeated NACK scheduling.
- Minimum and maximum retries.
- Recovery length and age checks.
- Retry bandwidth ceilings and congestion modes.
- Adaptive buffering and CBR output pacing.
- Per-peer recovery selection.

`OrderedPayloadBuffer` exists, but the main pure receive API exposes arrival
order directly. A stream consumer can therefore receive later payload before a
retransmission that logically precedes it.

NPD expansion failure currently drops the packet; current C delivers the
original unexpanded payload.

### Wire/report correctness

- Receiver-report fractional loss is lifetime-based rather than interval-based.
- Jitter is always zero.
- Echo response delay is always zero.
- RTP padding is returned as payload.
- CSRC count can be encoded without emitting CSRC entries.
- RTCP version is not consistently validated.
- SDES CNAME length can wrap to `u8`.
- SDES parsing can read beyond the advertised packet into the next compound
  packet.
- NACK record count can wrap to `u16`.
- UDP truncation is not detected.

### URL and networking behavior

- Unknown URL keys are silently ignored.
- Many accepted URL options do not affect runtime behavior.
- AES-192 exists in the crypto layer but is rejected by the URL parser.
- Current v0.2.20 URL options such as recovery depth/priority, RTT muting,
  split/merge, reflector, TTL, SSM source, local port, and `srp-compat` are
  absent.
- Sender builders default to `127.0.0.1:0`, preventing ordinary routing to
  non-loopback peers unless explicitly overridden.
- IPv6 endpoint reconstruction does not add brackets.
- Non-IP `miface` names are silently discarded.
- Flow IDs use a fixed `0x11223344` default instead of a valid random value.
- Simple RTP/RTCP even/odd port pairing is not part of the public transport API.
- IPv6 multicast and SSM are absent.
- Sender-listen and receiver-client roles are rejected by pure builders.

### Safe FFI API

The wrapper exposes only a small subset of current librist. Missing or partial
areas include:

- Peer handles, removal, reweighting, IDs, socket access, and secret updates.
- Data-block flags, sequence, peer, virtual ports, and reference metadata.
- Flow-ID and NPD controls.
- Receiver callbacks, timeout callback, and flow attributes.
- Jitter, recovery RTT multiplier/depth, and CBR output.
- Full stats v3 and per-peer receiver details.
- OOB read/write/callback.
- Custom transport vtable.
- TUN, tunnel, and `data_fd` APIs.

Configuration documentation also has correctness problems in
[`rist/src/options.rs`](rist/src/options.rs):

- Recovery maximum bitrate is documented as bps but librist uses kbps.
- Reorder buffer is documented as packets but librist uses milliseconds.
- FIFO zero is documented and accepted as disabling output, while current C
  rejects zero.
- Large `Duration` values are silently truncated to `u32` milliseconds.

[`DataBlock::timestamp`](rist/src/receiver.rs) calls `ts_ntp` a 90 kHz value,
although it is an NTP timestamp.

## Performance assessment

The sans-I/O core is already reasonably quick, but current throughput masks
allocation, memory, and runtime-design problems.

### Measured local release-mode baseline

| Path, 1,316-byte payload | Result |
|---|---:|
| Simple send | Approximately 2.99 million packets/s |
| Main clear send | Approximately 2.58 million packets/s |
| Main AES send | Approximately 96,800 packets/s, or 1.02 Gbit/s before socket/runtime overhead |
| Simple send allocations | 3 allocations / 3,240 allocated bytes |
| Main clear send allocations | 4 allocations / 4,580 allocated bytes |
| Main encrypted send allocations | 6 allocations / 7,252 allocated bytes |
| Simple receive allocations | 2 allocations / 1,372 allocated bytes |
| Main clear receive allocations | 2 allocations / 1,372 allocated bytes |
| Main encrypted receive allocations | 5 allocations / 4,064 allocated bytes |

These are directional Rust measurements, not a valid Rust-versus-C benchmark.
The repository currently contains no repeatable benchmark or profiling harness.

### Main Rust hot paths

- Simple send constructs an RTP `Vec` and clones it into history.
- Main send constructs the intermediate Simple/RTP packet and another GRE
  packet.
- Encryption and decryption allocate additional whole-packet vectors.
- History and missing tracking use allocation-heavy tree nodes.
- Main packets can be classified and parsed as GRE multiple times.
- RTCP compounds and NACKs are materialized into owned vectors.
- Multi-peer selection allocates vectors per packet.
- NPD allocates even when no null packet is removed.
- The Tokio sender creates a blocking task and payload copy per packet.
- Tokio `AsyncRead` uses a mutex and prefix `Vec::drain`, causing repeated
  memmoves for small reads.
- UDP uses one syscall per packet and does not tune socket buffers.

### Relevant C strengths

Current librist uses:

- Bounded sequence/retry rings.
- Bounded sender and receiver queues.
- Dedicated protocol/output threads.
- Scatter/gather `sendmsg` for clear Main packets.
- Cached crypto state and optional OS crypto.
- CBR pacing.
- Explicit socket buffer sizing.
- Custom transport support.

Current librist also has optimization opportunities:

- Packet records and payloads are still heap-allocated.
- Receive uses individual `recvfrom` calls.
- No `sendmmsg`, `recvmmsg`, or io_uring batching was found.
- Several peer/flow/event paths use coarse locks.
- Some Advanced construction and crypto paths copy through fixed buffers.
- The official tree has no meaningful throughput benchmark suite or fuzzing
  targets.

A pooled, batched Rust runtime can therefore plausibly outperform C after
correctness and boundedness are established.

## Validation performed

- `cargo fmt --all --check`: passed.
- `cargo test -p rist-core`: 75 tests passed.
- `cargo test -p rist-mio --lib`: 20 tests passed.
- `cargo test -p wavey-rist --all-features`: 28 unit tests and 2 doc tests
  passed, but these used registry `rist-core`/`rist-mio` dependencies rather
  than the entire checked-out source graph.
- Local `rist-sys` build against installed librist 0.2.18: passed.
- Workspace all-target/all-feature build: failed with the missing interop
  dependency described above.
- Clippy with warnings denied: blocked by the interop build and ten local style
  lints.

No benches, fuzzers, property tests, Miri/Loom jobs, sanitizers, long soak
tests, loss matrices, multi-source adversarial tests, or backpressure tests were
found.

Current librist registers 105 tests: 27 unit tests and 78
integration/regression tests. Its tag pipeline was overall successful, although
the Wine-based Windows runtime job was marked `allow_failure`.

## Dependency-ordered implementation plan

### Implementation progress

Updated 30 July 2026. These statuses describe the working tree after the
review; the findings above remain the audit of the originally reviewed commit.

- [x] **M0 complete.** The workspace uses one local source graph, pins CI and
  interop to librist v0.2.20, separates the interop package, rejects
  unsupported behavior, and has format/check/test/Clippy/docs/MSRV/Miri/
  sanitizer coverage configured.
- [x] **M1 complete.** C contexts have exclusive workers and cancellation-safe
  teardown; packet ownership is safe; SRP uses explicit state, RFC 5054 PAD,
  legacy compatibility, bounded work, constant-time proofs, zeroization, and
  EAP v4 AEAD; PSK and NACK work are bounded. Current-C SRP passes in both
  directions.
- [x] **M2 complete.** Recovery history and receiver tracking use bounded
  power-of-two windows; missing state expires; Simple/Main NACKs use librist's
  standard low-16-bit records and full local sequence context; rollover,
  restart, deadline, retry, age, bitrate, congestion, and loss/reorder behavior
  have direct tests. Recovery URL controls are applied, pending UDP sends are
  bounded and retain identical bytes on `WouldBlock`, and NPD failure preserves
  the original payload. Bounded per-peer retry rings share one packet history.
- [ ] **M3 in progress.** The runtime uses one-pass typed datagram dispatch.
  Separate bounded queues isolate data, RTCP, EAPOL, keepalive, buffer
  negotiation, OOB, and unknown traffic. The receiver bounds and isolates
  authentication, liveness, recovery, and feedback state by peer and flow.
  The multipath sender isolates GRE, encryption, liveness, RTT, feedback, and
  retry state by peer. Each multipath peer has an independent SRP session.
  IPv4 and IPv6 unicast work for Simple and Main caller and listener roles.
  Only valid traffic accepted in the current authentication state refreshes
  peer activity. Fresh SRP authentication gates address reassociation to one
  silent matching identity. Same-tuple and listener restarts force
  reauthentication. Simple-profile endpoints bind even RTP and adjacent odd
  RTCP sockets. Media and control traffic use their assigned sockets. Rust
  endpoints support all caller and listener directions. C-supported Main roles
  pass plaintext and SRP black-box tests in both directions. Simple reverse
  roles pass Rust-to-Rust tests as a Rust extension.
- [ ] **M4 pending.**
- [ ] **M5 pending.**
- [ ] **M6 pending.**

### M0: Establish a truthful baseline

Tasks:

1. Convert internal dependencies to `path + version` dependencies.
2. Include local `rist-sys` in the workspace.
3. Move interop tests into a separate workspace package that depends on local
   `wavey-rist`, `rist-core`, and `rist-mio`.
4. Pin CI to librist `v0.2.20`/`4f45ef8`.
5. Add a scheduled compatibility job against current upstream `master`.
6. Decide whether older librist releases are supported. If so, represent each
   ABI/API baseline explicitly with features or separate generated bindings.
7. Make pure `Advanced` return `UnsupportedProfile` until it is implemented.
8. Reject unsupported or no-op URL keys.
9. Add formatting, all-target/all-feature check, tests, Clippy, docs, MSRV,
   Miri, and sanitizer jobs.
10. Correct README package names and maturity claims.

Exit gate:

- One source graph with no registry duplicates.
- Every standard workspace command passes.
- C-to-Rust and Rust-to-C tests run against the pinned C build.
- Unsupported functionality fails explicitly.

### M1: Eliminate memory-safety and security blockers

FFI/Tokio tasks:

1. Put each C context behind one exclusively owning worker.
2. Remove the unproven `Sync` implementations.
3. Replace per-packet `spawn_blocking` with a bounded channel and long-lived
   worker.
4. Make shutdown cancellation-safe and join the worker before context
   destruction.
5. Keep callback userdata alive until the callback is disabled and context
   destruction completes.
6. Perform fallible URL/configuration preparation before callback
   registration, or guard all partial construction with RAII.
7. Use nonblocking, close-on-exec notification descriptors; prefer `eventfd`
   where available.
8. Share peer and SRP setup between synchronous and asynchronous constructors.
9. Make the packet/datagram API primary; keep byte-stream adapters separate and
   explicit about boundary loss.

Pure security tasks:

1. Replace authentication booleans with explicit EAP/SRP states.
2. Track the exact expected identifier and message subtype.
3. Accept Success only after the local proof/state sequence completes.
4. Clear all key/proof/passphrase state on logoff, restart, timeout, or failure.
5. Use a CSPRNG initial identifier.
6. Implement RFC 5054 PAD behavior and `srp-compat=1`.
7. Constrain SRP modulus/generator sizes and reject weak or oversized groups.
8. Use constant-time proof comparison.
9. Add authentication retry and expensive-operation rate limits.
10. Implement EAP v4 AES-256-GCM, HKDF, AAD, directional keys, monotonic
    nonces, and replay rejection with v3/v2 fallback.
11. Remove secret-bearing `Debug` implementations.
12. Use zeroizing containers and minimize secret cloning.
13. Reject zero PSK nonces and invalid key sizes.
14. Use random nonces on key rotation and implement future-nonce handling.
15. Limit PBKDF2 rekeys per key and add bad-decrypt strike/decay handling.
16. Bound NACK ranges to 256 and packets to 4,096 without unbounded expansion.

Exit gate:

- Adversarial authentication cannot bypass state.
- Malformed inputs have fixed allocation/work bounds.
- Latest-C SRP works in both directions.
- Cancellation/drop stress reports no race, UAF, leak, or deadlock.

### M2: Build a bounded and correct recovery engine

Tasks:

1. Replace `BTreeMap` history with a power-of-two ring.
2. Store a full-sequence tag, timestamp, payload length, and transmitted buffer
   in each history slot. Store retry data in bounded per-peer slots.
3. Replace delivered/missing sets with a bounded sequence window and bitmap.
4. Expire missing state by recovery age/window.
5. Emit and consume sequence-extension records correctly across 16-bit wrap.
6. Add checked/wrapping sequence arithmetic and full 32-bit rollover tests.
7. Implement reorder delay and deadline-aware ordered output.
8. Implement RTT-bounded NACK delay/repetition.
9. Apply minimum/maximum retry limits.
10. Apply recovery age and bitrate ceilings.
11. Suppress duplicate retry requests.
12. Implement congestion-control modes.
13. Apply every parsed recovery setting or reject it.
14. Add a bounded pending-send queue.
15. Commit sequence/history/statistics when the packet is accepted into that
    queue.
16. On `WouldBlock`, retain and retry identical bytes with the same sequence.
17. Preserve the original payload on NPD expansion failure.

Exit gate:

- Accelerated 16-bit and 32-bit wrap/restart tests pass.
- 0%, 1%, 10%, and 25% loss/reorder scenarios match or beat C recovery.
- Recovery memory is strictly bounded by configuration.
- Backpressure never creates phantom packets.

### M3: Correct runtime, network, and multipath behavior

Tasks:

1. [x] Parse each datagram once into a typed event.
2. [x] Dispatch data, RTCP, EAPOL, keepalive, buffer negotiation, OOB, and unknown
   controls into appropriate bounded queues.
3. [x] Maintain authentication, liveness, RTT, recovery, and feedback state per
   peer/flow.
4. [x] Refresh activity only for valid traffic acceptable in the current state.
5. [x] Implement safe NAT rebinding and restart reauthentication.
6. [x] Add Simple RTP/RTCP even/odd port management.
7. [x] Support caller/listener roles in both sender and receiver directions.
   Main plaintext and SRP roles pass C-to-Rust and Rust-to-C tests.
   Simple reverse roles pass Rust-to-Rust tests as a Rust extension.
   Current librist does not support those Simple reverse roles.
8. [x] Add complete IPv4/IPv6 unicast behavior.
   Native tests cover Simple and Main in caller and listener roles.
   Main passes current-C tests in both directions.
   Simple passes from a current-C sender to a Rust receiver.
   Current librist v0.2.20 crashes in its Simple IPv6 receiver, including a
   C-to-C baseline.
9. [ ] Add ASM/SSM multicast, TTL/hop limit, interface names, and local-port
   binding.
10. [ ] Configure socket buffers and detect truncated datagrams.
11. [ ] Implement weight-zero duplication and weighted balancing without
    per-packet allocation.
12. [ ] Add recovery priority and RTT tie-breaking.
13. [ ] Implement RTT auto-muting, settle/restore thresholds, sole-carrier
    protection, trickle traffic, and rejoin ramp.
14. [ ] Add split/merge, reflector, compression, and CBR output behavior.
15. [ ] Maintain per-peer stats and configuration rather than allowing the most
    recent URL to overwrite global settings.

Exit gate:

- Multipath failure/recovery works under asymmetric loss and RTT.
- NAT rebind and process restart do not weaken authentication.
- Multicast and all C-supported caller/listener role combinations interoperate
  with C.

### M4: Implement Advanced `Baseline.Direct`

Match the scope current librist actually implements:

1. Main-to-Advanced capability negotiation.
2. Native Advanced data and control headers.
3. 32-bit media sequences.
4. Range and bitmask NACKs in the correct sequence domain.
5. 1 MHz source timestamps and wrap-safe dejitter.
6. Type 8 Main GRE encapsulation.
7. Flow-ID mapping and flow attributes.
8. LZ4 compression with receiver autodetection.
9. PSK mode 1 and future-nonce announcement.
10. EAP v4 authenticated passphrase exchange.
11. Configurable Advanced recovery depth.
12. Main/Advanced interoperation and fallback behavior.

Do not claim DTLS, FEC, or Advanced fragmentation/reassembly as parity
requirements until the official C implementation supports them.

Exit gate:

- Bidirectional C/Rust differential and network tests cover every implemented
  Advanced capability.
- A Main peer is never upgraded before successful capability negotiation.

### M5: Complete the public API

Add safe equivalents for:

- Peer handles, removal, weight updates, IDs, sockets, and secret updates.
- Connection and authentication callbacks.
- All data-block metadata: timestamps, virtual ports, peer, flow ID, sequence,
  flags, and reference metadata.
- Flow-ID and NPD controls.
- Receiver callback and timeout callback.
- Jitter, recovery RTT multiplier/depth, and CBR output.
- Full stats v3, per-peer details, profiles, bytes, Advanced state, and
  RTT-muting events.
- OOB read/write/callback.
- Custom transport vtable.
- `data_fd`, tunnel, and TUN APIs where supported.
- Flow attributes and structured/JSON/OpenMetrics statistics.

Older librist compatibility should be explicit and versioned rather than
silently determined by whichever headers are installed.

Exit gate:

- Every supported public C operation has either a safe Rust equivalent or a
  documented, typed unsupported result.

### M6: Reach better-than-C performance

Tasks:

1. Introduce pooled packet buffers with headroom.
2. Encode RTP/GRE headers in place.
3. Encrypt/decrypt in place where ownership permits.
4. Store the transmitted buffer directly in recovery history.
5. Parse GRE exactly once and decrypt at most once.
6. Stream RTCP/NACK parsing directly into bounded consumers.
7. Cache expanded AES state and use available hardware acceleration.
8. Make peer selection and steady-state send/receive allocation-free.
9. Add scatter/gather `sendmsg`.
10. Add Linux `sendmmsg`/`recvmmsg` after portable correctness is established.
11. Consider io_uring only after the queue/ownership design is stable.
12. Use bounded driver queues, pacing, and explicit socket readiness.
13. Add allocator counters, RSS soaks, flamegraphs, and lock profiling.
14. Benchmark Rust and C with identical affinity, payloads, socket sizes,
    crypto, and network-fault settings.

Exit gate:

- Rust matches or improves C throughput, CPU, latency, recovery, and memory
  under the same harness.

## Definition of parity or better

### Correctness and security

- Simple, Main, and Advanced work in both C-to-Rust and Rust-to-C directions.
- Clear, AES-128, AES-192, AES-256, and SRP v2/v3/v4 are covered.
- Wrong-secret, wrong-password, replay, zero-nonce, malformed-group, and
  unauthenticated-control cases fail closed.
- Every NACK packet represents at most 4,096 requests and uses at most 64 KiB
  scratch.
- Abusive nonce traffic causes at most approximately 100 PBKDF2
  derivations/s/key.
- Fuzz/property/differential tests cannot panic, abort, overrun, or allocate
  outside configured bounds.

### Memory and recovery

- A 24-hour 100 Mbit/s run with 1% loss/reorder has less than 16 MiB post-warmup
  RSS growth.
- All history, missing, reorder, retry, and output state is bounded by explicit
  configuration.
- 16-bit and accelerated 32-bit wrap/restart tests recover successfully.
- Socket `WouldBlock` retries the identical datagram and sequence.
- Recovery p50/p95/p99 is no worse than C under identical 0%, 1%, 10%, and 25%
  loss and 5, 50, and 200 ms RTT scenarios.

### Runtime safety

- No task is spawned per packet.
- A single owner controls each C context.
- One million async cancellation/drop iterations pass sanitizer checks without
  UAF, race, leak, or deadlock.
- One datagram produces one outer GRE parse and at most one decrypt.

### Official C test reuse

- Run official black-box tests with Rust and C endpoints in both directions.
- Parameterize network scripts so they can start Rust or C commands.
- Import stable C packet vectors into Rust differential tests.
- Add a C-ABI adapter only when a private-function test has no network form.

### Performance

- Clear Main send uses at most one steady-state allocation and one full payload
  copy.
- Encrypted send uses at most one allocation and two full copies.
- Receive uses at most one steady-state allocation.
- Peer selection is allocation-free.
- Clear/AES-128/AES-256 are tested at 100, 500, and 1,000 Mbit/s.
- Initial CPU target is no more than 110% of C; a better-than-C claim requires
  no more than C CPU or a material, demonstrated latency/memory improvement.
- CBR packet-spacing variance and back-to-back rate are no worse than the same
  librist build.

## Recommended initial PR sequence

1. **Workspace truth:** local path dependencies, include `rist-sys`, separate
   interop package, pinned v0.2.20 CI.
2. **Truthful surface:** reject pure Advanced and unsupported URL options;
   correct API units and documentation.
3. **Tokio safety:** exclusively owned worker, bounded queue, callback RAII,
   nonblocking notification, shared SRP setup.
4. **Parser/security bounds:** NACK caps, checked lengths/arithmetic, RTP/RTCP
   hardening, secret redaction/zeroization, PSK rekey throttle.
5. **SRP parity:** explicit state machine, RFC 5054 padding, group bounds,
   constant-time proofs, `srp-compat`, EAP v4.
6. **Bounded recovery:** ring history, missing bitmap, sequence extension,
   timed retry policy, ordered output.
7. **Runtime/session:** unified demux, per-peer state, transactional
   backpressure, network roles, NAT/restart.
8. **Multipath/Main completion:** priority, RTT routing/muting, split/merge,
   reflector, compression, CBR.
9. **Advanced `Baseline.Direct`.**
10. **Full API and performance optimization.**
