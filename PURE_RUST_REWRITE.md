# Pure Rust RIST Rewrite

This repo now has a first pure Rust protocol path alongside the existing
librist bindings:

- `rist-core`: safe, sans-I/O protocol primitives and state machines.
- `rist-mio`: nonblocking UDP transport experiments built on Mio.
- `rist` and `rist-sys`: current public API over librist, kept as the
  compatibility layer while the Rust implementation matures.

## Upstream Test Targets

`librist` does have a Meson test suite under `test/rist`:

- `test_send_receive.c`: Simple and Main Profile send/receive tests.
- Simple Profile unicast with 0%, 10%, and 25% simulated packet loss.
- Simple Profile multicast tests on non-Darwin hosts.
- Main Profile server/client and client/server modes with 0%, 10%, and 25%
  simulated packet loss.
- Main Profile null packet deletion checks.
- Main Profile AES-128/AES-256 encryption success and mismatch failure tests.
- SRP authentication unit tests and SRP-enabled integration cases when built
  with SRP support.
- `test_sender_restart.c`: sender restart regression coverage.

Those tests are not a standalone cross-implementation conformance suite, but
they are a useful oracle. The Rust rewrite should add interop harnesses that run
Rust sender against `librist` receiver, `librist` sender against Rust receiver,
then Rust against Rust under the same loss profiles.

## Current Rust Milestone

The first milestone has grown into a usable pure-Rust prototype:

- RTP encode/decode for MPEG-TS-shaped RIST payloads.
- RTP header-extension support for RIST null packet deletion.
- MPEG-TS null packet suppression and expansion for 188-byte and 204-byte TS
  packets.
- RTCP sender reports, receiver reports, SDES CNAME, echo request/response,
  range NACKs, bitmask NACKs, seq-ext NACK context, and compound feedback
  decoding.
- Automatic RTCP polling for sender reports, receiver reports, echo requests,
  and NACK feedback in the pure Rust cores, with Mio helpers to send due RTCP.
- GRE reduced-header encode/decode for Main Profile v1 and v2 VSF wrapping.
- GRE keepalive and buffer-negotiation packet encode/decode.
- Main Profile defaults now use the librist-compatible GRE v1 reduced-packet
  wire shape, while retaining explicit GRE v2 VSF support in the packet layer.
- PSK crypto primitives matching librist's PBKDF2-HMAC-SHA256 + AES-CTR
  approach, with encrypted Main Profile reduced packets, feedback packets,
  keepalives, and buffer-negotiation packets.
- Production PSK transmit keys generate nonces from OS randomness and rotate
  nonce/key material after a configurable packet count. Deterministic nonces are
  confined to known-vector tests.
- EAPOL/EAP-SRP framing, librist-compatible SRP-SHA256 verifier and handshake
  primitives, generation-based credential lookup for re-authentication,
  passphrase rollover helpers, and unencrypted EAPOL GRE control packets for
  Main Profile authentication.
- Mio Main Profile SRP client/authenticator integration that gates data until
  authentication completes, plus environment-gated librist SRP handshake
  and payload interop in both directions.
- SRP credential rollover hooks through the Mio Main transport, including
  client password reset, authenticator credential staging/retirement, and
  re-authentication after rotating to a new generation.
- RIST URL parsing for listen/client addresses and common recovery/crypto query
  options.
- Typed parsing for librist peer URL options including bandwidth, retry,
  virtual-port, connection-timer, congestion-control, timing, multicast
  interface, SRP, and advanced/multiplex metadata, with pure Main Profile
  senders applying virtual GRE ports, multicast IPv4 interfaces, and initial
  RTP sequence numbers from URLs.
- Sequence extension and missing-packet tracking.
- Sender history and retransmission lookup.
- Pure Rust sender/receiver statistics for send, receive, missing, recovered,
  retransmitted, feedback, quality, and RTT counters.
- Simple Profile sender/receiver core that can detect a dropped packet, build
  NACK feedback, retransmit, and mark recovery.
- Main Profile sender/receiver core for GRE reduced data, NACK feedback,
  keepalive, buffer negotiation, NPD, PSK encryption, and encrypted feedback.
- Main Profile session timers for keepalive scheduling and peer inactivity
  timeout detection, wired through the Mio transport and pure builder URL
  options.
- A pure Rust peer-selection core plus Mio/Main and `rist::pure` multi-peer
  sender surfaces for duplicate mode (`weight=0`) and smooth weighted
  load-balancing with shared Main Profile sequence state.
- Receiver duplicate accounting for bonded duplicate paths, with receiver
  quality based on unique received packets rather than duplicate datagrams.
- Mio UDP transport for Simple and Main profiles, including packet loss recovery,
  NPD, RTCP echo RTT, Main Profile keepalive/buffer negotiation, and encrypted
  Main Profile recovery.
- Mio multicast socket controls, plus non-Darwin Simple Profile multicast
  coverage matching the upstream platform constraint.
- Reusable UDP bind support and explicit IPv4 multicast interface selection,
  with Main/Simple sender hooks and pure URL `miface` application for IPv4
  literal interfaces.
- Main Profile sender restart regression coverage that repeatedly creates,
  uses, drops, and recreates a sender while exercising a sustained send loop.
- Sans-I/O Main Profile sustained periodic-loss recovery coverage over hundreds
  of packets, exercising larger NACK feedback and retransmission batches.
- A `rist` crate `pure-rust` feature that exposes the Rust implementation under
  `rist::pure` while leaving the existing librist-backed API unchanged by
  default. `rist::pure::Sender` and `rist::pure::Receiver` now provide builder
  APIs over the Mio transport, with socket-address and RIST URL setup, PSK
  options, SRP URL credentials and handshake helpers, send/receive helpers,
  feedback, RTCP polling, stats, and local address access.
- `Profile::Advanced` is accepted by the pure builders for the implemented
  Main-compatible subset, with advanced-only policy still tracked as remaining
  work.
- An environment-gated bidirectional `librist` interop harness for Simple
  Profile. It covers pure Rust sender to librist receiver and librist sender to
  pure Rust receiver, including Simple Profile RTP/RTCP even-port pairing.
- Environment-gated Main Profile `librist` payload interop in both directions
  for clear and AES-128 traffic, including RTCP demux on the Rust receiver side,
  the initial Main RTCP sender report needed by librist receivers, and
  wrong-secret failure coverage in both directions.
- GitHub Actions CI that installs `librist-dev` and runs `RIST_INTEROP=1`
  interop coverage.

## Next Slices

1. Move beyond the upstream smoke matrix into remaining production gaps:
   Advanced-only policy completeness, multicast-specific SRP rollover coverage
   on non-Darwin hosts, applying the remaining parsed URL controls to runtime
   behavior, and long-running soak tests.
