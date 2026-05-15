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
- PSK crypto primitives matching librist's PBKDF2-HMAC-SHA256 + AES-CTR
  approach, with encrypted Main Profile reduced packets.
- RIST URL parsing for listen/client addresses and common recovery/crypto query
  options.
- Sequence extension and missing-packet tracking.
- Sender history and retransmission lookup.
- Pure Rust sender/receiver statistics for send, receive, missing, recovered,
  retransmitted, feedback, quality, and RTT counters.
- Simple Profile sender/receiver core that can detect a dropped packet, build
  NACK feedback, retransmit, and mark recovery.
- Main Profile sender/receiver core for GRE reduced data, NACK feedback,
  keepalive, buffer negotiation, NPD, PSK encryption, and encrypted feedback.
- Mio UDP transport for Simple and Main profiles, including packet loss recovery,
  NPD, RTCP echo RTT, Main Profile keepalive/buffer negotiation, and encrypted
  Main Profile recovery.
- A `rist` crate `pure-rust` feature that exposes the Rust implementation under
  `rist::pure` while leaving the existing librist-backed API unchanged by
  default.
- An environment-gated bidirectional `librist` interop harness for Simple
  Profile. It covers pure Rust sender to librist receiver and librist sender to
  pure Rust receiver, including Simple Profile RTP/RTCP even-port pairing.
- GitHub Actions CI that installs `librist-dev` and runs `RIST_INTEROP=1`
  interop coverage.

## Next Slices

1. Encrypt keepalive and buffer-negotiation control packets in Main Profile.
2. Replace deterministic PSK nonce construction in tests with production nonce
   generation and key-rotation policy.
3. Expand the `rist::pure` API from reexports into ergonomic sender/receiver
   builders that mirror the existing librist-backed API.
4. Implement SRP/EAP authentication and passphrase rollover.
5. Build out the remaining upstream loss/mode matrix: Simple multicast,
   Main server/client and client/server modes, AES mismatch failures, sender
   restart behavior, and SRP-enabled integration.
