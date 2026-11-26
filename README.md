# rist-rs

## rist-rs against librist

On our own bench, rist-rs now beats librist v0.2.20, the reference C
implementation that FFmpeg and GStreamer use for RIST. Across the same 102
cases (26 November 2026, dedicated Linode instances, London to London, New
York and Sydney, 1 to 257 ms RTT, no added loss, 1% and 5% random loss,
burst loss and outages of 20 ms to 1 s):

| | rist-rs | librist |
| --- | --- | --- |
| Frames lost or late, all 102 cases | **63** (the previous rist-rs: 8,927 in its 94 cases) | 2,111 |
| Sender CPU per Gbit/s | **about 0.66–0.71×** librist's | 1× |
| Receiver CPU per Gbit/s | **about 0.11–0.23×** librist's | 1× |
| Highest 4K rate carried whole | **every rung to 334 Mbit/s**, in every condition | stops between 165 and 334 Mbit/s |
| Added latency (p99) | **lower in all 102 cases** | |
| Interop with librist, both ways | works in all 44 cells (Main profile) | |

All with the product's own settings, not a tuned profile.

What it does not show yet:

1. **Only librist.** No commercial RIST stack or other open-source
   implementation was measured.
2. **Our own test.** We chose the cases and wrote the bench. librist's figures
   are its 24 November baseline, not re-run in the same hour. Interop is
   proven against librist, not yet against real encoders and decoders.
3. **Profiles.** Main on the bench and Simple in the interop tests, without
   encryption; the Advanced profile is not covered.
4. **Known weak spots.**
   - Fan-out to 100 receivers from one host fails, as it does for librist; one
     sending thread runs out of CPU, so rist-rs loses slightly more frames
     outright there.
   - Up to 6 to 8.5 points more bytes on the wire at 5% loss with short
     buffers and during a 1 s outage, because some repair requests and late
     repairs are sent twice. The median difference across the 102 cases is
     zero.
   - One case lost one frame where librist lost none; the same case lost
     nothing in three other runs.

The report, charts, per-case tables and how it was measured are in
[benchmarks/2026-11-26-librist-parity](benchmarks/2026-11-26-librist-parity/).

Pure Rust RIST protocol work plus the existing safe Rust bindings for
[librist](https://code.videolan.org/rist/librist).

RIST (Reliable Internet Stream Transport) is a protocol for reliable video streaming over lossy networks with low latency.

## Crates

- `rist-sys` - Raw FFI bindings generated via bindgen
- `rist-core` - Sans-I/O pure Rust protocol engine
- `rist-mio` - Nonblocking UDP transport for the pure Rust engine
- `rist-tools` - Operational loss and recovery qualification tools
- `wavey-rist` (`rist` library name) - Safe wrapper and public API
- `rist-interop-tests` - Black-box Rust/librist interoperability suite

## Features

- **Async Tokio support** - Enable with `tokio` feature
- **Optional stream adapters** - Explicit adapters implement `AsyncRead` and
  `AsyncWrite` when discarding packet boundaries is acceptable
- **Stats API** - Access connection statistics via `raw_stats()`
- **Configuration options** - Builder pattern for receiver/sender options

## C Parity Checklist

This checklist summarizes [the detailed parity review](RIST_PARITY_REVIEW.md).
A green tick means that the implementation and its tests are complete.
A red cross means that required work or verification remains.

- ✅ Workspace, build, CI, interoperability, and toolchain controls
- ✅ Security, SRP, EAP, PSK, parser bounds, and resource limits
  - A keyed endpoint drops clear packets other than EAPOL and never sends
    them; PSK itself has no authentication tag (see the security note below).
- ✅ Bounded Simple and Main recovery, NACKs, retries, rollover, and backpressure
- ✅ Typed one-pass Main datagram dispatch with bounded queues
- ✅ Per-peer authentication, liveness, RTT, recovery, and feedback state
- ✅ Valid-traffic activity rules
- ✅ Authenticated NAT rebinding and restart reauthentication
- ✅ Simple RTP and RTCP even-odd port pairs
- ✅ All caller and listener combinations supported by current librist
  - Main plaintext and SRP roles pass C-to-Rust and Rust-to-C tests.
  - Simple reverse roles pass Rust-to-Rust tests as a Rust extension.
- ✅ IPv4 and IPv6 unicast behavior
  - Simple and Main pass native tests in both caller and listener roles.
  - Main passes current-C interoperability tests in both directions.
  - Simple passes current-C sender to Rust receiver tests.
  - Current librist 0.2.20 crashes in its Simple IPv6 receiver, including a C-to-C baseline.
- ❌ ASM and SSM multicast behavior
- ✅ Socket buffers and truncated-datagram detection
  - Sockets request the current librist 8 MiB target and require its historical safe floor.
  - Small caller buffers use bounded scratch storage and return typed truncation errors.
  - Datagrams above librist's 10,000-byte limit fail before protocol parsing.
- ❌ Allocation-free weighted multipath transmission
- ❌ Recovery priority and RTT route selection
- ❌ RTT muting, failure handling, trickle traffic, and rejoin behavior
- ❌ Split, merge, reflector, compression, and CBR behavior
- ❌ Complete per-peer configuration and statistics
- ❌ Advanced profile data, control, recovery, encryption, and negotiation
- ❌ Complete public API and URL-option parity
- ❌ Measured throughput, latency, memory, and recovery parity

### Security note: RIST Main PSK has no authentication tag

RIST Main profile PSK encryption (AES-CTR with a key derived from the
passphrase by PBKDF2, as in librist) encrypts each packet but adds no
authentication tag. What that means:

- **Confidentiality, not integrity.** Without the passphrase nobody can read
  the media or control payloads (the GRE header, with the nonce and sequence,
  stays clear). There is no cryptographic integrity check and no sender
  authentication of data packets.
- **Wrong keys and forgeries are caught by header checks only.** After
  decryption rist-rs checks what librist checks (RTP version 2, VSF protocol
  and subtype) and more: no RTP padding or CSRC, MPEG-TS payload type, the
  RIST header extension when flagged, well-formed RTCP compounds and lengths.
  A nonce that fails the checks is shut out (at its first failure until it
  has passed them, at the seventh in a row after, as librist does). These
  checks reject a wrong key or a forged packet with high probability but not
  with cryptographic strength: random data passes the data-packet checks
  about once in 2^15 tries. Keepalives, buffer negotiation and out-of-band
  data carry too little structure to check.
- **Bit flips go undetected.** AES-CTR is malleable: an on-path attacker can
  change bits of an encrypted payload, for example media bytes, and the
  receiver cannot tell as long as the headers still pass.
- **A spoofed packet can stall a stream.** Packets forged with a sender's
  nonce can get that nonce shut out until the sender's nonce rotates, as
  with librist.
- **SRP does not change this.** EAP-SRP authenticates the peers to each
  other when a session is set up; it adds no per-packet integrity.

What rist-rs does with a key: a receiver drops every unencrypted packet
except EAPOL (which SRP needs) and counts it in `clear_packets_dropped`;
encrypted packets that fail the checks count in `decrypt_rejected`, packets
of a shut-out nonce in `decrypt_latched` (receiver and sender stats). An
endpoint with a key sends nothing clear but EAPOL: given only a receive key
it encrypts with the same passphrase, and given only a transmit key it also
drops clear packets from its peer. Where integrity
matters, carry RIST over an authenticated transport such as WireGuard or
IPsec.

### Needletail Readiness

Needletail uses Main-profile IPv4 unicast from a caller to a local listener.
Media uses 1,316-byte MPEG-TS payloads and flow ID `0x11223344`.

- ✅ Main caller-to-listener data and control interoperate with current librist.
- ✅ Dynamic librist media flows receive scheduled NACKs, and retry SSRC markers preserve recovery state.
- ✅ Bounded recovery supports Needletail's buffer, bandwidth, RTT, reorder, retry, and congestion controls.
- ✅ Socket buffers, backpressure, exact recovery bytes, and truncated-datagram handling are ready.
- ✅ `av-contrib` production ingest selects the pure Rust receiver.
- ✅ `rist-loss-proxy` injects deterministic first-send loss and measures successful recovery.
- ❌ Live 4K, sustained-loss, recovery, CPU, memory, and continuity qualification remains.

One product-level qualification gate remains before Needletail can use pure RIST in production.

### Loss Qualification

Build the release proxy:

```sh
cargo build --release -p rist-tools --bin rist-loss-proxy
```

Put the proxy between the RIST sender and receiver:

```sh
target/release/rist-loss-proxy \
  --listen 127.0.0.1:27010 \
  --target 127.0.0.1:27000 \
  --drop-every 100 \
  --duration-seconds 600
```

Send the source to port `27010`.
The proxy emits NDJSON statistics once per second.
It exits with status 1 when an injected loss has no observed retransmission.

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
rist = { version = "0.1", features = ["tokio"] }
```

### Async Example

```rust
use rist::tokio::{AsyncReceiver, AsyncSender};
use rist::Profile;

// Receiver
let mut receiver = AsyncReceiver::bind(Profile::Main, "rist://@:5000")?;
while let Some(data) = receiver.recv().await? {
    println!("received {} bytes", data.payload().len());
}

// Sender
let sender = AsyncSender::connect(Profile::Main, "rist://192.168.1.1:5000").await?;
sender.send(b"hello").await?;
```

### Stream API

The async types implement standard Tokio traits for stream-like usage:

```rust
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// Explicitly opt into an adapter that discards datagram boundaries.
let mut receiver = receiver.into_byte_stream();
let mut buf = vec![0u8; 1316];
let n = receiver.read(&mut buf).await?;

let mut sender = sender.into_byte_stream();
sender.write_all(b"data").await?;
```

### Configuration Options

```rust
use rist::{ReceiverOptions, SenderOptions, RecoveryMode};
use std::time::Duration;

let recv_opts = ReceiverOptions::new()
    .recovery_mode(RecoveryMode::Time)
    .recovery_length_min(Duration::from_millis(50))
    .recovery_length_max(Duration::from_millis(500))
    .fifo_size(4096);

let send_opts = SenderOptions::new()
    .recovery_length_max(Duration::from_millis(1000));
```

### Stats

```rust
// Receiver stats
if let Some(stats) = receiver.raw_stats() {
    println!("quality: {:.1}%, rtt: {}ms, received: {}",
        stats.quality, stats.rtt, stats.received);
}

// Sender stats
if let Some(stats) = sender.raw_stats() {
    println!("quality: {:.1}%, rtt: {}ms, retransmitted: {}",
        stats.quality, stats.rtt, stats.retransmitted);
}
```

## Examples

Protocol-level sender and receiver examples live with the `rist` crate.

```sh
cargo run -p wavey-rist --example receiver --features tokio
cargo run -p wavey-rist --example sender --features tokio
```

Application examples that combine RIST with browser playback or other services
belong in the consuming service repositories, not in this protocol crate.

## API Comparison with SRT

This library follows the same patterns as [sportsball-ai/av-rs](https://github.com/sportsball-ai/av-rs/tree/main/srt) SRT bindings for API consistency:

| Feature | SRT | RIST |
|---------|-----|------|
| Direction | Bidirectional (`AsyncStream`) | Unidirectional (`AsyncSender` / `AsyncReceiver`) |
| AsyncRead | `AsyncStream` | `AsyncReceiver` |
| AsyncWrite | `AsyncStream` | `AsyncSender` |
| Stats | `raw_stats()` | `raw_stats()` |
| Options | `ConnectOptions` / `ListenerOptions` | `SenderOptions` / `ReceiverOptions` |
| Connect | `Connect` future | `Connect` future |

## Requirements

- librist 0.2.20 or later (`pkg-config` must find it)
- Rust 1.74+

## License

MIT
