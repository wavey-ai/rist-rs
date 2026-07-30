# rist-rs

Pure Rust RIST protocol work plus the existing safe Rust bindings for
[librist](https://code.videolan.org/rist/librist).

RIST (Reliable Internet Stream Transport) is a protocol for reliable video streaming over lossy networks with low latency.

## Crates

- `rist-sys` - Raw FFI bindings generated via bindgen
- `rist-core` - Sans-I/O pure Rust protocol engine
- `rist-mio` - Nonblocking UDP transport for the pure Rust engine
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
- ✅ Bounded Simple and Main recovery, NACKs, retries, rollover, and backpressure
- ✅ Typed one-pass Main datagram dispatch with bounded queues
- ✅ Per-peer authentication, liveness, RTT, recovery, and feedback state
- ✅ Valid-traffic activity rules
- ✅ Authenticated NAT rebinding and restart reauthentication
- ✅ Simple RTP and RTCP even-odd port pairs
- ❌ All caller and listener combinations
  - Rust-to-Rust tests pass.
  - Current-C black-box tests still require correction.
- ❌ Complete IPv4 and IPv6 behavior
- ❌ ASM and SSM multicast behavior
- ❌ Socket buffers and truncated-datagram detection
- ❌ Allocation-free weighted multipath transmission
- ❌ Recovery priority and RTT route selection
- ❌ RTT muting, failure handling, trickle traffic, and rejoin behavior
- ❌ Split, merge, reflector, compression, and CBR behavior
- ❌ Complete per-peer configuration and statistics
- ❌ Advanced profile data, control, recovery, encryption, and negotiation
- ❌ Complete public API and URL-option parity
- ❌ Measured throughput, latency, memory, and recovery parity

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
