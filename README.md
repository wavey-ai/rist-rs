# rist-rs

Safe Rust bindings for [librist](https://code.videolan.org/rist/librist) (RIST protocol).

RIST (Reliable Internet Stream Transport) is a protocol for reliable video streaming over lossy networks with low latency.

## Crates

- `rist-sys` - Raw FFI bindings generated via bindgen
- `rist` - Safe Rust wrapper with sync and async APIs

## Features

- **Async Tokio support** - Enable with `tokio` feature
- **Stream-like API** - `AsyncReceiver` implements `AsyncRead`, `AsyncSender` implements `AsyncWrite`
- **Stats API** - Access connection statistics via `raw_stats()`
- **Configuration options** - Builder pattern for receiver/sender options

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

// AsyncReceiver implements AsyncRead
let mut buf = vec![0u8; 1316];
let n = receiver.read(&mut buf).await?;

// AsyncSender implements AsyncWrite
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

- librist 0.2+ installed (`pkg-config` must find it)
- Rust 1.70+

## License

MIT OR Apache-2.0
