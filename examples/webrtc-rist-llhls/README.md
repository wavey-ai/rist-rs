# WebRTC to RIST to LL-HLS Example

This example is the browser-to-RIST shape:

1. A sender browser tab records camera or file input with `MediaRecorder`.
2. The browser sends encoded media chunks over a WebRTC data channel.
3. The Rust server terminates WebRTC, fragments chunks into pure Rust RIST payloads with `rist-mio`, and sends them to a local RIST receiver.
4. The receiver reconstructs chunks and exposes them as a low-latency HLS playlist.
5. A second browser tab opens the LL-HLS receiver page and reports RIST-to-HLS latency.

The HTTP/WebSocket surface is served by the `web-service` crate. The RIST leg is pure Rust and does not use librist.

## Run

From the `rist-rs` repo:

```sh
cargo run --manifest-path examples/webrtc-rist-llhls/Cargo.toml
```

Open:

- Sender: `https://127.0.0.1:9443/sender`
- Receiver: `https://127.0.0.1:9444/receiver`

The default TLS certificate is loaded from `../web-services/tls/local.wavey.ai` relative to this repo checkout. You can override it:

```sh
cargo run --manifest-path examples/webrtc-rist-llhls/Cargo.toml -- \
  --cert /path/to/fullchain.pem \
  --key /path/to/privkey.pem
```

## Notes

The LL-HLS endpoint serves the exact chunks produced by the browser recorder. Native playback depends on the browser producing HLS-compatible fragmented MP4. When the browser falls back to WebM, the receiver page still shows the live playlist and latency metrics, but native HLS playback may need a browser-side HLS/MSE adapter or a server-side transmux step.

The RIST receiver is intentionally a second logical server in the same process for local iteration. Split the sender and receiver tasks into separate binaries and point `--rist-peer` at the receiver machine to test across hosts.

