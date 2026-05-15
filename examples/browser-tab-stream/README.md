# Browser Tab Stream Demo

Static sender/receiver UI for testing video flow and glass-to-glass latency between two browser tabs.

Browsers cannot open UDP sockets or speak RIST directly from ordinary web pages, so this example uses `BroadcastChannel` as the tab-to-tab transport. It is useful for iterating on the UI, frame pacing, encoding quality, and latency display before wiring the same concepts to a native RIST bridge.

## Run

```sh
cd examples/browser-tab-stream
python3 -m http.server 8787 --bind 127.0.0.1
```

Open two tabs:

- Sender: `http://127.0.0.1:8787/?role=sender&room=rist-demo`
- Receiver: `http://127.0.0.1:8787/?role=receiver&room=rist-demo`

Pick the same room in both tabs. The sender can stream from the camera or from a local video file. The receiver draws each frame and reports latency from sender capture timestamp to receiver draw time.

Camera capture requires `localhost`, `127.0.0.1`, or HTTPS. Local video files work without camera permission.
