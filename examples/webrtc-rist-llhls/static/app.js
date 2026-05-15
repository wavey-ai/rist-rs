(() => {
  "use strict";

  const DATA_MAGIC = "WRDC";
  const HEADER_BYTES = 27;
  const MAX_BUFFERED_BYTES = 8 * 1024 * 1024;
  const MIME_CANDIDATES = [
    'video/mp4;codecs="avc1.42E01E,mp4a.40.2"',
    "video/mp4",
    'video/webm;codecs="vp9,opus"',
    'video/webm;codecs="vp8,opus"',
    "video/webm",
  ];

  const $ = (id) => document.getElementById(id);
  const els = {
    senderLink: $("senderLink"),
    receiverLink: $("receiverLink"),
    subtitle: $("subtitle"),
    senderView: $("senderView"),
    receiverView: $("receiverView"),
    previewVideo: $("previewVideo"),
    senderStatus: $("senderStatus"),
    senderBadge: $("senderBadge"),
    receiverStatus: $("receiverStatus"),
    receiverBadge: $("receiverBadge"),
    cameraButton: $("cameraButton"),
    fileButton: $("fileButton"),
    fileInput: $("fileInput"),
    connectButton: $("connectButton"),
    startButton: $("startButton"),
    stopButton: $("stopButton"),
    cadenceInput: $("cadenceInput"),
    bitrateInput: $("bitrateInput"),
    webrtcState: $("webrtcState"),
    channelState: $("channelState"),
    chunksSent: $("chunksSent"),
    sendRate: $("sendRate"),
    recorderMime: $("recorderMime"),
    hlsVideo: $("hlsVideo"),
    loadHlsButton: $("loadHlsButton"),
    partsReceived: $("partsReceived"),
    bytesReceived: $("bytesReceived"),
    latestSequence: $("latestSequence"),
    ristLatency: $("ristLatency"),
    glassLatency: $("glassLatency"),
    playlistMime: $("playlistMime"),
  };

  const state = {
    role: location.pathname.includes("receiver") ? "receiver" : "sender",
    pc: null,
    ws: null,
    channel: null,
    sourceMode: "camera",
    stream: null,
    fileUrl: null,
    recorder: null,
    mime: "",
    seq: 0,
    chunksSent: 0,
    byteSamples: [],
  };

  function init() {
    applyRole();
    bindEvents();
    updateSenderStats();
    if (state.role === "receiver") {
      loadHls();
      setInterval(refreshReceiverStats, 500);
    }
    setInterval(updateSenderStats, 250);
    window.addEventListener("beforeunload", cleanup);
  }

  function applyRole() {
    const sender = state.role === "sender";
    els.senderView.classList.toggle("hidden", !sender);
    els.receiverView.classList.toggle("hidden", sender);
    els.senderLink.classList.toggle("active", sender);
    els.receiverLink.classList.toggle("active", !sender);
    els.subtitle.textContent = sender
      ? "Send camera or file chunks over WebRTC into a pure Rust RIST relay."
      : "Receive the relayed media through the LL-HLS endpoint.";
  }

  function bindEvents() {
    els.cameraButton.addEventListener("click", () => {
      state.sourceMode = "camera";
      setSenderStatus("Camera selected", "idle");
    });
    els.fileButton.addEventListener("click", () => {
      state.sourceMode = "file";
      els.fileInput.click();
    });
    els.fileInput.addEventListener("change", () => {
      state.sourceMode = "file";
      const file = els.fileInput.files && els.fileInput.files[0];
      setSenderStatus(file ? file.name : "File selected", "idle");
    });
    els.connectButton.addEventListener("click", connectWebRtc);
    els.startButton.addEventListener("click", startRecording);
    els.stopButton.addEventListener("click", stopRecording);
    els.loadHlsButton.addEventListener("click", loadHls);
  }

  async function connectWebRtc() {
    cleanupPeer();
    setSenderStatus("Connecting WebRTC", "idle");
    els.connectButton.disabled = true;

    const pc = new RTCPeerConnection({ iceServers: [] });
    const channel = pc.createDataChannel("media", { ordered: true });
    const ws = new WebSocket(signalingUrl());

    state.pc = pc;
    state.channel = channel;
    state.ws = ws;

    pc.onconnectionstatechange = () => {
      els.webrtcState.textContent = pc.connectionState;
      if (pc.connectionState === "connected") {
        setSenderStatus("WebRTC connected", "good");
      }
    };
    channel.onopen = () => {
      els.channelState.textContent = "open";
      els.startButton.disabled = false;
      setSenderStatus("Data channel open", "good");
    };
    channel.onclose = () => {
      els.channelState.textContent = "closed";
      els.startButton.disabled = true;
    };
    channel.onerror = () => setSenderStatus("Data channel error", "bad");

    await once(ws, "open");
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    await waitForIceGathering(pc);

    ws.send(JSON.stringify({ type: "offer", sdp: pc.localDescription }));
    ws.onmessage = async (event) => {
      const message = JSON.parse(event.data);
      if (message.type === "answer") {
        await pc.setRemoteDescription(message.sdp);
      } else if (message.type === "error") {
        setSenderStatus(message.message || "Signaling error", "bad");
      }
    };
  }

  async function startRecording() {
    if (!state.channel || state.channel.readyState !== "open") {
      setSenderStatus("Connect WebRTC first", "warn");
      return;
    }

    stopRecording();
    state.stream = state.sourceMode === "file" ? await fileStream() : await cameraStream();
    els.previewVideo.srcObject = state.stream;
    els.previewVideo.muted = true;
    els.previewVideo.playsInline = true;
    await els.previewVideo.play();

    state.mime = selectMime();
    const options = {
      videoBitsPerSecond: Number(els.bitrateInput.value) || 1_600_000,
    };
    if (state.mime) {
      options.mimeType = state.mime;
    }

    state.recorder = new MediaRecorder(state.stream, options);
    state.mime = state.recorder.mimeType || state.mime || "application/octet-stream";
    state.seq = 0;
    state.chunksSent = 0;
    state.byteSamples = [];
    els.recorderMime.textContent = state.mime;

    state.recorder.ondataavailable = sendBlob;
    state.recorder.onerror = () => setSenderStatus("Recorder error", "bad");
    state.recorder.start(Number(els.cadenceInput.value) || 500);

    els.startButton.disabled = true;
    els.stopButton.disabled = false;
    setSenderStatus("Recording", "good");
  }

  async function sendBlob(event) {
    if (!event.data || !event.data.size || !state.channel || state.channel.readyState !== "open") {
      return;
    }
    if (state.channel.bufferedAmount > MAX_BUFFERED_BYTES) {
      setSenderStatus("Backpressure", "warn");
      return;
    }

    const payload = await event.data.arrayBuffer();
    const packet = packChunk(state.seq++, Date.now(), state.mime, payload);
    state.channel.send(packet);
    state.chunksSent += 1;
    state.byteSamples.push({ at: performance.now(), bytes: packet.byteLength });
    updateSenderStats();
  }

  async function cameraStream() {
    return navigator.mediaDevices.getUserMedia({
      audio: true,
      video: { width: { ideal: 1280 }, height: { ideal: 720 }, frameRate: { ideal: 30 } },
    });
  }

  async function fileStream() {
    const file = els.fileInput.files && els.fileInput.files[0];
    if (!file) {
      els.fileInput.click();
      throw new Error("Select a video file");
    }
    if (state.fileUrl) {
      URL.revokeObjectURL(state.fileUrl);
    }
    state.fileUrl = URL.createObjectURL(file);
    els.previewVideo.srcObject = null;
    els.previewVideo.src = state.fileUrl;
    els.previewVideo.loop = true;
    els.previewVideo.muted = true;
    await els.previewVideo.play();
    const capture = els.previewVideo.captureStream || els.previewVideo.mozCaptureStream;
    if (!capture) {
      throw new Error("Video captureStream is unavailable");
    }
    return capture.call(els.previewVideo);
  }

  function stopRecording() {
    if (state.recorder && state.recorder.state !== "inactive") {
      state.recorder.stop();
    }
    state.recorder = null;
    if (state.stream) {
      for (const track of state.stream.getTracks()) {
        track.stop();
      }
      state.stream = null;
    }
    if (state.fileUrl) {
      URL.revokeObjectURL(state.fileUrl);
      state.fileUrl = null;
    }
    els.startButton.disabled = !state.channel || state.channel.readyState !== "open";
    els.stopButton.disabled = true;
    if (state.role === "sender") {
      setSenderStatus("Stopped", "idle");
    }
  }

  function cleanup() {
    stopRecording();
    cleanupPeer();
  }

  function cleanupPeer() {
    if (state.ws) {
      state.ws.close();
    }
    if (state.pc) {
      state.pc.close();
    }
    state.ws = null;
    state.pc = null;
    state.channel = null;
    els.webrtcState.textContent = "new";
    els.channelState.textContent = "closed";
    els.connectButton.disabled = false;
  }

  function packChunk(seq, sentAtMs, mime, payload) {
    const encoder = new TextEncoder();
    const mimeBytes = encoder.encode(mime || "application/octet-stream");
    const out = new ArrayBuffer(HEADER_BYTES + mimeBytes.length + payload.byteLength);
    const view = new DataView(out);
    for (let index = 0; index < DATA_MAGIC.length; index += 1) {
      view.setUint8(index, DATA_MAGIC.charCodeAt(index));
    }
    let offset = 4;
    view.setUint8(offset, 1);
    offset += 1;
    view.setUint16(offset, mimeBytes.length, false);
    offset += 2;
    view.setBigUint64(offset, BigInt(seq), false);
    offset += 8;
    view.setFloat64(offset, sentAtMs, false);
    offset += 8;
    view.setUint32(offset, payload.byteLength, false);
    offset += 4;
    new Uint8Array(out, offset, mimeBytes.length).set(mimeBytes);
    offset += mimeBytes.length;
    new Uint8Array(out, offset).set(new Uint8Array(payload));
    return out;
  }

  function selectMime() {
    if (!window.MediaRecorder) {
      throw new Error("MediaRecorder is unavailable");
    }
    return MIME_CANDIDATES.find((mime) => MediaRecorder.isTypeSupported(mime)) || "";
  }

  function signalingUrl() {
    const scheme = location.protocol === "https:" ? "wss" : "ws";
    return `${scheme}://${location.host}/signal`;
  }

  function waitForIceGathering(pc) {
    if (pc.iceGatheringState === "complete") {
      return Promise.resolve();
    }
    return new Promise((resolve) => {
      const done = () => {
        if (pc.iceGatheringState === "complete") {
          pc.removeEventListener("icegatheringstatechange", done);
          resolve();
        }
      };
      pc.addEventListener("icegatheringstatechange", done);
      setTimeout(resolve, 3000);
    });
  }

  function loadHls() {
    const playlist = `/hls/live.m3u8?cache=${Date.now()}`;
    if (els.hlsVideo.canPlayType("application/vnd.apple.mpegurl")) {
      els.hlsVideo.src = playlist;
      els.hlsVideo.play().catch(() => {});
      setReceiverStatus("Native HLS loaded", "good");
    } else {
      setReceiverStatus("Native HLS unavailable; polling stats", "warn");
    }
    refreshReceiverStats();
  }

  async function refreshReceiverStats() {
    try {
      const response = await fetch(`/api/stats?cache=${Date.now()}`, { cache: "no-store" });
      const stats = await response.json();
      els.partsReceived.textContent = String(stats.parts_received || 0);
      els.bytesReceived.textContent = formatBytes(stats.bytes_received || 0);
      els.latestSequence.textContent =
        stats.latest_sequence === null || stats.latest_sequence === undefined
          ? "n/a"
          : String(stats.latest_sequence);
      els.playlistMime.textContent = stats.mime || "n/a";
      els.ristLatency.textContent =
        stats.rist_latency_ms === null || stats.rist_latency_ms === undefined
          ? "n/a"
          : `${stats.rist_latency_ms.toFixed(1)} ms`;
      els.glassLatency.textContent = stats.last_sent_at_ms
        ? `${Math.max(0, Date.now() - stats.last_sent_at_ms).toFixed(1)} ms`
        : "n/a";
      if (stats.parts_received > 0) {
        setReceiverStatus("Receiving LL-HLS parts", "good");
      }
    } catch {
      setReceiverStatus("Stats unavailable", "bad");
    }
  }

  function updateSenderStats() {
    els.chunksSent.textContent = String(state.chunksSent);
    els.sendRate.textContent = formatBitrate(bytesPerSecond());
    if (state.pc) {
      els.webrtcState.textContent = state.pc.connectionState;
    }
    if (state.channel) {
      els.channelState.textContent = state.channel.readyState;
    }
  }

  function bytesPerSecond() {
    const now = performance.now();
    while (state.byteSamples.length && now - state.byteSamples[0].at > 1000) {
      state.byteSamples.shift();
    }
    return state.byteSamples.reduce((total, sample) => total + sample.bytes, 0);
  }

  function setSenderStatus(text, tone) {
    els.senderStatus.textContent = text;
    setBadge(els.senderBadge, text, tone);
  }

  function setReceiverStatus(text, tone) {
    els.receiverStatus.textContent = text;
    setBadge(els.receiverBadge, tone === "good" ? "live" : text.split(" ")[0].toLowerCase(), tone);
  }

  function setBadge(el, text, tone) {
    el.textContent = tone === "good" ? "live" : tone === "bad" ? "error" : tone === "warn" ? "warn" : "idle";
    if (text === "live") {
      el.textContent = text;
    }
    el.classList.remove("good", "warn", "bad");
    if (tone === "good" || tone === "warn" || tone === "bad") {
      el.classList.add(tone);
    }
  }

  function once(target, name) {
    return new Promise((resolve) => target.addEventListener(name, resolve, { once: true }));
  }

  function formatBitrate(bytesPerSecondValue) {
    const bits = bytesPerSecondValue * 8;
    if (bits >= 1_000_000) {
      return `${(bits / 1_000_000).toFixed(2)} Mbps`;
    }
    if (bits >= 1_000) {
      return `${(bits / 1_000).toFixed(1)} kbps`;
    }
    return `${Math.round(bits)} bps`;
  }

  function formatBytes(bytes) {
    if (bytes >= 1_000_000) {
      return `${(bytes / 1_000_000).toFixed(2)} MB`;
    }
    if (bytes >= 1_000) {
      return `${(bytes / 1_000).toFixed(1)} KB`;
    }
    return `${bytes} B`;
  }

  init();
})();

