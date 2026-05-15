(() => {
  "use strict";

  const CHANNEL_NAME = "rist-browser-tab-stream-v1";
  const DEFAULT_ROOM = "rist-demo";
  const MAX_SEND_WIDTH = 960;
  const MAX_SEND_HEIGHT = 540;
  const STALE_AFTER_MS = 1500;

  const $ = (id) => document.getElementById(id);

  const els = {
    roomInput: $("roomInput"),
    senderRole: $("senderRole"),
    receiverRole: $("receiverRole"),
    senderPanel: $("senderPanel"),
    receiverPanel: $("receiverPanel"),
    sourceVideo: $("sourceVideo"),
    senderCanvas: $("senderCanvas"),
    receiverCanvas: $("receiverCanvas"),
    cameraButton: $("cameraButton"),
    fileButton: $("fileButton"),
    fileInput: $("fileInput"),
    startButton: $("startButton"),
    stopButton: $("stopButton"),
    fpsSelect: $("fpsSelect"),
    qualityInput: $("qualityInput"),
    senderStatus: $("senderStatus"),
    senderBadge: $("senderBadge"),
    receiverStatus: $("receiverStatus"),
    receiverBadge: $("receiverBadge"),
    sentFrames: $("sentFrames"),
    sendFps: $("sendFps"),
    sendBitrate: $("sendBitrate"),
    remoteLatency: $("remoteLatency"),
    latencyNow: $("latencyNow"),
    latencyAvg: $("latencyAvg"),
    latencyMinMax: $("latencyMinMax"),
    receiveFps: $("receiveFps"),
    receivedFrames: $("receivedFrames"),
    droppedFrames: $("droppedFrames"),
  };

  const state = {
    channel: null,
    clientId: randomId(),
    role: "sender",
    room: DEFAULT_ROOM,
    sourceMode: "camera",
    selectedFile: null,
    fileUrl: null,
    stream: null,
    sending: false,
    captureRaf: 0,
    lastCaptureAt: 0,
    encoding: false,
    preferredMime: supportsWebp() ? "image/webp" : "image/jpeg",
    frameId: 0,
    sentFrames: 0,
    sendTimes: [],
    byteSamples: [],
    remoteLatencyMs: null,
    decoding: false,
    receivedFrames: 0,
    droppedFrames: 0,
    receiveTimes: [],
    latencies: [],
    lastFrameAt: 0,
    lastStatsAt: 0,
  };

  function init() {
    hydrateFromUrl();
    state.room = normalizeRoom(els.roomInput.value);
    els.roomInput.value = state.room;

    if (!("BroadcastChannel" in window)) {
      setSenderStatus("BroadcastChannel unavailable", "bad", "blocked");
      setReceiverStatus("BroadcastChannel unavailable", "bad", "blocked");
      setControlsEnabled(false);
      return;
    }

    state.channel = new BroadcastChannel(CHANNEL_NAME);
    state.channel.onmessage = onMessage;

    bindEvents();
    setRole(state.role);
    markSourceMode("camera");
    paintIdleCanvas(els.senderCanvas, "source");
    paintIdleCanvas(els.receiverCanvas, "receiver");
    updateSenderStats();
    updateReceiverStats();

    window.setInterval(tickStats, 250);
    window.addEventListener("beforeunload", stopSending);
  }

  function bindEvents() {
    els.senderRole.addEventListener("click", () => setRole("sender"));
    els.receiverRole.addEventListener("click", () => setRole("receiver"));
    els.roomInput.addEventListener("change", () => {
      state.room = normalizeRoom(els.roomInput.value);
      els.roomInput.value = state.room;
      resetReceiverStats();
      persistUrl();
    });

    els.cameraButton.addEventListener("click", () => {
      markSourceMode("camera");
      if (state.sending) {
        startCameraSource();
      }
    });

    els.fileButton.addEventListener("click", () => {
      markSourceMode("file");
      els.fileInput.click();
    });

    els.fileInput.addEventListener("change", () => {
      const file = els.fileInput.files && els.fileInput.files[0];
      if (!file) {
        return;
      }
      state.selectedFile = file;
      markSourceMode("file");
      if (state.sending) {
        startFileSource();
      } else {
        setSenderStatus(file.name, "idle", "file");
      }
    });

    els.startButton.addEventListener("click", () => {
      if (state.sourceMode === "file") {
        startFileSource();
      } else {
        startCameraSource();
      }
    });

    els.stopButton.addEventListener("click", stopSending);
  }

  function hydrateFromUrl() {
    const params = new URLSearchParams(window.location.search);
    const room = params.get("room");
    const role = params.get("role");
    if (room) {
      els.roomInput.value = normalizeRoom(room);
    }
    if (role === "receiver" || role === "sender") {
      state.role = role;
    }
  }

  function persistUrl() {
    const url = new URL(window.location.href);
    url.searchParams.set("role", state.role);
    url.searchParams.set("room", normalizeRoom(els.roomInput.value));
    window.history.replaceState(null, "", url);
  }

  function setRole(role) {
    state.role = role;
    const isSender = role === "sender";
    els.senderRole.classList.toggle("active", isSender);
    els.receiverRole.classList.toggle("active", !isSender);
    els.senderRole.setAttribute("aria-pressed", String(isSender));
    els.receiverRole.setAttribute("aria-pressed", String(!isSender));
    els.senderPanel.classList.toggle("hidden", !isSender);
    els.receiverPanel.classList.toggle("hidden", isSender);
    if (!isSender) {
      stopSending();
      resetReceiverStats();
    }
    persistUrl();
  }

  function markSourceMode(mode) {
    state.sourceMode = mode;
    els.cameraButton.classList.toggle("secondary", mode !== "camera");
    els.fileButton.classList.toggle("secondary", mode !== "file");
  }

  async function startCameraSource() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      setSenderStatus("Camera unavailable", "bad", "blocked");
      return;
    }

    markSourceMode("camera");
    prepareSourceStart();
    setSenderStatus("Requesting camera", "idle", "camera");

    try {
      state.stream = await navigator.mediaDevices.getUserMedia({
        audio: false,
        video: {
          width: { ideal: 1280 },
          height: { ideal: 720 },
          frameRate: { ideal: 30 },
        },
      });
      els.sourceVideo.srcObject = state.stream;
      els.sourceVideo.loop = false;
      await playSourceVideo();
      beginSending();
    } catch (error) {
      els.startButton.disabled = false;
      els.stopButton.disabled = true;
      setSenderStatus(readableError(error), "bad", "blocked");
    }
  }

  async function startFileSource() {
    markSourceMode("file");
    if (!state.selectedFile) {
      setSenderStatus("Select a video file", "idle", "file");
      els.fileInput.click();
      return;
    }

    prepareSourceStart();
    if (state.fileUrl) {
      URL.revokeObjectURL(state.fileUrl);
    }
    state.fileUrl = URL.createObjectURL(state.selectedFile);
    els.sourceVideo.srcObject = null;
    els.sourceVideo.src = state.fileUrl;
    els.sourceVideo.loop = true;
    els.sourceVideo.muted = true;

    try {
      await playSourceVideo();
      beginSending();
    } catch (error) {
      els.startButton.disabled = false;
      els.stopButton.disabled = true;
      setSenderStatus(readableError(error), "bad", "blocked");
    }
  }

  async function playSourceVideo() {
    els.sourceVideo.muted = true;
    els.sourceVideo.playsInline = true;
    await els.sourceVideo.play();
    if (!els.sourceVideo.videoWidth) {
      await once(els.sourceVideo, "loadedmetadata");
    }
    resizeSendCanvas();
  }

  function beginSending() {
    state.sending = true;
    state.lastCaptureAt = 0;
    state.encoding = false;
    state.frameId = 0;
    state.sentFrames = 0;
    state.sendTimes = [];
    state.byteSamples = [];
    els.startButton.disabled = true;
    els.stopButton.disabled = false;
    setSenderStatus("Streaming", "good", "live");
    window.cancelAnimationFrame(state.captureRaf);
    state.captureRaf = window.requestAnimationFrame(captureLoop);
    updateSenderStats();
  }

  function prepareSourceStart() {
    state.sending = false;
    window.cancelAnimationFrame(state.captureRaf);
    state.captureRaf = 0;
    els.startButton.disabled = true;
    els.stopButton.disabled = true;
    stopSourceOnly();
  }

  function stopSending() {
    state.sending = false;
    window.cancelAnimationFrame(state.captureRaf);
    state.captureRaf = 0;
    stopSourceOnly();
    els.startButton.disabled = false;
    els.stopButton.disabled = true;
    setSenderStatus("Stopped", "idle", "idle");
  }

  function stopSourceOnly() {
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
    els.sourceVideo.pause();
    els.sourceVideo.removeAttribute("src");
    els.sourceVideo.srcObject = null;
    els.sourceVideo.load();
    paintIdleCanvas(els.senderCanvas, "source");
  }

  function captureLoop(now) {
    if (!state.sending) {
      return;
    }

    const targetFps = Number(els.fpsSelect.value) || 15;
    const frameGap = 1000 / targetFps;
    if (now - state.lastCaptureAt >= frameGap && !state.encoding && canDrawSource()) {
      state.lastCaptureAt = now;
      encodeAndSendFrame();
    }

    state.captureRaf = window.requestAnimationFrame(captureLoop);
  }

  async function encodeAndSendFrame() {
    state.encoding = true;
    const canvas = els.senderCanvas;
    const ctx = canvas.getContext("2d", { alpha: false });
    const capturedAtMs = nowEpochMs();
    drawVideoContain(ctx, els.sourceVideo, canvas);

    try {
      const quality = Number(els.qualityInput.value) / 100;
      const blob = await canvasToBlob(canvas, state.preferredMime, quality);
      if (!blob || !state.sending || !state.channel) {
        return;
      }

      const frame = {
        type: "frame",
        room: room(),
        senderId: state.clientId,
        frameId: ++state.frameId,
        sentAtMs: capturedAtMs,
        width: canvas.width,
        height: canvas.height,
        mime: blob.type || state.preferredMime,
        blob,
      };
      state.channel.postMessage(frame);
      noteSentFrame(blob.size);
    } catch (error) {
      setSenderStatus(readableError(error), "bad", "error");
    } finally {
      state.encoding = false;
    }
  }

  function onMessage(event) {
    const message = event.data;
    if (!message || message.senderId === state.clientId || message.room !== room()) {
      return;
    }

    if (message.type === "frame") {
      if (state.role === "receiver") {
        handleFrame(message);
      }
      return;
    }

    if (message.type === "receiver-stats" && state.role === "sender") {
      state.remoteLatencyMs = message.latencyMs;
      updateSenderStats();
    }
  }

  async function handleFrame(message) {
    if (state.decoding) {
      state.droppedFrames += 1;
      updateReceiverStats();
      return;
    }

    state.decoding = true;
    try {
      const bitmap = await createImageBitmap(message.blob);
      if (els.receiverCanvas.width !== message.width || els.receiverCanvas.height !== message.height) {
        els.receiverCanvas.width = message.width;
        els.receiverCanvas.height = message.height;
      }
      const ctx = els.receiverCanvas.getContext("2d", { alpha: false });
      ctx.drawImage(bitmap, 0, 0, els.receiverCanvas.width, els.receiverCanvas.height);
      if (typeof bitmap.close === "function") {
        bitmap.close();
      }

      const latencyMs = Math.max(0, nowEpochMs() - message.sentAtMs);
      noteReceivedFrame(latencyMs);
      sendReceiverStats(message.frameId, latencyMs);
      setReceiverStatus("Receiving", "good", "live");
      updateReceiverStats();
    } catch (error) {
      state.droppedFrames += 1;
      setReceiverStatus(readableError(error), "bad", "error");
      updateReceiverStats();
    } finally {
      state.decoding = false;
    }
  }

  function sendReceiverStats(frameId, latencyMs) {
    const now = performance.now();
    if (!state.channel || now - state.lastStatsAt < 200) {
      return;
    }
    state.lastStatsAt = now;
    state.channel.postMessage({
      type: "receiver-stats",
      room: room(),
      senderId: state.clientId,
      frameId,
      latencyMs,
      avgLatencyMs: average(state.latencies),
      fps: framesPerSecond(state.receiveTimes),
    });
  }

  function noteSentFrame(bytes) {
    const now = performance.now();
    state.sentFrames += 1;
    state.sendTimes.push(now);
    state.byteSamples.push({ at: now, bytes });
    pruneWindow(state.sendTimes, now, 1000);
    while (state.byteSamples.length && now - state.byteSamples[0].at > 1000) {
      state.byteSamples.shift();
    }
    updateSenderStats();
  }

  function noteReceivedFrame(latencyMs) {
    const now = performance.now();
    state.receivedFrames += 1;
    state.lastFrameAt = now;
    state.receiveTimes.push(now);
    state.latencies.push(latencyMs);
    pruneWindow(state.receiveTimes, now, 1000);
    if (state.latencies.length > 240) {
      state.latencies.shift();
    }
  }

  function tickStats() {
    updateSenderStats();
    updateReceiverStats();
    if (state.role === "receiver") {
      if (!state.lastFrameAt) {
        setReceiverStatus("Waiting", "idle", "idle");
      } else if (performance.now() - state.lastFrameAt > STALE_AFTER_MS) {
        setReceiverStatus("No recent frames", "warn", "stale");
      }
    }
  }

  function updateSenderStats() {
    els.sentFrames.textContent = String(state.sentFrames);
    els.sendFps.textContent = formatNumber(framesPerSecond(state.sendTimes), 1);
    els.sendBitrate.textContent = formatBitrate(bytesPerSecond());
    els.remoteLatency.textContent =
      state.remoteLatencyMs === null ? "n/a" : `${formatNumber(state.remoteLatencyMs, 1)} ms`;
  }

  function updateReceiverStats() {
    const current = state.latencies.length ? state.latencies[state.latencies.length - 1] : null;
    const avg = average(state.latencies);
    const min = state.latencies.length ? Math.min(...state.latencies) : null;
    const max = state.latencies.length ? Math.max(...state.latencies) : null;

    els.latencyNow.textContent = current === null ? "n/a" : `${formatNumber(current, 1)} ms`;
    els.latencyAvg.textContent = avg === null ? "n/a" : `${formatNumber(avg, 1)} ms`;
    els.latencyMinMax.textContent =
      min === null || max === null ? "n/a" : `${formatNumber(min, 1)} / ${formatNumber(max, 1)} ms`;
    els.receiveFps.textContent = formatNumber(framesPerSecond(state.receiveTimes), 1);
    els.receivedFrames.textContent = String(state.receivedFrames);
    els.droppedFrames.textContent = String(state.droppedFrames);
  }

  function resetReceiverStats() {
    state.receivedFrames = 0;
    state.droppedFrames = 0;
    state.receiveTimes = [];
    state.latencies = [];
    state.lastFrameAt = 0;
    paintIdleCanvas(els.receiverCanvas, "receiver");
    setReceiverStatus("Waiting", "idle", "idle");
    updateReceiverStats();
  }

  function resizeSendCanvas() {
    const video = els.sourceVideo;
    const sourceWidth = video.videoWidth || MAX_SEND_WIDTH;
    const sourceHeight = video.videoHeight || MAX_SEND_HEIGHT;
    const scale = Math.min(MAX_SEND_WIDTH / sourceWidth, MAX_SEND_HEIGHT / sourceHeight, 1);
    const width = Math.max(2, Math.round(sourceWidth * scale));
    const height = Math.max(2, Math.round(sourceHeight * scale));
    els.senderCanvas.width = width % 2 === 0 ? width : width + 1;
    els.senderCanvas.height = height % 2 === 0 ? height : height + 1;
  }

  function drawVideoContain(ctx, video, canvas) {
    const videoWidth = video.videoWidth || 16;
    const videoHeight = video.videoHeight || 9;
    const scale = Math.min(canvas.width / videoWidth, canvas.height / videoHeight);
    const width = Math.round(videoWidth * scale);
    const height = Math.round(videoHeight * scale);
    const x = Math.round((canvas.width - width) / 2);
    const y = Math.round((canvas.height - height) / 2);
    ctx.fillStyle = "#101513";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.drawImage(video, x, y, width, height);
  }

  function paintIdleCanvas(canvas, label) {
    const ctx = canvas.getContext("2d", { alpha: false });
    ctx.fillStyle = "#101513";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = "#87928e";
    ctx.font = "600 18px system-ui, sans-serif";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText(label, canvas.width / 2, canvas.height / 2);
  }

  function canDrawSource() {
    return els.sourceVideo.readyState >= HTMLMediaElement.HAVE_CURRENT_DATA && !els.sourceVideo.paused;
  }

  function canvasToBlob(canvas, mime, quality) {
    return new Promise((resolve) => {
      canvas.toBlob(resolve, mime, quality);
    });
  }

  function once(target, eventName) {
    return new Promise((resolve) => {
      target.addEventListener(eventName, resolve, { once: true });
    });
  }

  function nowEpochMs() {
    return performance.timeOrigin + performance.now();
  }

  function room() {
    return normalizeRoom(els.roomInput.value);
  }

  function normalizeRoom(value) {
    const trimmed = String(value || "").trim();
    return trimmed || DEFAULT_ROOM;
  }

  function setSenderStatus(text, tone, badge) {
    els.senderStatus.textContent = text;
    setBadge(els.senderBadge, tone, badge);
  }

  function setReceiverStatus(text, tone, badge) {
    els.receiverStatus.textContent = text;
    setBadge(els.receiverBadge, tone, badge);
  }

  function setBadge(element, tone, text) {
    element.textContent = text;
    element.classList.remove("good", "warn", "bad");
    if (tone === "good" || tone === "warn" || tone === "bad") {
      element.classList.add(tone);
    }
  }

  function setControlsEnabled(enabled) {
    const controls = [
      els.senderRole,
      els.receiverRole,
      els.cameraButton,
      els.fileButton,
      els.startButton,
      els.stopButton,
      els.fpsSelect,
      els.qualityInput,
    ];
    for (const control of controls) {
      control.disabled = !enabled;
    }
  }

  function framesPerSecond(samples) {
    pruneWindow(samples, performance.now(), 1000);
    return samples.length;
  }

  function bytesPerSecond() {
    const now = performance.now();
    while (state.byteSamples.length && now - state.byteSamples[0].at > 1000) {
      state.byteSamples.shift();
    }
    return state.byteSamples.reduce((total, sample) => total + sample.bytes, 0);
  }

  function pruneWindow(samples, now, windowMs) {
    while (samples.length && now - samples[0] > windowMs) {
      samples.shift();
    }
  }

  function average(values) {
    if (!values.length) {
      return null;
    }
    return values.reduce((total, value) => total + value, 0) / values.length;
  }

  function formatNumber(value, digits) {
    if (value === null || Number.isNaN(value)) {
      return "n/a";
    }
    return Number(value).toFixed(digits);
  }

  function formatBitrate(bytesPerSecondValue) {
    const bits = bytesPerSecondValue * 8;
    if (bits >= 1_000_000) {
      return `${formatNumber(bits / 1_000_000, 2)} Mbps`;
    }
    if (bits >= 1_000) {
      return `${formatNumber(bits / 1_000, 1)} kbps`;
    }
    return `${Math.round(bits)} bps`;
  }

  function readableError(error) {
    if (!error) {
      return "Unknown error";
    }
    if (error.name === "NotAllowedError") {
      return "Camera permission denied";
    }
    return error.message || String(error);
  }

  function supportsWebp() {
    const canvas = document.createElement("canvas");
    canvas.width = 1;
    canvas.height = 1;
    return canvas.toDataURL("image/webp").startsWith("data:image/webp");
  }

  function randomId() {
    if (window.crypto && typeof window.crypto.randomUUID === "function") {
      return window.crypto.randomUUID();
    }
    return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
  }

  init();
})();
