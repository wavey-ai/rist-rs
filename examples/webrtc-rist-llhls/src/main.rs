use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use base64::Engine;
use bytes::Bytes;
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use http::{Request, StatusCode};
use rist_core::packet::rtcp::NackMode;
use rist_core::time::ntp_now;
use rist_core::ReceivedPayload;
use rist_mio::{MainMioReceiver, MainMioSender};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, RwLock};
use tokio::time::sleep;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, info, warn};
use web_service::{
    H2H3Server, HandlerResponse, HandlerResult, Router, Server, ServerBuilder, StreamWriter,
    WebSocketHandler, WebTransportHandler,
};
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

const INDEX_HTML: &str = include_str!("../static/index.html");
const APP_JS: &str = include_str!("../static/app.js");
const STYLES_CSS: &str = include_str!("../static/styles.css");

const FLOW_ID: u32 = 0x5752_484c;
const DATA_CHANNEL_MAGIC: &[u8; 4] = b"WRDC";
const RIST_CHUNK_MAGIC: &[u8; 4] = b"WRHL";
const DATA_CHANNEL_HEADER_LEN: usize = 27;
const RIST_HEADER_LEN: usize = 29;
const RIST_MAX_PAYLOAD: usize = 1200;
const HLS_WINDOW_PARTS: usize = 12;
const DEFAULT_PART_DURATION: f32 = 0.5;

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, default_value_t = 9443)]
    ingest_port: u16,
    #[arg(long, default_value_t = 9444)]
    hls_port: u16,
    #[arg(long, default_value = "127.0.0.1:7000")]
    rist_bind: SocketAddr,
    #[arg(long, default_value = "127.0.0.1:7000")]
    rist_peer: SocketAddr,
    #[arg(long)]
    cert: Option<PathBuf>,
    #[arg(long)]
    key: Option<PathBuf>,
}

#[derive(Clone)]
struct AppState {
    media_tx: mpsc::Sender<MediaChunk>,
    hls: Arc<RwLock<HlsStore>>,
}

#[derive(Clone, Copy)]
enum RouterRole {
    Ingest,
    Hls,
}

#[derive(Clone)]
struct ExampleRouter {
    state: Arc<AppState>,
    role: RouterRole,
}

#[derive(Debug)]
struct MediaChunk {
    seq: u64,
    sent_at_ms: u64,
    mime: String,
    data: Bytes,
}

#[derive(Clone, Debug)]
struct MediaPart {
    seq: u64,
    sent_at_ms: u64,
    received_at_ms: u64,
    mime: String,
    data: Bytes,
}

#[derive(Default)]
struct HlsStore {
    parts: VecDeque<MediaPart>,
    parts_received: u64,
    bytes_received: u64,
}

#[derive(Serialize)]
struct HlsStats {
    parts_received: u64,
    bytes_received: u64,
    latest_sequence: Option<u64>,
    last_sent_at_ms: Option<u64>,
    last_received_at_ms: Option<u64>,
    rist_latency_ms: Option<f64>,
    mime: Option<String>,
}

struct PendingChunk {
    sent_at_ms: u64,
    mime: String,
    fragments: Vec<Option<Bytes>>,
    received: usize,
}

struct RistFragment {
    seq: u64,
    sent_at_ms: u64,
    mime: String,
    index: usize,
    count: usize,
    payload: Bytes,
}

#[derive(Deserialize)]
struct SignalMessage {
    #[serde(rename = "type")]
    kind: String,
    sdp: Option<RTCSessionDescription>,
}

#[derive(Serialize)]
struct AnswerMessage {
    #[serde(rename = "type")]
    kind: &'static str,
    sdp: RTCSessionDescription,
}

#[derive(Serialize)]
struct ErrorMessage {
    #[serde(rename = "type")]
    kind: &'static str,
    message: String,
}

#[derive(Debug)]
struct ExampleError(String);

impl std::fmt::Display for ExampleError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ExampleError {}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,webrtc=warn".into()),
        )
        .init();

    let args = Args::parse();
    let (cert_b64, key_b64) = load_tls(&args)?;
    let (media_tx, media_rx) = mpsc::channel::<MediaChunk>(256);
    let hls = Arc::new(RwLock::new(HlsStore::default()));
    let state = Arc::new(AppState {
        media_tx,
        hls: Arc::clone(&hls),
    });

    tokio::spawn(run_rist_sender(media_rx, args.rist_peer));
    tokio::spawn(run_rist_receiver(args.rist_bind, hls));

    let ingest = build_server(
        args.ingest_port,
        cert_b64.clone(),
        key_b64.clone(),
        ExampleRouter {
            state: Arc::clone(&state),
            role: RouterRole::Ingest,
        },
    )?;
    let hls_server = build_server(
        args.hls_port,
        cert_b64,
        key_b64,
        ExampleRouter {
            state,
            role: RouterRole::Hls,
        },
    )?;

    let ingest_handle = ingest.start().await?;
    let hls_handle = hls_server.start().await?;
    let _ = ingest_handle.ready_rx.await;
    let _ = hls_handle.ready_rx.await;

    info!(
        "sender page:   https://127.0.0.1:{}/sender",
        args.ingest_port
    );
    info!(
        "receiver page: https://127.0.0.1:{}/receiver",
        args.hls_port
    );
    info!(
        "pure Rust RIST relay: WebRTC server -> {} -> receiver {}",
        args.rist_peer, args.rist_bind
    );

    tokio::signal::ctrl_c().await?;
    let _ = ingest_handle.shutdown_tx.send(());
    let _ = hls_handle.shutdown_tx.send(());
    let _ = ingest_handle.finished_rx.await;
    let _ = hls_handle.finished_rx.await;
    Ok(())
}

fn build_server(
    port: u16,
    cert_b64: String,
    key_b64: String,
    router: ExampleRouter,
) -> Result<H2H3Server> {
    H2H3Server::builder()
        .with_tls(cert_b64, key_b64)
        .with_port(port)
        .with_router(Box::new(router))
        .enable_h2(true)
        .enable_h3(false)
        .enable_websocket(true)
        .build()
        .map_err(|error| anyhow!(error.to_string()))
}

fn load_tls(args: &Args) -> Result<(String, String)> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let default_cert = manifest_dir
        .join("../../../web-services/tls/local.wavey.ai/fullchain.pem")
        .canonicalize()
        .unwrap_or_else(|_| {
            manifest_dir.join("../../../web-services/tls/local.wavey.ai/fullchain.pem")
        });
    let default_key = manifest_dir
        .join("../../../web-services/tls/local.wavey.ai/privkey.pem")
        .canonicalize()
        .unwrap_or_else(|_| {
            manifest_dir.join("../../../web-services/tls/local.wavey.ai/privkey.pem")
        });

    let cert_path = args.cert.as_ref().unwrap_or(&default_cert);
    let key_path = args.key.as_ref().unwrap_or(&default_key);
    let cert = std::fs::read(cert_path)
        .with_context(|| format!("read TLS certificate {}", cert_path.display()))?;
    let key =
        std::fs::read(key_path).with_context(|| format!("read TLS key {}", key_path.display()))?;
    Ok((
        base64::engine::general_purpose::STANDARD.encode(cert),
        base64::engine::general_purpose::STANDARD.encode(key),
    ))
}

#[async_trait]
impl Router for ExampleRouter {
    async fn route(&self, req: Request<()>) -> HandlerResult<HandlerResponse> {
        let path = req.uri().path();
        match path {
            "/" | "/sender" | "/receiver" => Ok(response(
                StatusCode::OK,
                "text/html; charset=utf-8",
                INDEX_HTML,
            )),
            "/app.js" => Ok(response(
                StatusCode::OK,
                "application/javascript; charset=utf-8",
                APP_JS,
            )),
            "/styles.css" => Ok(response(
                StatusCode::OK,
                "text/css; charset=utf-8",
                STYLES_CSS,
            )),
            "/api/stats" => self.stats_response().await,
            "/hls/live.m3u8" => self.playlist_response().await,
            _ if path.starts_with("/hls/part/") => self.part_response(path).await,
            _ => Ok(response(
                StatusCode::NOT_FOUND,
                "text/plain; charset=utf-8",
                "not found",
            )),
        }
    }

    fn is_streaming(&self, _path: &str) -> bool {
        false
    }

    async fn route_stream(
        &self,
        _req: Request<()>,
        mut stream_writer: Box<dyn StreamWriter>,
    ) -> HandlerResult<()> {
        let response = http::Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(())?;
        stream_writer.send_response(response).await?;
        stream_writer.finish().await
    }

    fn webtransport_handler(&self) -> Option<&dyn WebTransportHandler> {
        None
    }

    fn websocket_handler(&self, path: &str) -> Option<&dyn WebSocketHandler> {
        if matches!(self.role, RouterRole::Ingest) && path == "/signal" {
            Some(self)
        } else {
            None
        }
    }
}

#[async_trait]
impl WebSocketHandler for ExampleRouter {
    async fn handle_websocket(
        &self,
        _req: Request<()>,
        mut stream: tokio_tungstenite::WebSocketStream<
            hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>,
        >,
    ) -> HandlerResult<()> {
        let peer = create_peer_connection(self.state.media_tx.clone())
            .await
            .map_err(server_error)?;

        while let Some(message) = stream.next().await {
            let message = message.map_err(|error| server_error(anyhow!(error.to_string())))?;
            if !message.is_text() {
                continue;
            }

            let text = message
                .into_text()
                .map_err(|error| server_error(anyhow!(error.to_string())))?;
            let signal: SignalMessage =
                serde_json::from_str(&text).map_err(|error| server_error(anyhow!(error)))?;

            if signal.kind != "offer" {
                continue;
            }

            let Some(offer) = signal.sdp else {
                send_signal_error(&mut stream, "offer missing SDP").await?;
                continue;
            };

            match accept_offer(&peer, offer).await {
                Ok(answer) => {
                    let body = serde_json::to_string(&AnswerMessage {
                        kind: "answer",
                        sdp: answer,
                    })
                    .map_err(|error| server_error(anyhow!(error)))?;
                    stream
                        .send(Message::Text(body.into()))
                        .await
                        .map_err(|error| server_error(anyhow!(error.to_string())))?;
                }
                Err(error) => {
                    send_signal_error(&mut stream, &error.to_string()).await?;
                }
            }
        }

        let _ = peer.close().await;
        Ok(())
    }

    fn can_handle(&self, path: &str) -> bool {
        path == "/signal"
    }
}

impl ExampleRouter {
    async fn stats_response(&self) -> HandlerResult<HandlerResponse> {
        let stats = self.state.hls.read().await.stats();
        let body = serde_json::to_vec(&stats).map_err(|error| server_error(anyhow!(error)))?;
        Ok(response_bytes(
            StatusCode::OK,
            "application/json",
            Bytes::from(body),
        ))
    }

    async fn playlist_response(&self) -> HandlerResult<HandlerResponse> {
        let body = self.state.hls.read().await.playlist();
        let mut response = response(
            StatusCode::OK,
            "application/vnd.apple.mpegurl; charset=utf-8",
            body,
        );
        response
            .headers
            .push(("cache-control".into(), "no-store, no-cache".into()));
        Ok(response)
    }

    async fn part_response(&self, path: &str) -> HandlerResult<HandlerResponse> {
        let seq = path
            .trim_start_matches("/hls/part/")
            .trim_end_matches(".m4s")
            .parse::<u64>()
            .map_err(|_| server_error(anyhow!("invalid part sequence")))?;
        let Some(part) = self.state.hls.read().await.part(seq) else {
            return Ok(response(
                StatusCode::NOT_FOUND,
                "text/plain; charset=utf-8",
                "part not found",
            ));
        };

        let mut response =
            response_bytes(StatusCode::OK, content_type_for_mime(&part.mime), part.data);
        response
            .headers
            .push(("cache-control".into(), "no-store".into()));
        response
            .headers
            .push(("x-stream-sent-at-ms".into(), part.sent_at_ms.to_string()));
        response.headers.push((
            "x-stream-received-at-ms".into(),
            part.received_at_ms.to_string(),
        ));
        Ok(response)
    }
}

async fn create_peer_connection(
    media_tx: mpsc::Sender<MediaChunk>,
) -> Result<Arc<webrtc::peer_connection::RTCPeerConnection>> {
    let api = APIBuilder::new().build();
    let peer = Arc::new(api.new_peer_connection(RTCConfiguration::default()).await?);
    let media_tx = media_tx.clone();

    peer.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
        let media_tx = media_tx.clone();
        Box::pin(async move {
            info!(label = %dc.label(), "WebRTC data channel opened by browser");
            dc.on_message(Box::new(move |message: DataChannelMessage| {
                let media_tx = media_tx.clone();
                Box::pin(async move {
                    if message.is_string {
                        return;
                    }
                    match decode_datachannel_chunk(&message.data) {
                        Ok(chunk) => {
                            if media_tx.send(chunk).await.is_err() {
                                warn!("media relay queue closed");
                            }
                        }
                        Err(error) => warn!(error = %error, "invalid media chunk from browser"),
                    }
                })
            }));
        })
    }));

    Ok(peer)
}

async fn accept_offer(
    peer: &webrtc::peer_connection::RTCPeerConnection,
    offer: RTCSessionDescription,
) -> Result<RTCSessionDescription> {
    peer.set_remote_description(offer).await?;
    let answer = peer.create_answer(None).await?;
    let mut gather_complete = peer.gathering_complete_promise().await;
    peer.set_local_description(answer).await?;
    let _ = gather_complete.recv().await;
    peer.local_description()
        .await
        .ok_or_else(|| anyhow!("local WebRTC answer missing"))
}

async fn send_signal_error(
    stream: &mut tokio_tungstenite::WebSocketStream<
        hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>,
    >,
    message: &str,
) -> HandlerResult<()> {
    let body = serde_json::to_string(&ErrorMessage {
        kind: "error",
        message: message.to_string(),
    })
    .map_err(|error| server_error(anyhow!(error)))?;
    stream
        .send(Message::Text(body.into()))
        .await
        .map_err(|error| server_error(anyhow!(error.to_string())))
}

async fn run_rist_sender(mut media_rx: mpsc::Receiver<MediaChunk>, peer: SocketAddr) {
    let local = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let mut sender = match MainMioSender::connect(local, peer, FLOW_ID, 8192) {
        Ok(sender) => sender,
        Err(error) => {
            error!(error = %error, "failed to create RIST sender");
            return;
        }
    };
    let mut feedback_buf = vec![0u8; 65_536];
    info!(%peer, "pure Rust RIST sender ready");

    while let Some(chunk) = media_rx.recv().await {
        if let Err(error) = send_chunk_over_rist(&mut sender, &mut feedback_buf, chunk).await {
            warn!(error = %error, "failed to relay media chunk over RIST");
        }
    }
}

async fn send_chunk_over_rist(
    sender: &mut MainMioSender,
    feedback_buf: &mut [u8],
    chunk: MediaChunk,
) -> Result<()> {
    let mime = chunk.mime.as_bytes();
    let header_len = RIST_HEADER_LEN + mime.len();
    if header_len >= RIST_MAX_PAYLOAD {
        return Err(anyhow!("MIME type too large for RIST packet"));
    }
    let max_fragment_payload = RIST_MAX_PAYLOAD - header_len;
    let fragment_count = chunk.data.len().div_ceil(max_fragment_payload);
    if fragment_count > u16::MAX as usize {
        return Err(anyhow!("media chunk too large to fragment"));
    }

    for (index, payload) in chunk.data.chunks(max_fragment_payload).enumerate() {
        let packet = encode_rist_fragment(
            chunk.seq,
            chunk.sent_at_ms,
            &chunk.mime,
            index as u16,
            fragment_count as u16,
            payload,
        )?;

        loop {
            match sender.send_payload(&packet, ntp_now(), Instant::now()) {
                Ok(_) => break,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    drive_sender_feedback(sender, feedback_buf);
                    sleep(Duration::from_millis(1)).await;
                }
                Err(error) => return Err(error.into()),
            }
        }

        if index % 32 == 0 {
            drive_sender_feedback(sender, feedback_buf);
        }
    }

    drive_sender_feedback(sender, feedback_buf);
    Ok(())
}

async fn run_rist_receiver(bind_addr: SocketAddr, hls: Arc<RwLock<HlsStore>>) {
    let mut receiver =
        match MainMioReceiver::bind(bind_addr, FLOW_ID, "llhls-receiver", NackMode::Range) {
            Ok(receiver) => receiver,
            Err(error) => {
                error!(error = %error, "failed to bind RIST receiver");
                return;
            }
        };
    let mut buf = vec![0u8; 65_536];
    let mut pending: BTreeMap<u64, PendingChunk> = BTreeMap::new();
    let mut last_rtcp = Instant::now();
    info!(%bind_addr, "pure Rust RIST receiver ready");

    loop {
        let mut drained = false;
        for _ in 0..256 {
            match receiver.try_recv_payload(&mut buf) {
                Ok(Some((_peer, payload))) => {
                    drained = true;
                    match decode_rist_fragment(&payload) {
                        Ok(fragment) => {
                            if let Some(part) = push_fragment(&mut pending, fragment) {
                                hls.write().await.push(part);
                            }
                        }
                        Err(error) => warn!(error = %error, "invalid RIST fragment"),
                    }
                }
                Ok(None) => break,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => {
                    warn!(error = %error, "RIST receive failed");
                    break;
                }
            }
        }

        let now = Instant::now();
        if now.duration_since(last_rtcp) >= Duration::from_millis(20) {
            if let Err(error) = receiver.poll_rtcp_and_send(now, ntp_now()) {
                if error.kind() != io::ErrorKind::WouldBlock {
                    debug!(error = %error, "RIST RTCP feedback failed");
                }
            }
            last_rtcp = now;
        }

        if !drained {
            sleep(Duration::from_millis(1)).await;
        }
    }
}

fn drive_sender_feedback(sender: &mut MainMioSender, buf: &mut [u8]) {
    for _ in 0..32 {
        match sender.try_recv_feedback_and_retransmit(buf) {
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => {
                debug!(error = %error, "RIST sender feedback read failed");
                break;
            }
        }
    }
}

fn decode_datachannel_chunk(data: &[u8]) -> Result<MediaChunk> {
    if data.len() < DATA_CHANNEL_HEADER_LEN || &data[..4] != DATA_CHANNEL_MAGIC {
        return Err(anyhow!("bad data-channel chunk header"));
    }
    let version = data[4];
    if version != 1 {
        return Err(anyhow!("unsupported data-channel chunk version {version}"));
    }
    let mime_len = u16::from_be_bytes([data[5], data[6]]) as usize;
    let seq = u64::from_be_bytes(data[7..15].try_into()?);
    let sent_at_ms = f64::from_bits(u64::from_be_bytes(data[15..23].try_into()?)).max(0.0) as u64;
    let payload_len = u32::from_be_bytes(data[23..27].try_into()?) as usize;
    let mime_start = DATA_CHANNEL_HEADER_LEN;
    let payload_start = mime_start + mime_len;
    let payload_end = payload_start + payload_len;
    if data.len() < payload_end {
        return Err(anyhow!("truncated data-channel payload"));
    }
    let mime = std::str::from_utf8(&data[mime_start..payload_start])?.to_string();
    Ok(MediaChunk {
        seq,
        sent_at_ms,
        mime,
        data: Bytes::copy_from_slice(&data[payload_start..payload_end]),
    })
}

fn encode_rist_fragment(
    seq: u64,
    sent_at_ms: u64,
    mime: &str,
    index: u16,
    count: u16,
    payload: &[u8],
) -> Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        return Err(anyhow!("RIST fragment payload too large"));
    }
    let mime_bytes = mime.as_bytes();
    if mime_bytes.len() > u16::MAX as usize {
        return Err(anyhow!("MIME type too large"));
    }

    let mut out = Vec::with_capacity(RIST_HEADER_LEN + mime_bytes.len() + payload.len());
    out.extend_from_slice(RIST_CHUNK_MAGIC);
    out.push(1);
    out.extend_from_slice(&(mime_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&sent_at_ms.to_be_bytes());
    out.extend_from_slice(&index.to_be_bytes());
    out.extend_from_slice(&count.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(mime_bytes);
    out.extend_from_slice(payload);
    Ok(out)
}

fn decode_rist_fragment(payload: &ReceivedPayload) -> Result<RistFragment> {
    let data = payload.payload.as_slice();
    if data.len() < RIST_HEADER_LEN || &data[..4] != RIST_CHUNK_MAGIC {
        return Err(anyhow!("bad RIST media fragment header"));
    }
    if data[4] != 1 {
        return Err(anyhow!(
            "unsupported RIST media fragment version {}",
            data[4]
        ));
    }
    let mime_len = u16::from_be_bytes([data[5], data[6]]) as usize;
    let seq = u64::from_be_bytes(data[7..15].try_into()?);
    let sent_at_ms = u64::from_be_bytes(data[15..23].try_into()?);
    let index = u16::from_be_bytes(data[23..25].try_into()?) as usize;
    let count = u16::from_be_bytes(data[25..27].try_into()?) as usize;
    let fragment_len = u16::from_be_bytes(data[27..29].try_into()?) as usize;
    if count == 0 || index >= count {
        return Err(anyhow!("invalid RIST fragment index"));
    }
    let mime_start = RIST_HEADER_LEN;
    let fragment_start = mime_start + mime_len;
    let fragment_end = fragment_start + fragment_len;
    if data.len() < fragment_end {
        return Err(anyhow!("truncated RIST fragment"));
    }
    let mime = std::str::from_utf8(&data[mime_start..fragment_start])?.to_string();
    Ok(RistFragment {
        seq,
        sent_at_ms,
        mime,
        index,
        count,
        payload: Bytes::copy_from_slice(&data[fragment_start..fragment_end]),
    })
}

fn push_fragment(
    pending: &mut BTreeMap<u64, PendingChunk>,
    fragment: RistFragment,
) -> Option<MediaPart> {
    let entry = pending.entry(fragment.seq).or_insert_with(|| PendingChunk {
        sent_at_ms: fragment.sent_at_ms,
        mime: fragment.mime.clone(),
        fragments: vec![None; fragment.count],
        received: 0,
    });

    if entry.fragments.len() != fragment.count {
        pending.remove(&fragment.seq);
        return None;
    }

    if entry.fragments[fragment.index].is_none() {
        entry.fragments[fragment.index] = Some(fragment.payload);
        entry.received += 1;
    }

    if entry.received != entry.fragments.len() {
        return None;
    }

    let complete = pending.remove(&fragment.seq)?;
    let mut data = Vec::new();
    for fragment in complete.fragments {
        data.extend_from_slice(&fragment?);
    }

    Some(MediaPart {
        seq: fragment.seq,
        sent_at_ms: complete.sent_at_ms,
        received_at_ms: unix_now_ms(),
        mime: complete.mime,
        data: Bytes::from(data),
    })
}

impl HlsStore {
    fn push(&mut self, part: MediaPart) {
        self.bytes_received += part.data.len() as u64;
        self.parts_received += 1;
        self.parts.push_back(part);
        while self.parts.len() > HLS_WINDOW_PARTS {
            self.parts.pop_front();
        }
    }

    fn part(&self, seq: u64) -> Option<MediaPart> {
        self.parts.iter().find(|part| part.seq == seq).cloned()
    }

    fn stats(&self) -> HlsStats {
        let latest = self.parts.back();
        HlsStats {
            parts_received: self.parts_received,
            bytes_received: self.bytes_received,
            latest_sequence: latest.map(|part| part.seq),
            last_sent_at_ms: latest.map(|part| part.sent_at_ms),
            last_received_at_ms: latest.map(|part| part.received_at_ms),
            rist_latency_ms: latest
                .map(|part| part.received_at_ms.saturating_sub(part.sent_at_ms) as f64),
            mime: latest.map(|part| part.mime.clone()),
        }
    }

    fn playlist(&self) -> String {
        let first_seq = self.parts.front().map(|part| part.seq).unwrap_or(0);
        let next_seq = self.parts.back().map(|part| part.seq + 1).unwrap_or(0);
        let mut out = String::new();
        out.push_str("#EXTM3U\n");
        out.push_str("#EXT-X-VERSION:9\n");
        out.push_str("#EXT-X-TARGETDURATION:1\n");
        out.push_str("#EXT-X-PART-INF:PART-TARGET=0.500\n");
        out.push_str("#EXT-X-SERVER-CONTROL:CAN-BLOCK-RELOAD=YES,PART-HOLD-BACK=1.500\n");
        out.push_str(&format!("#EXT-X-MEDIA-SEQUENCE:{first_seq}\n"));
        for part in &self.parts {
            out.push_str(&format!(
                "#EXT-X-PART:DURATION={DEFAULT_PART_DURATION:.3},URI=\"part/{}.m4s\",INDEPENDENT=YES\n",
                part.seq
            ));
            out.push_str(&format!("#EXTINF:{DEFAULT_PART_DURATION:.3},\n"));
            out.push_str(&format!("part/{}.m4s\n", part.seq));
        }
        out.push_str(&format!(
            "#EXT-X-PRELOAD-HINT:TYPE=PART,URI=\"part/{next_seq}.m4s\"\n"
        ));
        out
    }
}

fn response(status: StatusCode, content_type: &str, body: impl Into<Bytes>) -> HandlerResponse {
    response_bytes(status, content_type, body.into())
}

fn response_bytes(status: StatusCode, content_type: &str, body: Bytes) -> HandlerResponse {
    HandlerResponse {
        status,
        body: Some(body),
        content_type: Some(content_type.to_string()),
        headers: vec![],
        etag: None,
    }
}

fn content_type_for_mime(mime: &str) -> &'static str {
    if mime.contains("mp4") {
        "video/mp4"
    } else if mime.contains("webm") {
        "video/webm"
    } else {
        "application/octet-stream"
    }
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn server_error(error: impl std::fmt::Display) -> web_service::ServerError {
    web_service::ServerError::Handler(Box::new(ExampleError(error.to_string())))
}
