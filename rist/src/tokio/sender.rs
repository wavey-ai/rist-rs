use crate::stats::SenderStats;
use crate::{Error, Profile, Result, SenderOptions};
use ::tokio::io::AsyncWrite;
use ::tokio::sync::{mpsc, oneshot};
use ::tokio::task::{spawn_blocking, JoinHandle as TokioJoinHandle};
use std::future::Future;
use std::io;
use std::os::raw::c_void;
use std::pin::Pin;
use std::ptr;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::thread::{self, JoinHandle};

const SEND_QUEUE_CAPACITY: usize = 256;

type WriteFuture = Pin<Box<dyn Future<Output = Result<usize>> + Send + 'static>>;

unsafe extern "C" fn stats_callback(
    arg: *mut c_void,
    stats_container: *const rist_sys::rist_stats,
) -> i32 {
    if arg.is_null() || stats_container.is_null() {
        return 0;
    }

    let stats_slot = unsafe { &*(arg as *const Mutex<Option<SenderStats>>) };
    let stats = unsafe { &*stats_container };
    if stats.stats_type == rist_sys::rist_stats_type_RIST_STATS_SENDER_PEER {
        let sender_stats = SenderStats::from(unsafe { &stats.stats.sender_peer });
        if let Ok(mut guard) = stats_slot.lock() {
            *guard = Some(sender_stats);
        }
    }
    unsafe {
        rist_sys::rist_stats_free(stats_container);
    }
    0
}

enum SenderCommand {
    Send {
        data: Vec<u8>,
        flow_id: u32,
        response: oneshot::Sender<Result<usize>>,
    },
}

struct SenderWorker {
    ctx: *mut rist_sys::rist_ctx,
    stats_callback_data: *const Mutex<Option<SenderStats>>,
}

impl SenderWorker {
    fn connect(
        profile: Profile,
        url: &str,
        options: &SenderOptions,
        stats: &Arc<Mutex<Option<SenderStats>>>,
    ) -> Result<Self> {
        // Prepare every fallible URL allocation before registering callbacks.
        let mut peer_config = crate::ffi::ParsedPeerConfig::parse(url)?;
        peer_config.configure(|config| {
            options.apply_to_peer_config(config);
        });

        let mut ctx = ptr::null_mut();
        let ret =
            unsafe { rist_sys::rist_sender_create(&mut ctx, profile.to_raw(), 0, ptr::null_mut()) };
        if ret != 0 || ctx.is_null() {
            return Err(Error::ContextCreation);
        }

        if let Err(error) = unsafe { peer_config.create_peer(ctx) } {
            unsafe {
                rist_sys::rist_destroy(ctx);
            }
            return Err(error);
        }

        let stats_callback_data = Arc::into_raw(stats.clone());
        unsafe {
            rist_sys::rist_stats_callback_set(
                ctx,
                1000,
                Some(stats_callback),
                stats_callback_data.cast_mut().cast(),
            );
        }

        let worker = Self {
            ctx,
            stats_callback_data,
        };
        if unsafe { rist_sys::rist_start(ctx) } != 0 {
            return Err(Error::Start);
        }
        Ok(worker)
    }

    fn send(&mut self, data: &[u8], flow_id: u32) -> Result<usize> {
        let block = rist_sys::rist_data_block {
            payload: data.as_ptr().cast(),
            payload_len: data.len(),
            ts_ntp: 0,
            flow_id,
            flags: 0,
            seq: 0,
            virt_src_port: 0,
            virt_dst_port: 0,
            peer: ptr::null_mut(),
            ref_: ptr::null_mut(),
        };
        let ret = unsafe { rist_sys::rist_sender_data_write(self.ctx, &block) };
        if ret < 0 {
            Err(Error::Send)
        } else {
            Ok(ret as usize)
        }
    }

    fn run(mut self, mut commands: mpsc::Receiver<SenderCommand>) {
        while let Some(command) = commands.blocking_recv() {
            match command {
                SenderCommand::Send {
                    data,
                    flow_id,
                    response,
                } => {
                    let _ = response.send(self.send(&data, flow_id));
                }
            }
        }
    }
}

impl Drop for SenderWorker {
    fn drop(&mut self) {
        unsafe {
            // Keep callback userdata alive until callbacks are disabled and
            // librist has joined its internal context threads.
            rist_sys::rist_stats_callback_set(self.ctx, 0, None, ptr::null_mut());
            rist_sys::rist_destroy(self.ctx);
            drop(Arc::from_raw(self.stats_callback_data));
        }
    }
}

/// Async RIST sender backed by one exclusively owning librist worker.
pub struct AsyncSender {
    commands: Option<mpsc::Sender<SenderCommand>>,
    worker: Option<JoinHandle<()>>,
    stats: Arc<Mutex<Option<SenderStats>>>,
}

enum ConnectState {
    Idle,
    Busy(TokioJoinHandle<Result<AsyncSender>>),
}

/// Future for connecting a sender.
pub struct Connect {
    profile: Profile,
    url: String,
    options: SenderOptions,
    state: ConnectState,
}

impl Future for Connect {
    type Output = Result<AsyncSender>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match &mut self.state {
            ConnectState::Idle => {
                let profile = self.profile;
                let url = self.url.clone();
                let options = self.options.clone();
                let mut handle =
                    spawn_blocking(move || AsyncSender::spawn_worker(profile, url, options));
                let result = Pin::new(&mut handle).poll(cx);
                self.state = ConnectState::Busy(handle);
                map_join_result(result)
            }
            ConnectState::Busy(handle) => map_join_result(Pin::new(handle).poll(cx)),
        }
    }
}

fn map_join_result(
    result: Poll<std::result::Result<Result<AsyncSender>, ::tokio::task::JoinError>>,
) -> Poll<Result<AsyncSender>> {
    match result {
        Poll::Ready(Ok(result)) => Poll::Ready(result),
        Poll::Ready(Err(error)) => Poll::Ready(Err(Error::JoinError(error.to_string()))),
        Poll::Pending => Poll::Pending,
    }
}

impl AsyncSender {
    fn spawn_worker(profile: Profile, url: String, options: SenderOptions) -> Result<Self> {
        let (commands, command_rx) = mpsc::channel(SEND_QUEUE_CAPACITY);
        let (startup_tx, startup_rx) = std::sync::mpsc::sync_channel(1);
        let stats = Arc::new(Mutex::new(None));
        let worker_stats = stats.clone();
        let worker = thread::Builder::new()
            .name("rist-sender".to_string())
            .spawn(
                move || match SenderWorker::connect(profile, &url, &options, &worker_stats) {
                    Ok(worker) => {
                        let _ = startup_tx.send(Ok(()));
                        worker.run(command_rx);
                    }
                    Err(error) => {
                        let _ = startup_tx.send(Err(error));
                    }
                },
            )
            .map_err(|error| Error::JoinError(error.to_string()))?;

        match startup_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                commands: Some(commands),
                worker: Some(worker),
                stats,
            }),
            Ok(Err(error)) => {
                let _ = worker.join();
                Err(error)
            }
            Err(error) => {
                let _ = worker.join();
                Err(Error::JoinError(error.to_string()))
            }
        }
    }

    /// Connect to a RIST receiver.
    pub fn connect(profile: Profile, url: &str) -> Connect {
        Self::connect_with_options(profile, url, SenderOptions::default())
    }

    /// Connect to a RIST receiver with custom options.
    pub fn connect_with_options(profile: Profile, url: &str, options: SenderOptions) -> Connect {
        Connect {
            profile,
            url: url.to_string(),
            options,
            state: ConnectState::Idle,
        }
    }

    /// Send one complete RIST datagram payload.
    pub async fn send(&mut self, data: &[u8]) -> Result<usize> {
        send_command(
            self.commands
                .as_ref()
                .ok_or_else(|| Error::JoinError("sender worker stopped".to_string()))?
                .clone(),
            data.to_vec(),
            0,
        )
        .await
    }

    /// Returns the latest stats for this sender.
    pub fn raw_stats(&self) -> Option<SenderStats> {
        self.stats.lock().ok().and_then(|guard| guard.clone())
    }

    /// Convert the packet-oriented sender into a byte-stream compatibility
    /// adapter. Each `poll_write` call becomes one RIST datagram, so callers
    /// must not assume stream writes preserve application message boundaries.
    pub fn into_byte_stream(self) -> AsyncSenderStream {
        AsyncSenderStream {
            sender: self,
            write_future: None,
        }
    }
}

async fn send_command(
    commands: mpsc::Sender<SenderCommand>,
    data: Vec<u8>,
    flow_id: u32,
) -> Result<usize> {
    let (response, result) = oneshot::channel();
    commands
        .send(SenderCommand::Send {
            data,
            flow_id,
            response,
        })
        .await
        .map_err(|_| Error::JoinError("sender worker stopped".to_string()))?;
    result
        .await
        .map_err(|_| Error::JoinError("sender worker stopped".to_string()))?
}

/// Byte-stream compatibility adapter for [`AsyncSender`].
pub struct AsyncSenderStream {
    sender: AsyncSender,
    write_future: Option<WriteFuture>,
}

impl AsyncWrite for AsyncSenderStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_future.is_none() {
            let Some(commands) = self.sender.commands.as_ref().cloned() else {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "sender worker stopped",
                )));
            };
            self.write_future = Some(Box::pin(send_command(commands, buf.to_vec(), 0)));
        }

        let result = self
            .write_future
            .as_mut()
            .expect("write future was just initialized")
            .as_mut()
            .poll(cx);
        match result {
            Poll::Ready(result) => {
                self.write_future = None;
                Poll::Ready(result.map_err(io::Error::other))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Drop for AsyncSenderStream {
    fn drop(&mut self) {
        // A pending write owns a command-sender clone. Release it before the
        // inner sender joins the worker, otherwise adapter cancellation can
        // keep the command channel open and deadlock shutdown.
        self.write_future.take();
    }
}

impl Drop for AsyncSender {
    fn drop(&mut self) {
        self.commands.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
