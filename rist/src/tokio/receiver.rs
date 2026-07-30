use crate::stats::ReceiverStats;
use crate::{DataBlock, Error, Profile, ReceiverOptions, Result};
use ::tokio::io::{AsyncRead, ReadBuf};
use ::tokio::sync::{mpsc, Mutex as TokioMutex};
use std::future::Future;
use std::io;
use std::os::raw::c_void;
use std::pin::Pin;
use std::ptr;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const RECEIVE_QUEUE_CAPACITY: usize = 256;
const WORKER_READ_TIMEOUT_MS: i32 = 20;

type ReceiveQueue = Arc<TokioMutex<mpsc::Receiver<Result<DataBlock>>>>;
type ReadFuture = Pin<Box<dyn Future<Output = Result<Option<DataBlock>>> + Send + 'static>>;

unsafe extern "C" fn stats_callback(
    arg: *mut c_void,
    stats_container: *const rist_sys::rist_stats,
) -> i32 {
    if arg.is_null() || stats_container.is_null() {
        return 0;
    }

    let stats_slot = unsafe { &*(arg as *const Mutex<Option<ReceiverStats>>) };
    let stats = unsafe { &*stats_container };
    if stats.stats_type == rist_sys::rist_stats_type_RIST_STATS_RECEIVER_FLOW {
        let receiver_stats = ReceiverStats::from(unsafe { &stats.stats.receiver_flow });
        if let Ok(mut guard) = stats_slot.lock() {
            *guard = Some(receiver_stats);
        }
    }
    unsafe {
        rist_sys::rist_stats_free(stats_container);
    }
    0
}

struct ReceiverWorker {
    ctx: *mut rist_sys::rist_ctx,
    stats_callback_data: *const Mutex<Option<ReceiverStats>>,
}

impl ReceiverWorker {
    fn bind(
        profile: Profile,
        url: &str,
        options: &ReceiverOptions,
        stats: &Arc<Mutex<Option<ReceiverStats>>>,
    ) -> Result<Self> {
        // Parsing and allocation happen before callback registration.
        let mut peer_config = crate::ffi::ParsedPeerConfig::parse(url)?;
        peer_config.configure(|config| {
            options.apply_to_peer_config(config);
        });

        let mut ctx = ptr::null_mut();
        let ret =
            unsafe { rist_sys::rist_receiver_create(&mut ctx, profile.to_raw(), ptr::null_mut()) };
        if ret != 0 || ctx.is_null() {
            return Err(Error::ContextCreation);
        }

        if let Err(error) = options.apply_to_receiver_ctx(ctx) {
            unsafe {
                rist_sys::rist_destroy(ctx);
            }
            return Err(error);
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

    fn run(self, incoming: mpsc::Sender<Result<DataBlock>>) {
        while !incoming.is_closed() {
            let mut block = ptr::null_mut();
            let ret = unsafe {
                rist_sys::rist_receiver_data_read2(self.ctx, &mut block, WORKER_READ_TIMEOUT_MS)
            };
            if ret < 0 {
                let _ = incoming.try_send(Err(Error::Read));
                break;
            }
            if ret == 0 || block.is_null() {
                continue;
            }

            let block = unsafe { DataBlock::copy_from_raw(block) };
            if incoming.try_send(Ok(block)).is_err() && incoming.is_closed() {
                break;
            }
        }
    }
}

impl Drop for ReceiverWorker {
    fn drop(&mut self) {
        unsafe {
            rist_sys::rist_stats_callback_set(self.ctx, 0, None, ptr::null_mut());
            rist_sys::rist_destroy(self.ctx);
            drop(Arc::from_raw(self.stats_callback_data));
        }
    }
}

/// Async RIST receiver backed by one exclusively owning librist worker.
pub struct AsyncReceiver {
    incoming: Option<ReceiveQueue>,
    worker: Option<JoinHandle<()>>,
    stats: Arc<Mutex<Option<ReceiverStats>>>,
}

impl AsyncReceiver {
    /// Bind a receiver to listen on the given URL.
    pub fn bind(profile: Profile, url: &str) -> Result<Self> {
        Self::bind_with_options(profile, url, ReceiverOptions::default())
    }

    /// Bind a receiver with custom options.
    pub fn bind_with_options(
        profile: Profile,
        url: &str,
        options: ReceiverOptions,
    ) -> Result<Self> {
        let (incoming_tx, incoming_rx) = mpsc::channel(RECEIVE_QUEUE_CAPACITY);
        let (startup_tx, startup_rx) = std::sync::mpsc::sync_channel(1);
        let stats = Arc::new(Mutex::new(None));
        let worker_stats = stats.clone();
        let url = url.to_string();
        let worker = thread::Builder::new()
            .name("rist-receiver".to_string())
            .spawn(
                move || match ReceiverWorker::bind(profile, &url, &options, &worker_stats) {
                    Ok(worker) => {
                        let _ = startup_tx.send(Ok(()));
                        worker.run(incoming_tx);
                    }
                    Err(error) => {
                        let _ = startup_tx.send(Err(error));
                    }
                },
            )
            .map_err(|error| Error::JoinError(error.to_string()))?;

        match startup_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                incoming: Some(Arc::new(TokioMutex::new(incoming_rx))),
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

    /// Receive one complete RIST datagram payload.
    pub async fn recv(&self) -> Result<Option<DataBlock>> {
        receive_next(
            self.incoming
                .as_ref()
                .ok_or_else(|| Error::JoinError("receiver worker stopped".to_string()))?
                .clone(),
        )
        .await
    }

    /// Receive data with a custom timeout.
    pub async fn recv_timeout(&self, timeout: Duration) -> Result<Option<DataBlock>> {
        match ::tokio::time::timeout(timeout, self.recv()).await {
            Ok(result) => result,
            Err(_) => Ok(None),
        }
    }

    /// Try to receive one complete payload without blocking.
    pub fn try_recv(&self) -> Result<Option<DataBlock>> {
        let incoming = self
            .incoming
            .as_ref()
            .ok_or_else(|| Error::JoinError("receiver worker stopped".to_string()))?;
        let mut incoming = incoming
            .try_lock()
            .map_err(|_| Error::Configuration("another receive is in progress".to_string()))?;
        match incoming.try_recv() {
            Ok(result) => result.map(Some),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => {
                Err(Error::JoinError("receiver worker stopped".to_string()))
            }
        }
    }

    /// Returns the latest stats for this receiver.
    pub fn raw_stats(&self) -> Option<ReceiverStats> {
        self.stats.lock().ok().and_then(|guard| guard.clone())
    }

    /// Convert the packet-oriented receiver into a byte-stream compatibility
    /// adapter. Datagram boundaries are discarded by reads from this adapter.
    pub fn into_byte_stream(self) -> AsyncReceiverStream {
        AsyncReceiverStream {
            receiver: self,
            read_buf: Vec::new(),
            read_future: None,
        }
    }
}

async fn receive_next(incoming: ReceiveQueue) -> Result<Option<DataBlock>> {
    match incoming.lock().await.recv().await {
        Some(result) => result.map(Some),
        None => Err(Error::JoinError("receiver worker stopped".to_string())),
    }
}

/// Byte-stream compatibility adapter for [`AsyncReceiver`].
pub struct AsyncReceiverStream {
    receiver: AsyncReceiver,
    read_buf: Vec<u8>,
    read_future: Option<ReadFuture>,
}

impl AsyncRead for AsyncReceiverStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.read_buf.is_empty() {
                let to_read = buf.remaining().min(self.read_buf.len());
                buf.put_slice(&self.read_buf[..to_read]);
                self.read_buf.drain(..to_read);
                return Poll::Ready(Ok(()));
            }

            if self.read_future.is_none() {
                let Some(incoming) = self.receiver.incoming.as_ref().cloned() else {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "receiver worker stopped",
                    )));
                };
                self.read_future = Some(Box::pin(receive_next(incoming)));
            }

            let result = self
                .read_future
                .as_mut()
                .expect("read future was just initialized")
                .as_mut()
                .poll(cx);
            match result {
                Poll::Ready(Ok(Some(block))) => {
                    self.read_future = None;
                    self.read_buf.extend_from_slice(block.payload());
                }
                Poll::Ready(Ok(None)) => {
                    self.read_future = None;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(error)) => {
                    self.read_future = None;
                    return Poll::Ready(Err(io::Error::other(error)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl Drop for AsyncReceiverStream {
    fn drop(&mut self) {
        // A pending read owns a receive-queue Arc. Release it before the inner
        // receiver joins the worker so a cancelled adapter cannot deadlock.
        self.read_future.take();
    }
}

impl Drop for AsyncReceiver {
    fn drop(&mut self) {
        self.incoming.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
