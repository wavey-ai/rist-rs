use crate::stats::SenderStats;
use crate::{Error, Profile, Result, SenderOptions};
use std::ffi::CString;
use std::future::Future;
use std::io;
use std::os::raw::c_void;
use std::pin::Pin;
use std::ptr;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use ::tokio::io::AsyncWrite;
use ::tokio::task::{spawn_blocking, JoinHandle};

/// Send-safe wrapper for rist context pointer.
/// SAFETY: librist contexts are thread-safe.
#[derive(Clone, Copy)]
struct SendCtx(usize);

unsafe impl Send for SendCtx {}

impl SendCtx {
    fn new(ctx: *mut rist_sys::rist_ctx) -> Self {
        Self(ctx as usize)
    }

    fn as_ptr(self) -> *mut rist_sys::rist_ctx {
        self.0 as *mut rist_sys::rist_ctx
    }
}

/// Stats callback for librist sender
unsafe extern "C" fn stats_callback(
    arg: *mut c_void,
    stats_container: *const rist_sys::rist_stats,
) -> i32 {
    if arg.is_null() || stats_container.is_null() {
        return 0;
    }

    let stats_arc = &*(arg as *const Arc<Mutex<Option<SenderStats>>>);
    let stats = &*stats_container;

    // Check if this is sender stats
    if stats.stats_type == rist_sys::rist_stats_type_RIST_STATS_SENDER_PEER {
        let sender_stats = SenderStats::from(&stats.stats.sender_peer);
        if let Ok(mut guard) = stats_arc.lock() {
            *guard = Some(sender_stats);
        }
    }

    // Free the stats container
    rist_sys::rist_stats_free(stats_container);

    0
}

/// Async RIST sender.
pub struct AsyncSender {
    ctx: SendCtx,
    raw_ctx: *mut rist_sys::rist_ctx,
    stats: Arc<Mutex<Option<SenderStats>>>,
    _stats_data: Option<Box<Arc<Mutex<Option<SenderStats>>>>>,
}

// SAFETY: The sender context is thread-safe in librist
unsafe impl Send for AsyncSender {}
unsafe impl Sync for AsyncSender {}

enum ConnectState {
    Idle,
    Busy(JoinHandle<Result<AsyncSender>>),
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

                let mut handle = spawn_blocking(move || {
                    let mut ctx: *mut rist_sys::rist_ctx = ptr::null_mut();

                    let ret = unsafe {
                        rist_sys::rist_sender_create(&mut ctx, profile.to_raw(), 0, ptr::null_mut())
                    };

                    if ret != 0 || ctx.is_null() {
                        return Err(Error::ContextCreation);
                    }

                    // Set up stats callback
                    let stats = Arc::new(Mutex::new(None));
                    let stats_data = Box::new(stats.clone());
                    let stats_ptr =
                        &*stats_data as *const Arc<Mutex<Option<SenderStats>>> as *mut c_void;

                    unsafe {
                        rist_sys::rist_stats_callback_set(ctx, 1000, Some(stats_callback), stats_ptr);
                    }

                    // Add peer
                    let url_c = CString::new(url.as_str())?;
                    let mut peer_config: *mut rist_sys::rist_peer_config = ptr::null_mut();

                    let ret =
                        unsafe { rist_sys::rist_parse_address2(url_c.as_ptr(), &mut peer_config) };

                    if ret != 0 || peer_config.is_null() {
                        unsafe { rist_sys::rist_destroy(ctx) };
                        return Err(Error::UrlParse(url));
                    }

                    // Apply options to peer config
                    unsafe {
                        options.apply_to_peer_config(&mut *peer_config);
                    }

                    let mut peer: *mut rist_sys::rist_peer = ptr::null_mut();
                    let ret = unsafe { rist_sys::rist_peer_create(ctx, &mut peer, peer_config) };

                    unsafe {
                        rist_sys::rist_peer_config_free2(&mut peer_config);
                    }

                    if ret != 0 {
                        unsafe { rist_sys::rist_destroy(ctx) };
                        return Err(Error::PeerCreation(url));
                    }

                    // Start
                    let ret = unsafe { rist_sys::rist_start(ctx) };
                    if ret != 0 {
                        unsafe { rist_sys::rist_destroy(ctx) };
                        return Err(Error::Start);
                    }

                    Ok(AsyncSender {
                        ctx: SendCtx::new(ctx),
                        raw_ctx: ctx,
                        stats,
                        _stats_data: Some(stats_data),
                    })
                });

                let ret = Pin::new(&mut handle).poll(cx);
                self.state = ConnectState::Busy(handle);
                match ret {
                    Poll::Ready(Ok(r)) => Poll::Ready(r),
                    Poll::Ready(Err(e)) => Poll::Ready(Err(Error::JoinError(e.to_string()))),
                    Poll::Pending => Poll::Pending,
                }
            }
            ConnectState::Busy(ref mut handle) => match Pin::new(handle).poll(cx) {
                Poll::Ready(Ok(r)) => Poll::Ready(r),
                Poll::Ready(Err(e)) => Poll::Ready(Err(Error::JoinError(e.to_string()))),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

impl AsyncSender {
    /// Connect to a RIST receiver.
    ///
    /// URL format: `rist://host:port`
    pub fn connect(profile: Profile, url: &str) -> Connect {
        Self::connect_with_options(profile, url, SenderOptions::default())
    }

    /// Connect to a RIST receiver with custom options.
    ///
    /// URL format: `rist://host:port`
    pub fn connect_with_options(profile: Profile, url: &str, options: SenderOptions) -> Connect {
        Connect {
            profile,
            url: url.to_string(),
            options,
            state: ConnectState::Idle,
        }
    }

    /// Send data.
    pub async fn send(&self, data: &[u8]) -> Result<usize> {
        let ctx = self.ctx;
        let data = data.to_vec();

        spawn_blocking(move || {
            let block = rist_sys::rist_data_block {
                payload: data.as_ptr() as *const _,
                payload_len: data.len(),
                ts_ntp: 0,
                flow_id: 0,
                flags: 0,
                seq: 0,
                virt_src_port: 0,
                virt_dst_port: 0,
                peer: ptr::null_mut(),
                ref_: ptr::null_mut(),
            };

            let ret = unsafe { rist_sys::rist_sender_data_write(ctx.as_ptr(), &block) };

            if ret < 0 {
                return Err(Error::Send);
            }

            Ok(ret as usize)
        })
        .await
        .map_err(|e| Error::JoinError(e.to_string()))?
    }

    /// Returns the latest stats for this sender.
    ///
    /// Stats are updated periodically (every 1 second by default).
    /// Returns `None` if no stats have been collected yet.
    pub fn raw_stats(&self) -> Option<SenderStats> {
        self.stats.lock().ok().and_then(|guard| guard.clone())
    }
}

impl AsyncWrite for AsyncSender {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let block = rist_sys::rist_data_block {
            payload: buf.as_ptr() as *const _,
            payload_len: buf.len(),
            ts_ntp: 0,
            flow_id: 0,
            flags: 0,
            seq: 0,
            virt_src_port: 0,
            virt_dst_port: 0,
            peer: ptr::null_mut(),
            ref_: ptr::null_mut(),
        };

        let ret = unsafe { rist_sys::rist_sender_data_write(self.raw_ctx, &block) };

        if ret < 0 {
            Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, "send failed")))
        } else {
            Poll::Ready(Ok(ret as usize))
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Drop for AsyncSender {
    fn drop(&mut self) {
        unsafe {
            rist_sys::rist_destroy(self.raw_ctx);
        }
    }
}
