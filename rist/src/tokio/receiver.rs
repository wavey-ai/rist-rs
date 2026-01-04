use crate::stats::ReceiverStats;
use crate::{DataBlock, Error, Profile, ReceiverOptions, Result};
use std::ffi::CString;
use std::io;
use std::os::raw::c_void;
use std::os::unix::io::{AsRawFd, RawFd};
use std::pin::Pin;
use std::ptr;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use ::tokio::io::{AsyncRead, ReadBuf};
use ::tokio::io::unix::AsyncFd;

/// Wrapper for a pipe read-end that can be used with AsyncFd.
/// librist will write to the write-end when data is available.
struct NotifyPipe {
    read_fd: RawFd,
    write_fd: RawFd,
}

impl NotifyPipe {
    fn new() -> io::Result<Self> {
        let mut fds = [0i32; 2];
        let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        // Set read end to non-blocking
        let flags = unsafe { libc::fcntl(fds[0], libc::F_GETFL) };
        if flags < 0 {
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            return Err(io::Error::last_os_error());
        }
        let ret = unsafe { libc::fcntl(fds[0], libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if ret < 0 {
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            read_fd: fds[0],
            write_fd: fds[1],
        })
    }

    /// Get the write fd to pass to librist
    fn write_fd(&self) -> RawFd {
        self.write_fd
    }

    /// Consume pending notifications (drain the pipe)
    fn consume(&self) -> io::Result<()> {
        let mut buf = [0u8; 64];
        loop {
            let ret = unsafe { libc::read(self.read_fd, buf.as_mut_ptr() as *mut _, buf.len()) };
            if ret < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    return Ok(()); // No more data
                }
                return Err(err);
            }
            if ret == 0 {
                return Ok(()); // EOF
            }
            // Loop to drain all pending bytes
        }
    }
}

impl AsRawFd for NotifyPipe {
    fn as_raw_fd(&self) -> RawFd {
        self.read_fd
    }
}

impl Drop for NotifyPipe {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.read_fd);
            libc::close(self.write_fd);
        }
    }
}

/// Async RIST receiver.
pub struct AsyncReceiver {
    raw_ctx: *mut rist_sys::rist_ctx,
    stats: Arc<Mutex<Option<ReceiverStats>>>,
    // prevent the boxed callback data from being dropped
    _stats_data: Option<Box<Arc<Mutex<Option<ReceiverStats>>>>>,
    // Buffer for AsyncRead
    read_buf: Mutex<Vec<u8>>,
    // AsyncFd for native async notification
    async_fd: AsyncFd<NotifyPipe>,
}

// SAFETY: librist contexts are thread-safe
unsafe impl Send for AsyncReceiver {}
unsafe impl Sync for AsyncReceiver {}

/// Stats callback for librist
unsafe extern "C" fn stats_callback(
    arg: *mut c_void,
    stats_container: *const rist_sys::rist_stats,
) -> i32 {
    if arg.is_null() || stats_container.is_null() {
        return 0;
    }

    let stats_arc = &*(arg as *const Arc<Mutex<Option<ReceiverStats>>>);
    let stats = &*stats_container;

    // Check if this is receiver stats
    if stats.stats_type == rist_sys::rist_stats_type_RIST_STATS_RECEIVER_FLOW {
        let receiver_stats = ReceiverStats::from(&stats.stats.receiver_flow);
        if let Ok(mut guard) = stats_arc.lock() {
            *guard = Some(receiver_stats);
        }
    }

    // Free the stats container
    rist_sys::rist_stats_free(stats_container);

    0
}

impl AsyncReceiver {
    /// Bind a receiver to listen on the given URL.
    ///
    /// URL format: `rist://@:port` for listening
    pub fn bind(profile: Profile, url: &str) -> Result<Self> {
        Self::bind_with_options(profile, url, ReceiverOptions::default())
    }

    /// Bind a receiver with custom options.
    ///
    /// URL format: `rist://@:port` for listening
    pub fn bind_with_options(
        profile: Profile,
        url: &str,
        options: ReceiverOptions,
    ) -> Result<Self> {
        let mut raw_ctx: *mut rist_sys::rist_ctx = ptr::null_mut();

        let ret = unsafe {
            rist_sys::rist_receiver_create(&mut raw_ctx, profile.to_raw(), ptr::null_mut())
        };

        if ret != 0 || raw_ctx.is_null() {
            return Err(Error::ContextCreation);
        }

        // Create pipe for async notification
        let notify_pipe = NotifyPipe::new().map_err(|e| Error::EventFd(e.to_string()))?;

        // Register the write-end with librist - it will write to this when data is available
        let ret = unsafe { rist_sys::rist_receiver_data_notify_fd_set(raw_ctx, notify_pipe.write_fd()) };
        if ret != 0 {
            return Err(Error::EventFd("failed to set notify fd".to_string()));
        }

        // Wrap the read-end in AsyncFd for tokio integration
        let async_fd = AsyncFd::new(notify_pipe).map_err(|e| Error::EventFd(e.to_string()))?;

        // Set up stats callback
        let stats = Arc::new(Mutex::new(None));
        let stats_data = Box::new(stats.clone());
        let stats_ptr = &*stats_data as *const Arc<Mutex<Option<ReceiverStats>>> as *mut c_void;

        unsafe {
            // Set stats callback with 1 second interval
            rist_sys::rist_stats_callback_set(raw_ctx, 1000, Some(stats_callback), stats_ptr);
        }

        let mut receiver = Self {
            raw_ctx,
            stats,
            _stats_data: Some(stats_data),
            read_buf: Mutex::new(Vec::new()),
            async_fd,
        };
        receiver.add_peer_with_options(url, &options)?;
        receiver.start()?;

        Ok(receiver)
    }

    fn add_peer_with_options(&mut self, url: &str, options: &ReceiverOptions) -> Result<()> {
        let url_c = CString::new(url)?;
        let mut peer_config: *mut rist_sys::rist_peer_config = ptr::null_mut();

        let ret = unsafe { rist_sys::rist_parse_address2(url_c.as_ptr(), &mut peer_config) };

        if ret != 0 || peer_config.is_null() {
            return Err(Error::UrlParse(url.to_string()));
        }

        // Apply options to peer config
        unsafe {
            options.apply_to_peer_config(&mut *peer_config);
        }

        let mut peer: *mut rist_sys::rist_peer = ptr::null_mut();
        let ret = unsafe { rist_sys::rist_peer_create(self.raw_ctx, &mut peer, peer_config) };

        unsafe {
            rist_sys::rist_peer_config_free2(&mut peer_config);
        }

        if ret != 0 {
            return Err(Error::PeerCreation(url.to_string()));
        }

        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        let ret = unsafe { rist_sys::rist_start(self.raw_ctx) };

        if ret != 0 {
            return Err(Error::Start);
        }

        Ok(())
    }

    /// Receive data asynchronously using native eventfd notification.
    ///
    /// Returns `Ok(None)` on timeout or when no data is available.
    pub async fn recv(&self) -> Result<Option<DataBlock>> {
        // Wait for the eventfd to be readable (librist signals data available)
        let mut guard = self.async_fd.readable().await.map_err(|e| Error::EventFd(e.to_string()))?;

        // Consume the event
        if let Err(e) = guard.get_inner().consume() {
            if e.kind() != io::ErrorKind::WouldBlock {
                return Err(Error::EventFd(e.to_string()));
            }
        }

        // Read with timeout=0 (non-blocking) since we know data is available
        let result = self.try_recv();

        // Clear readiness so we wait again next time
        guard.clear_ready();

        result
    }

    /// Receive data with a custom timeout.
    pub async fn recv_timeout(&self, timeout: Duration) -> Result<Option<DataBlock>> {
        // Use tokio timeout wrapping the native async recv
        match ::tokio::time::timeout(timeout, self.recv()).await {
            Ok(result) => result,
            Err(_) => Ok(None), // Timeout
        }
    }

    /// Try to receive data without blocking.
    /// Returns Ok(None) if no data is immediately available.
    pub fn try_recv(&self) -> Result<Option<DataBlock>> {
        let mut block: *mut rist_sys::rist_data_block = ptr::null_mut();

        // timeout=0 means non-blocking
        let ret = unsafe { rist_sys::rist_receiver_data_read2(self.raw_ctx, &mut block, 0) };

        if ret < 0 {
            return Err(Error::Read);
        }

        if ret == 0 || block.is_null() {
            return Ok(None);
        }

        Ok(Some(DataBlock::from_raw(block)))
    }

    /// Returns the latest stats for this receiver.
    ///
    /// Stats are updated periodically (every 1 second by default).
    /// Returns `None` if no stats have been collected yet.
    pub fn raw_stats(&self) -> Option<ReceiverStats> {
        self.stats.lock().ok().and_then(|guard| guard.clone())
    }
}

impl Drop for AsyncReceiver {
    fn drop(&mut self) {
        unsafe {
            rist_sys::rist_destroy(self.raw_ctx);
        }
    }
}

impl AsyncRead for AsyncReceiver {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // First, try to read from the internal buffer
        if let Ok(mut read_buf) = self.read_buf.lock() {
            if !read_buf.is_empty() {
                let to_read = std::cmp::min(buf.remaining(), read_buf.len());
                buf.put_slice(&read_buf[..to_read]);
                read_buf.drain(..to_read);
                return Poll::Ready(Ok(()));
            }
        }

        // Buffer is empty, read from RIST (non-blocking with 0 timeout)
        let mut block: *mut rist_sys::rist_data_block = ptr::null_mut();
        let ret = unsafe { rist_sys::rist_receiver_data_read2(self.raw_ctx, &mut block, 0) };

        if ret < 0 {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, "read failed")));
        }

        if ret == 0 || block.is_null() {
            // No data available, would block
            return Poll::Pending;
        }

        // Copy data from block
        let data_block = DataBlock::from_raw(block);
        let payload = data_block.payload();

        let to_read = std::cmp::min(buf.remaining(), payload.len());
        buf.put_slice(&payload[..to_read]);

        // Store remaining data in buffer
        if to_read < payload.len() {
            if let Ok(mut read_buf) = self.read_buf.lock() {
                read_buf.extend_from_slice(&payload[to_read..]);
            }
        }

        Poll::Ready(Ok(()))
    }
}
