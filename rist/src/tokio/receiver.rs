use crate::{DataBlock, Error, Profile, Result};
use std::ffi::CString;
use std::ptr;
use std::time::Duration;
use ::tokio::task::spawn_blocking;

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

/// Async RIST receiver.
pub struct AsyncReceiver {
    ctx: SendCtx,
    raw_ctx: *mut rist_sys::rist_ctx,
}

// SAFETY: librist contexts are thread-safe
unsafe impl Send for AsyncReceiver {}
unsafe impl Sync for AsyncReceiver {}

impl AsyncReceiver {
    /// Bind a receiver to listen on the given URL.
    ///
    /// URL format: `rist://@:port` for listening
    pub fn bind(profile: Profile, url: &str) -> Result<Self> {
        let mut raw_ctx: *mut rist_sys::rist_ctx = ptr::null_mut();

        let ret = unsafe {
            rist_sys::rist_receiver_create(&mut raw_ctx, profile.to_raw(), ptr::null_mut())
        };

        if ret != 0 || raw_ctx.is_null() {
            return Err(Error::ContextCreation);
        }

        let mut receiver = Self {
            ctx: SendCtx::new(raw_ctx),
            raw_ctx,
        };
        receiver.add_peer(url)?;
        receiver.start()?;

        Ok(receiver)
    }

    fn add_peer(&mut self, url: &str) -> Result<()> {
        let url_c = CString::new(url)?;
        let mut peer_config: *mut rist_sys::rist_peer_config = ptr::null_mut();

        let ret = unsafe { rist_sys::rist_parse_address2(url_c.as_ptr(), &mut peer_config) };

        if ret != 0 || peer_config.is_null() {
            return Err(Error::UrlParse(url.to_string()));
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

    /// Receive data asynchronously.
    ///
    /// Returns `Ok(None)` when the connection is closed.
    pub async fn recv(&self) -> Result<Option<DataBlock>> {
        self.recv_timeout(Duration::from_millis(100)).await
    }

    /// Receive data with a custom timeout.
    pub async fn recv_timeout(&self, timeout: Duration) -> Result<Option<DataBlock>> {
        let ctx = self.ctx;
        let timeout_ms: i32 = timeout
            .as_millis()
            .try_into()
            .map_err(|_| Error::TimeoutOverflow)?;

        spawn_blocking(move || {
            let mut block: *mut rist_sys::rist_data_block = ptr::null_mut();

            let ret =
                unsafe { rist_sys::rist_receiver_data_read2(ctx.as_ptr(), &mut block, timeout_ms) };

            if ret < 0 {
                return Err(Error::Read);
            }

            if ret == 0 || block.is_null() {
                return Ok(None);
            }

            Ok(Some(DataBlock::from_raw(block)))
        })
        .await
        .map_err(|e| Error::JoinError(e.to_string()))?
    }
}

impl Drop for AsyncReceiver {
    fn drop(&mut self) {
        unsafe {
            rist_sys::rist_destroy(self.raw_ctx);
        }
    }
}
