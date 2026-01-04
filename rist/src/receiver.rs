use crate::{Error, Profile, Result};
use std::ffi::CString;
use std::ptr;
use std::time::Duration;

/// A received data block from a RIST stream.
pub struct DataBlock {
    inner: *mut rist_sys::rist_data_block,
}

impl DataBlock {
    /// Create a DataBlock from a raw pointer.
    pub(crate) fn from_raw(inner: *mut rist_sys::rist_data_block) -> Self {
        Self { inner }
    }

    /// Get the payload data.
    pub fn payload(&self) -> &[u8] {
        unsafe {
            let ptr = (*self.inner).payload as *const u8;
            let len = (*self.inner).payload_len;
            std::slice::from_raw_parts(ptr, len)
        }
    }

    /// Get the timestamp (in 90kHz clock units).
    pub fn timestamp(&self) -> u64 {
        unsafe { (*self.inner).ts_ntp }
    }

    /// Get the flow ID.
    pub fn flow_id(&self) -> u32 {
        unsafe { (*self.inner).flow_id }
    }
}

impl Drop for DataBlock {
    fn drop(&mut self) {
        unsafe {
            rist_sys::rist_receiver_data_block_free2(&mut self.inner);
        }
    }
}

// SAFETY: DataBlock owns its data and can be sent between threads
unsafe impl Send for DataBlock {}

/// RIST receiver for receiving data streams.
pub struct Receiver {
    ctx: *mut rist_sys::rist_ctx,
    started: bool,
}

impl Receiver {
    /// Create a new RIST receiver with the specified profile.
    pub fn new(profile: Profile) -> Result<Self> {
        let mut ctx: *mut rist_sys::rist_ctx = ptr::null_mut();

        let ret = unsafe { rist_sys::rist_receiver_create(&mut ctx, profile.to_raw(), ptr::null_mut()) };

        if ret != 0 || ctx.is_null() {
            return Err(Error::ContextCreation);
        }

        Ok(Self { ctx, started: false })
    }

    /// Add a peer by URL (e.g., "rist://@:5000" for listening).
    pub fn add_peer(&mut self, url: &str) -> Result<()> {
        let url_c = CString::new(url)?;
        let mut peer_config: *mut rist_sys::rist_peer_config = ptr::null_mut();

        let ret = unsafe {
            rist_sys::rist_parse_address2(url_c.as_ptr(), &mut peer_config)
        };

        if ret != 0 || peer_config.is_null() {
            return Err(Error::UrlParse(url.to_string()));
        }

        let mut peer: *mut rist_sys::rist_peer = ptr::null_mut();
        let ret = unsafe {
            rist_sys::rist_peer_create(self.ctx, &mut peer, peer_config)
        };

        unsafe {
            rist_sys::rist_peer_config_free2(&mut peer_config);
        }

        if ret != 0 {
            return Err(Error::PeerCreation(url.to_string()));
        }

        Ok(())
    }

    /// Start the receiver.
    pub fn start(&mut self) -> Result<()> {
        if self.started {
            return Err(Error::AlreadyStarted);
        }

        let ret = unsafe { rist_sys::rist_start(self.ctx) };

        if ret != 0 {
            return Err(Error::Start);
        }

        self.started = true;
        Ok(())
    }

    /// Read data with a timeout.
    ///
    /// Returns `Ok(None)` on timeout, `Ok(Some(data))` on success.
    pub fn read(&self, timeout: Duration) -> Result<Option<DataBlock>> {
        if !self.started {
            return Err(Error::NotStarted);
        }

        let timeout_ms: i32 = timeout
            .as_millis()
            .try_into()
            .map_err(|_| Error::TimeoutOverflow)?;

        let mut block: *mut rist_sys::rist_data_block = ptr::null_mut();

        let ret = unsafe { rist_sys::rist_receiver_data_read2(self.ctx, &mut block, timeout_ms) };

        if ret < 0 {
            return Err(Error::Read);
        }

        if ret == 0 || block.is_null() {
            return Ok(None);
        }

        Ok(Some(DataBlock::from_raw(block)))
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        unsafe {
            rist_sys::rist_destroy(self.ctx);
        }
    }
}

// SAFETY: Receiver owns its context and librist contexts are thread-safe
unsafe impl Send for Receiver {}
