use crate::{Error, Profile, Result};
use std::ffi::CString;
use std::ptr;

/// RIST sender for sending data streams.
pub struct Sender {
    ctx: *mut rist_sys::rist_ctx,
    started: bool,
}

impl Sender {
    /// Create a new RIST sender with the specified profile.
    pub fn new(profile: Profile) -> Result<Self> {
        let mut ctx: *mut rist_sys::rist_ctx = ptr::null_mut();

        let ret = unsafe { rist_sys::rist_sender_create(&mut ctx, profile.to_raw(), 0, ptr::null_mut()) };

        if ret != 0 || ctx.is_null() {
            return Err(Error::ContextCreation);
        }

        Ok(Self { ctx, started: false })
    }

    /// Add a peer by URL (e.g., "rist://192.168.1.1:5000").
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

    /// Start the sender.
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

    /// Send data.
    ///
    /// Returns the number of bytes written on success.
    pub fn send(&self, data: &[u8]) -> Result<usize> {
        if !self.started {
            return Err(Error::NotStarted);
        }

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

        let ret = unsafe { rist_sys::rist_sender_data_write(self.ctx, &block) };

        if ret < 0 {
            return Err(Error::Send);
        }

        Ok(ret as usize)
    }

    /// Send data with a specific flow ID.
    pub fn send_with_flow_id(&self, data: &[u8], flow_id: u32) -> Result<usize> {
        if !self.started {
            return Err(Error::NotStarted);
        }

        let block = rist_sys::rist_data_block {
            payload: data.as_ptr() as *const _,
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
            return Err(Error::Send);
        }

        Ok(ret as usize)
    }
}

impl Drop for Sender {
    fn drop(&mut self) {
        unsafe {
            rist_sys::rist_destroy(self.ctx);
        }
    }
}

// SAFETY: Sender owns its context and librist contexts are thread-safe
unsafe impl Send for Sender {}
