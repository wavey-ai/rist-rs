use crate::{Error, Profile, ReceiverOptions, Result};
use std::ptr;
use std::time::Duration;

/// A received data block from a RIST stream.
pub struct DataBlock {
    payload: Vec<u8>,
    timestamp: u64,
    virtual_source_port: u16,
    virtual_destination_port: u16,
    flow_id: u32,
    sequence: u64,
    flags: u32,
}

impl DataBlock {
    /// Copy a librist-owned block into safe Rust storage and release it.
    pub(crate) unsafe fn copy_from_raw(mut inner: *mut rist_sys::rist_data_block) -> Self {
        debug_assert!(!inner.is_null());
        let block = unsafe { &*inner };
        let payload = if block.payload.is_null() || block.payload_len == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(block.payload.cast::<u8>(), block.payload_len) }
                .to_vec()
        };
        let owned = Self {
            payload,
            timestamp: block.ts_ntp,
            virtual_source_port: block.virt_src_port,
            virtual_destination_port: block.virt_dst_port,
            flow_id: block.flow_id,
            sequence: block.seq,
            flags: block.flags,
        };
        unsafe {
            rist_sys::rist_receiver_data_block_free2(&mut inner);
        }
        owned
    }

    /// Get the payload data.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Get the timestamp (in 90kHz clock units).
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Get the flow ID.
    pub fn flow_id(&self) -> u32 {
        self.flow_id
    }

    /// Get the virtual source port.
    pub fn virtual_source_port(&self) -> u16 {
        self.virtual_source_port
    }

    /// Get the virtual destination port.
    pub fn virtual_destination_port(&self) -> u16 {
        self.virtual_destination_port
    }

    /// Get the packet sequence reported by librist.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Get the packet flags reported by librist.
    pub fn flags(&self) -> u32 {
        self.flags
    }
}

/// RIST receiver for receiving data streams.
pub struct Receiver {
    ctx: *mut rist_sys::rist_ctx,
    started: bool,
}

impl Receiver {
    /// Create a new RIST receiver with the specified profile.
    pub fn new(profile: Profile) -> Result<Self> {
        let mut ctx: *mut rist_sys::rist_ctx = ptr::null_mut();

        let ret =
            unsafe { rist_sys::rist_receiver_create(&mut ctx, profile.to_raw(), ptr::null_mut()) };

        if ret != 0 || ctx.is_null() {
            return Err(Error::ContextCreation);
        }

        Ok(Self {
            ctx,
            started: false,
        })
    }

    /// Add a peer by URL (e.g., "rist://@:5000" for listening).
    pub fn add_peer(&mut self, url: &str) -> Result<()> {
        self.add_peer_with_options(url, &ReceiverOptions::default())
    }

    /// Add a peer by URL with custom receiver options.
    pub fn add_peer_with_options(&mut self, url: &str, options: &ReceiverOptions) -> Result<()> {
        options.apply_to_receiver_ctx(self.ctx)?;

        let mut config = crate::ffi::ParsedPeerConfig::parse(url)?;
        config.configure(|config| {
            options.apply_to_peer_config(config);
        });
        unsafe {
            config.create_peer(self.ctx)?;
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

        Ok(Some(unsafe { DataBlock::copy_from_raw(block) }))
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
