//! Configuration options for RIST senders and receivers.

use std::time::Duration;

/// Recovery mode for packet loss recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RecoveryMode {
    /// Recovery is disabled.
    Disabled,
    /// Time-based recovery (default).
    #[default]
    Time,
}

impl RecoveryMode {
    #[allow(dead_code)]
    pub(crate) fn to_raw(self) -> rist_sys::rist_recovery_mode {
        match self {
            RecoveryMode::Disabled => rist_sys::rist_recovery_mode_RIST_RECOVERY_MODE_DISABLED,
            RecoveryMode::Time => rist_sys::rist_recovery_mode_RIST_RECOVERY_MODE_TIME,
        }
    }
}

/// Options for configuring a RIST receiver.
#[derive(Debug, Clone, Default)]
pub struct ReceiverOptions {
    /// Recovery mode for packet loss.
    pub recovery_mode: Option<RecoveryMode>,
    /// Maximum bitrate for recovery (bps).
    pub recovery_maxbitrate: Option<u32>,
    /// Minimum recovery buffer length.
    pub recovery_length_min: Option<Duration>,
    /// Maximum recovery buffer length.
    pub recovery_length_max: Option<Duration>,
    /// Reorder buffer size (packets).
    pub recovery_reorder_buffer: Option<u32>,
    /// Minimum RTT for recovery.
    pub recovery_rtt_min: Option<Duration>,
    /// Maximum RTT for recovery.
    pub recovery_rtt_max: Option<Duration>,
    /// Output FIFO size (packets). 0 to disable.
    pub fifo_size: Option<u32>,
}

impl ReceiverOptions {
    /// Create new receiver options with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the recovery mode.
    pub fn recovery_mode(mut self, mode: RecoveryMode) -> Self {
        self.recovery_mode = Some(mode);
        self
    }

    /// Set maximum recovery bitrate in bps.
    pub fn recovery_maxbitrate(mut self, bitrate: u32) -> Self {
        self.recovery_maxbitrate = Some(bitrate);
        self
    }

    /// Set minimum recovery buffer length.
    pub fn recovery_length_min(mut self, duration: Duration) -> Self {
        self.recovery_length_min = Some(duration);
        self
    }

    /// Set maximum recovery buffer length.
    pub fn recovery_length_max(mut self, duration: Duration) -> Self {
        self.recovery_length_max = Some(duration);
        self
    }

    /// Set FIFO buffer size.
    pub fn fifo_size(mut self, size: u32) -> Self {
        self.fifo_size = Some(size);
        self
    }

    pub(crate) fn apply_to_receiver_ctx(&self, ctx: *mut rist_sys::rist_ctx) -> crate::Result<()> {
        if let Some(size) = self.fifo_size {
            if size != 0 && !size.is_power_of_two() {
                return Err(crate::Error::Configuration(
                    "receiver fifo_size must be 0 or a power of 2".to_string(),
                ));
            }

            let ret = unsafe { rist_sys::rist_receiver_set_output_fifo_size(ctx, size) };
            if ret != 0 {
                return Err(crate::Error::Configuration(
                    "failed to set receiver output fifo size".to_string(),
                ));
            }
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn apply_to_peer_config(&self, config: &mut rist_sys::rist_peer_config) {
        if let Some(mode) = self.recovery_mode {
            config.recovery_mode = mode.to_raw();
        }
        if let Some(bitrate) = self.recovery_maxbitrate {
            config.recovery_maxbitrate = bitrate;
        }
        if let Some(duration) = self.recovery_length_min {
            config.recovery_length_min = duration.as_millis() as u32;
        }
        if let Some(duration) = self.recovery_length_max {
            config.recovery_length_max = duration.as_millis() as u32;
        }
        if let Some(buffer) = self.recovery_reorder_buffer {
            config.recovery_reorder_buffer = buffer;
        }
        if let Some(duration) = self.recovery_rtt_min {
            config.recovery_rtt_min = duration.as_millis() as u32;
        }
        if let Some(duration) = self.recovery_rtt_max {
            config.recovery_rtt_max = duration.as_millis() as u32;
        }
    }
}

/// Options for configuring a RIST sender.
#[derive(Debug, Clone, Default)]
pub struct SenderOptions {
    /// Recovery mode for packet loss.
    pub recovery_mode: Option<RecoveryMode>,
    /// Maximum bitrate for recovery (bps).
    pub recovery_maxbitrate: Option<u32>,
    /// Minimum recovery buffer length.
    pub recovery_length_min: Option<Duration>,
    /// Maximum recovery buffer length.
    pub recovery_length_max: Option<Duration>,
}

impl SenderOptions {
    /// Create new sender options with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the recovery mode.
    pub fn recovery_mode(mut self, mode: RecoveryMode) -> Self {
        self.recovery_mode = Some(mode);
        self
    }

    /// Set maximum recovery bitrate in bps.
    pub fn recovery_maxbitrate(mut self, bitrate: u32) -> Self {
        self.recovery_maxbitrate = Some(bitrate);
        self
    }

    /// Set minimum recovery buffer length.
    pub fn recovery_length_min(mut self, duration: Duration) -> Self {
        self.recovery_length_min = Some(duration);
        self
    }

    /// Set maximum recovery buffer length.
    pub fn recovery_length_max(mut self, duration: Duration) -> Self {
        self.recovery_length_max = Some(duration);
        self
    }

    #[allow(dead_code)]
    pub(crate) fn apply_to_peer_config(&self, config: &mut rist_sys::rist_peer_config) {
        if let Some(mode) = self.recovery_mode {
            config.recovery_mode = mode.to_raw();
        }
        if let Some(bitrate) = self.recovery_maxbitrate {
            config.recovery_maxbitrate = bitrate;
        }
        if let Some(duration) = self.recovery_length_min {
            config.recovery_length_min = duration.as_millis() as u32;
        }
        if let Some(duration) = self.recovery_length_max {
            config.recovery_length_max = duration.as_millis() as u32;
        }
    }
}
