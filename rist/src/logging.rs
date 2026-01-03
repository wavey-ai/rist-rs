/// Log level for librist logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogLevel {
    Disable,
    Error,
    #[default]
    Warn,
    Notice,
    Info,
    Debug,
    Simulate,
}

impl LogLevel {
    pub(crate) fn to_raw(self) -> rist_sys::rist_log_level {
        match self {
            LogLevel::Disable => rist_sys::rist_log_level_RIST_LOG_DISABLE,
            LogLevel::Error => rist_sys::rist_log_level_RIST_LOG_ERROR,
            LogLevel::Warn => rist_sys::rist_log_level_RIST_LOG_WARN,
            LogLevel::Notice => rist_sys::rist_log_level_RIST_LOG_NOTICE,
            LogLevel::Info => rist_sys::rist_log_level_RIST_LOG_INFO,
            LogLevel::Debug => rist_sys::rist_log_level_RIST_LOG_DEBUG,
            LogLevel::Simulate => rist_sys::rist_log_level_RIST_LOG_SIMULATE,
        }
    }
}

/// Set the global logging level for librist.
pub fn set_logging(_level: LogLevel) -> crate::Result<()> {
    // TODO: implement logging callback setup
    Ok(())
}
