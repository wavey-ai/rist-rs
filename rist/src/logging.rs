use std::ptr;

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
    #[allow(dead_code)]
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
pub fn set_logging(level: LogLevel) -> crate::Result<()> {
    unsafe {
        if matches!(level, LogLevel::Disable) {
            rist_sys::rist_logging_unset_global();
            return Ok(());
        }

        let mut settings: *mut rist_sys::rist_logging_settings = ptr::null_mut();
        let ret = rist_sys::rist_logging_set(
            &mut settings,
            level.to_raw(),
            None,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        if ret != 0 || settings.is_null() {
            return Err(crate::Error::LoggingSetup);
        }

        let set_ret = rist_sys::rist_logging_set_global(settings);
        let free_ret = rist_sys::rist_logging_settings_free2(&mut settings);

        if set_ret != 0 || free_ret != 0 {
            return Err(crate::Error::LoggingSetup);
        }
    }

    Ok(())
}
