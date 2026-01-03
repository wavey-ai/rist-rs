use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to create context")]
    ContextCreation,

    #[error("failed to create peer: {0}")]
    PeerCreation(String),

    #[error("failed to parse URL: {0}")]
    UrlParse(String),

    #[error("failed to start context")]
    Start,

    #[error("failed to send data")]
    Send,

    #[error("failed to read data")]
    Read,

    #[error("invalid string: contains null byte")]
    NulError(#[from] std::ffi::NulError),

    #[error("context already started")]
    AlreadyStarted,

    #[error("context not started")]
    NotStarted,

    #[error("timeout value too large")]
    TimeoutOverflow,

    #[error("logging setup failed")]
    LoggingSetup,

    #[error("async task join error: {0}")]
    JoinError(String),
}
