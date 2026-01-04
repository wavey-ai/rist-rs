//! Safe Rust bindings for librist (RIST protocol).
//!
//! RIST (Reliable Internet Stream Transport) is a protocol for reliable
//! video streaming over lossy networks with low latency.
//!
//! # Example
//!
//! ```no_run
//! use rist::{Receiver, Profile};
//! use std::time::Duration;
//!
//! let mut receiver = Receiver::new(Profile::Main)?;
//! receiver.add_peer("rist://@:5000")?;
//! receiver.start()?;
//!
//! loop {
//!     if let Some(data) = receiver.read(Duration::from_millis(100))? {
//!         // Process received data
//!     }
//! }
//! # Ok::<(), rist::Error>(())
//! ```

mod error;
mod logging;
mod options;
mod profile;
mod receiver;
mod sender;
pub mod stats;

#[cfg(feature = "tokio")]
pub mod tokio;

pub use error::Error;
pub use logging::{set_logging, LogLevel};
pub use options::{ReceiverOptions, RecoveryMode, SenderOptions};
pub use profile::Profile;
pub use receiver::{DataBlock, Receiver};
pub use sender::Sender;
pub use stats::{ReceiverStats, SenderStats};

pub type Result<T> = std::result::Result<T, Error>;
