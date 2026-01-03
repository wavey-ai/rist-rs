//! Safe Rust bindings for librist (RIST protocol).
//!
//! RIST (Reliable Internet Stream Transport) is a protocol for reliable
//! video streaming over lossy networks with low latency.
//!
//! # Example
//!
//! ```no_run
//! use rist::{Receiver, Profile};
//!
//! let mut receiver = Receiver::new(Profile::Main)?;
//! receiver.add_peer("rist://@:5000")?;
//! receiver.start()?;
//!
//! loop {
//!     if let Some(data) = receiver.read()? {
//!         // Process received data
//!     }
//! }
//! # Ok::<(), rist::Error>(())
//! ```

mod error;
mod logging;
mod profile;
mod receiver;
mod sender;

pub use error::Error;
pub use logging::{LogLevel, set_logging};
pub use profile::Profile;
pub use receiver::{Receiver, DataBlock};
pub use sender::Sender;

pub type Result<T> = std::result::Result<T, Error>;
