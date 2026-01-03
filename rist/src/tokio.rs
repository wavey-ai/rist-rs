//! Async RIST support using Tokio.
//!
//! This module provides async versions of the RIST sender and receiver.
//!
//! # Example
//!
//! ```no_run
//! use rist::tokio::{AsyncReceiver, AsyncSender};
//! use rist::Profile;
//!
//! # async fn example() -> rist::Result<()> {
//! // Receiver
//! let mut receiver = AsyncReceiver::bind(Profile::Main, "rist://@:5000")?;
//! while let Some(data) = receiver.recv().await? {
//!     println!("received {} bytes", data.payload().len());
//! }
//!
//! // Sender
//! let mut sender = AsyncSender::connect(Profile::Main, "rist://192.168.1.1:5000").await?;
//! sender.send(b"hello").await?;
//! # Ok(())
//! # }
//! ```

mod receiver;
mod sender;

pub use receiver::AsyncReceiver;
pub use sender::AsyncSender;
