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

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_receiver_create() {
        let result = Receiver::new(Profile::Main);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sender_create() {
        let result = Sender::new(Profile::Main);
        assert!(result.is_ok());
    }

    #[test]
    fn test_receiver_add_peer() {
        let mut receiver = Receiver::new(Profile::Main).unwrap();
        let result = receiver.add_peer("rist://@:16000");
        assert!(result.is_ok());
    }

    #[test]
    fn test_sender_add_peer() {
        let mut sender = Sender::new(Profile::Main).unwrap();
        let result = sender.add_peer("rist://127.0.0.1:16001");
        assert!(result.is_ok());
    }

    #[test]
    fn test_receiver_start() {
        let mut receiver = Receiver::new(Profile::Main).unwrap();
        receiver.add_peer("rist://@:16002").unwrap();
        let result = receiver.start();
        assert!(result.is_ok());
    }

    #[test]
    fn test_sender_start() {
        let mut sender = Sender::new(Profile::Main).unwrap();
        sender.add_peer("rist://127.0.0.1:16003").unwrap();
        let result = sender.start();
        assert!(result.is_ok());
    }

    #[test]
    fn test_receiver_read_timeout() {
        let mut receiver = Receiver::new(Profile::Main).unwrap();
        receiver.add_peer("rist://@:16004").unwrap();
        receiver.start().unwrap();

        // Should timeout since nothing is sending
        let result = receiver.read(Duration::from_millis(100));
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_sync_roundtrip() {
        let mut receiver = Receiver::new(Profile::Main).unwrap();
        receiver.add_peer("rist://@:16005").unwrap();
        receiver.start().unwrap();

        let mut sender = Sender::new(Profile::Main).unwrap();
        sender.add_peer("rist://127.0.0.1:16005").unwrap();
        sender.start().unwrap();

        // Send test data
        let test_data = [0x47u8; 1316];
        let total_packets = 50;

        for _ in 0..total_packets {
            let sent = sender.send(&test_data).unwrap();
            assert_eq!(sent, 1316);
        }

        // Give packets time to arrive
        thread::sleep(Duration::from_millis(100));

        // Receive packets
        let mut received_count = 0;
        for _ in 0..total_packets {
            if let Ok(Some(data)) = receiver.read(Duration::from_millis(100)) {
                assert_eq!(data.payload().len(), 1316);
                assert_eq!(data.payload()[0], 0x47);
                received_count += 1;
            }
        }

        assert!(received_count > 0, "expected to receive some packets");
    }

    #[test]
    fn test_sender_empty_url() {
        let mut sender = Sender::new(Profile::Main).unwrap();
        let result = sender.add_peer("");
        assert!(result.is_err());
    }

    #[test]
    fn test_send_with_flow_id() {
        let mut receiver = Receiver::new(Profile::Main).unwrap();
        receiver.add_peer("rist://@:16006").unwrap();
        receiver.start().unwrap();

        let mut sender = Sender::new(Profile::Main).unwrap();
        sender.add_peer("rist://127.0.0.1:16006").unwrap();
        sender.start().unwrap();

        // Send with specific flow ID
        let test_data = [0x47u8; 1316];
        sender.send_with_flow_id(&test_data, 42).unwrap();

        thread::sleep(Duration::from_millis(100));

        // Try to receive
        if let Ok(Some(data)) = receiver.read(Duration::from_millis(100)) {
            assert_eq!(data.payload().len(), 1316);
        }
    }

    #[test]
    fn test_profiles() {
        // Test all profiles can be used
        for profile in [Profile::Simple, Profile::Main, Profile::Advanced] {
            let result = Receiver::new(profile);
            assert!(result.is_ok());
        }
    }
}
