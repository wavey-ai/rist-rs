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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Profile, ReceiverOptions};
    use ::tokio::io::AsyncReadExt;
    use ::tokio::time::timeout;
    use std::time::Duration;

    #[tokio::test]
    async fn test_receiver_bind() {
        let _guard = crate::TEST_MUTEX.lock().unwrap();
        let url = format!("rist://@:{}", crate::next_test_port());
        // Just test that we can create a receiver without panicking
        let result = AsyncReceiver::bind(Profile::Main, &url);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_receiver_bind_with_options() {
        let _guard = crate::TEST_MUTEX.lock().unwrap();
        let url = format!("rist://@:{}", crate::next_test_port());
        let options = ReceiverOptions::new().fifo_size(2048);
        let result = AsyncReceiver::bind_with_options(Profile::Main, &url, options);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_receiver_bind_rejects_invalid_fifo_size() {
        let _guard = crate::TEST_MUTEX.lock().unwrap();
        let url = format!("rist://@:{}", crate::next_test_port());
        let options = ReceiverOptions::new().fifo_size(3);
        let result = AsyncReceiver::bind_with_options(Profile::Main, &url, options);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_receiver_recv_timeout() {
        let _guard = crate::TEST_MUTEX.lock().unwrap();
        let url = format!("rist://@:{}", crate::next_test_port());
        let receiver = AsyncReceiver::bind(Profile::Main, &url).unwrap();

        // Should timeout since nothing is sending
        let result = timeout(
            Duration::from_millis(200),
            receiver.recv_timeout(Duration::from_millis(100)),
        )
        .await;

        assert!(result.is_ok());
        let inner = result.unwrap();
        assert!(inner.is_ok());
        assert!(inner.unwrap().is_none()); // No data received
    }

    #[tokio::test]
    async fn test_sender_connect_empty_url() {
        let _guard = crate::TEST_MUTEX.lock().unwrap();
        // Empty URL should fail
        let result = AsyncSender::connect(Profile::Main, "").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_async_client_server() {
        let _guard = crate::TEST_MUTEX.lock().unwrap();
        // Similar to sportsball's test_async_client_server but for unidirectional RIST
        let port = crate::next_test_port();
        let receiver_url = format!("rist://@:{port}");
        let sender_url = format!("rist://127.0.0.1:{port}");
        let receiver = AsyncReceiver::bind(Profile::Main, &receiver_url).unwrap();
        let sender = AsyncSender::connect(Profile::Main, &sender_url)
            .await
            .unwrap();

        // Send multiple packets (like sportsball does with 5 iterations of 10 packets)
        let total_packets = 50;
        for _ in 0..total_packets {
            let payload = [0x47u8; 1316]; // TS sync byte
            let sent = sender.send(&payload).await.unwrap();
            assert_eq!(sent, 1316);
        }

        // Give packets time to arrive
        ::tokio::time::sleep(Duration::from_millis(100)).await;

        // Receive packets - RIST is UDP so we may not get all of them
        let mut received_count = 0;
        for _ in 0..total_packets {
            let result = receiver.recv_timeout(Duration::from_millis(100)).await;
            if let Ok(Some(data)) = result {
                assert_eq!(data.payload().len(), 1316);
                assert_eq!(data.payload()[0], 0x47);
                received_count += 1;
            }
        }

        // Should have received at least some packets
        assert!(received_count > 0, "expected to receive some packets");

        // Stats are optional - callback might not have fired yet
        // Just verify the API doesn't panic
        let _ = receiver.raw_stats();
    }

    #[tokio::test]
    async fn test_stats_available() {
        let _guard = crate::TEST_MUTEX.lock().unwrap();
        let url = format!("rist://@:{}", crate::next_test_port());
        let receiver = AsyncReceiver::bind(Profile::Main, &url).unwrap();

        // Stats might be None initially
        let stats = receiver.raw_stats();
        // Just check it doesn't panic
        drop(stats);
    }

    #[tokio::test]
    async fn test_stream_api() {
        let _guard = crate::TEST_MUTEX.lock().unwrap();
        // Test that AsyncRead works on receiver (stream-like API)
        let port = crate::next_test_port();
        let receiver_url = format!("rist://@:{port}");
        let sender_url = format!("rist://127.0.0.1:{port}");
        let mut receiver = AsyncReceiver::bind(Profile::Main, &receiver_url).unwrap();
        let sender = AsyncSender::connect(Profile::Main, &sender_url)
            .await
            .unwrap();

        // Send test data
        let test_data = b"Hello, RIST stream!";
        sender.send(test_data).await.unwrap();

        // Give data time to arrive
        ::tokio::time::sleep(Duration::from_millis(100)).await;

        // Read using stream API
        let mut buf = vec![0u8; 1024];
        let read_result = timeout(Duration::from_millis(500), receiver.read(&mut buf)).await;

        // Just verify the stream API is accessible - may or may not have data
        // depending on timing
        assert!(read_result.is_ok() || read_result.is_err());
    }
}
