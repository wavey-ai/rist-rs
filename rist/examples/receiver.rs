//! Example RIST receiver.
//!
//! Run with: cargo run --example receiver --features tokio

use rist::tokio::AsyncReceiver;
use rist::{Profile, ReceiverOptions};
use std::time::Duration;

#[tokio::main]
async fn main() -> rist::Result<()> {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "rist://@:5000".to_string());

    println!("Listening on {}", url);

    let options = ReceiverOptions::new()
        .recovery_length_max(Duration::from_millis(1000))
        .fifo_size(1024);

    let receiver = AsyncReceiver::bind_with_options(Profile::Main, &url, options)?;

    let mut total_bytes = 0u64;
    let mut total_packets = 0u64;

    loop {
        match receiver.recv_timeout(Duration::from_secs(1)).await? {
            Some(data) => {
                total_bytes += data.payload().len() as u64;
                total_packets += 1;

                if total_packets % 100 == 0 {
                    println!(
                        "Received {} packets, {} bytes, flow_id={}",
                        total_packets,
                        total_bytes,
                        data.flow_id()
                    );

                    if let Some(stats) = receiver.raw_stats() {
                        println!(
                            "  Stats: quality={:.1}%, rtt={}ms, lost={}",
                            stats.quality, stats.rtt, stats.lost
                        );
                    }
                }
            }
            None => {
                // Timeout, no data received
            }
        }
    }
}
