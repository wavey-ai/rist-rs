//! Example RIST sender.
//!
//! Run with: cargo run --example sender --features tokio

use rist::tokio::AsyncSender;
use rist::{Profile, SenderOptions};
use std::time::Duration;

#[tokio::main]
async fn main() -> rist::Result<()> {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "rist://127.0.0.1:5000".to_string());

    println!("Connecting to {}", url);

    let options = SenderOptions::new().recovery_length_max(Duration::from_millis(1000));

    let sender = AsyncSender::connect_with_options(Profile::Main, &url, options).await?;

    println!("Connected!");

    // Send MPEG-TS sized packets
    let payload = vec![0x47u8; 1316]; // TS sync byte + padding
    let mut total_sent = 0u64;

    loop {
        match sender.send(&payload).await {
            Ok(n) => {
                total_sent += n as u64;

                if total_sent % (1316 * 100) == 0 {
                    println!("Sent {} bytes", total_sent);

                    if let Some(stats) = sender.raw_stats() {
                        println!(
                            "  Stats: quality={:.1}%, rtt={}ms, retransmitted={}",
                            stats.quality, stats.rtt, stats.retransmitted
                        );
                    }
                }
            }
            Err(e) => {
                eprintln!("Send error: {}", e);
                break;
            }
        }

        // Send at ~10 Mbps (roughly 950 packets/sec for 1316 byte packets)
        tokio::time::sleep(Duration::from_micros(1050)).await;
    }

    Ok(())
}
