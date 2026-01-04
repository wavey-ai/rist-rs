//! Example synchronous RIST sender.
//!
//! Run with: cargo run --example sender_sync

use rist::{Profile, Sender};
use std::thread;
use std::time::Duration;

fn main() -> rist::Result<()> {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "rist://127.0.0.1:5000".to_string());

    println!("Connecting to {}", url);

    let mut sender = Sender::new(Profile::Main)?;
    sender.add_peer(&url)?;
    sender.start()?;

    println!("Connected!");

    // Send MPEG-TS sized packets
    let payload = vec![0x47u8; 1316]; // TS sync byte + padding
    let mut total_sent = 0u64;

    loop {
        match sender.send(&payload) {
            Ok(n) => {
                total_sent += n as u64;

                if total_sent % (1316 * 100) == 0 {
                    println!("Sent {} bytes", total_sent);
                }
            }
            Err(e) => {
                eprintln!("Send error: {}", e);
                break;
            }
        }

        // Send at ~10 Mbps (roughly 950 packets/sec for 1316 byte packets)
        thread::sleep(Duration::from_micros(1050));
    }

    Ok(())
}
