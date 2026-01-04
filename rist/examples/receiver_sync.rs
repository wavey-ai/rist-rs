//! Example synchronous RIST receiver.
//!
//! Run with: cargo run --example receiver_sync

use rist::{Profile, Receiver};
use std::time::Duration;

fn main() -> rist::Result<()> {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "rist://@:5000".to_string());

    println!("Listening on {}", url);

    let mut receiver = Receiver::new(Profile::Main)?;
    receiver.add_peer(&url)?;
    receiver.start()?;

    println!("Receiver started!");

    let mut total_bytes = 0u64;
    let mut total_packets = 0u64;

    loop {
        match receiver.read(Duration::from_secs(1))? {
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
                }
            }
            None => {
                // Timeout, no data received
            }
        }
    }
}
