//! Receiver micro-benchmark (ignored by default; run it in release mode):
//!
//! ```text
//! nice -n 15 cargo test -p rist-core --release --test receiver_bench -j8 -- --ignored --nocapture
//! ```
//!
//! It feeds paced 2160p160 (~16k packets/s) and 2160p320 (~32k packets/s)
//! traffic with 1 % and 5 % random loss through `SimpleReceiverCore` with the
//! product defaults (`RecoveryConfig::default()`: bandwidth 100000 kbit/s,
//! L 1000 ms, reorder 15 ms, rtt_min 5 ms, rtt_max 500 ms). NACKs are served by
//! a `SimpleSenderCore` and the retransmissions arrive one RTT later (they can
//! be lost too). Only the receiver's own calls (`accept_packet` and
//! `poll_rtcp`) are timed, per 1 ms batch.
//!
//! The file uses only API that already existed at rist-rs 904e3e8, so the same
//! file can be dropped into an old checkout to compare.
//!
//! After the data, a tail (`RIST_BENCH_TAIL_MS`, default 300) keeps polling
//! and delivering repairs without new data, so the final counts show holes
//! that were really not repaired rather than repairs still in flight.
//!
//! Environment: `RIST_BENCH_SECS` (default 30), `RIST_BENCH_RTT_MS` (default
//! 30), `RIST_BENCH_TAIL_MS` (default 300), `RIST_BENCH_CASES` (comma list of
//! case names, default all).

use rist_core::packet::rtcp::NackMode;
use rist_core::time::ntp_now;
use rist_core::{CongestionControlMode, RecoveryConfig, SimpleReceiverCore, SimpleSenderCore};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

const PAYLOAD_BYTES: usize = 1316;

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn lost(&mut self, loss_per_mille: u64) -> bool {
        self.next() % 1000 < loss_per_mille
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn run_case(name: &str, packets_per_second: u64, loss_per_mille: u64) {
    let seconds = env_u64("RIST_BENCH_SECS", 30);
    let rtt = Duration::from_millis(env_u64("RIST_BENCH_RTT_MS", 30));
    let recovery = RecoveryConfig::default();
    let ssrc = 0x5eed_0000;
    let mut sender = SimpleSenderCore::new(ssrc, 1 << 17)
        .with_recovery_config(recovery.clone(), CongestionControlMode::Normal);
    let mut receiver = SimpleReceiverCore::new(ssrc, "bench", NackMode::Range)
        .with_recovery_config(recovery, CongestionControlMode::Normal);
    let payload = vec![0x47_u8; PAYLOAD_BYTES];
    let mut rng = XorShift(0x9e37_79b9_7f4a_7c15 ^ packets_per_second ^ loss_per_mille);
    let mut retransmits: VecDeque<(Instant, Vec<u8>)> = VecDeque::new();
    let mut batch: Vec<Vec<u8>> = Vec::with_capacity(64);

    let data_ticks = seconds * 1000;
    let total_ticks = data_ticks + env_u64("RIST_BENCH_TAIL_MS", 300);
    let start = Instant::now();
    let mut timed = Duration::ZERO;
    let mut accepted = 0_u64;
    let mut data_sent = 0_u64;
    let mut data_lost = 0_u64;
    let mut retransmits_lost = 0_u64;
    let mut feedback_packets = 0_u64;
    let mut max_lag = Duration::ZERO;

    for tick in 0..total_ticks {
        let target = start + Duration::from_millis(tick);
        let now = Instant::now();
        if now < target {
            std::thread::sleep(target - now);
        } else {
            max_lag = max_lag.max(now - target);
        }
        let now = Instant::now();
        let ntp = ntp_now();

        // Untimed: produce this millisecond's packets and due retransmissions.
        batch.clear();
        let count = if tick < data_ticks {
            packets_per_second * (tick + 1) / 1000 - packets_per_second * tick / 1000
        } else {
            0
        };
        for _ in 0..count {
            let packet = sender.send_payload(&payload, ntp, now);
            data_sent += 1;
            if rng.lost(loss_per_mille) {
                data_lost += 1;
            } else {
                batch.push(packet.bytes);
            }
        }
        while retransmits.front().is_some_and(|(at, _)| *at <= now) {
            let (_, bytes) = retransmits.pop_front().unwrap();
            if rng.lost(loss_per_mille) {
                retransmits_lost += 1;
            } else {
                batch.push(bytes);
            }
        }

        // Timed: the receiver's work for this millisecond.
        let t0 = Instant::now();
        for bytes in &batch {
            receiver.accept_packet(bytes).unwrap();
        }
        let feedback = receiver.poll_rtcp(now, ntp);
        timed += t0.elapsed();
        accepted += batch.len() as u64;

        // Untimed: the sender answers, the repairs arrive one RTT later.
        if let Some(feedback) = feedback {
            feedback_packets += 1;
            let retries = sender.handle_feedback_at(&feedback, ntp).unwrap();
            for retry in retries {
                retransmits.push_back((now + rtt, retry.bytes));
            }
        }
    }
    let wall = start.elapsed();
    let stats = receiver.stats();
    let unrecovered = stats
        .total_missing_packets
        .saturating_sub(stats.recovered_packets);
    println!(
        "BENCH case={name} pps={packets_per_second} loss={:.1}% secs={seconds} rtt_ms={} \
         ns_per_packet={:.1} accepted={accepted} timed_ms={:.1} wall_s={:.2} max_lag_ms={:.1} \
         data_sent={data_sent} data_lost={data_lost} retransmits_lost={retransmits_lost} \
         holes={} recovered={} unrecovered_or_open={unrecovered} currently_missing={} \
         duplicates={} rx_feedback_polls={feedback_packets} tx_retransmitted={}",
        loss_per_mille as f64 / 10.0,
        rtt.as_millis(),
        timed.as_nanos() as f64 / accepted.max(1) as f64,
        timed.as_secs_f64() * 1000.0,
        wall.as_secs_f64(),
        max_lag.as_secs_f64() * 1000.0,
        stats.total_missing_packets,
        stats.recovered_packets,
        stats.currently_missing_packets,
        stats.duplicate_packets,
        sender.stats().retransmitted_packets,
    );
}

#[test]
#[ignore = "paced micro-benchmark; run in release with --ignored --nocapture"]
fn receiver_product_defaults_ns_per_packet() {
    let cases: [(&str, u64, u64); 4] = [
        ("2160p160-l1", 16_000, 10),
        ("2160p160-l5", 16_000, 50),
        ("2160p320-l1", 32_000, 10),
        ("2160p320-l5", 32_000, 50),
    ];
    let wanted = std::env::var("RIST_BENCH_CASES").ok();
    for (name, pps, loss) in cases {
        if wanted
            .as_deref()
            .is_some_and(|list| !list.split(',').any(|case| case == name))
        {
            continue;
        }
        run_case(name, pps, loss);
    }
}
