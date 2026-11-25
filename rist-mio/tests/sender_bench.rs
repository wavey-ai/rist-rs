//! Sender micro-benchmark (ignored by default; run it in release mode):
//!
//! ```text
//! nice -n 15 cargo test -p rist-mio --release --test sender_bench -j8 -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Main profile, product defaults (`RecoveryConfig::default()`), 1316-byte
//! payloads (7 TS packets), send times 31.25 us apart (32k packets/s,
//! about 337 Mbit/s) on a virtual clock. Each case reports the best of 5
//! rounds in ns per packet and the heap allocations per packet (a counting
//! global allocator), after a warm-up past the send history's growth.
//!
//! - `core send_payload`: `MainSenderCore::send_payload` (build only).
//! - `mio send_payload`: `MainMioSender::connect` + `send_payload` to a
//!   loopback UDP sink that is never read (the kernel drops the overflow),
//!   so it includes the syscall.
//!
//! The cases above use only API that existed at rist-rs 904e3e8, so the same
//! file (minus the block marked `new-api`) measures an old checkout. The
//! `new-api` cases measure `send_payload_with` / `send_payload_meta`.
//!
//! Environment: `RIST_SENDER_BENCH_PACKETS` (default 200000 per round).

use rist_core::{CongestionControlMode, MainSenderCore, RecoveryConfig};
use rist_mio::MainMioSender;
use std::alloc::{GlobalAlloc, Layout, System};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

struct Counting;

static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

const PAYLOAD: [u8; 1316] = [0x47; 1316];
const GAP: Duration = Duration::from_nanos(31_250);
const WARM_PACKETS: u64 = 150_000;

fn packets() -> u64 {
    std::env::var("RIST_SENDER_BENCH_PACKETS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(200_000)
}

/// Runs `send` for the warm-up and then for 5 timed rounds; prints the
/// best ns/packet and the allocations per packet over all rounds.
fn measure(name: &str, mut send: impl FnMut(Instant)) {
    let start = Instant::now();
    let mut now = start;
    for _ in 0..WARM_PACKETS {
        now += GAP;
        send(now);
    }
    let packets = packets();
    let mut best = f64::MAX;
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..5 {
        let started = Instant::now();
        for _ in 0..packets {
            now += GAP;
            send(now);
        }
        best = best.min(started.elapsed().as_nanos() as f64 / packets as f64);
    }
    let allocations = ALLOCATIONS.load(Ordering::Relaxed) - before;
    // 1 Gbit/s of 1316-byte payloads is about 95k packets/s.
    let cores_per_gbit = best * 1e9 / (1316.0 * 8.0) / 1e9;
    println!(
        "SENDER case={name:<28} ns_per_packet={best:>8.1} allocs_per_packet={:.3} cores_per_gbit={cores_per_gbit:.3}",
        allocations as f64 / (5 * packets) as f64
    );
}

fn core_sender() -> MainSenderCore {
    let mut sender = MainSenderCore::new(0x1122_3344, 8_192);
    sender.set_recovery_config(RecoveryConfig::default(), CongestionControlMode::Normal);
    sender
}

fn mio_sender() -> (UdpSocket, MainMioSender) {
    let sink = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let local = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let mut sender =
        MainMioSender::connect(local, sink.local_addr().unwrap(), 0x1122_3344, 8_192).unwrap();
    sender.set_recovery_config(RecoveryConfig::default(), CongestionControlMode::Normal);
    (sink, sender)
}

#[test]
#[ignore]
fn sender_path() {
    let mut sender = core_sender();
    measure("core send_payload", |now| {
        std::hint::black_box(sender.send_payload(&PAYLOAD, 0, now));
    });

    let (_sink, mut sender) = mio_sender();
    measure("mio send_payload", |now| {
        std::hint::black_box(sender.send_payload(&PAYLOAD, 0, now).unwrap());
    });

    // BEGIN new-api
    let mut sender = core_sender();
    measure("core send_payload_with", |now| {
        std::hint::black_box(
            sender.send_payload_with(&PAYLOAD, 0, now, |meta, head, body| {
                std::hint::black_box((head, body));
                meta
            }),
        );
    });

    let mut sender = core_sender();
    let mut out = Vec::with_capacity(1_500);
    measure("core send_payload_into", |now| {
        std::hint::black_box(sender.send_payload_into(&PAYLOAD, 0, now, &mut out));
    });

    let (_sink, mut sender) = mio_sender();
    measure("mio send_payload_meta", |now| {
        std::hint::black_box(sender.send_payload_meta(&PAYLOAD, 0, now).unwrap());
    });
    // END new-api
}
