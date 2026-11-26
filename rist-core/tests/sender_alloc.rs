//! Allocations on the sender's data path, counted by a global allocator
//! (this test binary only). Deterministic: virtual send times.

use rist_core::{CongestionControlMode, MainSenderCore, RecoveryConfig, SimpleSenderCore};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::time::{Duration, Instant};

struct Counting;

thread_local! {
    static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|count| count.set(count.get() + 1));
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.with(|count| count.set(count.get() + 1));
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn allocations() -> u64 {
    ALLOCATIONS.with(Cell::get)
}

const PAYLOAD: [u8; 1316] = [0x47; 1316];
/// 32k packets/s.
const GAP: Duration = Duration::from_nanos(31_250);

fn main_sender() -> MainSenderCore {
    let mut sender = MainSenderCore::new(0x1122_3344, 8_192);
    sender.set_recovery_config(RecoveryConfig::default(), CongestionControlMode::Normal);
    sender
}

/// Sends until the history has wrapped twice at its final size.
fn warm(mut send: impl FnMut(Instant), start: Instant, packets: u64) -> Instant {
    for n in 0..packets {
        send(start + GAP * n as u32);
    }
    start + GAP * packets as u32
}

#[test]
fn main_send_payload_with_allocates_nothing_once_warm() {
    let start = Instant::now();
    let mut sender = main_sender();
    let mut sent = 0usize;
    let t = warm(
        |now| sent += sender.send_payload_with(&PAYLOAD, 0, now, |meta, _, _| meta.len),
        start,
        200_000,
    );
    let capacity = sender.stats().sent_packets;
    assert_eq!(capacity, 200_000);
    let before = allocations();
    for n in 0..20_000u32 {
        sent += sender.send_payload_with(&PAYLOAD, 0, t + GAP * n, |meta, head, body| {
            std::hint::black_box((head, body));
            meta.len
        });
    }
    assert_eq!(allocations() - before, 0);
    assert!(sent > 0);
}

#[test]
fn main_send_payload_into_allocates_nothing_once_warm() {
    let start = Instant::now();
    let mut sender = main_sender();
    let mut out = Vec::with_capacity(1_500);
    let t = warm(
        |now| {
            sender.send_payload_into(&PAYLOAD, 0, now, &mut out);
        },
        start,
        200_000,
    );
    let before = allocations();
    for n in 0..20_000u32 {
        sender.send_payload_into(&PAYLOAD, 0, t + GAP * n, &mut out);
    }
    assert_eq!(allocations() - before, 0);
}

#[test]
fn main_send_payload_allocates_only_the_returned_packet() {
    let start = Instant::now();
    let mut sender = main_sender();
    let t = warm(
        |now| {
            sender.send_payload(&PAYLOAD, 0, now);
        },
        start,
        200_000,
    );
    let before = allocations();
    for n in 0..20_000u32 {
        std::hint::black_box(sender.send_payload(&PAYLOAD, 0, t + GAP * n));
    }
    assert_eq!(allocations() - before, 20_000);
}

#[test]
fn simple_send_payload_with_allocates_nothing_once_warm() {
    let start = Instant::now();
    let mut sender = SimpleSenderCore::new(0x1122_3344, 8_192)
        .with_recovery_config(RecoveryConfig::default(), CongestionControlMode::Normal);
    let t = warm(
        |now| {
            sender.send_payload_with(&PAYLOAD, 0, now, |_, rtp| rtp.len());
        },
        start,
        200_000,
    );
    let before = allocations();
    for n in 0..20_000u32 {
        sender.send_payload_with(&PAYLOAD, 0, t + GAP * n, |sequence, rtp| {
            std::hint::black_box((sequence, rtp));
        });
    }
    assert_eq!(allocations() - before, 0);
    // A disabled history still sends, from the scratch buffer.
    let mut no_history = SimpleSenderCore::new(2, 0);
    let first = no_history.send_payload_with(b"abc", 0, t, |_, rtp| rtp.to_vec());
    assert_eq!(&first[12..], b"abc");
}
