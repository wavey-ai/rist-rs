//! Allocations on the mio Main sender's data path, counted by a global
//! allocator (this test binary only).

use rist_core::{CongestionControlMode, RecoveryConfig};
use rist_mio::MainMioSender;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
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

#[test]
fn send_payload_meta_allocates_nothing_once_warm() {
    let sink = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let local = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let mut sender = MainMioSender::connect(local, sink.local_addr().unwrap(), 2, 8_192).unwrap();
    sender.set_recovery_config(RecoveryConfig::default(), CongestionControlMode::Normal);
    let payload = [0x47u8; 1316];
    let start = Instant::now();
    let gap = Duration::from_nanos(31_250);
    let mut now = start;
    // Past the history's growth (it keeps about 2 s of packets).
    for _ in 0..100_000 {
        now += gap;
        sender.send_payload_meta(&payload, 0, now).unwrap();
        // The sink is never read: its queue overflows, as a slow path would.
    }
    // Hold the clock so no timer comes due while counting.
    assert!(sender.next_timeout().unwrap() > now);
    let before = allocations();
    for _ in 0..20_000 {
        let meta = sender.send_payload_meta(&payload, 0, now).unwrap();
        assert_eq!(meta.len, 12 + 12 + 1316);
    }
    assert_eq!(allocations() - before, 0);
    assert_eq!(sender.pending_send_len(), 0);
}
