//! Allocations on the mio Main receiver's data path, counted by a global
//! allocator (this test binary only).

use rist_core::packet::rtcp::NackMode;
use rist_mio::{MainMioReceiver, MainMioSender};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::net::{Ipv4Addr, SocketAddr};
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

/// An in-order data packet costs one allocation: the payload the receiver
/// hands out (`ReceivedPayload::payload`).
#[test]
fn clear_data_packet_allocates_only_the_payload() {
    let local = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let mut receiver = MainMioReceiver::bind(local, 2, "alloc", NackMode::Range).unwrap();
    let mut sender =
        MainMioSender::connect(local, receiver.local_addr().unwrap(), 2, 1_024).unwrap();
    let payload = [0x47u8; 1316];
    let mut buf = vec![0u8; 10_001];
    let start = Instant::now();
    let mut received = 0u64;
    let mut allocated = 0u64;
    for round in 0..200u32 {
        for n in 0..32u32 {
            let now = start + Duration::from_micros(u64::from(round * 32 + n) * 31);
            sender.send_payload_meta(&payload, 0, now).unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut got = 0;
        while got < 32 {
            let before = allocations();
            let event = receiver.try_recv_payload(&mut buf).unwrap();
            let after = allocations();
            match event {
                Some((_, payload)) => {
                    assert_eq!(payload.payload.len(), 1316);
                    got += 1;
                    if round > 0 {
                        allocated += after - before;
                        received += 1;
                    }
                }
                None => assert!(Instant::now() < deadline, "lost on loopback"),
            }
        }
    }
    assert_eq!(received, 199 * 32);
    assert_eq!(allocated, received, "allocations per data packet");
}
