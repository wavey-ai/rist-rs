//! Main sender to Main receiver over loopback through the in-process
//! `LossProxy`, with the product defaults on both ends.
//!
//! The sender is a registered mio source driven only by `send_payload_meta`
//! and `service`; the receiver polls `poll_rtcp_and_send_all`, and its
//! payloads go through `OrderedPayloadBuffer::with_deadline`, as the
//! product's ingest will. Every injected loss must be repaired and the byte
//! stream must come out complete and in order.
//!
//! `RIST_E2E_PACKETS` (default 2000) and `RIST_E2E_DROP_EVERY` (default
//! 20, i.e. 5 %) size a longer run:
//!
//! ```text
//! RIST_E2E_PACKETS=100000 nice -n 15 cargo test -p rist-tools --release --test loopback_e2e -- --nocapture
//! ```

use mio::{Events, Interest, Poll, Token};
use rist_core::packet::rtcp::NackMode;
use rist_core::time::ntp_now;
use rist_core::{CongestionControlMode, OrderedPayloadBuffer, OrderedPush, RecoveryConfig};
use rist_mio::{MainMioReceiver, MainMioSender};
use rist_tools::{LossProxy, LossProxyConfig};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

#[test]
fn main_sender_to_main_receiver_through_loss_proxy() {
    let packets = env_u64("RIST_E2E_PACKETS", 2_000);
    let drop_every = env_u64("RIST_E2E_DROP_EVERY", 20);
    const BURST: u64 = 8;
    const BURST_GAP: Duration = Duration::from_millis(2);
    let flow_id = 0x1122_3344;
    let recovery = RecoveryConfig::default();

    let mut receiver = MainMioReceiver::bind(loopback(), flow_id, "e2e", NackMode::Range).unwrap();
    receiver.set_recovery_config(recovery.clone(), CongestionControlMode::Normal);
    let mut proxy = LossProxy::bind(LossProxyConfig {
        listen: loopback(),
        upstream_bind: loopback(),
        target: receiver.local_addr().unwrap(),
        drop_every,
    })
    .unwrap();
    let mut sender =
        MainMioSender::connect(loopback(), proxy.listen_addr().unwrap(), flow_id, 8_192).unwrap();
    sender.set_recovery_config(recovery, CongestionControlMode::Normal);
    let mut poll = Poll::new().unwrap();
    let mut events = Events::with_capacity(16);
    poll.registry()
        .register(&mut sender, Token(0), Interest::READABLE)
        .unwrap();

    let mut ordered = OrderedPayloadBuffer::with_deadline(65_536, Duration::from_millis(1_100));
    let mut released = Vec::new();
    let mut next_expected = 0u64;
    let mut receiver_buf = vec![0u8; 10_001];
    let mut sender_buf = vec![0u8; 10_001];
    let mut sent = 0u64;
    let mut service_calls = 0u64;
    let start = Instant::now();
    let mut next_burst = start;
    let deadline = start + BURST_GAP * (packets / BURST) as u32 + Duration::from_secs(10);
    while next_expected < packets {
        let now = Instant::now();
        if sent < packets && now >= next_burst {
            for _ in 0..BURST.min(packets - sent) {
                let mut payload = [0x47u8; 1316];
                payload[1..9].copy_from_slice(&sent.to_be_bytes());
                sender.send_payload_meta(&payload, ntp_now(), now).unwrap();
                sent += 1;
            }
            next_burst += BURST_GAP;
        }
        proxy.poll().unwrap();
        while let Some((_from, payload)) = receiver.try_recv_payload(&mut receiver_buf).unwrap() {
            match ordered.push_into(payload, now, &mut released).unwrap() {
                OrderedPush::Released | OrderedPush::Held | OrderedPush::Duplicate => {}
                OrderedPush::Late => panic!("a repair came after its gap was skipped"),
            }
        }
        receiver.poll_rtcp_and_send_all(now, ntp_now()).unwrap();
        ordered.release_expired_into(now, &mut released);
        for payload in released.drain(..) {
            let index = u64::from_be_bytes(payload.payload[1..9].try_into().unwrap());
            assert_eq!(index, next_expected, "out of order");
            next_expected += 1;
        }
        proxy.poll().unwrap();
        let next = sender.service(now, ntp_now(), &mut sender_buf).unwrap();
        service_calls += 1;
        let wait = [next, (sent < packets).then_some(next_burst)]
            .into_iter()
            .flatten()
            .min()
            .map_or(Duration::from_millis(1), |at| {
                at.saturating_duration_since(Instant::now())
            })
            .min(Duration::from_micros(500));
        poll.poll(&mut events, Some(wait)).unwrap();
        assert!(
            Instant::now() < deadline,
            "released {next_expected} of {packets}; proxy {:?}; receiver {:?}; sender {:?}",
            proxy.stats(),
            receiver.stats(),
            sender.stats()
        );
    }
    let proxy_stats = proxy.stats();
    let sender_stats = sender.stats();
    println!(
        "E2E packets={packets} drop_every={drop_every} elapsed_ms={} proxy={proxy_stats:?} \
         ordered={:?} sender_retransmits={} receiver_nacks={}",
        start.elapsed().as_millis(),
        ordered.stats(),
        sender_stats.retransmitted_packets,
        receiver.stats().nack_packets,
    );
    assert_eq!(proxy_stats.injected_drops, packets / drop_every);
    assert!(
        proxy_stats.all_injected_drops_recovered(),
        "{proxy_stats:?}"
    );
    assert_eq!(ordered.skipped_packets(), 0);
    assert_eq!(ordered.late_dropped(), 0);
    assert_eq!(sender_stats.sent_packets, packets);
    assert!(service_calls > 0);
}
