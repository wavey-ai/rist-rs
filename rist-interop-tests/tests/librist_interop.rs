#![forbid(unsafe_code)]
//! End-to-end packet and authentication interoperability with librist.

use rist_core::packet::gre::{BufferNegotiation, GreKeepalive};
use rist_core::packet::rtcp::{
    encode_echo, encode_empty_receiver_report, encode_sdes_cname, Echo, EchoKind, NackMode,
};
use rist_core::time::ntp_now;
use rist_core::{PskKey, SrpCredentialStore};
use rist_mio::{MainMioReceiver, MainMioSender, SimpleMioReceiver, SimpleMioSender};
use rist_tools::{LossProxy, LossProxyConfig};
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

static INTEROP_MUTEX: Mutex<()> = Mutex::new(());

fn lock_interop() -> std::sync::MutexGuard<'static, ()> {
    INTEROP_MUTEX
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn loopback_any() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
}

fn ipv6_loopback_any() -> SocketAddr {
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))
}

fn next_even_test_port_pair() -> u16 {
    next_even_test_port_pair_for(loopback_any())
}

fn next_even_ipv6_test_port_pair() -> u16 {
    next_even_test_port_pair_for(ipv6_loopback_any())
}

fn next_even_test_port_pair_for(local: SocketAddr) -> u16 {
    for _ in 0..128 {
        let socket = UdpSocket::bind(local).expect("failed to allocate UDP port");
        let port = socket.local_addr().unwrap().port();
        drop(socket);

        let base = if port % 2 == 0 {
            port
        } else {
            port.saturating_add(1)
        };
        if base == u16::MAX {
            continue;
        }

        let mut rtp_addr = local;
        rtp_addr.set_port(base);
        let mut rtcp_addr = local;
        rtcp_addr.set_port(base + 1);
        if let (Ok(_rtp), Ok(_rtcp)) = (UdpSocket::bind(rtp_addr), UdpSocket::bind(rtcp_addr)) {
            return base;
        }
    }

    panic!("failed to allocate even UDP port pair");
}

fn interop_enabled() -> bool {
    std::env::var_os("RIST_INTEROP").is_some()
}

#[test]
fn pure_rust_simple_sender_to_librist_receiver() {
    if !interop_enabled() {
        return;
    }
    let _guard = lock_interop();

    let port = next_even_test_port_pair();
    let receiver_url = format!("rist://@127.0.0.1:{port}");
    let receiver_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));

    let mut receiver = rist::Receiver::new(rist::Profile::Simple).unwrap();
    receiver.add_peer(&receiver_url).unwrap();
    receiver.start().unwrap();

    let sender_port = next_even_test_port_pair();
    let sender_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, sender_port));
    let mut sender = SimpleMioSender::connect(sender_addr, receiver_addr, 0x1122_3344, 64).unwrap();
    let payload = mpegts_payload_7("PURE RUST TO LIBRIST");
    sender.send_rtcp(&simple_rtcp_probe(0x1122_3344)).unwrap();
    thread::sleep(Duration::from_millis(20));
    for sequence in 1..=20 {
        let packet =
            sender.build_payload_with_sequence(sequence, &payload, ntp_now(), Instant::now());
        sender.send_outbound(&packet).unwrap();
        thread::sleep(Duration::from_millis(10));
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(block) = receiver.read(Duration::from_millis(50)).unwrap() {
            assert!(block.payload().starts_with(&[0x47]));
            assert!(block
                .payload()
                .windows(b"PURE RUST TO LIBRIST".len())
                .any(|window| window == b"PURE RUST TO LIBRIST"));
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for librist receiver"
        );
    }
}

fn simple_rtcp_probe(ssrc: u32) -> Vec<u8> {
    let mut packet = Vec::new();
    encode_empty_receiver_report(ssrc, &mut packet);
    encode_sdes_cname(ssrc, "rust", &mut packet);
    encode_echo(
        Echo {
            ssrc,
            ntp_timestamp: ntp_now(),
            kind: EchoKind::Request,
        },
        &mut packet,
    );
    packet
}

#[test]
fn librist_simple_sender_to_pure_rust_receiver() {
    if !interop_enabled() {
        return;
    }
    let _guard = lock_interop();
    let flow_id = 0x1122_3344;
    let receiver_port = next_even_test_port_pair();
    let receiver_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, receiver_port));
    let mut receiver =
        SimpleMioReceiver::bind(receiver_addr, flow_id, "rust", NackMode::Range).unwrap();
    let receiver_addr = receiver.local_addr().unwrap();
    let sender_url = format!("rist://127.0.0.1:{}", receiver_addr.port());

    let mut sender = rist::Sender::new(rist::Profile::Simple).unwrap();
    sender.add_peer(&sender_url).unwrap();
    sender.start().unwrap();

    let payload = mpegts_payload("LIBRIST TO PURE RUST");
    for _ in 0..5 {
        sender.send(&payload).unwrap();
        thread::sleep(Duration::from_millis(10));
    }

    let mut buf = [0; 1500];
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some((_from, received)) = receiver.try_recv_payload(&mut buf).unwrap() {
            assert!(received.payload.starts_with(&[0x47]));
            assert!(received
                .payload
                .windows(b"LIBRIST TO PURE RUST".len())
                .any(|window| window == b"LIBRIST TO PURE RUST"));
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for pure Rust receiver"
        );
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn librist_simple_sender_to_pure_rust_ipv6_receiver() {
    if !interop_enabled() {
        return;
    }
    let _guard = lock_interop();

    let flow_id = 0x1122_3344;
    let port = next_even_ipv6_test_port_pair();
    let receiver_addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0));
    let mut receiver =
        SimpleMioReceiver::bind(receiver_addr, flow_id, "rust", NackMode::Range).unwrap();
    let sender_url = format!("rist://[::1]:{port}");
    let mut sender = rist::Sender::new(rist::Profile::Simple).unwrap();
    sender.add_peer(&sender_url).unwrap();
    sender.start().unwrap();

    let payload = mpegts_payload("LIBRIST SIMPLE IPV6 TO PURE RUST");
    for _ in 0..5 {
        sender.send(&payload).unwrap();
        thread::sleep(Duration::from_millis(10));
    }

    let mut buf = [0u8; 1500];
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some((from, received)) = receiver.try_recv_payload(&mut buf).unwrap() {
            assert!(from.is_ipv6());
            assert!(received
                .payload
                .windows(b"LIBRIST SIMPLE IPV6 TO PURE RUST".len())
                .any(|window| window == b"LIBRIST SIMPLE IPV6 TO PURE RUST"));
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for the pure Rust Simple IPv6 receiver"
        );
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn pure_rust_main_sender_to_librist_receiver() {
    if !interop_enabled() {
        return;
    }
    let _guard = lock_interop();

    let port = next_even_test_port_pair();
    let receiver_url = format!("rist://@127.0.0.1:{port}");
    let receiver_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));

    let mut receiver = rist::Receiver::new(rist::Profile::Main).unwrap();
    receiver.add_peer(&receiver_url).unwrap();
    receiver.start().unwrap();

    let mut sender =
        MainMioSender::connect(loopback_any(), receiver_addr, 0x1122_3344, 64).unwrap();
    send_main_session_probe(&mut sender);

    let payload = mpegts_payload_7("PURE RUST MAIN TO LIBRIST");
    for _ in 0..20 {
        sender
            .send_payload(&payload, ntp_now(), Instant::now())
            .unwrap();
        thread::sleep(Duration::from_millis(10));
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(block) = receiver.read(Duration::from_millis(50)).unwrap() {
            assert!(block.payload().starts_with(&[0x47]));
            assert!(block
                .payload()
                .windows(b"PURE RUST MAIN TO LIBRIST".len())
                .any(|window| window == b"PURE RUST MAIN TO LIBRIST"));
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for librist Main receiver"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
#[allow(clippy::await_holding_lock)] // The whole interop suite is intentionally serialized.
async fn pure_rust_main_sender_to_async_librist_receiver() {
    if !interop_enabled() {
        return;
    }
    let _guard = lock_interop();

    let port = next_even_test_port_pair();
    let receiver_url = format!("rist://@127.0.0.1:{port}");
    let receiver_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));

    let receiver = rist::tokio::AsyncReceiver::bind(rist::Profile::Main, &receiver_url).unwrap();

    let mut sender =
        MainMioSender::connect(loopback_any(), receiver_addr, 0x1122_3344, 64).unwrap();
    send_main_session_probe(&mut sender);

    let payload = mpegts_payload_7("PURE RUST MAIN TO ASYNC LIBRIST");
    for _ in 0..20 {
        sender
            .send_payload(&payload, ntp_now(), Instant::now())
            .unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(block) = receiver
            .recv_timeout(Duration::from_millis(50))
            .await
            .unwrap()
        {
            assert!(block.payload().starts_with(&[0x47]));
            assert!(block
                .payload()
                .windows(b"PURE RUST MAIN TO ASYNC LIBRIST".len())
                .any(|window| window == b"PURE RUST MAIN TO ASYNC LIBRIST"));
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for async librist Main receiver"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

#[tokio::test(flavor = "current_thread")]
#[allow(clippy::await_holding_lock)] // The whole interop suite is intentionally serialized.
async fn av_contrib_style_main_sender_to_async_librist_receiver() {
    if !interop_enabled() {
        return;
    }
    let _guard = lock_interop();

    let flow_id = 0x1122_3344;
    let port = next_even_test_port_pair();
    let receiver_url = format!("rist://@127.0.0.1:{port}");
    let receiver_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));

    let receiver = rist::tokio::AsyncReceiver::bind(rist::Profile::Main, &receiver_url).unwrap();

    let mut sender = MainMioSender::connect(loopback_any(), receiver_addr, flow_id, 8192).unwrap();
    send_main_session_probe(&mut sender);

    let payload = mpegts_payload_7("AV CONTRIB STYLE RUST TO ASYNC LIBRIST");
    let mut feedback_buf = [0u8; 65_536];
    for _ in 0..20 {
        sender
            .send_payload(&payload, ntp_now(), Instant::now())
            .unwrap();
        sender
            .try_recv_feedback_and_retransmit(&mut feedback_buf)
            .unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(block) = receiver
            .recv_timeout(Duration::from_millis(50))
            .await
            .unwrap()
        {
            assert!(block.payload().starts_with(&[0x47]));
            assert!(block
                .payload()
                .windows(b"AV CONTRIB STYLE RUST TO ASYNC LIBRIST".len())
                .any(|window| window == b"AV CONTRIB STYLE RUST TO ASYNC LIBRIST"));
            return;
        }

        assert!(
            Instant::now() < deadline,
            "timed out waiting for av-contrib-style async librist Main receiver"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

#[test]
fn librist_main_sender_to_pure_rust_receiver() {
    if !interop_enabled() {
        return;
    }
    let _guard = lock_interop();

    let flow_id = 0x1122_3344;
    let receiver_port = next_even_test_port_pair();
    let receiver_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, receiver_port));
    let mut receiver =
        MainMioReceiver::bind(receiver_addr, flow_id, "rust", NackMode::Range).unwrap();
    let receiver_addr = receiver.local_addr().unwrap();
    let sender_url = format!("rist://127.0.0.1:{}", receiver_addr.port());

    let mut sender = rist::Sender::new(rist::Profile::Main).unwrap();
    sender.add_peer(&sender_url).unwrap();
    sender.start().unwrap();

    let payload = mpegts_payload_7("LIBRIST MAIN TO PURE RUST");
    for _ in 0..20 {
        sender.send(&payload).unwrap();
        thread::sleep(Duration::from_millis(10));
    }

    let mut buf = [0; 1500];
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some((_from, received)) = receiver.try_recv_payload(&mut buf).unwrap() {
            assert!(received.payload.starts_with(&[0x47]));
            assert!(received
                .payload
                .windows(b"LIBRIST MAIN TO PURE RUST".len())
                .any(|window| window == b"LIBRIST MAIN TO PURE RUST"));
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for pure Rust Main receiver"
        );
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn librist_main_sender_recovers_every_injected_loss_for_pure_rust_receiver() {
    if !interop_enabled() {
        return;
    }
    let _guard = lock_interop();

    const PACKETS: u8 = 21;
    const DROP_EVERY: u64 = 5;

    let flow_id = 0x1122_3344;
    let receiver_port = next_even_test_port_pair();
    let receiver_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, receiver_port));
    let mut receiver =
        MainMioReceiver::bind(receiver_addr, flow_id, "rust-loss", NackMode::Range).unwrap();
    let mut proxy = LossProxy::bind(LossProxyConfig {
        listen: loopback_any(),
        upstream_bind: loopback_any(),
        target: receiver.local_addr().unwrap(),
        drop_every: DROP_EVERY,
    })
    .unwrap();
    let sender_url = format!("rist://{}", proxy.listen_addr().unwrap());
    let mut sender = rist::Sender::new(rist::Profile::Main).unwrap();
    sender.add_peer(&sender_url).unwrap();
    sender.start().unwrap();

    for sequence in 0..PACKETS {
        sender.send(&[sequence; 1_316]).unwrap();
        proxy.poll().unwrap();
        thread::sleep(Duration::from_millis(2));
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut received = HashSet::new();
    let mut receiver_buf = vec![0; 65_536];
    while received.len() < usize::from(PACKETS) {
        proxy.poll().unwrap();
        while let Some((_from, payload)) = receiver.try_recv_payload(&mut receiver_buf).unwrap() {
            assert_eq!(payload.payload.len(), 1_316);
            received.insert(payload.payload[0]);
        }
        receiver
            .poll_rtcp_and_send(Instant::now(), ntp_now())
            .unwrap();
        proxy.poll().unwrap();

        assert!(
            Instant::now() < deadline,
            "timed out after receiving {} of {PACKETS} payloads; proxy={:?}, receiver={:?}",
            received.len(),
            proxy.stats(),
            receiver.stats()
        );
        thread::sleep(Duration::from_millis(1));
    }

    assert_eq!(proxy.stats().injected_drops, 4);
    assert_eq!(proxy.stats().recovered_forwards, 4);
    assert!(proxy.stats().all_injected_drops_recovered());
    let peer = receiver
        .peer_addr()
        .expect("pure receiver lost the proxy peer");
    let flow_stats = receiver
        .peer_flow_ids(peer)
        .unwrap()
        .into_iter()
        .filter_map(|flow_id| {
            receiver
                .peer_flow_stats(peer, flow_id)
                .map(|stats| (flow_id, stats))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        flow_stats
            .iter()
            .map(|(_, stats)| stats.received_packets)
            .sum::<u64>(),
        u64::from(PACKETS),
        "unexpected C media flow statistics: {flow_stats:?}"
    );
    assert_eq!(
        flow_stats
            .iter()
            .map(|(_, stats)| stats.recovered_packets)
            .sum::<u64>(),
        4,
        "unexpected C media recovery statistics: {flow_stats:?}"
    );
    assert_eq!(
        flow_stats
            .iter()
            .map(|(_, stats)| stats.currently_missing_packets)
            .sum::<u64>(),
        0,
        "C media flows retained missing packets: {flow_stats:?}"
    );
}

#[test]
fn pure_rust_main_sender_to_librist_ipv6_receiver() {
    if !interop_enabled() {
        return;
    }
    let _guard = lock_interop();

    let flow_id = 0x1122_3344;
    let port = next_even_ipv6_test_port_pair();
    let receiver_url = format!("rist://@[::1]:{port}");
    let receiver_addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0));
    let mut receiver = rist::Receiver::new(rist::Profile::Main).unwrap();
    receiver.add_peer(&receiver_url).unwrap();
    receiver.start().unwrap();

    let mut sender =
        MainMioSender::connect(ipv6_loopback_any(), receiver_addr, flow_id, 64).unwrap();
    send_main_session_probe(&mut sender);
    let payload = mpegts_payload_7("PURE RUST MAIN IPV6 TO LIBRIST");
    for _ in 0..20 {
        sender
            .send_payload(&payload, ntp_now(), Instant::now())
            .unwrap();
        thread::sleep(Duration::from_millis(10));
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(block) = receiver.read(Duration::from_millis(50)).unwrap() {
            assert!(block
                .payload()
                .windows(b"PURE RUST MAIN IPV6 TO LIBRIST".len())
                .any(|window| window == b"PURE RUST MAIN IPV6 TO LIBRIST"));
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for the librist Main IPv6 receiver"
        );
    }
}

#[test]
fn librist_main_sender_to_pure_rust_ipv6_receiver() {
    if !interop_enabled() {
        return;
    }
    let _guard = lock_interop();

    let flow_id = 0x1122_3344;
    let port = next_even_ipv6_test_port_pair();
    let receiver_addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0));
    let mut receiver =
        MainMioReceiver::bind(receiver_addr, flow_id, "rust", NackMode::Range).unwrap();
    let sender_url = format!("rist://[::1]:{port}");
    let mut sender = rist::Sender::new(rist::Profile::Main).unwrap();
    sender.add_peer(&sender_url).unwrap();
    sender.start().unwrap();

    let payload = mpegts_payload_7("LIBRIST MAIN IPV6 TO PURE RUST");
    for _ in 0..20 {
        sender.send(&payload).unwrap();
        thread::sleep(Duration::from_millis(10));
    }

    let mut buf = [0u8; 1500];
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some((from, received)) = receiver.try_recv_payload(&mut buf).unwrap() {
            assert!(from.is_ipv6());
            assert!(received
                .payload
                .windows(b"LIBRIST MAIN IPV6 TO PURE RUST".len())
                .any(|window| window == b"LIBRIST MAIN IPV6 TO PURE RUST"));
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for the pure Rust Main IPv6 receiver"
        );
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn librist_main_receiver_caller_from_pure_rust_sender_listener() {
    if !interop_enabled() {
        return;
    }
    let _guard = lock_interop();

    let flow_id = 0x1122_3344;
    let sender_port = next_even_test_port_pair();
    let sender_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, sender_port));
    let mut sender = MainMioSender::listen(sender_addr, flow_id, 64).unwrap();
    let receiver_url = format!("rist://127.0.0.1:{sender_port}");
    let mut receiver = rist::Receiver::new(rist::Profile::Main).unwrap();
    receiver.add_peer(&receiver_url).unwrap();
    receiver.start().unwrap();

    let mut control_buf = [0u8; 1500];
    let discovery_deadline = Instant::now() + Duration::from_secs(5);
    while sender.peer_addr().is_none() {
        sender.try_recv_event(&mut control_buf).unwrap();
        assert!(
            Instant::now() < discovery_deadline,
            "timed out waiting for the librist Main receiver caller"
        );
        thread::sleep(Duration::from_millis(1));
    }
    send_main_session_probe(&mut sender);

    let payload = mpegts_payload_7("LIBRIST MAIN CALLER FROM RUST LISTENER");
    for _ in 0..20 {
        sender
            .send_payload(&payload, ntp_now(), Instant::now())
            .unwrap();
        thread::sleep(Duration::from_millis(10));
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(block) = receiver.read(Duration::from_millis(50)).unwrap() {
            assert!(block
                .payload()
                .windows(b"LIBRIST MAIN CALLER FROM RUST LISTENER".len())
                .any(|window| window == b"LIBRIST MAIN CALLER FROM RUST LISTENER"));
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for the librist Main receiver caller"
        );
    }
}

#[test]
fn pure_rust_main_receiver_caller_from_librist_sender_listener() {
    if !interop_enabled() {
        return;
    }
    let _guard = lock_interop();

    let flow_id = 0x1122_3344;
    let sender_port = next_even_test_port_pair();
    let sender_url = format!("rist://@127.0.0.1:{sender_port}");
    let sender_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, sender_port));
    let mut sender = rist::Sender::new(rist::Profile::Main).unwrap();
    sender.add_peer(&sender_url).unwrap();
    sender.start().unwrap();

    let mut receiver = MainMioReceiver::connect(
        loopback_any(),
        sender_addr,
        flow_id,
        "rust",
        NackMode::Range,
    )
    .unwrap();
    receiver
        .send_keepalive_to(
            sender_addr,
            GreKeepalive::librist_default([1, 2, 3, 4, 5, 6]),
        )
        .unwrap();
    let now = Instant::now();
    receiver.poll_rtcp_and_send(now, ntp_now()).unwrap();
    receiver
        .poll_rtcp_and_send(now + Duration::from_secs(1), ntp_now())
        .unwrap();
    thread::sleep(Duration::from_millis(20));

    let payload = mpegts_payload_7("RUST MAIN CALLER FROM LIBRIST LISTENER");
    for _ in 0..20 {
        sender.send(&payload).unwrap();
        thread::sleep(Duration::from_millis(10));
    }

    let mut buf = [0u8; 1500];
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some((_from, received)) = receiver.try_recv_payload(&mut buf).unwrap() {
            assert!(received
                .payload
                .windows(b"RUST MAIN CALLER FROM LIBRIST LISTENER".len())
                .any(|window| window == b"RUST MAIN CALLER FROM LIBRIST LISTENER"));
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for the pure Rust Main receiver caller"
        );
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn librist_main_receiver_caller_srp_to_pure_rust_sender_listener() {
    if !interop_enabled() {
        return;
    }
    let _guard = lock_interop();

    let flow_id = 0x1122_3344;
    let sender_port = next_even_test_port_pair();
    let sender_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, sender_port));
    let mut sender = MainMioSender::listen(sender_addr, flow_id, 64).unwrap();
    sender.set_tx_key(PskKey::new(128, b"12345678").unwrap());
    sender.set_rx_key(PskKey::receiver(128, b"12345678").unwrap());
    let mut store = SrpCredentialStore::new();
    store.stage_password("testuser", b"testpassword").unwrap();
    sender.enable_srp_authenticator(store);

    let receiver_url = format!(
        "rist://127.0.0.1:{sender_port}?secret=12345678&aes-type=128&username=testuser&password=testpassword"
    );
    let mut receiver = rist::Receiver::new(rist::Profile::Main).unwrap();
    receiver.add_peer(&receiver_url).unwrap();
    receiver.start().unwrap();

    drive_main_sender_srp_authenticator(&mut sender);
    assert!(sender.srp_authenticated());
    send_main_session_probe(&mut sender);

    let payload = mpegts_payload_7("LIBRIST SRP CALLER FROM RUST LISTENER");
    for _ in 0..20 {
        sender
            .send_payload(&payload, ntp_now(), Instant::now())
            .unwrap();
        thread::sleep(Duration::from_millis(10));
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(block) = receiver.read(Duration::from_millis(50)).unwrap() {
            assert!(block
                .payload()
                .windows(b"LIBRIST SRP CALLER FROM RUST LISTENER".len())
                .any(|window| window == b"LIBRIST SRP CALLER FROM RUST LISTENER"));
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for the SRP-authenticated librist receiver caller"
        );
    }
}

#[test]
fn pure_rust_main_receiver_caller_srp_to_librist_sender_listener() {
    if !interop_enabled() {
        return;
    }
    let _guard = lock_interop();

    let flow_id = 0x1122_3344;
    let sender_port = next_even_test_port_pair();
    let sender_url = format!(
        "rist://@127.0.0.1:{sender_port}?secret=12345678&aes-type=128&username=testuser&password=testpassword"
    );
    let sender_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, sender_port));
    let mut sender = rist::Sender::new(rist::Profile::Main).unwrap();
    sender.add_peer(&sender_url).unwrap();
    sender.start().unwrap();

    let mut receiver = MainMioReceiver::connect(
        loopback_any(),
        sender_addr,
        flow_id,
        "rust",
        NackMode::Range,
    )
    .unwrap();
    receiver.set_tx_key(PskKey::new(128, b"12345678").unwrap());
    receiver.set_rx_key(PskKey::receiver(128, b"12345678").unwrap());
    receiver.enable_srp_client("testuser", b"testpassword");
    receiver
        .send_keepalive_to(
            sender_addr,
            GreKeepalive::librist_default([1, 2, 3, 4, 5, 6]),
        )
        .unwrap();
    receiver.start_srp_authentication().unwrap();
    drive_main_receiver_srp_client(&mut receiver);
    assert!(receiver.srp_authenticated());
    send_main_receiver_session_probe(&mut receiver, sender_addr);

    let payload = mpegts_payload_7("RUST SRP CALLER FROM LIBRIST LISTENER");
    for _ in 0..20 {
        sender.send(&payload).unwrap();
        thread::sleep(Duration::from_millis(10));
    }

    let mut buf = [0u8; 1500];
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some((_from, received)) = receiver.try_recv_payload(&mut buf).unwrap() {
            assert!(received
                .payload
                .windows(b"RUST SRP CALLER FROM LIBRIST LISTENER".len())
                .any(|window| window == b"RUST SRP CALLER FROM LIBRIST LISTENER"));
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for the SRP-authenticated pure Rust receiver caller"
        );
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn pure_rust_main_aes_sender_to_librist_receiver() {
    if !interop_enabled() {
        return;
    }
    let _guard = lock_interop();

    let port = next_even_test_port_pair();
    let receiver_url = format!("rist://@127.0.0.1:{port}?secret=12345678&aes-type=128");
    let receiver_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));

    let mut receiver = rist::Receiver::new(rist::Profile::Main).unwrap();
    receiver.add_peer(&receiver_url).unwrap();
    receiver.start().unwrap();

    let mut sender =
        MainMioSender::connect(loopback_any(), receiver_addr, 0x1122_3344, 64).unwrap();
    sender.set_tx_key(PskKey::new(128, b"12345678").unwrap());
    sender.set_rx_key(PskKey::receiver(128, b"12345678").unwrap());
    send_main_session_probe(&mut sender);

    let payload = mpegts_payload_7("PURE RUST AES TO LIBRIST");
    for _ in 0..20 {
        sender
            .send_payload(&payload, ntp_now(), Instant::now())
            .unwrap();
        thread::sleep(Duration::from_millis(10));
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(block) = receiver.read(Duration::from_millis(50)).unwrap() {
            assert!(block.payload().starts_with(&[0x47]));
            assert!(block
                .payload()
                .windows(b"PURE RUST AES TO LIBRIST".len())
                .any(|window| window == b"PURE RUST AES TO LIBRIST"));
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for encrypted librist Main receiver"
        );
    }
}

#[test]
fn librist_main_aes_sender_to_pure_rust_receiver() {
    if !interop_enabled() {
        return;
    }
    let _guard = lock_interop();

    let flow_id = 0x1122_3344;
    let receiver_port = next_even_test_port_pair();
    let receiver_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, receiver_port));
    let mut receiver =
        MainMioReceiver::bind(receiver_addr, flow_id, "rust", NackMode::Range).unwrap();
    receiver.set_tx_key(PskKey::new(128, b"12345678").unwrap());
    receiver.set_rx_key(PskKey::receiver(128, b"12345678").unwrap());
    let receiver_addr = receiver.local_addr().unwrap();
    let sender_url = format!(
        "rist://127.0.0.1:{}?secret=12345678&aes-type=128",
        receiver_addr.port()
    );

    let mut sender = rist::Sender::new(rist::Profile::Main).unwrap();
    sender.add_peer(&sender_url).unwrap();
    sender.start().unwrap();

    let payload = mpegts_payload_7("LIBRIST AES TO PURE RUST");
    for _ in 0..20 {
        sender.send(&payload).unwrap();
        thread::sleep(Duration::from_millis(10));
    }

    let mut buf = [0; 1500];
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some((_from, received)) = receiver.try_recv_payload(&mut buf).unwrap() {
            assert!(received.payload.starts_with(&[0x47]));
            assert!(received
                .payload
                .windows(b"LIBRIST AES TO PURE RUST".len())
                .any(|window| window == b"LIBRIST AES TO PURE RUST"));
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for encrypted pure Rust Main receiver"
        );
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn pure_rust_main_aes_sender_wrong_secret_does_not_reach_librist_receiver() {
    if !interop_enabled() {
        return;
    }
    let _guard = lock_interop();

    let port = next_even_test_port_pair();
    let receiver_url = format!("rist://@127.0.0.1:{port}?secret=12345678&aes-type=128");
    let receiver_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));

    let mut receiver = rist::Receiver::new(rist::Profile::Main).unwrap();
    receiver.add_peer(&receiver_url).unwrap();
    receiver.start().unwrap();

    let mut sender =
        MainMioSender::connect(loopback_any(), receiver_addr, 0x1122_3344, 64).unwrap();
    sender.set_tx_key(PskKey::new(128, b"wrongpass").unwrap());
    send_main_session_probe(&mut sender);

    let payload = mpegts_payload_7("WRONG SECRET TO LIBRIST");
    for _ in 0..5 {
        sender
            .send_payload(&payload, ntp_now(), Instant::now())
            .unwrap();
        thread::sleep(Duration::from_millis(10));
    }

    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        assert!(
            receiver.read(Duration::from_millis(50)).unwrap().is_none(),
            "librist receiver delivered payload encrypted with the wrong secret"
        );
        if Instant::now() >= deadline {
            return;
        }
    }
}

#[test]
fn librist_main_aes_sender_wrong_secret_does_not_reach_pure_rust_receiver() {
    if !interop_enabled() {
        return;
    }
    let _guard = lock_interop();

    let flow_id = 0x1122_3344;
    let receiver_port = next_even_test_port_pair();
    let receiver_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, receiver_port));
    let mut receiver =
        MainMioReceiver::bind(receiver_addr, flow_id, "rust", NackMode::Range).unwrap();
    receiver.set_rx_key(PskKey::receiver(128, b"wrongpass").unwrap());
    let receiver_addr = receiver.local_addr().unwrap();
    let sender_url = format!(
        "rist://127.0.0.1:{}?secret=12345678&aes-type=128",
        receiver_addr.port()
    );

    let mut sender = rist::Sender::new(rist::Profile::Main).unwrap();
    sender.add_peer(&sender_url).unwrap();
    sender.start().unwrap();

    let payload = mpegts_payload_7("LIBRIST WRONG SECRET");
    for _ in 0..5 {
        sender.send(&payload).unwrap();
        thread::sleep(Duration::from_millis(10));
    }

    let mut buf = [0; 1500];
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        match receiver.try_recv_payload(&mut buf) {
            Ok(Some((_from, received))) => {
                panic!(
                    "pure Rust receiver delivered wrong-secret payload: {:02x?}",
                    &received.payload[..received.payload.len().min(16)]
                );
            }
            Ok(None) => {}
            Err(err) if err.kind() == std::io::ErrorKind::InvalidData => {}
            Err(err) => panic!("unexpected receive error: {err}"),
        }
        if Instant::now() >= deadline {
            return;
        }
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn pure_rust_main_srp_client_sends_payload_to_librist_receiver() {
    if !interop_enabled() {
        return;
    }
    let _guard = lock_interop();

    let port = next_even_test_port_pair();
    let receiver_url = format!(
        "rist://@127.0.0.1:{port}?secret=12345678&aes-type=128&username=testuser&password=testpassword"
    );
    let receiver_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));

    let mut receiver = rist::Receiver::new(rist::Profile::Main).unwrap();
    receiver.add_peer(&receiver_url).unwrap();
    receiver.start().unwrap();

    let mut sender =
        MainMioSender::connect(loopback_any(), receiver_addr, 0x1122_3344, 64).unwrap();
    sender.set_tx_key(PskKey::new(128, b"12345678").unwrap());
    sender.set_rx_key(PskKey::receiver(128, b"12345678").unwrap());
    sender.enable_srp_client("testuser", b"testpassword");
    sender
        .send_keepalive(GreKeepalive::librist_default([1, 2, 3, 4, 5, 6]))
        .unwrap();
    thread::sleep(Duration::from_millis(20));
    sender.start_srp_authentication().unwrap();
    drive_main_srp_client(&mut sender);
    assert!(sender.srp_authenticated());

    send_main_session_probe(&mut sender);
    let payload = mpegts_payload_7("PURE RUST SRP TO LIBRIST");
    for _ in 0..20 {
        sender
            .send_payload(&payload, ntp_now(), Instant::now())
            .unwrap();
        thread::sleep(Duration::from_millis(10));
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(block) = receiver.read(Duration::from_millis(50)).unwrap() {
            assert!(block.payload().starts_with(&[0x47]));
            assert!(block
                .payload()
                .windows(b"PURE RUST SRP TO LIBRIST".len())
                .any(|window| window == b"PURE RUST SRP TO LIBRIST"));
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for SRP-authenticated librist Main receiver"
        );
    }
}

#[test]
fn librist_main_srp_client_sends_payload_to_pure_rust_receiver() {
    if !interop_enabled() {
        return;
    }
    let _guard = lock_interop();

    let flow_id = 0x1122_3344;
    let receiver_port = next_even_test_port_pair();
    let receiver_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, receiver_port));
    let mut receiver =
        MainMioReceiver::bind(receiver_addr, flow_id, "rust", NackMode::Range).unwrap();
    receiver.set_rx_key(PskKey::receiver(128, b"12345678").unwrap());
    let mut store = SrpCredentialStore::new();
    store.stage_password("testuser", b"testpassword").unwrap();
    receiver.enable_srp_authenticator(store);
    let receiver_addr = receiver.local_addr().unwrap();

    let sender_url = format!(
        "rist://127.0.0.1:{}?secret=12345678&aes-type=128&username=testuser&password=testpassword",
        receiver_addr.port()
    );
    let mut sender = rist::Sender::new(rist::Profile::Main).unwrap();
    sender.add_peer(&sender_url).unwrap();
    sender.start().unwrap();

    drive_main_srp_authenticator(&mut receiver);
    assert!(receiver.srp_authenticated());

    let payload = mpegts_payload_7("LIBRIST SRP TO PURE RUST");
    for _ in 0..20 {
        sender.send(&payload).unwrap();
        thread::sleep(Duration::from_millis(10));
    }

    let mut buf = [0; 1500];
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some((_from, received)) = receiver.try_recv_payload(&mut buf).unwrap() {
            assert!(received.payload.starts_with(&[0x47]));
            assert!(received
                .payload
                .windows(b"LIBRIST SRP TO PURE RUST".len())
                .any(|window| window == b"LIBRIST SRP TO PURE RUST"));
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for SRP-authenticated pure Rust Main receiver"
        );
        thread::sleep(Duration::from_millis(1));
    }
}

fn send_main_session_probe(sender: &mut MainMioSender) {
    sender
        .send_keepalive(GreKeepalive::librist_default([1, 2, 3, 4, 5, 6]))
        .unwrap();
    sender
        .send_buffer_negotiation(BufferNegotiation::session(1000, 250))
        .unwrap();
    let now = Instant::now();
    sender.poll_rtcp_and_send(now, ntp_now()).unwrap();
    sender
        .poll_rtcp_and_send(now + Duration::from_secs(1), ntp_now())
        .unwrap();
    thread::sleep(Duration::from_millis(20));
}

fn send_main_receiver_session_probe(receiver: &mut MainMioReceiver, peer: SocketAddr) {
    receiver
        .send_keepalive_to(peer, GreKeepalive::librist_default([1, 2, 3, 4, 5, 6]))
        .unwrap();
    receiver
        .send_buffer_negotiation_to(peer, BufferNegotiation::session(1000, 250))
        .unwrap();
    let now = Instant::now();
    receiver.poll_rtcp_and_send(now, ntp_now()).unwrap();
    receiver
        .poll_rtcp_and_send(now + Duration::from_secs(1), ntp_now())
        .unwrap();
    thread::sleep(Duration::from_millis(20));
}

fn drive_main_srp_client(sender: &mut MainMioSender) {
    let mut buf = [0; 1500];
    let deadline = Instant::now() + Duration::from_secs(5);
    while !sender.srp_authenticated() {
        sender.try_recv_eapol_and_respond(&mut buf).unwrap();
        assert!(
            Instant::now() < deadline,
            "timed out waiting for pure Rust SRP client"
        );
        thread::sleep(Duration::from_millis(1));
    }
}

fn drive_main_sender_srp_authenticator(sender: &mut MainMioSender) {
    let mut buf = [0u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(5);
    while !sender.srp_authenticated() {
        sender.try_recv_event(&mut buf).unwrap();
        assert!(
            Instant::now() < deadline,
            "timed out waiting for the pure Rust sender SRP authenticator"
        );
        thread::sleep(Duration::from_millis(1));
    }
}

fn drive_main_receiver_srp_client(receiver: &mut MainMioReceiver) {
    let mut buf = [0u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(5);
    while !receiver.srp_authenticated() {
        receiver.try_recv_event(&mut buf).unwrap();
        assert!(
            Instant::now() < deadline,
            "timed out waiting for the pure Rust receiver SRP client"
        );
        thread::sleep(Duration::from_millis(1));
    }
}

fn drive_main_srp_authenticator(receiver: &mut MainMioReceiver) {
    let mut buf = [0; 1500];
    let deadline = Instant::now() + Duration::from_secs(5);
    while !receiver.srp_authenticated() {
        receiver.try_recv_eapol_and_respond(&mut buf).unwrap();
        assert!(
            Instant::now() < deadline,
            "timed out waiting for pure Rust SRP authenticator"
        );
        thread::sleep(Duration::from_millis(1));
    }
}

fn mpegts_payload(label: &str) -> [u8; 188] {
    let mut payload = [0xff; 188];
    payload[0] = 0x47;
    payload[1] = 0x11;
    payload[2] = 0x11;
    payload[3] = 0x10;
    let bytes = label.as_bytes();
    payload[4..4 + bytes.len()].copy_from_slice(bytes);
    payload
}

fn mpegts_payload_7(label: &str) -> [u8; 1316] {
    let packet = mpegts_payload(label);
    let mut payload = [0xff; 1316];
    for chunk in payload.chunks_exact_mut(188) {
        chunk.copy_from_slice(&packet);
    }
    payload
}
