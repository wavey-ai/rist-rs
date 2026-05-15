#![forbid(unsafe_code)]

use rist_core::packet::gre::{BufferNegotiation, GreKeepalive};
use rist_core::packet::rtcp::{
    encode_echo, encode_empty_receiver_report, encode_sdes_cname, Echo, EchoKind, NackMode,
};
use rist_core::time::ntp_now;
use rist_core::{PskKey, SrpCredentialStore};
use rist_mio::{MainMioReceiver, MainMioSender, SimpleMioReceiver, SimpleMioSender};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

static INTEROP_MUTEX: Mutex<()> = Mutex::new(());

fn loopback_any() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
}

fn next_even_test_port_pair() -> u16 {
    for _ in 0..128 {
        let socket = UdpSocket::bind(loopback_any()).expect("failed to allocate UDP port");
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

        let rtp_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, base));
        let rtcp_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, base + 1));
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
    let _guard = INTEROP_MUTEX.lock().unwrap();

    let port = next_even_test_port_pair();
    let receiver_url = format!("rist://@127.0.0.1:{port}");
    let receiver_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
    let receiver_rtcp_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port + 1));

    let mut receiver = rist::Receiver::new(rist::Profile::Simple).unwrap();
    receiver.add_peer(&receiver_url).unwrap();
    receiver.start().unwrap();

    let sender_port = next_even_test_port_pair();
    let sender_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, sender_port));
    let sender_rtcp_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, sender_port + 1));
    let rtcp_socket = UdpSocket::bind(sender_rtcp_addr).unwrap();
    let mut sender = SimpleMioSender::connect(sender_addr, receiver_addr, 0x1122_3344, 64).unwrap();
    let payload = mpegts_payload_7("PURE RUST TO LIBRIST");
    send_simple_rtcp_probe(&rtcp_socket, receiver_rtcp_addr, 0x1122_3344);
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

fn send_simple_rtcp_probe(socket: &UdpSocket, peer: SocketAddr, ssrc: u32) {
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
    socket.send_to(&packet, peer).unwrap();
}

#[test]
fn librist_simple_sender_to_pure_rust_receiver() {
    if !interop_enabled() {
        return;
    }
    let _guard = INTEROP_MUTEX.lock().unwrap();

    let flow_id = 0x1122_3344;
    let receiver_port = next_even_test_port_pair();
    let receiver_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, receiver_port));
    let receiver_rtcp_addr =
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, receiver_port + 1));
    let _rtcp_sink = UdpSocket::bind(receiver_rtcp_addr).unwrap();
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
fn pure_rust_main_sender_to_librist_receiver() {
    if !interop_enabled() {
        return;
    }
    let _guard = INTEROP_MUTEX.lock().unwrap();

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

#[test]
fn librist_main_sender_to_pure_rust_receiver() {
    if !interop_enabled() {
        return;
    }
    let _guard = INTEROP_MUTEX.lock().unwrap();

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
fn pure_rust_main_aes_sender_to_librist_receiver() {
    if !interop_enabled() {
        return;
    }
    let _guard = INTEROP_MUTEX.lock().unwrap();

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
    let _guard = INTEROP_MUTEX.lock().unwrap();

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
    let _guard = INTEROP_MUTEX.lock().unwrap();

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
    let _guard = INTEROP_MUTEX.lock().unwrap();

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
fn pure_rust_main_srp_client_authenticates_with_librist_receiver() {
    if !interop_enabled() {
        return;
    }
    let _guard = INTEROP_MUTEX.lock().unwrap();

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
    sender.enable_srp_client("testuser", b"testpassword");
    sender
        .send_keepalive(GreKeepalive::librist_default([1, 2, 3, 4, 5, 6]))
        .unwrap();
    thread::sleep(Duration::from_millis(20));
    sender.start_srp_authentication().unwrap();
    drive_main_srp_client(&mut sender);
    assert!(sender.srp_authenticated());
}

#[test]
fn librist_main_srp_client_authenticates_with_pure_rust_receiver() {
    if !interop_enabled() {
        return;
    }
    let _guard = INTEROP_MUTEX.lock().unwrap();

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
