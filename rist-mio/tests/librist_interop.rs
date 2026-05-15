#![forbid(unsafe_code)]

use rist_core::time::ntp_now;
use rist_mio::SimpleMioSender;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

fn loopback_any() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
}

fn next_test_port() -> u16 {
    let socket = UdpSocket::bind(loopback_any()).expect("failed to allocate UDP port");
    socket.local_addr().unwrap().port()
}

fn interop_enabled() -> bool {
    std::env::var_os("RIST_INTEROP").is_some()
}

#[test]
fn pure_rust_simple_sender_to_librist_receiver() {
    if !interop_enabled() {
        return;
    }

    let port = next_test_port();
    let receiver_url = format!("rist://@127.0.0.1:{port}");
    let receiver_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));

    let mut receiver = rist::Receiver::new(rist::Profile::Simple).unwrap();
    receiver.add_peer(&receiver_url).unwrap();
    receiver.start().unwrap();

    let mut sender =
        SimpleMioSender::connect(loopback_any(), receiver_addr, 0x1122_3344, 64).unwrap();
    let payload = mpegts_payload("PURE RUST TO LIBRIST");
    sender
        .send_payload(&payload, ntp_now(), Instant::now())
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(2);
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
