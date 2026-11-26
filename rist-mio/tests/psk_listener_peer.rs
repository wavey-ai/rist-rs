//! A keyed listening `MainMioSender` chooses its peer only from RTCP that
//! passed the PSK checks, decrypts each candidate source with its own copy
//! of the receive key, and ignores other sources, undecrypted, once it has
//! chosen: a third host can neither take it over nor shut out its peer's
//! nonce without spoofing the peer's address.

use rist_core::crypto::PskKey;
use rist_core::packet::gre::{GreHeader, GreKeepalive};
use rist_core::packet::rtcp::NackMode;
use rist_core::time::ntp_now;
use rist_core::{MainPacket, MainReceiverCore};
use rist_mio::{MainMioReceiver, MainMioSender, MainReceiverEvent, MainSenderEvent};
use std::net::{SocketAddr, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

const FLOW: u32 = 0x1122_3344;
const SECRET: &[u8] = b"secret";

// The strings are read through Debug in assertion messages.
#[allow(dead_code)]
#[derive(Debug)]
enum Seen {
    Feedback(SocketAddr),
    Keepalive(SocketAddr),
    Oob(SocketAddr),
    Unhandled(SocketAddr, bool),
    Other(String),
    Error(String),
}

fn drain(sender: &mut MainMioSender, buf: &mut [u8], expected: usize) -> Vec<Seen> {
    let mut seen = Vec::new();
    let end = Instant::now() + Duration::from_secs(2);
    while Instant::now() < end && seen.len() < expected {
        match sender.try_recv_event(buf) {
            Ok(Some(event)) => seen.push(match event {
                MainSenderEvent::Feedback { from, .. } => Seen::Feedback(from),
                MainSenderEvent::Keepalive { from, .. } => Seen::Keepalive(from),
                MainSenderEvent::Oob { from, .. } => Seen::Oob(from),
                MainSenderEvent::Unhandled { from, packet } => {
                    Seen::Unhandled(from, matches!(packet, MainPacket::Unknown { .. }))
                }
                other => Seen::Other(format!("{other:?}")),
            }),
            Ok(None) => thread::sleep(Duration::from_millis(1)),
            Err(error) => seen.push(Seen::Error(error.to_string())),
        }
    }
    seen
}

fn keyed_listener() -> (MainMioSender, SocketAddr) {
    let mut sender = MainMioSender::listen("127.0.0.1:0".parse().unwrap(), FLOW, 64).unwrap();
    sender.set_tx_key(PskKey::new(128, SECRET).unwrap());
    sender.set_rx_key(PskKey::receiver(128, SECRET).unwrap());
    let addr = sender.local_addr().unwrap();
    (sender, addr)
}

fn keyed_receiver_core() -> MainReceiverCore {
    MainReceiverCore::new(FLOW, "rust", NackMode::Range)
        .with_tx_key(PskKey::new(128, SECRET).unwrap())
        .with_rx_key(PskKey::receiver(128, SECRET).unwrap())
}

/// Encrypted-looking data packets carrying `nonce`, made without the key.
fn forged_data_with_nonce(nonce: u32, count: u32) -> Vec<Vec<u8>> {
    (0..count)
        .map(|i| {
            let mut packet = vec![0x30, 0x08, 0x88, 0xb6];
            packet.extend_from_slice(&nonce.to_be_bytes());
            packet.extend_from_slice(&(1000 + i).to_be_bytes());
            packet.extend_from_slice(&[0xa5; 40]);
            packet
        })
        .collect()
}

/// A keepalive made without the key: GRE K and S flags, version 1, the
/// keepalive protocol, any nonce, 8 random bytes. It decrypts to a
/// keepalive of valid form under any key.
fn forged_keepalive() -> Vec<u8> {
    let mut packet = vec![0x30, 0x08, 0x88, 0xb5, 0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0];
    packet.extend_from_slice(&[0x13, 0x57, 0x9b, 0xdf, 0x24, 0x68, 0xac, 0xe0]);
    packet
}

/// Review defect 1: once the peer is chosen, packets from another address
/// carrying the peer's nonce (seen on the wire, the GRE key field is
/// clear) are not decrypted: they shut nothing out, and the peer's later
/// feedback is served.
#[test]
fn third_host_cannot_shut_out_the_chosen_peers_nonce() {
    let (mut sender, sender_addr) = keyed_listener();
    let legit = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut core = keyed_receiver_core();
    let mut buf = [0u8; 2048];

    let keepalive = core.build_keepalive(GreKeepalive::librist_default([1; 6]));
    legit.send_to(&keepalive.bytes, sender_addr).unwrap();
    let feedback = core.build_feedback();
    legit.send_to(&feedback.bytes, sender_addr).unwrap();
    let nonce = GreHeader::decode(&feedback.bytes).unwrap().0.key.unwrap();
    let before = drain(&mut sender, &mut buf, 2);
    assert!(
        matches!(before.last(), Some(Seen::Feedback(from)) if *from == legit.local_addr().unwrap()),
        "{before:?}"
    );
    assert_eq!(sender.peer_addr(), Some(legit.local_addr().unwrap()));

    let attacker = UdpSocket::bind("127.0.0.1:0").unwrap();
    let attacker_addr = attacker.local_addr().unwrap();
    for packet in forged_data_with_nonce(nonce, 8) {
        attacker.send_to(&packet, sender_addr).unwrap();
    }
    let attack = drain(&mut sender, &mut buf, 8);
    assert_eq!(attack.len(), 8, "{attack:?}");
    assert!(
        attack
            .iter()
            .all(|seen| matches!(seen, Seen::Unhandled(from, true) if *from == attacker_addr)),
        "{attack:?}"
    );
    let stats = sender.stats();
    assert_eq!(stats.decrypt_rejected, 0);
    assert_eq!(stats.decrypt_latched, 0);
    assert_eq!(stats.nonce_latches, 0);

    for _ in 0..3 {
        let feedback = core.build_feedback();
        legit.send_to(&feedback.bytes, sender_addr).unwrap();
    }
    let after = drain(&mut sender, &mut buf, 3);
    assert_eq!(after.len(), 3, "{after:?}");
    assert!(
        after.iter().all(
            |seen| matches!(seen, Seen::Feedback(from) if *from == legit.local_addr().unwrap())
        ),
        "{after:?}"
    );
    assert_eq!(sender.peer_addr(), Some(legit.local_addr().unwrap()));
}

/// Before the peer is chosen, each source has its own receive state: a
/// third host sending packets with a candidate's nonce shuts out only its
/// own copy, the candidate's RTCP still chooses it, and the counters of
/// the dropped copy are kept.
#[test]
fn third_host_cannot_shut_out_a_candidates_nonce_before_the_peer_is_chosen() {
    let (mut sender, sender_addr) = keyed_listener();
    let legit = UdpSocket::bind("127.0.0.1:0").unwrap();
    let legit_addr = legit.local_addr().unwrap();
    let mut core = keyed_receiver_core();
    let mut buf = [0u8; 2048];

    let keepalive = core.build_keepalive(GreKeepalive::librist_default([1; 6]));
    let nonce = GreHeader::decode(&keepalive.bytes).unwrap().0.key.unwrap();
    legit.send_to(&keepalive.bytes, sender_addr).unwrap();
    let seen = drain(&mut sender, &mut buf, 1);
    assert!(
        matches!(seen.as_slice(), [Seen::Keepalive(from)] if *from == legit_addr),
        "{seen:?}"
    );
    // A keepalive does not choose a keyed listener's peer.
    assert_eq!(sender.peer_addr(), None);

    let attacker = UdpSocket::bind("127.0.0.1:0").unwrap();
    for packet in forged_data_with_nonce(nonce, 8) {
        attacker.send_to(&packet, sender_addr).unwrap();
    }
    let attack = drain(&mut sender, &mut buf, 8);
    assert_eq!(attack.len(), 8, "{attack:?}");
    assert!(
        attack.iter().all(|seen| matches!(seen, Seen::Error(_))),
        "{attack:?}"
    );
    let stats = sender.stats();
    assert_eq!(stats.decrypt_rejected, 1);
    assert_eq!(stats.decrypt_latched, 7);
    assert_eq!(stats.nonce_latches, 1);
    assert_eq!(sender.peer_addr(), None);

    let feedback = core.build_feedback();
    legit.send_to(&feedback.bytes, sender_addr).unwrap();
    let seen = drain(&mut sender, &mut buf, 1);
    assert!(
        matches!(seen.as_slice(), [Seen::Feedback(from)] if *from == legit_addr),
        "{seen:?}"
    );
    assert_eq!(sender.peer_addr(), Some(legit_addr));
    // The attacker's copy is gone; its counters are not.
    let stats = sender.stats();
    assert_eq!(stats.decrypt_rejected, 1);
    assert_eq!(stats.decrypt_latched, 7);
    assert_eq!(stats.nonce_latches, 1);
    // The chosen peer's nonce state went on with it: its feedback is served.
    let feedback = core.build_feedback();
    legit.send_to(&feedback.bytes, sender_addr).unwrap();
    let seen = drain(&mut sender, &mut buf, 1);
    assert!(
        matches!(seen.as_slice(), [Seen::Feedback(from)] if *from == legit_addr),
        "{seen:?}"
    );
}

/// Review defect 2: a host without the key cannot take over a keyed
/// listening sender with a forged keepalive or out-of-band packet (both
/// decrypt to something of valid form under any key). The real receiver's
/// RTCP chooses the peer, and media goes to it alone.
#[test]
fn keyless_host_cannot_take_over_a_keyed_listening_sender() {
    let (mut sender, sender_addr) = keyed_listener();
    let attacker = UdpSocket::bind("127.0.0.1:0").unwrap();
    attacker
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let attacker_addr = attacker.local_addr().unwrap();
    let mut wrong_key = MainReceiverCore::new(FLOW, "rust", NackMode::Range)
        .with_tx_key(PskKey::new(128, b"not the secret").unwrap());
    let forged_oob = wrong_key.build_oob(b"forged out-of-band");
    attacker.send_to(&forged_keepalive(), sender_addr).unwrap();
    attacker.send_to(&forged_oob.bytes, sender_addr).unwrap();

    let mut buf = [0u8; 2048];
    let seen = drain(&mut sender, &mut buf, 2);
    assert!(
        matches!(
            seen.as_slice(),
            [Seen::Keepalive(a), Seen::Oob(b)] if *a == attacker_addr && *b == attacker_addr
        ),
        "{seen:?}"
    );
    assert_eq!(sender.peer_addr(), None);
    // Nothing goes anywhere without a peer.
    assert!(sender
        .send_payload(&[0x47; 188], ntp_now(), Instant::now())
        .is_err());

    let mut receiver = MainMioReceiver::connect(
        "127.0.0.1:0".parse().unwrap(),
        sender_addr,
        FLOW,
        "rust",
        NackMode::Range,
    )
    .unwrap();
    receiver.set_tx_key(PskKey::new(128, SECRET).unwrap());
    receiver.set_rx_key(PskKey::receiver(128, SECRET).unwrap());
    let receiver_addr = receiver.local_addr().unwrap();
    receiver.send_feedback_to(sender_addr).unwrap();
    let seen = drain(&mut sender, &mut buf, 1);
    assert!(
        matches!(seen.as_slice(), [Seen::Feedback(from)] if *from == receiver_addr),
        "{seen:?}"
    );
    assert_eq!(sender.peer_addr(), Some(receiver_addr));

    // The attacker keeps sending; it is ignored, undecrypted.
    attacker.send_to(&forged_keepalive(), sender_addr).unwrap();
    for i in 0..20u8 {
        while let Ok(Some(event)) = sender.try_recv_event(&mut buf) {
            if let MainSenderEvent::Unhandled { from, .. } = event {
                assert_eq!(from, attacker_addr);
            }
        }
        sender
            .send_payload(&[0x47 ^ i; 188], ntp_now(), Instant::now())
            .unwrap();
        thread::sleep(Duration::from_millis(2));
    }
    let mut to_attacker = 0;
    while attacker.recv_from(&mut buf).is_ok() {
        to_attacker += 1;
    }
    let mut delivered = 0;
    let end = Instant::now() + Duration::from_secs(2);
    while Instant::now() < end && delivered < 20 {
        match receiver.try_recv_event(&mut buf) {
            Ok(Some(MainReceiverEvent::Payload { .. })) => delivered += 1,
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => thread::sleep(Duration::from_millis(1)),
        }
    }
    assert_eq!(to_attacker, 0);
    assert_eq!(delivered, 20);
    assert_eq!(receiver.stats().decrypt_rejected, 0);
}
