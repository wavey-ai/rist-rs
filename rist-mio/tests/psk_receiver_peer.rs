//! A keyed listening `MainMioReceiver` takes a source as its peer (the one
//! `poll_rtcp_and_send`, `send_feedback` and
//! `poll_session_and_send_keepalive` serve) and sends it anything from
//! `poll_keepalive_all` or `poll_all_rtcp_and_send` only once that source's
//! data or RTCP passed the PSK checks. Keepalives, buffer negotiation and
//! out-of-band packets pass with a weak verdict that a host with no key
//! earns every time, so they prove nothing.

use rist_core::crypto::{derive_aes_key, AesKeySize, PskKey};
use rist_core::packet::gre::GreKeepalive;
use rist_core::packet::rtcp::NackMode;
use rist_core::time::ntp_now;
use rist_core::MainSessionConfig;
use rist_mio::{
    MainMioReceiver, MainMioSender, MainReceiverEvent, MainSenderEvent, DEFAULT_MAIN_PEER_CAPACITY,
};
use std::net::{SocketAddr, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

const FLOW: u32 = 0x1122_3344;
const SECRET: &[u8] = b"secret";

/// GRE K and S set, a fixed nonce, eight junk bytes: decrypts to a
/// keepalive that passes the check, with no key at all.
fn forged_keepalive(nonce: u32, sequence: u32) -> Vec<u8> {
    let mut packet = vec![0x30, 0x00, 0x88, 0xb5];
    packet.extend_from_slice(&nonce.to_be_bytes());
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&[0x5a; 8]);
    packet
}

/// GRE K and S set, protocol 0x0800: out-of-band data is opaque, so any
/// bytes pass.
fn forged_oob(nonce: u32, sequence: u32) -> Vec<u8> {
    let mut packet = vec![0x30, 0x00, 0x08, 0x00];
    packet.extend_from_slice(&nonce.to_be_bytes());
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&[0x3c; 24]);
    packet
}

/// A forged reduced data packet: refused by the checks.
fn forged_data(nonce: u32, sequence: u32) -> Vec<u8> {
    let mut packet = vec![0x30, 0x08, 0x88, 0xb6];
    packet.extend_from_slice(&nonce.to_be_bytes());
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&[0xa5; 40]);
    packet
}

struct Run {
    delivered: usize,
    forged_events: usize,
    nack_requests: u64,
    feedback_events: usize,
    peer: Option<SocketAddr>,
    sender: SocketAddr,
    attacker: SocketAddr,
    keepalives_to_attacker: usize,
    keepalives_to_sender: usize,
}

fn run(attack: bool) -> Run {
    let mut receiver =
        MainMioReceiver::bind("127.0.0.1:0".parse().unwrap(), FLOW, "rx", NackMode::Range).unwrap();
    receiver.set_rx_key(PskKey::receiver(128, SECRET).unwrap());
    // Keepalives due often enough to see where they go within the run.
    receiver.set_session_config(MainSessionConfig {
        keepalive_interval: Duration::from_millis(50),
        session_timeout: Duration::from_secs(2),
    });
    let raddr = receiver.local_addr().unwrap();
    let mut sender =
        MainMioSender::connect("127.0.0.1:0".parse().unwrap(), raddr, FLOW, 1024).unwrap();
    sender.set_tx_key(PskKey::new(128, SECRET).unwrap());
    let sender_addr = sender.local_addr().unwrap();
    let attacker = UdpSocket::bind("127.0.0.1:0").unwrap();
    attacker.set_nonblocking(true).unwrap();
    let attacker_addr = attacker.local_addr().unwrap();
    let keepalive = GreKeepalive::librist_default([1, 2, 3, 4, 5, 6]);
    let mut buf = vec![0u8; 12_000];
    let mut sbuf = vec![0u8; 12_000];
    let payload = vec![0x47u8; 188];
    let mut run = Run {
        delivered: 0,
        forged_events: 0,
        nack_requests: 0,
        feedback_events: 0,
        peer: None,
        sender: sender_addr,
        attacker: attacker_addr,
        keepalives_to_attacker: 0,
        keepalives_to_sender: 0,
    };
    let mut forged = 0u32;
    for i in 0..200u32 {
        if i % 20 == 10 {
            // A gap the receiver should NACK.
            sender.set_next_rtp_sequence(i * 10 + 1000);
        }
        sender
            .send_payload(&payload, ntp_now(), Instant::now())
            .unwrap();
        let until = Instant::now() + Duration::from_millis(3);
        while Instant::now() < until {
            if attack {
                forged += 1;
                let packet = if forged % 2 == 0 {
                    forged_keepalive(0x0bad_0001, forged)
                } else {
                    forged_oob(0x0bad_0001, forged)
                };
                let _ = attacker.send_to(&packet, raddr);
            }
            loop {
                match receiver.try_recv_event(&mut buf) {
                    Ok(Some(MainReceiverEvent::Payload { .. })) => run.delivered += 1,
                    Ok(Some(
                        MainReceiverEvent::Keepalive { from, .. }
                        | MainReceiverEvent::Oob { from, .. },
                    )) if from == attacker_addr => run.forged_events += 1,
                    Ok(Some(_)) | Err(_) => {}
                    Ok(None) => break,
                }
            }
            let _ = receiver.poll_rtcp_and_send(Instant::now(), ntp_now());
            if let Ok(poll) = receiver.poll_session_and_send_keepalive(Instant::now(), keepalive) {
                if poll.keepalive.is_some() {
                    match receiver.peer_addr() {
                        Some(peer) if peer == attacker_addr => run.keepalives_to_attacker += 1,
                        Some(peer) if peer == sender_addr => run.keepalives_to_sender += 1,
                        _ => {}
                    }
                }
            }
            while let Ok(Some(event)) = sender.try_recv_event(&mut sbuf) {
                if matches!(event, MainSenderEvent::Feedback { .. }) {
                    run.feedback_events += 1;
                }
            }
            thread::sleep(Duration::from_micros(300));
        }
    }
    // Whatever reached the attacker's socket.
    while let Ok((_, from)) = attacker.recv_from(&mut buf) {
        assert_eq!(from, raddr);
        run.keepalives_to_attacker += 1;
    }
    run.nack_requests = sender.stats().nack_requests;
    run.peer = receiver.peer_addr();
    eprintln!(
        "attack={attack} delivered={} forged_events={} nack_requests={} feedback_events={} \
         peer={:?} sender={:?} attacker={:?} keepalives to sender {} to attacker {}",
        run.delivered,
        run.forged_events,
        run.nack_requests,
        run.feedback_events,
        run.peer,
        run.sender,
        run.attacker,
        run.keepalives_to_sender,
        run.keepalives_to_attacker,
    );
    run
}

/// Review 4 #1: before the fix a host with no key took the receiver's peer
/// with forged keepalives (sender NACK requests 94,540 -> 0, feedback
/// events 277 -> 7, peer = the attacker). Now the forged packets are still
/// returned as events, but the peer stays the real sender and the sender's
/// NACKs and reports keep coming.
#[test]
fn keyless_keepalives_and_oob_do_not_take_a_keyed_receivers_peer() {
    let clean = run(false);
    let attacked = run(true);

    assert_eq!(clean.peer, Some(clean.sender));
    assert!(clean.nack_requests > 0 && clean.feedback_events > 0);

    assert!(
        attacked.forged_events > 100,
        "the attack did not get through the checks: {} forged events",
        attacked.forged_events
    );
    assert_eq!(
        attacked.peer,
        Some(attacked.sender),
        "the forged packets took the receiver's peer"
    );
    assert_eq!(
        attacked.keepalives_to_attacker, 0,
        "the attacker was sent keepalives or feedback"
    );
    assert!(
        attacked.keepalives_to_sender > 0,
        "the real sender got no keepalives"
    );
    assert!(
        attacked.nack_requests * 4 >= clean.nack_requests,
        "the sender's NACK requests fell from {} to {} under the attack",
        clean.nack_requests,
        attacked.nack_requests
    );
    assert!(
        attacked.feedback_events * 4 >= clean.feedback_events,
        "the sender's feedback fell from {} to {} under the attack",
        clean.feedback_events,
        attacked.feedback_events
    );
    assert!(attacked.delivered * 100 >= clean.delivered * 95);
}

/// Review 4 #2: before the fix `poll_keepalive_all` sent an encrypted
/// keepalive to each source whose every packet was refused (256 of them
/// took 35 ms in a release build), each
/// send deriving that session's transmit key, and reflected traffic to spoofed addresses. Now refused sessions get
/// nothing, so derive nothing, while the real sender is still served.
#[test]
fn refused_sessions_get_no_keepalive_and_derive_no_key() {
    let mut receiver =
        MainMioReceiver::bind("127.0.0.1:0".parse().unwrap(), FLOW, "rx", NackMode::Range).unwrap();
    receiver.set_rx_key(PskKey::receiver(128, SECRET).unwrap());
    let raddr = receiver.local_addr().unwrap();
    let mut buf = vec![0u8; 12_000];

    // The real sender, proven by its data.
    let mut sender =
        MainMioSender::connect("127.0.0.1:0".parse().unwrap(), raddr, FLOW, 1024).unwrap();
    sender.set_tx_key(PskKey::new(128, SECRET).unwrap());
    sender
        .send_payload(&[0x47; 188], ntp_now(), Instant::now())
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match receiver.try_recv_event(&mut buf) {
            Ok(Some(MainReceiverEvent::Payload { .. })) => break,
            Ok(_) | Err(_) => {
                assert!(Instant::now() < deadline, "the real payload never arrived");
                thread::sleep(Duration::from_millis(1));
            }
        }
    }

    // Refused sources (forged data) up to the session capacity, less one
    // that sends only forged keepalives, which pass the checks but prove
    // nothing.
    let refused = DEFAULT_MAIN_PEER_CAPACITY - 2;
    let sockets: Vec<UdpSocket> = (0..refused)
        .map(|_| UdpSocket::bind("127.0.0.1:0").unwrap())
        .collect();
    for (i, socket) in sockets.iter().enumerate() {
        socket
            .send_to(&forged_data(0x7000_0000 + i as u32, 1), raddr)
            .unwrap();
    }
    let keepalive_only = UdpSocket::bind("127.0.0.1:0").unwrap();
    for sequence in 0..4 {
        keepalive_only
            .send_to(&forged_keepalive(0x0bad_0002, sequence), raddr)
            .unwrap();
    }
    thread::sleep(Duration::from_millis(50));
    while !matches!(receiver.try_recv_event(&mut buf), Ok(None)) {}
    assert_eq!(receiver.peer_count(), DEFAULT_MAIN_PEER_CAPACITY);
    assert!(receiver.psk_receive_counters().decrypt_rejected >= refused as u64);

    let keepalive = GreKeepalive::librist_default([1, 2, 3, 4, 5, 6]);
    let now = Instant::now();
    // The first poll arms each peer's timer; the second finds it due.
    receiver.poll_keepalive_all(now, keepalive).unwrap();
    let later = now + Duration::from_secs(5);
    let start = Instant::now();
    let sent = receiver.poll_keepalive_all(later, keepalive).unwrap();
    let took = start.elapsed();
    let rtcp = receiver.poll_all_rtcp_and_send(later, ntp_now()).unwrap();
    assert_eq!(
        sent, 1,
        "keepalives went to sessions that never passed the checks"
    );

    thread::sleep(Duration::from_millis(50));
    let mut reflected = 0;
    for socket in sockets.iter().chain(std::iter::once(&keepalive_only)) {
        socket.set_nonblocking(true).unwrap();
        while socket.recv_from(&mut buf).is_ok() {
            reflected += 1;
        }
    }
    assert_eq!(
        reflected, 0,
        "refused sources were sent {reflected} packets"
    );

    let mut sbuf = vec![0u8; 12_000];
    let mut keepalives_at_sender = 0;
    let mut rtcp_at_sender = 0;
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline && keepalives_at_sender == 0 {
        match sender.try_recv_event(&mut sbuf) {
            Ok(Some(MainSenderEvent::Keepalive { .. })) => keepalives_at_sender += 1,
            Ok(Some(MainSenderEvent::Feedback { .. })) => rtcp_at_sender += 1,
            Ok(Some(_)) | Err(_) => {}
            Ok(None) => thread::sleep(Duration::from_millis(1)),
        }
    }
    assert_eq!(keepalives_at_sender, 1, "the real sender got no keepalive");

    // No derivation per refused session: the round costs well under the
    // time of even a tenth of the 255 it would take to key them all.
    let mut samples: Vec<Duration> = (0..9u8)
        .map(|n| {
            let start = Instant::now();
            std::hint::black_box(derive_aes_key(AesKeySize::Aes128, SECRET, &[n, 1, 2, 3]));
            start.elapsed()
        })
        .collect();
    samples.sort();
    let per_derivation = samples[samples.len() / 2];
    eprintln!(
        "keepalives sent {sent} in {took:?} (one derivation {per_derivation:?}), rtcp {rtcp} \
         ({rtcp_at_sender} seen at the sender), reflected {reflected}"
    );
    assert!(
        took < per_derivation * 25,
        "a keepalive round over {refused} refused sessions took {took:?}, \
         one derivation takes {per_derivation:?}"
    );
}
