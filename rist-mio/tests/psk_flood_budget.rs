//! A keyed listening `MainMioReceiver` under a flood of forged encrypted
//! packets from a host with no key, sent from many source ports with a new
//! nonce in each:
//!
//! - an established peer's nonce rotation never waits on the receive-wide
//!   budget of nonce changes, so the flood cannot stall it (review 3,
//!   defect 1);
//! - the sessions the flood creates cost no PBKDF2 derivation of their own:
//!   the derivations stay within the receive-wide budget however many
//!   sessions the flood creates and the caller evicts (review 3, defect 2).

use rist_core::crypto::{derive_aes_key, AesKeySize, PskKey, MAX_SHARED_RECEIVE_REKEYS_PER_SECOND};
use rist_core::packet::rtcp::NackMode;
use rist_core::time::ntp_now;
use rist_mio::{MainMioReceiver, MainMioSender, MainReceiverEvent};
use std::net::{SocketAddr, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

const FLOW: u32 = 0x1122_3344;
const SECRET: &[u8] = b"secret";

/// A GRE packet with a key (nonce) and sequence, as an encrypted RIST
/// packet looks, with garbage for contents: what a host with no key sends.
fn forged(nonce: u32, sequence: u32) -> Vec<u8> {
    let mut packet = vec![0x30, 0x08, 0x88, 0xb6];
    packet.extend_from_slice(&nonce.to_be_bytes());
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&[0xa5; 40]);
    packet
}

/// A Rust sender rotating its nonce every 50 packets sends 600 payloads at
/// 5 ms while 16 keyless sources send 20 forged packets, each with a new
/// nonce, before every payload (about 4,000 a second). Before the fix the
/// flood took the endpoint's 64 nonce changes at the start of every second
/// and the established session lost every packet under each new nonce
/// until it won a slot (153 of 600 delivered). Now only the session's
/// first packets can wait for a slot; once it has delivered, it rotates
/// under its own limit.
#[test]
fn an_established_peer_keeps_rotating_its_nonce_under_a_keyless_flood() {
    let mut receiver =
        MainMioReceiver::bind("127.0.0.1:0".parse().unwrap(), FLOW, "rx", NackMode::Range).unwrap();
    receiver.set_rx_key(PskKey::receiver(128, SECRET).unwrap());
    let raddr: SocketAddr = receiver.local_addr().unwrap();
    let mut sender =
        MainMioSender::connect("127.0.0.1:0".parse().unwrap(), raddr, FLOW, 1024).unwrap();
    sender.set_tx_key(PskKey::with_key_rotation(128, 50, SECRET).unwrap());
    let attackers: Vec<UdpSocket> = (0..16)
        .map(|_| UdpSocket::bind("127.0.0.1:0").unwrap())
        .collect();

    let mut buf = vec![0u8; 12_000];
    let payload = vec![0x47u8; 188];
    let total = 600usize;
    let mut nonce = 0x0100_0000u32;
    let mut delivered = 0usize;
    let mut first_delivery_at_send: Option<usize> = None;
    let mut poll = |receiver: &mut MainMioReceiver,
                    delivered: &mut usize,
                    first: &mut Option<usize>,
                    sent: usize,
                    until: Instant| {
        while Instant::now() < until {
            match receiver.try_recv_event(&mut buf) {
                Ok(Some(MainReceiverEvent::Payload { .. })) => {
                    *delivered += 1;
                    first.get_or_insert(sent);
                }
                Ok(Some(_)) | Err(_) => {}
                Ok(None) => thread::sleep(Duration::from_micros(200)),
            }
        }
    };
    for sent in 1..=total {
        for k in 0..20 {
            nonce = nonce.wrapping_add(1);
            let _ = attackers[k % attackers.len()].send_to(&forged(nonce, sent as u32), raddr);
        }
        sender
            .send_payload(&payload, ntp_now(), Instant::now())
            .unwrap();
        poll(
            &mut receiver,
            &mut delivered,
            &mut first_delivery_at_send,
            sent,
            Instant::now() + Duration::from_millis(5),
        );
    }
    poll(
        &mut receiver,
        &mut delivered,
        &mut first_delivery_at_send,
        total,
        Instant::now() + Duration::from_millis(300),
    );

    let counters = receiver.psk_receive_counters();
    let first = first_delivery_at_send.expect("no payload delivered at all");
    // Payloads sent from the one that was first delivered on: the session
    // is established, and 11 or 12 nonce rotations fall in this span.
    let established_span = total - first + 1;
    eprintln!(
        "delivered {delivered}/{total}, first at send {first}, span {established_span}, {counters:?}"
    );
    assert!(
        counters.decrypt_rejected + counters.decrypt_latched > 1_000,
        "the flood did not reach the checks: {counters:?}"
    );
    assert!(
        established_span >= 300,
        "the session took {first} sends to start"
    );
    assert!(
        delivered * 100 >= established_span * 97,
        "an established session lost payloads under the flood: \
         {delivered} delivered of {established_span} sent since it started"
    );
}

fn garbage_session_rounds(keyed: bool, sockets: &[UdpSocket], rounds: u32) -> Duration {
    let mut receiver =
        MainMioReceiver::bind("127.0.0.1:0".parse().unwrap(), FLOW, "rx", NackMode::Range).unwrap();
    if keyed {
        receiver.set_rx_key(PskKey::receiver(128, SECRET).unwrap());
    }
    let addr = receiver.local_addr().unwrap();
    let mut buf = vec![0u8; 12_000];
    let mut busy = Duration::ZERO;
    for round in 0..rounds {
        for (i, socket) in sockets.iter().enumerate() {
            socket
                .send_to(&forged(round * 1000 + i as u32 + 1, 1), addr)
                .unwrap();
        }
        thread::sleep(Duration::from_millis(20));
        let start = Instant::now();
        while !matches!(receiver.try_recv_event(&mut buf), Ok(None)) {}
        busy += start.elapsed();
        assert!(
            receiver.peer_count() > 0,
            "round {round} created no session"
        );
        receiver.evict_idle_peers(Instant::now(), Duration::from_secs(2));
    }
    busy
}

/// 256 source ports each send one forged packet with a new nonce, and the
/// caller evicts the refused sessions, 8 times over: 2,048 sessions. Before
/// the fix each session derived a transmit key at once (two derivations
/// with only a receive key configured), 561 ms keyed against 15 ms unkeyed
/// in a release build. Now the keyed endpoint's extra time is that of the
/// derivations the receive-wide budget allows, with a wide margin.
#[test]
fn sessions_a_keyless_flood_creates_cost_no_derivation_of_their_own() {
    let mut samples: Vec<Duration> = (0..9u8)
        .map(|n| {
            let start = Instant::now();
            std::hint::black_box(derive_aes_key(AesKeySize::Aes128, SECRET, &[n, 1, 2, 3]));
            start.elapsed()
        })
        .collect();
    samples.sort();
    let per_derivation = samples[samples.len() / 2];

    let sockets: Vec<UdpSocket> = (0..256)
        .map(|_| UdpSocket::bind("127.0.0.1:0").unwrap())
        .collect();
    let rounds = 8;
    let unkeyed = garbage_session_rounds(false, &sockets, rounds);
    let started = Instant::now();
    let keyed = garbage_session_rounds(true, &sockets, rounds);
    let windows = started.elapsed().as_secs() as u32 + 2;

    let sessions = 256 * rounds;
    let allowed = MAX_SHARED_RECEIVE_REKEYS_PER_SECOND * windows;
    assert!(
        allowed * 4 < sessions,
        "too few sessions to tell the two apart"
    );
    let extra = keyed.saturating_sub(unkeyed);
    let bound = per_derivation * allowed * 2 + Duration::from_millis(50);
    eprintln!(
        "unkeyed {unkeyed:?}, keyed {keyed:?}, per derivation {per_derivation:?}, \
         budget allows {allowed} in {windows} windows, bound {bound:?}"
    );
    assert!(
        extra <= bound,
        "{sessions} forged sessions cost {extra:?} more keyed than unkeyed, \
         more than {allowed} derivations ({bound:?})"
    );
}
