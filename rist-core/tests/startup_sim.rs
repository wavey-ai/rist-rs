//! The start of a stream in virtual time, delivered as the product does it:
//! a `SimpleSenderCore`, a `SimpleReceiverCore` and the receiver's payloads
//! (duplicates included) through `OrderedPayloadBuffer::with_deadline(cap,
//! L)` with the library's defaults, released at each 1 ms receiver tick.
//!
//! The path has a one-way delay of RTT / 2 (plus, in the jitter cases, a
//! normal jitter as netem applies it, which reorders), and drops what a case
//! says at the start of the stream: the first `k` originals, the sender's
//! first copy of packet 0, or both (a burst that takes the first packets of
//! the stream). Nothing else is lost. A frame counts when every one of its
//! packets came out of the ordered buffer, within L of its send time.
//!
//! ```text
//! nice -n 15 cargo test -p rist-core --test startup_sim -j8
//! ```

use rist_core::packet::rtcp::NackMode;
use rist_core::time::ntp_from_unix_duration;
use rist_core::{
    CongestionControlMode, OrderedPayloadBuffer, RecoveryConfig, RecoveryTuning,
    SimpleReceiverCore, SimpleSenderCore,
};
use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;
use std::time::{Duration, Instant};

const FRAME_INTERVAL_US: u64 = 40_000;

#[derive(Clone, Copy, Debug)]
struct Case {
    rtt_ms: u64,
    length_ms: u64,
    /// Packets of frame 0 (the I-frame) and of every later frame.
    first_frame_packets: u64,
    frame_packets: u64,
    frames: u64,
    /// Gap between the packets of a frame on the wire.
    spacing_us: u64,
    /// Originals 0..k are dropped.
    lose_first: u64,
    /// The sender's first copy of packet 0 (`duplicate_gap` after it) is
    /// dropped too.
    lose_first_copy: bool,
    /// Standard deviation of a normal one-way jitter on every packet.
    jitter_sigma_us: u64,
    sender: SenderKind,
    /// Turn the buffer's startup hold off (the behaviour before it).
    no_startup_hold: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SenderKind {
    /// `RecoveryTuning::default()` on both sides (the product).
    Product,
    /// A sender that never copies its first packet (librist), product
    /// receiver.
    LibristSender,
    /// `RecoveryTuning::librist_like()` on both sides, with the ordered
    /// buffer's hold from `ordered_startup_hold` (zero).
    LibristLike,
}

impl Case {
    fn new(rtt_ms: u64, length_ms: u64) -> Self {
        Self {
            rtt_ms,
            length_ms,
            first_frame_packets: 300,
            frame_packets: 96,
            frames: 25,
            spacing_us: 10,
            lose_first: 0,
            lose_first_copy: false,
            jitter_sigma_us: 0,
            sender: SenderKind::Product,
            no_startup_hold: false,
        }
    }

    fn packets_before(&self, frame: u64) -> u64 {
        if frame == 0 {
            0
        } else {
            self.first_frame_packets + (frame - 1) * self.frame_packets
        }
    }

    fn frame_len(&self, frame: u64) -> u64 {
        if frame == 0 {
            self.first_frame_packets
        } else {
            self.frame_packets
        }
    }
}

enum Kind {
    Data(Vec<u8>),
    ToReceiver(Vec<u8>),
    ToSender(Vec<u8>),
    ReceiverTick,
    SenderTick,
    Frame(u64),
}

struct Event {
    at: u64,
    order: u64,
    kind: Kind,
}

impl PartialEq for Event {
    fn eq(&self, other: &Self) -> bool {
        (self.at, self.order) == (other.at, other.order)
    }
}
impl Eq for Event {}
impl PartialOrd for Event {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Event {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.at, self.order).cmp(&(other.at, other.order))
    }
}

/// splitmix64.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn unit(&mut self) -> f64 {
        ((self.next() >> 11) as f64 + 0.5) / (1u64 << 53) as f64
    }

    /// A standard normal draw (Box-Muller).
    fn normal(&mut self) -> f64 {
        let (u, v) = (self.unit(), self.unit());
        (-2.0 * u.ln()).sqrt() * (std::f64::consts::TAU * v).cos()
    }
}

struct Path {
    owd_us: u64,
    sigma_us: u64,
    rng: Rng,
}

impl Path {
    /// netem `delay owd jitter distribution normal`: never below zero.
    fn delay(&mut self) -> u64 {
        if self.sigma_us == 0 {
            return self.owd_us;
        }
        let jitter = self.rng.normal() * self.sigma_us as f64;
        (self.owd_us as f64 + jitter).max(0.0) as u64
    }
}

#[derive(Debug, Default)]
struct Outcome {
    frames_lost: Vec<u64>,
    frames_late: Vec<u64>,
    /// Completion time (us after its send) of each frame, `None` if lost.
    completion: Vec<Option<u64>>,
    late_dropped: u64,
    startup_holes: u64,
    startup_packets: u64,
    retransmitted: u64,
}

fn run(case: Case, seed: u64) -> Outcome {
    let t0 = Instant::now();
    let ntp0 = ntp_from_unix_duration(Duration::from_secs(1_000));
    let at = |us: u64| t0 + Duration::from_micros(us);
    let ntp = |us: u64| ntp0 + (us << 32) / 1_000_000;
    let length = Duration::from_millis(case.length_ms);
    let recovery = RecoveryConfig {
        length_min: length,
        length_max: length,
        ..RecoveryConfig::default()
    };
    let (sender_tuning, receiver_tuning) = match case.sender {
        SenderKind::Product => (RecoveryTuning::default(), RecoveryTuning::default()),
        SenderKind::LibristSender => (
            RecoveryTuning {
                duplicate_late_repairs: false,
                ..RecoveryTuning::default()
            },
            RecoveryTuning::default(),
        ),
        SenderKind::LibristLike => (
            RecoveryTuning::librist_like(),
            RecoveryTuning::librist_like(),
        ),
    };
    let flow = 0x1122_3344;
    let mut sender = SimpleSenderCore::new(flow, 16_384)
        .with_recovery_config(recovery.clone(), CongestionControlMode::Normal)
        .with_recovery_tuning(sender_tuning);
    let mut receiver = SimpleReceiverCore::new(flow, "sim", NackMode::Range)
        .with_recovery_config(recovery, CongestionControlMode::Normal)
        .with_recovery_tuning(receiver_tuning);
    let mut ordered = OrderedPayloadBuffer::with_deadline(65_536, length);
    if case.no_startup_hold {
        ordered.set_startup_hold(Duration::ZERO);
    } else if case.sender == SenderKind::LibristLike {
        ordered.set_startup_hold(receiver_tuning.ordered_startup_hold(length));
    }

    let total = case.packets_before(case.frames);
    let mut released_at: Vec<Option<u64>> = vec![None; total as usize];
    let mut queue = BinaryHeap::new();
    let mut order = 0;
    let mut push = |queue: &mut BinaryHeap<Reverse<Event>>, at: u64, kind: Kind| {
        order += 1;
        queue.push(Reverse(Event { at, order, kind }));
    };
    let mut path = Path {
        owd_us: case.rtt_ms * 500,
        sigma_us: case.jitter_sigma_us,
        rng: Rng(seed.wrapping_mul(0x2545_f491_4f6c_dd1d) ^ 0x5bd1_e995),
    };
    for frame in 0..case.frames {
        push(&mut queue, frame * FRAME_INTERVAL_US, Kind::Frame(frame));
    }
    push(&mut queue, 0, Kind::ReceiverTick);
    push(&mut queue, 0, Kind::SenderTick);
    let end = case.frames * FRAME_INTERVAL_US + 2 * (case.length_ms + case.rtt_ms) * 1_000;
    let mut copies_of_zero = 0;
    let mut out = Vec::new();
    let mut deliver = |out: &mut Vec<rist_core::ReceivedPayload>, now: u64| {
        for payload in out.drain(..) {
            let slot = &mut released_at[payload.sequence as usize];
            assert!(slot.is_none(), "{} released twice", payload.sequence);
            *slot = Some(now);
        }
    };

    while let Some(Reverse(event)) = queue.pop() {
        let now = event.at;
        if now > end {
            break;
        }
        match event.kind {
            Kind::Frame(frame) => {
                for index in 0..case.frame_len(frame) {
                    let sent_at = now + index * case.spacing_us;
                    let packet = sender.send_payload(&[0x47; 1316], ntp(sent_at), at(sent_at));
                    assert_eq!(
                        u64::from(packet.sequence),
                        case.packets_before(frame) + index
                    );
                    if u64::from(packet.sequence) < case.lose_first {
                        continue;
                    }
                    let delay = path.delay();
                    push(&mut queue, sent_at + delay, Kind::Data(packet.bytes));
                }
            }
            Kind::Data(bytes) => {
                let received = receiver.accept_packet_at(&bytes, at(now)).unwrap();
                ordered.push_into(received, at(now), &mut out).unwrap();
                deliver(&mut out, now);
            }
            Kind::ToReceiver(bytes) => {
                for response in receiver.handle_rtcp_at(&bytes, ntp(now)).unwrap() {
                    let delay = path.delay();
                    push(&mut queue, now + delay, Kind::ToSender(response));
                }
            }
            Kind::ToSender(bytes) => {
                let served = now.div_ceil(250) * 250;
                let outcome = sender
                    .handle_feedback_outcome_at(&bytes, ntp(served), at(served))
                    .unwrap();
                for response in outcome.responses {
                    let delay = path.delay();
                    push(&mut queue, served + delay, Kind::ToReceiver(response));
                }
                for retry in outcome.retries {
                    let delay = path.delay();
                    push(&mut queue, served + delay, Kind::Data(retry.bytes));
                }
            }
            Kind::ReceiverTick => {
                ordered.release_expired_into(at(now), &mut out);
                deliver(&mut out, now);
                let mut packets = Vec::new();
                receiver.poll_rtcp_into(at(now), ntp(now), &mut packets, 64);
                for packet in packets {
                    let delay = path.delay();
                    push(&mut queue, now + delay, Kind::ToSender(packet));
                }
                push(&mut queue, now + 1_000, Kind::ReceiverTick);
            }
            Kind::SenderTick => {
                for repair in sender.poll_repairs_at(at(now)) {
                    if repair.sequence == 0 {
                        copies_of_zero += 1;
                        if copies_of_zero == 1 && case.lose_first_copy {
                            continue;
                        }
                    }
                    let delay = path.delay();
                    push(&mut queue, now + delay, Kind::Data(repair.bytes));
                }
                if now % 5_000 == 0 {
                    if let Some(rtcp) = sender.poll_rtcp(at(now), ntp(now)) {
                        let delay = path.delay();
                        push(&mut queue, now + delay, Kind::ToReceiver(rtcp));
                    }
                }
                push(&mut queue, now + 250, Kind::SenderTick);
            }
        }
    }
    ordered.release_expired_into(at(end), &mut out);
    deliver(&mut out, end);

    let deadline = case.length_ms * 1_000;
    let mut outcome = Outcome::default();
    for frame in 0..case.frames {
        let first = case.packets_before(frame) as usize;
        let range = first..first + case.frame_len(frame) as usize;
        let sent = frame * FRAME_INTERVAL_US;
        let done = range
            .map(|sequence| released_at[sequence])
            .try_fold(0, |done: u64, at| at.map(|at| done.max(at)));
        match done {
            None => {
                outcome.frames_lost.push(frame);
                outcome.completion.push(None);
            }
            Some(done) => {
                if done - sent > deadline {
                    outcome.frames_late.push(frame);
                }
                outcome.completion.push(Some(done - sent));
            }
        }
    }
    let stats = receiver.stats();
    outcome.late_dropped = ordered.stats().late_dropped;
    outcome.startup_holes = stats.startup_holes;
    outcome.startup_packets = stats.startup_packets;
    outcome.retransmitted = sender.stats().retransmitted_packets;
    outcome
}

/// L = max(4 RTT, 40 ms), and the product L at RTT 250.
const PATHS: [(u64, u64); 4] = [(1, 40), (30, 120), (100, 400), (250, 1_000)];

fn assert_clean(case: Case, outcome: &Outcome) {
    assert!(
        outcome.frames_lost.is_empty() && outcome.frames_late.is_empty(),
        "{case:?}: lost {:?} late {:?} (late dropped {}, startup holes {}, startup packets {}, \
         retransmitted {}, frame 0 completion {:?})",
        outcome.frames_lost,
        outcome.frames_late,
        outcome.late_dropped,
        outcome.startup_holes,
        outcome.startup_packets,
        outcome.retransmitted,
        outcome.completion[0],
    );
}

/// Goal 1: a burst that takes the first k packets of the stream (k = 1..8),
/// with or without the sender's first copy of packet 0, loses no frame.
#[test]
fn a_burst_at_the_start_loses_no_frame() {
    for (rtt_ms, length_ms) in PATHS {
        for lose_first in 1..=8 {
            for lose_first_copy in [false, true] {
                // Paced so that 8 packets span the 1 ms to the first copy
                // (and frame 0 still fits well within L = 40 ms).
                let case = Case {
                    lose_first,
                    lose_first_copy,
                    spacing_us: 150,
                    first_frame_packets: 96,
                    ..Case::new(rtt_ms, length_ms)
                };
                assert_clean(case, &run(case, 1));
            }
        }
    }
}

/// Goal 1 for a stream that does not start at sequence 0 for the receiver's
/// zero-start rule to cover: a burst of 40 packets plus the first copy is
/// repaired from the sender's late copy of packet 0.
#[test]
fn a_long_burst_at_the_start_is_recovered_from_the_late_copy() {
    for (rtt_ms, length_ms) in PATHS {
        let case = Case {
            lose_first: 40,
            lose_first_copy: true,
            spacing_us: 25,
            ..Case::new(rtt_ms, length_ms)
        };
        let outcome = run(case, 1);
        assert_clean(case, &outcome);
        assert!(outcome.startup_packets >= 1, "{outcome:?}");
    }
}

/// Goal 2: 5 ms of normal jitter at RTT 30 reorders the first frame (and
/// every frame); nothing below the first packet seen is dropped.
#[test]
fn reordering_at_the_start_loses_no_frame() {
    for (first_frame_packets, frame_packets) in [(400, 96), (1_500, 600)] {
        for seed in 1..=4 {
            let case = Case {
                first_frame_packets,
                frame_packets,
                jitter_sigma_us: 5_000,
                ..Case::new(30, 120)
            };
            let outcome = run(case, seed);
            assert_clean(case, &outcome);
            assert_eq!(outcome.late_dropped, 0, "{case:?} {outcome:?}");
        }
    }
}

/// Goal 3: a sender that never copies its first packet (librist) loses it;
/// the receiver takes the stream as numbered from 0 and NACKs it.
#[test]
fn a_lost_first_packet_from_a_librist_like_sender_is_repaired() {
    for (rtt_ms, length_ms) in PATHS {
        for lose_first in [1, 3, 8] {
            let case = Case {
                lose_first,
                sender: SenderKind::LibristSender,
                ..Case::new(rtt_ms, length_ms)
            };
            let outcome = run(case, 1);
            assert_clean(case, &outcome);
            assert_eq!(outcome.startup_holes, lose_first, "{outcome:?}");
        }
    }
}

/// `librist_like()` keeps librist's limit (no startup recovery): a lost
/// first packet loses frame 0, nothing else.
#[test]
fn librist_like_tuning_keeps_the_old_start() {
    let case = Case {
        lose_first: 1,
        sender: SenderKind::LibristLike,
        ..Case::new(30, 120)
    };
    let outcome = run(case, 1);
    assert_eq!(outcome.frames_lost, vec![0]);
    assert_eq!(outcome.startup_holes, 0);
}

/// Goal 4: the hold costs the first frames only. With nothing lost and no
/// reordering, every frame completes when it would without the hold; with
/// jitter, every frame sent after the first 120 ms does.
#[test]
fn the_startup_hold_leaves_the_steady_state_alone() {
    for (rtt_ms, length_ms) in PATHS {
        let case = Case::new(rtt_ms, length_ms);
        let held = run(case, 1);
        let plain = run(
            Case {
                no_startup_hold: true,
                ..case
            },
            1,
        );
        assert_eq!(held.completion, plain.completion, "{case:?}");
    }
    for seed in 1..=4 {
        let case = Case {
            jitter_sigma_us: 5_000,
            ..Case::new(30, 120)
        };
        let held = run(case, seed);
        let plain = run(
            Case {
                no_startup_hold: true,
                ..case
            },
            seed,
        );
        assert_eq!(held.completion[3..], plain.completion[3..], "seed {seed}");
        assert!(
            plain.frames_lost.contains(&0),
            "the jitter must hit the start: {plain:?}"
        );
    }
}

/// Without the hold (the behaviour before), the same bursts lose frame 0:
/// the cases above test what the hold adds.
#[test]
fn without_the_startup_hold_a_burst_at_the_start_loses_frame_0() {
    let case = Case {
        lose_first: 3,
        no_startup_hold: true,
        spacing_us: 150,
        ..Case::new(250, 1_000)
    };
    assert_eq!(run(case, 1).frames_lost, vec![0]);
}
