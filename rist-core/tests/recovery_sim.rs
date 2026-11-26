//! Deterministic loss-recovery simulation in virtual time.
//!
//! A `SimpleSenderCore` and a `SimpleReceiverCore` exchange video frames
//! over a simulated path: one-way delay RTT / 2 each way, independent random
//! loss on both directions (data, repairs, NACKs and echo alike), frames of
//! `packets_per_frame` packets handed over at once every 41.7 ms (24 fps,
//! as the transport bench does), 10 us apart on the wire. The receiver
//! polls every 1 ms (the bench's receiver tick), the sender serves feedback
//! and its own repairs every 250 us and its RTCP every 5 ms (the bench's
//! sender adapter). The recovery settings are the product defaults
//! (`RecoveryConfig::default()`: bandwidth 100000 kbit/s, rtt_min 5 ms,
//! rtt_max 500 ms, reorder 15 ms) with the buffer L of each case.
//!
//! Cases with `jitter_us` add U(0, jitter) to every one-way delay, both
//! directions and all traffic, without keeping order; cases with
//! `reorder_per_mille` also hold back that share of data packets by
//! U(0, 2 x reorder buffer). The report then counts what reordering costs:
//! NACKed sequences whose original was not lost (`spur nk`), repairs sent
//! for them (`spur rx`) and repairs refused by the sender's spacing check
//! (`refused`); duplicate repairs are `dupx2`.
//!
//! Variants, all on the same original-packet loss pattern:
//! - `defaults`: `RecoveryTuning::default()` (P2/P3/P7/P8 + B1-B4);
//! - `parity`: `RecoveryTuning::librist_like()` (P2/P3/P7/P8 only);
//! - `librist-timing`: parity, with the first NACK at max(RTT/2, reorder)
//!   as librist schedules it.
//!
//! ```text
//! nice -n 15 cargo test -p rist-core --release --test recovery_sim -j8 -- --ignored --nocapture
//! ```
//!
//! `RIST_SIM_SECS` (default 15) and `RIST_SIM_SEEDS` (default 4) scale it;
//! `RIST_SIM_ABLATION=1` adds the defaults minus one feature each;
//! `RIST_SIM_CASES=0,2` runs only those cases (indices into `CASES`).
//! The non-ignored test runs a short case and checks the ordering.

use rist_core::packet::rtcp::{decode_nacks_from_compound, NackMode};
use rist_core::sequence::extend_near;
use rist_core::time::ntp_from_unix_duration;
use rist_core::{
    CongestionControlMode, RecoveryConfig, RecoveryTuning, SenderStats, SimpleReceiverCore,
    SimpleSenderCore,
};
use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;
use std::time::{Duration, Instant};

const FRAME_INTERVAL_US: u64 = 41_667;
const PACKET_SPACING_US: u64 = 10;
const PAYLOAD: [u8; 1316] = [0x47; 1316];

#[derive(Clone, Copy)]
struct Case {
    name: &'static str,
    rtt_ms: u64,
    length_ms: u64,
    packets_per_frame: u64,
    loss_per_mille: u64,
    /// One-way delay jitter, U(0, jitter_us), on every packet.
    jitter_us: u64,
    /// Data packets held back by U(0, 2 x reorder buffer), per mille.
    reorder_per_mille: u64,
}

/// 2 x the product reorder buffer (15 ms).
const REORDER_DISPLACEMENT_US: u64 = 30_000;

/// Delay variation of the simulated path. Draws come from their own
/// generator, and none at all without jitter or reordering, so the loss
/// pattern and the plain cases stay as they were.
struct PathModel {
    rng: Rng,
    jitter_us: u64,
    reorder_per_mille: u64,
}

impl PathModel {
    fn jitter(&mut self) -> u64 {
        if self.jitter_us == 0 {
            return 0;
        }
        self.rng.next() % (self.jitter_us + 1)
    }

    /// One-way delay of a data packet (original or repair).
    fn data(&mut self, owd: u64) -> u64 {
        let mut delay = owd + self.jitter();
        if self.reorder_per_mille > 0 && self.rng.next() % 1_000 < self.reorder_per_mille {
            delay += self.rng.next() % (REORDER_DISPLACEMENT_US + 1);
        }
        delay
    }

    /// One-way delay of RTCP.
    fn control(&mut self, owd: u64) -> u64 {
        owd + self.jitter()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Variant {
    Defaults,
    Parity,
    LibristTiming,
    /// Defaults without one feature, for the report's breakdown.
    NoProbe,
    NoNackCopies,
    NoDuplicates,
    FixedFirstNack,
}

impl Variant {
    fn name(self) -> &'static str {
        match self {
            Variant::Defaults => "defaults",
            Variant::Parity => "parity",
            Variant::LibristTiming => "librist-timing",
            Variant::NoProbe => " - tail probe",
            Variant::NoNackCopies => " - NACK copies",
            Variant::NoDuplicates => " - dup repairs",
            Variant::FixedFirstNack => " - adaptive F",
        }
    }
}

enum Kind {
    /// A data packet (original or repair) reaches the receiver.
    Data(Vec<u8>),
    /// RTCP from the sender reaches the receiver.
    ToReceiver(Vec<u8>),
    /// RTCP from the receiver reaches the sender.
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

struct Rng(u64);

impl Rng {
    /// splitmix64. (xorshift64 with `% 1000` gave visibly correlated
    /// consecutive draws in this simulation.)
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

/// Loss of the original of `sequence`: the same in every variant. The
/// first packet always arrives (a receiver cannot ask for what precedes the
/// first packet it sees).
fn original_lost(seed: u64, sequence: u64, loss_per_mille: u64) -> bool {
    if sequence == 0 {
        return false;
    }
    let mut rng = Rng(seed.wrapping_mul(0x0123_4567_89ab_cdef) ^ sequence);
    rng.next() % 1_000 < loss_per_mille
}

#[derive(Debug, Default, Clone)]
struct Outcome {
    frames: u64,
    frames_lost: u64,
    frames_late: u64,
    holes: u64,
    unrecovered: u64,
    lossy_frame_latency_us: Vec<u64>,
    sent_packets: u64,
    retransmitted: u64,
    nack_packets: u64,
    nack_copies: u64,
    duplicates_received: u64,
    tail_probes: u64,
    duplicate_repairs: u64,
    refused_spacing: u64,
    feedback_bytes: u64,
    nack_entries: u64,
    /// NACKed sequences (copies included) whose original was not lost.
    spurious_nack_entries: u64,
    /// NACK-driven repairs of sequences whose original was not lost.
    spurious_repairs: u64,
}

fn run(case: Case, variant: Variant, seconds: u64, seed: u64) -> Outcome {
    let t0 = Instant::now();
    let ntp0 = ntp_from_unix_duration(Duration::from_secs(1_000));
    let at = |us: u64| t0 + Duration::from_micros(us);
    let ntp = |us: u64| ntp0 + (us << 32) / 1_000_000;
    let owd = case.rtt_ms * 500;
    let length = Duration::from_millis(case.length_ms);
    let mut recovery = RecoveryConfig {
        length_min: length,
        length_max: length,
        ..RecoveryConfig::default()
    };
    let tuning = match variant {
        Variant::Defaults => RecoveryTuning::default(),
        Variant::NoProbe => RecoveryTuning {
            tail_probe: rist_core::TailProbe::Off,
            ..RecoveryTuning::default()
        },
        Variant::NoNackCopies => RecoveryTuning {
            redundant_nacks: false,
            ..RecoveryTuning::default()
        },
        Variant::NoDuplicates => RecoveryTuning {
            duplicate_late_repairs: false,
            ..RecoveryTuning::default()
        },
        Variant::FixedFirstNack => RecoveryTuning {
            adaptive_first_nack: false,
            ..RecoveryTuning::default()
        },
        Variant::Parity => RecoveryTuning::librist_like(),
        Variant::LibristTiming => {
            recovery.reorder_buffer = recovery
                .reorder_buffer
                .max(Duration::from_micros(case.rtt_ms * 500));
            RecoveryTuning::librist_like()
        }
    };
    let flow = 0x1122_3344;
    let mut sender = SimpleSenderCore::new(flow, 8_192)
        .with_recovery_config(recovery.clone(), CongestionControlMode::Normal)
        .with_recovery_tuning(tuning);
    let mut receiver = SimpleReceiverCore::new(flow, "sim", NackMode::Range)
        .with_recovery_config(recovery, CongestionControlMode::Normal)
        .with_recovery_tuning(tuning);

    let frames = seconds * 1_000_000 / FRAME_INTERVAL_US;
    let total = frames * case.packets_per_frame;
    let mut arrival: Vec<Option<u64>> = vec![None; total as usize];
    let mut lost_original = vec![false; total as usize];
    let mut queue = BinaryHeap::new();
    let mut order = 0;
    let mut push = |queue: &mut BinaryHeap<Reverse<Event>>, at: u64, kind: Kind| {
        order += 1;
        queue.push(Reverse(Event { at, order, kind }));
    };
    let mut rng = Rng(seed.wrapping_mul(0x2545_f491_4f6c_dd1d));
    let mut path = PathModel {
        rng: Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0x5bd1_e995),
        jitter_us: case.jitter_us,
        reorder_per_mille: case.reorder_per_mille,
    };
    let lost = |rng: &mut Rng| rng.next() % 1_000 < case.loss_per_mille;
    for frame in 0..frames {
        push(&mut queue, frame * FRAME_INTERVAL_US, Kind::Frame(frame));
    }
    push(&mut queue, 0, Kind::ReceiverTick);
    push(&mut queue, 0, Kind::SenderTick);
    let end = frames * FRAME_INTERVAL_US + 2 * (case.length_ms + case.rtt_ms) * 1_000;
    let mut outcome = Outcome {
        frames,
        holes: 0,
        ..Outcome::default()
    };
    let mut duplicates = 0;
    let mut feedback_bytes = 0;

    while let Some(Reverse(event)) = queue.pop() {
        let now = event.at;
        if now > end {
            break;
        }
        match event.kind {
            Kind::Frame(frame) => {
                for index in 0..case.packets_per_frame {
                    let sent_at = now + index * PACKET_SPACING_US;
                    let packet = sender.send_payload(&PAYLOAD, ntp(sent_at), at(sent_at));
                    let sequence = u64::from(packet.sequence);
                    debug_assert_eq!(sequence, frame * case.packets_per_frame + index);
                    if original_lost(seed, sequence, case.loss_per_mille) {
                        lost_original[sequence as usize] = true;
                        outcome.holes += 1;
                    } else {
                        let delay = path.data(owd);
                        push(&mut queue, sent_at + delay, Kind::Data(packet.bytes));
                    }
                }
            }
            Kind::Data(bytes) => {
                let received = receiver.accept_packet_at(&bytes, at(now)).unwrap();
                let slot = &mut arrival[received.sequence as usize];
                if received.duplicate || slot.is_some() {
                    duplicates += 1;
                } else {
                    *slot = Some(now);
                }
            }
            Kind::ToReceiver(bytes) => {
                for response in receiver.handle_rtcp_at(&bytes, ntp(now)).unwrap() {
                    if !lost(&mut rng) {
                        feedback_bytes += response.len() as u64;
                        let delay = path.control(owd);
                        push(&mut queue, now + delay, Kind::ToSender(response));
                    }
                }
            }
            Kind::ToSender(bytes) => {
                // The sender reads feedback at its next 250 us service.
                let served = now.div_ceil(250) * 250;
                let newest = sender.next_sequence().wrapping_sub(1);
                for sequence in decode_nacks_from_compound(&bytes).unwrap() {
                    let sequence = u64::from(extend_near(newest, sequence as u16));
                    outcome.nack_entries += 1;
                    if !lost_original
                        .get(sequence as usize)
                        .copied()
                        .unwrap_or(true)
                    {
                        outcome.spurious_nack_entries += 1;
                    }
                }
                let outcome_at = sender
                    .handle_feedback_outcome_at(&bytes, ntp(served), at(served))
                    .unwrap();
                for response in outcome_at.responses {
                    if !lost(&mut rng) {
                        let delay = path.control(owd);
                        push(&mut queue, served + delay, Kind::ToReceiver(response));
                    }
                }
                for retry in outcome_at.retries {
                    let sequence = u64::from(retry.sequence) as usize;
                    if !lost_original.get(sequence).copied().unwrap_or(true) {
                        outcome.spurious_repairs += 1;
                    }
                    if !lost(&mut rng) {
                        let delay = path.data(owd);
                        push(&mut queue, served + delay, Kind::Data(retry.bytes));
                    }
                }
            }
            Kind::ReceiverTick => {
                let mut packets = Vec::new();
                receiver.poll_rtcp_into(at(now), ntp(now), &mut packets, 64);
                for packet in packets {
                    if !lost(&mut rng) {
                        feedback_bytes += packet.len() as u64;
                        let delay = path.control(owd);
                        push(&mut queue, now + delay, Kind::ToSender(packet));
                    }
                }
                push(&mut queue, now + 1_000, Kind::ReceiverTick);
            }
            Kind::SenderTick => {
                for repair in sender.poll_repairs_at(at(now)) {
                    if !lost(&mut rng) {
                        let delay = path.data(owd);
                        push(&mut queue, now + delay, Kind::Data(repair.bytes));
                    }
                }
                if now % 5_000 == 0 {
                    if let Some(rtcp) = sender.poll_rtcp(at(now), ntp(now)) {
                        if !lost(&mut rng) {
                            let delay = path.control(owd);
                            push(&mut queue, now + delay, Kind::ToReceiver(rtcp));
                        }
                    }
                }
                push(&mut queue, now + 250, Kind::SenderTick);
            }
        }
    }

    let deadline = case.length_ms * 1_000;
    for frame in 0..frames {
        let first = frame * case.packets_per_frame;
        let range = first as usize..(first + case.packets_per_frame) as usize;
        let sent = frame * FRAME_INTERVAL_US;
        let mut complete = Some(0);
        for sequence in range.clone() {
            match (arrival[sequence], complete) {
                (Some(t), Some(c)) => complete = Some(t.max(c)),
                _ => complete = None,
            }
            if arrival[sequence].is_none() {
                outcome.unrecovered += 1;
            }
        }
        let lossy = range.clone().any(|sequence| lost_original[sequence]);
        match complete {
            None => outcome.frames_lost += 1,
            Some(done) => {
                let latency = done - sent;
                if latency > deadline {
                    outcome.frames_late += 1;
                }
                if lossy {
                    outcome.lossy_frame_latency_us.push(latency);
                }
            }
        }
    }
    let stats: SenderStats = sender.stats();
    let receiver_stats = receiver.stats();
    outcome.sent_packets = stats.sent_packets;
    outcome.retransmitted = stats.retransmitted_packets;
    outcome.tail_probes = stats.tail_probes;
    outcome.duplicate_repairs = stats.duplicate_repairs;
    outcome.refused_spacing = stats.retransmit_refused_spacing;
    outcome.nack_packets = receiver_stats.nack_packets;
    outcome.nack_copies = receiver_stats.nack_copies_sent;
    outcome.duplicates_received = duplicates;
    outcome.feedback_bytes = feedback_bytes;
    outcome
}

fn percentile(values: &mut [u64], p: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_unstable();
    let index = ((values.len() - 1) as f64 * p).round() as usize;
    values[index] as f64 / 1_000.0
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn report(case: Case, seconds: u64, seeds: u64) {
    println!(
        "\n{} (RTT {} ms, L {} ms, {} packets/frame, {} % loss each way, jitter {} us, {} % held back, {} s x {} seeds)",
        case.name,
        case.rtt_ms,
        case.length_ms,
        case.packets_per_frame,
        case.loss_per_mille as f64 / 10.0,
        case.jitter_us,
        case.reorder_per_mille as f64 / 10.0,
        seconds,
        seeds
    );
    println!(
        "{:<15} {:>7} {:>7} {:>6} {:>6} {:>8} {:>8} {:>8} {:>7} {:>7} {:>7} {:>6} {:>6} {:>8} {:>7} {:>7} {:>7}",
        "variant",
        "frames",
        "lost",
        "late",
        "holes",
        "unrec",
        "p50 ms",
        "p99 ms",
        "rtx %",
        "dup rx",
        "nack/s",
        "probe",
        "dupx2",
        "fb kB/s",
        "spur nk",
        "spur rx",
        "refused"
    );
    let mut variants = vec![Variant::Defaults, Variant::Parity, Variant::LibristTiming];
    if std::env::var_os("RIST_SIM_ABLATION").is_some() {
        variants.extend([
            Variant::NoProbe,
            Variant::NoNackCopies,
            Variant::NoDuplicates,
            Variant::FixedFirstNack,
        ]);
    }
    for variant in variants {
        let mut total = Outcome::default();
        for seed in 1..=seeds {
            let outcome = run(case, variant, seconds, seed);
            total.frames += outcome.frames;
            total.frames_lost += outcome.frames_lost;
            total.frames_late += outcome.frames_late;
            total.holes += outcome.holes;
            total.unrecovered += outcome.unrecovered;
            total
                .lossy_frame_latency_us
                .extend(outcome.lossy_frame_latency_us);
            total.sent_packets += outcome.sent_packets;
            total.retransmitted += outcome.retransmitted;
            total.nack_packets += outcome.nack_packets;
            total.nack_copies += outcome.nack_copies;
            total.duplicates_received += outcome.duplicates_received;
            total.tail_probes += outcome.tail_probes;
            total.duplicate_repairs += outcome.duplicate_repairs;
            total.refused_spacing += outcome.refused_spacing;
            total.feedback_bytes += outcome.feedback_bytes;
            total.nack_entries += outcome.nack_entries;
            total.spurious_nack_entries += outcome.spurious_nack_entries;
            total.spurious_repairs += outcome.spurious_repairs;
        }
        let secs = (seconds * seeds) as f64;
        println!(
            "{:<15} {:>7} {:>7} {:>6} {:>6} {:>8} {:>8.1} {:>8.1} {:>7.2} {:>7} {:>7.0} {:>6} {:>6} {:>8.1} {:>7} {:>7} {:>7}",
            variant.name(),
            total.frames,
            total.frames_lost,
            total.frames_late,
            total.holes,
            total.unrecovered,
            percentile(&mut total.lossy_frame_latency_us, 0.5),
            percentile(&mut total.lossy_frame_latency_us, 0.99),
            100.0 * total.retransmitted as f64 / total.sent_packets.max(1) as f64,
            total.duplicates_received,
            total.nack_packets as f64 / secs,
            total.tail_probes,
            total.duplicate_repairs,
            total.feedback_bytes as f64 / secs / 1_000.0,
            total.spurious_nack_entries,
            total.spurious_repairs,
            total.refused_spacing,
        );
    }
}

const CASES: [Case; 8] = [
    Case {
        name: "2160p25 rtt1 l40",
        rtt_ms: 1,
        length_ms: 40,
        packets_per_frame: 96,
        loss_per_mille: 50,
        jitter_us: 0,
        reorder_per_mille: 0,
    },
    Case {
        name: "2160p25 rtt1 l40 1%",
        rtt_ms: 1,
        length_ms: 40,
        packets_per_frame: 96,
        loss_per_mille: 10,
        jitter_us: 0,
        reorder_per_mille: 0,
    },
    Case {
        name: "2160p160 rtt30 l120",
        rtt_ms: 30,
        length_ms: 120,
        packets_per_frame: 630,
        loss_per_mille: 50,
        jitter_us: 0,
        reorder_per_mille: 0,
    },
    Case {
        name: "2160p25 rtt100 l400",
        rtt_ms: 100,
        length_ms: 400,
        packets_per_frame: 96,
        loss_per_mille: 50,
        jitter_us: 0,
        reorder_per_mille: 0,
    },
    Case {
        name: "2160p25 rtt250 l1000",
        rtt_ms: 250,
        length_ms: 1_000,
        packets_per_frame: 96,
        loss_per_mille: 50,
        jitter_us: 0,
        reorder_per_mille: 0,
    },
    Case {
        name: "2160p25 rtt30 l1000 (product L)",
        rtt_ms: 30,
        length_ms: 1_000,
        packets_per_frame: 96,
        loss_per_mille: 50,
        jitter_us: 0,
        reorder_per_mille: 0,
    },
    Case {
        name: "2160p25 rtt5 l200 1% jitter3 reorder1%",
        rtt_ms: 5,
        length_ms: 200,
        packets_per_frame: 96,
        loss_per_mille: 10,
        jitter_us: 3_000,
        reorder_per_mille: 10,
    },
    Case {
        name: "2160p25 rtt30 l1000 5% jitter2 reorder1% (product L)",
        rtt_ms: 30,
        length_ms: 1_000,
        packets_per_frame: 96,
        loss_per_mille: 50,
        jitter_us: 2_000,
        reorder_per_mille: 10,
    },
];

#[test]
#[ignore]
fn recovery_simulation_report() {
    let seconds = env_u64("RIST_SIM_SECS", 15);
    let seeds = env_u64("RIST_SIM_SEEDS", 4);
    let only = std::env::var("RIST_SIM_CASES").ok();
    for (index, case) in CASES.into_iter().enumerate() {
        if only
            .as_deref()
            .is_some_and(|list| !list.split(',').any(|item| item == index.to_string()))
        {
            continue;
        }
        report(case, seconds, seeds);
    }
}

/// A short, deterministic check of the headline: at RTT 1 / L 40 / 5 %
/// the defaults deliver more frames within L than parity, and parity no
/// fewer than librist's timing.
#[test]
fn defaults_deliver_more_frames_in_time_than_parity_at_rtt1_l40() {
    let case = CASES[0];
    let missed = |variant| {
        (1..=2)
            .map(|seed| {
                let outcome = run(case, variant, 3, seed);
                outcome.frames_lost + outcome.frames_late
            })
            .sum::<u64>()
    };
    let defaults = missed(Variant::Defaults);
    let parity = missed(Variant::Parity);
    let librist = missed(Variant::LibristTiming);
    assert!(defaults < parity, "defaults {defaults} parity {parity}");
    assert!(
        parity <= librist,
        "parity {parity} librist timing {librist}"
    );
}

/// Reordering and jitter must not make the extras misfire: on a path with
/// 3 ms of jitter both ways and 1 % of the data held back by up to twice
/// the reorder buffer, the defaults (adaptive first NACK, NACK copies,
/// duplicate repairs, tail probes) repair at most a little more of what
/// was never lost than librist-like recovery does, the spacing check
/// absorbs the NACK copies, duplicate repairs stay rare, and no more
/// frames are missed.
#[test]
fn reordering_and_jitter_keep_spurious_repairs_bounded() {
    let case = CASES[6];
    assert!(case.jitter_us > 0 && case.reorder_per_mille > 0);
    let totals = |variant| {
        let mut total = Outcome::default();
        for seed in 1..=2 {
            let outcome = run(case, variant, 3, seed);
            total.frames_lost += outcome.frames_lost + outcome.frames_late;
            total.holes += outcome.holes;
            total.spurious_repairs += outcome.spurious_repairs;
            total.spurious_nack_entries += outcome.spurious_nack_entries;
            total.duplicate_repairs += outcome.duplicate_repairs;
            total.refused_spacing += outcome.refused_spacing;
            total.nack_copies += outcome.nack_copies;
        }
        total
    };
    let defaults = totals(Variant::Defaults);
    let parity = totals(Variant::Parity);
    let summary = |name: &str, total: &Outcome| {
        format!(
            "{name}: missed {} holes {} spurious NACKed {} spurious repairs {} \
             duplicate repairs {} refused by spacing {} NACK copies {}",
            total.frames_lost,
            total.holes,
            total.spurious_nack_entries,
            total.spurious_repairs,
            total.duplicate_repairs,
            total.refused_spacing,
            total.nack_copies
        )
    };
    let report = format!(
        "{}\n{}",
        summary("defaults", &defaults),
        summary("parity", &parity)
    );
    // Reordering beyond the reorder buffer costs both the same repairs.
    assert!(parity.spurious_repairs > 0, "{report}");
    assert!(
        defaults.spurious_repairs * 100 <= parity.spurious_repairs * 115 + 1_000,
        "{report}"
    );
    // The copies are what the sender's spacing check refuses.
    assert!(defaults.refused_spacing > 0, "{report}");
    assert!(defaults.refused_spacing <= defaults.nack_copies, "{report}");
    assert!(
        defaults.duplicate_repairs * 10 <= defaults.holes,
        "{report}"
    );
    assert!(defaults.frames_lost <= parity.frames_lost, "{report}");
}
